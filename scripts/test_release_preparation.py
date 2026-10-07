"""Candidate bundles bind packaged native artifacts to committed source."""

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/prepare_release.py"


@unittest.skipUnless(
    sys.platform.startswith("linux")
    and all(shutil.which(tool) for tool in ("git", "cc", "dpkg-deb", "dpkg-shlibdeps")),
    "candidate package tests need native Linux Debian packaging tools and cc",
)
class ReleasePreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.work = pathlib.Path(self.temporary.name)
        self.repo = self.work / "repo"
        (self.repo / "scripts").mkdir(parents=True)
        # Missing implementation is the initial failing feature test.
        self.assertTrue(SCRIPT.is_file(), "a release-candidate preparation command is required")
        shutil.copyfile(SCRIPT, self.repo / "scripts/prepare_release.py")
        shutil.copytree(ROOT / "packaging", self.repo / "packaging")
        (self.repo / "Cargo.toml").write_text('[workspace.package]\nversion = "0.1.0"\n')
        (self.repo / "Cargo.lock").write_text("# locked fixture\nversion = 3\n")
        self.git("init", "-q")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "user.name", "Release fixture")
        self.git("add", ".")
        self.git("commit", "-qm", "test: candidate source fixture")
        self.commit = self.git("rev-parse", "HEAD")
        self.tools = self.work / "tools"
        self.tools.mkdir()
        source = self.work / "fixture.c"
        source.write_text("int main(void) { return 0; }\n")
        self.executable = self.work / "fixture"
        self.shared = self.work / "fixture.so"
        for command in (
            ["cc", str(source), "-o", str(self.executable)],
            ["cc", "-shared", "-fPIC", str(source), "-o", str(self.shared)],
        ):
            subprocess.run(command, check=True, capture_output=True)
        self.cargo_trace = self.work / "cargo.json"
        cargo = self.tools / "cargo"
        cargo.write_text(
            f"#!{sys.executable}\n"
            "import json, os, pathlib, shutil, sys\n"
            "if sys.argv[1:] == ['--version']:\n"
            "    print('cargo 1.99.0 (release fixture)'); sys.exit(0)\n"
            "if os.environ.get('CANDIDATE_FIXTURE_BUILD_FAIL'):\n"
            "    print('fixture build failed', file=sys.stderr); sys.exit(7)\n"
            "args = sys.argv[1:]\n"
            "target = pathlib.Path(os.environ['CARGO_TARGET_DIR'])\n"
            "output = target / args[args.index('--target') + 1] / 'release'\n"
            "output.mkdir(parents=True)\n"
            f"pathlib.Path({str(self.cargo_trace)!r}).write_text(json.dumps({{"
            "'args': args, 'cwd': os.getcwd(), "
            "'source': pathlib.Path('Cargo.toml').read_text(), "
            "'epoch': os.environ['SOURCE_DATE_EPOCH']}))\n"
            "for name in ('maki', 'maki-attach', 'maki-check'):\n"
            f"    shutil.copyfile({str(self.executable)!r}, output / name)\n"
            f"shutil.copyfile({str(self.shared)!r}, output / 'libmaki_nbdkit.so')\n"
        )
        cargo.chmod(0o755)
        rustc = self.tools / "rustc"
        rustc.write_text("#!/bin/sh\nprintf 'rustc 1.99.0 (fixture)\\nhost: fixture-native-linux-gnu\\n'\n")
        rustc.chmod(0o755)
        self.environment = os.environ.copy()
        self.environment["PATH"] = str(self.tools) + os.pathsep + self.environment["PATH"]

    def git(self, *args):
        return subprocess.run(
            ["git", "-C", str(self.repo), *args], check=True, capture_output=True, text=True
        ).stdout.strip()

    def prepare(self, name="candidate", succeeds=True):
        output = self.work / name
        result = subprocess.run(
            [sys.executable, "-B", str(self.repo / "scripts/prepare_release.py"), "--output", str(output)],
            cwd=self.work,
            env=self.environment,
            capture_output=True,
            text=True,
        )
        if succeeds:
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
        return output, result

    def test_bundle_has_committed_source_dependencies_and_verifiable_manifest(self):
        # Untracked files must neither enter the archive nor affect the build.
        (self.repo / "local-secret").write_text("do not package me")
        output, _ = self.prepare()
        manifest = json.loads((output / "manifest.json").read_text())
        self.assertEqual(manifest["source"]["commit"], self.commit)
        self.assertEqual(manifest["source"]["tree"], self.git("rev-parse", "HEAD^{tree}"))
        self.assertEqual(manifest["workspace_version"], "0.1.0")
        self.assertEqual(manifest["qualification"], "candidate-only; production approval remains separate")
        self.assertTrue(manifest["build_host"]["distribution"]["id"])
        self.assertIn("host: fixture-native-linux-gnu", manifest["toolchain"]["rustc"])
        package = output / manifest["package"]["filename"]
        package_version = subprocess.check_output(["dpkg-deb", "--field", package, "Version"], text=True).strip()
        self.assertEqual(package_version, f"0.1.0~rc+git{self.commit[:12]}")
        self.assertIn("libc6", manifest["package"]["depends"])
        self.assertIn("nbd-client (>= 1:3.27.0)", manifest["package"]["depends"])
        with tarfile.open(output / manifest["source"]["filename"], "r:gz") as archive:
            names = archive.getnames()
            self.assertTrue(any(name.endswith("/Cargo.lock") for name in names))
            self.assertFalse(any(name.endswith("/local-secret") for name in names))
        for line in (output / "SHA256SUMS").read_text().splitlines():
            digest, filename = line.split("  ")
            self.assertEqual(digest, hashlib.sha256((output / filename).read_bytes()).hexdigest())
        self.assertEqual(
            {line.split("  ")[1] for line in (output / "SHA256SUMS").read_text().splitlines()},
            {path.name for path in output.iterdir()} - {"SHA256SUMS"},
        )
        invocation = json.loads(self.cargo_trace.read_text())
        self.assertIn("--locked", invocation["args"])
        self.assertIn("--release", invocation["args"])
        self.assertNotIn("--features", invocation["args"])
        self.assertNotEqual(pathlib.Path(invocation["cwd"]), self.repo)
        self.assertEqual(invocation["epoch"], self.git("show", "-s", "--format=%ct", "HEAD"))

    def test_tracked_worktree_changes_are_refused_before_building(self):
        with (self.repo / "Cargo.toml").open("a") as handle:
            handle.write("# not committed\n")
        output, result = self.prepare(succeeds=False)
        self.assertIn("tracked", result.stderr)
        self.assertFalse(output.exists())
        self.assertFalse(self.cargo_trace.exists())

    def test_staged_changes_are_refused_before_building(self):
        (self.repo / "new-tracked").write_text("pending addition")
        self.git("add", "new-tracked")
        output, result = self.prepare(succeeds=False)
        self.assertIn("tracked", result.stderr)
        self.assertFalse(output.exists())

    def test_existing_output_is_preserved(self):
        output = self.work / "candidate"
        output.mkdir()
        (output / "sentinel").write_text("preserve")
        _, result = self.prepare(succeeds=False)
        self.assertIn("exists", result.stderr)
        self.assertEqual((output / "sentinel").read_text(), "preserve")
        self.assertFalse(self.cargo_trace.exists())

    def test_failed_build_leaves_no_partial_candidate(self):
        self.environment["CANDIDATE_FIXTURE_BUILD_FAIL"] = "1"
        output, result = self.prepare(succeeds=False)
        self.assertIn("fixture build failed", result.stderr)
        self.assertFalse(output.exists())

    def test_failed_native_dependency_scan_leaves_no_candidate(self):
        shlibdeps = self.tools / "dpkg-shlibdeps"
        shlibdeps.write_text("#!/bin/sh\necho 'fixture dependency scan failed' >&2\nexit 8\n")
        shlibdeps.chmod(0o755)
        output, result = self.prepare(succeeds=False)
        self.assertIn("fixture dependency scan failed", result.stderr)
        self.assertFalse(output.exists())

    def test_same_commit_and_artifacts_have_same_bundle_checksums(self):
        first, _ = self.prepare("first")
        second, _ = self.prepare("second")
        self.assertEqual((first / "SHA256SUMS").read_bytes(), (second / "SHA256SUMS").read_bytes())

    def test_source_links_are_refused_before_extraction_or_building(self):
        (self.repo / "escape").symlink_to("../../outside-source")
        self.git("add", "escape")
        self.git("commit", "-qm", "test: unsupported source link")
        output, result = self.prepare(succeeds=False)
        self.assertIn("unsupported source archive entry", result.stderr)
        self.assertFalse(output.exists())
        self.assertFalse(self.cargo_trace.exists())


if __name__ == "__main__":
    unittest.main()
