"""Candidate bundles bind packaged native artifacts to committed source."""

import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/prepare_release.py"


@unittest.skipUnless(
    sys.platform.startswith("linux")
    and all(shutil.which(tool) for tool in ("git", "cc", "dpkg", "dpkg-deb", "dpkg-shlibdeps")),
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
        shutil.copyfile(ROOT / "CHANGELOG.md", self.repo / "CHANGELOG.md")
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
            "import json, os, pathlib, shutil, subprocess, sys, tomllib\n"
            "if sys.argv[1:] == ['--version']:\n"
            "    print('cargo 1.99.0 (release fixture)'); sys.exit(0)\n"
            "if os.environ.get('CANDIDATE_FIXTURE_BUILD_FAIL'):\n"
            "    print('fixture build failed', file=sys.stderr); sys.exit(7)\n"
            "args = sys.argv[1:]\n"
            "target = pathlib.Path(os.environ['CARGO_TARGET_DIR'])\n"
            "config_path = pathlib.Path('.cargo/config.toml')\n"
            "config = tomllib.loads(config_path.read_text()) if config_path.exists() else {}\n"
            "build_config = config.get('build', {})\n"
            "build = pathlib.Path(os.environ.get('CARGO_BUILD_BUILD_DIR', "
            "build_config.get('build-dir', str(target))))\n"
            "build.mkdir(parents=True, exist_ok=True)\n"
            "(build / 'intermediate-fixture').write_text('candidate compilation')\n"
            "compiler = os.environ.get('RUSTC') or os.environ.get('CARGO_BUILD_RUSTC') "
            "or build_config.get('rustc', 'rustc')\n"
            "compiler_version = subprocess.check_output([compiler, '-vV'], text=True).strip()\n"
            "output = target / args[args.index('--target') + 1] / 'release'\n"
            "output.mkdir(parents=True)\n"
            f"pathlib.Path({str(self.cargo_trace)!r}).write_text(json.dumps({{"
            "'args': args, 'cwd': os.getcwd(), "
            "'target': str(target), 'build': str(build), "
            "'compiler': compiler, 'compiler_version': compiler_version, "
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
        # Fixtures need tools, not the caller's credentials or Cargo overrides.
        # Keep subprocess diagnostics safe even when an assertion fails.
        self.environment = {
            "PATH": str(self.tools) + os.pathsep + os.defpath,
            "LANG": "C",
            "LC_ALL": "C",
            "TMPDIR": str(self.work),
        }

    def git(self, *args, env=None):
        return subprocess.run(
            ["git", "-C", str(self.repo), *args], env=env, check=True, capture_output=True, text=True
        ).stdout.strip()

    def print_version(self, succeeds=True):
        result = subprocess.run(
            [sys.executable, "-B", str(self.repo / "scripts/prepare_release.py"), "--print-version"],
            cwd=self.work,
            env=self.environment,
            capture_output=True,
            text=True,
        )
        if succeeds:
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertEqual(result.stdout.count("\n"), 1)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertEqual(result.stdout, "")
        return result

    def assert_version_order(self, earlier, later):
        result = subprocess.run(
            ["dpkg", "--compare-versions", earlier, "lt", later], capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, f"{earlier} must sort below {later}: {result.stderr}")

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
        self.environment["DPKG_DEB_COMPRESSOR_TYPE"] = "gzip"
        output, _ = self.prepare()
        manifest = json.loads((output / "manifest.json").read_text())
        self.assertEqual(manifest["build"]["package_environment"], {"DPKG_DEB_COMPRESSOR_TYPE": "gzip"})
        self.assertEqual(manifest["source"]["commit"], self.commit)
        self.assertEqual(manifest["source"]["tree"], self.git("rev-parse", "HEAD^{tree}"))
        self.assertEqual(manifest["workspace_version"], "0.1.0")
        self.assertEqual(manifest["qualification"], "candidate-only; production approval remains separate")
        self.assertTrue(manifest["build_host"]["distribution"]["id"])
        self.assertIn("host: fixture-native-linux-gnu", manifest["toolchain"]["rustc"])
        package = output / manifest["package"]["filename"]
        package_version = subprocess.check_output(["dpkg-deb", "--field", package, "Version"], text=True).strip()
        self.assertEqual(package_version, f"0.1.0~rc+rev1.git{self.commit[:12]}")
        self.assertEqual(package_version, self.print_version().stdout.strip())
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

    def test_candidate_hashes_each_published_artifact_once(self):
        spec = importlib.util.spec_from_file_location("prepare", self.repo / "scripts/prepare_release.py")
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        with mock.patch.dict(os.environ, self.environment, clear=True), mock.patch.object(
                builder, "digest", wraps=builder.digest) as trace:
            builder.prepare(self.work / "result")
        names = [call.args[0].name for call in trace.call_args_list]
        self.assertCountEqual(names, [p.name for p in (self.work / "result").iterdir() if p.name != "SHA256SUMS"])

    def test_closed_output_after_build_banner_preserves_success(self):
        output = self.work / "candidate"
        with subprocess.Popen([sys.executable, "-B", self.repo / "scripts/prepare_release.py",
                               "--output", output], env=self.environment,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
            self.assertIn(b"Building candidate", child.stdout.readline())
            child.stdout.close()
            self.assertEqual(child.wait(timeout=30), 0, child.stderr.read())
        self.assertTrue((output / "SHA256SUMS").is_file())

    def test_documented_background_build_preserves_status_with_and_without_errexit(self):
        guide = (ROOT / "docs/releasing.md").read_text().split("## Prepare and inspect", 1)[1]
        block = guide.split("```bash\n", 1)[1].split("\n```", 1)[0]
        for strict in (False, True):
            for status in (0, 7):
                with self.subTest(strict=strict, status=status), tempfile.TemporaryDirectory() as work:
                    script = ("set -e\n" if strict else "") + f"rustup() {{ return {status}; }}\n" + block
                    result = subprocess.run(["bash", "-c", script], cwd=self.repo, capture_output=True,
                                            env={**self.environment, "HOME": work})
                    self.assertEqual(result.returncode, status)
                    self.assertEqual([f.read_text().strip() for f in (pathlib.Path(work) / "logs").glob("*.status")],
                                     [str(status)])

    def test_source_bytes_and_modes_are_independent_of_archive_attributes(self):
        contents = b"#!/bin/sh\n# revision: $Format:%H$\n"
        note = self.repo / "release notes"
        note.write_bytes(contents)
        note.chmod(0o755)
        self.git("add", note.name)
        self.git("commit", "-qm", "test: include release notes")
        attrs = self.repo / ".git/info/attributes"
        archives = []
        for setting in ("export-ignore", "export-subst"):
            with self.subTest(setting=setting):
                attrs.write_text(f'"release notes" {setting}\n')
                output, _ = self.prepare(setting)
                manifest = json.loads((output / "manifest.json").read_text())
                archive = output / manifest["source"]["filename"]
                with tarfile.open(archive) as tar:
                    member = tar.getmember("maki-0.1.0/release notes")
                    self.assertEqual(tar.extractfile(member).read(), contents)
                    self.assertEqual(member.mode, 0o755)
                archives.append(manifest["source"]["sha256"])
        self.assertEqual(archives[0], archives[1])

    def test_source_names_and_bytes_are_reproducible_across_filesystem_encodings(self):
        names = [b"release-\xc3\xa9.md", b"release-\xff.md"]
        for name in names:
            (self.repo / os.fsdecode(name)).write_bytes(name)
        self.git("add", ".")
        self.git("commit", "-qm", "test: non-ASCII archive members")
        digests = []
        for mode in ("0", "1"):
            with self.subTest(utf8_mode=mode):
                self.environment.update(LC_ALL="C", PYTHONCOERCECLOCALE="0", PYTHONUTF8=mode)
                bundle, _ = self.prepare(f"locale-{mode}")
                archive = next(bundle.glob("*-source.tar.gz"))
                digests.append(hashlib.sha256(archive.read_bytes()).hexdigest())
                with tarfile.open(archive, encoding="utf-8") as source:
                    for name in names:
                        path = "maki-0.1.0/" + name.decode("utf-8", "surrogateescape")
                        self.assertEqual(source.extractfile(path).read(), name)
        self.assertEqual(digests[0], digests[1])

    def test_source_archive_uses_original_git_objects_with_local_replacements(self):
        (self.repo / "notes.txt").write_text("committed contents\n")
        (self.repo / "other.txt").write_text("different contents\n")
        self.git("add", "notes.txt", "other.txt")
        self.git("commit", "-qm", "test: add release notes")
        self.git("replace", self.git("rev-parse", "HEAD:notes.txt"), self.git("rev-parse", "HEAD:other.txt"))

        output, _ = self.prepare()
        manifest = json.loads((output / "manifest.json").read_text())
        with tarfile.open(output / manifest["source"]["filename"]) as archive:
            self.assertEqual(archive.extractfile("maki-0.1.0/notes.txt").read(), b"committed contents\n")

    def test_filemode_false_does_not_hide_executable_changes_on_posix(self):
        tracked = self.repo / "Cargo.toml"
        self.git("config", "core.fileMode", "false")
        mode = tracked.stat().st_mode
        tracked.chmod(mode | 0o100)
        self.assertIn("tracked changes", self.print_version(succeeds=False).stderr)
        self.assertFalse(self.cargo_trace.exists())
        tracked.chmod(mode)
        self.print_version()
        executable = self.repo / "packaging/debian/build-deb.py"
        executable_mode = executable.stat().st_mode
        self.assertTrue(executable_mode & 0o100)
        executable.chmod(executable_mode & ~0o100)
        self.assertIn("tracked changes", self.print_version(succeeds=False).stderr)
        executable.chmod(executable_mode)
        self.print_version()
        self.assertEqual(self.git("config", "--bool", "core.fileMode"), "false")

    def test_filemode_false_is_preserved_on_a_fixed_mode_filesystem(self):
        from scripts import prepare_release
        self.git("config", "core.fileMode", "false")
        tracked = self.repo / "Cargo.toml"
        tracked.chmod(tracked.stat().st_mode | 0o100)
        with mock.patch.object(prepare_release.os, "fchmod", return_value=None):
            self.assertFalse(prepare_release.tracked_changes(repo=self.repo))

    def test_print_version_needs_no_build_tools_or_output_directory(self):
        # Only Git is needed: neither dpkg nor the selected compiler is usable.
        (self.tools / "git").symlink_to(shutil.which("git"))
        self.environment["PATH"] = str(self.tools)
        self.environment["RUSTC"] = "compiler-must-not-be-probed"
        self.environment["CANDIDATE_FIXTURE_BUILD_FAIL"] = "1"
        before = set(self.work.iterdir())
        version = self.print_version().stdout.strip()
        self.assertEqual(version, f"0.1.0~rc+rev1.git{self.commit[:12]}")
        self.assertEqual(self.print_version().stdout.strip(), version)
        self.assertEqual(set(self.work.iterdir()), before)
        self.assertFalse(self.cargo_trace.exists())

    def test_descendant_version_increases_despite_reversed_hashes_and_timestamps(self):
        tree = self.git("rev-parse", "HEAD^{tree}")

        def commit_after(parent, epoch, prefix=""):
            environment = self.environment | {
                "GIT_AUTHOR_DATE": f"{epoch} +0000",
                "GIT_COMMITTER_DATE": f"{epoch} +0000",
            }
            # Choose real Git objects with deliberately reversed hash order.
            # Unreferenced trial objects do not affect the ancestor count.
            for attempt in range(512):
                commit = self.git(
                    "commit-tree", tree, "-p", parent, "-m", f"version order fixture {attempt}",
                    env=environment,
                )
                if commit.startswith(prefix):
                    self.git("update-ref", "HEAD", commit)
                    return commit
            self.fail(f"could not make a fixture commit with prefix {prefix}")

        parent = self.commit
        for _ in range(7):
            parent = commit_after(parent, 2_000_000_000)
        ancestor = commit_after(parent, 2_000_000_000, "f")
        earlier = self.print_version().stdout.strip()
        descendant = commit_after(ancestor, 1_000_000_000, "0")
        later = self.print_version().stdout.strip()
        self.assertEqual(earlier, f"0.1.0~rc+rev9.git{ancestor[:12]}")
        self.assertEqual(later, f"0.1.0~rc+rev10.git{descendant[:12]}")
        self.assertLess(
            int(self.git("show", "-s", "--format=%ct", descendant)),
            int(self.git("show", "-s", "--format=%ct", ancestor)),
        )
        self.assert_version_order(f"0.1.0~rc+git{descendant[:12]}", f"0.1.0~rc+git{ancestor[:12]}")
        self.assert_version_order(earlier, later)
        self.assertFalse(self.cargo_trace.exists())

    def test_candidate_order_covers_legacy_rc_final_and_workspace_bump(self):
        candidate = self.print_version().stdout.strip()
        for legacy_hash in ("000000000000", "ffffffffffff"):
            self.assert_version_order(f"0.1.0~rc+git{legacy_hash}", candidate)
        self.assert_version_order(candidate, "0.1.0")
        # Old source-build packages need a reviewed downgrade migration: their
        # suffix sorts above both the new prerelease and the same final version.
        self.assert_version_order(candidate, "0.1.0+git000000000000")
        self.assert_version_order("0.1.0", "0.1.0+git000000000000")
        (self.repo / "Cargo.toml").write_text('[workspace.package]\nversion = "0.1.1"\n')
        self.git("add", "Cargo.toml")
        self.git("commit", "-qm", "test: bump the workspace version")
        next_candidate = self.print_version().stdout.strip()
        self.assertEqual(next_candidate, f"0.1.1~rc+rev2.git{self.git('rev-parse', 'HEAD')[:12]}")
        self.assert_version_order(candidate, next_candidate)
        self.assert_version_order("0.1.0", next_candidate)
        self.assert_version_order(next_candidate, "0.1.1")

    def test_candidate_version_ignores_checkout_local_grafts(self):
        self.git("commit", "--allow-empty", "-qm", "test: second commit")
        head = self.git("rev-parse", "HEAD")
        expected = f"0.1.0~rc+rev2.git{head[:12]}"
        self.assertEqual(self.print_version().stdout.strip(), expected)
        (self.repo / ".git/info/grafts").write_text(head + "\n")
        self.assertEqual(self.print_version().stdout.strip(), expected)
        output, _ = self.prepare()
        self.assertEqual(json.loads((output / "manifest.json").read_text())["package"]["version"], expected)

    def test_shallow_history_is_refused_before_output_or_building(self):
        self.git("commit", "--allow-empty", "-qm", "test: complete history has two commits")
        complete_version = self.print_version().stdout.strip()
        shallow = self.work / "shallow"
        self.git("clone", "--quiet", "--depth=1", self.repo.as_uri(), str(shallow))
        self.repo = shallow
        self.assertEqual(self.git("rev-parse", "--is-shallow-repository"), "true")
        self.environment["RUSTC"] = "compiler-must-not-be-probed"
        result = self.print_version(succeeds=False)
        self.assertIn("complete Git history", result.stderr)
        output, result = self.prepare("never-created/candidate", succeeds=False)
        self.assertIn("complete Git history", result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertFalse(output.parent.exists())
        self.assertFalse(self.cargo_trace.exists())
        self.git("fetch", "--quiet", "--unshallow")
        self.assertEqual(self.print_version().stdout.strip(), complete_version)

    def test_unchanged_hint_preserves_the_index_but_does_not_hide_local_edits(self):
        self.git("update-index", "--assume-unchanged", "Cargo.toml")
        self.print_version()
        with (self.repo / "Cargo.toml").open("a") as source:
            source.write("# worktree edit\n")
        self.assertIn("tracked changes", self.print_version(succeeds=False).stderr)
        self.assertEqual(self.git("ls-files", "-v", "Cargo.toml"), "h Cargo.toml")

    def test_release_checks_contents_when_git_stat_information_is_unchanged(self):
        tracked = self.repo / "Cargo.lock"
        original = tracked.read_bytes()
        self.git("config", "core.trustctime", "false")
        self.git("config", "core.checkStat", "minimal")
        before = 1_700_000_000_000_000_000
        os.utime(tracked, ns=(before, before))
        self.git("update-index", "--refresh")
        tracked.write_bytes(original.replace(b"version = 3", b"version = 4"))
        os.utime(tracked, ns=(before, before))
        self.assertEqual(self.git("status", "--porcelain"), "")
        self.assertIn("tracked changes", self.print_version(succeeds=False).stderr)
        tracked.write_bytes(original)
        self.print_version()

    def test_present_skipped_file_is_checked_but_absent_sparse_file_is_supported(self):
        self.git("update-index", "--split-index")
        self.git("update-index", "--skip-worktree", "Cargo.lock", "Cargo.toml")
        self.git("update-index", "--assume-unchanged", "Cargo.toml")
        (self.repo / "Cargo.lock").unlink()
        self.print_version()
        with (self.repo / "Cargo.toml").open("a") as source:
            source.write("# worktree edit\n")
        self.assertIn("tracked changes", self.print_version(succeeds=False).stderr)
        self.assertEqual(self.git("ls-files", "-v", "Cargo.toml"), "s Cargo.toml")

    @unittest.skipUnless(shutil.which("ssh-keygen"), "signed commit fixture requires SSH signing")
    def test_signature_display_does_not_change_the_source_timestamp(self):
        from scripts.qualification_source import extract_revision
        key = self.work / "fixture-key"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key], check=True)
        self.git("config", "gpg.format", "ssh")
        self.git("config", "user.signingkey", str(key))
        self.git("commit", "-qS", "--allow-empty", "-m", "test: signed fixture")
        allowed = self.work / "allowed-signers"
        allowed.write_text("fixture@example.invalid " + key.with_suffix(".pub").read_text())
        self.git("config", "gpg.ssh.allowedSignersFile", str(allowed))
        self.git("config", "log.showSignature", "true")
        commit = self.git("rev-parse", "HEAD")
        directory, _ = self.prepare()
        self.assertEqual(json.loads((directory / "manifest.json").read_text())["source"]["commit"], commit)
        source = self.work / "qualification"
        source.mkdir()
        extract_revision(self.repo, commit, self.work / "qualification.tar", source)
        self.assertEqual((source / "Cargo.toml").read_bytes(), (self.repo / "Cargo.toml").read_bytes())

    def test_tracked_worktree_changes_are_refused_before_building(self):
        with (self.repo / "Cargo.toml").open("a") as handle:
            handle.write("# not committed\n")
        output, result = self.prepare(succeeds=False)
        self.assertIn("tracked", result.stderr)
        self.assertFalse(output.exists())
        self.assertFalse(self.cargo_trace.exists())
        self.assertIn("tracked", self.print_version(succeeds=False).stderr)

    def test_candidate_isolates_intermediates_from_environment_and_cargo_config(self):
        for setting in ("environment", "config"):
            with self.subTest(setting=setting):
                outside = self.work / f"shared-{setting}"
                outside.mkdir()
                (outside / "sentinel").write_text("preserve")
                if setting == "environment":
                    self.environment["CARGO_BUILD_BUILD_DIR"] = str(outside)
                else:
                    self.environment.pop("CARGO_BUILD_BUILD_DIR", None)
                    (self.repo / ".cargo").mkdir()
                    (self.repo / ".cargo/config.toml").write_text(
                        f"[build]\nbuild-dir = {json.dumps(str(outside))}\n"
                    )
                    self.git("add", ".cargo/config.toml")
                    self.git("commit", "-qm", "test: external Cargo intermediate directory")
                self.prepare(f"candidate-{setting}")
                invocation = json.loads(self.cargo_trace.read_text())
                target = pathlib.Path(invocation["target"])
                build = pathlib.Path(invocation["build"])
                self.assertEqual(build.parent, target.parent)
                self.assertNotEqual(build, target)
                self.assertFalse(build.exists(), "temporary intermediates must be cleaned")
                self.assertEqual(sorted(path.name for path in outside.iterdir()), ["sentinel"])
                self.assertEqual((outside / "sentinel").read_text(), "preserve")

    def test_manifest_records_build_and_selected_target_rustflags(self):
        target_key = "CARGO_TARGET_FIXTURE_NATIVE_LINUX_GNU_RUSTFLAGS"
        self.environment.update({
            target_key: "--cfg target_marker",
            "CARGO_BUILD_RUSTFLAGS": "--cfg fallback_marker",
            "CARGO_TARGET_OTHER_LINUX_GNU_RUSTFLAGS": "--cfg other_marker",
            "CARGO_TARGET_FIXTURE_NATIVE_LINUX_GNU_UNRELATED": "unrelated",
        })
        output, _ = self.prepare()
        manifest = json.loads((output / "manifest.json").read_text())
        self.assertEqual(manifest["build"]["compiler_environment"], {
            "RUSTC": str(self.tools / "rustc"),
            target_key: "--cfg target_marker",
            "CARGO_BUILD_RUSTFLAGS": "--cfg fallback_marker",
        })

    def test_compiler_overrides_match_the_recorded_toolchain_and_target(self):
        alternate = self.tools / "alternate-rustc"
        alternate.write_text(
            "#!/bin/sh\nprintf 'rustc 1.98.0 (alternate fixture)\\nhost: alternate-linux-gnu\\n'\n"
        )
        alternate.chmod(0o755)
        cases = (
            ("RUSTC", {"RUSTC": str(alternate)}),
            ("CARGO_BUILD_RUSTC", {"CARGO_BUILD_RUSTC": str(alternate)}),
            ("relative", {"RUSTC": str(alternate.relative_to(self.work))}),
            ("precedence", {"RUSTC": str(alternate),
                            "CARGO_BUILD_RUSTC": str(self.tools / "rustc")}),
        )
        for setting, overrides in cases:
            with self.subTest(setting=setting):
                self.environment.pop("RUSTC", None)
                self.environment.pop("CARGO_BUILD_RUSTC", None)
                self.environment.update(overrides)
                output, _ = self.prepare(f"candidate-{setting}")
                invocation = json.loads(self.cargo_trace.read_text())
                manifest = json.loads((output / "manifest.json").read_text())
                self.assertEqual(manifest["toolchain"]["rustc"], invocation["compiler_version"])
                self.assertEqual(manifest["build_host"]["rust_target"], "alternate-linux-gnu")
                self.assertEqual(invocation["args"][invocation["args"].index("--target") + 1],
                                 "alternate-linux-gnu")
                self.assertEqual(manifest["toolchain"]["rustc_executable"], str(alternate))
                self.assertEqual(manifest["build"]["compiler_environment"]["RUSTC"], str(alternate))

    def test_default_compiler_selection_overrides_cargo_config(self):
        (self.repo / ".cargo").mkdir()
        (self.repo / ".cargo/config.toml").write_text(
            '[build]\nrustc = "must-not-select-this-configured-compiler"\n'
        )
        self.git("add", ".cargo/config.toml")
        self.git("commit", "-qm", "test: configured compiler differs from selected compiler")
        output, _ = self.prepare()
        invocation = json.loads(self.cargo_trace.read_text())
        manifest = json.loads((output / "manifest.json").read_text())
        self.assertEqual(invocation["compiler"], str(self.tools / "rustc"))
        self.assertEqual(manifest["toolchain"]["rustc"], invocation["compiler_version"])

    def test_staged_changes_are_refused_before_building(self):
        (self.repo / "new-tracked").write_text("pending addition")
        self.git("add", "new-tracked")
        output, result = self.prepare(succeeds=False)
        self.assertIn("tracked", result.stderr)
        self.assertFalse(output.exists())
        self.assertIn("tracked", self.print_version(succeeds=False).stderr)

    def test_existing_output_is_preserved(self):
        output = self.work / "candidate"
        output.mkdir()
        (output / "sentinel").write_text("preserve")
        _, result = self.prepare(succeeds=False)
        self.assertIn("exists", result.stderr)
        self.assertEqual((output / "sentinel").read_text(), "preserve")
        self.assertFalse(self.cargo_trace.exists())

    def test_head_change_during_cleanliness_check_stops_candidate(self):
        from scripts import prepare_release

        (self.repo / "notes.txt").write_text("release notes\n")
        self.git("add", "notes.txt")
        self.git("commit", "-qm", "fixture: add release notes")
        tracked_changes = prepare_release.tracked_changes

        def change_checked_head():
            dirty = tracked_changes()
            self.assertFalse(dirty)
            self.git("reset", "--soft", self.commit)
            return dirty

        output = self.work / "candidate"
        with mock.patch.object(prepare_release, "ROOT", self.repo), \
                mock.patch.object(prepare_release, "tracked_changes", change_checked_head):
            with self.assertRaisesRegex(SystemExit, "HEAD changed"):
                prepare_release.prepare(output)
        self.assertFalse(output.exists())
        self.assertFalse(self.cargo_trace.exists())

    def test_failed_build_leaves_no_partial_candidate(self):
        self.environment["CANDIDATE_FIXTURE_BUILD_FAIL"] = "1"
        output, result = self.prepare(succeeds=False)
        self.assertIn("fixture build failed", result.stderr)
        self.assertFalse(output.exists())

    def test_concurrently_reserved_empty_output_is_preserved(self):
        from scripts import prepare_release
        output = self.work / "candidate"
        output.mkdir()
        reserved_inode = output.stat().st_ino
        exists = pathlib.Path.exists

        # Both callers can observe an absent destination before one creates it.
        # The filesystem already contains that caller's empty directory at rename.
        def observed_exists(path):
            return path != output and exists(path)

        with mock.patch.object(prepare_release, "ROOT", self.repo), \
                mock.patch.dict(os.environ, self.environment, clear=True), \
                mock.patch.object(pathlib.Path, "exists", observed_exists):
            with self.assertRaisesRegex(SystemExit, "output already exists"):
                prepare_release.prepare(output)
        self.assertTrue(self.cargo_trace.exists())
        self.assertEqual(output.stat().st_ino, reserved_inode)
        self.assertEqual(list(output.iterdir()), [])

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
