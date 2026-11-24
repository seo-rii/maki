"""The scheduled job must run every ignored release gate to completion, the
pull-request job every script test module, and the RHEL 9 job the packaged
build, the native suites and the RPM in a RHEL 9 userspace."""

import fnmatch
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
WITNESS_MANIFEST = ROOT / "crates" / "maki-witness" / "Cargo.toml"
ETCD_GATE = ROOT / "crates" / "maki-witness" / "tests" / "etcd_ha.rs"
ETCD_CFG = '#[cfg(all(unix, feature = "etcd-qualification"))]'
DAEMON = ROOT / "crates" / "maki-nbdkit" / "src" / "daemon.rs"
PLUGIN_STEP = "nbdkit plugin build (cdylib + plugin_init symbol)"
BYTECODE_STEP = "Python suites leave no bytecode in the checkout (Linux)"
FAKE_STEP = 'release build refuses provider = "fake"'
# What `maki volume create` prints for provider = "fake" without the feature.
FAKE_REFUSAL = ('error: config invalid: provider "fake" is not compiled into this build '
                "(feature `fake-provider`); it is a test-only, non-cryptographic provider")

NM = r'''#!/usr/bin/env python3
import json
import os
import sys
arguments = sys.argv[1:]
if "-D" not in arguments or arguments[-1] != "target/release/libmaki_nbdkit.so":
    sys.exit("fixture: unexpected nm arguments: " + " ".join(arguments))
for kind, name in json.loads(os.environ["NM_SYMBOLS"]):
    if kind == "U":
        if "--defined-only" not in arguments:
            print(" " * 16 + " U " + name)
    else:
        print("0000000000012340 " + kind + " " + name)
'''

MAKI = r'''#!/usr/bin/env python3
import json
import os
import pathlib
import sys
import tomllib
arguments = sys.argv[1:]
if len(arguments) != 3 or arguments[:2] != ["volume", "create"]:
    sys.exit("fixture: unexpected maki arguments: " + " ".join(arguments))
config = tomllib.loads(pathlib.Path(arguments[2]).read_text())
pathlib.Path(os.environ["OBSERVED"]).write_text(json.dumps(config))
mode = os.environ["MAKI_MODE"]
if mode in ("accepted", "refused-after-writing"):
    root = pathlib.Path(config["backing"]["root"])
    root.mkdir(parents=True)
    (root / "superblock.a").write_bytes(b"fixture")
if mode == "accepted":
    print("created volume fakevol (provider fake)")
    sys.exit(0)
print({"refused": os.environ["FAKE_REFUSAL"],
       "refused-after-writing": os.environ["FAKE_REFUSAL"],
       "schema": "error: config invalid: volume.device_block_size must be a power of two",
       "parse": "error: config parse error: unknown field at line 3, column 1",
       "io": "error: Permission denied (os error 13)"}[mode], file=sys.stderr)
sys.exit(1)
'''


def step_script(name):
    """The `run` block of a workflow step, as the runner's shell receives it."""
    step = WORKFLOW.read_text().split(f"      - name: {name}\n", 1)[1]
    run = re.search(r"(?m)^        run: \|\n((?:          .*\n)+)", step)
    assert run is not None, f"{name} must have an executable shell block"
    return "".join(line[10:] + "\n" for line in run.group(1).splitlines())


def run_step(name, root, environment, replacements=()):
    script = step_script(name)
    for old, new in replacements:
        script = script.replace(old, new)
    binary = root / "bin"
    binary.mkdir(exist_ok=True)
    cargo = binary / "cargo"
    cargo.write_text("#!/bin/sh\nexit 0\n")
    cargo.chmod(0o700)
    environment = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ["PATH"],
                       **environment)
    # A `run` step without `shell:` executes as `bash -e {0}` on Linux runners.
    return subprocess.run(["bash", "-e", "-c", script], cwd=root, env=environment,
                          capture_output=True, text=True, timeout=10)


class ReleaseGateContract(unittest.TestCase):
    def test_nightly_does_not_stop_at_the_first_failing_gate_binary(self):
        workflow = WORKFLOW.read_text()
        self.assertIn(
            "run: cargo test --workspace --release --locked --no-fail-fast -- --ignored\n",
            workflow,
        )

    def test_integration_gate_opt_in_requires_a_same_repository_pull_request(self):
        workflow = WORKFLOW.read_text()
        for job in ("nightly-gates", "etcd-qualification"):
            match = re.search(rf"^  {job}:\n    if: ([^\n]+)", workflow, re.MULTILINE)
            self.assertIsNotNone(match)
            for event, repository, branch, enabled in (
                ("schedule", "", "", True),
                ("workflow_dispatch", "", "", True),
                ("push", "seo-rii/maki", "review/integration-test", False),
                ("pull_request", "seo-rii/maki", "review/integration-test", True),
                ("pull_request", "external/fork", "review/integration-test", False),
                ("pull_request", "seo-rii/maki", "fix/ordinary", False),
            ):
                with self.subTest(job=job, event=event, repository=repository, branch=branch):
                    expression = match.group(1)
                    values = {
                        "github.event.pull_request.head.repo.full_name": repository,
                        "github.event_name": event,
                        "github.repository": "seo-rii/maki",
                        "github.head_ref": branch,
                    }
                    for name, value in values.items():
                        expression = expression.replace(name, repr(value))
                    expression = expression.replace("||", "or").replace("&&", "and")
                    actual = eval(expression, {"__builtins__": {}}, {
                        "startsWith": lambda value, prefix: value.startswith(prefix),
                    })
                    self.assertIs(actual, enabled)

    def test_etcd_quorum_gate_is_an_opt_in_feature(self):
        # The quorum gate refuses to skip without an operator-provided etcd
        # binary, so the unfiltered `-- --ignored` run must not compile it.
        self.assertIn("\netcd-qualification = []\n", WITNESS_MANIFEST.read_text())
        gate = ETCD_GATE.read_text()
        self.assertIn(f"{ETCD_CFG}\nmod quorum {{", gate)
        self.assertNotIn("#[cfg(unix)]\nmod quorum", gate)


class PythonSuites(unittest.TestCase):
    def pull_request_job(self):
        """The always-on `pr` job without its comments."""
        workflow = WORKFLOW.read_text()
        job = workflow[workflow.index("\n  pr:\n"):workflow.index("\n  latest-stable:\n")]
        return "".join(line for line in job.splitlines(keepends=True)
                       if not line.lstrip().startswith("#"))

    def test_the_pull_request_job_runs_every_script_test_module(self):
        # Most modules run because their name matches a discovery pattern
        # and the rest are named: a module that does neither would never run.
        job = self.pull_request_job()
        self.assertNotIn("continue-on-error", job)
        patterns = re.findall(r"python3 -B -m unittest discover -s scripts -p '([^']+)'", job)
        named = set(re.findall(r"python3 -B -m unittest scripts\.(test_\w+)", job))
        modules = sorted(path.stem for path in (ROOT / "scripts").glob("test_*.py"))
        self.assertGreater(len(modules), 20)
        self.assertEqual(
            [module for module in modules if module not in named and not any(
                fnmatch.fnmatchcase(module + ".py", pattern) for pattern in patterns)],
            [], "name these modules in a Linux step of the pr job, or rename them to match "
                f"one of {patterns}")
        self.assertEqual(sorted(named - set(modules)), [],
                         "the workflow names script test modules that do not exist")

    @unittest.skipUnless(os.name == "posix", "the step runs in bash on Linux runners")
    def test_bytecode_gate_follows_the_suites_and_rejects_a_cache_directory(self):
        job = self.pull_request_job()
        gate = job.index(f"      - name: {BYTECODE_STEP}\n        if: runner.os == 'Linux'\n")
        self.assertLess(job.rindex("python3 -B -m unittest"), gate)
        with tempfile.TemporaryDirectory(prefix="maki-ci-gate-") as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            result = run_step(BYTECODE_STEP, root, {})
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            cache = root / "scripts" / "__pycache__"
            cache.mkdir()
            (cache / "campaign_io.cpython-311.opt-1.pyc").write_bytes(b"fixture")
            result = run_step(BYTECODE_STEP, root, {})
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("campaign_io.cpython-311.opt-1.pyc", result.stderr)


@unittest.skipUnless(os.name == "posix", "the nightly steps run in bash on Linux runners")
class NightlyArtifactGates(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="maki-ci-gate-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def plugin_gate(self, symbols):
        case = Path(tempfile.mkdtemp(dir=self.root))
        (case / "bin").mkdir()
        nm = case / "bin" / "nm"
        nm.write_text(NM)
        nm.chmod(0o700)
        return run_step(PLUGIN_STEP, case, {"NM_SYMBOLS": json.dumps(symbols)})

    def test_plugin_gate_accepts_a_defined_plugin_init_function(self):
        result = self.plugin_gate([["U", "nbdkit_debug"], ["T", "plugin_init"],
                                   ["T", "maki_plugin_shutdown"]])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_plugin_gate_rejects_undefined_prefixed_or_data_symbols(self):
        for symbols in ([["U", "plugin_init"]],
                        [["T", "nbdkit_plugin_init"]],
                        [["T", "plugin_init_v2"]],
                        [["D", "plugin_init"]],
                        []):
            with self.subTest(symbols=symbols):
                result = self.plugin_gate(symbols)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def fake_gate(self, mode):
        case = self.root / mode
        (case / "target" / "release").mkdir(parents=True)
        (case / "tmp").mkdir()
        maki = case / "target" / "release" / "maki"
        maki.write_text(MAKI)
        maki.chmod(0o700)
        observed = case / "observed.json"
        result = run_step(FAKE_STEP, case,
                          {"MAKI_MODE": mode, "OBSERVED": str(observed),
                           "FAKE_REFUSAL": FAKE_REFUSAL},
                          replacements=(("/tmp/", f"{case}/tmp/"),))
        self.assertTrue(observed.exists(), result.stdout + result.stderr)
        config = json.loads(observed.read_text())
        self.assertEqual(config["crypto"]["provider"], "fake", "the gate must ask for fake")
        self.assertEqual(config["backing"]["root"], f"{case}/tmp/fakevol")
        return result

    def test_fake_gate_accepts_only_the_compiled_out_refusal(self):
        result = self.fake_gate("refused")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_fake_gate_rejects_other_create_failures(self):
        # A config drifting out of schema fails before the provider check
        # and must not keep the gate green.
        for mode in ("schema", "parse", "io"):
            with self.subTest(mode=mode):
                result = self.fake_gate(mode)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_fake_gate_rejects_an_accepted_or_written_volume(self):
        for mode in ("accepted", "refused-after-writing"):
            with self.subTest(mode=mode):
                result = self.fake_gate(mode)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_fake_refusal_matches_the_daemon_message(self):
        # The gate greps a stable part of this message; rewording it in the
        # daemon must update the gate in the same change.
        self.assertIn('"provider \\"fake\\" is not compiled into this build (feature '
                      '`fake-provider`); \\\n', DAEMON.read_text())
        self.assertIn("provider \"fake\" is not compiled into this build", FAKE_REFUSAL)


def jobs():
    """Each job's body, by name."""
    return dict(re.findall(r"(?ms)^  ([\w-]+):\n(.*?)(?=^  [\w-]+:|\Z)", WORKFLOW.read_text()))


def steps(job):
    """(name or action, body) of each step of a job, comments removed."""
    body = "".join(line for line in job.splitlines(keepends=True)
                   if not line.lstrip().startswith("#"))
    found = re.findall(r"(?ms)^      - (?:name: ([^\n]+)|uses: ([^\n]+))\n(.*?)(?=^      - |\Z)", body)
    return [(name or uses, rest) for name, uses, rest in found]


class RhelUserspaceJob(unittest.TestCase):
    """A RHEL 9 userspace (glibc 2.34, nbdkit 1.38, lvm2, rpm 4.16) on every change."""

    def setUp(self):
        self.job = jobs()["rhel9"]
        self.steps = steps(self.job)
        self.names = [name for name, _ in self.steps]

    def step(self, name):
        return dict(self.steps)[name]

    def test_runs_on_every_change_in_a_centos_stream_9_container(self):
        self.assertIn("\n    runs-on: ubuntu-latest\n", "\n" + self.job)
        self.assertIn("\n    container: quay.io/centos/centos:stream9\n", "\n" + self.job)
        self.assertRegex(self.job, r"(?m)^    timeout-minutes: \d+$")
        self.assertNotRegex(self.job, r"(?m)^    (?:if|needs|continue-on-error):")
        self.assertNotIn("continue-on-error", self.job)

    def test_uses_the_baseline_toolchain_and_its_own_cache(self):
        pull_request = [name for name, _ in steps(jobs()["pr"])]
        toolchain = [name for name in pull_request if name.startswith("dtolnay/rust-toolchain@")]
        self.assertEqual([name for name in self.names if name.startswith("dtolnay/")], toolchain[:1])
        self.assertIn("actions/checkout@v4", self.names)
        self.assertIn("Swatinem/rust-cache@v2", self.names)
        self.assertIn("key: rhel9", self.step("Swatinem/rust-cache@v2"))

    def test_installs_from_baseos_appstream_and_crb_only(self):
        install = self.step(self.names[0])
        self.assertLess(self.names.index(self.names[0]), self.names.index("actions/checkout@v4"),
                        "git must be installed before the checkout")
        commands = re.findall(r"(?m)^\s*dnf (.*?)\\?$", install)
        self.assertTrue(commands, "the first step installs the dependencies with dnf")
        self.assertNotIn("epel", install.lower())
        self.assertEqual(re.findall(r"--enablerepo=(\S+)", install), ["crb"],
                         "CRB only, for nbdkit-devel")
        packages = set(re.findall(r"[\w.+-]+", " ".join(
            line for line in install.splitlines() if not line.strip().startswith(("nbdkit --", "test ")))))
        for package in ("gcc", "git-core", "python3", "rpm-build", "cpio", "nbdkit", "nbdkit-devel",
                        "libnbd", "lvm2", "xfsprogs", "util-linux", "kmod", "systemd", "kernel-headers"):
            self.assertIn(package, packages)
        for check in ("nbdkit --version", "nbdinfo --version", "nbdcopy --version",
                      "test -f /usr/include/nbdkit-plugin.h",
                      'test "$(command -v nbdkit)" = /usr/sbin/nbdkit'):
            self.assertIn(check, install)

    def test_builds_tests_and_packages_what_the_debian_package_ships(self):
        order = [self.names.index(name) for name in (
            "actions/checkout@v4", "packaged binaries", "nbdkit ABI against the EL9 header",
            "helper, attach and plugin suites", "RPM package contract",
            "build, install and remove the RPM")]
        self.assertEqual(order, sorted(order))
        self.assertIn("run: cargo build --release --locked -p maki -p maki-attach -p maki-check "
                      "-p maki-nbdkit\n", self.step("packaged binaries"))
        self.assertIn("run: cargo test --locked -p maki-nbdkit --test review_abi -- --nocapture\n",
                      self.step("nbdkit ABI against the EL9 header"))
        self.assertIn("run: python3 -B scripts/run_cargo_tests.py --locked -p maki-privileged "
                      "-p maki-attach -p maki-nbdkit\n", self.step("helper, attach and plugin suites"))
        self.assertIn("run: python3 -B -m unittest scripts.test_rpm_package -v\n",
                      self.step("RPM package contract"))

    def test_the_built_rpm_is_installed_checked_and_refuses_removal_under_a_record(self):
        script = self.step("build, install and remove the RPM")
        self.assertIn("set -euo pipefail", script)
        self.assertIn("packaging/rpm/build-rpm.py", script)
        self.assertIn("--release-dir target/release", script)
        self.assertNotIn("--no-autoreq", script, "the real package keeps its native requirements")
        for check in ("grep -qx glibc", "GLIBC_2\\.34", "dnf install -y", "rpm -V maki",
                      "systemd-analyze verify", "/usr/lib/systemd/system/maki@.service",
                      "/run/maki-attach/", "rpm -e maki"):
            self.assertIn(check, script)
        record = script.index("/run/maki-attach/")
        self.assertLess(record, script.index("rpm -e maki"))
        self.assertRegex(script, r"if rpm -e maki; then[^\n]*\n[^\n]*exit 1")


if __name__ == "__main__":
    unittest.main()
