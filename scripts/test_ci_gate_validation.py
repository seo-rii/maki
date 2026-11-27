"""The scheduled job must run every ignored release gate to completion, the
pull-request job every script test module, the RHEL 9 job the packaged
build, the native suites and the RPM in a RHEL 9 userspace, the kernel
lifecycle job a whole attachment and the documented quick start on the
runner's kernel, the booted-host jobs the guides and the privileged runner in
booted Debian 12 and EL9 guests, the fuzz job every fuzz target from its
committed seeds, the big-endian job the replay of those seeds on s390x, and
the fuzz qualification workflow the CPU-hours of SPEC §56 per target,
recorded."""

import fnmatch
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
FUZZ_MANIFEST = ROOT / "fuzz" / "Cargo.toml"
FUZZ_STEP = "run every fuzz target from its seeds"
QUALIFICATION = ROOT / ".github" / "workflows" / "fuzz-qualification.yml"
CAMPAIGN = ROOT / "scripts" / "fuzz_campaign.py"
WITNESS_MANIFEST = ROOT / "crates" / "maki-witness" / "Cargo.toml"
ETCD_GATE = ROOT / "crates" / "maki-witness" / "tests" / "etcd_ha.rs"
ETCD_CFG = '#[cfg(all(unix, feature = "etcd-qualification"))]'
DAEMON = ROOT / "crates" / "maki-nbdkit" / "src" / "daemon.rs"
PLUGIN_STEP = "nbdkit plugin build (cdylib + plugin_init symbol)"
BYTECODE_STEP = "Python suites leave no bytecode in the checkout (Linux)"
FAKE_STEP = 'release build refuses provider = "fake"'
KERNEL_RUNNER_STEP = "attach lifecycle through the privileged runner"
QUICKSTART_STEP = "documented quick start on the installed package"
RUNNER = ROOT / "scripts" / "privileged-linux-validation.sh"
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


def campaign():
    """scripts/fuzz_campaign.py, which plans and records the fuzz qualification."""
    spec = importlib.util.spec_from_file_location("fuzz_campaign", CAMPAIGN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def step_script(name, workflow=WORKFLOW):
    """The `run` block of a workflow step, as the runner's shell receives it."""
    step = workflow.read_text().split(f"      - name: {name}\n", 1)[1]
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
        for job in ("nightly-gates", "etcd-qualification", "fuzz"):
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

    def test_the_etcd_gates_run_one_at_a_time(self):
        # Each gate starts a three-member etcd cluster and a frontend on ports
        # it chose by binding port 0 and releasing it, so two gates started at
        # once can take each other's ports: in one of seven runs on a shared
        # host a member exited during startup.
        job = jobs()["etcd-qualification"]
        commands = [" ".join(line.split()) for line in job.splitlines()
                    if "--test etcd_ha" in line and not line.lstrip().startswith("#")]
        self.assertEqual(commands, [
            "cargo test --release --locked -p maki-witness --features etcd-qualification "
            "--test etcd_ha -- --ignored --test-threads=1"
        ])
        gate = ETCD_GATE.read_text()
        self.assertGreaterEqual(gate.count("#[ignore = \"requires verified MAKI_ETCD_BIN"), 2)


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
        # Test tools: nbdkit-server as the RPM requires it, the basic plugins
        # for the tests' memory and eval exports, the UAPI headers and a C
        # compiler for the header probes.
        for package in ("gcc", "git-core", "python3", "rpm-build", "cpio", "nbdkit-server",
                        "nbdkit-basic-plugins", "nbdkit-devel", "libnbd", "util-linux", "systemd",
                        "kernel-headers"):
            self.assertIn(package, packages)
        # The nbdkit metapackage is what the guide says not to install; the
        # rest of the runtime must come from the RPM's own Requires.
        for package in ("nbdkit", "nbdkit-selinux", "lvm2", "xfsprogs", "kmod"):
            self.assertNotIn(package, packages)
        for check in ("nbdkit --version", "nbdinfo --version", "nbdcopy --version",
                      "test -f /usr/include/nbdkit-plugin.h", "test -f /usr/include/linux/nbd.h",
                      "test -f /usr/include/linux/nbd-netlink.h",
                      'test "$(command -v nbdkit)" = /usr/sbin/nbdkit'):
            self.assertIn(check, install)

    def test_root_in_the_runner_owned_workspace(self):
        # Container steps run as root, but /__w (the workspace, RUNNER_TEMP)
        # and /github/home belong to the runner's uid 1001. actions/checkout
        # trusts the workspace only in a temporary git config, so root's git
        # refuses it, and fixtures that require root-owned ancestors closed
        # to others (regression_mount_target.rs) refuse the workspace, HOME
        # and the world-writable /tmp.
        name = "root in the runner-owned workspace"
        position = self.names.index(name)
        self.assertEqual(position, self.names.index("actions/checkout@v4") + 1)
        self.assertLess(position, self.names.index("packaged binaries"))
        script = self.step(name)
        self.assertIn('git config --global --add safe.directory "$GITHUB_WORKSPACE"', script)
        created = re.findall(r"install -d -o root -g root -m 0755 (/\S+)", script)
        self.assertEqual(len(created), 1, script)
        directory = created[0]
        # 0755 like the root runner's scratch directory: fixtures hand files
        # to uid 65534, which must be able to reach them.
        for unsuitable in ("/tmp", "/var/tmp", "/dev/shm", "/__w", "/github", "/home", "/root"):
            self.assertFalse(directory == unsuitable or directory.startswith(unsuitable + "/"),
                             directory)
        self.assertIn(f'echo "TMPDIR={directory}" >> "$GITHUB_ENV"', script)

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
        # One failing test binary must not hide the verdict of the others.
        self.assertIn("run: python3 -B scripts/run_cargo_tests.py --locked --no-fail-fast "
                      "-p maki-privileged -p maki-attach -p maki-nbdkit\n",
                      self.step("helper, attach and plugin suites"))
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
        # The user and groups the package creates are provided, each once
        # (scripts/test_rpm_package.py checks that they do not come from a
        # dependency generator of the build host).
        self.assertIn('rpm -qp --provides "$package" | tee "$RUNNER_TEMP/provides"\n', script)
        self.assertRegex(script, r"for provided in 'user\(maki\)' 'group\(maki\)' 'group\(maki-admin\)'; do\n"
                                 r"\s*test \"\$\(grep -cxF \"\$provided\" \"\$RUNNER_TEMP/provides\"\)\" = 1\n"
                                 r"\s*done\n")
        # The RPM's Requires bring the rest of the runtime, without the
        # nbdkit metapackage.
        install = script.index("dnf install -y")
        self.assertLess(install, script.index("rpm -q nbdkit-server lvm2 xfsprogs util-linux systemd kmod\n"))
        self.assertRegex(script, r"for unwanted in nbdkit nbdkit-selinux; do\n\s*if rpm -q \"\$unwanted\"; "
                                 r"then exit 1; fi\n\s*done")
        # dnf refuses nbdkit-selinux beside the installed package.
        self.assertIn('if dnf install --assumeno nbdkit-selinux > "$RUNNER_TEMP/selinux" 2>&1; then exit 1; fi\n',
                      script)
        self.assertIn("grep -q 'conflicts with nbdkit-selinux' \"$RUNNER_TEMP/selinux\"\n", script)
        self.assertLess(install, script.index("--assumeno nbdkit-selinux"))
        record = script.index("echo '{}' > /run/maki-attach/ci.nbd\n")
        self.assertLess(record, script.index("rpm -e maki"))
        self.assertRegex(script, r"if rpm -e maki; then[^\n]*\n[^\n]*exit 1")
        # rpm cannot stop a transaction from %preun. Under the record dnf
        # must refuse, before it changes anything, to remove Maki, to remove
        # what it requires, and to put the nbdkit metapackage in its place;
        # the checks that follow fail if the runtime was erased after all.
        refusals = [
            ('if dnf remove -y maki > "$RUNNER_TEMP/remove" 2>&1; then exit 1; fi\n',
             "grep -q 'removing the following protected packages: maki' \"$RUNNER_TEMP/remove\"\n"),
            ('if dnf remove -y lvm2 > "$RUNNER_TEMP/remove-lvm2" 2>&1; then exit 1; fi\n',
             "grep -q 'broken dependencies for the following protected packages: maki' "
             "\"$RUNNER_TEMP/remove-lvm2\"\n"),
            ('if dnf install -y --allowerasing nbdkit > "$RUNNER_TEMP/metapackage" 2>&1; then exit 1; fi\n',
             "grep -q 'conflicts with nbdkit provided by' \"$RUNNER_TEMP/metapackage\"\n"),
        ]
        position = record
        for attempt, reason in refusals:
            with self.subTest(attempt=attempt):
                # Each refusal is checked for its reason on the next line.
                self.assertRegex(script, re.escape(attempt) + r"\s*" + re.escape(reason))
                self.assertLess(position, script.index(attempt))
                position = script.index(attempt)
        intact = script.index("rpm -q maki nbdkit-server lvm2 xfsprogs kmod\n")
        self.assertLess(position, intact)
        self.assertLess(intact, script.index("rpm -V maki\n", intact))
        self.assertLess(script.index("rpm -V maki\n", intact), script.index("if rpm -e maki; then"))
        self.assertEqual(script.count("for unwanted in nbdkit nbdkit-selinux; do\n"), 2,
                         "neither may be installed before or after the refused transactions")
        # An upgrade or reinstallation is never refused, also under the record.
        reinstall = script.index('dnf reinstall -y -q "$package"\n')
        self.assertLess(record, reinstall)
        self.assertLess(reinstall, script.index("rm /run/maki-attach/ci.nbd\n"))
        # Without a record dnf still refuses and rpm removes the package,
        # with its entry in /etc/dnf/protected.d.
        idle = script.index('if dnf remove -y maki > "$RUNNER_TEMP/remove-idle" 2>&1; then exit 1; fi\n')
        self.assertLess(script.index("rm /run/maki-attach/ci.nbd\n"), idle)
        removal = script.index("rpm -e maki\n", idle)
        self.assertLess(removal, script.index("test ! -e /etc/dnf/protected.d/maki.conf\n"))


# Stands in for every command the quick start step runs, by the name it is
# called by; it records each call with the directory it ran in.
QUICKSTART_STUB = r"""#!@PYTHON@
import json
import os
from pathlib import Path
import sys
name = Path(sys.argv[0]).name
args = sys.argv[1:]
root = Path(os.environ["FIXTURE"])
with (root / "calls.jsonl").open("a") as calls:
    calls.write(json.dumps([name, os.getcwd(), *args]) + "\n")
if name == "sudo":
    if args[:1] == ["bash"]:
        print("the documented program's output")
        sys.exit(int(os.environ.get("QUICKSTART_STATUS", "0")))
    if args[:1] == ["test"]:
        assert args[1:3] == ["!", "-e"], args
        sys.exit(1 if Path(args[3]).exists() else 0)
    assert args[:1] == ["apt-get"], args
elif name == "python3":
    if args[:2] == ["-B", "scripts/documented_quickstart.py"]:
        directory = Path(args[2])
        directory.mkdir(parents=True)
        (directory / "quickstart.sh").write_text("program\n")
        (directory / "demo.toml").write_text("configuration\n")
    else:
        assert args[:2] == ["-B", "packaging/debian/build-deb.py"], args
        assert "--no-shlibdeps" not in args, args
        Path(args[args.index("--output") + 1]).write_text("package\n")
elif name == "git":
    print("1700000000")
elif name == "dpkg":
    print("amd64")
elif name == "dpkg-deb":
    print("nbdkit, lvm2, xfsprogs, util-linux, systemd (>= 249), kmod")
elif name == "findmnt":
    sys.exit(0 if os.environ.get("MOUNTED") else 1)
elif name == "systemctl":
    print(os.environ.get("ACTIVE_STATE", "inactive"))
"""


class KernelLifecycleJob(unittest.TestCase):
    """A whole attachment on the runner's own kernel on every change: the
    privileged runner's lifecycle, then the package built from the commit
    running the documented install steps, quick start and bootstrap."""

    def setUp(self):
        self.job = jobs().get("kernel-lifecycle")
        self.assertIsNotNone(self.job, "ci.yml has no kernel-lifecycle job")
        self.steps = steps(self.job)
        self.names = [name for name, _ in self.steps]

    def step(self, name):
        self.assertIn(name, self.names)
        return dict(self.steps)[name]

    def test_runs_on_every_change_on_a_runner_vm(self):
        # A VM with systemd as PID 1, udev and the nbd module: not a container.
        self.assertIn("\n    runs-on: ubuntu-latest\n", "\n" + self.job)
        self.assertNotIn("container:", self.job)
        self.assertRegex(self.job, r"(?m)^    timeout-minutes: \d+$")
        self.assertNotRegex(self.job, r"(?m)^    (?:if|needs|continue-on-error):")
        self.assertNotIn("continue-on-error", self.job)
        # pipefail: a command whose output goes through tee keeps its status.
        self.assertRegex(self.job, r"(?m)^    defaults:\n      run:\n        shell: bash\n")
        workflow = WORKFLOW.read_text()
        triggers = workflow[workflow.index("\non:\n"):workflow.index("\njobs:\n")]
        for trigger in ("\n  pull_request:", "\n  workflow_dispatch:",
                        "\n  push:\n    branches: [main, master]\n"):
            self.assertIn(trigger, triggers)

    def test_uses_the_baseline_toolchain_and_its_own_cache(self):
        pull_request = [name for name, _ in steps(jobs()["pr"])]
        toolchain = [name for name in pull_request if name.startswith("dtolnay/rust-toolchain@")]
        self.assertEqual([name for name in self.names if name.startswith("dtolnay/")], toolchain[:1])
        self.assertIn("actions/checkout@v4", self.names)
        self.assertIn("key: kernel-lifecycle", self.step("Swatinem/rust-cache@v2"))

    def test_loads_the_nbd_module_as_the_runner_asks_before_it_runs(self):
        load = self.step("load the NBD module")
        self.assertIn("sudo modprobe nbd nbds_max=16 max_part=8", load)
        self.assertIn('sudo apt-get install -y -q "linux-modules-extra-$(uname -r)"', load)
        self.assertIn("test -d /sys/module/nbd", load)
        # What the runner loads it with for /dev/nbd15, its device here.
        self.assertIn('requested_devices=$((nbd_index + 1))\n((requested_devices >= 16)) || '
                      'requested_devices=16\nsudo -n modprobe nbd "nbds_max=$requested_devices" '
                      'max_part=8\n', RUNNER.read_text())
        self.assertLess(self.names.index("load the NBD module"), self.names.index(KERNEL_RUNNER_STEP))

    def runner_command(self):
        run = step_script(KERNEL_RUNNER_STEP).replace("\\\n", " ")
        lines = [line for line in run.splitlines() if "privileged-linux-validation.sh" in line]
        self.assertEqual(len(lines), 1, run)
        return shlex.split(lines[0])

    def test_the_privileged_runner_drives_the_whole_lifecycle_as_the_runner_user(self):
        self.assertRegex(self.step(KERNEL_RUNNER_STEP), r"(?m)^        timeout-minutes: \d+$")
        words = self.runner_command()
        # Not through sudo: the runner refuses root and calls sudo itself.
        self.assertEqual(words[0], "scripts/privileged-linux-validation.sh")
        # In the foreground, so that the step's status is the run's.
        self.assertNotIn("--background", words)
        self.assertIn("--install-missing", words)
        # The detach and second attach run in every run; this adds the
        # cleanup after a killed daemon, a third attach and a final detach.
        self.assertIn("--kill-daemon", words)
        self.assertIn("--kill-daemon)\n            kill_daemon=true\n", RUNNER.read_text())
        device = words[words.index("--device") + 1]
        self.assertRegex(device, r"^/dev/nbd(?:[0-9]|1[0-5])$", "a device the module loaded")
        self.assertEqual(words[words.index("--confirm-wipe") + 1], device)
        self.assertIn(f"test -b {device}\n", self.step("load the NBD module"))
        # The quick start's attachment takes the lowest free device.
        self.assertNotEqual(device, "/dev/nbd0")

    def test_the_essential_steps_are_not_skipped(self):
        conditions = {name: re.findall(r"(?m)^        if: (.*)$", body) for name, body in self.steps}
        for name in ("runner host", "load the NBD module", KERNEL_RUNNER_STEP):
            self.assertEqual(conditions[name], [], name)
        # Also after the runner failed: the quick start's verdict is its own.
        for name in ("packaged binaries", QUICKSTART_STEP):
            self.assertEqual(conditions[name], ["${{ !cancelled() }}"], name)

    @unittest.skipUnless(os.name == "posix", "the step runs in bash on Linux runners")
    def test_the_runners_status_is_the_steps(self):
        for status in ("0", "7"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "scripts").mkdir()
                runner = root / "scripts/privileged-linux-validation.sh"
                runner.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$(dirname "$0")/../arguments"\n'
                                  f'exit {status}\n')
                runner.chmod(0o700)
                result = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c",
                                         step_script(KERNEL_RUNNER_STEP)], cwd=root,
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, status == "0", result.stdout + result.stderr)
                self.assertEqual((root / "arguments").read_text().split(), self.runner_command()[1:])

    def test_the_package_from_this_commit_runs_the_documented_quick_start(self):
        # The package's tmpfiles close /run/maki to the runner's own nbdkit.
        order = [self.names.index(name) for name in (
            KERNEL_RUNNER_STEP, "packaged binaries", QUICKSTART_STEP)]
        self.assertEqual(order, sorted(order))
        self.assertIn("run: cargo build --release --locked -p maki -p maki-attach -p maki-check "
                      "-p maki-nbdkit\n", self.step("packaged binaries"))
        script = step_script(QUICKSTART_STEP)
        self.assertRegex(self.step(QUICKSTART_STEP), r"(?m)^        timeout-minutes: \d+$")
        self.assertIn("python3 -B packaging/debian/build-deb.py --release-dir target/release", script)
        # The guide's own block installs the package, from the directory it
        # runs in, so the step does not.
        self.assertIn('--output "$workdir/maki.deb"', script)
        self.assertNotRegex(script, r"(?m)\b(?:apt|apt-get|dpkg) (?:-\S+ )*(?:install|-i)\b.*maki")
        self.assertIn("sudo bash quickstart.sh 2>&1 | tee quickstart.log\n", script)

    def run_quickstart_step(self, **environment):
        directory = tempfile.TemporaryDirectory(prefix="maki-ci-quickstart-")
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        binary = root / "bin"
        binary.mkdir()
        stub = binary / "stub"
        stub.write_text(QUICKSTART_STUB.replace("@PYTHON@", sys.executable))
        stub.chmod(0o700)
        for name in ("sudo", "python3", "git", "dpkg", "dpkg-deb", "findmnt", "systemctl", "nbdkit"):
            (binary / name).symlink_to(stub)
        (root / "run/maki-attach").mkdir(parents=True)
        (root / "sys/block/nbd0").mkdir(parents=True)
        if environment.pop("RECORD", None):
            (root / "run/maki-attach/demo.nbd").write_text("{}")
        if environment.pop("BACKEND", None):
            (root / "sys/block/nbd0/backend").write_text("maki-demo\n")
        script = step_script(QUICKSTART_STEP)
        for old in ("/run/maki-attach/", "/sys/block/"):
            self.assertIn(old, script)
            script = script.replace(old, f"{root}{old}")
        env = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ["PATH"],
                   FIXTURE=str(root), RUNNER_TEMP=str(root / "temp"), **environment)
        # A `run` step under `defaults: run: shell: bash`.
        result = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
                                cwd=root, env=env, capture_output=True, text=True, timeout=10)
        calls = [json.loads(line) for line in (root / "calls.jsonl").read_text().splitlines()]
        return result, calls, root

    @unittest.skipUnless(os.name == "posix", "the step runs in bash on Linux runners")
    def test_the_quick_start_runs_in_its_directory_and_its_failure_fails_the_step(self):
        result, calls, root = self.run_quickstart_step()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        workdir = str(root / "temp" / "quickstart")
        programs = [call for call in calls if call[0] == "python3"]
        self.assertEqual([call[2:4] for call in programs],
                         [["-B", "scripts/documented_quickstart.py"],
                          ["-B", "packaging/debian/build-deb.py"]])
        self.assertEqual(programs[1][programs[1].index("--output") + 1], workdir + "/maki.deb")
        [run] = [call for call in calls if call[:1] == ["sudo"] and call[2:3] == ["bash"]]
        self.assertEqual(run[1:], [workdir, "bash", "quickstart.sh"])
        self.assertLess(calls.index(programs[1]), calls.index(run))
        self.assertIn("the documented program's output", (Path(workdir) / "quickstart.log").read_text())
        # Through tee, the program's failure is still the step's, and nothing
        # after it runs.
        result, calls, _ = self.run_quickstart_step(QUICKSTART_STATUS="3")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse([call for call in calls if call[0] in ("findmnt", "systemctl")], calls)

    @unittest.skipUnless(os.name == "posix", "the step runs in bash on Linux runners")
    def test_an_attachment_the_quick_start_left_fails_the_step(self):
        for leftover in ({"RECORD": "1"}, {"MOUNTED": "1"}, {"ACTIVE_STATE": "active"},
                         {"ACTIVE_STATE": "failed"}, {"BACKEND": "1"}):
            with self.subTest(leftover=leftover):
                result, _, _ = self.run_quickstart_step(**leftover)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_failure_prints_the_kernel_log_units_devices_and_helper_output(self):
        diagnostics = self.step("diagnostics on failure")
        # Also when a time limit cancels the job, as a hung kernel request would.
        self.assertIn("if: ${{ failure() || cancelled() }}", diagnostics)
        self.assertRegex(diagnostics, r"(?m)^        timeout-minutes: \d+$")
        self.assertEqual(self.names.index("diagnostics on failure"), self.names.index(QUICKSTART_STEP) + 1)
        for needed in ('latest="$HOME/logs/maki-privileged-validation.latest"', 'cat "$latest/status"',
                       '"$latest"/*.txt', "sudo dmesg", "journalctl -b", "-u 'maki*'",
                       "/sys/block/nbd*", "dmsetup", "sudo ls -la /run/maki-attach", "fuser -v /dev/nbd*"):
            self.assertIn(needed, diagnostics)

    def test_logs_are_kept_without_the_source_build_keys_or_backings(self):
        collect = self.step("collect logs")
        upload = self.step("actions/upload-artifact@v4")
        self.assertIn("if: always()", collect)
        self.assertIn("if: always()", upload)
        self.assertIn('> "$out/versions.txt"', collect)
        self.assertIn("path: ${{ runner.temp }}/kernel-lifecycle-logs\n", upload)
        self.assertLess(self.names.index("collect logs"), self.names.index("actions/upload-artifact@v4"))
        self.assertIn("--exclude=./source --exclude=./target --exclude=./build", collect)
        self.assertIn("--exclude=./maki.deb", collect)
        for needed in ("journalctl -b --no-pager -o short-monotonic -k",
                       "journalctl -b --no-pager -o short-monotonic -u 'maki*'"):
            self.assertIn(needed, collect)
        # The runner's key lives in its work tree below /var/tmp, the quick
        # start's in /etc/maki/secrets, the backings below /var/tmp and
        # /var/lib/maki.
        for kept_out in ("/var/tmp", "/etc/maki", "/var/lib/maki", "work_dir"):
            self.assertNotIn(kept_out, collect)

    @unittest.skipUnless(os.name == "posix", "the step runs in bash on Linux runners")
    def test_the_collected_run_directory_leaves_out_the_snapshot_and_builds(self):
        with tempfile.TemporaryDirectory(prefix="maki-ci-collect-") as directory:
            root = Path(directory)
            run = root / "home/logs/maki-privileged-validation-20261126T000000Z-1"
            for name in ("source/scripts", "target/release", "build/debug"):
                (run / name).mkdir(parents=True)
                (run / name / "file").write_text("large\n")
            for name in ("run.log", "status", "maki-detach.txt", "detach-opener.txt"):
                (run / name).write_text("evidence\n")
            (root / "home/logs/maki-privileged-validation.latest").symlink_to(run.name)
            binary = root / "bin"
            binary.mkdir()
            (binary / "sudo").write_text("#!/bin/sh\necho journal\n")
            (binary / "sudo").chmod(0o700)
            env = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ["PATH"],
                       HOME=str(root / "home"), RUNNER_TEMP=str(root / "temp"))
            result = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c",
                                     step_script("collect logs")], cwd=root, env=env,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            archive = root / "temp/kernel-lifecycle-logs/privileged-run.tar.gz"
            members = subprocess.run(["tar", "-tzf", str(archive)], capture_output=True, text=True,
                                     check=True).stdout.split()
            self.assertEqual(sorted(member.removeprefix("./") for member in members if member != "./"),
                             ["detach-opener.txt", "maki-detach.txt", "run.log", "status"])
            for name in ("kernel.log", "maki-units.log", "udev.log"):
                self.assertEqual((root / "temp/kernel-lifecycle-logs" / name).read_text(), "journal\n")
            # Each tool's version under the command that printed it, also
            # where the tool is missing, and in the job's log.
            versions = (root / "temp/kernel-lifecycle-logs/versions.txt").read_text()
            # LVM's version lines need root (it opens /dev/mapper/control)
            # and its warnings about inherited descriptors suppressed.
            for command in ("uname -srvm", "nbdkit --version",
                            "sudo env LVM_SUPPRESS_FD_WARNINGS=1 lvm version", "mkfs.xfs -V",
                            "udevadm --version", "sudo --version"):
                self.assertIn(f"$ {command}\n", versions)
            self.assertIn(versions, result.stdout)


# The booted-host jobs: each guest's package built on its own distribution,
# then a fresh guest per suite booted from a pinned cloud image under KVM.
BOOTED_GUESTS = {
    # guest: (package job, guest job, build container, package file, builder)
    "debian12": ("debian12-package", "debian12-guest", "debian:12", "maki.deb",
                 "packaging/debian/build-deb.py"),
    "el9": ("el9-package", "el9-guest", "quay.io/centos/centos:stream9", "maki.rpm",
            "packaging/rpm/build-rpm.py"),
}
BOOTED_DRIVER = "python3 -B scripts/booted-host-validation.py"
BOOTED_GUEST_STEPS = [
    "actions/checkout@v4", "runner host", "enable KVM", "QEMU and seed tools",
    "actions/download-artifact@v4", "image cache key", "actions/cache/restore@v4", "guest image",
    "actions/cache/save@v4", "guest payload", "boot the guest", "guest facts",
    "guest package manager", "installation guide and quick start", "privileged runner lifecycle",
    "guest versions", "collect guest logs", "actions/upload-artifact@v4",
]


def guest_phase(phase, timeout, *extra):
    """The command a guest step runs: one phase of the guest script, as root,
    under a time limit that runs as root too (--root puts `timeout` inside
    sudo, so it reaches the phase's root children)."""
    return (f'{BOOTED_DRIVER} run --work "$RUNNER_TEMP/guest" --timeout {timeout} --root -- python3 -B '
            f'/var/tmp/maki-ci/booted-host-guest.py {phase} --guest "$GUEST"' + "".join(
                f" {word}" for word in extra))


# How much later than a command's own limit the driver gives up on the
# connection (CONNECTION_MARGIN), and how far an SSH probe of the boot can
# overrun the boot's deadline.
BOOTED_CONNECTION_MARGIN = 90
BOOTED_PROBE_OVERRUN = 60


class BootedHostJobs(unittest.TestCase):
    """A booted Debian 12 and a booted EL9 guest per suite, on every change:
    the guides' install steps, the quick start and the first-volume bootstrap
    with the package from the commit, and the privileged runner's lifecycle
    with that package's binaries; on EL9 with SELinux enforcing."""

    def setUp(self):
        self.jobs = jobs()
        for guest, (package, guest_job, *_rest) in BOOTED_GUESTS.items():
            self.assertIn(package, self.jobs, f"ci.yml has no {package} job")
            self.assertIn(guest_job, self.jobs, f"ci.yml has no {guest_job} job")

    def steps_of(self, job):
        return steps(self.jobs[job])

    def step(self, job, name):
        found = dict(self.steps_of(job))
        self.assertIn(name, found, f"{job} has no step {name!r}")
        return found[name]

    def run_line(self, job, name):
        """A step's `run:` command, which must be a single line."""
        body = self.step(job, name)
        match = re.search(r"(?m)^        run: (?!\|)(.+)$", body)
        self.assertIsNotNone(match, f"{job}'s {name!r} runs one command")
        return match.group(1)

    def test_every_job_runs_on_every_change_with_a_time_limit_and_bash(self):
        for guest, (package, guest_job, *_rest) in BOOTED_GUESTS.items():
            for job in (package, guest_job):
                with self.subTest(job=job):
                    body = self.jobs[job]
                    self.assertIn("\n    runs-on: ubuntu-latest\n", "\n" + body)
                    self.assertRegex(body, r"(?m)^    timeout-minutes: \d+$")
                    self.assertNotRegex(body, r"(?m)^    (?:if|continue-on-error):")
                    self.assertNotIn("continue-on-error", body)
                    self.assertRegex(body, r"(?m)^    defaults:\n      run:\n        shell: bash\n")
            # The guest job waits for its own package only: one distribution's
            # failure does not hide the other's verdict.
            self.assertNotRegex(self.jobs[package], r"(?m)^    needs:")
            self.assertIn(f"\n    needs: {package}\n", "\n" + self.jobs[guest_job])

    def test_every_step_has_a_time_limit_and_the_job_outlasts_them(self):
        # A hung step fails by its own limit, so the steps after it, the log
        # collection above all, still run within the job's.
        for guest, (package, guest_job, *_rest) in BOOTED_GUESTS.items():
            for job in (package, guest_job):
                total = int(re.search(r"(?m)^    timeout-minutes: (\d+)$", self.jobs[job]).group(1))
                limits = {}
                for name, body in self.steps_of(job):
                    with self.subTest(job=job, step=name):
                        found = re.findall(r"(?m)^        timeout-minutes: (\d+)$", body)
                        self.assertEqual(len(found), 1, body)
                        limits[name] = int(found[0])
                running = sum(limits.values())
                if job == guest_job:
                    # One of the two suite steps runs in each of the job's guests.
                    running -= min(limits["installation guide and quick start"],
                                   limits["privileged runner lifecycle"])
                with self.subTest(job=job):
                    self.assertLess(running, total)

    def test_each_package_is_built_from_the_commit_on_its_own_distribution(self):
        baseline = [name for name, _ in steps(self.jobs["pr"]) if name.startswith("dtolnay/")][:1]
        for guest, (package, _job, container, filename, builder) in BOOTED_GUESTS.items():
            with self.subTest(guest=guest):
                body = self.jobs[package]
                self.assertIn(f"\n    container: {container}\n", "\n" + body)
                names = [name for name, _ in self.steps_of(package)]
                self.assertEqual([name for name in names if name.startswith("dtolnay/")], baseline)
                self.assertIn(f"key: {package}", self.step(package, "Swatinem/rust-cache@v2"))
                # git before the checkout, and root's git trusts the workspace.
                self.assertLess(names.index("build dependencies"), names.index("actions/checkout@v4"))
                self.assertIn('git config --global --add safe.directory "$GITHUB_WORKSPACE"',
                              self.step(package, "root in the runner-owned workspace"))
                self.assertIn("run: cargo build --release --locked -p maki -p maki-attach -p maki-check "
                              "-p maki-nbdkit\n", self.step(package, "packaged binaries"))
                build = self.step(package, "guest package")
                self.assertIn(f"python3 -B {builder} --release-dir target/release", build)
                self.assertIn(f"--output dist/{filename}", build)
                # The installed package keeps its native library requirements.
                self.assertNotIn("--no-shlibdeps", build)
                self.assertNotIn("--no-autoreq", build)
                self.assertIn("git rev-parse --verify 'HEAD^{commit}' > dist/source-revision", build)
                self.assertIn(f"sha256sum {filename} source-revision | tee SHA256SUMS", build)
                upload = self.step(package, "actions/upload-artifact@v4")
                self.assertIn(f"name: {package}\n", upload)
                self.assertIn("path: dist\n", upload)
                self.assertIn("if-no-files-found: error\n", upload)
                self.assertEqual(names[-1], "actions/upload-artifact@v4")

    def test_each_suite_gets_a_fresh_guest_on_a_runner_vm(self):
        for guest, (package, guest_job, *_rest) in BOOTED_GUESTS.items():
            with self.subTest(guest=guest):
                body = self.jobs[guest_job]
                # QEMU runs on the runner VM itself, not in a container.
                self.assertNotIn("container:", body)
                self.assertRegex(body, r"(?m)^    strategy:\n      fail-fast: false\n      matrix:\n"
                                       r"        suite: \[guides, runner\]\n")
                self.assertRegex(body, rf"(?m)^    env:\n      GUEST: {guest}\n"
                                       r"      SUITE: \$\{\{ matrix\.suite \}\}\n")

    def test_the_guest_steps_run_in_order(self):
        for guest, (_package, guest_job, *_rest) in BOOTED_GUESTS.items():
            with self.subTest(guest=guest):
                expected = list(BOOTED_GUEST_STEPS)
                if guest == "el9":
                    expected.insert(expected.index("guest versions"), "SELinux")
                self.assertEqual([name for name, _ in self.steps_of(guest_job)], expected)

    def test_kvm_is_opened_to_the_runner_user_and_required(self):
        for guest, (_package, guest_job, *_rest) in BOOTED_GUESTS.items():
            with self.subTest(guest=guest):
                kvm = self.step(guest_job, "enable KVM")
                self.assertIn('KERNEL=="kvm", GROUP="kvm", MODE="0666"', kvm)
                self.assertIn("sudo udevadm trigger --name-match=kvm", kvm)
                for check in ("test -r /dev/kvm", "test -w /dev/kvm"):
                    self.assertIn(check, kvm)
                tools = self.step(guest_job, "QEMU and seed tools")
                for tool in ("qemu-system-x86", "qemu-utils", "genisoimage", "openssh-client"):
                    self.assertIn(tool, tools)
                boot = self.step(guest_job, "boot the guest")
                # KVM is the driver's default; TCG is for a local trial only.
                self.assertNotIn("--accel", boot)
                self.assertIn(f'{BOOTED_DRIVER} boot --guest "$GUEST" --images "$RUNNER_TEMP/images" '
                              '--work "$RUNNER_TEMP/guest"', boot)
                self.assertIn(f'{BOOTED_DRIVER} copy-in --work "$RUNNER_TEMP/guest" --timeout ', boot)
                self.assertIn(' "$RUNNER_TEMP/payload"\n', boot)

    def test_the_boot_and_the_copy_end_within_the_boot_steps_limit(self):
        for guest, (_package, guest_job, *_rest) in BOOTED_GUESTS.items():
            with self.subTest(guest=guest):
                body = self.step(guest_job, "boot the guest")
                minutes = int(re.search(r"(?m)^        timeout-minutes: (\d+)$", body).group(1))
                boot = int(re.search(r" boot --guest .*--timeout (\d+)\n", body).group(1))
                copy = int(re.search(r" copy-in --work \S+ --timeout (\d+) ", body).group(1))
                # The boot's deadline, a probe that overruns it, cloud-init's
                # wait given up after its margin, then the copy, and a minute
                # for the keys, the seed and QEMU's start.
                self.assertLess(boot + BOOTED_PROBE_OVERRUN + BOOTED_CONNECTION_MARGIN + copy + 60,
                                minutes * 60)

    def test_the_image_is_cached_by_its_pin_and_verified_after_a_hit(self):
        for guest, (_package, guest_job, *_rest) in BOOTED_GUESTS.items():
            with self.subTest(guest=guest):
                names = [name for name, _ in self.steps_of(guest_job)]
                key = self.step(guest_job, "image cache key")
                self.assertIn("        id: image\n", key)
                self.assertEqual(self.run_line(guest_job, "image cache key"),
                                 f'{BOOTED_DRIVER} image-key --guest "$GUEST" >> "$GITHUB_OUTPUT"')
                restore = self.step(guest_job, "actions/cache/restore@v4")
                save = self.step(guest_job, "actions/cache/save@v4")
                for body in (restore, save):
                    self.assertIn("          key: ${{ steps.image.outputs.key }}\n", body)
                    self.assertIn("          path: ${{ runner.temp }}/images\n", body)
                    # Only the pinned image: never an older pin's.
                    self.assertNotIn("restore-keys", body)
                self.assertIn("        id: image-cache\n", restore)
                self.assertIn("        if: steps.image-cache.outputs.cache-hit != 'true'\n", save)
                # fetch checks a restored image's digest as it checks a download.
                self.assertLess(names.index("image cache key"), names.index("actions/cache/restore@v4"))
                self.assertLess(names.index("actions/cache/restore@v4"), names.index("guest image"))
                self.assertLess(names.index("guest image"), names.index("actions/cache/save@v4"))

    def test_the_guest_gets_the_package_its_package_job_built(self):
        for guest, (package, guest_job, *_rest) in BOOTED_GUESTS.items():
            with self.subTest(guest=guest):
                download = self.step(guest_job, "actions/download-artifact@v4")
                self.assertIn(f"name: {package}\n", download)
                self.assertIn("path: ${{ runner.temp }}/package\n", download)
                self.assertEqual(self.run_line(guest_job, "guest image"),
                                 f'{BOOTED_DRIVER} fetch --guest "$GUEST" --directory "$RUNNER_TEMP/images"')
                self.assertEqual(self.run_line(guest_job, "guest payload"),
                                 f'{BOOTED_DRIVER} payload --guest "$GUEST" --suite "$SUITE" --package '
                                 '"$RUNNER_TEMP/package" --output "$RUNNER_TEMP/payload"')

    def test_each_phase_runs_as_root_in_the_guest_within_its_steps_limit(self):
        phases = {"guest facts": ("facts", None), "guest package manager": ("prepare", None),
                  "installation guide and quick start": ("guides", "matrix.suite == 'guides'"),
                  "privileged runner lifecycle": ("runner", "matrix.suite == 'runner'"),
                  "guest versions": ("versions", "${{ !cancelled() }}")}
        for guest, (_package, guest_job, *_rest) in BOOTED_GUESTS.items():
            these = dict(phases)
            if guest == "el9":
                these["SELinux"] = ("selinux", "${{ !cancelled() }}")
            for name, (phase, condition) in these.items():
                with self.subTest(guest=guest, step=name):
                    body = self.step(guest_job, name)
                    self.assertEqual(re.findall(r"(?m)^        if: (.*)$", body),
                                     [condition] if condition else [])
                    line = self.run_line(guest_job, name)
                    timeout = int(re.search(r"--timeout (\d+) ", line).group(1))
                    extra = ('--suite "$SUITE"',) if phase == "selinux" else ()
                    self.assertEqual(line, guest_phase(phase, timeout, *extra))
                    # The guest's own limit ends the phase before the step's.
                    minutes = int(re.search(r"(?m)^        timeout-minutes: (\d+)$", body).group(1))
                    self.assertLess(timeout + 90, minutes * 60)

    def test_only_the_el9_guest_records_selinux(self):
        debian = dict(self.steps_of("debian12-guest"))
        el9 = dict(self.steps_of("el9-guest"))
        self.assertNotIn("SELinux", debian)
        self.assertNotIn("selinux", self.jobs["debian12-guest"])
        self.assertIn("SELinux", el9)
        # Otherwise the two jobs run the same steps the same way.
        for name, body in debian.items():
            with self.subTest(step=name):
                self.assertEqual(el9[name].replace("el9", "GUEST"), body.replace("debian12", "GUEST"))

    def test_the_logs_are_always_collected_and_kept(self):
        for guest, (_package, guest_job, *_rest) in BOOTED_GUESTS.items():
            with self.subTest(guest=guest):
                collect = self.step(guest_job, "collect guest logs")
                self.assertIn("if: always()", collect)
                self.assertEqual(self.run_line(guest_job, "collect guest logs"),
                                 f'{BOOTED_DRIVER} finish --work "$RUNNER_TEMP/guest" '
                                 '--output "$RUNNER_TEMP/guest-logs"')
                upload = self.step(guest_job, "actions/upload-artifact@v4")
                self.assertIn("if: always()", upload)
                self.assertIn(f"name: {guest}-guest-${{{{ matrix.suite }}}}-logs\n", upload)
                self.assertIn("path: ${{ runner.temp }}/guest-logs\n", upload)
                for kept_out in ("/etc/maki", "/var/lib/maki", "id_ed25519", "seed"):
                    self.assertNotIn(kept_out, collect + upload)


FAKE_CARGO_FUZZ = r'''#!/usr/bin/env python3
import json
import os
import sys
arguments = sys.argv[1:]
if arguments == ["fuzz", "list"]:
    listing = os.environ.get("FUZZ_LIST", "")
    if listing == "fail":
        sys.exit(2)
    if listing != "empty":
        print("\n".join(json.loads(os.environ["FUZZ_TARGETS"])))
    sys.exit(0)
if arguments[:2] != ["fuzz", "run"]:
    sys.exit("fixture: unexpected cargo arguments: " + " ".join(arguments))
with open(os.environ["FUZZ_CALLS"], "a") as calls:
    calls.write(json.dumps(arguments[2:]) + "\n")
sys.exit(1 if arguments[2] == os.environ.get("FUZZ_FAIL", "") else 0)
'''


def fuzz_targets():
    """The [[bin]] names of fuzz/Cargo.toml, in order."""
    return re.findall(r'(?m)^\[\[bin\]\]\nname = "([^"]+)"$', FUZZ_MANIFEST.read_text())


class FuzzJob(unittest.TestCase):
    """Every fuzz target runs from its committed seeds on a pinned nightly,
    where the release gates run and never on the pull-request path."""

    def setUp(self):
        self.job = jobs().get("fuzz")
        self.assertIsNotNone(self.job, "ci.yml has no fuzz job")
        self.steps = steps(self.job)
        self.names = [name for name, _ in self.steps]

    def step(self, name):
        return dict(self.steps)[name]

    def test_a_pinned_nightly_and_cargo_fuzz_off_the_pull_request_path(self):
        self.assertIn("\n    runs-on: ubuntu-latest\n", "\n" + self.job)
        self.assertRegex(self.job, r"(?m)^    timeout-minutes: \d+$")
        self.assertNotIn("continue-on-error", self.job)
        self.assertRegex(self.step("dtolnay/rust-toolchain@master"),
                         r"(?m)^          toolchain: nightly-\d{4}-\d{2}-\d{2}$")
        self.assertIn("run: cargo install cargo-fuzz --version 0.13.2 --locked\n",
                      self.step("install pinned cargo-fuzz"))
        self.assertIn("key: fuzz", self.step("Swatinem/rust-cache@v2"))
        for job in ("pr", "latest-stable", "rhel9"):
            self.assertNotIn("cargo fuzz", jobs()[job])
            self.assertNotIn("nightly", jobs()[job])

    def test_the_fuzz_build_starts_from_the_workspace_lockfile(self):
        build = self.step("build every fuzz target")
        self.assertIn("cp Cargo.lock fuzz/Cargo.lock\n", build)
        self.assertLess(build.index("cp Cargo.lock fuzz/Cargo.lock\n"), build.index("cargo fuzz build"))
        self.assertLess(self.names.index("build every fuzz target"), self.names.index(FUZZ_STEP))

    def test_crates_the_workspace_lockfile_cannot_pin_are_pinned_exactly(self):
        # After `cp Cargo.lock fuzz/Cargo.lock` Cargo adds libFuzzer's crate
        # and its `arbitrary` at whatever version is newest unless the
        # manifest names one.
        lockfile = (ROOT / "Cargo.lock").read_text()
        for name in ("libfuzzer-sys", "arbitrary"):
            with self.subTest(name=name):
                self.assertNotIn(f'name = "{name}"', lockfile)
                self.assertRegex(FUZZ_MANIFEST.read_text(), rf'(?m)^{name} = "=\d+\.\d+\.\d+"$')

    def test_the_job_reads_the_repository_and_writes_nothing(self):
        self.assertRegex(self.job, r"(?m)^    permissions:\n      contents: read\n    [a-z]")

    def test_the_fuzzed_code_uses_the_workspace_patches(self):
        # Without them the fuzzed serde_json, bytes, hyper, rustls and
        # tungstenite would be the crates.io releases, not the vendored
        # copies production uses. The witness's and the remote providers'
        # targets put every patched crate in the fuzz crate's graph.
        root = re.search(r"(?ms)^\[patch\.crates-io\]\n(.*?)(?=^\[|\Z)", (ROOT / "Cargo.toml").read_text())
        fuzz = re.search(r"(?ms)^\[patch\.crates-io\]\n(.*?)(?=^\[|\Z)", FUZZ_MANIFEST.read_text())
        self.assertIsNotNone(fuzz, "fuzz/Cargo.toml patches nothing")
        patches = dict(re.findall(r'(?m)^(\w+) = \{ path = "([^"]+)" \}$', root.group(1)))
        for name, path in re.findall(r'(?m)^(\w+) = \{ path = "([^"]+)" \}$', fuzz.group(1)):
            self.assertEqual("../" + patches[name], path, name)
        self.assertGreaterEqual(set(patches), {"serde_json", "bytes", "hyper", "rustls", "tungstenite"})
        for name in patches:
            with self.subTest(name=name):
                self.assertRegex(fuzz.group(1), rf"(?m)^{name} = ")

    @unittest.skipUnless(os.name == "posix", "the step runs in bash on Linux runners")
    def test_every_target_runs_briefly_from_its_seeds_and_a_crash_fails_the_job(self):
        self.assertIn("shell: bash", self.step(FUZZ_STEP))
        targets = fuzz_targets()
        self.assertGreaterEqual(len(targets), 16)
        for target in ("witness_rpc", "witness_etcd", "http_response", "websocket_response",
                       "grpc_response", "helper_reports", "helper_sysfs"):
            self.assertIn(target, targets)
        lengths = campaign()
        for failing in ("", targets[len(targets) // 2]):
            with self.subTest(failing=failing), tempfile.TemporaryDirectory(prefix="maki-ci-fuzz-") as directory:
                root = Path(directory)
                binary = root / "bin"
                binary.mkdir()
                cargo = binary / "cargo"
                cargo.write_text(FAKE_CARGO_FUZZ)
                cargo.chmod(0o700)
                (root / "scripts").mkdir()
                shutil.copy(CAMPAIGN, root / "scripts" / "fuzz_campaign.py")
                calls = root / "calls.jsonl"
                environment = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ["PATH"],
                                   FUZZ_TARGETS=json.dumps(targets), FUZZ_CALLS=str(calls),
                                   FUZZ_FAIL=failing)
                result = subprocess.run(["bash", "-e", "-c", step_script(FUZZ_STEP)], cwd=root,
                                        env=environment, capture_output=True, text=True, timeout=10)
                ran = [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
                if failing:
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(ran[-1][0], failing)
                    continue
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual([call[0] for call in ran], targets)
                for call in ran:
                    target = call[0]
                    # New inputs go to the uncommitted corpus; the seeds are only read.
                    self.assertEqual(call[1:3], [f"fuzz/corpus/{target}", f"fuzz/seeds/{target}"])
                    self.assertTrue((root / "fuzz" / "corpus" / target).is_dir())
                    options = call[call.index("--") + 1:]
                    self.assertTrue(any(re.fullmatch(r"-max_total_time=\d+", option) for option in options),
                                    options)
                    self.assertTrue(any(re.fullmatch(r"-timeout=\d+", option) for option in options), options)
                    length = [option for option in options if option.startswith("-max_len=")]
                    self.assertEqual(len(length), 1, options)
                    # The qualification's length: beyond the bounds the
                    # target's readers check, and no committed seed is cut
                    # to it (scripts/test_fuzz_qualification_validation.py).
                    self.assertEqual(int(length[0].split("=")[1]), lengths.max_len(target), target)
                    if target in ("format_decoders", "format_records"):
                        # A superblock frame is 4096 bytes after the selector.
                        self.assertGreater(int(length[0].split("=")[1]), 4097)
                    if target == "nbd_handshake":
                        # Beyond the client's 64 KiB byte limit.
                        self.assertGreater(int(length[0].split("=")[1]), 64 * 1024)

    @unittest.skipUnless(os.name == "posix", "the step runs in bash on Linux runners")
    def test_a_target_list_that_fails_or_is_empty_fails_the_step(self):
        for listing in ("fail", "empty"):
            with self.subTest(listing=listing), tempfile.TemporaryDirectory(prefix="maki-ci-fuzz-") as directory:
                root = Path(directory)
                binary = root / "bin"
                binary.mkdir()
                cargo = binary / "cargo"
                cargo.write_text(FAKE_CARGO_FUZZ)
                cargo.chmod(0o700)
                calls = root / "calls.jsonl"
                environment = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ["PATH"],
                                   FUZZ_TARGETS=json.dumps(fuzz_targets()), FUZZ_CALLS=str(calls),
                                   FUZZ_LIST=listing)
                result = subprocess.run(["bash", "-e", "-c", step_script(FUZZ_STEP)], cwd=root,
                                        env=environment, capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(calls.exists(), "a target ran without a list")

    def test_a_crash_input_is_kept(self):
        upload = self.step("actions/upload-artifact@v4")
        self.assertIn("if: failure()", upload)
        self.assertIn("path: fuzz/artifacts", upload)



class BigEndianSeedReplay(unittest.TestCase):
    """Every committed fuzz seed replayed on a big-endian host, s390x under
    qemu-user, on every change: the netlink seeds are a little-endian
    host's, and the replay of a big-endian host takes another path."""

    def setUp(self):
        self.job = jobs().get("big-endian-seeds")
        self.assertIsNotNone(self.job, "ci.yml has no big-endian-seeds job")
        self.steps = steps(self.job)
        self.names = [name for name, _ in self.steps]

    def step(self, name):
        return dict(self.steps)[name]

    def test_runs_on_every_change_on_the_baseline_toolchain(self):
        self.assertNotRegex(self.job, r"(?m)^    if:")
        self.assertIn("\n    runs-on: ubuntu-latest\n", "\n" + self.job)
        self.assertRegex(self.job, r"(?m)^    timeout-minutes: \d+$")
        self.assertNotIn("continue-on-error", self.job)
        self.assertIn("          targets: s390x-unknown-linux-gnu\n",
                      self.step("dtolnay/rust-toolchain@1.94.0"))
        self.assertIn("key: big-endian-seeds", self.step("Swatinem/rust-cache@v2"))

    def test_the_replay_is_cross_built_and_run_under_qemu(self):
        tools = self.step("s390x cross compiler and qemu-user")
        for package in ("gcc-s390x-linux-gnu", "libc6-dev-s390x-cross", "qemu-user"):
            self.assertRegex(tools, rf"apt-get install [^\n]*\b{package}\b")
        replay = self.step("replay every committed seed on s390x")
        for line in ("CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_LINKER: s390x-linux-gnu-gcc\n",
                     "CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_RUNNER: qemu-s390x -L /usr/s390x-linux-gnu\n",
                     "CC_s390x_unknown_linux_gnu: s390x-linux-gnu-gcc\n"):
            self.assertIn(line, replay)
        self.assertIn("cargo test --locked -p maki-fuzz-harness --target s390x-unknown-linux-gnu "
                      "--test review_fuzz_corpus", replay)
        self.assertLess(self.names.index("s390x cross compiler and qemu-user"),
                        self.names.index("the target is big-endian"))
        self.assertLess(self.names.index("the target is big-endian"),
                        self.names.index("replay every committed seed on s390x"))

    @unittest.skipUnless(os.name == "posix", "the step runs in bash on Linux runners")
    def test_a_target_that_is_not_big_endian_fails_the_job(self):
        for endian, passes in (("big", True), ("little", False)):
            with self.subTest(endian=endian), tempfile.TemporaryDirectory(prefix="maki-ci-be-") as directory:
                root = Path(directory)
                binary = root / "bin"
                binary.mkdir()
                for tool, text in (("rustc", f'target_arch="s390x"\ntarget_endian="{endian}"\n'),
                                   ("qemu-s390x", "qemu-s390x version 8.2.2\n")):
                    (binary / tool).write_text(f"#!/bin/sh\nprintf '%s' '{text}'\n")
                    (binary / tool).chmod(0o700)
                environment = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ["PATH"])
                result = subprocess.run(["bash", "-e", "-c", step_script("the target is big-endian")],
                                        cwd=root, env=environment, capture_output=True, text=True,
                                        timeout=10)
                self.assertEqual(result.returncode == 0, passes, result.stdout + result.stderr)


def qualification_jobs():
    """Each job of the qualification workflow, by name, in order."""
    text = QUALIFICATION.read_text().split("\njobs:\n", 1)[1]
    return dict(re.findall(r"(?ms)^  ([\w-]+):\n(.*?)(?=^  [\w-]+:|\Z)", text))


def job_step_script(job, name):
    """The `run` block of the step `name` of a job's body."""
    step = job.split(f"      - name: {name}\n", 1)[1]
    run = re.search(r"(?m)^        run: \|\n((?:          .*\n)+)", step)
    assert run is not None, f"{name} must have an executable shell block"
    return "".join(line[10:] + "\n" for line in run.group(1).splitlines())


def run_bash(script, root, environment):
    # The workflow's default shell: bash with -e and pipefail.
    return subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
                          cwd=root, env=dict(os.environ, **environment), capture_output=True,
                          text=True, timeout=60)


class FuzzQualificationWorkflow(unittest.TestCase):
    """SPEC §56's 24 CPU-hours per fuzz target, on hosted runners, dispatched
    by hand: shards of one build, merged corpora and a recorded verdict."""

    def setUp(self):
        self.assertTrue(QUALIFICATION.is_file(), "there is no .github/workflows/fuzz-qualification.yml")
        self.text = QUALIFICATION.read_text()
        self.jobs = qualification_jobs()

    def step(self, job, name):
        return dict(steps(self.jobs[job]))[name]

    def names(self, job):
        return [name for name, _ in steps(self.jobs[job])]

    def test_it_runs_only_when_dispatched_with_the_campaigns_inputs(self):
        on = self.text.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertEqual(re.findall(r"(?m)^  (\w+):", on), ["workflow_dispatch"])
        inputs = dict(re.findall(r'(?ms)^      (\w+):\n(?:        [^\n]*\n)*?        default: "?([^"\n]+)"?\n', on))
        self.assertEqual(inputs, {"targets": "all", "cpu_hours": "24", "shard_hours": "5",
                                  "max_parallel": "16"})
        self.assertRegex((ROOT / "SPEC.md").read_text(), r"\nparser fuzz +24 CPU-hours / target\n")

    def test_it_reads_the_repository_and_writes_nothing(self):
        self.assertIn("\npermissions:\n  contents: read\n\n", self.text)
        self.assertNotRegex(self.text, r"(?m)^    permissions:")
        self.assertNotIn("secrets.", self.text)
        self.assertIn("\ndefaults:\n  run:\n    shell: bash\n", self.text)
        self.assertIn("\nconcurrency:\n  group: fuzz-qualification\n  cancel-in-progress: false\n",
                      self.text)

    def test_inputs_and_matrix_values_reach_the_shell_only_through_the_environment(self):
        for job, body in self.jobs.items():
            for name, step in steps(body):
                run = re.search(r"(?ms)^        run: (.*?)(?=^        [\w-]+:|\Z)", step)
                if run:
                    with self.subTest(job=job, step=name):
                        self.assertNotIn("${{", run.group(1))

    def test_every_job_has_a_time_limit_a_hosted_runner_allows(self):
        self.assertEqual(list(self.jobs), ["plan", "build", "fuzz", "merge", "summary"])
        for job, body in self.jobs.items():
            with self.subTest(job=job):
                limit = re.search(r"(?m)^    timeout-minutes: (\d+)$", body)
                self.assertIsNotNone(limit)
                self.assertLessEqual(int(limit.group(1)), 360)
                self.assertIn("\n    runs-on: ubuntu-latest\n", "\n" + body)
                self.assertNotIn("continue-on-error", body)

    def test_the_jobs_run_plan_build_fuzz_merge_summary(self):
        needs = {job: re.search(r"(?m)^    needs: (.+)$", body) for job, body in self.jobs.items()}
        self.assertIsNone(needs["plan"])
        self.assertEqual({job: match.group(1) for job, match in needs.items() if match}, {
            "build": "plan", "fuzz": "[plan, build]", "merge": "[plan, build, fuzz]",
            "summary": "[plan, build, fuzz, merge]"})
        # A failed shard's corpus is still merged; the summary runs whatever
        # the other jobs did, and reports what is missing.
        self.assertIn("    if: ${{ !cancelled() && needs.build.result == 'success' }}\n", self.jobs["merge"])
        self.assertIn("    if: ${{ always() && needs.plan.result == 'success' }}\n", self.jobs["summary"])
        self.assertRegex(self.jobs["plan"], r"(?m)^      (plan|matrix|targets|max_parallel): "
                                            r"\$\{\{ steps\.plan\.outputs\.\1 \}\}$")
        self.assertEqual(len(re.findall(r"(?m)^      (\w+): \$\{\{ steps\.plan\.outputs\.\1 \}\}$",
                                        self.jobs["plan"])), 4)

    @unittest.skipUnless(os.name == "posix", "the step runs in bash on Linux runners")
    def test_the_plan_step_hands_the_dispatched_inputs_to_the_script(self):
        with tempfile.TemporaryDirectory(prefix="maki-ci-qualification-") as directory:
            temp = Path(directory)
            output = temp / "output"
            environment = {"TARGETS": "all", "CPU_HOURS": "24", "SHARD_HOURS": "5",
                           "MAX_PARALLEL": "16", "RUNNER_TEMP": str(temp), "GITHUB_OUTPUT": str(output)}
            result = run_bash(job_step_script(self.jobs["plan"], "plan the shards"), ROOT, environment)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            outputs = dict(line.split("=", 1) for line in output.read_text().splitlines())
            plan = json.loads(outputs["plan"])
            self.assertEqual(plan["targets"], fuzz_targets())
            self.assertEqual(json.loads(outputs["matrix"]), plan["matrix"])
            self.assertEqual(len(plan["matrix"]), 2 * len(fuzz_targets()))
            self.assertEqual(outputs["max_parallel"], "16")
            output.unlink()
            environment["CPU_HOURS"] = "0"
            result = run_bash(job_step_script(self.jobs["plan"], "plan the shards"), ROOT, environment)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists() and output.read_text(), "a refused plan wrote outputs")

    def test_the_build_is_the_fuzz_jobs(self):
        ci = dict(steps(jobs()["fuzz"]))
        for name in ("dtolnay/rust-toolchain@master", "install pinned cargo-fuzz"):
            with self.subTest(step=name):
                self.assertEqual(self.step("build", name), ci[name])
        build = self.step("build", "build every fuzz target")
        self.assertLess(build.index("cp Cargo.lock fuzz/Cargo.lock\n"), build.index("cargo fuzz build\n"))
        self.assertEqual(self.names("build")[-2:], ["actions/upload-artifact@v4"] * 2)
        uploads = [step for name, step in steps(self.jobs["build"]) if name == "actions/upload-artifact@v4"]
        self.assertIn("name: fuzz-binaries\n", uploads[0])
        self.assertIn("name: fuzz-build\n", uploads[1])

    @unittest.skipUnless(os.name == "posix", "the steps run in bash on Linux runners")
    def test_the_planned_binaries_are_packed_with_their_digests_and_checked_unpacked(self):
        with tempfile.TemporaryDirectory(prefix="maki-ci-qualification-") as directory:
            root = Path(directory)
            release = root / "fuzz/target/x86_64-unknown-linux-gnu/release"
            release.mkdir(parents=True)
            for target in ("format_decoders", "witness_etcd", "helper_sysfs"):
                (release / target).write_text(f"#!/bin/sh\necho {target}\n")
                (release / target).chmod(0o755)
            binary = root / "bin"
            binary.mkdir()
            for tool, text in (("rustc", "rustc 1.102.0-nightly"), ("cargo", "cargo-fuzz 0.13.2")):
                (binary / tool).write_text(f"#!/bin/sh\necho '{text}'\n")
                (binary / tool).chmod(0o700)
            temp = root / "temp"
            temp.mkdir()
            environment = {"PATH": str(binary) + os.pathsep + os.environ["PATH"],
                           "TARGETS": json.dumps(["format_decoders", "witness_etcd"]),
                           "RUNNER_TEMP": str(temp), "GITHUB_SHA": "f" * 40}
            result = run_bash(job_step_script(self.jobs["build"], "package the planned targets"),
                              root, environment)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            members = subprocess.run(["tar", "-tvf", str(temp / "fuzz-binaries.tar")],
                                     capture_output=True, text=True, check=True).stdout
            self.assertRegex(members, r"(?m)^-rwxr-xr-x .* binaries/witness_etcd$")
            self.assertNotIn("helper_sysfs", members)
            sums = (temp / "build-record" / "SHA256SUMS").read_text()
            self.assertEqual([line.split()[1] for line in sums.splitlines()],
                             ["format_decoders", "witness_etcd"])
            self.assertIn("revision " + "f" * 40, (temp / "build-record" / "versions.txt").read_text())
            # Each shard and merge unpacks and checks that build.
            unpack = job_step_script(self.jobs["fuzz"], "unpack the build")
            self.assertEqual(job_step_script(self.jobs["merge"], "unpack the build"),
                             "\n".join(unpack.splitlines()[:3]) + "\n")
            shutil.rmtree(temp / "binaries")
            result = run_bash(unpack, root, environment)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(os.access(temp / "binaries" / "witness_etcd", os.X_OK))
            (temp / "binaries" / "witness_etcd").write_text("#!/bin/sh\necho changed\n")
            subprocess.run(["tar", "-C", str(temp), "-cf", str(temp / "fuzz-binaries.tar"), "binaries"],
                           check=True)
            result = run_bash(unpack, root, environment)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_each_shard_fuzzes_the_build_on_its_matrix_entry(self):
        fuzz = self.jobs["fuzz"]
        self.assertIn("    strategy:\n      fail-fast: false\n"
                      "      max-parallel: ${{ fromJSON(needs.plan.outputs.max_parallel) }}\n"
                      "      matrix:\n        include: ${{ fromJSON(needs.plan.outputs.matrix) }}\n", fuzz)
        self.assertEqual(self.names("fuzz")[:4], ["actions/checkout@v4", "actions/download-artifact@v4",
                                                  "unpack the build", "fuzz the shard"])
        shard = self.step("fuzz", "fuzz the shard")
        self.assertIn("        timeout-minutes: ${{ matrix.minutes }}\n", shard)
        for variable, value in (("TARGET", "matrix.target"), ("SHARD", "matrix.shard"),
                                ("CPU_SECONDS", "matrix.cpu_seconds"),
                                ("WALL_SECONDS", "matrix.wall_seconds"), ("WORKERS", "matrix.workers")):
            self.assertIn(f"          {variable}: ${{{{ {value} }}}}\n", shard)
        script = job_step_script(fuzz, "fuzz the shard")
        # The script itself is the step's process, which alone the runner
        # signals when it interrupts the step (StepCancellation in
        # scripts/test_fuzz_qualification_validation.py).
        self.assertEqual(shlex.split(script.replace("\\\n", " ")), [
            "exec", "python3", "-B", "scripts/fuzz_campaign.py", "run", "--binary", "$RUNNER_TEMP/binaries/$TARGET",
            "--target", "$TARGET", "--shard", "$SHARD", "--cpu-seconds", "$CPU_SECONDS",
            "--wall-seconds", "$WALL_SECONDS", "--workers", "$WORKERS", "--seeds", "fuzz/seeds/$TARGET",
            "--out", "$RUNNER_TEMP/shard"])
        # Every key the step reads is in the plan's matrix entries.
        entry = campaign().plan("journal_scan", "1", "5", "4")["matrix"][0]
        for key in re.findall(r"\$\{\{ matrix\.(\w+) \}\}", fuzz):
            self.assertIn(key, entry)
        uploads = [step for name, step in steps(fuzz) if name == "actions/upload-artifact@v4"]
        self.assertEqual(len(uploads), 3)
        for upload, condition, name, path in (
                (uploads[0], "always()", "fuzz-shard-${{ matrix.target }}-${{ matrix.shard }}",
                 "${{ runner.temp }}/shard"),
                (uploads[1], "always()", "fuzz-stats-${{ matrix.target }}-${{ matrix.shard }}",
                 "${{ runner.temp }}/shard/shard.json"),
                (uploads[2], "failure()", "fuzz-crashes-${{ matrix.target }}-${{ matrix.shard }}",
                 "${{ runner.temp }}/shard/artifacts")):
            with self.subTest(name=name):
                self.assertIn(f"        if: {condition}\n", upload)
                self.assertIn(f"          name: {name}\n", upload)
                self.assertIn(f"          path: {path}\n", upload)

    def test_each_targets_shard_corpora_are_merged_with_its_seeds(self):
        merge = self.jobs["merge"]
        self.assertIn("      matrix:\n        target: ${{ fromJSON(needs.plan.outputs.targets) }}\n", merge)
        self.assertIn("          pattern: fuzz-shard-${{ matrix.target }}-*\n", merge)
        script = job_step_script(merge, "merge the seeds and the shard corpora")
        self.assertEqual(shlex.split(script.replace("\\\n", " ")), [
            "exec", "python3", "-B", "scripts/fuzz_campaign.py", "merge", "--binary", "$RUNNER_TEMP/binaries/$TARGET",
            "--target", "$TARGET", "--seeds", "fuzz/seeds/$TARGET", "--shards", "$RUNNER_TEMP/shards",
            "--out", "$RUNNER_TEMP/merged"])
        uploads = [step for name, step in steps(merge) if name == "actions/upload-artifact@v4"]
        self.assertEqual(len(uploads), 2)
        for upload, name, path in ((uploads[0], "fuzz-corpus-${{ matrix.target }}", "${{ runner.temp }}/merged"),
                                   (uploads[1], "fuzz-coverage-${{ matrix.target }}",
                                    "${{ runner.temp }}/merged/coverage.json")):
            self.assertIn("        if: always()\n", upload)
            self.assertIn(f"          name: {name}\n", upload)
            self.assertIn(f"          path: {path}\n", upload)

    @unittest.skipUnless(os.name == "posix", "the step runs in bash on Linux runners")
    def test_the_summary_is_kept_and_its_status_is_the_verdict(self):
        summary = self.jobs["summary"]
        for pattern in ("fuzz-stats-*", "fuzz-coverage-*"):
            self.assertIn(f"          pattern: {pattern}\n", summary)
        self.assertIn("          name: fuzz-build\n", summary)
        self.assertIn("        if: ${{ !cancelled() }}\n", self.step("summary", "summarize the campaign"))
        upload = self.step("summary", "actions/upload-artifact@v4")
        self.assertIn("        if: always()\n", upload)
        self.assertIn("          name: fuzz-qualification-summary\n", upload)
        plan = campaign().plan("journal_scan", "0.001", "5", "4")
        with tempfile.TemporaryDirectory(prefix="maki-ci-qualification-") as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            shutil.copy(CAMPAIGN, root / "scripts" / "fuzz_campaign.py")
            temp = root / "temp"
            digest = "ab" * 32
            (temp / "build").mkdir(parents=True)
            (temp / "build" / "SHA256SUMS").write_text(f"{digest}  journal_scan\n")
            (temp / "stats" / "fuzz-stats-journal_scan-1").mkdir(parents=True)
            (temp / "coverage" / "fuzz-coverage-journal_scan").mkdir(parents=True)
            (temp / "coverage" / "fuzz-coverage-journal_scan" / "coverage.json").write_text(json.dumps({
                "target": "journal_scan", "binary_sha256": digest, "merge_exit": 0, "coverage_exit": 0,
                "cov": 169, "ft": 300, "inputs": 9, "bytes": 900, "seeds": 7}))
            step_summary = temp / "step-summary.md"
            for cpu, status in ((plan["cpu_seconds"], 0), (0.5, 1)):
                with self.subTest(cpu=cpu):
                    (temp / "stats" / "fuzz-stats-journal_scan-1" / "shard.json").write_text(json.dumps({
                        "target": "journal_scan", "shard": 1, "binary_sha256": digest, "artifacts": [],
                        "cpu_seconds": plan["cpu_seconds"], "wall_seconds": plan["wall_seconds"],
                        "workers": [{"worker": worker, "exit": 0, "stopped": False, "cpu_seconds": cpu,
                                     "wall_seconds": cpu, "executions": 10} for worker in range(1, 5)]}))
                    step_summary.write_text("")
                    result = run_bash(job_step_script(summary, "summarize the campaign"), root, {
                        "PLAN": json.dumps(plan), "RUNNER_TEMP": str(temp),
                        "GITHUB_STEP_SUMMARY": str(step_summary)})
                    self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                    self.assertIn("| `journal_scan` | 4,096 |", step_summary.read_text())
                    self.assertTrue((temp / "summary" / "summary.json").is_file())


if __name__ == "__main__":
    unittest.main()
