"""CI must run the test targets that need root as root, and none may be forgotten."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location(
    "run_root_tests", Path(__file__).with_name("run_root_tests.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

ROOT = runner.ROOT
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
STEP = """      - name: root-only tests (Linux)
        if: runner.os == 'Linux'
        run: python3 -B scripts/run_root_tests.py --open-build-tree --workspace --locked
"""
WORKSPACE_TESTS = "        run: python scripts/run_cargo_tests.py --workspace --locked\n"

# How a test finds out, or says, that it lacks a privilege:
#   geteuid/getuid      libc::geteuid() == 0, behind is_root(), running_as_root(),
#                       skip_unless_root() or inline
#   "need(s) root"      the printed skip reasons
#   chown/lchown/fchown giving a fixture away, which only root may do
#   unshare, CLONE_NEW* a private mount namespace
#   Command::new("id")  `id -u`
PRIVILEGE_PROBE = re.compile(
    r'\bgete?uid\b|\bneeds? root\b|\b[fl]?chown\b|\bunshare\b|CLONE_NEW|Command::new\("id"\)')

# Sources that probe their privilege although no case in them skips for lack
# of root, and why. Everything else that matches must run in the root step.
NOT_ROOT_ONLY = {
    "bins/maki-attach/tests/e2e.rs":
        "one case skips as root, where the verb would really run",
    "bins/maki/tests/remote_admin.rs":
        "drops CAP_DAC_OVERRIDE when it happens to run as root and asserts the same either way",
    "crates/maki-backing/src/creation_owner_tests.rs":
        "two cases skip as root, which may give files away; the others use the running user",
    "crates/maki-backing/src/root_directory_tests.rs":
        "one case skips as root, which DAC cannot deny",
    "crates/maki-crypto-local/tests/review_keysource.rs":
        "one case skips as root, which reads any file",
    "crates/maki-privileged/tests/regression_mount_target.rs":
        "asserts more without root, and its fixtures live below CARGO_TARGET_TMPDIR, which "
        "a root run must leave to the unprivileged user",
}

INLINE_TESTS = re.compile(
    r"(?m)^[ \t]*#\[cfg\((?:all\()?test\b[^\n]*\n(?:[ \t]*#\[[^\n]*\n)*[ \t]*(?:pub )?mod \w+ \{")
TEST_ATTRIBUTE = re.compile(r"(?m)^[ \t]*#\[(?:tokio::)?test\b")


def unit_test_code(path):
    """The part of a Rust source that is compiled only into a test executable."""
    text = path.read_text(encoding="utf-8")
    if "tests" in path.relative_to(ROOT).parts[2:3]:
        return text
    inline = INLINE_TESTS.search(text)
    if inline:
        return text[inline.start():]
    # A module file of unit tests, included by `#[cfg(test)] mod` elsewhere.
    return text if TEST_ATTRIBUTE.search(text) else ""


def probing_sources():
    sources = [path for pattern in ("crates/*/tests", "bins/*/tests", "crates/*/src", "bins/*/src")
               for directory in ROOT.glob(pattern) for path in directory.rglob("*.rs")]
    return sorted(path.relative_to(ROOT).as_posix() for path in sources
                  if PRIVILEGE_PROBE.search(unit_test_code(path)))


def targets_of(source):
    """The test targets, by source file, whose executable contains `source`."""
    parts = Path(source).parts
    package, kind, below = Path(*parts[:2]), parts[2], parts[3:]
    if kind == "src":
        return [next((package / "src" / name).as_posix() for name in ("lib.rs", "main.rs")
                     if (ROOT / package / "src" / name).is_file())]
    if len(below) == 1:
        return [source]
    # A helper below tests/: every integration test that includes it by path.
    included = '#[path = "' + "/".join(below) + '"]'
    return sorted(path.relative_to(ROOT).as_posix()
                  for path in (ROOT / package / "tests").glob("*.rs")
                  if included in path.read_text(encoding="utf-8"))


def target_sources(target):
    """A listed target's own sources: the file and what it includes by path, or all of src/."""
    path = ROOT / target
    if path.parent.name == "src":
        return sorted(path.parent.rglob("*.rs"))
    included = re.findall(r'#\[path = "([^"]+)"\]', path.read_text(encoding="utf-8"))
    return [path, *(path.parent / name for name in included)]


class RootOnlyTargetsAreNotForgotten(unittest.TestCase):
    def test_every_source_that_probes_its_privilege_is_classified(self):
        required = {}
        for source in probing_sources():
            if source in NOT_ROOT_ONLY:
                continue
            targets = targets_of(source)
            self.assertTrue(targets, f"{source} probes its privilege but no test includes it")
            for target in targets:
                required.setdefault(target, []).append(source)
        listed = set(runner.ROOT_TARGETS)
        unlisted = {target: sources for target, sources in required.items()
                    if target not in listed}
        self.assertEqual(unlisted, {}, (
            "these test targets probe their privilege (see PRIVILEGE_PROBE). If a case skips "
            "without root, add the target to ROOT_TARGETS in scripts/run_root_tests.py so CI "
            "runs it as root; otherwise explain the source in NOT_ROOT_ONLY"))
        self.assertEqual(sorted(listed - set(required)), [], (
            "ROOT_TARGETS lists targets in which nothing probes its privilege any more"))

    def test_listed_targets_and_classifications_still_exist(self):
        self.assertEqual(len(set(runner.ROOT_TARGETS)), len(runner.ROOT_TARGETS))
        for target in runner.ROOT_TARGETS:
            self.assertTrue((ROOT / target).is_file(), f"{target} is listed but does not exist")
        probing = set(probing_sources())
        for source, reason in NOT_ROOT_ONLY.items():
            self.assertTrue((ROOT / source).is_file(), f"{source} is classified but gone")
            self.assertIn(source, probing, f"{source} no longer probes its privilege")
            self.assertTrue(reason)

    def test_a_root_run_stays_out_of_the_build_tree_and_needs_no_native_plugin(self):
        # Entries a root run creates below CARGO_TARGET_TMPDIR stay root-owned
        # for later unprivileged steps and the build cache. The native nbdkit
        # tests get their plugin path from run_cargo_tests.py, not from here.
        for target in runner.ROOT_TARGETS:
            for path in target_sources(target):
                text = path.read_text(encoding="utf-8")
                self.assertNotIn("CARGO_TARGET_TMPDIR", text, path)
                self.assertNotIn("native_plugin", text, path)

    def test_the_scan_sees_each_way_a_test_probes_its_privilege(self):
        for line in ("unsafe { libc::geteuid() == 0 }",
                     "if unsafe { libc::getuid() } != 0 {",
                     'eprintln!("needs root to chown the fixture; skipping");',
                     'eprintln!("{test}: skipped: files of another user need root");',
                     "std::os::unix::fs::lchown(path, Some(uid), Some(gid)).unwrap();",
                     "if libc::unshare(libc::CLONE_NEWNS) != 0",
                     'let usable = Command::new("unshare")',
                     'let uid = Command::new("id").arg("-u").output().unwrap();'):
            with self.subTest(line=line):
                self.assertRegex(line, PRIVILEGE_PROBE)
        with tempfile.TemporaryDirectory() as directory:
            production = Path(directory) / "crates" / "fixture" / "src" / "owner.rs"
            production.parent.mkdir(parents=True)
            with mock.patch.object(sys.modules[__name__], "ROOT", Path(directory)):
                production.write_text(
                    "fn euid() -> u32 { unsafe { libc::geteuid() } }\n"
                    "#[cfg(test)]\nextern crate self as fixture;\n")
                self.assertEqual(unit_test_code(production), "")
                production.write_text(
                    "fn euid() -> u32 { 0 }\n\n#[cfg(all(test, unix))]\nmod tests {\n"
                    "    #[test]\n    fn t() { if unsafe { libc::geteuid() } != 0 { return; } }\n}\n")
                self.assertIn("geteuid", unit_test_code(production))
                self.assertNotIn("fn euid", unit_test_code(production))
                production.write_text("use super::*;\n#[test]\nfn t() { libc::geteuid(); }\n")
                self.assertIn("geteuid", unit_test_code(production))

    def test_the_pull_request_job_runs_them_from_the_workspace_compilation(self):
        workflow = WORKFLOW.read_text()
        jobs = dict(re.findall(r"(?ms)^  ([\w-]+):\n(.*?)(?=^  [\w-]+:|\Z)", workflow))
        pull_request = jobs["pr"]
        self.assertNotRegex(pull_request, r"(?m)^    if:")
        self.assertNotIn("continue-on-error", pull_request)
        # The same cargo selection as the unprivileged run: nothing is
        # rebuilt, and the tests run with the features they were built with.
        self.assertIn(WORKSPACE_TESTS, pull_request)
        self.assertIn(STEP, pull_request)
        self.assertLess(pull_request.index(WORKSPACE_TESTS), pull_request.index(STEP))
        self.assertEqual(workflow.count("scripts/run_root_tests.py"), 1)


TEST_BINARY = '''#!{python} -B
import json, os, stat, sys
record = {{"target": {target!r}, "cwd": os.getcwd(), "arguments": sys.argv[1:],
          "environment": dict(os.environ),
          "scratch": stat.S_IMODE(os.stat(os.environ["TMPDIR"]).st_mode),
          "build": stat.S_IMODE(os.stat({build!r}).st_mode)}}
with open({log!r}, "a") as log:
    log.write(json.dumps(record) + "\\n")
sys.stdout.write({output!r})
sys.exit({status})
'''

SUDO = '''#!{python} -B
import json, os, sys
with open({log!r}, "a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\\n")
if os.environ.get("FIXTURE_SUDO") == "password":
    sys.exit("sudo: a password is required")
assert sys.argv[1] == "-n", sys.argv
if sys.argv[2:] == ["id", "-u"]:
    print(os.environ.get("FIXTURE_SUDO", "0"))
    sys.exit(0)
os.execvp(sys.argv[2], sys.argv[2:])
'''

CARGO = '''#!{python} -B
import json, sys
with open({log!r}, "a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\\n")
sys.stdout.write(open({events!r}).read())
sys.exit({status})
'''

PASSED = "\nrunning 1 test\ntest case ... ok\n\ntest result: ok. 1 passed; 0 failed\n"


def with_output(text):
    return ("\nrunning 1 test\ntest case ... ok\n\nsuccesses:\n\n---- case stdout ----\n"
            f"{text}\n\nsuccesses:\n    case\n\ntest result: ok. 1 passed; 0 failed\n")


@unittest.skipUnless(sys.platform.startswith("linux"), "the root-only targets are Linux-only")
class RootRunner(unittest.TestCase):
    def setUp(self):
        # The fixture build tree is one other users can reach, whatever the
        # caller's umask.
        self.addCleanup(os.umask, os.umask(0o022))
        temporary = tempfile.TemporaryDirectory(prefix="maki-root-runner-", dir=runner.SCRATCH_PARENT)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o755)
        self.tools = self.root / "tools"
        self.build = self.root / "target"
        (self.build / "debug" / "deps").mkdir(parents=True)
        (self.build / "CACHEDIR.TAG").write_text("Signature: 8a477f597d28d172789f06886806bc55\n")
        self.tools.mkdir()
        self.logs = {name: self.root / f"{name}.jsonl" for name in ("cargo", "sudo", "tests")}
        self.events = self.root / "events.jsonl"
        self.binary = self.build / "debug" / "maki"
        self.script(self.binary, "#!/bin/sh\n")
        self.script(self.tools / "sudo", SUDO.format(python=sys.executable, log=str(self.logs["sudo"])))
        self.compile()
        environment = {"PATH": f"{self.tools}{os.pathsep}{os.environ['PATH']}",
                       "MAKI_FIXTURE_MARKER": "inherited", "RUST_BACKTRACE": "0"}
        for patch in (mock.patch.dict(os.environ, environment),
                      mock.patch.object(runner, "owned_by", return_value=set())):
            patch.start()
            self.addCleanup(patch.stop)
        os.environ.pop("CARGO", None)
        os.environ.pop("RUST_TEST_THREADS", None)

    @staticmethod
    def script(path, text):
        path.write_text(text)
        path.chmod(0o755)

    def compile(self, omit=(), outputs=None, statuses=None, status=0):
        """A compilation that reports every listed target (but `omit`) and one binary."""
        events = [
            {"reason": "compiler-message", "message": {"rendered": "warning: fixture\n"}},
            {"reason": "compiler-artifact", "target": {"kind": ["lib"], "src_path": str(
                ROOT / "crates/maki-privileged/src/lib.rs")}, "profile": {"test": False},
             "manifest_path": str(ROOT / "crates/maki-privileged/Cargo.toml"), "executable": None},
            {"reason": "compiler-artifact", "target": {"kind": ["bin"], "src_path": str(
                ROOT / "bins/maki/src/main.rs")}, "profile": {"test": False},
             "manifest_path": str(ROOT / "bins/maki/Cargo.toml"), "executable": str(self.binary)},
            {"reason": "build-finished", "success": True},
        ]
        for index, target in enumerate(runner.ROOT_TARGETS):
            if target in omit:
                continue
            executable = self.build / "debug" / "deps" / f"target-{index}"
            self.script(executable, TEST_BINARY.format(
                python=sys.executable, target=target, build=str(self.build),
                log=str(self.logs["tests"]), output=(outputs or {}).get(target, PASSED),
                status=(statuses or {}).get(target, 0)))
            kind = "lib" if "/src/" in target else "test"
            events.append({"reason": "compiler-artifact", "profile": {"test": True},
                           "target": {"kind": [kind], "src_path": str(ROOT / target)},
                           "manifest_path": str(ROOT / Path(*Path(target).parts[:2]) / "Cargo.toml"),
                           "executable": str(executable)})
        self.events.write_text("".join(json.dumps(event) + "\n" for event in events))
        self.script(self.tools / "cargo", CARGO.format(
            python=sys.executable, log=str(self.logs["cargo"]), events=str(self.events),
            status=status))

    def log(self, name):
        path = self.logs[name]
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def invoke(self, *arguments, euid=1000):
        self.output, self.errors = io.StringIO(), io.StringIO()
        with mock.patch.object(runner.os, "geteuid", return_value=euid), \
                contextlib.redirect_stdout(self.output), contextlib.redirect_stderr(self.errors):
            return runner.run(arguments or ["--workspace", "--locked"])

    def test_an_unprivileged_caller_compiles_as_itself_and_runs_each_target_through_sudo(self):
        status = self.invoke("--workspace", "--locked", "--", "--test-threads=2")
        self.assertEqual(status, 0, self.output.getvalue() + self.errors.getvalue())
        self.assertEqual(self.log("cargo"), [
            ["test", "--workspace", "--locked", "--no-run", "--message-format=json"]])
        runs = self.log("tests")
        self.assertEqual([run["target"] for run in runs], list(runner.ROOT_TARGETS))
        sudo = self.log("sudo")
        self.assertEqual(sudo[0], ["-n", "id", "-u"])
        self.assertEqual(len(sudo), len(runs) + 2)
        scratch = runs[0]["environment"]["TMPDIR"]
        self.assertEqual(sudo[-1], ["-n", "rm", "-rf", "--", scratch])
        self.assertFalse(Path(scratch).exists())
        self.assertEqual(Path(scratch).parent, Path(runner.SCRATCH_PARENT))
        for run, call, target in zip(runs, sudo[1:-1], runner.ROOT_TARGETS):
            package = str(ROOT / Path(*Path(target).parts[:2]))
            self.assertEqual(call[:3], ["-n", "env", "-i"])
            self.assertEqual(call[-2:], ["--show-output", "--test-threads=2"])
            self.assertEqual(run["arguments"], ["--show-output", "--test-threads=2"])
            self.assertEqual(run["cwd"], package)
            environment = run["environment"]
            self.assertEqual(environment["CARGO_MANIFEST_DIR"], package)
            self.assertEqual(environment["PATH"], os.environ["PATH"])
            self.assertEqual(environment["TMPDIR"], scratch)
            self.assertEqual(environment["RUST_BACKTRACE"], "0")
            self.assertNotIn("MAKI_FIXTURE_MARKER", environment)
            # Fixture users must be able to search the scratch directory.
            self.assertEqual(run["scratch"], 0o755)
        self.assertIn("warning: fixture", self.errors.getvalue())
        self.assertIn(f"{len(runs)} of {len(runs)} targets passed as root", self.output.getvalue())

    def test_a_root_caller_runs_the_targets_directly(self):
        self.assertEqual(self.invoke(euid=0), 0, self.errors.getvalue())
        self.assertEqual(self.log("sudo"), [])
        self.assertEqual(len(self.log("tests")), len(runner.ROOT_TARGETS))

    def test_without_root_nothing_is_compiled_or_run(self):
        for case, environment in (("password", {"FIXTURE_SUDO": "password"}),
                                  ("another user", {"FIXTURE_SUDO": "1000"}),
                                  ("no sudo", {"PATH": str(self.root / "empty")})):
            with self.subTest(case=case), mock.patch.dict(os.environ, environment):
                self.assertNotEqual(self.invoke(), 0)
                self.assertIn("not run without it", self.errors.getvalue())
                self.assertEqual(self.log("cargo"), [])
                self.assertEqual(self.log("tests"), [])

    def test_a_compilation_without_a_listed_target_runs_nothing(self):
        missing = runner.ROOT_TARGETS[3]
        self.compile(omit=(missing,))
        self.assertNotEqual(self.invoke("--locked", "-p", "maki-backing"), 0)
        self.assertIn(missing, self.errors.getvalue())
        self.assertEqual(self.log("tests"), [])
        self.compile(status=101)
        self.assertEqual(self.invoke(), 101)
        self.assertEqual(self.log("tests"), [])

    def test_one_failing_target_fails_the_run_without_hiding_the_others(self):
        failing = runner.ROOT_TARGETS[1]
        self.compile(statuses={failing: 101})
        self.assertEqual(self.invoke(), 1)
        self.assertEqual(len(self.log("tests")), len(runner.ROOT_TARGETS))
        self.assertIn(f"failed as root: {failing}\n", self.errors.getvalue())
        self.assertIn(f"{len(runner.ROOT_TARGETS) - 1} of {len(runner.ROOT_TARGETS)} targets",
                      self.output.getvalue())
        self.assertEqual(self.log("sudo")[-1][:3], ["-n", "rm", "-rf"])

    def test_skip_notices_are_listed_and_one_that_blames_root_fails_the_run(self):
        target = runner.ROOT_TARGETS[2]
        self.compile(outputs={target: with_output("skipped: no single cgroup-v2 mount here")})
        self.assertEqual(self.invoke(), 0, self.errors.getvalue())
        self.assertIn(f"still reported as skipped (see docs/testing.md):\n  {target}: case: "
                      "skipped: no single cgroup-v2 mount here\n", self.output.getvalue())
        # A test that is only named after skipping reported nothing.
        self.compile(outputs={target: with_output("done").replace("case", "list_skipping_x")})
        self.assertEqual(self.invoke(), 0, self.errors.getvalue())
        self.assertIn("still reported as skipped (see docs/testing.md):\n  nothing\n",
                      self.output.getvalue())
        self.compile(outputs={target: with_output("needs root to chown the fixture; skipping")})
        self.assertEqual(self.invoke(), 1)
        self.assertIn(f"ran as root, but a test reports that it needs root:\n  {target}: case: "
                      "needs root to chown the fixture; skipping\n", self.errors.getvalue())

    def test_a_build_tree_closed_to_other_users_is_refused_or_opened_for_the_run(self):
        self.build.chmod(0o750)
        self.binary.chmod(0o750)
        self.assertNotEqual(self.invoke(), 0)
        self.assertIn(f"closed to other users: {self.build}, {self.binary} ", self.errors.getvalue())
        self.assertEqual(self.log("tests"), [])
        self.assertEqual(self.log("sudo")[-1][:3], ["-n", "rm", "-rf"])
        self.assertEqual(self.invoke("--open-build-tree", "--workspace", "--locked"), 0,
                         self.errors.getvalue())
        self.assertEqual(self.log("cargo")[-1][:3], ["test", "--workspace", "--locked"])
        self.assertIn(["-n", "chmod", "o+x", "--", str(self.build)], self.log("sudo"))
        self.assertEqual({run["build"] for run in self.log("tests")}, {0o751})
        self.assertEqual(stat.S_IMODE(self.build.stat().st_mode), 0o750)
        self.assertEqual(stat.S_IMODE(self.binary.stat().st_mode), 0o750)

    def test_entries_left_owned_by_root_fail_the_run(self):
        left = str(self.build / "tmp" / "mount-target-ok")
        with mock.patch.object(runner, "owned_by", side_effect=[{"/old"}, {"/old", left}]) as scan:
            self.assertEqual(self.invoke(), 1)
        self.assertIn(f"left entries owned by root, which later unprivileged steps and the "
                      f"build cache cannot replace:\n  {left}\n", self.errors.getvalue())
        self.assertEqual(scan.call_args.args, (0, {ROOT, self.build}))
        # A root caller owns its whole tree: there is nothing to compare.
        with mock.patch.object(runner, "owned_by", side_effect=[set(), set()]) as scan:
            self.assertEqual(self.invoke(euid=0), 0, self.errors.getvalue())
        self.assertEqual(scan.call_args.args, (0, set()))

    def test_options_this_script_sets_are_refused(self):
        for option in ("--no-run", "--message-format=short"):
            with self.subTest(option=option):
                self.assertNotEqual(self.invoke("--workspace", option), 0)
                self.assertEqual(self.log("cargo"), [])


class OwnershipScan(unittest.TestCase):
    def test_finds_every_entry_of_one_owner_below_the_trees(self):
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory) / "target"
            (tree / "tmp" / "mount-target-ok").mkdir(parents=True)
            (tree / "tmp" / "mount-target-ok" / "data").write_text("")
            (tree / "link").symlink_to("/nonexistent")
            mine = {str(tree), *(str(path) for path in tree.rglob("*"))}
            self.assertEqual(len(mine), 5)
            self.assertEqual(runner.owned_by(os.getuid(), {tree}), mine)
            self.assertEqual(runner.owned_by(os.getuid() + 1, {tree}), set())
            self.assertEqual(runner.owned_by(os.getuid(), set()), set())

    def test_the_build_tree_is_the_directory_cargo_tagged(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve() / "target"
            (target / "debug" / "deps").mkdir(parents=True)
            (target / "CACHEDIR.TAG").write_text("")
            self.assertEqual(runner.build_tree([target / "debug" / "maki",
                                                target / "debug" / "deps" / "test-1"]), {target})
            untagged = Path(directory).resolve() / "elsewhere" / "maki"
            self.assertEqual(runner.build_tree([untagged]), {untagged.parent})


if __name__ == "__main__":
    unittest.main()
