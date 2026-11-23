"""The scheduled job must run every ignored release gate to completion."""

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


if __name__ == "__main__":
    unittest.main()
