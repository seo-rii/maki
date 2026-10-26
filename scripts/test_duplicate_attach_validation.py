"""Duplicate-attach qualification using real shell control flow and local peers.

The nbdkit fixture models its listener precheck before the volume-lock error.
No plugin, kernel NBD, sudo, LVM, mount, or cloud operation is performed.
"""
import json
import os
import pathlib
import shutil
import signal
import subprocess
import tempfile
import tomllib
import unittest


# Startup::run -> AdapterError's Display -> RecoveryError::AlreadyAttached.
LOCK_ERROR = "maki-nbdkit: startup failed: adapter error (errno 5): VOLUME_ALREADY_ATTACHED"
PASS = "PASS: duplicate volume attach fails closed"


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "Bash and POSIX processes")
class DuplicateAttachQualification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        script = pathlib.Path(__file__).with_name("privileged-linux-validation.sh").read_text()
        start = script.index('config_path="$run_dir/volume.toml"\n')
        cls.generation = script[start:script.index('\nif [[ "$discard" == true ]]; then', start)]
        start = script.index("stop_process_normally() {\n")
        cls.stop = script[start:script.index("\n}\n", start) + 3]
        start = script.index("cleanup() {\n")
        cls.cleanup = script[start:script.index("\n}\n", start) + 3]
        start = script.index('duplicate_socket="$work_dir/duplicate.sock"\n')
        marker = 'pass "duplicate volume attach fails closed"'
        cls.duplicate = script[start:script.index(marker, start) + len(marker)]

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="maki-duplicate-")
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        self.binary = self.root / "bin"
        self.binary.mkdir()
        fake = self.binary / "nbdkit"
        fake.write_text('''#!/usr/bin/env python3
import json
import os
import pathlib
import signal
import socket
import sys
import tomllib

listener = sys.argv[sys.argv.index("-U") + 1]
config_path = next(arg[7:] for arg in sys.argv if arg.startswith("config="))
config = tomllib.loads(pathlib.Path(config_path).read_text())
pathlib.Path(os.environ["OBSERVATION"]).write_text(json.dumps({
    "listener": listener, "config_path": config_path, "config": config,
    "pid": os.getpid(),
}))
mode = os.environ["REJECTION_MODE"]
lock_error = "maki-nbdkit: startup failed: adapter error (errno 5): VOLUME_ALREADY_ATTACHED"
if mode == "locked" and config["nbd"]["socket"] != listener:
    print("nbd.socket does not match the unique native pathname listener", file=sys.stderr)
    sys.exit(1)
if mode in ("live", "live-with-lock"):
    endpoint = socket.socket(socket.AF_UNIX)
    endpoint.bind(listener)
    endpoint.listen()
    if mode == "live-with-lock":
        print(lock_error, file=sys.stderr, flush=True)
    signal.pause()
if mode == "signal":
    print(lock_error, file=sys.stderr, flush=True)
    os.kill(os.getpid(), signal.SIGTERM)
messages = {
    "locked": lock_error,
    "forced-lock": lock_error,
    "successful-exit": lock_error,
    "other-status": lock_error,
    "listener": "nbd.socket does not match the unique native pathname listener",
    "plugin": "nbdkit: error: cannot open plugin: No such file or directory",
    "config": "maki-nbdkit: startup failed: cannot read config file",
    "control": "maki-nbdkit: startup failed: control socket already has a live listener",
    "empty": "",
    "unrelated-marker": "maki-nbdkit: startup failed: cannot read /VOLUME_ALREADY_ATTACHED",
}
print(messages[mode], file=sys.stderr)
sys.exit(0 if mode == "successful-exit" else 42 if mode == "other-status" else 1)
''')
        fake.chmod(0o700)
        client = self.binary / "nbdinfo"
        client.write_text("#!/bin/sh\nexit 1\n")
        client.chmod(0o700)

    def run_case(self, mode, *, directory_name="work", stale_log=False):
        case = self.root / mode
        case.mkdir()
        work = case / directory_name
        work.mkdir()
        run = case / "run"
        run.mkdir()
        observation = case / "observed.json"
        if stale_log:
            (run / "duplicate-nbdkit.log").write_text(LOCK_ERROR + "\n")
        environment = dict(os.environ, PATH=str(self.binary) + os.pathsep + os.environ["PATH"],
                           work_dir=str(work), run_dir=str(run), volume_name="duplicate-proof",
                           socket_path=str(case / "original.sock"),
                           control_socket_path=str(case / "original-control.sock"),
                           plugin_path=str(case / "not-loaded.so"),
                           OBSERVATION=str(observation), REJECTION_MODE=mode)
        setup = '''set -euo pipefail
log() { :; }
pass() { printf 'PASS: %s\\n' "$*"; }
die() { printf '%s\\n' "$*" >&2; exit 1; }
# Preserve polling/termination behavior while keeping the live-peer test brief.
sleep() { command sleep 0.01; }
nbdkit_launcher=()
duplicate_pid=""
'''
        program = (setup + self.stop + '\ntrap \'stop_process_normally "$duplicate_pid" fixture\' EXIT\n'
                   + self.generation + "\n" + self.duplicate)
        process = subprocess.Popen(["bash", "-c", program], env=environment,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
            self.fail("duplicate-attach fragment did not finish and clean up its child")
        result = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
        self.assertTrue(observation.exists(), result.stderr)
        observed = json.loads(observation.read_text())
        with self.assertRaises(ProcessLookupError, msg="the duplicate process must be reaped"):
            os.kill(observed["pid"], 0)
        return result, observed, tomllib.loads((run / "volume.toml").read_text())

    def assert_rejected(self, mode, **kwargs):
        result, _, _ = self.run_case(mode, **kwargs)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn(PASS, result.stdout)

    def assert_lock_configuration(self, **kwargs):
        result, observed, original = self.run_case("locked", **kwargs)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(PASS, result.stdout)
        duplicate = observed["config"]
        self.assertEqual(duplicate["nbd"]["socket"], observed["listener"])
        self.assertNotEqual(duplicate["nbd"]["socket"], original["nbd"]["socket"])
        self.assertNotEqual(duplicate["control"]["socket"], original["control"]["socket"])
        self.assertNotEqual(duplicate["control"]["socket"], duplicate["nbd"]["socket"])
        duplicate["nbd"]["socket"] = original["nbd"]["socket"]
        duplicate["control"]["socket"] = original["control"]["socket"]
        self.assertEqual(duplicate, original, "volume, key, backing and limits must be identical")

    def test_duplicate_has_matching_listener_and_preserves_volume_identity(self):
        self.assert_lock_configuration()

    def test_duplicate_configuration_preserves_quoted_unicode_paths(self):
        self.assert_lock_configuration(directory_name='운영 "archive" \\root')

    def test_exact_volume_lock_failure_control(self):
        result, _, _ = self.run_case("forced-lock")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(PASS, result.stdout)

    def test_unrelated_startup_failure_is_not_lock_evidence(self):
        for mode in ("listener", "plugin", "config", "control", "empty"):
            with self.subTest(mode=mode):
                self.assert_rejected(mode)

    def test_successful_exit_with_lock_text_is_not_lock_evidence(self):
        self.assert_rejected("successful-exit")

    def test_signal_exit_with_lock_text_is_not_lock_evidence(self):
        self.assert_rejected("signal")

    def test_unexpected_exit_status_with_lock_text_is_not_lock_evidence(self):
        self.assert_rejected("other-status")

    def test_unrelated_lock_marker_is_not_lock_evidence(self):
        self.assert_rejected("unrelated-marker")

    def test_stale_log_cannot_supply_lock_evidence(self):
        self.assert_rejected("plugin", stale_log=True)

    def test_live_duplicate_is_stopped_and_cannot_pass(self):
        for mode in ("live", "live-with-lock"):
            with self.subTest(mode=mode):
                self.assert_rejected(mode)

    def test_unstopped_duplicate_preserves_its_backing_during_cleanup(self):
        work = self.root / "maki-privileged-validation.fixture"
        work.mkdir()
        sentinel = work / "backing-data"
        sentinel.write_bytes(b"owned disposable backing")
        setup = '''set -euo pipefail
log() { :; }
stop_process_normally() { [[ "$1" != duplicate ]]; }
disconnect_test_nbd() { :; }
mount_active=false
mountpoint=""
vg_created=false
pv_created=false
cleanup_safe=true
duplicate_pid=duplicate
nbdkit_pid=primary
runtime_dir=""
runtime_parent_created=false
control_runtime_dir=""
control_runtime_parent_created=false
attach_config_dir=""
sudo_keeper_pid=""
'''
        finish = ('\ncleanup_rc=0\ncleanup || cleanup_rc=$?\n'
                  'printf "%s\\n" "$duplicate_pid"\nexit "$cleanup_rc"\n')
        result = subprocess.run(["bash", "-c", setup + self.cleanup + finish],
                                env=dict(os.environ, work_root=str(self.root), work_dir=str(work)),
                                capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(sentinel.exists(), "failed duplicate termination must preserve its backing")
        self.assertEqual(result.stdout.strip(), "duplicate", "retain the unfinished process identity")


if __name__ == "__main__":
    unittest.main()
