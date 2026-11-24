"""Exercise raw NBD ownership with mocked commands and private sysfs fixtures.

The shell fragments come from the runner, but sudo, the helper's raw NBD
verbs (maki-attach nbd-connect and nbd-disconnect), system locks, LVM, mounts,
and process cleanup are replaced. No kernel device is opened.
"""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("privileged-linux-validation.sh")
WRAPPER = Path(__file__).with_name("privileged_validation_nbd.py")
HELPER = "/not-opened/maki-attach"


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux shell validation runner")
class RawNbdOwnership(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = SCRIPT.read_text()
        start = source.index("nbd_has_pid() {\n")
        cls.functions = source[start:source.index("\ncleanup() {\n", start)]
        start = source.index('log "attaching the disposable export to $device"\n')
        cls.connect = source[start:source.index("\nfor _ in", start)]
        start = source.index("cleanup() {\n")
        cls.cleanup = source[start:source.index("\n}\n", start) + 3]
        start = source.index("finish() {\n")
        cls.finish = source[start:source.index("\n}\n", start) + 3]
        start = source.index('log "removing the disposable LVM metadata"\n')
        marker = 'pass "disposable LVM state removed"'
        cls.final_reconnect = source[start:source.index(marker, start) + len(marker)]
        start = source.index('log "running the real maki-attach helper"\n')
        cls.helper_attach = source[start:source.index("\nmount_active=true", start) + len("\nmount_active=true")]

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="maki-nbd-ownership-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sysfs = self.root / "sys/block/nbd15"
        self.sysfs.mkdir(parents=True)
        self.calls = self.root / "calls.jsonl"
        self.calls.write_text("")
        self.driver = self.root / "mock_sudo.py"
        self.driver.write_text('''import contextlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest import mock

root = Path(os.environ["FIXTURE"])
sysfs = root / "sys/block/nbd15"
def record(event):
    with (root / "calls.jsonl").open("a") as output:
        output.write(json.dumps(event) + "\\n")

def command(arguments, **kwargs):
    arguments = list(arguments)
    if arguments[0] == "vgs":
        assert (root / "locked").exists(), "VG observation outside attach lock"
        assert arguments == ["vgs", "--noheadings", "-o", "lv_count", "maki_validation_1000_42"]
        return subprocess.CompletedProcess(arguments, int(os.environ.get("VGS_RESULT", "0")),
                                           stdout=os.environ.get("LV_COUNT", "1"))
    if arguments[0] in ("vgchange", "lvremove", "vgremove", "pvremove"):
        assert (root / "locked").exists(), "LVM mutation outside attach lock"
        record(["lvm", *arguments])
        if os.environ.get("FAIL_REMOVAL") == arguments[0]:
            return subprocess.CompletedProcess(arguments, 5)
        if os.environ.get("REPLACE_AFTER_LVM") == arguments[0]:
            (sysfs / "backend").write_text("foreign\\n")
        return subprocess.CompletedProcess(arguments, 0)
    assert arguments[0] == "/not-opened/maki-attach", arguments
    assert arguments[1] in ("nbd-connect", "nbd-disconnect"), arguments
    assert arguments[arguments.index("--nbd-device") + 1] == "/dev/nbd15", arguments
    if arguments[1] == "nbd-disconnect":
        backend = (sysfs / "backend").read_text().strip() if (sysfs / "backend").exists() else "missing"
        record(["disconnect", backend])
        (sysfs / "pid").unlink(missing_ok=True)
        (sysfs / "backend").unlink(missing_ok=True)
        return subprocess.CompletedProcess(arguments, 0)
    assert arguments[arguments.index("--block-size") + 1] == "4096", arguments
    identifier = arguments[arguments.index("--identifier") + 1] if "--identifier" in arguments else "unidentified"
    record(["connect", identifier])
    mode = os.environ["CONNECT_MODE"]
    if mode != "failed-empty":
        (sysfs / "pid").write_text("12345\\n")
        (sysfs / "backend").write_text(("foreign" if mode == "failed-foreign" else identifier) + "\\n")
    return subprocess.CompletedProcess(arguments, 0 if mode == "success" else 1)

@contextlib.contextmanager
def fixture_lock():
    assert not (root / "locked").exists(), "recursive attach lock"
    (root / "locked").write_text("held")
    record(["lock"])
    try:
        yield
    finally:
        record(["unlock"])
        (root / "locked").unlink()

args = sys.argv[1:]
assert args.pop(0) == "-n"
if args[0] == "env":
    assert not (root / "locked").exists(), "helper called while raw lock is held"
    assert args[2] == "/not-opened/maki-attach", args
    action = args[3]
    assert action in ("attach", "cleanup"), args
    record(["helper", action])
    if action == "attach":
        (sysfs / "pid").write_text("12345\\n")
        (sysfs / "backend").write_text("helper-identity\\n")
    elif os.environ.get("HELPER_CLEANUP_RESULT", "0") == "0":
        (sysfs / "pid").unlink(missing_ok=True)
        (sysfs / "backend").unlink(missing_ok=True)
    sys.exit(int(os.environ.get("HELPER_" + action.upper() + "_RESULT", "0")))
assert args.pop(0) == "python3", args
wrapper = args.pop(0)
assert Path(wrapper) == Path(os.environ["WRAPPER"]), wrapper
spec = importlib.util.spec_from_file_location("validation_nbd", wrapper)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
with mock.patch.object(module, "attach_lock", fixture_lock), \\
        mock.patch.object(module, "SYSFS", root / "sys/block"), \\
        mock.patch.object(module.subprocess, "run", command):
    sys.exit(module.main(args))
''')

    def run_case(self, mode="success", *, before="", after="", attempt=True,
                 full_cleanup=False):
        setup = r'''set -Eeuo pipefail
export PATH=/__maki_no_external_commands__
nbd_connected=false
nbd_connection_attempted=false
nbd_connection_id=""
helper_cleanup_needed=false
device=/dev/nbd15
nbd_target=nbd15
socket_path=/not-opened/fixture.sock
run_dir="$FIXTURE"
status_path="$FIXTURE/status"
pass_count=0
attach_bin=/not-opened/maki-attach
attach_config_path=/not-opened/attach.toml
volume_name=privval-1000-42
vg_name=maki_validation_1000_42
lv_name=data
mount_active=false
mountpoint=""
vg_created=false
lv_created=false
pv_created=false
cleanup_safe=true
nbdkit_pid=fixture
duplicate_pid=""
sudo_keeper_pid=""
runtime_dir=""
runtime_parent_created=false
control_runtime_dir=""
control_runtime_parent_created=false
attach_config_dir=""
work_dir=""
log() { :; }
pass() { :; }
date() { printf 'fixture-time\n'; }
basename() { printf '%s\n' "$nbd_target"; }
python3() { "$PYTHON" "$@"; }
sudo() { "$PYTHON" "$DRIVER" "$@"; }
findmnt() { return 1; }
kill() { [[ "$1" == -0 ]]; }
stop_process_normally() { printf '["stop", "%s"]\n' "$1" >> "$FIXTURE/calls.jsonl"; }
'''
        functions = self.functions.replace('"/sys/block/', '"' + str(self.root) + '/sys/block/')
        body = setup + functions + "\n" + self.cleanup + "\n" + self.finish + "\n" + before + "\n"
        body += "trap '" + ("finish" if full_cleanup else "disconnect_test_nbd") + "' EXIT\n"
        if attempt:
            body += self.connect + "\n"
        body += after + "\n"
        result = subprocess.run(["/bin/bash", "-c", body],
                                env=dict(os.environ, FIXTURE=str(self.root),
                                         # The driver imports the wrapper from scripts/.
                                         PYTHONDONTWRITEBYTECODE="1",
                                         CONNECT_MODE=mode, PYTHON=sys.executable,
                                         WRAPPER=str(WRAPPER), DRIVER=str(self.driver),
                                         REPO_ROOT=str(SCRIPT.parent.parent)),
                                stdin=subprocess.DEVNULL, text=True,
                                capture_output=True, timeout=5)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        return result, calls

    def test_fixture_interpreters_write_no_bytecode_next_to_the_wrapper(self):
        bytecode = (WRAPPER.with_name("__pycache__"), WRAPPER.stem + ".*")
        for stale in bytecode[0].glob(bytecode[1]):
            stale.unlink()
        result, calls = self.run_case()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any(call[0] == "connect" for call in calls), calls)
        self.assertEqual(list(bytecode[0].glob(bytecode[1])), [], "the driver compiled into the checkout")

    def device_state(self, backend):
        (self.sysfs / "pid").write_text("12345\n")
        if backend is not None:
            (self.sysfs / "backend").write_text(backend + "\n")

    def test_bug197_failed_connect_does_not_disconnect_foreign_backend(self):
        result, calls = self.run_case("failed-foreign")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[0] == "disconnect" for call in calls), calls)
        self.assertEqual((self.sysfs / "backend").read_text().strip(), "foreign")

    def test_bug197_replaced_connection_is_not_disconnected(self):
        result, calls = self.run_case(after='printf "foreign\\n" > "$FIXTURE/sys/block/nbd15/backend"')
        self.assertFalse(any(call[0] == "disconnect" for call in calls), calls)
        self.assertEqual((self.sysfs / "backend").read_text().strip(), "foreign")
        self.assertNotEqual(result.returncode, 0)

    def test_partial_own_connection_is_disconnected(self):
        result, calls = self.run_case("failed-own")
        self.assertNotEqual(result.returncode, 0)
        connected = [call[1] for call in calls if call[0] == "connect"]
        self.assertEqual([call for call in calls if call[0] == "disconnect"],
                         [["disconnect", connected[0]]])

    def test_failed_connect_without_connection_needs_no_disconnect(self):
        result, calls = self.run_case("failed-empty")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[0] == "disconnect" for call in calls), calls)

    def test_no_attempt_does_not_touch_foreign_connection(self):
        self.device_state("foreign")
        result, calls = self.run_case(attempt=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [])

    def test_raw_connect_sets_unique_backend_identifier(self):
        result, calls = self.run_case()
        self.assertEqual(result.returncode, 0, result.stderr)
        identifiers = [call[1] for call in calls if call[0] == "connect"]
        self.assertEqual(len(identifiers), 1)
        self.assertRegex(identifiers[0], r"^maki-privval-[0-9a-f-]{36}$")
        self.assertEqual([call for call in calls if call[0] == "disconnect"],
                         [["disconnect", identifiers[0]]])

    def test_pid_only_foreign_connection_is_preserved(self):
        self.device_state(None)
        result, calls = self.run_case()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[0] in ("connect", "disconnect") for call in calls), calls)
        self.assertTrue((self.sysfs / "pid").exists())

    def test_cleanup_reconnects_and_removes_only_owned_lvm(self):
        result, calls = self.run_case(attempt=False, full_cleanup=True,
                                      before="lv_created=true\nvg_created=true\npv_created=true")
        self.assertEqual(result.returncode, 0, result.stderr)
        connects = [call[1] for call in calls if call[0] == "connect"]
        self.assertEqual(len(connects), 1)
        self.assertEqual([call[1] for call in calls if call[0] == "lvm"],
                         ["vgchange", "lvremove", "vgremove", "pvremove"])
        self.assertEqual([call for call in calls if call[0] == "disconnect"],
                         [["disconnect", connects[0]]])

    def test_failed_lvm_removal_preserves_the_lower_storage_layers(self):
        for removal in ("lvremove", "vgremove", "pvremove"):
            with self.subTest(removal=removal):
                self.calls.write_text("")
                self.sysfs.joinpath("pid").unlink(missing_ok=True)
                self.sysfs.joinpath("backend").unlink(missing_ok=True)
                result, calls = self.run_case(attempt=False, full_cleanup=True,
                    before=f"export FAIL_REMOVAL={removal}\nlv_created=true\nvg_created=true\npv_created=true")
                self.assertNotEqual(result.returncode, 0)
                lvm = [call[1] for call in calls if call[0] == "lvm"]
                self.assertEqual(lvm[-1], removal)
                self.assertFalse(any(call[0] in ("disconnect", "stop") for call in calls), calls)

    def test_cleanup_after_failed_lvcreate_can_release_a_proven_empty_vg(self):
        for output, status, empty in (("  0", 0, True), ("0", 5, False), ("", 0, False)):
            with self.subTest(output=output, status=status):
                self.calls.write_text("")
                self.sysfs.joinpath("pid").unlink(missing_ok=True)
                self.sysfs.joinpath("backend").unlink(missing_ok=True)
                result, calls = self.run_case(attempt=False, full_cleanup=True,
                    before=(f"export FAIL_REMOVAL=lvremove VGS_RESULT={status} LV_COUNT='{output}'\n"
                            "lv_created=true\nvg_created=true\npv_created=true"))
                self.assertEqual(result.returncode == 0, empty, result.stderr)
                removals = [call[1] for call in calls if call[0] == "lvm"]
                self.assertEqual(removals, ["vgchange", "lvremove"] +
                                 (["vgremove", "pvremove"] if empty else []))
                self.assertEqual(any(call[0] == "disconnect" for call in calls), empty)

    def test_cleanup_refuses_foreign_backend_before_lvm_or_disconnect(self):
        self.device_state("foreign")
        result, calls = self.run_case(attempt=False, full_cleanup=True,
                                      before="lv_created=true\nvg_created=true\npv_created=true")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[0] in ("connect", "disconnect", "lvm", "stop")
                             for call in calls), calls)

    def test_cleanup_reconnect_partial_failure_disconnects_own_backend(self):
        result, calls = self.run_case("failed-own", attempt=False, full_cleanup=True,
                                      before="lv_created=true\nvg_created=true\npv_created=true")
        self.assertNotEqual(result.returncode, 0)
        identifier = next(call[1] for call in calls if call[0] == "connect")
        self.assertEqual([call for call in calls if call[0] == "disconnect"],
                         [["disconnect", identifier]])
        self.assertFalse(any(call[0] in ("lvm", "stop") for call in calls), calls)

    def test_final_reconnect_uses_fresh_identity(self):
        result, calls = self.run_case(after="disconnect_test_nbd\n" + self.final_reconnect)
        self.assertEqual(result.returncode, 0, result.stderr)
        identifiers = [call[1] for call in calls if call[0] == "connect"]
        self.assertEqual(len(set(identifiers)), 2)
        self.assertEqual([call for call in calls if call[0] == "disconnect"],
                         [["disconnect", identifier] for identifier in identifiers])

    def test_final_reconnect_failure_cannot_disconnect_foreign_backend(self):
        result, calls = self.run_case(after='disconnect_test_nbd\nexport CONNECT_MODE=failed-foreign\n'
                                      + self.final_reconnect)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(["disconnect", "foreign"], calls)
        self.assertFalse(any(call[0] == "lvm" for call in calls), calls)

    def test_backend_replaced_between_lvm_steps_stops_further_changes(self):
        result, calls = self.run_case(after='export REPLACE_AFTER_LVM=vgchange\n'
                                      + self.final_reconnect)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([call[1] for call in calls if call[0] == "lvm"], ["vgchange"])
        self.assertNotIn(["disconnect", "foreign"], calls)

    def test_helper_handoff_keeps_the_helper_identifier_out_of_raw_cleanup(self):
        result, calls = self.run_case(full_cleanup=True,
                                      after="disconnect_test_nbd\n" + self.helper_attach)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call for call in calls if call[0] == "helper"],
                         [["helper", "attach"], ["helper", "cleanup"]])
        self.assertNotIn(["disconnect", "helper-identity"], calls)

    def test_failed_helper_attach_uses_helper_cleanup(self):
        result, calls = self.run_case(attempt=False, full_cleanup=True,
                                      after="export HELPER_ATTACH_RESULT=1\n" + self.helper_attach)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([call for call in calls if call[0] == "helper"],
                         [["helper", "attach"], ["helper", "cleanup"]])
        self.assertFalse(any(call[0] == "disconnect" for call in calls), calls)

    def test_failed_helper_cleanup_preserves_attachment_and_process(self):
        result, calls = self.run_case(attempt=False, full_cleanup=True,
                                      after="export HELPER_CLEANUP_RESULT=1\n" + self.helper_attach)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[0] in ("connect", "disconnect", "lvm", "stop")
                             for call in calls), calls)
        self.assertEqual((self.sysfs / "backend").read_text().strip(), "helper-identity")


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux attach lock and sysfs")
class LockedNbdOperations(unittest.TestCase):
    identifier = "maki-privval-11111111-2222-3333-4444-555555555555"

    def setUp(self):
        spec = importlib.util.spec_from_file_location("validation_nbd", WRAPPER)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        temporary = tempfile.TemporaryDirectory(prefix="maki-nbd-locked-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sysfs = self.root / "sys/block/nbd15"
        self.sysfs.mkdir(parents=True)
        patcher = mock.patch.object(self.module, "SYSFS", self.sysfs.parent)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.events = []

    @contextlib.contextmanager
    def lock(self):
        self.events.append("lock")
        try:
            yield
        finally:
            self.events.append("unlock")

    def invoke(self, action, **kwargs):
        options = ["--device", "/dev/nbd15", "--identifier", self.identifier, "--helper", HELPER,
                   action]
        for key, value in kwargs.items():
            options += ["--" + key, value]
        with mock.patch.object(self.module, "attach_lock", self.lock), \
                mock.patch.object(self.module.subprocess, "run") as command, \
                contextlib.redirect_stderr(io.StringIO()):
            command.return_value = subprocess.CompletedProcess([], 0)
            result = self.module.main(options)
        return result, command

    def test_missing_or_empty_backend_with_pid_refuses_every_mutation(self):
        (self.sysfs / "pid").write_text("12345\n")
        for value in (None, "", "\n"):
            if value is not None:
                (self.sysfs / "backend").write_text(value)
            for action, options in (("connect", {"socket": "/not-opened/nbd.sock"}),
                                    ("disconnect", {}), ("remove-pv", {})):
                with self.subTest(backend=value, action=action):
                    result, command = self.invoke(action, **options)
                    self.assertNotEqual(result, 0)
                    command.assert_not_called()

    def test_unreadable_backend_is_not_treated_as_absent(self):
        with mock.patch.object(Path, "open", side_effect=PermissionError("fixture unreadable")):
            for action in ("disconnect", "remove-pv"):
                result, command = self.invoke(action)
                self.assertNotEqual(result, 0)
                command.assert_not_called()

    def test_unreadable_pid_is_not_treated_as_absent(self):
        with mock.patch.object(Path, "lstat", side_effect=PermissionError("fixture unreadable")):
            result, command = self.invoke("connect", socket="/not-opened/nbd.sock")
        self.assertNotEqual(result, 0)
        command.assert_not_called()

    def test_missing_sysfs_device_refuses_connect(self):
        self.sysfs.rmdir()
        result, command = self.invoke("connect", socket="/not-opened/nbd.sock")
        self.assertNotEqual(result, 0)
        command.assert_not_called()

    def test_foreign_backend_refuses_all_cleanup_commands(self):
        (self.sysfs / "backend").write_text("foreign\n")
        for action in ("disconnect", "activate-vg", "remove-lv", "remove-vg", "remove-pv"):
            with self.subTest(action=action):
                result, command = self.invoke(action, vg="maki_validation_1000_42", lv="data")
                self.assertNotEqual(result, 0)
                command.assert_not_called()

    def test_connect_exit_zero_without_identifier_is_not_ownership_proof(self):
        result, command = self.invoke("connect", socket="/not-opened/nbd.sock")
        self.assertNotEqual(result, 0)
        command.assert_called_once()

    def test_disconnect_exit_zero_with_live_backend_retains_failure(self):
        (self.sysfs / "backend").write_text(self.identifier + "\n")
        result, command = self.invoke("disconnect")
        self.assertNotEqual(result, 0)
        command.assert_called_once_with([HELPER, "nbd-disconnect", "--nbd-device", "/dev/nbd15",
                                         "--identifier", self.identifier])

    def test_owned_lvm_command_is_issued_inside_shared_lock(self):
        (self.sysfs / "backend").write_text(self.identifier + "\n")
        def command(arguments):
            self.assertEqual(self.events, ["lock"])
            self.events.append(arguments)
            return subprocess.CompletedProcess(arguments, 0)
        with mock.patch.object(self.module, "attach_lock", self.lock), \
                mock.patch.object(self.module.subprocess, "run", command):
            result = self.module.main(["--device", "/dev/nbd15", "--identifier", self.identifier,
                                       "--helper", HELPER, "remove-pv"])
        self.assertEqual(result, 0)
        self.assertEqual(self.events, ["lock", ["pvremove", "--yes", "--force", "/dev/nbd15"], "unlock"])

    def test_lock_failure_prevents_backend_probe_and_mutation(self):
        with mock.patch.object(self.module, "attach_lock", side_effect=PermissionError("fixture")), \
                mock.patch.object(self.module, "backend") as backend, \
                mock.patch.object(self.module.subprocess, "run") as command, \
                contextlib.redirect_stderr(io.StringIO()):
            result = self.module.main(["--device", "/dev/nbd15", "--identifier", self.identifier,
                                       "--helper", HELPER, "disconnect"])
        self.assertNotEqual(result, 0)
        backend.assert_not_called()
        command.assert_not_called()

    def test_private_fixture_lock_uses_flock_and_preserves_existing_inode(self):
        (self.root / "run").mkdir(mode=0o755)
        with mock.patch.object(self.module.fcntl, "flock") as flock:
            with self.module.attach_lock(self.root, os.getuid()):
                lock = self.root / "run/maki-attach/attach.lock"
                inode = lock.stat().st_ino
                self.assertEqual(lock.stat().st_mode & 0o777, 0o600)
                flock.assert_called_once()
                self.assertEqual(flock.call_args.args[1], self.module.fcntl.LOCK_EX)
            with self.module.attach_lock(self.root, os.getuid()):
                self.assertEqual(lock.stat().st_ino, inode)

    def test_untrusted_lock_paths_never_acquire_lock(self):
        run = self.root / "run"
        run.mkdir(mode=0o755)
        state = run / "maki-attach"
        state.mkdir(mode=0o700)
        lock = state / "attach.lock"
        lock.write_text("")
        lock.chmod(0o644)
        with mock.patch.object(self.module.fcntl, "flock") as flock:
            with self.assertRaisesRegex(RuntimeError, "private root-owned"):
                with self.module.attach_lock(self.root, os.getuid()):
                    self.fail("insecure lock accepted")
            lock.chmod(0o600)
            run.chmod(0o777)
            with self.assertRaisesRegex(RuntimeError, "group/other writable"):
                with self.module.attach_lock(self.root, os.getuid()):
                    self.fail("writable parent accepted")
            flock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
