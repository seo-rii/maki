"""The privileged runner's attach lifecycle: data written and fsynced, a detach
whose disconnect finds the device held open, a second attach that reads the
data back, and with --kill-daemon a cleanup after nbdkit was killed, a new
nbdkit, a third attach and a final detach.

Fragments of the runner run in Bash against mocked commands and a private
sysfs tree, and the opener runs against a scripted device and clock. No
kernel device is opened and nothing runs as root.
"""
import errno
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("privileged-linux-validation.sh")
OPENER = Path(__file__).with_name("privileged_validation_opener.py")


def load_opener():
    spec = importlib.util.spec_from_file_location("privileged_validation_opener", OPENER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fragment(source, start, end):
    begin = source.index(start)
    return source[begin:source.index(end, begin)]


class LifecycleOrder(unittest.TestCase):
    """What the run does after the workload, in order."""

    @classmethod
    def setUpClass(cls):
        cls.source = SCRIPT.read_text()
        cls.lifecycle = fragment(cls.source, 'pass "workload gate still verifies the live attachment',
                                 'log "removing the disposable LVM metadata"')

    def assert_in_order(self, text, *needles):
        position = -1
        for needle in needles:
            with self.subTest(needle=needle):
                found = text.find(needle, position + 1)
                self.assertGreater(found, position, f"{needle!r} missing or out of order")
                position = found

    def test_every_run_detaches_with_an_opener_and_attaches_again(self):
        self.assert_in_order(
            self.lifecycle,
            # What the release checks look for is there before the detach.
            '\nrequire_attached "the first attach"\n',
            # Written and fsynced, then hashed, while attached.
            'dd if=/dev/urandom of="$mountpoint/work/lifecycle.dat" bs=1M count=32 conv=fsync',
            'sync -f "$mountpoint/work"',
            '(cd "$mountpoint/work" && sha256sum lifecycle.dat smoke.db) >"$run_dir/lifecycle.sha256"',
            # The detach's disconnect finds the device held open.
            "\nhold_device_open\n",
            "\nrun_helper detach maki-detach ||",
            # The opener had closed the device when the detach returned.
            "if ! grep -q ' closing after holding it ' \"$run_dir/detach-opener.txt\"; then",
            "\nfinish_opener\n",
            '\nrequire_released "detach with an opener of $device"\n',
            # Later attaches no longer create the sentinel.
            "s/^init_sentinel = true$/init_sentinel = false/",
            'sudo -n install -m 0600 -o root -g root "$run_dir/attach-reattach.toml" "$attach_config_path"',
            "\nrun_helper attach maki-reattach ||",
            '\nrequire_attached "the second attach"\n',
            "\nrun_helper verify maki-verify-reattach ||",
            "\ncheck_lifecycle_data reattach\n",
            'if [[ "$kill_daemon" == true ]]; then\n',
        )

    def test_kill_daemon_cleans_up_after_a_killed_nbdkit_and_detaches_at_the_end(self):
        killed = fragment(self.lifecycle, 'if [[ "$kill_daemon" == true ]]; then\n', "\nelse\n")
        self.assert_in_order(
            killed,
            'sync -f "$mountpoint/work"',
            'kill -KILL "$nbdkit_pid"',
            'wait "$nbdkit_pid" || killed_status=$?',
            '[[ "$killed_status" == 137 ]] ||',
            "\n    run_helper cleanup maki-cleanup-dead-daemon ||",
            '\n    require_released "cleanup after nbdkit was killed"\n',
            # The killed nbdkit left its socket; a new one is started on the
            # same configuration and must negotiate.
            'remove_stale_test_socket "$socket_path"',
            '"${nbdkit_launcher[@]}" nbdkit --foreground -U "$socket_path" "$plugin_path"',
            'config="$config_path" >>"$run_dir/nbdkit.log" 2>&1 &',
            'nbdinfo "$nbd_uri"',
            "\n    run_helper attach maki-attach-after-kill ||",
            '\n    require_attached "the attach after nbdkit was killed"\n',
            "\n    run_helper verify maki-verify-after-kill ||",
            "\n    check_lifecycle_data restart\n",
            "\n    run_helper detach maki-detach-final ||",
            '\n    require_released "the final detach"',
        )
        # The cleanup trap must know whether storage is still attached.
        self.assert_in_order(killed, "run_helper cleanup", "mount_active=false",
                             "helper_cleanup_needed=false", "helper_cleanup_needed=true",
                             "run_helper attach", "mount_active=true", "run_helper detach",
                             "mount_active=false", "helper_cleanup_needed=false")

    def test_without_kill_daemon_cleanup_ends_the_attachment(self):
        tail = self.lifecycle[self.lifecycle.index("\nelse\n"):]
        self.assert_in_order(
            tail,
            '"$attach_bin" cleanup --volume "$volume_name"',
            '>"$run_dir/maki-cleanup.txt" 2>&1',
            '\n    require_released "cleanup"\n',
            "\nfi\n",
            '>"$run_dir/maki-cleanup-idempotent.txt" 2>&1',
        )

    def test_the_cleanup_trap_releases_an_opener_before_any_helper_cleanup(self):
        cleanup = fragment(self.source, "cleanup() {\n", "\n}\n")
        self.assert_in_order(cleanup, 'if [[ -n "${opener_pid:-}" ]]; then',
                             ': >"$run_dir/stop-opener"', 'wait "$opener_pid"',
                             '"$attach_bin" cleanup --volume')

    @unittest.skipUnless(shutil.which("bash"), "requires Bash")
    def test_preflight_states_whether_the_daemon_is_killed(self):
        for flags, killed in (([], False), (["--kill-daemon"], True)):
            with self.subTest(flags=flags):
                result = subprocess.run(["bash", str(SCRIPT), "--preflight", *flags],
                                        capture_output=True, text=True, check=True, timeout=10)
                self.assertIn("-> detach with an opener -> attach -> data read back", result.stdout)
                self.assertEqual("SIGKILL nbdkit -> cleanup" in result.stdout, killed)
                self.assertEqual("forced crash" in result.stdout, not killed)

    def test_usage_documents_kill_daemon(self):
        usage = fragment(self.source, "usage() {", "\n}\n")
        self.assertIn("[--kill-daemon]", usage)
        self.assertIn("  --kill-daemon ", usage)

    @unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("bash")
                         and shutil.which("git"), "Linux shell and git")
    def test_the_launcher_passes_kill_daemon_to_its_worker(self):
        launcher = fragment(self.source, "prepare_source_snapshot() {",
                            '[[ "$background" == false ]] || die "--run-dir')
        for killed in ("false", "true"):
            with self.subTest(kill_daemon=killed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                repo = root / "repo"
                (repo / "scripts").mkdir(parents=True)
                for name in ("qualification_source.py", "prepare_release.py"):
                    shutil.copyfile(SCRIPT.with_name(name), repo / "scripts" / name)
                worker = repo / "scripts/privileged-linux-validation.sh"
                worker.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$(dirname "$0")/../../arguments"\n')
                worker.chmod(0o755)

                def git(*arguments):
                    subprocess.run(["git", "-C", str(repo), *arguments], check=True,
                                   capture_output=True)
                git("init", "-q")
                git("add", ".")
                git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.test",
                    "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")
                setup = f"""set -euo pipefail
run_dir=""
device=/dev/nbd15
confirmed_device="$device"
install_missing=true
discard=false
kill_daemon={killed}
prebuilt_dir=""
work_root=""
background=false
sudo() {{ :; }}
"""
                result = subprocess.run(["bash", "-c", setup + launcher], capture_output=True,
                                        text=True, timeout=15,
                                        env=dict(os.environ, REPO_ROOT=str(repo),
                                                 log_root=str(root / "logs")))
                self.assertEqual(result.returncode, 0, result.stderr)
                arguments = (root / "logs/maki-privileged-validation.latest/arguments").read_text().split()
                self.assertEqual(arguments[:4], ["--device", "/dev/nbd15", "--confirm-wipe", "/dev/nbd15"])
                self.assertIn("--install-missing", arguments)
                self.assertEqual("--kill-daemon" in arguments, killed == "true")


@unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("bash"), "Linux shell")
class LifecycleFragments(unittest.TestCase):
    """The lifecycle's functions against mocked commands."""

    @classmethod
    def setUpClass(cls):
        source = SCRIPT.read_text()
        cls.functions = fragment(source, "run_helper() {\n", '\nrequire_attached "the first attach"\n')
        cls.nbd_has_pid = fragment(source, "nbd_has_pid() {\n", "\n}\n") + "\n}\n"
        cls.detach = fragment(source, 'log "detaching while another process holds $device open"\n',
                              "\n# The sentinel exists now.")

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="maki-lifecycle-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sysfs = self.root / "sys/block/nbd15"
        (self.sysfs / "holders").mkdir(parents=True)
        (self.root / "run/maki-attach").mkdir(parents=True)
        (self.root / "size").write_text("0\n")
        (self.root / "mnt/work").mkdir(parents=True)
        self.run_dir = self.root / "logs"
        self.run_dir.mkdir()
        self.helper = self.root / "maki-attach"
        self.helper.write_text('#!/bin/sh\necho "helper $*"\necho "helper diagnostic" >&2\n'
                               'exit "${HELPER_STATUS:-0}"\n')
        self.helper.chmod(0o700)

    def run_fragment(self, body, **environment):
        setup = r'''set -Eeuo pipefail
device=/dev/nbd15
nbd_target=nbd15
volume_name=privval-1000-42
mountpoint="$FIXTURE/mnt"
run_dir="$FIXTURE/logs"
attach_bin="$FIXTURE/maki-attach"
attach_config_path=/not-opened/attach.toml
REPO_ROOT=/not-opened
opener_pid=""
log() { printf 'LOG: %s\n' "$*"; }
pass() { printf 'PASS: %s\n' "$*"; }
die() { printf 'DIE: %s\n' "$*"; exit 1; }
basename() { printf '%s\n' "$nbd_target"; }
findmnt() { [[ -e "$FIXTURE/mounted" ]]; }
sudo() {
    [[ "$1" == -n ]] || return 99
    shift
    case "$1" in
        env) shift 2; "$@" ;;
        blockdev) cat "$FIXTURE/size" ;;
        sh) shift; [[ -z "${SUDO_FAILS:-}" ]] || return 1; sh "$1" "$2" "$3" "$FIXTURE$4" ;;
        python3) shift 3; "$FIXTURE/opener" "$@" ;;
        *) return 98 ;;
    esac
}
'''
        functions = (self.nbd_has_pid + self.functions).replace('"/sys/block/', f'"{self.root}/sys/block/')
        environment = dict(os.environ, FIXTURE=str(self.root), **environment)
        return subprocess.run(["bash", "-c", setup + functions + "\n" + body], env=environment,
                              capture_output=True, text=True, timeout=10)

    def test_run_helper_keeps_the_output_and_the_status_of_the_helper(self):
        for status in ("0", "3"):
            with self.subTest(status=status):
                result = self.run_fragment('run_helper detach maki-detach || '
                                           'printf "STATUS %s\\n" "$?"', HELPER_STATUS=status)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                evidence = (self.run_dir / "maki-detach.txt").read_text()
                self.assertIn("helper detach --volume privval-1000-42 --config /not-opened/attach.toml",
                              evidence)
                self.assertIn("helper diagnostic", evidence)
                self.assertIn("helper diagnostic", result.stdout)
                self.assertIn(f"exited with status {status} after", result.stdout)
                self.assertEqual("STATUS 3" in result.stdout, status == "3")

    def test_a_released_attachment_passes_and_each_leftover_fails(self):
        result = self.run_fragment('require_released detach')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS: detach left no mount, holder, connection or attach record", result.stdout)
        leftovers = {
            "mounted": (lambda: (self.root / "mounted").touch(), "left $mountpoint mounted"),
            "holder": (lambda: (self.sysfs / "holders/dm-0").touch(), "left holders of /dev/nbd15: dm-0"),
            "backend": (lambda: (self.sysfs / "backend").write_text("maki-1\n"), "backend maki-1"),
            "pid": (lambda: (self.sysfs / "pid").write_text("123\n"), "connected (backend not shown)"),
            "size": (lambda: (self.root / "size").write_text("4096\n"), "exposing 4096 bytes"),
            "record": (lambda: (self.root / "run/maki-attach/privval-1000-42.nbd").touch(),
                       "left the attach record"),
        }
        for name, (make, message) in leftovers.items():
            with self.subTest(leftover=name):
                self.setUp()
                make()
                result = self.run_fragment('require_released detach')
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(message.replace("$mountpoint", str(self.root / "mnt")), result.stdout)
                self.assertNotIn("PASS:", result.stdout)

    def test_a_record_that_cannot_be_looked_for_fails_both_ways(self):
        # sudo failing is no proof that the record is gone, or that it exists.
        for check in ("require_released detach", "require_attached attach"):
            with self.subTest(check=check):
                self.setUp()
                if check.startswith("require_attached"):
                    self.attached()
                result = self.run_fragment(check, SUDO_FAILS="1")
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("DIE: could not look for the attach record "
                              "/run/maki-attach/privval-1000-42.nbd", result.stdout)
                self.assertNotIn("PASS:", result.stdout)

    def attached(self):
        (self.root / "mounted").touch()
        (self.sysfs / "backend").write_text("maki-1529f24b\n")
        (self.sysfs / "pid").write_text("123\n")
        (self.root / "size").write_text("536870912\n")
        (self.root / "run/maki-attach/privval-1000-42.nbd").write_text("{}")

    def test_an_attachment_shows_what_a_teardown_must_remove(self):
        # The positive control of require_released: what it looks for is
        # there while attached, under the names it looks for.
        self.attached()
        result = self.run_fragment("require_attached attach")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS: attach shows the mount, the connection maki-1529f24b and the attach "
                      "record", result.stdout)
        missing = {
            "mount": (lambda: (self.root / "mounted").unlink(), "left $mountpoint unmounted"),
            "backend": (lambda: (self.sysfs / "backend").unlink(),
                        "left /dev/nbd15 without the attachment's backend identifier (none)"),
            "foreign backend": (lambda: (self.sysfs / "backend").write_text("other\n"),
                                "without the attachment's backend identifier (other)"),
            "record": (lambda: (self.root / "run/maki-attach/privval-1000-42.nbd").unlink(),
                       "left no attach record at /run/maki-attach/privval-1000-42.nbd"),
        }
        for name, (remove, message) in missing.items():
            with self.subTest(missing=name):
                self.setUp()
                self.attached()
                remove()
                result = self.run_fragment("require_attached attach")
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(message.replace("$mountpoint", str(self.root / "mnt")), result.stdout)
                self.assertNotIn("PASS:", result.stdout)

    def run_detach(self, helper):
        """The runner's detach section with an opener that closes the
        device half a second after it starts holding it."""
        self.opener('echo "  0.000s holding the device open; it shows backend \'maki-1\'"\n'
                    'sleep 0.5\n'
                    'echo "  0.500s closing after holding it 2.0 s more; the device shows backend \'maki-1\'"\n'
                    'touch "$FIXTURE/closed"\n'
                    'echo "  0.500s the connection\'s attributes outlived the acknowledged disconnect '
                    'until the close"\n')
        self.helper.write_text("#!/bin/sh\n" + helper)
        return self.run_fragment(self.detach)

    def test_a_detach_that_returns_before_the_opener_closed_the_device_fails(self):
        # The helper returned without waiting: the device was still held.
        result = self.run_detach('echo "detach returns at once"\n')
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("DIE: maki-attach detach returned while the opener still held /dev/nbd15",
                      result.stdout)
        self.assertNotIn("PASS: detach waited", result.stdout)

    def test_a_detach_that_returns_once_the_opener_closed_the_device_passes(self):
        result = self.run_detach('for _ in $(seq 1 200); do [ -e "$FIXTURE/closed" ] && exit 0; '
                                 'sleep 0.02; done\nexit 9\n')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS: detach with an opener of /dev/nbd15 left no mount, holder, connection "
                      "or attach record", result.stdout)
        self.assertIn("PASS: detach waited for the opener to close /dev/nbd15 and completed in one run",
                      result.stdout)

    def test_data_that_changed_after_the_detach_fails(self):
        work = self.root / "mnt/work"
        (work / "lifecycle.dat").write_bytes(os.urandom(4096))
        (work / "smoke.db").write_bytes(b"database")
        written = subprocess.run(["sha256sum", "lifecycle.dat", "smoke.db"], cwd=work,
                                 capture_output=True, text=True, check=True).stdout
        (self.run_dir / "lifecycle.sha256").write_text(written)
        result = self.run_fragment("check_lifecycle_data reattach")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("lifecycle.dat: OK", (self.run_dir / "lifecycle-check-reattach.txt").read_text())
        for changed in ("smoke.db", "lifecycle.dat"):
            with self.subTest(changed=changed):
                original = (work / changed).read_bytes()
                (work / changed).write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
                result = self.run_fragment("check_lifecycle_data restart")
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("DIE: data written before the first detach changed after the restart",
                              result.stdout)
                (work / changed).write_bytes(original)
        (work / "smoke.db").unlink()
        result = self.run_fragment("check_lifecycle_data restart")
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def opener(self, script):
        opener = self.root / "opener"
        opener.write_text("#!/bin/sh\n" + script)
        opener.chmod(0o700)

    def test_the_detach_starts_only_once_the_opener_holds_the_device(self):
        self.opener('echo "  0.000s holding the device open; it shows backend \'maki-1\'"\n'
                    'test "$1 $2 $3 $4" = "--device /dev/nbd15 --stop-file $FIXTURE/logs/stop-opener"\n'
                    'while [ ! -e "$FIXTURE/release" ]; do sleep 0.01; done\nexit "$OPENER_STATUS"\n')
        for status, ok in (("0", True), ("8", False)):
            with self.subTest(status=status):
                result = self.run_fragment('hold_device_open\ntouch "$FIXTURE/release"\nfinish_opener\n'
                                           'test -z "$opener_pid"\necho FINISHED', OPENER_STATUS=status)
                self.assertEqual(result.returncode == 0, ok, result.stdout + result.stderr)
                self.assertIn("holding the device open", result.stdout)
                self.assertEqual("FINISHED" in result.stdout, ok)
                if not ok:
                    self.assertIn("DIE: the opener of /dev/nbd15 exited with status 8", result.stdout)
                (self.root / "release").unlink()

    def test_an_opener_that_never_holds_the_device_stops_the_run(self):
        self.opener('echo "cannot open /dev/nbd15: Permission denied"\nexit 2\n')
        result = self.run_fragment("hold_device_open\necho STARTED")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("DIE: the opener did not start holding /dev/nbd15", result.stdout)
        self.assertIn("Permission denied", result.stderr)
        self.assertNotIn("STARTED", result.stdout)

    # sudo checks its policy with real, effective and saved uid 0, so for
    # that moment the invoking user's `kill -0` on its PID fails with EPERM.
    # In CI's first booted-host run (Debian 12) the wait's first look fell
    # there, before the opener had written that it held the device, and the
    # run stopped although the opener was starting.
    REFUSE_SIGNALS = ('kill() { if [ "$1" = -0 ]; then echo "kill: ($2) - Operation not permitted" >&2; '
                      'return 1; fi; builtin kill "$@"; }\n')

    def test_the_wait_does_not_signal_the_opener_that_sudo_started(self):
        self.opener('sleep 0.3\necho "  0.000s holding the device open; it shows backend \'maki-1\'"\n'
                    'while [ ! -e "$FIXTURE/release" ]; do sleep 0.01; done\n')
        result = self.run_fragment(self.REFUSE_SIGNALS + 'hold_device_open\necho HOLDING\n'
                                   'touch "$FIXTURE/release"\nfinish_opener\necho FINISHED')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("HOLDING", result.stdout)
        self.assertIn("FINISHED", result.stdout)
        self.assertNotIn("DIE:", result.stdout)

    def test_an_opener_that_exits_before_holding_the_device_ends_the_wait_at_once(self):
        # Without signals the wait still sees the opener go, long before its
        # ten seconds are up.
        self.opener('echo "cannot open /dev/nbd15: No such device or address"\nexit 2\n')
        started = time.monotonic()
        result = self.run_fragment(self.REFUSE_SIGNALS + "hold_device_open\necho STARTED")
        self.assertLess(time.monotonic() - started, 5)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("DIE: the opener did not start holding /dev/nbd15", result.stdout)
        self.assertIn("No such device or address", result.stderr)
        self.assertNotIn("STARTED", result.stdout)

    def test_a_process_runs_until_it_exits_whoever_owns_it(self):
        # PID 1 belongs to root: a runner user cannot signal it, and it runs.
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        self.addCleanup(child.kill)
        zombie = subprocess.Popen([sys.executable, "-c", "pass"])
        deadline = time.monotonic() + 10
        while (Path(f"/proc/{zombie.pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
               and time.monotonic() < deadline):
            time.sleep(0.01)
        self.addCleanup(zombie.wait)
        script = "".join(f'if process_running {pid}; then echo "{pid} running"; else echo "{pid} gone"; fi\n'
                         for pid in (1, child.pid, zombie.pid, 2 ** 22 + 1))
        result = self.run_fragment(script)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            "1 running", f"{child.pid} running", f"{zombie.pid} gone", f"{2 ** 22 + 1} gone"])
        if os.geteuid() != 0:
            # What the wait cannot rely on.
            self.assertNotEqual(subprocess.run(["bash", "-c", "kill -0 1"], capture_output=True).returncode, 0)


class ScriptedDevice:
    """A device whose reads follow a script: True serves a block, an int
    fails with that errno, ("bytes", n) returns n bytes."""

    def __init__(self, reads, on_close):
        self.reads = list(reads)
        self.on_close = on_close
        self.closed = False

    def read(self):
        outcome = self.reads.pop(0) if self.reads else True
        if outcome is True:
            return 4096
        if isinstance(outcome, tuple):
            return outcome[1]
        raise OSError(outcome, os.strerror(outcome))

    def close(self):
        self.closed = True
        self.on_close()


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class Opener(unittest.TestCase):
    """privileged_validation_opener.py's verdict on what it saw."""

    @classmethod
    def setUpClass(cls):
        cls.module = load_opener()

    def hold(self, reads, *, shown_at_failure="maki-1", gone_after_close=True, stop_after=None,
             hold_seconds=2.0, initial="maki-1", during_hold="maki-1"):
        state = {"backend": initial, "reads": 0}
        clock = Clock()

        def sleep(seconds):
            # The backend the device shows while it is held after the failure.
            if seconds == hold_seconds:
                state["backend"] = during_hold
            clock.sleep(seconds)
        output = []

        def on_close():
            if gone_after_close:
                state["backend"] = None

        device = ScriptedDevice(reads, on_close)
        original_read = device.read

        def read():
            state["reads"] += 1
            try:
                return original_read()
            except OSError:
                state["backend"] = shown_at_failure
                raise

        device.read = read
        status = self.module.hold(
            device, lambda: state["backend"],
            lambda: stop_after is not None and state["reads"] >= stop_after,
            clock=clock, sleep=sleep, say=output.append, hold_seconds=hold_seconds)
        return status, "\n".join(output), device, clock

    def test_an_acknowledged_disconnect_while_held_open_is_the_expected_case(self):
        status, output, device, clock = self.hold([True, True, True, errno.EIO])
        self.assertEqual(status, 0, output)
        self.assertTrue(device.closed)
        self.assertIn("holding the device open; it shows backend 'maki-1'", output)
        self.assertIn("read failed with EIO after 3 served reads: the kernel acknowledged the "
                      "disconnect; the device shows backend 'maki-1'", output)
        self.assertIn("the device shows no connection now that it is closed", output)
        # It held the device for the time it says after the failed read.
        self.assertGreaterEqual(clock.now, 3 * self.module.INTERVAL + 2.0)

    def test_attributes_gone_while_held_open_are_refused(self):
        # The kernel would then not have kept the connection's attributes:
        # the detach's wait for its opener was not exercised.
        for case in ({"shown_at_failure": None, "during_hold": None},
                     {"shown_at_failure": "maki-2", "during_hold": "maki-2"},
                     # Gone or another at the failure, shown again at the close.
                     {"shown_at_failure": None}, {"shown_at_failure": "maki-2"},
                     # Shown at the failure, gone before the close.
                     {"during_hold": None}, {"during_hold": "maki-2"}):
            with self.subTest(**case):
                status, output, _, _ = self.hold([True, errno.EIO], **case)
                self.assertEqual(status, 8, output)
                self.assertIn("stopped showing the connection while it was held open", output)

    def test_attributes_that_outlive_the_close_are_refused(self):
        status, output, _, clock = self.hold([True, errno.EIO], gone_after_close=False)
        self.assertEqual(status, 5, output)
        self.assertIn("still shows a connection 5 s after the close", output)

    def test_a_failure_before_any_served_read_or_other_than_eio_is_refused(self):
        status, output, device, _ = self.hold([errno.EIO])
        self.assertEqual(status, 6, output)
        self.assertTrue(device.closed)
        # A device that showed no connection when it was opened proves
        # nothing about one, whatever its reads did.
        status, output, device, _ = self.hold([True, True, errno.EIO], initial=None)
        self.assertEqual(status, 6, output)
        self.assertTrue(device.closed)
        status, output, _, _ = self.hold([True, errno.EINVAL])
        self.assertEqual(status, 7, output)
        self.assertIn("reported EINVAL, not EIO", output)

    def test_a_short_read_is_not_a_served_read(self):
        for count in (0, 512):
            with self.subTest(count=count):
                status, output, device, _ = self.hold([True, ("bytes", count), errno.EIO])
                self.assertEqual(status, 9, output)
                self.assertIn(f"refused: a read returned {count} bytes, not 4096", output)
                self.assertTrue(device.closed)

    def test_the_device_reads_one_whole_block_directly(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "device"
            path.write_bytes(bytes(range(256)) * 32)
            try:
                device = self.module.Device(str(path))
            except OSError as error:
                if error.errno == errno.EINVAL:
                    self.skipTest(f"{directory} does not take O_DIRECT")
                raise
            try:
                self.assertEqual(device.read(), 4096)
                self.assertEqual(bytes(device.buffer[:4]), bytes([0, 1, 2, 3]))
            finally:
                device.close()
            path.write_bytes(b"")
            device = self.module.Device(str(path))
            try:
                self.assertEqual(device.read(), 0)
            finally:
                device.close()

    def test_a_stop_request_or_no_disconnect_ends_the_hold_without_a_verdict(self):
        status, output, device, _ = self.hold([], stop_after=2)
        self.assertEqual(status, 3, output)
        self.assertTrue(device.closed)
        status, output, device, clock = self.hold([])
        self.assertEqual(status, 4, output)
        self.assertTrue(device.closed)
        self.assertGreater(clock.now, self.module.DEADLINE)

    def test_only_a_canonical_nbd_device_is_opened(self):
        for device in ("/dev/sda", "/dev/nbd256", "/dev/nbd01", "nbd0"):
            with self.subTest(device=device):
                with self.assertRaises(SystemExit) as raised, \
                        open(os.devnull, "w") as quiet, \
                        mock.patch("sys.stderr", quiet):
                    self.module.main(["--device", device, "--stop-file", "/nonexistent"])
                self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
