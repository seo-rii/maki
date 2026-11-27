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
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("privileged-linux-validation.sh")
OPENER = Path(__file__).with_name("privileged_validation_opener.py")
CAPTURE = Path(__file__).with_name("privileged_validation_capture.py")
PRIVILEGED = Path(__file__).resolve().parents[1] / "crates/maki-privileged/src"
# An attachment's connection identifier, as attach records hold it.
ATTACHMENT = "maki-0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c"


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
            # What the helper's readers parse, from this attachment.
            '\ncapture_helper_outputs\n',
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
            '\n    kill_nbdkit "after the second attach"\n',
            # What the device shows decides the path cleanup must take.
            '\n    shown="$(shown_backend)"\n',
            "\n    run_helper cleanup maki-cleanup-dead-daemon ||",
            '\n    require_cleanup_path maki-cleanup-dead-daemon "$shown"\n',
            '\n    require_released "cleanup after nbdkit was killed"\n',
            # The killed nbdkit left its socket; a new one is started on the
            # same configuration and must negotiate.
            '\n    start_nbdkit "after the first SIGKILL" nbdinfo-after-kill\n',
            "\n    run_helper attach maki-attach-after-kill ||",
            '\n    require_attached "the attach after nbdkit was killed"\n',
            "\n    run_helper verify maki-verify-after-kill ||",
            "\n    check_lifecycle_data restart\n",
            # Cleanup's path for a device that shows no connection: the
            # device of a killed nbdkit is released by hand first, its
            # attach record kept.
            '\n    kill_nbdkit "after the third attach"\n',
            "\n    release_by_hand\n",
            "\n    run_helper cleanup maki-cleanup-disconnected ||",
            '\n    require_cleanup_path maki-cleanup-disconnected ""\n',
            '\n    require_released "cleanup of the disconnected attachment"\n',
            '\n    start_nbdkit "after the second SIGKILL" nbdinfo-after-disconnect\n',
            "\n    run_helper attach maki-attach-after-disconnect ||",
            '\n    require_attached "the attach after disconnected recovery"\n',
            "\n    run_helper verify maki-verify-after-disconnect ||",
            "\n    check_lifecycle_data recovery\n",
            "\n    run_helper detach maki-detach-final ||",
            '\n    require_released "the final detach"',
        )
        # The cleanup trap must know whether storage is still attached.
        self.assert_in_order(killed, "run_helper cleanup", "mount_active=false",
                             "helper_cleanup_needed=false", "helper_cleanup_needed=true",
                             "run_helper attach", "mount_active=true", "release_by_hand",
                             "run_helper cleanup", "mount_active=false",
                             "helper_cleanup_needed=false", "helper_cleanup_needed=true",
                             "run_helper attach", "mount_active=true", "run_helper detach",
                             "mount_active=false", "helper_cleanup_needed=false")

    def test_a_kill_syncs_and_requires_sigkill_and_a_restart_negotiates(self):
        functions = fragment(self.source, "run_helper() {\n", '\nrequire_attached "the first attach"\n')
        kill = fragment(functions, "kill_nbdkit() {\n", "\n}\n")
        self.assert_in_order(kill, 'sync -f "$mountpoint/work"', 'kill -KILL "$nbdkit_pid"',
                             'wait "$nbdkit_pid" || killed_status=$?', 'nbdkit_pid=""',
                             '[[ "$killed_status" == 137 ]] ||')
        start = fragment(functions, "start_nbdkit() {\n", "\n}\n")
        self.assert_in_order(start, 'remove_stale_test_socket "$socket_path"',
                             '"${nbdkit_launcher[@]}" nbdkit --foreground -U "$socket_path" "$plugin_path"',
                             'config="$config_path" >>"$run_dir/nbdkit.log" 2>&1 &',
                             "nbdkit_pid=$!", 'nbdinfo "$nbd_uri" >"$run_dir/$2.txt"')

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
vg_name=maki_validation_1000_42
lv_name=data
mountpoint="$FIXTURE/mnt"
run_dir="$FIXTURE/logs"
attach_bin="$FIXTURE/maki-attach"
attach_config_path=/not-opened/attach.toml
REPO_ROOT=/not-opened
opener_pid=""
mount_active=true
RELEASE_LOOKS=3
log() { printf 'LOG: %s\n' "$*"; }
pass() { printf 'PASS: %s\n' "$*"; }
die() { printf 'DIE: %s\n' "$*"; exit 1; }
basename() { printf '%s\n' "$nbd_target"; }
findmnt() { [[ -e "$FIXTURE/mounted" ]]; }
sleep() { :; }
sudo() {
    [[ "$1" == -n ]] || return 99
    shift
    case "$1" in
        env) shift 2; "$@" ;;
        blockdev) cat "$FIXTURE/size" ;;
        sh) shift; [[ -z "${SUDO_FAILS:-}" ]] || return 1; sh "$1" "$2" "$3" "$FIXTURE$4" ;;
        # A script of the run, by its name, from the fixture.
        python3) shift 2; script="${1##*/}"; shift; "$FIXTURE/$script" "$@" ;;
        umount|dmsetup) "$FIXTURE/root-command" "$@" ;;
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
        self.script("privileged_validation_opener.py", script)

    def script(self, name, body):
        path = self.root / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o700)

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

    def test_cleanup_must_take_the_path_for_what_the_device_showed(self):
        detach = "maki-attach: /dev/nbd15 shows the attachment's connection; cleanup follows the detach path"
        recovery = "maki-attach: /dev/nbd15 shows no connection; cleanup follows disconnected recovery"
        for shown, logged, ok in (("maki-1", detach, True), ("", recovery, True),
                                  ("maki-1", recovery, False), ("", detach, False), ("", "", False)):
            with self.subTest(shown=shown, logged=logged):
                (self.run_dir / "maki-cleanup.txt").write_text(f"# cleanup volume\n{logged}\n")
                result = self.run_fragment(f'require_cleanup_path maki-cleanup "{shown}"\necho CHECKED')
                self.assertEqual(result.returncode == 0, ok, result.stdout + result.stderr)
                self.assertEqual("CHECKED" in result.stdout, ok)
                if not ok:
                    self.assertIn("DIE: cleanup did not say it took the path", result.stdout)

    # The kernel keeps a connection's attributes until the last opener of
    # the device has closed it: which step of the release by hand they go
    # at, by what the device's openers are.
    RELEASES = {"mapping": ["kernel-disconnect", "umount", "dmsetup"],
                "mount": ["kernel-disconnect", "umount"], "disconnect": ["kernel-disconnect"]}

    def release(self, gone_at, *, disconnect_status=0, record=True):
        """The runner's release by hand on a mounted, mapped device whose
        connection's attributes go at `gone_at` (or never, None)."""
        self.attached()
        (self.sysfs / "backend").write_text(ATTACHMENT + "\n")
        if not record:
            (self.root / "run/maki-attach/privval-1000-42.nbd").unlink()
        (self.sysfs / "holders/dm-0/dm").mkdir(parents=True)
        (self.sysfs / "holders/dm-0/dm/name").write_text("maki_validation_1000_42-data\n")
        gone = f'rm -f "{self.sysfs}/backend" "{self.sysfs}/pid"\n'
        calls = f'echo "$*" >> "{self.root}/root-calls"\n'
        self.script("privileged_validation_nbd.py", calls.replace("$*", "kernel-disconnect $*")
                    + 'echo "the kernel acknowledged NBD_CMD_DISCONNECT for nbd15"\n'
                    + (gone if gone_at == "disconnect" else "") + f"exit {disconnect_status}\n")
        self.script("root-command", calls + 'case "$1" in\n'
                    f'  umount) rm "{self.root}/mounted"; {gone if gone_at == "mount" else ":"} ;;\n'
                    f'  dmsetup) rm -r "{self.sysfs}/holders/dm-0"; {gone if gone_at == "mapping" else ":"} ;;\n'
                    "esac\n")
        result = self.run_fragment("release_by_hand\necho RELEASED")
        root_calls = self.root / "root-calls"
        made = root_calls.read_text().splitlines() if root_calls.exists() else []
        return result, made

    def test_the_release_by_hand_stops_once_the_device_shows_no_connection(self):
        for gone_at, steps in self.RELEASES.items():
            with self.subTest(gone_at=gone_at):
                self.setUp()
                result, made = self.release(gone_at)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual([call.split()[0] for call in made], steps)
                disconnect = made[0].split()
                self.assertEqual(disconnect[1:], ["--device", "/dev/nbd15", "--identifier",
                                                  ATTACHMENT, "--helper",
                                                  str(self.root / "maki-attach"), "kernel-disconnect"])
                if "umount" in steps:
                    self.assertEqual(made[1], f"umount {self.root}/mnt")
                if "dmsetup" in steps:
                    self.assertEqual(made[2], "dmsetup remove maki_validation_1000_42-data")
                # Each step says what the device showed after it.
                self.assertIn("LOG: after NBD_CMD_DISCONNECT, with XFS mounted, /dev/nbd15 shows backend "
                              + ("none" if gone_at == "disconnect" else ATTACHMENT), result.stdout)
                self.assertIn("PASS: /dev/nbd15 shows no connection while the attach record of its "
                              "killed nbdkit remains", result.stdout)
                self.assertIn("RELEASED", result.stdout)

    def test_a_release_by_hand_that_leaves_a_connection_or_no_record_stops_the_run(self):
        cases = {"never gone": ({"gone_at": None}, "/dev/nbd15 still shows a connection"),
                 "disconnect refused": ({"gone_at": "mapping", "disconnect_status": 1},
                                        "NBD_CMD_DISCONNECT of /dev/nbd15 failed"),
                 "no record": ({"gone_at": "mapping", "record": False},
                               "the attach record went before cleanup ran")}
        for name, (options, message) in cases.items():
            with self.subTest(case=name):
                self.setUp()
                result, made = self.release(**options)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(f"DIE: {message}", result.stdout)
                self.assertNotIn("RELEASED", result.stdout)
                if name == "disconnect refused":
                    self.assertEqual([call.split()[0] for call in made], ["kernel-disconnect"])

    def test_no_release_by_hand_without_an_attachments_connection(self):
        for shown in ("maki-bootstrap-" + ATTACHMENT[5:], "maki-1", None):
            with self.subTest(shown=shown):
                self.setUp()
                self.attached()
                if shown is None:
                    (self.sysfs / "backend").unlink()
                else:
                    (self.sysfs / "backend").write_text(shown + "\n")
                self.script("privileged_validation_nbd.py", f'touch "{self.root}/root-calls"\n')
                result = self.run_fragment("release_by_hand\necho RELEASED")
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("DIE: /dev/nbd15 shows no attachment's connection before the release "
                              f"by hand ({shown or 'none'})", result.stdout)
                self.assertFalse((self.root / "root-calls").exists())

    def test_the_helpers_outputs_are_captured_as_root_into_the_run_directory(self):
        self.script("privileged_validation_capture.py", 'printf "%s\\n" "$@"\n')
        result = self.run_fragment("capture_helper_outputs")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.run_dir / "helper-outputs.json").read_text().split(),
                         ["--device", "/dev/nbd15", "--vg", "maki_validation_1000_42", "--lv", "data",
                          "--mountpoint", str(self.root / "mnt")])
        self.assertIn("PASS: captured the outputs of the helper's probes", result.stdout)
        self.script("privileged_validation_capture.py", "exit 1\n")
        result = self.run_fragment("capture_helper_outputs")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DIE: could not capture the helper's probe outputs", result.stdout)

    def test_an_opener_that_never_holds_the_device_stops_the_run(self):
        self.opener('echo "cannot open /dev/nbd15: Permission denied"\nexit 2\n')
        result = self.run_fragment("hold_device_open\necho STARTED")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("DIE: the opener did not start holding /dev/nbd15", result.stdout)
        self.assertIn("Permission denied", result.stderr)
        self.assertNotIn("STARTED", result.stdout)


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


def load_capture():
    spec = importlib.util.spec_from_file_location("privileged_validation_capture", CAPTURE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rust_literals(text):
    """The string literals of a span of Rust, in order, decoded."""
    found = []
    for raw, plain in re.findall(r'r#"(.*?)"#|"((?:[^"\\]|\\.)*)"', text, re.S):
        found.append(raw or plain.encode().decode("unicode_escape"))
    return found


def rust_span(name, start, end):
    source = (PRIVILEGED / name).read_text()
    begin = source.index(start)
    return source[begin:source.index(end, begin + len(start))]


class HelperOutputs(unittest.TestCase):
    """privileged_validation_capture.py runs each probe as the helper does:
    the commands are read from the helper's own sources here."""

    @classmethod
    def setUpClass(cls):
        cls.module = load_capture()

    def test_each_command_is_the_helpers(self):
        lvm = self.module.lvm_report(["/dev/nbd15", "/dev/nbd15p1"])
        devices = lvm.index("--devices") + 1
        # `device_list` joins the candidates with commas.
        self.assertEqual(lvm[devices], "/dev/nbd15,/dev/nbd15p1")
        self.assertEqual(lvm[:devices] + lvm[devices + 1:],
                         rust_literals(rust_span("lvm_preflight.rs", "fn report_command(",
                                                 "\n}\n")))
        self.assertEqual(self.module.label_probe("/proc/1/fd/3")[:-1],
                         rust_literals(rust_span("lvm_preflight.rs", 'controlled_command("blkid")',
                                                 "&pinned")))
        self.assertEqual(self.module.filesystem_probe("/dev/vg/lv")[:-1],
                         rust_literals(rust_span("exec.rs", "PlannedStep::VerifyFilesystemIdentity {",
                                                 "verify_filesystem_probe(")))
        self.assertEqual(self.module.uuid_value("/dev/mapper/vg-lv")[:-1],
                         rust_literals(rust_span("exec.rs", "fn blkid_uuid_command(", "\n}\n")))
        self.assertEqual(self.module.mapping_info("vg-lv"),
                         rust_literals(rust_span("recover.rs", "fn controlled_dmsetup(", "\n}\n"))
                         + rust_literals(rust_span("recover.rs", "fn dmsetup_info_command(", "\n}\n"))
                         + ["vg-lv"])
        size = rust_literals(rust_span("exec.rs", 'command::controlled("blockdev")', "\n"))
        self.assertEqual(size, ["blockdev", "--getsize64", "/dev/{vg}/{lv}"])
        self.assertEqual(self.module.lv_size("vg", "lv"), ["blockdev", "--getsize64", "/dev/vg/lv"])

    def test_the_environment_and_limits_are_the_helpers(self):
        pairs = rust_literals(rust_span("command.rs", "pub(crate) fn controlled(", "\n}\n"))
        self.assertEqual(self.module.ENVIRONMENT, dict(zip(pairs[::2], pairs[1::2])))
        policy = rust_span("command.rs", "pub(super) const STEP: Self", "\n}\n")
        self.assertIn("max_output_bytes: 64 * 1024,", policy)
        self.assertEqual(self.module.MAX_OUTPUT, 64 * 1024)
        self.assertIn("timeout: Duration::from_secs(15),", rust_span(
            "command.rs", "pub(super) const PROBE: Self", "};"))
        self.assertEqual(self.module.TIMEOUT, 15)
        with mock.patch.object(self.module.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 2, stdout=b"out\n", stderr=b"")
            self.assertEqual(self.module.run(["blkid"]),
                             {"argv": ["blkid"], "status": 2, "stdout": "out\n", "stderr": "",
                              "truncated": False})
        run.assert_called_once_with(["blkid"], env=self.module.ENVIRONMENT,
                                    stdin=subprocess.DEVNULL, capture_output=True, timeout=15)

    def test_the_attributes_are_the_ones_the_helpers_readers_open(self):
        opened = set()
        for name in ("allocation.rs", "detach.rs", "displaced.rs", "recover.rs", "lvm_preflight.rs",
                     "exec.rs", "probe.rs", "workload_verify.rs", "nbd_kernel.rs"):
            opened |= set(re.findall(r'join\("([a-z_/]+)"\)', (PRIVILEGED / name).read_text()))
        self.assertEqual(set(self.module.ATTRIBUTES) | {"holders", "slaves"}, opened)

    def sysfs(self, root):
        def node(name, **attributes):
            (root / name / "holders").mkdir(parents=True)
            (root / name / "slaves").mkdir()
            for attribute, value in attributes.items():
                path = root / name / attribute.replace("__", "/")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(value + "\n")
        node("nbd15", dev="43:240", size="1048576", pid="1234", backend=ATTACHMENT)
        node("nbd15p1", dev="43:241", size="2048", partition="1", start="2048")
        node("dm-0", dev="252:0", size="786432", dm__name="vg-data", dm__uuid="LVM-abc")
        node("dm-1", dev="252:1", dm__name="other-data", dm__uuid="LVM-def")
        node("nbd1", dev="43:16")
        node("dm-5", dev="252:5", dm__name="unrelated")
        (root / "nbd15/holders/dm-0").symlink_to("../../dm-0")
        (root / "dm-0/slaves/nbd15").symlink_to("../../nbd15")
        (root / "dm-0/holders/dm-1").symlink_to("../../dm-1")
        (root / "dm-1/slaves/dm-0").symlink_to("../../dm-0")

    def test_the_tree_is_the_devices_nodes_in_the_fuzz_inputs_format(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.sysfs(root)
            self.assertEqual(self.module.tree(root, "nbd15"), [
                "nbd15/", "nbd15/dev=43:240", "nbd15/size=1048576", "nbd15/pid=1234",
                f"nbd15/backend={ATTACHMENT}", "nbd15/holders/", "nbd15/holders/dm-0>dm-0",
                "nbd15/slaves/",
                "nbd15p1/", "nbd15p1/dev=43:241", "nbd15p1/size=2048", "nbd15p1/partition=1",
                "nbd15p1/start=2048", "nbd15p1/holders/", "nbd15p1/slaves/",
                "dm-0/", "dm-0/dev=252:0", "dm-0/size=786432", "dm-0/dm/name=vg-data",
                "dm-0/dm/uuid=LVM-abc", "dm-0/holders/", "dm-0/holders/dm-1>dm-1", "dm-0/slaves/",
                "dm-0/slaves/nbd15>nbd15",
                "dm-1/", "dm-1/dev=252:1", "dm-1/dm/name=other-data", "dm-1/dm/uuid=LVM-def",
                "dm-1/holders/", "dm-1/slaves/", "dm-1/slaves/dm-0>dm-0",
            ])

    def test_a_capture_holds_each_probe_the_tree_and_the_mount_table(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.sysfs(root / "sys")
            device = root / "nbd15"
            device.write_bytes(bytes(4096))
            mountinfo = root / "mountinfo"
            mountinfo.write_text("22 1 0:21 / /proc rw - proc proc rw\n"
                                 "90 22 252:0 / /srv/maki rw,nosuid,nodev - xfs /dev/mapper/vg-data rw\n")
            ran = []

            def execute(argv):
                ran.append(argv)
                return {"argv": argv, "status": 0, "stdout": "", "stderr": "", "truncated": False}
            with mock.patch.object(self.module.os, "open", wraps=os.open) as opened:
                captured = self.module.capture(str(device), "vg", "data", "/srv/maki",
                                               sysfs=root / "sys", mountinfo=mountinfo,
                                               execute=execute)
            self.assertEqual(list(captured["commands"]),
                             ["lvm_report", "pv_label", "filesystem", "dm_info", "lv_size", "blkid_value"])
            label = captured["commands"]["pv_label"]["argv"]
            self.assertRegex(label[-1], rf"^/proc/{os.getpid()}/fd/\d+$")
            # The probe read the device through a descriptor opened for it.
            self.assertEqual(opened.call_args.args[0], str(device))
            lvm = captured["commands"]["lvm_report"]["argv"]
            self.assertEqual(lvm[lvm.index("--devices") + 1], f"{device},/dev/nbd15p1")
            self.assertEqual(captured["commands"]["filesystem"]["argv"][-1], "/dev/vg/data")
            self.assertEqual(captured["commands"]["dm_info"]["argv"][-1], "vg-data")
            self.assertEqual(captured["commands"]["blkid_value"]["argv"][-1], "/dev/mapper/vg-data")
            self.assertTrue(captured["sysfs"].startswith("nbd15/\nnbd15/dev=43:240\n"))
            self.assertEqual(captured["mountinfo"], mountinfo.read_text())
            json.dumps(captured)

    def test_only_a_canonical_nbd_device_is_captured(self):
        for device in ("/dev/sda", "/dev/nbd01", "nbd0"):
            with self.subTest(device=device):
                with self.assertRaises(SystemExit) as raised, \
                        open(os.devnull, "w") as quiet, mock.patch("sys.stderr", quiet):
                    self.module.main(["--device", device, "--vg", "vg", "--lv", "lv",
                                      "--mountpoint", "/srv/maki"])
                self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
