"""The runner's denial checks must prove the permission boundary, not any failure.

The unrelated-user socket and unprivileged disconnect fragments come from the
runner. sudo, nbdinfo, nbd-client and the ownership check are fixtures that
print what the real tools report; no socket, device, or privileged operation
is used.
"""
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("privileged-linux-validation.sh")
SOCKET_PASS = "PASS: unrelated user is denied by the runtime-directory boundary"
DISCONNECT_PASS = "PASS: unprivileged NBD disconnect ioctl is denied"
URI = "nbd+unix:///?socket=/run/maki/privval-1000-42/nbd.sock"

SUDO = r'''#!/bin/sh
[ "$#" -ge 4 ] && [ "$1" = -n ] && [ "$2" = -u ] && [ "$3" = nobody ] ||
    { echo "fixture: unexpected sudo arguments: $*" >&2; exit 97; }
shift 3
case "$SUDO_MODE" in
    run) exec "$@" ;;
    policy) printf "Sorry, user fixture is not allowed to execute '/usr/bin/%s' as nobody on fixture-host.\n" "$*" >&2 ;;
    password) echo "sudo: a password is required" >&2 ;;
    missing) printf 'sudo: %s: command not found\n' "$1" >&2 ;;
    exec-denied) printf 'sudo: unable to execute /usr/bin/%s: Permission denied\n' "$1" >&2 ;;
esac
exit 1
'''

# Both tools print their own diagnostics; the fixture replays one of them.
TOOL = r'''#!/bin/sh
[ "$*" = "$EXPECTED_ARGUMENTS" ] ||
    { echo "fixture: unexpected $(basename "$0") arguments: $*" >&2; exit 98; }
[ -z "$TOOL_STDOUT" ] || printf '%s' "$TOOL_STDOUT"
[ -z "$TOOL_STDERR" ] || printf '%s\n' "$TOOL_STDERR" >&2
[ "$TOOL_DISCONNECTS" != 1 ] || rm -f "$FIXTURE/owned-backend"
exit "$TOOL_STATUS"
'''


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "Bash and POSIX processes")
class UnprivilegedDenialProbes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = SCRIPT.read_text()
        start = source.index("die() {\n")
        cls.functions = source[start:source.index("\n}\n", source.index("pass() {\n", start)) + 3]
        start = source.index(
            'pass "nbdkit runs unprivileged with no-new-privileges and empty effective capabilities"\n')
        start = source.index("\n", start) + 1
        marker = 'pass "unrelated user is denied by the runtime-directory boundary"'
        cls.socket_probe = source[start:source.index(marker, start) + len(marker)]
        start = source.index('pass "kernel NBD attach and 512 MiB geometry"\n')
        start = source.index("\n", start) + 1
        marker = 'pass "unprivileged NBD disconnect ioctl is denied"'
        cls.disconnect_probe = source[start:source.index(marker, start) + len(marker)]

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="maki-denial-")
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        (self.root / "run").mkdir()
        self.binary = self.root / "bin"
        self.binary.mkdir()
        for name, text in (("sudo", SUDO), ("nbdinfo", TOOL), ("nbd-client", TOOL)):
            path = self.binary / name
            path.write_text(text)
            path.chmod(0o700)
        (self.root / "owned-backend").write_text("maki-privval-fixture\n")

    def run_probe(self, probe, arguments, *, stderr="", stdout="", status=1, sudo="run",
                  disconnects=False):
        setup = r'''set -Eeuo pipefail
IFS=$'\n\t'
date() { printf 'fixture-time\n'; }
run_dir="$FIXTURE/run"
nbd_uri="$URI"
device=/dev/nbd15
nbd_target=nbd15
nbd_connection_id=maki-privval-fixture
# The real check proves the live kernel backend is still this run's own.
test_nbd_action() {
    [[ "$*" == check ]] || { printf 'fixture: unexpected ownership action: %s\n' "$*" >&2; return 99; }
    [[ -e "$FIXTURE/owned-backend" ]]
}
'''
        environment = dict(os.environ, PATH=str(self.binary) + os.pathsep + os.environ["PATH"],
                           FIXTURE=str(self.root), URI=URI, SUDO_MODE=sudo,
                           EXPECTED_ARGUMENTS=arguments, TOOL_STDOUT=stdout, TOOL_STDERR=stderr,
                           TOOL_STATUS=str(status), TOOL_DISCONNECTS="1" if disconnects else "0")
        return subprocess.run(["bash", "-c", setup + self.functions + "\n" + probe + "\n"],
                              env=environment, capture_output=True, text=True, timeout=10)

    def socket(self, **kwargs):
        return self.run_probe(self.socket_probe, URI, **kwargs)

    def disconnect(self, **kwargs):
        return self.run_probe(self.disconnect_probe, "-d nbd15", **kwargs)

    def assert_passed(self, result, marker):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(marker, result.stdout)

    def assert_rejected(self, result, marker, evidence=None):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn(marker, result.stdout)
        if evidence is not None:
            self.assertIn(evidence, result.stderr, "the failure must show what the tool printed")

    def test_socket_permission_denial_passes(self):
        for stderr in ("nbdinfo: nbd_connect_uri: connect: Permission denied",
                       "/usr/bin/nbdinfo: nbd_connect_uri: connect: Permission denied"):
            with self.subTest(stderr=stderr):
                self.assert_passed(self.socket(stderr=stderr), SOCKET_PASS)

    def test_sudo_refusal_is_not_socket_boundary_evidence(self):
        expected = {
            "policy": "is not allowed to execute",
            "password": "a password is required",
            "missing": "command not found",
            # A Permission denied that is not connect(2) on the socket.
            "exec-denied": "unable to execute",
        }
        for mode, evidence in expected.items():
            with self.subTest(mode=mode):
                self.assert_rejected(self.socket(sudo=mode), SOCKET_PASS, evidence)

    def test_other_nbdinfo_failures_are_not_socket_boundary_evidence(self):
        for stderr in ("nbdinfo: nbd_connect_uri: connect: Connection refused",
                       "nbdinfo: nbd_connect_uri: connect: No such file or directory",
                       # Connected, then closed by the server: the boundary did not hold.
                       "nbdinfo: nbd_connect_uri: recv: Connection reset by peer",
                       "nbdinfo: unrecognized option '--fixture'",
                       ""):
            with self.subTest(stderr=stderr):
                self.assert_rejected(self.socket(stderr=stderr), SOCKET_PASS, stderr)

    def test_unrelated_user_opening_the_socket_fails(self):
        self.assert_rejected(self.socket(stdout="protocol: newstyle-fixed without TLS\n",
                                         status=0), SOCKET_PASS)

    def test_kernel_disconnect_denials_pass(self):
        for stdout, stderr in (
                # Netlink: the kernel's EPERM is reported without an errno.
                ("", "Error: Failed to disconnect device, check dmsg\n\nExiting."),
                # ioctl: NBD_DISCONNECT without CAP_SYS_ADMIN.
                ("disconnect, ", "Error: Ioctl failed: Operation not permitted\n\nExiting."),
                # ioctl: a device node the invoking user cannot open.
                ("", "Error: Cannot open NBD: Permission denied\n"
                     "Please ensure the 'nbd' module is loaded.\nExiting.")):
            with self.subTest(stderr=stderr):
                result = self.disconnect(stdout=stdout, stderr=stderr)
                self.assert_passed(result, DISCONNECT_PASS)
                self.assertTrue((self.root / "owned-backend").exists())

    def test_disconnect_usage_and_setup_errors_are_not_denial_evidence(self):
        for status, stderr in (
                (1, "Error: Invalid nbd device target\n\nExiting."),
                (1, "nbd-client version 3.27.1\n"
                    "Usage: nbd-client -name|-N name host [port] nbd_device\n"
                    "Or   : nbd-client -d nbd_device"),
                (1, "Error: Couldn't resolve the nbd netlink family, make sure the nbd module "
                    "is loaded and your nbd driver supports the netlink interface.\nExiting."),
                (1, "Error: Cannot open NBD: No such file or directory\n"
                    "Please ensure the 'nbd' module is loaded.\nExiting."),
                (127, "bash: line 1: nbd-client: command not found"),
                # Permission denied for the client executable, not the device.
                (126, "bash: line 1: /usr/sbin/nbd-client: Permission denied"),
                (1, "")):
            with self.subTest(stderr=stderr):
                result = self.disconnect(stderr=stderr, status=status)
                self.assert_rejected(result, DISCONNECT_PASS, stderr.splitlines()[0] if stderr else None)

    def test_denial_text_with_a_lost_backend_fails(self):
        result = self.disconnect(stderr="Error: Ioctl failed: Operation not permitted\n\nExiting.",
                                 disconnects=True)
        self.assert_rejected(result, DISCONNECT_PASS)

    def test_successful_unprivileged_disconnect_fails(self):
        result = self.disconnect(stdout="disconnect, sock, done\n", status=0, disconnects=True)
        self.assert_rejected(result, DISCONNECT_PASS)


if __name__ == "__main__":
    unittest.main()
