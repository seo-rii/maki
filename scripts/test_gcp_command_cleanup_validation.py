"""Bounded GCP commands own local process groups; no cloud calls are made."""
import importlib.util
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


@unittest.skipUnless(sys.platform == "linux", "Linux process-group ownership")
class CommandCleanupTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location(
            "gcp_command_cleanup", Path(__file__).with_name("gcp-reset-validation.py"))
        self.host = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.host)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.process = None
        self.descendant_exited = None
        self.signaled = []

    def fixture(self, action, inherited_pipes=False, leader_exits=False):
        ready = self.root / "ready"
        pending = self.root / "pending"
        program = (
            "import os, signal\n"
            "from pathlib import Path\n"
            "reader, writer = os.pipe()\n"
            "child = os.fork()\n"
            "if child == 0:\n"
            "    os.close(reader)\n"
            + ("" if inherited_pipes else "    os.close(1)\n    os.close(2)\n")
            + "    os.write(writer, b'ready')\n"
            "    os.close(writer)\n"
            "    signal.pause()\n"
            "    os._exit(0)\n"
            "os.close(writer)\n"
            "os.read(reader, 5)\n"
            "os.close(reader)\n"
            f"Path({str(pending)!r}).write_text(str(child))\n"
            f"os.replace({str(pending)!r}, {str(ready)!r})\n"
            + action)
        original_popen = subprocess.Popen

        def launch(*args, **kwargs):
            self.process = original_popen(*args, **kwargs)
            leader_fd = os.pidfd_open(self.process.pid)

            def cleanup_leader():
                try:
                    signal.pidfd_send_signal(leader_fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                finally:
                    os.close(leader_fd)
                self.process.wait(timeout=5)
                for stream in (self.process.stdout, self.process.stderr):
                    if stream is not None:
                        stream.close()

            self.addCleanup(cleanup_leader)
            until = time.monotonic() + 5
            while not ready.exists():
                self.assertLess(time.monotonic(), until, "fixture did not start")
                time.sleep(.01)
            descendant_fd = os.pidfd_open(int(ready.read_text()))
            self.descendant_exited = select.poll()
            self.descendant_exited.register(descendant_fd, select.POLLIN)

            def cleanup_descendant():
                try:
                    signal.pidfd_send_signal(descendant_fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                finally:
                    self.assertTrue(self.descendant_exited.poll(2000))
                    os.close(descendant_fd)

            self.addCleanup(cleanup_descendant)
            self.assertFalse(self.descendant_exited.poll(0), "fixture exited early")
            if leader_exits:
                os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOWAIT)
            return self.process

        original_killpg = os.killpg

        def kill_owned(group, sig):
            self.assertEqual(group, self.process.pid)
            self.assertEqual(os.getpgid(group), group, "command must own its group")
            self.assertEqual(os.getsid(group), group, "command must own its session")
            self.assertIsNone(self.process.returncode, "leader was reaped before cleanup")
            # A reaped leader would raise ChildProcessError here. Keeping it
            # waitable prevents its PID/PGID being reused before this signal.
            os.waitid(os.P_PID, group, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            self.signaled.append((group, sig))
            original_killpg(group, sig)

        for patch in (mock.patch.object(self.host.subprocess, "Popen", side_effect=launch),
                      mock.patch.object(self.host.os, "killpg", side_effect=kill_owned)):
            patch.start()
            self.addCleanup(patch.stop)
        return [sys.executable, "-B", "-c", program]

    def assert_cleaned(self, returncode):
        self.assertTrue(self.descendant_exited.poll(2000), "command left its descendant alive")
        self.assertEqual(self.process.returncode, returncode)
        self.assertTrue(self.signaled, "owned process group was never signaled")
        self.assertTrue(self.process.stdout.closed)
        self.assertTrue(self.process.stderr.closed)
        with self.assertRaises(ChildProcessError):
            os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)

    def test_bug196_timeout_cleans_descendant_with_closed_pipes(self):
        command = self.fixture("signal.pause()\n")
        with self.assertRaisesRegex(TimeoutError, "command deadline") as caught:
            self.host.bounded_run(command, .1)
        self.assertIsInstance(caught.exception.__cause__, subprocess.TimeoutExpired)
        self.assert_cleaned(-signal.SIGKILL)

    def test_bug196_timeout_cleans_descendant_holding_both_pipes(self):
        command = self.fixture("signal.pause()\n", inherited_pipes=True)
        with self.assertRaises(TimeoutError):
            self.host.bounded_run(command, .1)
        self.assert_cleaned(-signal.SIGKILL)

    def test_bug196_success_cleans_descendant_after_leader_exit(self):
        command = self.fixture("os.write(1, b'{}'); os.write(2, b'warning')\n",
                               leader_exits=True)
        result = self.host.bounded_run(command, .5)
        self.assertEqual((result.args, result.returncode, result.stdout, result.stderr),
                         (command, 0, b"{}", b"warning"))
        self.assert_cleaned(0)

    def test_completed_command_observed_after_its_deadline_times_out(self):
        command = self.fixture("pass\n", leader_exits=True)
        clock = mock.Mock()
        clock.monotonic.return_value = 0

        class DelayedEOF(self.host.selectors.DefaultSelector):
            def unregister(self, fileobj):
                key = super().unregister(fileobj)
                if not self.get_map():
                    clock.monotonic.return_value = 2
                return key

        with (mock.patch.object(self.host, "time", clock),
              mock.patch.object(self.host.selectors, "DefaultSelector", DelayedEOF),
              self.assertRaisesRegex(TimeoutError, "command deadline")):
            self.host.bounded_run(command, 1)
        self.assert_cleaned(0)

    def test_bug196_success_does_not_wait_for_descendant_pipe_eof(self):
        command = self.fixture("os.write(1, b'{}')\n", inherited_pipes=True,
                               leader_exits=True)
        result = self.host.bounded_run(command, .5)
        self.assertEqual(result.stdout, b"{}")
        self.assert_cleaned(0)

    def test_bug196_nonzero_exit_cleans_descendant_and_preserves_stderr(self):
        command = self.fixture("os.write(2, b'failed\\xff'); os._exit(7)\n",
                               inherited_pipes=True, leader_exits=True)
        with self.assertRaisesRegex(RuntimeError, "gcloud exited 7: failed\ufffd"):
            self.host.bounded_run(command, .5)
        self.assert_cleaned(7)

    def test_bug196_signal_exit_cleans_descendant(self):
        command = self.fixture("os.kill(os.getpid(), signal.SIGTERM)\n",
                               leader_exits=True)
        with self.assertRaisesRegex(RuntimeError, f"gcloud exited {-signal.SIGTERM}:"):
            self.host.bounded_run(command, .5)
        self.assert_cleaned(-signal.SIGTERM)

    def test_bug196_streaming_output_limit_cleans_running_group(self):
        command = self.fixture(
            "os.write(1, b'x' * ((1 << 20) + 1)); signal.pause()\n",
            inherited_pipes=True)
        with self.assertRaisesRegex(ValueError, "gcloud output limit exceeded"):
            self.host.bounded_run(command, 1)
        self.assert_cleaned(-signal.SIGKILL)

    def test_bug196_combined_output_limit_cleans_descendant(self):
        command = self.fixture(
            "os.write(1, b'x' * (1 << 19)); os.write(2, b'y' * ((1 << 19) + 1))\n")
        with self.assertRaisesRegex(ValueError, "gcloud output limit exceeded"):
            self.host.bounded_run(command, 1)
        self.assertTrue(self.descendant_exited.poll(2000), "output limit leaked descendant")

    def read_failure(self, error):
        command = self.fixture("os.write(1, b'ready'); signal.pause()\n")
        original_read = os.read

        def fail_read(descriptor, size):
            if self.process is not None and descriptor == self.process.stdout.fileno():
                raise error
            return original_read(descriptor, size)

        with mock.patch.object(self.host.os, "read", side_effect=fail_read):
            with self.assertRaises(type(error)) as caught:
                self.host.bounded_run(command, 1)
        self.assertIs(caught.exception, error)
        self.assert_cleaned(-signal.SIGKILL)

    def test_bug196_read_error_cleans_owned_group(self):
        self.read_failure(OSError("fixture read failure"))

    def test_bug196_interrupt_cleans_owned_group(self):
        self.read_failure(KeyboardInterrupt("fixture interrupt"))

    def test_exact_output_limit_preserves_binary_streams_and_stdin_eof(self):
        stdout = b"\x00\xff" * (1 << 18)
        stderr = b"\xfe\x00" * (1 << 18)
        command = [sys.executable, "-B", "-c",
                   "import os; assert os.read(0, 1) == b''; "
                   "os.write(1, b'\\x00\\xff' * (1 << 18)); "
                   "os.write(2, b'\\xfe\\x00' * (1 << 18))"]
        result = self.host.bounded_run(command, 5)
        self.assertEqual((result.args, result.returncode, result.stdout, result.stderr),
                         (command, 0, stdout, stderr))

    def test_nonzero_exit_reports_only_the_existing_stderr_tail(self):
        command = [sys.executable, "-B", "-c",
                   "import os; os.write(2, b'prefix' + b'x' * 4095 + b'\\xff'); os._exit(2)"]
        with self.assertRaises(RuntimeError) as caught:
            self.host.bounded_run(command, 5)
        self.assertEqual(str(caught.exception), "gcloud exited 2: " + "x" * 4095 + "\ufffd")


if __name__ == "__main__":
    unittest.main()
