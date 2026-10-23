"""Owned launcher cleanup, using local processes without cloud or KVM calls."""
import importlib.util
import os
from pathlib import Path
import select
import signal
import sys
import tempfile
import unittest
from unittest import mock


@unittest.skipUnless(sys.platform == "linux", "Linux process-group ownership")
class ProcessCleanupTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.runners = {}
        for name, filename, classname in (
                ("gcp", "gcp-reset-validation.py", "RemoteProcess"),
                ("firecracker", "firecracker-powercut-validation.py", "SerialProcess")):
            spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.runners[name] = (module, getattr(module, classname))

    def launch(self, name, leader_exits=True):
        module, runner = self.runners[name]
        command = (
            "import os, signal\n"
            "child = os.fork()\n"
            "if child == 0:\n"
            "    os.close(0)\n"
            "    os.close(1)\n"
            "    signal.pause()\n"
            "    os._exit(0)\n"
            "print(child, flush=True)\n"
            + ("" if leader_exits else "signal.pause()\n"))
        process = runner([sys.executable, "-c", command], self.root / name, "a" * 32, 0)
        self.addCleanup(process.close)
        ready, _, _ = select.select([process.child.stdout], [], [], 5)
        self.assertTrue(ready, "fixture did not launch its descendant")
        descendant = int(process.child.stdout.readline())
        descriptor = os.pidfd_open(descendant)

        def cleanup_descendant():
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                os.close(descriptor)

        self.addCleanup(cleanup_descendant)
        exited = select.poll()
        exited.register(descriptor, select.POLLIN)
        self.assertFalse(exited.poll(0), "fixture descendant exited prematurely")
        if leader_exits:
            # Observe termination without consuming the identity needed for
            # safe group cleanup. The controller itself must do the same.
            os.waitid(os.P_PID, process.child.pid, os.WEXITED | os.WNOWAIT)
        return module, process, exited

    def test_bug155_close_terminates_descendant_after_early_leader_exit(self):
        for name in self.runners:
            with self.subTest(runner=name):
                _, process, exited = self.launch(name)
                process.close()
                self.assertTrue(exited.poll(2000), "close left its descendant running")
                self.assertEqual(process.child.returncode, 0)

    def test_bug155_gcp_eof_does_not_reap_before_group_cleanup(self):
        _, process, exited = self.launch("gcp")
        with self.assertRaisesRegex(RuntimeError, "SSH closed"):
            process.event(5)
        process.close()
        self.assertTrue(exited.poll(2000), "EOF handling lost group ownership")
        self.assertEqual(process.child.returncode, 0)

    def test_poll_retains_leader_until_descendant_cleanup(self):
        for name in self.runners:
            with self.subTest(runner=name):
                _, process, exited = self.launch(name)
                self.assertEqual(process.poll(), 0)
                self.assertIsNone(process.child.returncode)
                self.assertIsNotNone(os.waitid(
                    os.P_PID, process.child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT))
                self.assertFalse(exited.poll(0))
                process.close()
                self.assertTrue(exited.poll(2000))

    def test_early_firecracker_diagnostics_cannot_reap_owned_leader(self):
        _, process, exited = self.launch("firecracker")
        with self.assertRaisesRegex(RuntimeError, "reaped child"):
            process.diagnostics()
        process.close()
        self.assertTrue(exited.poll(2000))
        self.assertEqual(process.child.returncode, 0)

    def test_gcp_cut_precheck_retains_group_for_cleanup(self):
        module, process, exited = self.launch("gcp")
        with mock.patch.object(module, "reset_instance") as reset:
            with self.assertRaisesRegex(RuntimeError, "before reset"):
                module.cut_instance(object(), process)
        reset.assert_not_called()
        process.close()
        self.assertTrue(exited.poll(2000))
        self.assertEqual(process.child.returncode, 0)

    def test_bug155_gcp_normal_waits_cleanup_before_reaping(self):
        for method in ("wait_clean", "wait_after_reset"):
            with self.subTest(method=method):
                # launch() needs a distinct artifact directory per child.
                self.root = Path(self.directory.name) / method
                self.root.mkdir()
                _, process, exited = self.launch("gcp")
                getattr(process, method)(5)
                process.close()
                self.assertTrue(exited.poll(2000), "normal wait lost group ownership")
                self.assertEqual(process.child.returncode, 0)

    def test_gcp_wait_timeout_still_terminates_owned_group(self):
        for method in ("wait_clean", "wait_after_reset"):
            with self.subTest(method=method):
                self.root = Path(self.directory.name) / method
                self.root.mkdir()
                module, process, exited = self.launch("gcp", leader_exits=False)
                with mock.patch.object(module.time, "monotonic", side_effect=[0, 1]):
                    with self.assertRaises(TimeoutError):
                        getattr(process, method)(.5)
                self.assertEqual(process.child.returncode, -signal.SIGKILL)
                self.assertTrue(exited.poll(2000))

    def test_bug155_failed_firecracker_crash_still_cleans_descendant(self):
        _, process, exited = self.launch("firecracker")
        with self.assertRaisesRegex(RuntimeError, "already exited"):
            process.crash()
        process.close()
        self.assertTrue(exited.poll(2000), "crash precheck lost group ownership")
        self.assertEqual(process.child.returncode, 0)

    def test_close_terminates_live_leader_and_descendant(self):
        for name in self.runners:
            with self.subTest(runner=name):
                _, process, exited = self.launch(name, leader_exits=False)
                process.close()
                self.assertTrue(exited.poll(2000))
                self.assertEqual(process.child.returncode, -signal.SIGKILL)

    def test_repeat_close_never_signals_a_reaped_process_group(self):
        for name in self.runners:
            with self.subTest(runner=name):
                module, process, _ = self.launch(name, leader_exits=False)
                process.close()
                with mock.patch.object(module.os, "killpg") as kill:
                    process.close()
                kill.assert_not_called()

    def test_firecracker_crash_preserves_sigkill_result_and_repeated_cleanup(self):
        module, process, exited = self.launch("firecracker", leader_exits=False)
        result = process.crash()
        self.assertEqual(result["returncode"], -signal.SIGKILL)
        self.assertTrue(exited.poll(2000))
        with mock.patch.object(module.os, "killpg") as kill:
            process.close()
        kill.assert_not_called()
        self.assertIsInstance(process.diagnostics(), str)


if __name__ == "__main__":
    unittest.main()
