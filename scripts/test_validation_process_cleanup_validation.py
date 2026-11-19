"""Owned launcher cleanup, using local processes without cloud or KVM calls."""
import importlib.util
import json
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

    def test_event_received_after_deadline_is_rejected(self):
        token = "a" * 32
        for name, (module, runner) in self.runners.items():
            for observed in (4, 10, 12):
                with self.subTest(name=name, observed=observed):
                    process = runner.__new__(runner)
                    process.token, process.boot, process.cycle = token, 0, 0
                    process.buffer, process.total = bytearray(), 0
                    process.selector = mock.Mock()
                    process.child = mock.Mock()
                    process.serial = process.stdout_log = mock.Mock()
                    frame = {"event": "ready", "token": token, "boot": 0, "cycle": 0,
                             "boot_id": "00112233-4455-6677-8899-aabbccddeeff"}
                    wire = module.PREFIX + json.dumps(frame).encode() + b"\n"
                    times = [0, 0, observed]
                    with mock.patch.object(module.time, "monotonic", side_effect=times), \
                            mock.patch.object(module.os, "read", return_value=wire):
                        if observed < 10:
                            self.assertEqual(process.expect("ready", 10), frame)
                        else:
                            with self.assertRaises(TimeoutError):
                                process.expect("ready", 10)

    def test_campaign_save_failure_preserves_the_previous_complete_report(self):
        for name, (module, _) in self.runners.items():
            with self.subTest(name=name):
                folder = self.root / name
                folder.mkdir()
                path = folder / "results.json"
                module.save_json(path, {"boots": [1]})
                def fail_after_prefix(value, stream, **options):
                    stream.write('{"partial":')
                    raise OSError("no space left on device")
                with mock.patch.object(json, "dump", side_effect=fail_after_prefix):
                    with self.assertRaisesRegex(OSError, "no space"):
                        module.save_json(path, {"boots": [1, 2]})
                self.assertEqual(json.loads(path.read_text()), {"boots": [1]})
                self.assertEqual(list(folder.iterdir()), [path])
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_stderr_is_bounded_and_cannot_block_control_stdout(self):
        for name, (module, runner) in self.runners.items():
            with self.subTest(name=name), mock.patch.object(module, "MAX_OUTPUT", 8192):
                folder = self.root / name
                # Write more than fits in either the stderr pipe or the diagnostic log.
                program = ("import os; data=b'x'*4096; "
                           "[os.write(2,data) for _ in range(128)]; print('finished',flush=True)")
                with runner([sys.executable, "-c", program], folder, "a" * 32, 0) as process:
                    self.assertTrue(select.select([process.child.stdout], [], [], 5)[0])
                    self.assertEqual(process.child.stdout.readline(), b"finished\n")
                diagnostics = (folder / "stderr.log").read_bytes()
                self.assertEqual(len(diagnostics), 8192)
                self.assertTrue(diagnostics.endswith(b"[stderr truncated]\n"))

    def test_diagnostics_capture_high_numbered_pipe(self):
        import fcntl
        import resource

        soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft_limit != resource.RLIM_INFINITY and soft_limit <= 1024:
            self.skipTest("needs a pipe descriptor above the select() limit")
        read_fd, write_fd = os.pipe()
        with os.fdopen(read_fd, "rb") as original, os.fdopen(write_fd, "wb") as writer:
            high_fd = fcntl.fcntl(original, fcntl.F_DUPFD_CLOEXEC, 1024)
            with os.fdopen(high_fd, "rb") as pipe, tempfile.TemporaryFile() as log:
                writer.write(b"campaign diagnostics")
                writer.close()
                module, _ = self.runners["gcp"]
                module.DiagnosticLog(pipe, log, 8192).finish()
                log.seek(0)
                self.assertEqual(log.read(), b"campaign diagnostics")

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
