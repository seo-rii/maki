"""The background runner must not mistake interruption or empty runs for a pass."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock


class BackgroundStorageTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location(
            "storage_runner", Path(__file__).with_name("storage-repeat-validation.py"))
        self.runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.runner)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_rollback_profile_builds_each_required_package_and_freezes_all_suites(self):
        expected = {
            "maki-backing": ("rollback_backing", "rollback_model"),
            "maki-core": ("rollback_protection", "rollback_process"),
        }
        calls = []

        def child(command, _cwd, log, _stop, _timeout, **_kwargs):
            calls.append(command)
            if command[0] == "cargo":
                package = command[command.index("-p") + 1]
                self.assertIn(package, expected)
                selected = tuple(command[i + 1] for i, arg in enumerate(command) if arg == "--test")
                self.assertEqual(selected, expected[package])
                events = []
                for name in selected:
                    executable = self.root / (name + "-build")
                    executable.write_bytes(b"frozen fixture")
                    events.append(json.dumps({"reason": "compiler-artifact", "target": {"name": name},
                                              "executable": str(executable)}))
                log.write_text("\n".join(events))
            else:
                log.write_text("fixture: test\n")
            return {"exit_code": 0, "reason": "exited"}

        config = {"source": str(self.root), "target_dir": str(self.root / "target"),
                  "profile": "rollback"}
        with mock.patch.object(self.runner, "run_child", side_effect=child):
            binaries = self.runner.prepare(self.root, config, time.monotonic() + 30)
        self.assertEqual(set(binaries), {name for group in expected.values() for name in group})
        manifest = json.loads((self.root / "binaries.json").read_text())
        self.assertEqual(set(manifest), set(binaries))
        self.assertTrue(all(value["expected_tests"] == 1 for value in manifest.values()))
        self.assertEqual(sum(command[0] == "cargo" for command in calls), 2)

    def test_unknown_profile_cannot_silently_run_the_default_suites(self):
        with mock.patch.object(self.runner, "run_child") as child:
            with self.assertRaisesRegex(ValueError, "profile"):
                self.runner.prepare(self.root, {"profile": "typo"}, time.monotonic() + 30)
            child.assert_not_called()

    def prepare_with_clock(self, budget, build_seconds=0, list_seconds=0,
                           after_child=None, groups=None):
        """Advance a fake clock while exercising real prepare orchestration."""
        clock = [0]
        calls = []
        groups = groups or {"fixture": ("one", "two", "three")}

        def child(command, _cwd, log, stop, timeout, **_kwargs):
            calls.append((command, timeout))
            is_build = command[0] == "cargo"
            seconds = build_seconds if is_build else list_seconds
            clock[0] += min(seconds, max(0, timeout))
            if stop.exists():
                result = {"exit_code": 130, "reason": "cancelled"}
            elif timeout < seconds:
                result = {"exit_code": -9, "reason": "timeout"}
            else:
                result = {"exit_code": 0, "reason": "exited"}
            if is_build:
                package = command[command.index("-p") + 1]
                events = []
                for name in groups[package]:
                    artifact = self.root / (name + "-built")
                    artifact.write_bytes(b"fixture binary")
                    events.append(json.dumps({"reason": "compiler-artifact", "target": {"name": name},
                                              "executable": str(artifact)}))
                log.write_text("\n".join(events))
            else:
                log.write_text("fixture: test\n")
            if after_child is not None:
                after_child(command, clock)
            return result

        config = {"source": str(self.root), "target_dir": str(self.root / "target")}
        with mock.patch.object(self.runner, "suite_groups", return_value=groups), \
                mock.patch.object(self.runner.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(self.runner, "run_child", side_effect=child):
            error = None
            try:
                self.runner.prepare(self.root, config, budget)
            except Exception as caught:
                error = caught
        return calls, clock[0], error

    def test_bug156_enumeration_uses_remaining_campaign_budget(self):
        calls, elapsed, error = self.prepare_with_clock(1, build_seconds=.2, list_seconds=.6)
        self.assertIsInstance(error, TimeoutError)
        self.assertEqual(len(calls), 3, "expired campaign must not enumerate another binary")
        self.assertAlmostEqual(calls[1][1], .8)
        self.assertAlmostEqual(calls[2][1], .2)
        self.assertAlmostEqual(elapsed, 1)
        self.assertFalse((self.root / "binaries.json").exists())

    def test_bug156_expired_preparation_starts_no_build(self):
        calls, _, error = self.prepare_with_clock(0)
        self.assertIsInstance(error, TimeoutError)
        self.assertEqual(calls, [])
        self.assertFalse((self.root / "bin").exists())

    def test_bug156_no_new_build_or_enumeration_after_budget_expires(self):
        calls, _, error = self.prepare_with_clock(
            1, build_seconds=1, groups={"first": ("one",), "second": ("two",)})
        self.assertIsInstance(error, TimeoutError)
        self.assertEqual(len(calls), 1)
        self.assertFalse((self.root / "bin").exists())

    def test_bug156_time_spent_freezing_binary_is_in_campaign_budget(self):
        def child_completed(command, clock):
            if command[0] == "cargo":
                # Reading/copying artifacts can exhaust the remaining budget
                # even when the preceding child completed successfully.
                original = self.runner.shutil.copyfile

                def copyfile(*args, **kwargs):
                    result = original(*args, **kwargs)
                    clock[0] = 1
                    return result

                patch = mock.patch.object(self.runner.shutil, "copyfile", side_effect=copyfile)
                patch.start()
                self.addCleanup(patch.stop)

        calls, _, error = self.prepare_with_clock(1, after_child=child_completed)
        self.assertIsInstance(error, TimeoutError)
        self.assertEqual(len(calls), 1)
        self.assertFalse((self.root / "binaries.json").exists())

    def test_preparation_preserves_per_child_caps_with_enough_budget(self):
        calls, elapsed, error = self.prepare_with_clock(2000, build_seconds=1, list_seconds=1)
        self.assertIsNone(error)
        self.assertEqual([timeout for _, timeout in calls], [1800, 30, 30, 30])
        self.assertEqual(elapsed, 4)
        manifest = json.loads((self.root / "binaries.json").read_text())
        self.assertEqual(set(manifest), {"one", "two", "three"})
        self.assertTrue(all(item["expected_tests"] == 1 for item in manifest.values()))

    def test_preparation_child_cap_timeout_remains_incomplete(self):
        for stage, build_seconds, list_seconds, expected in (
                ("build", 1801, 0, 1800), ("list", 0, 31, 30)):
            with self.subTest(stage=stage):
                self.root = Path(self.temp.name) / stage
                self.root.mkdir()
                _, elapsed, error = self.prepare_with_clock(
                    2000, build_seconds=build_seconds, list_seconds=list_seconds)
                self.assertIsInstance(error, TimeoutError)
                self.assertEqual(elapsed, expected)
                self.assertFalse((self.root / "binaries.json").exists())

    def test_preparation_does_not_launch_next_child_after_stop(self):
        def stop_after_build(command, _clock):
            if command[0] == "cargo":
                (self.root / "STOP").touch()

        calls, _, error = self.prepare_with_clock(100, after_child=stop_after_build)
        self.assertIsNotNone(error)
        self.assertEqual(len(calls), 1)
        self.assertFalse((self.root / "binaries.json").exists())

    def test_bug156_preparation_timeout_is_incomplete_and_stop_is_cancelled(self):
        for cancelled in (False, True):
            with self.subTest(cancelled=cancelled):
                directory = self.root / str(cancelled)
                directory.mkdir()
                self.runner.save_json(directory / "config.json", {
                    "rounds": 1, "max_seconds": 10, "suite_timeout": 5,
                    "revision": "fixture", "source": str(directory),
                })
                if cancelled:
                    (directory / "STOP").touch()
                with mock.patch.object(self.runner, "prepare", side_effect=TimeoutError("preparation deadline")):
                    self.assertEqual(self.runner.worker(directory), 1)
                report = json.loads((directory / "status.json").read_text())
                self.assertEqual(report["state"], "cancelled" if cancelled else "incomplete")
                self.assertEqual(report["completed_rounds"], 0)
                self.assertEqual(report["passed_tests"], 0)
                self.assertIn("preparation deadline", report["error"])

    def test_each_started_campaign_uses_its_own_target_directory(self):
        def completed(command, **_kwargs):
            if command[:2] == ["git", "archive"]:
                output = next(value for value in command if value.startswith("--output="))
                Path(output.split("=", 1)[1]).write_bytes(b"frozen source")
            return subprocess.CompletedProcess(command, 0)

        process = mock.Mock(pid=os.getpid())
        args = types.SimpleNamespace(rounds=1, max_seconds=60, suite_timeout=30)
        with mock.patch.object(self.runner.Path, "home", return_value=self.root), \
                mock.patch.object(
                    self.runner.shutil, "disk_usage", return_value=types.SimpleNamespace(free=3 << 30)
                ), \
                mock.patch.object(self.runner.subprocess, "run", side_effect=completed), \
                mock.patch.object(
                    self.runner.subprocess,
                    "check_output",
                    side_effect=["revision-one\n", "rustc fixture\n", "cargo fixture\n",
                                 "revision-two\n", "rustc fixture\n", "cargo fixture\n"],
                ), \
                mock.patch.object(self.runner.subprocess, "Popen", return_value=process):
            self.runner.start(args)
            first = json.loads((self.root / "logs/maki-storage-latest.json").read_text())
            args.profile = "rollback"
            self.runner.start(args)
            second = json.loads((self.root / "logs/maki-storage-latest.json").read_text())

        first_config = json.loads((Path(first["run_dir"]) / "config.json").read_text())
        second_config = json.loads((Path(second["run_dir"]) / "config.json").read_text())
        self.assertEqual(Path(first_config["target_dir"]), Path(first["run_dir"]) / "target")
        self.assertEqual(Path(second_config["target_dir"]), Path(second["run_dir"]) / "target")
        self.assertNotEqual(first_config["target_dir"], second_config["target_dir"])
        self.assertEqual(first_config["profile"], "storage")
        self.assertEqual(first_config["suites"], list(self.runner.SUITES))
        self.assertEqual(second_config["profile"], "rollback")
        self.assertEqual(second_config["suites"], [
            "rollback_backing", "rollback_model", "rollback_protection", "rollback_process",
        ])

    def test_only_complete_nonempty_test_results_are_accepted(self):
        valid = "test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.2s"
        self.assertEqual(self.runner.passed_count(valid), 14)
        for text in ("", valid.replace("14 passed", "0 passed"),
                     valid.replace("0 ignored", "1 ignored"),
                     valid.replace("0 filtered out", "1 filtered out"),
                     valid.replace("0 failed", "1 failed")):
            with self.assertRaises(ValueError):
                self.runner.passed_count(text)

    @unittest.skipUnless(sys.platform == "linux", "Linux background runner")
    def test_child_exit_timeout_and_cancellation_are_distinct(self):
        handlers = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT)}
        result = self.runner.run_child(
            [sys.executable, "-c", "raise SystemExit(7)"], self.root,
            self.root / "failed.log", self.root / "STOP", 10)
        self.assertEqual(result["exit_code"], 7)
        self.assertEqual(result["reason"], "exited")
        result = self.runner.run_child(
            [sys.executable, "-c", "import time; time.sleep(30)"], self.root,
            self.root / "timeout.log", self.root / "STOP", .1)
        self.assertEqual(result["reason"], "timeout")
        (self.root / "STOP").touch()
        result = self.runner.run_child(
            [sys.executable, "-c", "raise SystemExit(0)"], self.root,
            self.root / "cancel.log", self.root / "STOP", 10)
        self.assertEqual(result["reason"], "cancelled")
        self.assertNotEqual(result["exit_code"], 0)
        self.assertEqual({number: signal.getsignal(number) for number in handlers}, handlers)

    @unittest.skipUnless(sys.platform == "linux", "Linux background runner")
    def test_supervisor_signal_cleans_build_and_suite_groups_and_records_cancellation(self):
        module_path = Path(__file__).with_name("storage-repeat-validation.py").resolve()
        for stage, number, during_launch in (("build", signal.SIGTERM, False),
                                             ("suite", signal.SIGTERM, False),
                                             ("suite", signal.SIGINT, False),
                                             ("build", signal.SIGTERM, True)):
            with self.subTest(stage=stage, signal=number, during_launch=during_launch):
                directory = self.root / f"{stage}-{number}-{during_launch}"
                directory.mkdir()
                fixture = directory / ("cargo" if stage == "build" else "fixture")
                fixture.write_text(
                    f"#!{sys.executable}\n"
                    "import json, os, pathlib, subprocess, sys, time\n"
                    "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
                    f"ready = pathlib.Path({str(directory / 'children.json')!r})\n"
                    "temporary = ready.with_suffix('.tmp')\n"
                    "temporary.write_text(json.dumps([os.getpid(), child.pid]))\n"
                    "temporary.replace(ready)\n"
                    "time.sleep(30)\n")
                fixture.chmod(0o700)
                self.runner.save_json(directory / "config.json", {
                    "rounds": 1, "max_seconds": 10, "suite_timeout": 5,
                    "revision": "fixture", "source": str(directory),
                    "target_dir": str(directory / "target"),
                })
                controller_code = (
                    "import importlib.util, os, pathlib, signal, time\n"
                    f"spec = importlib.util.spec_from_file_location('runner', {str(module_path)!r})\n"
                    "runner = importlib.util.module_from_spec(spec)\n"
                    "spec.loader.exec_module(runner)\n"
                    f"directory = pathlib.Path({str(directory)!r})\n")
                if stage == "suite":
                    controller_code += (
                        "runner.prepare = lambda *args: {'fixture': directory / 'fixture'}\n")
                if during_launch:
                    controller_code += (
                        "original = runner.subprocess.Popen\n"
                        "def interrupted_launch(*args, **kwargs):\n"
                        "    child = original(*args, **kwargs)\n"
                        "    deadline = time.monotonic() + 5\n"
                        "    while not (directory / 'SIGNAL').exists():\n"
                        "        if time.monotonic() >= deadline:\n"
                        "            os.killpg(child.pid, signal.SIGKILL)\n"
                        "            child.wait()\n"
                        "            raise RuntimeError('launch fixture timed out')\n"
                        "        time.sleep(.01)\n"
                        f"    os.kill(os.getpid(), {number})\n"
                        "    return child\n"
                        "runner.subprocess.Popen = interrupted_launch\n")
                controller_code += "raise SystemExit(runner.worker(directory))\n"
                environment = dict(os.environ, PATH=str(directory) + os.pathsep + os.environ["PATH"])
                with os.fdopen(os.open(directory / "controller.log",
                                       os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
                    controller = subprocess.Popen(
                        [sys.executable, "-B", "-c", controller_code], env=environment,
                        stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                        start_new_session=True)
                self.addCleanup(self.stop_controller, controller)
                deadline = time.monotonic() + 5
                while not (directory / "children.json").exists():
                    self.assertIsNone(controller.poll())
                    self.assertLess(time.monotonic(), deadline, "fixture did not start")
                    time.sleep(.01)
                pids = json.loads((directory / "children.json").read_text())
                identities = {pid: self.runner.process_identity(pid) for pid in pids}
                self.assertTrue(all(identities.values()))
                self.addCleanup(self.stop_owned_group, pids[0], identities)
                if during_launch:
                    (directory / "SIGNAL").touch()
                else:
                    controller.send_signal(number)
                self.assertEqual(controller.wait(timeout=5), 1)
                deadline = time.monotonic() + 3
                while any(self.runner.process_identity(pid) == identity
                          for pid, identity in identities.items()) and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(all(self.runner.process_identity(pid) != identity
                                    for pid, identity in identities.items()),
                                "supervisor termination left an owned process alive")
                report = json.loads((directory / "status.json").read_text())
                self.assertEqual(report["state"], "cancelled")
                self.assertEqual(report["exit_code"], 1)
                self.assertEqual(report["completed_rounds"], 0)
                self.assertTrue((directory / "STOP").exists())
                self.assertIn("cancelled", report["error"])

    @unittest.skipUnless(sys.platform == "linux", "Linux background runner")
    def test_descendant_cleanup_preserves_early_leader_exit_status(self):
        child_code = (
            "import os, pathlib, time\n"
            f"pathlib.Path({str(self.root / 'descendant.pid')!r}).write_text(str(os.getpid()))\n"
            "time.sleep(30)\n")
        leader_code = (
            "import pathlib, subprocess, sys, time\n"
            f"subprocess.Popen([sys.executable, '-c', {child_code!r}])\n"
            f"ready = pathlib.Path({str(self.root / 'descendant.pid')!r})\n"
            "deadline = time.monotonic() + 5\n"
            "while not ready.exists():\n"
            "    if time.monotonic() >= deadline:\n"
            "        raise RuntimeError('descendant did not start')\n"
            "    time.sleep(.01)\n")
        result = self.runner.run_child(
            [sys.executable, "-c", leader_code], self.root,
            self.root / "leader.log", self.root / "STOP", 10)
        self.assertEqual(result["reason"], "exited")
        self.assertEqual(result["exit_code"], 0)
        pid = int((self.root / "descendant.pid").read_text())
        deadline = time.monotonic() + 3
        while self.runner.process_identity(pid) is not None and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertIsNone(self.runner.process_identity(pid), "leader exit left its descendant running")

    @staticmethod
    def stop_controller(controller):
        if controller.poll() is None:
            controller.kill()
        controller.wait(timeout=5)

    def stop_owned_group(self, group, identities):
        # A matching live descendant still reserves this process group ID.
        for pid, identity in identities.items():
            if self.runner.process_identity(pid) == identity:
                try:
                    if os.getpgid(pid) == group:
                        os.killpg(group, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                return

    @unittest.skipUnless(sys.platform == "linux", "Linux background runner")
    def test_output_limit_stops_noisy_child_and_logs_are_private(self):
        result = self.runner.run_child(
            [sys.executable, "-c", "import os,time; os.write(1,b'x'*4096); time.sleep(30)"],
            self.root, self.root / "noisy.log", self.root / "STOP", 10, max_bytes=1024)
        self.assertEqual(result["reason"], "output_limit")
        self.assertEqual((self.root / "noisy.log").stat().st_mode & 0o777, 0o600)

    def test_atomic_state_is_private(self):
        self.runner.save_json(self.root / "status.json", {"state": "running"})
        self.runner.save_json(self.root / "status.json", {"state": "failed"})
        self.assertEqual(json.loads((self.root / "status.json").read_text())["state"], "failed")
        self.assertEqual((self.root / "status.json").stat().st_mode & 0o777, 0o600)

    @unittest.skipUnless(sys.platform == "linux", "Linux process identity")
    def test_pid_reuse_and_missing_pid_are_not_running(self):
        identity = self.runner.process_identity(os.getpid())
        self.assertTrue(self.runner.alive({"pid": os.getpid(), "identity": identity}))
        self.assertFalse(self.runner.alive({"pid": os.getpid(), "identity": "old"}))
        self.assertFalse(self.runner.alive({"pid": 999999999, "identity": identity}))

    @unittest.skipUnless(sys.platform == "linux", "Linux background runner")
    def test_terminal_report_requires_all_rounds_and_records_failure(self):
        for child_exit, expected in [(0, "passed"), (7, "failed")]:
            directory = self.root / str(child_exit)
            directory.mkdir()
            executable = directory / "fixture"
            executable.write_text(
                f"#!{sys.executable}\n"
                "print('test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.0s')\n"
                f"raise SystemExit({child_exit})\n")
            executable.chmod(0o700)
            self.runner.save_json(directory / "config.json", {
                "rounds": 2, "max_seconds": 10, "suite_timeout": 5,
                "revision": "fixture", "source": str(directory),
            })
            with mock.patch.object(self.runner, "prepare", return_value={"fixture": executable}):
                exit_code = self.runner.worker(directory)
            report = json.loads((directory / "status.json").read_text())
            self.assertEqual(report["state"], expected)
            self.assertEqual(report["exit_code"], exit_code)
            self.assertEqual(report["completed_rounds"], 2 if child_exit == 0 else 0)
            self.assertEqual(report["passed_tests"], 4 if child_exit == 0 else 0)

    @unittest.skipUnless(sys.platform == "linux", "Linux background runner")
    def test_build_exception_also_persists_terminal_failure(self):
        self.runner.save_json(self.root / "config.json", {
            "rounds": 1, "max_seconds": 10, "suite_timeout": 5,
            "revision": "fixture", "source": str(self.root),
        })
        with mock.patch.object(self.runner, "prepare", side_effect=OSError("no compiler")):
            self.assertNotEqual(self.runner.worker(self.root), 0)
        report = json.loads((self.root / "status.json").read_text())
        self.assertEqual(report["state"], "failed")
        self.assertIn("no compiler", report["error"])


if __name__ == "__main__":
    unittest.main()
