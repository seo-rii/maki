"""The background runner must not mistake interruption or empty runs for a pass."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
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
            self.runner.start(args)
            second = json.loads((self.root / "logs/maki-storage-latest.json").read_text())

        first_config = json.loads((Path(first["run_dir"]) / "config.json").read_text())
        second_config = json.loads((Path(second["run_dir"]) / "config.json").read_text())
        self.assertEqual(Path(first_config["target_dir"]), Path(first["run_dir"]) / "target")
        self.assertEqual(Path(second_config["target_dir"]), Path(second["run_dir"]) / "target")
        self.assertNotEqual(first_config["target_dir"], second_config["target_dir"])

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
