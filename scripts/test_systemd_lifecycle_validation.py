"""Private-unit fixture contracts; these tests never talk to systemd."""

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("systemd-lifecycle-validation.py")
SPEC = importlib.util.spec_from_file_location("maki_systemd_fixture", SCRIPT)
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class SystemdLifecycleFixtureTests(unittest.TestCase):
    def verify_events(self, mode, events, target_state, *, states=None, resource=False):
        """Run the campaign oracle against a trace without using a service manager."""
        with tempfile.TemporaryDirectory() as temporary:
            case = fixture.Fixture(Path(temporary), Path("/tmp/helper"), mode)
            records = [{"event": name} for name in events]
            if resource:
                (case.directory / "resource").write_text("owned")
            with (patch.object(case, "ctl", return_value=subprocess.CompletedProcess([], 0, "", "")),
                  patch.object(case, "events", return_value=records),
                  patch.object(case, "state", side_effect=lambda which: (states or {}).get(which, target_state)),
                  patch.object(case, "wait", side_effect=lambda condition, label:
                               fixture.require(condition(), "timed out: " + label)),
                  patch.object(fixture.time, "sleep")):
                case.verify(mode)

    def test_failed_cleanup_trace_requires_live_daemon(self):
        with self.assertRaisesRegex(AssertionError, "daemon"):
            self.verify_events("failed-stop", (
                "daemon-start", "attach-start", "attach-ready", "workload-start",
                "workload-stop", "cleanup-stop", "cleanup-refused", "daemon-stop",
            ), "inactive", states={"attach": "failed"}, resource=True)

    def test_cancelled_start_cannot_stop_daemon_with_resource(self):
        with self.assertRaisesRegex(AssertionError, "daemon"):
            self.verify_events("cancel-start", (
                "daemon-start", "attach-start", "daemon-stop",
            ), "inactive", resource=True)

    def test_failed_or_interrupted_cleanup_preserves_live_daemon(self):
        for mode in ("failed-stop", "timeout-stop", "kill-stop"):
            with self.subTest(mode=mode):
                self.verify_events(mode, (
                    "daemon-start", "attach-start", "attach-ready", "workload-start",
                    "workload-stop", "cleanup-stop", "cleanup-refused",
                ), "inactive", states={"attach": "failed", "daemon": "active"}, resource=True)

    def test_normal_stop_requires_cleanup_before_daemon_stop(self):
        prefix = ("daemon-start", "attach-start", "attach-ready", "workload-start",
                  "workload-stop", "cleanup-stop")
        self.verify_events("normal-stop", (*prefix, "cleanup-complete", "daemon-stop"), "inactive")
        with self.assertRaisesRegex(AssertionError, "daemon stopped before"):
            self.verify_events("normal-stop", (*prefix, "daemon-stop", "cleanup-complete"), "inactive")

    def test_normal_stop_waits_for_the_actual_daemon_shutdown(self):
        with self.assertRaisesRegex(AssertionError, "daemon"):
            self.verify_events("normal-stop", (
                "daemon-start", "attach-start", "attach-ready", "workload-start",
                "workload-stop", "cleanup-stop", "cleanup-complete",
            ), "inactive", states={"daemon": "active"})

    def test_recovery_oracle_accepts_cleanup_before_each_reattach(self):
        self.verify_events("exit-once", (
            "attach-start", "cleanup-recover", "cleanup-complete",
            "attach-start", "attach-ready", "workload-start",
        ), "active")
        self.verify_events("repeated-failure", (
            "attach-start", "cleanup-recover", "cleanup-complete",
            "attach-start", "cleanup-recover", "cleanup-complete",
            "attach-start", "cleanup-recover", "cleanup-complete",
        ), "failed")

    def test_recovery_oracle_rejects_reattach_before_cleanup_completion(self):
        for completion in ((), ("cleanup-complete",)):
            with self.subTest(completion=completion):
                with self.assertRaisesRegex(AssertionError, "reattach"):
                    self.verify_events("exit-once", (
                        "attach-start", "cleanup-recover",
                        "attach-start", "attach-ready", "workload-start",
                        *completion,
                    ), "active")

    def test_recovery_oracle_rejects_stale_cleanup_completion(self):
        with self.assertRaisesRegex(AssertionError, "reattach"):
            self.verify_events("repeated-failure", (
                "attach-start", "cleanup-recover", "cleanup-complete",
                "attach-start", "cleanup-recover",
                "attach-start", "cleanup-complete",
            ), "failed")

    def test_cancellation_oracle_rejects_unsafe_events(self):
        self.verify_events("cancel-start", ("attach-start",), "inactive",
                           states={"daemon": "active"}, resource=True)
        for event in ("unsafe-workload-start", "unsafe-cleanup-before-workload-stop"):
            with self.subTest(event=event):
                with self.assertRaisesRegex(AssertionError, "unsafe"):
                    self.verify_events("cancel-start", ("attach-start", event), "inactive",
                                       states={"daemon": "active"}, resource=True)

    def test_cancellation_waits_for_service_stop_jobs_before_checking_safety(self):
        for terminal_state in ("inactive", "failed"):
            with self.subTest(terminal_state=terminal_state), tempfile.TemporaryDirectory() as temporary:
                case = fixture.Fixture(Path(temporary), Path("/tmp/helper"), "cancel-start")
                (case.directory / "resource").write_text("owned")
                records = [{"event": "attach-start"}]
                stopping = iter(("deactivating", terminal_state))

                def state(which):
                    if which == "target":
                        return "inactive"
                    if which == "daemon":
                        return "active"
                    result = next(stopping, terminal_state)
                    if result == terminal_state:
                        records.append({"event": "unsafe-workload-start"})
                    return result

                with (patch.object(case, "ctl", return_value=subprocess.CompletedProcess([], 0, "", "")),
                      patch.object(case, "events", return_value=records),
                      patch.object(case, "state", side_effect=state),
                      patch.object(fixture.time, "sleep")):
                    with self.assertRaisesRegex(AssertionError, "unsafe"):
                        case.verify("cancel-start")

    def test_attach_refuses_to_overwrite_an_existing_resource(self):
        for contents in ("owned", "foreign"):
            with self.subTest(contents=contents), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                (directory / "mode").write_text("normal-stop")
                resource = directory / "resource"
                resource.write_text(contents)
                self.assertNotEqual(fixture.actor(directory, "attach"), 0)
                self.assertEqual(resource.read_text(), contents)
                self.assertIn("unsafe-attach-existing-resource",
                              (directory / "events.jsonl").read_text())

    def test_graph_uses_only_private_instances_and_the_real_hook(self):
        volume = "mkci_fixture123"
        units = fixture.names(volume)
        files = fixture.fixture_units(volume, Path("/tmp/private fixture"), Path("/tmp/real helper"))
        self.assertEqual(set(files), set(units.values()))
        for content in files.values():
            self.assertNotIn("%i", content)
            self.assertNotIn("AssertPathExists=", content)
            self.assertNotIn("network-online.target", content)
            self.assertNotIn("/dev/nbd", content)
            self.assertNotIn("WantedBy=multi-user.target", content)
        attach = files[units["attach"]]
        self.assertIn('ExecStopPost="/tmp/real helper" recover-failed-start --volume mkci_fixture123', attach)
        self.assertIn("StartLimitIntervalSec=300", attach)
        self.assertIn("StartLimitBurst=3", attach)
        self.assertNotIn("PartOf=", files[units["daemon"]])
        stop_commands = [line for line in attach.splitlines() if line.startswith("ExecStop=")]
        self.assertEqual(len(stop_commands), 2)
        self.assertIn("cleanup-stop", stop_commands[0])
        self.assertFalse(stop_commands[0].startswith("ExecStop=-"))
        self.assertEqual(stop_commands[1], fixture.STOP_REQUEST.replace("%i", volume))
        recovery = files[units["recovery"]]
        self.assertIn(f"OnSuccess={units['target']}", recovery)
        self.assertIn(f"After={units['target']} {units['attach']} {units['daemon']}", recovery)
        self.assertIn("StartLimitBurst=3", recovery)

    def test_unexpected_hook_or_external_dependency_is_refused(self):
        read_text = Path.read_text
        for replacement in ("OnFailure=foreign.service\n", "ExecStopPost=/bin/false\n"):
            def changed(path, *args, **kwargs):
                text = read_text(path, *args, **kwargs)
                if path.name == "maki-attach@.service":
                    if replacement.startswith("OnFailure"):
                        return text.replace("[Unit]\n", "[Unit]\n" + replacement)
                    return text.replace("ExecStopPost=/usr/bin/maki-attach recover-failed-start --volume %i\n", replacement)
                return text
            with self.subTest(replacement=replacement), patch.object(Path, "read_text", changed):
                with self.assertRaises(ValueError):
                    fixture.fixture_units("mkci_fixture", Path("/tmp/private"), Path("/tmp/helper"))

    def test_fixture_refuses_changed_or_missing_daemon_stop_request(self):
        read_text = Path.read_text
        for replacement in ("", fixture.STOP_REQUEST.replace("--job-mode=fail", "--job-mode=replace"),
                            fixture.STOP_REQUEST.replace("ExecStop=-", "ExecStop=")):
            def changed(path, *args, **kwargs):
                text = read_text(path, *args, **kwargs)
                if path.name == "maki-attach@.service":
                    return text.replace(fixture.STOP_REQUEST, replacement)
                return text
            with self.subTest(replacement=replacement), patch.object(Path, "read_text", changed):
                with self.assertRaisesRegex(ValueError, "cleanup/daemon-stop"):
                    fixture.fixture_units("mkci_fixture", Path("/tmp/private"), Path("/tmp/helper"))

    def test_manual_cleanup_retries_only_after_the_blocker_is_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "mode").write_text("retry-failed-stop")
            self.assertEqual(fixture.actor(directory, "attach"), 0)
            self.assertNotEqual(fixture.actor(directory, "cleanup-stop"), 0)
            self.assertNotEqual(fixture.actor(directory, "cleanup-manual"), 0)
            self.assertTrue((directory / "resource").exists())
            (directory / "allow-cleanup").touch()
            self.assertEqual(fixture.actor(directory, "cleanup-manual"), 0)
            self.assertFalse((directory / "resource").exists())

    def test_instance_and_argument_boundaries(self):
        for volume in ("production", "mkci_../production", "mkci_name.service", "mkci_"):
            with self.assertRaises(ValueError):
                fixture.names(volume)
        self.assertEqual(fixture.unit_argument('a "$b" %i \\'), '"a \\"$$b\\" %%i \\\\"')
        with self.assertRaises(ValueError):
            fixture.unit_argument("path\ninjection")

    def test_simulated_cleanup_preserves_live_workload_foreign_resource_and_failure(self):
        for mode in ("exit-once", "foreign-resource", "cleanup-failure"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                (directory / "mode").write_text(mode)
                self.assertEqual(fixture.actor(directory, "attach"), 1)
                if mode == "exit-once":
                    (directory / "workload-running").touch()
                    self.assertNotEqual(fixture.actor(directory, "cleanup-recover"), 0)
                    self.assertTrue((directory / "resource").exists())
                    (directory / "workload-running").unlink()
                    self.assertEqual(fixture.actor(directory, "cleanup-recover"), 0)
                    self.assertFalse((directory / "resource").exists())
                    self.assertEqual(fixture.actor(directory, "attach"), 0)
                else:
                    self.assertNotEqual(fixture.actor(directory, "cleanup-recover"), 0)
                    self.assertTrue((directory / "resource").exists())

    def test_cleanup_disables_hooks_and_removes_only_its_recorded_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case = fixture.Fixture(root, Path("/tmp/helper"), "normal-stop")
            runtime = root / "runtime"
            runtime.mkdir()
            unrelated = runtime / "unrelated.service"
            unrelated.write_text("preserve")
            for name in (case.units["attach"], case.units["recovery"]):
                source = case.directory / name
                source.write_text(case.files[name])
                destination = runtime / name
                destination.symlink_to(source)
                case.linked.append((destination, source))
            commands = []

            def control(*arguments, **kwargs):
                commands.append(arguments)
                return subprocess.CompletedProcess(arguments, 0, "ActiveState=inactive\n", "")

            with patch.object(case, "ctl", control):
                case.cleanup()
            self.assertEqual(unrelated.read_text(), "preserve")
            expected = tuple(destination.name for destination, _ in case.linked)
            self.assertIn(("stop", *expected), commands)
            for destination, source in case.linked:
                self.assertFalse(destination.exists())
                text = source.read_text()
                self.assertNotIn("OnFailure=", text)
                self.assertNotIn("OnSuccess=", text)
                self.assertNotIn("ExecStopPost=", text)


if __name__ == "__main__":
    unittest.main()
