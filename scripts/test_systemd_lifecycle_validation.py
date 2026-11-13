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
