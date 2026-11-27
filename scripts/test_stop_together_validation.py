"""Several volumes stopping together on the installed package (AUD-197):
the provisioning from the documented blocks, the stop with every device
held open and what is read from systemd, against a fake host. Nothing here
attaches, stops a unit or runs as root."""
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest import mock


DRIVER = Path(__file__).with_name("stop-together-validation.py")


def load_driver():
    spec = importlib.util.spec_from_file_location("stop_together_validation", DRIVER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DocumentedVolumes(unittest.TestCase):
    """Each volume is the quick start's, its `demo` replaced by its name, as
    an operator edits the variables for another volume."""

    @classmethod
    def setUpClass(cls):
        cls.driver = load_driver()
        cls.quickstart = cls.driver.QUICKSTART
        cls.steps = dict(cls.quickstart.steps())

    def test_a_volume_is_provisioned_and_started_with_the_documented_blocks(self):
        provision = self.driver.provision_blocks("stop2")
        labels = [label for label, _ in provision]
        self.assertEqual([label.split(", ", 1)[1].split(",")[0].split(":")[0] for label in labels],
                         ["1. Create the key", "2. Write the volume configuration",
                          "3. Create the volume", self.quickstart.PROVISION_STEP])
        for label, block in provision + [self.driver.start_block("stop2")]:
            with self.subTest(label=label):
                expected = self.steps[label].replace("demo", "stop2")
                if label == provision[-1][0]:
                    expected = expected.replace("\ndev=/dev/nbd0\n", "\ndev=/dev/nbd8\n")
                self.assertEqual(block, expected)
                self.assertNotIn("demo", block)
                self.assertIn("stop2", block)
        self.assertTrue(self.driver.start_block("stop2")[0].startswith(
            "quickstart.md, 6. Start the lifecycle and write data"))
        bootstrap = provision[-1][1]
        self.assertEqual(self.quickstart.bootstrap_values(bootstrap),
                         {"volume": "stop2", "dev": "/dev/nbd8",
                          "record": "/etc/maki/attach/stop2.bootstrap"})
        for line in ("vg=vg_maki_stop2", "mountpoint=/srv/stop2",
                     "attach_config=/etc/maki/attach/stop2.toml"):
            self.assertIn("\n" + line + "\n", bootstrap)
        configuration = self.driver.configuration("stop2")
        for line in ('name = "stop2"', 'root = "/var/lib/maki/stop2"',
                     'socket = "/run/maki/stop2/nbd.sock"',
                     'socket = "/run/maki-control/stop2/control.sock"'):
            self.assertIn("\n" + line + "\n", configuration)
        self.assertNotIn("demo", configuration)

    def test_the_volumes_are_named_and_counted_within_bounds(self):
        self.assertEqual(self.driver.names(3), ["stop1", "stop2", "stop3"])
        for arguments in (["--volumes", "1"], ["--volumes", "9"], ["--hold", "0"],
                          ["--hold", "15"]):
            with self.subTest(arguments=arguments):
                with self.assertRaises(SystemExit), mock.patch("sys.stderr", io.StringIO()):
                    self.driver.main([*arguments, "/nonexistent"])

    def test_a_record_names_the_device_it_attached(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            (state / "stop1.nbd").write_text(json.dumps({"device": "/dev/nbd2", "volume": "stop1"}))
            self.assertEqual(self.driver.device_of("stop1", state), "/dev/nbd2")
            (state / "stop1.nbd").write_text(json.dumps({"device": "/dev/sda"}))
            with self.assertRaisesRegex(RuntimeError, "names no NBD device"):
                self.driver.device_of("stop1", state)

    def test_the_stop_times_are_systemds_monotonic_timestamps(self):
        shown = ("ActiveExitTimestampMonotonic=100250000\n"
                 "InactiveEnterTimestampMonotonic=110500000\nResult=success\n")
        run = mock.Mock(return_value=subprocess.CompletedProcess([], 0, stdout=shown))
        self.assertEqual(self.driver.unit_times("stop1", 100.0, run),
                         {"stop_began": 0.25, "stop_ended": 10.5, "stop_seconds": 10.25,
                          "result": "success"})
        self.assertEqual(run.call_args.args[0][-1], "maki-attach@stop1.service")
        for broken in ("ActiveExitTimestampMonotonic=0\nInactiveEnterTimestampMonotonic=5\n",
                       "ActiveExitTimestampMonotonic=9\nInactiveEnterTimestampMonotonic=5\n",
                       "Result=success\n"):
            with self.subTest(shown=broken):
                run.return_value = subprocess.CompletedProcess([], 0, stdout=broken)
                with self.assertRaises(RuntimeError):
                    self.driver.unit_times("stop1", 100.0, run)


class FakeOpener:
    def __init__(self, argv, stdout, stderr, holds=True, status=0):
        self.argv = argv
        self.status = status
        if holds:
            stdout.write("  0.000s holding the device open; it shows backend 'maki-1'\n")
        stdout.flush()
        self.returncode = None

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.returncode = self.status
        return self.status

    def kill(self):
        self.returncode = -9


class StopTogether(unittest.TestCase):
    """The stop of every target at once, against a fake host."""

    @classmethod
    def setUpClass(cls):
        cls.driver = load_driver()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="maki-stop-together-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root / "run/maki-attach"
        self.state.mkdir(parents=True)
        self.sysfs = self.root / "sys/block"
        self.work = self.root / "work"
        self.work.mkdir()
        self.events = []
        for index, name in enumerate(("stop1", "stop2", "stop3")):
            (self.state / f"{name}.nbd").write_text(json.dumps({"device": f"/dev/nbd{index}"}))
            (self.sysfs / f"nbd{index}").mkdir(parents=True)
            (self.sysfs / f"nbd{index}/backend").write_text(f"maki-{index}\n")
        self.result = "success"
        self.left = None

    def host(self, argv, **_):
        self.events.append(argv)
        if argv[:2] == ["systemctl", "stop"]:
            for index, name in enumerate(("stop1", "stop2", "stop3")):
                if self.left != name:
                    (self.state / f"{name}.nbd").unlink()
                    (self.sysfs / f"nbd{index}/backend").unlink()
            return subprocess.CompletedProcess(argv, 0)
        if argv[:2] == ["systemctl", "show"] and "-P" in argv:
            return subprocess.CompletedProcess(argv, 0, stdout="inactive\n")
        if argv[:2] == ["systemctl", "show"]:
            index = int(argv[-1][len("maki-attach@stop"):-len(".service")])
            return subprocess.CompletedProcess(argv, 0, stdout=(
                f"ActiveExitTimestampMonotonic={(100 + index * 0.01) * 1e6:.0f}\n"
                f"InactiveEnterTimestampMonotonic={(100 + index * 10.2) * 1e6:.0f}\n"
                f"Result={self.result}\n"))
        if argv[0] == "findmnt":
            return subprocess.CompletedProcess(argv, 1)
        raise AssertionError(argv)

    def popen(self, argv, stdout, stderr, **opener):
        self.events.append(["opener", argv[argv.index("--device") + 1],
                            argv[argv.index("--hold") + 1]])
        return FakeOpener(argv, stdout, stderr, **opener)

    def stop(self, **opener):
        with mock.patch("sys.stdout", io.StringIO()) as output:
            try:
                return self.driver.stop_together(
                    ["stop1", "stop2", "stop3"], 10, self.work, run=self.host,
                    popen=lambda *a, **k: self.popen(*a, **k, **opener), clock=lambda: 100.0,
                    sleep=lambda _: None, state=self.state, sysfs=self.sysfs), output.getvalue()
            finally:
                self.printed = output.getvalue()

    def test_every_device_is_held_open_before_one_stop_of_every_target(self):
        report, printed = self.stop()
        openers = [event for event in self.events if event[0] == "opener"]
        self.assertEqual(openers, [["opener", "/dev/nbd0", "10"], ["opener", "/dev/nbd1", "10"],
                                   ["opener", "/dev/nbd2", "10"]])
        stops = [event for event in self.events if event[:2] == ["systemctl", "stop"]]
        self.assertEqual(stops, [["systemctl", "stop", "maki-workload@stop1.target",
                                  "maki-workload@stop2.target", "maki-workload@stop3.target"]])
        self.assertGreater(self.events.index(stops[0]), self.events.index(openers[-1]))
        self.assertEqual([volume["stop_seconds"] for volume in report["volumes"]],
                         [10.19, 20.38, 30.57])
        self.assertEqual(json.loads((self.work / "stop-together.json").read_text()), report)
        self.assertRegex(printed, r"stop3\s+/dev/nbd2\s+0\.030 s\s+30\.600 s\s+30\.570 s\s+success")
        # Each opener was told to let go at the end.
        for name in ("stop1", "stop2", "stop3"):
            self.assertTrue((self.work / f"stop-opener-{name}").exists())

    def test_a_failed_stop_or_opener_or_a_leftover_fails_after_the_report(self):
        cases = {"result": ("failed", "maki-attach@stop1.service stopped with result failed"),
                 "opener": (3, "the opener of /dev/nbd0 exited with status 3"),
                 "left": ("stop2", "stop2: its attach record remains")}
        for name, (value, message) in cases.items():
            with self.subTest(case=name):
                self.setUp()
                opener = {}
                if name == "result":
                    self.result = value
                elif name == "opener":
                    opener = {"status": value}
                else:
                    self.left = value
                with self.assertRaisesRegex(RuntimeError, re.escape(message)):
                    self.stop(**opener)
                self.assertTrue((self.work / "stop-together.json").exists())

    def test_an_opener_that_never_holds_its_device_stops_before_any_stop(self):
        with self.assertRaisesRegex(RuntimeError, "did not start holding /dev/nbd0"):
            self.stop(holds=False, status=2)
        self.assertFalse([event for event in self.events if event[:2] == ["systemctl", "stop"]])


if __name__ == "__main__":
    unittest.main()
