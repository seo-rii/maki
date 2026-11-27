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
# The MESSAGE_IDs of systemd's catalog: a stop job has begun, has finished;
# a unit has succeeded, has failed.
STOPPING = "de5b426a63be47a7b6ac3eaac82e2f6f"
STOPPED = "9d1aaa27d60140bd96365438aad20286"
SUCCEEDED = "7ad2d189f7e94e70a38c781354912448"
FAILED = "d9b373ed55a64feb8242e02dbe79a49c"


def entry(unit, seconds, message_id, **fields):
    """A journal entry of PID 1 about `unit`, as `journalctl -o json` prints it."""
    return {"__MONOTONIC_TIMESTAMP": str(int(seconds * 1e6)), "_PID": "1", "UNIT": unit,
            "MESSAGE_ID": message_id, "MESSAGE": f"{message_id} {unit}",
            **{name: str(value) for name, value in fields.items()}}


def journal(*entries):
    return "".join(json.dumps(item) + "\n" for item in entries)


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

    def test_the_stop_times_are_the_journals_for_the_stop_job_after_the_request(self):
        # systemd forgets a unit that has stopped, and its timestamps with
        # it; the journal of PID 1 keeps the stop job's messages.
        unit = "maki-attach@stop1.service"
        found = journal(
            # A stop of the same unit before the request is not this one.
            entry(unit, 50.0, STOPPING, JOB_ID=7, JOB_TYPE="stop"),
            entry(unit, 50.5, STOPPED, JOB_ID=7, JOB_TYPE="stop", JOB_RESULT="done"),
            entry(unit, 100.25, STOPPING, JOB_ID=42, JOB_TYPE="stop"),
            entry(unit, 110.49, SUCCEEDED),
            entry(unit, 110.5, STOPPED, JOB_ID=42, JOB_TYPE="stop", JOB_RESULT="done"))
        run = mock.Mock(return_value=subprocess.CompletedProcess([], 0, stdout=found))
        self.assertEqual(self.driver.journal_times("stop1", 100.0, run, lambda _: None),
                         {"stop_began": 0.25, "stop_ended": 10.5, "stop_seconds": 10.25,
                          "result": "success", "job_result": "done"})
        argv = run.call_args.args[0]
        self.assertEqual(argv[0], "journalctl")
        for needed in ("--boot", "--output=json", "--no-pager", "_PID=1", f"UNIT={unit}"):
            self.assertIn(needed, argv)
        # A unit that failed its stop is reported with its result.
        run.return_value = subprocess.CompletedProcess([], 0, stdout=journal(
            entry(unit, 100.25, STOPPING, JOB_ID=42, JOB_TYPE="stop"),
            entry(unit, 110.49, FAILED, UNIT_RESULT="exit-code"),
            entry(unit, 110.5, STOPPED, JOB_ID=42, JOB_TYPE="stop", JOB_RESULT="done")))
        self.assertEqual(self.driver.journal_times("stop1", 100.0, run, lambda _: None)["result"],
                         "exit-code")
        # Without a stop job begun and finished after the request there are
        # no times, also once the journal has been looked at again.
        for entries in ((), (entry(unit, 50.0, STOPPING, JOB_ID=7),
                             entry(unit, 50.5, STOPPED, JOB_ID=7, JOB_RESULT="done")),
                        (entry(unit, 100.25, STOPPING, JOB_ID=42),),
                        (entry(unit, 100.25, STOPPING, JOB_ID=42),
                         entry(unit, 110.5, STOPPED, JOB_ID=43, JOB_RESULT="done"))):
            with self.subTest(entries=entries):
                run.reset_mock()
                run.return_value = subprocess.CompletedProcess([], 0, stdout=journal(*entries))
                with self.assertRaisesRegex(RuntimeError, "journal shows no"):
                    self.driver.journal_times("stop1", 100.0, run, lambda _: None)
                self.assertGreater(run.call_count, 1)


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
        self.stop_status = 0
        # As systemd does: `systemctl stop` of the targets returns once the
        # targets' own jobs are done, and each attach unit is then still
        # deactivating for this many looks at its state, without the time
        # it entered inactive (GitHub's run of 2026-11-27).
        self.deactivating = {1: 2, 2: 4, 3: 6}
        self.ended = "inactive"
        # Once an attach unit is inactive systemd garbage-collects it, and
        # `systemctl show` then loads a fresh one: every timestamp 0 and
        # Result=success (GitHub's run 45969555304). A failed unit stays
        # loaded while it is failed. The journal of PID 1 keeps the stop
        # job's messages, the last ones this many looks late.
        self.journal_lag = {1: 0, 2: 0, 3: 0}

    def host(self, argv, **_):
        self.events.append(argv)
        if argv[:2] == ["systemctl", "stop"]:
            for index, name in enumerate(("stop1", "stop2", "stop3")):
                if self.left != name:
                    (self.state / f"{name}.nbd").unlink()
                    (self.sysfs / f"nbd{index}/backend").unlink()
            return subprocess.CompletedProcess(argv, self.stop_status)
        if argv[0] == "journalctl":
            unit = next(word[len("UNIT="):] for word in argv if word.startswith("UNIT="))
            index = int(unit[len("maki-attach@stop"):-len(".service")])
            entries = [entry(unit, 50.0, STOPPING, JOB_ID=10 + index, JOB_TYPE="stop"),
                       entry(unit, 50.5, STOPPED, JOB_ID=10 + index, JOB_TYPE="stop",
                             JOB_RESULT="done"),
                       entry(unit, 100 + index * 0.01, STOPPING, JOB_ID=100 + index,
                             JOB_TYPE="stop")]
            if self.deactivating[index] == 0 and self.journal_lag[index] == 0:
                if self.ended == "failed":
                    entries.append(entry(unit, 100 + index * 10.2 - 0.001, FAILED,
                                         UNIT_RESULT=self.result))
                else:
                    entries.append(entry(unit, 100 + index * 10.2 - 0.001, SUCCEEDED))
                entries.append(entry(unit, 100 + index * 10.2, STOPPED, JOB_ID=100 + index,
                                     JOB_TYPE="stop", JOB_RESULT="done"))
            elif self.deactivating[index] == 0:
                self.journal_lag[index] -= 1
            return subprocess.CompletedProcess(argv, 0, stdout=journal(*entries))
        attach = argv[-1].startswith("maki-attach@stop")
        index = int(argv[-1][len("maki-attach@stop"):-len(".service")]) if attach else None
        stopping = attach and self.deactivating[index] > 0
        if argv[:2] == ["systemctl", "show"] and "-P" in argv:
            if stopping:
                self.deactivating[index] -= 1
                return subprocess.CompletedProcess(argv, 0, stdout="deactivating\n")
            return subprocess.CompletedProcess(argv, 0, stdout=(self.ended if attach
                                                                 else "inactive") + "\n")
        if argv[:2] == ["systemctl", "show"]:
            if not stopping and self.ended == "inactive":
                # Garbage-collected: a fresh unit.
                return subprocess.CompletedProcess(argv, 0, stdout=(
                    "ActiveExitTimestampMonotonic=0\nInactiveEnterTimestampMonotonic=0\n"
                    "Result=success\n"))
            ended = 0 if stopping else (100 + index * 10.2) * 1e6
            return subprocess.CompletedProcess(argv, 0, stdout=(
                f"ActiveExitTimestampMonotonic={(100 + index * 0.01) * 1e6:.0f}\n"
                f"InactiveEnterTimestampMonotonic={ended:.0f}\n"
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
        cases = {"stop": (1, "systemctl stop exited with status 1"),
                 "result": ("failed", "maki-attach@stop1.service stopped with result failed"),
                 "opener": (3, "the opener of /dev/nbd0 exited with status 3"),
                 "left": ("stop2", "stop2: its attach record remains")}
        for name, (value, message) in cases.items():
            with self.subTest(case=name):
                self.setUp()
                opener = {}
                if name == "stop":
                    self.stop_status = value
                elif name == "result":
                    # A unit whose stop fails ends failed, and stays loaded.
                    self.ended, self.result = "failed", value
                elif name == "opener":
                    opener = {"status": value}
                else:
                    self.left = value
                with self.assertRaisesRegex(RuntimeError, re.escape(message)):
                    self.stop(**opener)
                self.assertTrue((self.work / "stop-together.json").exists())

    def test_each_attach_units_times_are_read_once_it_has_stopped(self):
        report, _ = self.stop()
        for index in (1, 2, 3):
            unit = f"maki-attach@stop{index}.service"
            looks = [position for position, event in enumerate(self.events)
                     if event == ["systemctl", "show", "-P", "ActiveState", unit]]
            [read] = [position for position, event in enumerate(self.events)
                      if event[:2] == ["systemctl", "show"] and "-P" not in event
                      and event[-1] == unit]
            # Each look while it was deactivating, and the one that found it
            # stopped, came before its times were read.
            self.assertGreaterEqual(len([look for look in looks if look < read]), 2 * index + 1)
        self.assertEqual([volume["result"] for volume in report["volumes"]], ["success"] * 3)
        self.assertEqual(report["stop_command_seconds"], 0.0)

    def test_the_times_survive_the_units_garbage_collection_and_a_late_journal(self):
        # The run of 45969555304: every attach unit had stopped, systemd had
        # forgotten it, and its stop's last messages may reach the journal
        # after it shows the unit inactive.
        self.journal_lag = {1: 0, 2: 3, 3: 1}
        report, printed = self.stop()
        self.assertEqual([(volume["stop_began"], volume["stop_ended"], volume["stop_seconds"])
                          for volume in report["volumes"]],
                         [(0.01, 10.2, 10.19), (0.02, 20.4, 20.38), (0.03, 30.6, 30.57)])
        self.assertEqual([volume["result"] for volume in report["volumes"]], ["success"] * 3)
        self.assertNotIn("unknown", printed)

    def test_an_attach_unit_that_does_not_stop_or_fails_is_reported(self):
        for case, message in (("never", "maki-attach@stop2.service did not stop within 300 s"),
                              ("failed", "maki-attach@stop1.service stopped with result exit-code")):
            with self.subTest(case=case):
                self.setUp()
                if case == "never":
                    self.deactivating[2] = 10 ** 6
                else:
                    self.ended, self.result = "failed", "exit-code"
                with self.assertRaisesRegex(RuntimeError, re.escape(message)):
                    self.stop()
                report = json.loads((self.work / "stop-together.json").read_text())
                if case == "never":
                    self.assertIsNone(report["volumes"][1]["stop_seconds"])
                    self.assertEqual(report["volumes"][0]["stop_seconds"], 10.19)
                else:
                    self.assertEqual(report["volumes"][0]["result"], "exit-code")

    def test_an_opener_that_never_holds_its_device_stops_before_any_stop(self):
        with self.assertRaisesRegex(RuntimeError, "did not start holding /dev/nbd0"):
            self.stop(holds=False, status=2)
        self.assertFalse([event for event in self.events if event[:2] == ["systemctl", "stop"]])


if __name__ == "__main__":
    unittest.main()
