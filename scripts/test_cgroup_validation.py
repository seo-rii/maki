"""The fault campaign's oracle must not manufacture durability evidence."""
import importlib.util
import pathlib
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "campaign", pathlib.Path(__file__).with_name("cgroup-validation.py")
)
campaign = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(campaign)


class Client:
    def __init__(self, fail=None):
        self.data = {}
        self.fail = fail

    def write(self, offset, data, fua=False):
        if self.fail == "write":
            raise RuntimeError("write failed")
        self.data[offset] = data

    def flush(self):
        if self.fail == "flush":
            raise RuntimeError("flush failed")

    def read(self, offset, length):
        return self.data.get(offset, bytes(length))


class OracleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.ledger = pathlib.Path(self.directory.name) / "ack.jsonl"

    def test_failed_flush_never_records_durable_writes(self):
        with self.assertRaises(RuntimeError):
            campaign.durable_write(Client("flush"), self.ledger, [(0, b"a" * 4096)], "flush")
        self.assertFalse(self.ledger.exists())

    def test_failed_fua_never_records_durable_write(self):
        with self.assertRaises(RuntimeError):
            campaign.durable_write(Client("write"), self.ledger, [(0, b"a" * 4096)], "fua")
        self.assertFalse(self.ledger.exists())

    def test_latest_ack_wins_and_missing_data_fails(self):
        client = Client()
        campaign.durable_write(client, self.ledger, [(0, b"a" * 4096)], "flush")
        campaign.durable_write(client, self.ledger, [(0, b"b" * 4096)], "fua")
        self.assertEqual(campaign.verify(client, self.ledger), 1)
        client.data.clear()
        with self.assertRaisesRegex(AssertionError, "durable data mismatch"):
            campaign.verify(client, self.ledger)

    def test_unacknowledged_other_offset_is_not_a_durability_claim(self):
        client = Client()
        campaign.durable_write(client, self.ledger, [(0, b"a" * 4096)], "flush")
        client.write(4096, b"b" * 4096)
        del client.data[4096]
        self.assertEqual(campaign.verify(client, self.ledger), 1)

    def test_empty_or_truncated_oracle_cannot_pass(self):
        self.ledger.write_text("")
        with self.assertRaises(ValueError):
            campaign.verify(Client(), self.ledger)
        self.ledger.write_text('{"offset":0')
        with self.assertRaises(ValueError):
            campaign.verify(Client(), self.ledger)

    def test_exit_137_alone_does_not_prove_oom(self):
        with self.assertRaisesRegex(AssertionError, "OOMKilled"):
            campaign.require_oom({"Running": False, "ExitCode": 137, "OOMKilled": False})
        campaign.require_oom({"Running": False, "ExitCode": 137, "OOMKilled": True})

    def test_container_cli_timeout_still_cleans_exact_created_container(self):
        target = campaign.Target.__new__(campaign.Target)
        target.identifier, target.serial, target.image = None, 0, "test-image"
        target.token = "unique-test"
        target.options = mock.Mock(return_value=[])
        target.remove = mock.Mock()
        created = mock.Mock(stdout="dedicated-container-id\n")
        with mock.patch.object(campaign, "run", side_effect=[created, TimeoutError("stalled")]):
            with self.assertRaises(TimeoutError):
                target.one_shot(["/opt/maki/maki", "check"])
        self.assertEqual(target.identifier, "maki-fault-unique-test-1")
        target.remove.assert_called_once_with()

    def test_campaign_uses_json_api_fields_and_pins_inspected_image(self):
        info = mock.Mock(stdout=campaign.json.dumps({
            "CgroupVersion": "2", "MemoryLimit": True, "SwapLimit": True,
            "CpuCfsQuota": True, "PidsLimit": True, "ServerVersion": "test",
        }))
        inspected = mock.Mock(stdout="sha256:immutable\n")
        output = pathlib.Path(self.directory.name) / "campaign"
        args = mock.Mock(output=output, image="mutable:tag", rounds=1)
        with mock.patch.object(campaign, "run", side_effect=[info, inspected]), \
                mock.patch.object(campaign, "Target", side_effect=RuntimeError("stop before Docker mutation")) as target:
            with self.assertRaisesRegex(RuntimeError, "stop before Docker mutation"):
                campaign.campaign(args)
            self.assertEqual(target.call_args.args[0], "sha256:immutable")

    def test_oom_gate_is_not_disabled_by_python_optimization(self):
        code = f'''import importlib.util
spec = importlib.util.spec_from_file_location("campaign", {str(SPEC.origin)!r})
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.require_oom({{"Running": False, "ExitCode": 137, "OOMKilled": False}})
'''
        result = campaign.subprocess.run([campaign.sys.executable, "-O", "-c", code], capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_pressure_requires_actual_completed_io(self):
        with self.assertRaisesRegex(AssertionError, "pressure I/O"):
            campaign.require_pressure({"completed": 0, "attempted": 0})
        campaign.require_pressure({"completed": 3, "attempted": 4})

    def test_constrained_startup_timeout_is_recorded_as_unavailable(self):
        target = mock.Mock()
        target.start.side_effect = TimeoutError("no READY")
        target.state.return_value = {"Running": True, "OOMKilled": False}
        target.stats.return_value = {"memory.max": "33554432"}
        result = campaign.constrained_recovery(target)
        self.assertFalse(result["ready"])
        self.assertEqual(result["outcome"], "startup-timeout")
        target.client.assert_not_called()
        target.kill.assert_called_once_with()
        target.remove.assert_called_once_with()

    def test_unrelated_startup_failure_is_not_qualified_as_oom(self):
        target = mock.Mock()
        target.start.side_effect = RuntimeError("invalid config")
        target.state.return_value = {"Running": False, "OOMKilled": False, "ExitCode": 1}
        with self.assertRaisesRegex(AssertionError, "OOMKilled"):
            campaign.constrained_recovery(target)
        target.remove.assert_called_once_with()

    def test_startup_metrics_use_the_current_container_before_ready(self):
        target = campaign.Target.__new__(campaign.Target)
        target.cgroup = pathlib.Path("/stale-previous-container")
        target.state = mock.Mock(return_value={"Pid": 1234})

        def read(path):
            if str(path) == "/proc/1234/cgroup":
                return "0::/current-container\n"
            if str(path) == "/sys/fs/cgroup/current-container/memory.max":
                return "33554432\n"
            return "0"

        with mock.patch.object(pathlib.Path, "read_text", autospec=True, side_effect=read):
            self.assertEqual(target.stats()["memory.max"], "33554432")


if __name__ == "__main__":
    unittest.main()
