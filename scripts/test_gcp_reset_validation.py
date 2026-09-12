"""Whole-GCE-reset host oracle and native guest durability contracts."""
import argparse
import importlib.util
import json
import pathlib
import signal
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, pathlib.Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HostContracts(unittest.TestCase):
    def setUp(self):
        self.host = load("gcp_reset_host", "gcp-reset-validation.py")
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = pathlib.Path(self.directory.name)
        self.ledger = self.path / "acks.jsonl"
        self.token = "a" * 32
        self.boot_id = "12345678-1234-1234-1234-123456789abc"

    def frame(self, **fields):
        return b"MAKI_GCP_RESET_V1 " + json.dumps({
            "token": self.token, "cycle": 1, "boot_id": self.boot_id, **fields
        }).encode()

    def ack(self, cycle=0):
        return {
            "event": "ack", "command": f"write-{cycle}", "cycle": cycle,
            "mode": "flush" if cycle % 2 == 0 else "fua",
            "boot_id": self.boot_id,
            "records": self.host.expected_records(cycle),
        }

    def test_noise_stale_identity_truncation_and_oversize_are_rejected(self):
        self.assertIsNone(self.host.decode_frame(b"Linux boot output", self.token, 1))
        with self.assertRaisesRegex(ValueError, "identity"):
            self.host.decode_frame(self.frame(event="ready"), "b" * 32, 1)
        with self.assertRaisesRegex(ValueError, "identity"):
            self.host.decode_frame(self.frame(event="ready"), self.token, 2)
        for raw in (b"MAKI_GCP_RESET_V1 {", b"MAKI_GCP_RESET_V1 " + b"x" * 65536):
            with self.assertRaises(ValueError):
                self.host.decode_frame(raw, self.token, 1)

    def test_boot_identity_is_required_and_must_change_after_reset(self):
        with self.assertRaisesRegex(ValueError, "boot"):
            self.host.validate_boot_id("not-a-boot-id")
        self.host.require_new_boot(None, self.boot_id)
        with self.assertRaisesRegex(ValueError, "did not change"):
            self.host.require_new_boot(self.boot_id, self.boot_id)
        self.host.require_new_boot(self.boot_id, "87654321-4321-4321-4321-cba987654321")

    def test_every_boot_id_is_unique_not_just_different_from_previous(self):
        seen = set()
        alternate = "87654321-4321-4321-4321-cba987654321"
        self.host.require_unique_boot(seen, self.boot_id)
        self.host.require_unique_boot(seen, alternate)
        with self.assertRaisesRegex(ValueError, "reused"):
            self.host.require_unique_boot(seen, self.boot_id)

    def test_payloads_cover_eight_ranges_and_modes_alternate(self):
        first = self.host.expected_records(0)
        second = self.host.expected_records(1)
        self.assertEqual(len(first), 16)
        self.assertEqual(len({row["offset"] // (16 << 20) for row in first}), 8)
        self.assertEqual(len({row["offset"] for row in first}), 16)
        self.assertNotEqual(first, second)
        self.assertEqual([self.host.mode_for_cycle(i) for i in range(4)],
                         ["flush", "fua", "flush", "fua"])

    def test_false_partial_or_wrong_barrier_ack_never_enters_ledger(self):
        for field, value in (("event", "ready"), ("command", "write-77"),
                             ("mode", "fua"), ("cycle", 1), ("records", []),
                             ("boot_id", "invalid")):
            ack = self.ack()
            ack[field] = value
            with self.assertRaises(ValueError):
                self.host.record_ack(self.ledger, ack, 0)
            self.assertFalse(self.ledger.exists())

    def test_correct_ack_fsyncs_file_and_parent_and_loads_latest(self):
        with mock.patch.object(self.host.os, "fsync", wraps=self.host.os.fsync) as sync:
            self.host.record_ack(self.ledger, self.ack(), 0)
            self.assertGreaterEqual(sync.call_count, 2)
        next_ack = self.ack(1)
        next_ack["boot_id"] = "87654321-4321-4321-4321-cba987654321"
        self.host.record_ack(self.ledger, next_ack, 1)
        self.assertEqual(self.host.load_ledger(self.ledger), next_ack)

    def test_empty_truncated_duplicate_or_tampered_ledger_fails_closed(self):
        for text in ("", "{", json.dumps(self.ack()) + "\n" + json.dumps(self.ack()) + "\n"):
            self.ledger.write_text(text)
            with self.assertRaises(ValueError):
                self.host.load_ledger(self.ledger)
        self.ledger.write_text(json.dumps(self.ack()) + "\n")
        value = json.loads(self.ledger.read_text())
        value["records"][0]["sha256"] = "0" * 64
        self.ledger.write_text(json.dumps(value) + "\n")
        with self.assertRaises(ValueError):
            self.host.load_ledger(self.ledger)

    def test_missing_wrong_duplicate_or_guest_supplied_expectation_is_failure(self):
        expected = self.host.expected_records(0)
        self.host.verify_readbacks(expected, expected)
        wrong = [dict(row) for row in expected]
        wrong[0]["sha256"] = "0" * 64
        for actual in ([], expected[:-1], wrong, expected + expected[:1]):
            with self.assertRaises(ValueError):
                self.host.verify_readbacks(expected, actual)

    def test_remote_command_is_quoted_and_reset_is_the_only_power_operation(self):
        args = types.SimpleNamespace(
            gcloud="gcloud", project="test-project", zone="asia-northeast3-a",
            instance="maki-reset-test", guest_agent="/opt/maki/gcp-reset-guest.py",
            guest_config="/mnt/maki-data/config.toml", guest_plugin="/opt/maki/libmaki_nbdkit.so",
            guest_maki="/opt/maki/maki", data_disk="maki-reset-data", connect_timeout=9,
        )
        ssh = self.host.ssh_command(args, self.token, 3, verify_only=False)
        rendered = " ".join(ssh)
        self.assertIn("compute ssh maki-reset-test", rendered)
        self.assertIn("--cycle 3", rendered)
        self.assertIn("sudo -n", rendered)
        self.assertNotIn(" stop ", f" {rendered} ")
        self.assertNotIn(" reboot ", f" {rendered} ")
        with mock.patch.object(self.host, "bounded_run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, b"{}", b"")
            self.host.reset_instance(args, timeout=17)
        command = run.call_args.args[0]
        self.assertEqual(command[1:4], ["compute", "instances", "reset"])
        self.assertNotIn("stop", command)
        self.assertNotIn("reboot", command)

    def test_resource_identity_includes_instance_disk_resource_and_attachment(self):
        args = types.SimpleNamespace(gcloud="gcloud", project="test-project",
                                     zone="asia-northeast3-a", instance="maki-reset-test",
                                     data_disk="maki-reset-data")
        instance = {
            "id": "101", "status": "RUNNING",
            "disks": [
                {"boot": True, "deviceName": "boot", "source": "zones/z/disks/boot"},
                {"boot": False, "deviceName": "maki-data",
                 "source": "https://compute.googleapis.com/compute/v1/projects/p/zones/z/disks/maki-reset-data"},
            ],
        }
        disk = {"id": "202", "selfLink":
                "https://compute.googleapis.com/compute/v1/projects/p/zones/z/disks/maki-reset-data"}
        replies = [subprocess.CompletedProcess([], 0, json.dumps(instance).encode(), b""),
                   subprocess.CompletedProcess([], 0, json.dumps(disk).encode(), b"")]
        with mock.patch.object(self.host, "bounded_run", side_effect=replies):
            identity = self.host.resource_identity(args, 30)
        self.assertEqual(identity, {
            "instance_id": "101", "data_disk_id": "202",
            "data_disk_self_link": disk["selfLink"],
            "attachment_source": instance["disks"][1]["source"],
            "attachment_device_name": "maki-data", "status": "RUNNING",
        })

    def test_changed_resource_identity_or_non_running_state_fails(self):
        baseline = {"instance_id": "101", "data_disk_id": "202",
                    "data_disk_self_link": "disk-url", "attachment_source": "disk-url",
                    "attachment_device_name": "data", "status": "RUNNING"}
        self.host.validate_resource_identity(baseline, dict(baseline))
        for field, value in (("instance_id", "999"), ("data_disk_id", "888"),
                             ("data_disk_self_link", "other"), ("attachment_source", "other"),
                             ("attachment_device_name", "other"), ("status", "STOPPING")):
            changed = dict(baseline)
            changed[field] = value
            with self.assertRaises(ValueError):
                self.host.validate_resource_identity(baseline, changed)

    def test_ready_requires_native_provider_capabilities_and_stable_fs_uuid(self):
        ready = {"event": "ready", "provider": "local-aes-gcm-siv", "can_flush": True,
                 "can_fua": True, "fs_uuid": "00112233-4455-6677-8899-aabbccddeeff",
                 "witness_service": "active", "graceful_stop_witness": "absent"}
        self.host.validate_ready(ready, None)
        self.host.validate_ready(ready, ready["fs_uuid"])
        for field, value in (("provider", "wrong"), ("can_flush", False),
                             ("can_fua", False), ("fs_uuid", "changed"),
                             ("witness_service", "inactive"),
                             ("graceful_stop_witness", "present")):
            invalid = dict(ready)
            invalid[field] = value
            with self.assertRaises(ValueError):
                self.host.validate_ready(invalid, ready["fs_uuid"])

    def test_reset_requires_running_same_resources_after_exit_zero(self):
        args = types.SimpleNamespace(timeout=30)
        baseline = {"instance_id": "101"}
        order = []
        with mock.patch.object(self.host, "bounded_run", side_effect=lambda *_: order.append("reset-exit0")):
            with mock.patch.object(self.host, "wait_for_running",
                                   side_effect=lambda *_: order.append("running-same-resources")):
                self.host.reset_and_wait(args, ["gcloud", "compute", "instances", "reset"], baseline)
        self.assertEqual(order, ["reset-exit0", "running-same-resources"])

    def test_offline_deep_check_is_host_invoked_and_requires_exit_zero(self):
        args = types.SimpleNamespace(
            gcloud="gcloud", project="test-project", zone="asia-northeast3-a",
            instance="maki-reset-test", guest_maki="/opt/maki/maki",
            guest_config="/mnt/maki-data/config.toml", connect_timeout=9,
        )
        command = self.host.offline_check_command(args)
        rendered = " ".join(command)
        self.assertIn("compute ssh maki-reset-test", rendered)
        self.assertIn("/opt/maki/maki check /mnt/maki-data/config.toml --deep", rendered)
        with mock.patch.object(self.host, "bounded_run",
                               return_value=subprocess.CompletedProcess([], 0, b"deep ok", b"")):
            evidence = self.host.run_offline_check(args, 30)
        self.assertEqual(evidence["returncode"], 0)
        self.assertEqual(evidence["stdout"], "deep ok")

    def test_reset_finishes_before_old_ssh_is_accepted_as_dead(self):
        order = []
        process = mock.Mock()
        process.child.poll.return_value = None
        process.wait_after_reset.side_effect = lambda timeout: order.append("ssh-dead")
        args = types.SimpleNamespace(timeout=30)
        def reset_done(*_args, **_kwargs):
            order.append("reset-done")
            return subprocess.CompletedProcess([], 0, b"", b"")
        with mock.patch.object(self.host, "reset_instance",
                               side_effect=reset_done):
            self.host.cut_instance(args, process)
        self.assertEqual(order, ["reset-done", "ssh-dead"])

    def test_cut_refuses_an_ssh_child_that_died_before_reset(self):
        process = mock.Mock()
        process.child.poll.return_value = 255
        args = types.SimpleNamespace(timeout=30)
        with mock.patch.object(self.host, "reset_instance") as reset:
            with self.assertRaisesRegex(RuntimeError, "before reset"):
                self.host.cut_instance(args, process)
        reset.assert_not_called()

    def test_timeout_kills_and_reaps_only_owned_ssh_child(self):
        process = self.host.RemoteProcess(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            self.path / "ssh", self.token, 0,
        )
        with self.assertRaises(TimeoutError):
            with process:
                process.expect("ready", timeout=0.05)
        self.assertEqual(process.child.returncode, -signal.SIGKILL)

    def test_post_reset_ssh_timeout_is_retried_with_a_fresh_owned_child(self):
        args = types.SimpleNamespace(timeout=60, connect_timeout=1)
        first = mock.Mock()
        first.expect.side_effect = TimeoutError("booting")
        second = mock.Mock()
        ready = {"event": "ready", "boot_id": self.boot_id}
        second.expect.return_value = ready
        with mock.patch.object(self.host, "ssh_command", return_value=["gcloud"]):
            with mock.patch.object(self.host, "RemoteProcess", side_effect=[first, second]):
                with mock.patch.object(self.host.time, "sleep"):
                    process, actual = self.host.launch_guest(
                        args, self.token, 1, False, self.path / "retry")
        self.assertIs(process, second)
        self.assertEqual(actual, ready)
        first.close.assert_called_once_with()

    def test_optimized_interpreter_keeps_false_ack_gate(self):
        source = str(pathlib.Path(__file__).with_name("gcp-reset-validation.py"))
        code = f'''import importlib.util, pathlib
spec=importlib.util.spec_from_file_location("host", {source!r})
host=importlib.util.module_from_spec(spec); spec.loader.exec_module(host)
host.record_ack(pathlib.Path({str(self.ledger)!r}), {{"event":"ready"}}, 0)
'''
        result = subprocess.run([sys.executable, "-O", "-c", code], capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"ValueError", result.stderr)
        self.assertFalse(self.ledger.exists())


class GuestContracts(unittest.TestCase):
    def setUp(self):
        self.guest = load("gcp_reset_guest", "gcp-reset-guest.py")
        self.host = load("gcp_reset_host_guest_test", "gcp-reset-validation.py")

    def test_failed_flush_or_any_individual_fua_does_not_ack(self):
        for mode in ("flush", "fua"):
            client = mock.Mock()
            if mode == "flush":
                client.flush.side_effect = RuntimeError("flush failed")
            else:
                client.write.side_effect = RuntimeError("FUA failed")
            with self.assertRaises(RuntimeError):
                self.guest.barrier(client, int(mode == "fua"), mode)

    def test_payload_manifest_matches_independent_host_oracle(self):
        for cycle, mode in ((0, "flush"), (1, "fua")):
            client = mock.Mock()
            records = self.guest.barrier(client, cycle, mode)
            self.assertEqual(records, self.host.expected_records(cycle))
            self.assertEqual(client.write.call_count, 16)
            for call in client.write.call_args_list:
                self.assertEqual(call.kwargs["fua"], mode == "fua")
            self.assertEqual(client.flush.call_count, int(mode == "flush"))

    def test_ready_capabilities_are_taken_from_real_libnbd_client(self):
        client = object.__new__(self.guest.Nbd)
        client.can_flush = True
        client.can_fua = True
        self.assertEqual(self.guest.capabilities(client), {"can_flush": True, "can_fua": True})

    def test_active_shutdown_witness_and_absent_ledger_are_required(self):
        path = pathlib.Path("/mnt/maki-data/graceful-stop.jsonl")
        with mock.patch.object(self.guest, "run_output", return_value="active"):
            with mock.patch.object(self.guest.pathlib.Path, "exists", return_value=False):
                self.assertEqual(self.guest.shutdown_witness(path), {
                    "witness_service": "active", "graceful_stop_witness": "absent"
                })
        with mock.patch.object(self.guest, "run_output", return_value="inactive"):
            with self.assertRaises(ValueError):
                self.guest.shutdown_witness(path)
        with mock.patch.object(self.guest, "run_output", return_value="active"):
            with mock.patch.object(self.guest.pathlib.Path, "exists", return_value=True):
                with self.assertRaises(ValueError):
                    self.guest.shutdown_witness(path)

    def test_later_cycle_reads_previous_generation_before_new_writes(self):
        events = []
        client = mock.Mock()
        client.read.side_effect = lambda offset: self.guest.payload(1, self.guest.index_for_offset(offset))
        args = argparse.Namespace(cycle=2, verify_only=False)
        with mock.patch.object(self.guest, "barrier", return_value=[]) as barrier:
            with mock.patch.object(self.guest, "wait_for_reset"):
                self.guest.execute_cycle(args, client, lambda event, **fields: events.append((event, fields)))
        self.assertEqual(events[0][0], "readback")
        self.assertEqual(events[0][1]["generation"], 1)
        self.assertEqual(len(events[0][1]["records"]), 16)
        barrier.assert_called_once_with(client, 2, "flush")
        self.assertEqual(events[-1][0], "ack")

    def test_ack_is_emitted_then_guest_waits_for_external_reset(self):
        events = []
        args = argparse.Namespace(cycle=0, verify_only=False)
        with mock.patch.object(self.guest, "barrier", return_value=[]) as barrier:
            with mock.patch.object(self.guest, "wait_for_reset", side_effect=RuntimeError("still alive")) as wait:
                with self.assertRaisesRegex(RuntimeError, "still alive"):
                    self.guest.execute_cycle(args, mock.Mock(),
                                             lambda event, **fields: events.append((event, fields)))
        barrier.assert_called_once()
        self.assertEqual(events[-1][0], "ack")
        wait.assert_called_once_with()

    def test_verify_only_reads_previous_generation_and_returns_without_ack(self):
        events = []
        client = mock.Mock()
        client.read.side_effect = lambda offset: self.guest.payload(2, self.guest.index_for_offset(offset))
        args = argparse.Namespace(cycle=3, verify_only=True)
        self.guest.execute_cycle(args, client, lambda event, **fields: events.append((event, fields)))
        self.assertEqual([event for event, _ in events], ["readback", "verified"])


if __name__ == "__main__":
    unittest.main()
