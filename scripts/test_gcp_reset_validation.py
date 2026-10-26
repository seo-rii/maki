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
                 "source": "https://compute.googleapis.com/compute/v1/projects/test-project/zones/asia-northeast3-a/disks/maki-reset-data"},
            ],
        }
        disk = {"id": "202", "selfLink":
                "https://compute.googleapis.com/compute/v1/projects/test-project/zones/asia-northeast3-a/disks/maki-reset-data"}
        replies = [subprocess.CompletedProcess([], 0, json.dumps(instance).encode(), b""),
                   subprocess.CompletedProcess([], 0, json.dumps(disk).encode(), b"")]
        with mock.patch.object(self.host, "bounded_run", side_effect=replies):
            identity = self.host.resource_identity(args, 30)
        self.assertEqual(identity, {
            "instance_id": "101", "data_disk_id": "202",
            "data_disk_self_link": "projects/test-project/zones/asia-northeast3-a/disks/maki-reset-data",
            "attachment_source": "projects/test-project/zones/asia-northeast3-a/disks/maki-reset-data",
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

    def test_discard_profile_requires_trim_and_an_independent_complete_manifest(self):
        ready = {"event": "ready", "provider": "local-aes-gcm-siv", "can_flush": True,
                 "can_fua": True, "can_trim": True,
                 "fs_uuid": "00112233-4455-6677-8899-aabbccddeeff",
                 "witness_service": "active", "graceful_stop_witness": "absent"}
        self.host.validate_ready(ready, None, "v3-discard")
        invalid = dict(ready, can_trim=False)
        with self.assertRaisesRegex(ValueError, "TRIM"):
            self.host.validate_ready(invalid, None, "v3-discard")

        expected = self.host.expected_discard_manifest(0)
        self.assertEqual(expected["trim"], [
            {"offset": 0, "length": 4096},
            {"offset": 4096, "length": 4096},
        ])
        self.assertNotEqual(expected["write"][0]["sha256"],
                            expected["rewrite"]["sha256"])
        final = {row["offset"]: row for row in expected["final"]}
        self.assertEqual(final[4096]["sha256"], self.host.ZERO_SHA256)
        self.assertEqual(final[0], expected["rewrite"])
        event = {"event": "ack", "command": "discard-0", "cycle": 0,
                 "mode": "flush", "profile": "v3-discard", "boot_id": self.boot_id,
                 "manifest": expected}
        self.host.validate_ack(event, 0, "v3-discard")
        for field in ("write", "trim", "rewrite", "final"):
            invalid = json.loads(json.dumps(event))
            invalid["manifest"][field] = []
            with self.assertRaises(ValueError):
                self.host.validate_ack(invalid, 0, "v3-discard")

        self.host.record_ack(self.ledger, event, 0, "v3-discard")
        self.assertEqual(self.host.load_ledger(self.ledger, "v3-discard"), event)

    def test_discard_profile_is_explicitly_forwarded_to_guest(self):
        args = types.SimpleNamespace(
            gcloud="gcloud", project="test-project", zone="asia-northeast3-a",
            instance="maki-reset-test", guest_agent="/opt/maki/gcp-reset-guest.py",
            guest_config="/mnt/maki-data/config.toml", guest_plugin="/opt/maki/libmaki_nbdkit.so",
            connect_timeout=9, profile="v3-discard",
        )
        command = self.host.ssh_command(args, self.token, 0, False)
        self.assertIn("--profile v3-discard", command[command.index("--command") + 1])

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
        process.poll.return_value = None
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
        process.poll.return_value = 255
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

    def test_campaign_reaps_owned_child_on_each_post_launch_failure(self):
        baseline = dict(instance_id="101", data_disk_id="202",
                        data_disk_self_link="disk-url", attachment_source="disk-url",
                        attachment_device_name="data", status="RUNNING")
        for failure in ("boot", "ready", "resource-query", "resource-identity", "ack"):
            with self.subTest(failure=failure):
                args = types.SimpleNamespace(
                    cycles=2, timeout=10, connect_timeout=1, project="test-project",
                    zone="us-central1-a", instance="cleanup-fixture", data_disk="fixture",
                    profile="v2", output=self.path / failure,
                )
                # Only a local sleeping child is real: no gcloud or guest I/O.
                process = self.host.RemoteProcess(
                    [sys.executable, "-c", "import time; time.sleep(30)"],
                    self.path / f"child-{failure}", self.token, 0,
                )
                self.addCleanup(process.close)
                process.expect = mock.Mock(side_effect=ValueError("fixture ACK failure"))
                ready = dict(event="ready", boot_id=self.boot_id,
                             provider="local-aes-gcm-siv", can_flush=True, can_fua=True,
                             fs_uuid="00112233-4455-6677-8899-aabbccddeeff",
                             witness_service="active", graceful_stop_witness="absent")
                current = dict(baseline)
                if failure == "boot":
                    ready["boot_id"] = "invalid"
                elif failure == "ready":
                    ready["can_fua"] = False
                elif failure == "resource-query":
                    current = ValueError("fixture resource query failure")
                elif failure == "resource-identity":
                    current["data_disk_id"] = "changed"
                with mock.patch.object(self.host, "resource_identity",
                                       side_effect=[baseline, current]), \
                        mock.patch.object(self.host, "launch_guest", return_value=(process, ready)):
                    with self.assertRaises(ValueError):
                        self.host.campaign(args)
                self.assertEqual(process.child.returncode, -signal.SIGKILL,
                                 "campaign must kill and reap its child before returning")
                result = json.loads((args.output / "results.json").read_text())
                self.assertFalse(result["passed"])
                self.assertIn("ValueError", result["error"])
                self.assertFalse((args.output / "host-acks.jsonl").exists())

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


class ResourceIdentityContracts(unittest.TestCase):
    """Resource descriptions must identify the disk actually attached to the VM."""

    def setUp(self):
        self.host = load("gcp_resource_identity", "gcp-reset-validation.py")
        self.args = types.SimpleNamespace(
            gcloud="never-run-gcloud", project="test-project", zone="test-zone-a",
            instance="fixture", data_disk="expected-disk",
        )
        self.disk_path = "projects/test-project/zones/test-zone-a/disks/expected-disk"
        self.disk_url = "https://compute.googleapis.com/compute/v1/" + self.disk_path
        self.instance = {
            "id": "101", "status": "RUNNING", "disks": [
                {"boot": False, "deviceName": "expected-disk", "source": self.disk_url},
            ],
        }
        self.disk = {"id": "202", "selfLink": self.disk_url}

    def identity(self, instance=None, disk=None):
        values = (self.instance if instance is None else instance,
                  self.disk if disk is None else disk)
        replies = [subprocess.CompletedProcess([], 0, json.dumps(value).encode(), b"")
                   for value in values]
        with mock.patch.object(self.host, "bounded_run", side_effect=replies) as run:
            value = self.host.resource_identity(self.args, 30)
        self.assertEqual(run.call_count, 2)
        command = run.call_args.args[0]
        self.assertEqual(command[2:5], ["disks", "describe", "expected-disk"])
        self.assertEqual(command[command.index("--project") + 1], "test-project")
        self.assertEqual(command[command.index("--zone") + 1], "test-zone-a")
        self.host.validate_resource_identity(value, value)
        return value

    def test_matching_attached_disk_is_accepted(self):
        identity = self.identity()
        self.assertEqual(identity["instance_id"], "101")
        self.assertEqual(identity["data_disk_id"], "202")
        self.assertEqual(identity["attachment_source"], identity["data_disk_self_link"])

    def test_attached_disk_and_described_disk_must_match(self):
        self.instance["disks"][0]["source"] = self.disk_url.replace("expected-disk", "another-disk")
        with self.assertRaises(ValueError):
            self.identity()

    def test_null_disk_id_must_not_become_a_valid_string(self):
        self.disk["id"] = None
        with self.assertRaises(ValueError):
            self.identity()

    def test_same_name_in_another_project_or_zone_is_not_the_requested_disk(self):
        for old, new in (("test-project", "other-project"), ("test-zone-a", "other-zone-a")):
            for both in (False, True):
                with self.subTest(scope=old, descriptions_agree=both):
                    instance = json.loads(json.dumps(self.instance))
                    wrong = self.disk_url.replace(old, new)
                    instance["disks"][0]["source"] = wrong
                    disk = dict(self.disk, selfLink=wrong) if both else self.disk
                    with self.assertRaises(ValueError):
                        self.identity(instance, disk)

    def test_described_disk_must_match_the_requested_resource(self):
        for old, new in (("test-project", "other-project"), ("test-zone-a", "other-zone-a"),
                         ("expected-disk", "another-disk")):
            with self.subTest(field=old):
                disk = dict(self.disk, selfLink=self.disk_url.replace(old, new))
                with self.assertRaises(ValueError):
                    self.identity(disk=disk)

    def test_equivalent_google_api_references_have_one_stable_identity(self):
        references = (self.disk_path, self.disk_url,
                      "https://www.googleapis.com/compute/v1/" + self.disk_path)
        baseline = None
        for source in references:
            for self_link in references:
                with self.subTest(source=source, self_link=self_link):
                    instance = json.loads(json.dumps(self.instance))
                    instance["disks"][0].update(source=source, deviceName="data-alias")
                    current = self.identity(instance, dict(self.disk, selfLink=self_link))
                    self.assertEqual(current["attachment_source"], self.disk_path)
                    self.assertEqual(current["data_disk_self_link"], self.disk_path)
                    if baseline is not None:
                        self.host.validate_resource_identity(baseline, current)
                    baseline = current

    def test_missing_or_malformed_resource_ids_are_rejected(self):
        invalid = (None, True, False, -1, 101.0, 1.5, "", "None", "101.0", "+101",
                   "-101", " 101", "101 ", "1e2", "0101", "١٠١", [], {},
                   1 << 64, str(1 << 64))
        for resource in ("instance", "disk"):
            for bad in invalid:
                with self.subTest(resource=resource, value=bad):
                    instance, disk = dict(self.instance), dict(self.disk)
                    (instance if resource == "instance" else disk)["id"] = bad
                    with self.assertRaises(ValueError):
                        self.identity(instance, disk)
            with self.subTest(resource=resource, missing=True):
                instance, disk = dict(self.instance), dict(self.disk)
                del (instance if resource == "instance" else disk)["id"]
                with self.assertRaises(ValueError):
                    self.identity(instance, disk)

    def test_uint64_string_and_integer_ids_have_the_same_identity(self):
        for value in (0, 1, (1 << 53) + 1, (1 << 64) - 1):
            with self.subTest(value=value):
                integer = self.identity(dict(self.instance, id=value), dict(self.disk, id=value))
                string = self.identity(dict(self.instance, id=str(value)), dict(self.disk, id=str(value)))
                self.assertEqual(integer, string)
                self.assertEqual(integer["data_disk_id"], str(value))

    def test_ambiguous_nonboot_attachments_are_rejected(self):
        duplicate = dict(self.instance["disks"][0], deviceName="other-alias")
        alias_collision = dict(self.instance["disks"][0],
                               source=self.disk_url.replace("expected-disk", "another-disk"))
        for other in (duplicate, alias_collision):
            with self.subTest(attachment=other):
                instance = dict(self.instance, disks=self.instance["disks"] + [other])
                with self.assertRaises(ValueError):
                    self.identity(instance)

    def test_boot_attachment_cannot_be_the_data_disk(self):
        self.instance["disks"][0]["boot"] = True
        with self.assertRaises(ValueError):
            self.identity()

    def test_unrelated_boot_and_data_disks_do_not_change_selection(self):
        self.instance["disks"].extend([
            {"boot": True, "deviceName": "boot", "source": "projects/p/zones/z/disks/boot"},
            {"boot": False, "deviceName": "other", "source": self.disk_url.replace("expected-disk", "other")},
        ])
        self.assertEqual(self.identity()["attachment_device_name"], "expected-disk")

    def test_missing_or_malformed_resource_references_are_rejected(self):
        invalid = (None, 202, "", "expected-disk", self.disk_url + "/", self.disk_url + "?x=1",
                   self.disk_url + "#fragment", self.disk_url.replace("https:", "http:"),
                   self.disk_url.replace("compute.googleapis.com", "foreign.invalid"),
                   self.disk_url.replace("/zones/", "/regions/"),
                   self.disk_url.replace("/disks/", "/instances/"),
                   self.disk_url.replace("/expected-disk", "/%65xpected-disk"))
        for field in ("source", "selfLink"):
            for bad in invalid:
                with self.subTest(field=field, value=bad):
                    instance = json.loads(json.dumps(self.instance))
                    disk = dict(self.disk)
                    (instance["disks"][0] if field == "source" else disk)[field] = bad
                    with self.assertRaises(ValueError):
                        self.identity(instance, disk)


class ResourceDeadlineContracts(unittest.TestCase):
    def setUp(self):
        self.host = load("gcp_resource_deadline", "gcp-reset-validation.py")
        self.args = types.SimpleNamespace(
            gcloud="fixture-gcloud", project="fixture-project", zone="fixture-zone",
            instance="fixture-instance", data_disk="fixture-data",
        )
        self.disk = "projects/fixture-project/zones/fixture-zone/disks/fixture-data"
        self.baseline = dict(
            instance_id="1", data_disk_id="2", data_disk_self_link=self.disk,
            attachment_source=self.disk, attachment_device_name="fixture-data",
            status="RUNNING",
        )
        self.now = 0.0
        self.durations = iter([2, 2])
        self.statuses = iter(["RUNNING"])
        self.calls = []
        for patch in (
                mock.patch.object(self.host.time, "monotonic", side_effect=lambda: self.now),
                mock.patch.object(self.host.time, "sleep", side_effect=self.advance),
                mock.patch.object(self.host, "bounded_run", side_effect=self.rpc)):
            patch.start()
            self.addCleanup(patch.stop)

    def advance(self, seconds):
        self.now += seconds

    def rpc(self, command, timeout):
        resource = command[2]
        self.calls.append((resource, timeout))
        duration = next(self.durations)
        # Enforce each subprocess's timeout, without executing gcloud or sleeping.
        self.advance(min(duration, timeout))
        if duration > timeout:
            raise TimeoutError("fixture RPC deadline")
        if resource == "instances":
            value = dict(id="1", status=next(self.statuses), disks=[dict(
                boot=False, deviceName="fixture-data", source=self.disk,
            )])
        else:
            value = dict(id="2", selfLink=self.disk)
        return subprocess.CompletedProcess(command, 0, json.dumps(value).encode(), b"")

    def test_two_slow_queries_share_one_wait_budget(self):
        self.durations = iter([6, 6])
        with self.assertRaises(TimeoutError):
            self.host.wait_for_running(self.args, 10, self.baseline)
        self.assertEqual(self.now, 10)
        self.assertEqual(self.calls, [("instances", 10), ("disks", 4)])

    def test_short_queries_succeed_with_shrinking_budget(self):
        current = self.host.wait_for_running(self.args, 10, self.baseline)
        self.assertEqual(current, self.baseline)
        self.assertEqual(self.now, 4)
        self.assertEqual(self.calls, [("instances", 10), ("disks", 8)])

    def test_first_query_exhaustion_prevents_disk_query(self):
        for duration in (10, 11):
            with self.subTest(duration=duration):
                self.now = 0
                self.calls.clear()
                self.durations = iter([duration, 1])
                self.statuses = iter(["RUNNING"])
                with self.assertRaises(TimeoutError):
                    self.host.wait_for_running(self.args, 10, self.baseline)
                self.assertEqual(self.now, 10)
                self.assertEqual(self.calls, [("instances", 10)])

    def test_expired_identity_budget_does_not_start_a_query(self):
        with self.assertRaises(TimeoutError):
            self.host.resource_identity(self.args, 0)
        self.assertEqual(self.calls, [])

    def test_identity_response_at_deadline_is_rejected(self):
        self.durations = iter([4, 6])
        with self.assertRaises(TimeoutError):
            self.host.resource_identity(self.args, 10)
        self.assertEqual(self.now, 10)

    def test_json_processing_counts_toward_identity_deadline(self):
        original = self.host.decode_json_result
        for delayed_resource, overhead, expected_calls in (
                ("instance describe", 8, 1), ("disk describe", 6, 2)):
            with self.subTest(resource=delayed_resource):
                self.now = 0
                self.calls.clear()
                self.durations = iter([2, 2])
                self.statuses = iter(["RUNNING"])

                def decode(result, what):
                    value = original(result, what)
                    if what == delayed_resource:
                        self.advance(overhead)
                    return value

                with mock.patch.object(self.host, "decode_json_result", side_effect=decode):
                    with self.assertRaises(TimeoutError):
                        self.host.resource_identity(self.args, 10)
                self.assertEqual(self.now, 10)
                self.assertEqual(len(self.calls), expected_calls)

    def test_final_identity_validation_cannot_accept_running_after_deadline(self):
        original = self.host.validate_resource_identity

        def validate(*args, **kwargs):
            original(*args, **kwargs)
            self.advance(6)

        with mock.patch.object(self.host, "validate_resource_identity", side_effect=validate):
            with self.assertRaises(TimeoutError):
                self.host.wait_for_running(self.args, 10, self.baseline)
        self.assertEqual(self.now, 10)

    def test_wait_retries_non_running_state_with_remaining_budget(self):
        self.durations = iter([1, 1, 1, 1])
        self.statuses = iter(["STOPPING", "RUNNING"])
        current = self.host.wait_for_running(self.args, 10, self.baseline)
        self.assertEqual(current, self.baseline)
        self.assertEqual(self.now, 6)
        self.assertEqual(self.calls, [
            ("instances", 10), ("disks", 9), ("instances", 6), ("disks", 5),
        ])


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
        client.can_trim = True
        self.assertEqual(self.guest.capabilities(client), {
            "can_flush": True, "can_fua": True
        })
        self.assertEqual(self.guest.capabilities(client, "v3-discard"), {
            "can_flush": True, "can_fua": True, "can_trim": True
        })

    def test_discard_manifest_matches_host_oracle_and_barriers_every_operation(self):
        for cycle, mode in ((0, "flush"), (1, "fua")):
            client = mock.Mock()
            manifest = self.guest.discard_barrier(client, cycle, mode)
            self.assertEqual(manifest, self.host.expected_discard_manifest(cycle))
            self.assertEqual(client.write.call_count, 17)
            self.assertEqual(client.trim.call_args_list, [
                mock.call(0, 4096, fua=mode == "fua"),
                mock.call(4096, 4096, fua=mode == "fua"),
            ])
            self.assertEqual(client.flush.call_count, 3 * int(mode == "flush"))
            first = client.write.call_args_list[0]
            rewrite = client.write.call_args_list[-1]
            self.assertEqual(first.args[0], 0)
            self.assertEqual(rewrite.args[0], 0)
            self.assertNotEqual(first.args[1], rewrite.args[1])

    def test_failed_trim_or_rewrite_barrier_does_not_complete(self):
        for method, failure_call in (("trim", 1), ("write", 17), ("flush", 2)):
            client = mock.Mock()
            getattr(client, method).side_effect = [None] * (failure_call - 1) + [RuntimeError("failed")]
            with self.assertRaises(RuntimeError):
                self.guest.discard_barrier(client, 0, "flush")

    def test_discard_readback_reports_rewrite_and_persistent_zero(self):
        events = []
        client = mock.Mock()
        expected = self.host.expected_discard_manifest(1)["final"]
        blocks = {row["offset"]: bytes(4096) if row["offset"] == 4096
                  else self.guest.discard_final_block(1, row["offset"])
                  for row in expected}
        client.read.side_effect = blocks.__getitem__
        args = argparse.Namespace(cycle=2, verify_only=True, profile="v3-discard")
        self.guest.execute_cycle(args, client,
                                 lambda event, **fields: events.append((event, fields)))
        self.assertEqual(events[0][0], "readback")
        self.assertEqual(events[0][1]["manifest"], expected)
        self.assertEqual(events[1], ("verified", {"generation": 1, "count": 16}))

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
