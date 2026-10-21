"""Host/guest cycle bounds, with simulated infrastructure and in-memory I/O."""
import argparse
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, pathlib.Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReachedFilesystemSetup(Exception):
    pass


class MemoryNbd:
    def __init__(self):
        self.blocks = {}
        self.reads = self.writes = self.trims = self.flushes = 0

    def read(self, offset):
        self.reads += 1
        return self.blocks.get(offset, bytes(4096))

    def write(self, offset, block, fua=False):
        self.writes += 1
        self.blocks[offset] = block

    def trim(self, offset, length, fua=False):
        self.trims += 1
        assert length == 4096
        self.blocks[offset] = bytes(length)

    def flush(self):
        self.flushes += 1


class CycleBoundaryContracts(unittest.TestCase):
    def setUp(self):
        previous_umask = os.umask(0o077)
        self.addCleanup(os.umask, previous_umask)
        self.host = load("gcp_cycle_host", "gcp-reset-validation.py")
        self.guest = load("gcp_cycle_guest", "gcp-reset-guest.py")
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = pathlib.Path(directory.name)

    def cli_error(self, argv):
        # Run the original argparse and validation; stop before any VM lookup.
        with mock.patch.object(sys, "argv", argv), mock.patch.object(
                pathlib.Path, "resolve", side_effect=ReachedFilesystemSetup):
            try:
                self.guest.main()
            except ReachedFilesystemSetup:
                return
            except ValueError as error:
                return error
        self.fail("guest main did not reach its filesystem setup boundary")

    def cli(self, cycle, profile, verify_only=False):
        argv = ["gcp-reset-guest.py", "--token", "a" * 32,
                "--cycle", str(cycle), "--profile", profile]
        if verify_only:
            argv.append("--verify-only")
        return argv

    def test_write_cli_accepts_first_and_last_generation(self):
        for profile in ("v2", "v3-discard"):
            for cycle in (0, 63):
                with self.subTest(profile=profile, cycle=cycle):
                    self.assertIsNone(self.cli_error(self.cli(cycle, profile)))

    def test_write_cli_rejects_out_of_range_generations_before_setup(self):
        for profile in ("v2", "v3-discard"):
            for cycle in (-1, 64, 65):
                with self.subTest(profile=profile, cycle=cycle):
                    self.assertEqual(str(self.cli_error(self.cli(cycle, profile))), "invalid cycle")

    def test_verify_only_cli_accepts_first_and_last_boots(self):
        for profile in ("v2", "v3-discard"):
            for cycle in (1, 63, 64):
                with self.subTest(profile=profile, cycle=cycle):
                    self.assertIsNone(self.cli_error(self.cli(cycle, profile, verify_only=True)))

    def test_verify_only_cli_requires_a_valid_prior_generation_before_setup(self):
        for profile in ("v2", "v3-discard"):
            for cycle in (-1, 0, 65):
                with self.subTest(profile=profile, cycle=cycle):
                    self.assertIsInstance(self.cli_error(self.cli(cycle, profile, verify_only=True)), ValueError)

    def campaign_args(self, cycles, profile):
        return argparse.Namespace(
            cycles=cycles, profile=profile, timeout=10, connect_timeout=1,
            output=self.path / f"{profile}-{cycles}", project="test-project",
            zone="test-zone", instance="test-instance", data_disk="test-data",
            gcloud="forbidden-gcloud", guest_agent="/opt/maki/gcp-reset-guest.py",
            guest_config="/mnt/maki-data/config.toml",
            guest_plugin="/opt/maki/libmaki_nbdkit.so", guest_maki="/opt/maki/maki")

    def run_local_campaign(self, cycles, profile):
        args = self.campaign_args(cycles, profile)
        client = MemoryNbd()
        launches, resets = [], []

        def launch(args, token, cycle, verify_only, output):
            # Preserve the original host-generated CLI, including verify-only.
            command = self.host.ssh_command(args, token, cycle, verify_only)
            argv = shlex.split(command[command.index("--command") + 1])[3:]
            self.assertIsNone(self.cli_error(argv), f"guest CLI rejected cycle {cycle}, verify-only={verify_only}")
            events = []

            def emit(event, **fields):
                events.append(dict(event=event, token=token, cycle=cycle,
                                   boot_id=f"00000000-0000-0000-0000-{cycle + 1:012x}", **fields))

            emit("ready", provider="local-aes-gcm-siv", can_flush=True,
                 can_fua=True, can_trim=True,
                 fs_uuid="10000000-0000-0000-0000-000000000001",
                 witness_service="active", graceful_stop_witness="absent")
            before = (client.writes, client.trims, client.flushes)
            with mock.patch.object(self.guest, "wait_for_reset") as wait_for_reset:
                self.guest.execute_cycle(argparse.Namespace(
                    cycle=cycle, profile=profile, verify_only=verify_only), client, emit)
            if verify_only:
                self.assertEqual((client.writes, client.trims, client.flushes), before)
                wait_for_reset.assert_not_called()
            else:
                wait_for_reset.assert_called_once_with()
            launches.append((cycle, verify_only))

            def expect(event, timeout):
                value = events.pop(0)
                self.assertEqual(value["event"], event)
                return value

            process = mock.Mock(cycle=cycle)
            process.expect.side_effect = expect
            process.wait_clean.side_effect = lambda timeout: self.assertEqual(events, [])
            return process, events.pop(0)

        def reset(args, process, baseline):
            resets.append(process.cycle)
            return {"reset_returncode": 0, "ssh_returncode": 255}

        identity = dict(instance_id="1", data_disk_id="2", data_disk_self_link="test/data",
                        attachment_source="test/data", attachment_device_name="test-data",
                        status="RUNNING")
        # Only controller/generation logic and the local fsynced ledger are real.
        # This fixture is not a VM-reset or storage-durability qualification.
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(self.host, "launch_guest", side_effect=launch))
            stack.enter_context(mock.patch.object(self.host, "resource_identity", return_value=identity))
            stack.enter_context(mock.patch.object(self.host, "cut_instance", side_effect=reset))
            offline = stack.enter_context(mock.patch.object(
                self.host, "run_offline_check", return_value={"returncode": 0}))
            stack.enter_context(mock.patch.object(subprocess, "Popen", side_effect=AssertionError("external process")))
            stack.enter_context(mock.patch.object(self.guest, "Nbd", side_effect=AssertionError("real NBD")))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            self.host.campaign(args)
            offline.assert_called_once_with(args, args.timeout)

        result = json.loads((args.output / "results.json").read_text())
        self.assertTrue(result["passed"])
        self.assertEqual(result["boots"][-1]["verified_generation"], cycles - 1)
        self.assertEqual(result["boots"][-1]["verified_units"], 16)
        self.assertNotIn("acked_units", result["boots"][-1])
        self.assertEqual(launches, [(cycle, cycle == cycles) for cycle in range(cycles + 1)])
        self.assertEqual(resets, list(range(cycles)))
        ledger = args.output / "host-acks.jsonl"
        self.assertEqual(len(ledger.read_text().splitlines()), cycles)
        self.assertEqual(self.host.load_ledger(ledger, profile)["cycle"], cycles - 1)

    def test_campaign_63_and_64_reach_final_readback_and_offline_check(self):
        for profile in ("v2", "v3-discard"):
            for cycles in (63, 64):
                with self.subTest(profile=profile, cycles=cycles):
                    self.run_local_campaign(cycles, profile)

    def test_campaign_65_is_rejected_before_resource_lookup(self):
        for profile in ("v2", "v3-discard"):
            with self.subTest(profile=profile):
                args = self.campaign_args(65, profile)
                with mock.patch.object(self.host, "resource_identity") as lookup:
                    with self.assertRaisesRegex(ValueError, "cycles must be 2..64"):
                        self.host.campaign(args)
                lookup.assert_not_called()
                self.assertFalse(args.output.exists())


if __name__ == "__main__":
    unittest.main()
