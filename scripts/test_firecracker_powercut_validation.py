"""Host-oracle and guest-barrier contracts, without KVM or device operations."""
import contextlib
import hashlib
import importlib.util
import io
import json
import pathlib
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
        self.host = load("fc_host", "firecracker-powercut-validation.py")
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = pathlib.Path(self.directory.name)
        self.ledger = self.path / "acks.jsonl"

    def frame(self, **fields):
        return b"MAKI_FC_V1 " + json.dumps({"token": "a" * 32, "boot": 1, **fields}).encode()

    def test_serial_noise_is_not_an_ack_and_stale_boot_is_rejected(self):
        self.assertIsNone(self.host.decode_frame(b"kernel: READY=1", "a" * 32, 1))
        with self.assertRaisesRegex(ValueError, "identity"):
            self.host.decode_frame(self.frame(event="ack"), "b" * 32, 1)
        with self.assertRaisesRegex(ValueError, "identity"):
            self.host.decode_frame(self.frame(event="ack"), "a" * 32, 2)

    def test_wire_fua_requires_a_native_default_export_in_the_server_log(self):
        guest = load("fc_fua", "firecracker-guest-agent.py")
        cgroup = load("cgroup_fua", "cgroup-validation.py")
        socket = self.path / "nbd.sock"
        connections = self.path / "connections.log"
        for client in (guest, cgroup):
            for fields in ('Connect export="" fua=2', 'Connect export="" fua=1',
                           'Connect export="" fua=20', 'Connect export="other" fua=2', ''):
                with self.subTest(client=client.__name__, fields=fields):
                    # cgroup reuses its daemon for multiple connections.
                    stale = 'old connection=1 Connect export="" fua=2\n' if client is cgroup else ''
                    connections.write_text(stale)
                    library = mock.Mock()
                    library.nbd_create.return_value = 1
                    library.nbd_can_fua.return_value = library.nbd_can_flush.return_value = 1

                    def negotiate(_handle, _address):
                        with connections.open("a") as log:
                            log.write(f"new connection=2 {fields}\n")
                        return 0

                    library.nbd_connect_unix.side_effect = negotiate
                    with mock.patch.object(client.ctypes, "CDLL", return_value=library):
                        if fields == 'Connect export="" fua=2':
                            handle = client.Nbd(socket)
                            handle.lib.nbd_close(handle.handle)
                        else:
                            with self.assertRaisesRegex((ValueError, AssertionError), "native FUA"):
                                client.Nbd(socket)
                    library.nbd_close.assert_called_once_with(1)

    def test_guest_mount_failure_reaches_host_before_ready(self):
        guest = load("fc_mount_failure", "firecracker-guest-agent.py")
        agent = guest.Agent()
        with mock.patch.object(guest, "mount_guest", side_effect=OSError("data mount failed")), \
                contextlib.redirect_stdout(io.StringIO()) as console:
            try:
                agent.startup()
            except OSError as error:
                agent.failure(error)
        process = self.host.SerialProcess.__new__(self.host.SerialProcess)
        process.token, process.boot = "a" * 32, 0
        process.buffer = bytearray(console.getvalue().encode())
        with self.assertRaisesRegex(RuntimeError, "data mount failed"):
            process.expect("ready", 120)

    def test_truncated_or_oversized_control_frames_are_rejected(self):
        for raw in (b"MAKI_FC_V1 {", b"MAKI_FC_V1 " + b"x" * 65536):
            with self.assertRaises(ValueError):
                self.host.decode_frame(raw, "a" * 32, 1)

    def ack(self, cycle=0):
        mode = "flush" if cycle % 2 == 0 else "fua"
        return {"event": "ack", "command": f"write-{cycle}", "cycle": cycle,
                "mode": mode, "records": self.host.expected_records(cycle)}

    def test_false_partial_or_wrong_barrier_ack_never_enters_ledger(self):
        for field, value in (("event", "ready"), ("command", "write-77"),
                             ("mode", "fua"), ("cycle", 1), ("records", [])):
            ack = self.ack()
            ack[field] = value
            with self.assertRaises(ValueError):
                self.host.record_ack(self.ledger, ack, 0)
            self.assertFalse(self.ledger.exists())

    def test_previous_ledgers_remain_readable_only_as_historical_evidence(self):
        archived = self.ack()
        for index, row in enumerate(archived["records"]):
            seed = f"maki-firecracker-v1:0:{index}".encode()
            row["sha256"] = hashlib.sha256(hashlib.sha256(seed).digest() * 128).hexdigest()
        self.ledger.write_text(json.dumps(archived) + "\n")
        self.assertEqual(self.host.load_ledger(self.ledger, expected_cycles=1), archived["records"])
        with self.assertRaises(ValueError):
            self.host.load_ledger(self.ledger, expected_cycles=1, require_current=True)
        with self.assertRaises(ValueError):
            self.host.record_ack(self.ledger, archived, 0)
        self.host.record_ack(self.ledger, self.ack(1), 1)
        with self.assertRaises(ValueError):
            self.host.load_ledger(self.ledger, expected_cycles=2)

    def test_correct_ack_is_fsynced_and_latest_generation_is_loaded(self):
        with mock.patch.object(self.host.os, "fsync", wraps=self.host.os.fsync) as sync:
            self.host.record_ack(self.ledger, self.ack(), 0)
            self.assertGreaterEqual(sync.call_count, 1)
        self.host.record_ack(self.ledger, self.ack(1), 1)
        self.assertEqual(self.host.load_ledger(self.ledger, expected_cycles=2), self.host.expected_records(1))

    def test_empty_truncated_or_duplicate_ledger_cannot_qualify(self):
        for text in ("", "{", json.dumps(self.ack()) + "\n" + json.dumps(self.ack()) + "\n"):
            self.ledger.write_text(text)
            with self.assertRaises(ValueError):
                self.host.load_ledger(self.ledger, expected_cycles=2)

    def test_each_verification_boot_requires_exactly_its_preceding_ack_rows(self):
        self.host.record_ack(self.ledger, self.ack(0), 0)
        with self.assertRaisesRegex(ValueError, "ACK.*count"):
            self.host.load_ledger(self.ledger, expected_cycles=2)
        self.host.record_ack(self.ledger, self.ack(1), 1)
        with self.assertRaisesRegex(ValueError, "ACK.*count"):
            self.host.load_ledger(self.ledger, expected_cycles=1)
        self.assertEqual(self.host.load_ledger(self.ledger, expected_cycles=2),
                         self.host.expected_records(1))

    def test_missing_wrong_or_duplicate_readback_is_failure(self):
        expected = self.host.expected_records(0)
        self.host.verify_readbacks(expected, expected)
        wrong = [dict(row) for row in expected]
        wrong[0]["sha256"] = "0" * 64
        for actual in ([], expected[:-1], wrong, expected + expected[:1]):
            with self.assertRaises(ValueError):
                self.host.verify_readbacks(expected, actual)

    def test_every_boot_uses_same_data_image_with_explicit_flush_semantics(self):
        args = types.SimpleNamespace(kernel=self.path / "kernel", rootfs=self.path / "root",
                                     data=self.path / "data", vcpus=2, memory_mib=512, timeout=450)
        for boot in (0, 1):
            config = self.host.make_config(args, boot, "a" * 32)
            self.assertIn("maki_ready_timeout=450", config["boot-source"]["boot_args"])
            root, data = config["drives"]
            self.assertTrue(root["is_read_only"])
            self.assertFalse(data["is_read_only"])
            self.assertEqual(data["path_on_host"], str(args.data))
            self.assertEqual(data["cache_type"], "Writeback")
            self.assertEqual(data["io_engine"], "Sync")
            self.assertIn(f"maki_boot={boot}", config["boot-source"]["boot_args"])
            self.assertEqual(config["machine-config"]["mem_size_mib"], 512)

    def test_timeout_kills_and_reaps_owned_child_before_diagnostics(self):
        process = self.host.SerialProcess([sys.executable, "-c", "import time; time.sleep(30)"],
                                          self.path / "boot", "a" * 32, 0)
        with self.assertRaises(TimeoutError):
            with process:
                process.expect("ready", timeout=0.05)
        self.assertEqual(process.child.returncode, -9)
        self.assertIsInstance(process.diagnostics(), str)

    def test_optimized_interpreter_keeps_false_ack_gate(self):
        source = str(pathlib.Path(__file__).with_name("firecracker-powercut-validation.py"))
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
        self.guest = load("fc_guest", "firecracker-guest-agent.py")
        self.host = load("fc_host", "firecracker-powercut-validation.py")

    def test_failed_flush_or_fua_does_not_return_an_ack(self):
        for mode in ("flush", "fua"):
            client = mock.Mock()
            if mode == "flush":
                client.flush.side_effect = RuntimeError("injected flush failure")
            else:
                client.write.side_effect = RuntimeError("injected FUA failure")
            with self.assertRaises(RuntimeError):
                self.guest.barrier(client, 0, mode)

    def test_pid1_children_use_an_explicit_system_path(self):
        with mock.patch.dict("os.environ", PATH="/unknown"):
            child_path = self.guest.run([sys.executable, "-c", "import os; print(os.environ['PATH'])"])
        self.assertEqual(child_path, self.guest.SYSTEM_PATH)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux guest")
    def test_guest_setup_limits_combined_output_before_child_exit(self):
        gce = load("gce_setup", "gcp-reset-guest.py")
        for run in (self.guest.run, gce.run_output):
            for fd in (1, 2):
                with self.subTest(run=run, fd=fd), self.assertRaisesRegex(ValueError, "output limit"):
                    run([sys.executable, "-c",
                         f"import os,time; os.write({fd}, b'x' * 65537); time.sleep(10)"], timeout=1)
            with self.subTest(run=run):
                exact = "import os; os.write(1, b'a'*32768); os.write(2, b'b'*32768)"
                self.assertEqual(run([sys.executable, "-c", exact]), "a" * 32768)
                with self.assertRaisesRegex(ValueError, "output limit"):
                    run([sys.executable, "-c", exact + "; os.write(2, b'!')"])
                with self.assertRaisesRegex(RuntimeError, "exited 9: diagnostic"):
                    run([sys.executable, "-c", "import sys; print('diagnostic', file=sys.stderr); sys.exit(9)"])
                with self.assertRaises(subprocess.TimeoutExpired):
                    run([sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.1)

    def test_real_payload_manifest_matches_host_and_barrier_calls(self):
        for cycle, mode in ((0, "flush"), (1, "fua")):
            client = mock.Mock()
            records = self.guest.barrier(client, cycle, mode)
            self.assertEqual(records, self.host.expected_records(cycle))
            self.assertEqual(client.write.call_count, 16)
            for call in client.write.call_args_list:
                self.assertEqual(call.kwargs["fua"], mode == "fua")
                block = call.args[1]
                self.assertNotEqual(block, block[512:] + block[:512])
            self.assertEqual(client.flush.call_count, int(mode == "flush"))


if __name__ == "__main__":
    unittest.main()
