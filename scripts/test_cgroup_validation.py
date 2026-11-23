"""The fault campaign's oracle must not manufacture durability evidence."""
import argparse
import contextlib
import csv
import importlib.util
import io
import pathlib
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "campaign", pathlib.Path(__file__).with_name("cgroup-validation.py")
)
campaign = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(campaign)


def resource_snapshot(memory_mib, cpu="100000 100000"):
    return {"memory.max": str(memory_mib << 20), "memory.swap.max": "0",
            "cpu.max": cpu, "pids.max": "64"}


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

    def close(self):
        pass

    def read(self, offset, length):
        return self.data.get(offset, bytes(length))


class OracleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.ledger = pathlib.Path(self.directory.name) / "ack.jsonl"

    def unstarted_target(self):
        directory = pathlib.Path(tempfile.mkdtemp(dir=self.directory.name))
        with mock.patch.object(campaign.Target, "one_shot"):
            return campaign.Target("fixture-image", directory)

    def test_each_durable_block_distinguishes_sector_positions(self):
        for mode, writes in campaign.epoch_writes(0):
            for offset, block in writes:
                with self.subTest(mode=mode, offset=offset):
                    self.assertNotEqual(block, block[512:] + block[:512])

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

    def test_resumed_epoch_requires_fresh_contents_for_every_durable_unit(self):
        client = Client()
        args = argparse.Namespace(mode="write", rounds=1, start_epoch=0, socket=None, connected_fd=None, ledger=self.ledger)
        with mock.patch.object(campaign, "Nbd", return_value=client), contextlib.redirect_stdout(io.StringIO()):
            campaign.client_main(args)
            before = client.data.copy()
            args.start_epoch = args.rounds
            campaign.client_main(args)
        self.assertEqual(campaign.verify(client, self.ledger), 136)
        for index in range(136):
            self.assertNotEqual(before[index * 4096], client.data[index * 4096])
        client.data = before
        with self.assertRaisesRegex(AssertionError, "durable data mismatch"):
            campaign.verify(client, self.ledger)

    def test_campaign_requires_every_planned_ack_in_order(self):
        client = Client()
        for epoch in range(2):
            for mode, writes in campaign.epoch_writes(epoch):
                campaign.durable_write(client, self.ledger, writes, mode)
        self.assertEqual(campaign.verify(client, self.ledger, 2), 136)
        rows = self.ledger.read_text().splitlines(keepends=True)
        for invalid in (rows[1:], rows[:-1], rows[:136], [rows[1], *rows[1:]], [*rows, rows[0]]):
            self.ledger.write_text("".join(invalid))
            with self.assertRaises(ValueError):
                campaign.verify(client, self.ledger, 2)

    def test_rejects_a_mismatched_ack_before_parsing_later_rows(self):
        self.ledger.write_text('{"offset": 4096}\nunfinished row\n')
        with self.assertRaisesRegex(ValueError, "differs from the planned workload"):
            campaign.verify(Client(), self.ledger, 1)

    def test_freeze_observation_requires_a_connected_client(self):
        target = self.unstarted_target()
        target.ledger, target.identifier = self.ledger, "owned"
        self.ledger.write_bytes(b"unchanged")
        # A child that merely starts/exits without connecting must not qualify.
        target.client_command = mock.Mock(return_value=[campaign.sys.executable, "-c", "pass"])
        with mock.patch.object(campaign, "run") as docker:
            with self.assertRaisesRegex(AssertionError, "did not connect"):
                target.freeze_and_resume(self.ledger.parent, 1)
        docker.assert_called_once_with(["docker", "pause", "owned"])

    def test_connection_signal_follows_the_kernel_connection_and_precedes_negotiation(self):
        path = self.ledger.parent / "nbd.sock"
        connections = path.with_name("connections.log")
        connections.write_text('old connection=1 Connect export="" fua=1\n')
        receiver, sender = campaign.socket.socketpair()
        with campaign.socket.socket(campaign.socket.AF_UNIX) as listener, receiver, sender:
            listener.bind(str(path))
            listener.listen(1)
            listener.settimeout(1)
            receiver.settimeout(1)
            library = mock.Mock()
            library.nbd_create.return_value = 1
            library.nbd_can_fua.return_value = library.nbd_can_flush.return_value = 1

            def negotiate(_handle, descriptor):
                with listener.accept()[0]:
                    self.assertEqual(receiver.recv(1), b"C")
                with connections.open("a") as log:
                    log.write('current connection=2 Connect export="" fua=2\n')
                campaign.os.close(descriptor)  # model ownership taken by libnbd
                return 0

            library.nbd_connect_socket.side_effect = negotiate
            with mock.patch.object(campaign.ctypes, "CDLL", return_value=library):
                campaign.Nbd(path, sender.detach()).close()
            library.nbd_connect_unix.assert_not_called()

    def test_mount_argument_keeps_quoted_source_in_one_csv_field(self):
        target = self.unstarted_target()
        target.token = "fixture"
        target.case = self.ledger.parent / 'qual,"quoted"'
        options = target.options("32m", "1")
        fields, = csv.reader([options[options.index("--mount") + 1]])
        self.assertEqual(fields, ["type=bind", f"src={target.case}", "dst=/case"])

    def test_start_receives_notifications_in_a_long_artifact_directory(self):
        directory = self.ledger.parent / ("long-name" * 13)
        directory.mkdir()
        target = self.unstarted_target()
        target.case, target.identifier = directory, None
        target.create = mock.Mock()

        def announce_ready(_command):
            path = directory / "ready.sock"
            self.assertTrue(path.is_socket())
            with campaign.socket.socket(campaign.socket.AF_UNIX, campaign.socket.SOCK_DGRAM) as client, \
                    campaign.unix_socket_path(path) as address:
                client.sendto(b"READY=1", address)

        with mock.patch.object(campaign, "run", side_effect=announce_ready):
            try:
                target.start()
            finally:
                target.notify.close()

    def test_ready_packet_must_be_received_before_the_startup_deadline(self):
        target = self.unstarted_target()
        target.identifier, target.case = None, self.ledger.parent
        target.create = mock.Mock()
        for elapsed in (4, 30, 31):
            now = [0]

            def receive(_size):
                now[0] = elapsed
                return b"READY=1"

            with self.subTest(elapsed=elapsed), mock.patch.object(campaign.socket, "socket") as packet, \
                    mock.patch.object(campaign.time, "monotonic", side_effect=lambda: now[0]), \
                    mock.patch.object(campaign, "run"):
                packet.return_value.recv.side_effect = receive
                if elapsed < 30:
                    target.start()
                else:
                    with self.assertRaisesRegex(TimeoutError, "did not announce READY"):
                        target.start()

    def test_ready_state_check_uses_remaining_startup_budget(self):
        target = self.unstarted_target()
        target.identifier, target.case = None, self.ledger.parent
        target.create = mock.Mock()
        target.state = mock.Mock(side_effect=campaign.subprocess.TimeoutExpired("inspect", 29.9))
        now = [0.0]

        def receive(_size):
            now[0] += 0.1
            raise campaign.socket.timeout()

        with mock.patch.object(campaign.socket, "socket") as notification, \
                mock.patch.object(campaign.time, "monotonic", side_effect=lambda: now[0]), \
                mock.patch.object(campaign, "run"):
            notification.return_value.recv.side_effect = receive
            with self.assertRaisesRegex(TimeoutError, "did not announce READY"):
                target.start()
        self.assertAlmostEqual(target.state.call_args.kwargs["timeout"], 29.9)

    def test_oom_observation_uses_remaining_budget_and_retains_first_exit(self):
        target = self.unstarted_target()
        stopped = {"Running": False, "OOMKilled": True, "ExitCode": 137}
        now = 0.0

        def state(timeout):
            nonlocal now
            now += 2
            return {"Running": True} if now == 2 else stopped

        def sleep(seconds):
            nonlocal now
            now += seconds

        target.state = mock.Mock(side_effect=state)
        with mock.patch.object(campaign.time, "monotonic", side_effect=lambda: now), \
                mock.patch.object(campaign.time, "sleep", side_effect=sleep):
            self.assertIs(target.wait_for_oom(), stopped)
        self.assertEqual(target.state.call_count, 2)
        self.assertEqual(target.state.call_args_list[0].kwargs["timeout"], 10)
        self.assertAlmostEqual(target.state.call_args_list[1].kwargs["timeout"], 7.9)

    def test_oom_first_observed_after_the_deadline_fails(self):
        target = self.unstarted_target()
        now = 0

        def delayed_state(timeout=45):
            nonlocal now
            now += 30
            return {"Running": False, "OOMKilled": True, "ExitCode": 137}

        target.state = mock.Mock(side_effect=delayed_state)
        with mock.patch.object(campaign.time, "monotonic", side_effect=lambda: now), \
                self.assertRaisesRegex(TimeoutError, "OOM"):
            target.wait_for_oom()
        target.state.assert_called_once_with(timeout=10)

    def test_cleanup_tolerates_a_concurrent_exit_and_preserves_a_live_container(self):
        target = self.unstarted_target()
        target.directory, target.serial, target.notify = self.ledger.parent, 1, None
        for still_running in (True, False):
            with self.subTest(still_running=still_running):
                target.identifier = "owned"
                target.state = mock.Mock(side_effect=[{"Running": True}, {"Running": still_running}])
                def docker(command):
                    if command[1] == "kill":
                        raise RuntimeError("container exited")
                    return mock.Mock(stdout="", stderr="")
                with mock.patch.object(campaign, "run", side_effect=docker) as run:
                    if still_running:
                        with self.assertRaisesRegex(RuntimeError, "container exited"):
                            target.remove()
                        self.assertEqual(target.identifier, "owned")
                        self.assertEqual(run.call_count, 1)
                    else:
                        target.remove()
                        self.assertIsNone(target.identifier)
                        run.assert_called_with(["docker", "rm", "owned"])

    def test_remove_container_even_when_log_collection_fails(self):
        target = self.unstarted_target()
        target.notify, target.identifier = None, "owned-container"
        target.state = mock.Mock(return_value={"Running": False})
        with mock.patch.object(campaign, "run", side_effect=[OSError("logs unavailable"), None]) as run:
            with self.assertRaisesRegex(OSError, "logs unavailable"):
                target.remove()
        run.assert_called_with(["docker", "rm", "owned-container"])
        self.assertIsNone(target.identifier)

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

    def test_failed_constrained_create_preserves_the_original_error(self):
        for creation in (RuntimeError("image missing"), campaign.subprocess.TimeoutExpired("docker create", 45)):
            with self.subTest(creation=creation):
                target = self.unstarted_target()
                with mock.patch.object(campaign, "run", side_effect=[creation, mock.Mock(stdout="")]) as run:
                    with self.assertRaises(type(creation)) as raised:
                        campaign.constrained_recovery(target)
                self.assertIs(raised.exception, creation)
                self.assertEqual([call.args[0][1] for call in run.call_args_list], ["create", "ps"])
                self.assertIsNone(target.identifier)
                self.assertIsNone(target.pending_identifier)
                self.assertIsNone(target.notify)

    def test_timed_out_create_cleans_up_only_the_named_owned_container(self):
        for created in (False, True):
            with self.subTest(created=created):
                target = self.unstarted_target()
                name = f"maki-fault-{target.token}-1"
                timeout = campaign.subprocess.TimeoutExpired("docker create", 45)
                def docker(command, **_options):
                    action = command[1]
                    if action == "create":
                        raise timeout
                    if action == "ps":
                        self.assertIn("label=maki.failure-validation=" + target.token, command)
                        return mock.Mock(stdout="other\n" + (name + "\n" if created else ""))
                    self.assertEqual(command[-1], name)
                    if action == "inspect":
                        return mock.Mock(stdout='{"Running":false}')
                    return mock.Mock(stdout="", stderr="")
                with mock.patch.object(campaign, "run", side_effect=docker) as run:
                    with self.assertRaises(campaign.subprocess.TimeoutExpired) as raised:
                        target.one_shot(["true"])
                self.assertIs(raised.exception, timeout)
                self.assertEqual([call.args[0][1] for call in run.call_args_list],
                                 ["create", "ps"] + (["inspect", "logs", "rm"] if created else []))
                self.assertIsNone(target.identifier)
                self.assertIsNone(target.pending_identifier)

    def test_failed_create_and_ownership_lookup_are_both_reported_and_cleanup_can_retry(self):
        target = self.unstarted_target()
        error = RuntimeError("image missing")
        with mock.patch.object(campaign, "run", side_effect=[error, RuntimeError("Docker unavailable")]):
            with self.assertRaisesRegex(RuntimeError, "image missing.*Docker unavailable") as raised:
                campaign.constrained_recovery(target)
        self.assertIs(raised.exception.__cause__, error)
        name = f"maki-fault-{target.token}-1"
        self.assertEqual(target.pending_identifier, name)
        self.assertIsNone(target.identifier)
        with mock.patch.object(campaign, "run", side_effect=[mock.Mock(stdout=name),
                               mock.Mock(stdout='{"Running":false}'), mock.Mock(stdout="", stderr=""), None]) as run:
            target.remove()
        run.assert_called_with(["docker", "rm", name])
        self.assertIsNone(target.identifier)
        self.assertIsNone(target.pending_identifier)

    def test_campaign_persists_primary_and_cleanup_failures(self):
        output = self.ledger.parent / "results"
        name = None

        def docker(command, **_options):
            nonlocal name
            action = command[1]
            if action == "info":
                return mock.Mock(stdout=campaign.json.dumps(dict(CgroupVersion="2", MemoryLimit=True,
                                 SwapLimit=True, CpuCfsQuota=True, PidsLimit=True, ServerVersion="fixture")))
            if action == "image":
                return mock.Mock(stdout="image")
            if action == "create":
                name = command[command.index("--name") + 1]
                raise campaign.subprocess.TimeoutExpired("docker create", 45)
            if action == "ps":
                return mock.Mock(stdout=name)
            self.assertEqual(action, "inspect")
            raise RuntimeError("inspect unavailable")

        with mock.patch.object(campaign, "run", side_effect=docker):
            with self.assertRaisesRegex(RuntimeError, "inspect unavailable"):
                campaign.campaign(argparse.Namespace(output=output, image="fixture"))
        report = campaign.json.loads((output / "results.json").read_text())
        self.assertFalse(report["passed"])
        self.assertIn("TimeoutExpired", report["error"])
        self.assertIn("docker create", report["error"])
        self.assertIn(name, report["error"])
        self.assertIn("inspect unavailable", report["error"])

    def test_container_cli_timeout_still_cleans_exact_created_container(self):
        target = self.unstarted_target()
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
        script = pathlib.Path(SPEC.origin)
        bytecode = (script.with_name("__pycache__"), script.stem + ".*")
        for stale in bytecode[0].glob(bytecode[1]):
            stale.unlink()
        result = campaign.subprocess.run([campaign.sys.executable, "-O", "-c", code], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(bytecode[0].glob(bytecode[1])), [], "the child compiled into the checkout")

    def test_pressure_requires_actual_completed_io(self):
        with self.assertRaisesRegex(AssertionError, "pressure I/O"):
            campaign.require_pressure({"completed": 0, "attempted": 0})
        campaign.require_pressure({"completed": 3, "attempted": 4})

    def test_completed_case_is_published_before_the_next_case_starts(self):
        output = self.ledger.parent / "campaign"
        info = mock.Mock(stdout=campaign.json.dumps(dict(CgroupVersion="2", MemoryLimit=True,
                         SwapLimit=True, CpuCfsQuota=True, PidsLimit=True, ServerVersion="fixture")))
        target = mock.Mock()
        target.client.return_value = target.kill.return_value = {}
        target.stats.side_effect = [{**resource_snapshot(96, "12500 50000"), "cpu.stat": "nr_throttled 1"},
                                    resource_snapshot(192)]
        target.one_shot.return_value = mock.Mock(returncode=0, stdout="ok")

        def create(_image, directory):
            if directory.name == "cpu-memory-kill":
                return target
            saved = campaign.json.loads((output / "results.json").read_text())
            self.assertFalse(saved["passed"])
            first, = saved["cases"]
            self.assertTrue(first["passed"])
            self.assertEqual(first["scenario"], "cpu-memory-kill")
            raise RuntimeError("second case failed")

        with mock.patch.object(campaign, "run", side_effect=[info, mock.Mock(stdout="image")]), \
                mock.patch.object(campaign, "Target", side_effect=create):
            with self.assertRaisesRegex(RuntimeError, "second case failed"):
                campaign.campaign(argparse.Namespace(output=output, image="fixture", rounds=1))
        final = campaign.json.loads((output / "results.json").read_text())
        self.assertEqual([c["passed"] for c in final["cases"]], [True, False])

    def test_initial_docker_failure_leaves_a_failed_campaign_report(self):
        for step in ("info", "image"):
            with self.subTest(step=step):
                output = self.ledger.parent / step
                info = mock.Mock(stdout=campaign.json.dumps(dict(
                    CgroupVersion="2", MemoryLimit=True, SwapLimit=True, CpuCfsQuota=True,
                    PidsLimit=True, ServerVersion="fixture")))
                failure = RuntimeError(f"{step} unavailable")
                commands = [failure] if step == "info" else [info, failure]
                with mock.patch.object(campaign, "run", side_effect=commands):
                    with self.assertRaisesRegex(RuntimeError, str(failure)):
                        campaign.campaign(argparse.Namespace(output=output, image="fixture"))
                report = campaign.json.loads((output / "results.json").read_text())
                self.assertFalse(report["passed"])
                self.assertEqual(report["cases"], [])
                self.assertIn(str(failure), report["error"])

    def test_constrained_oom_at_deadline_or_during_final_stats(self):
        stopped = {"Running": False, "OOMKilled": True, "ExitCode": 137, "Pid": 0}
        for timing in ("deadline", "stats", "kill"):
            with self.subTest(timing=timing):
                target = mock.Mock()
                target.start.side_effect = TimeoutError("no READY")
                target.state.side_effect = [stopped] if timing == "deadline" else [
                    {"Running": True}, stopped]
                if timing == "stats":
                    target.stats.side_effect = FileNotFoundError("PID has exited")
                if timing == "kill":
                    target.kill.side_effect = RuntimeError("container already exited")
                result = campaign.constrained_recovery(target)
                self.assertEqual(result["outcome"], "startup-oom")
                self.assertFalse(result["limits_verified"])
                self.assertEqual(result["termination"], stopped)
                if timing == "deadline":
                    target.stats.assert_not_called()
                target.remove.assert_called_once_with()

    def test_constrained_startup_timeout_is_recorded_as_unavailable(self):
        target = mock.Mock()
        target.start.side_effect = TimeoutError("no READY")
        target.state.return_value = {"Running": True, "OOMKilled": False}
        target.stats.return_value = resource_snapshot(32)
        result = campaign.constrained_recovery(target)
        self.assertFalse(result["ready"])
        self.assertEqual(result["outcome"], "startup-timeout")
        self.assertTrue(result["limits_verified"])
        target.client.assert_not_called()
        target.kill.assert_called_once_with()
        target.remove.assert_called_once_with()

    def test_constrained_recovery_uses_requested_memory_cap(self):
        target = mock.Mock()
        target.start.side_effect = TimeoutError("no READY")
        target.state.return_value = {"Running": True, "OOMKilled": False}
        target.stats.return_value = resource_snapshot(64)
        result = campaign.constrained_recovery(target, memory_mib=64)
        self.assertFalse(result["ready"])
        target.start.assert_called_once_with(memory="64m")

    def test_only_the_observed_memory_cap_and_disabled_swap_can_qualify_readback(self):
        expected = resource_snapshot(64)
        for field, value in (("memory.max", "max"), ("memory.max", str(192 << 20)),
                             ("memory.swap.max", "max"), ("memory.swap.max", "unavailable"),
                             ("memory.max", None)):
            with self.subTest(field=field, value=value):
                target = mock.Mock()
                target.stats.return_value = dict(expected)
                if value is None:
                    del target.stats.return_value[field]
                else:
                    target.stats.return_value[field] = value
                with self.assertRaisesRegex(AssertionError, field):
                    campaign.constrained_recovery(target, memory_mib=64)
                target.client.assert_not_called()
                target.remove.assert_called_once_with()
        target = mock.Mock()
        final = {**expected, "memory.peak": str(63 << 20)}
        target.stats.side_effect = [{**expected, "memory.peak": str(8 << 20)}, final]
        result = campaign.constrained_recovery(target, memory_mib=64, rounds=7)
        self.assertEqual(result["resources"], final)
        self.assertEqual(result["outcome"], "verified")
        self.assertTrue(result["limits_verified"])
        target.assert_has_calls([mock.call.stats(), mock.call.client("verify", rounds=7),
                                 mock.call.stats(), mock.call.kill()])

    def test_throttling_does_not_prove_expected_cpu_or_pid_limits(self):
        expected = {**resource_snapshot(96, "25000 100000"), "cpu.stat": "nr_throttled 7"}
        campaign.require_limits(expected, 96, "0.25")
        for field, value in (("cpu.max", "50000 100000"), ("cpu.max", "max 100000"),
                             ("cpu.max", "0 0"), ("cpu.max", "unavailable"), ("cpu.max", None),
                             ("pids.max", "128"), ("pids.max", "max"), ("pids.max", None)):
            with self.subTest(field=field, value=value):
                observed = dict(expected)
                if value is None:
                    del observed[field]
                else:
                    observed[field] = value
                with self.assertRaisesRegex(AssertionError, field):
                    campaign.require_limits(observed, 96, "0.25")

    def test_limits_must_still_match_after_recovery_readback(self):
        target = mock.Mock()
        target.stats.side_effect = [
            resource_snapshot(32),
            {**resource_snapshot(32), "memory.max": "max"},
        ]
        with self.assertRaisesRegex(AssertionError, "memory.max"):
            campaign.constrained_recovery(target)
        target.client.assert_called_once_with("verify", rounds=1)
        target.remove.assert_called_once_with()

    def test_unrelated_startup_failure_is_not_qualified_as_oom(self):
        target = mock.Mock()
        target.start.side_effect = RuntimeError("invalid config")
        target.state.return_value = {"Running": False, "OOMKilled": False, "ExitCode": 1}
        with self.assertRaisesRegex(AssertionError, "OOMKilled"):
            campaign.constrained_recovery(target)
        target.remove.assert_called_once_with()

    def test_membership_path_preserves_non_lf_bytes(self):
        target = self.unstarted_target()
        target.state = mock.Mock(return_value={"Pid": 1234})
        root = pathlib.Path(self.directory.name)
        proc = root / "proc/1234"
        proc.mkdir(parents=True)
        (proc / "status").write_text("")
        for leaf in ("parent\u2028child", "parent\x85child", "parent\r", "nonutf\udcfe"):
            with self.subTest(leaf=leaf):
                cgroup = root / "sys/fs/cgroup" / leaf
                cgroup.mkdir(parents=True)
                (cgroup / "memory.max").write_text("50331648")
                (proc / "cgroup").write_bytes(b"0::/" + campaign.os.fsencode(leaf) + b"\n")
                with mock.patch.object(campaign.pathlib, "Path", side_effect=lambda path: root / path.lstrip("/")):
                    self.assertEqual(target.stats()["memory.max"], "50331648")

    def test_startup_metrics_use_the_current_container_before_ready(self):
        target = self.unstarted_target()
        target.cgroup = pathlib.Path("/stale-previous-container")
        target.state = mock.Mock(return_value={"Pid": 1234})

        def read(path):
            if str(path) == "/proc/1234/status":
                return "Name:\tnbdkit\nVmHWM:\t12345 kB\nVmRSS:\t8192 kB\nRssAnon:\t4096 kB\nRssFile:\t4096 kB\nRssShmem:\t0 kB\n"
            if str(path) == "/sys/fs/cgroup/current-container/memory.max":
                return "33554432\n"
            return "0"

        with mock.patch.object(pathlib.Path, "read_bytes", return_value=b"0::/current-container\n"), \
                mock.patch.object(pathlib.Path, "read_text", autospec=True, side_effect=read):
            stats = target.stats()
            self.assertEqual(stats["memory.max"], "33554432")
            self.assertEqual(stats["process.VmHWM.bytes"], 12345 * 1024)
            self.assertEqual(stats["process.VmRSS.bytes"], 8192 * 1024)


if __name__ == "__main__":
    unittest.main()
