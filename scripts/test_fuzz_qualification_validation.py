"""The parser fuzz qualification campaign (scripts/fuzz_campaign.py, run by
.github/workflows/fuzz-qualification.yml): how it splits a target's
CPU-hours, the -max_len each target needs, what one shard records of its
libFuzzer processes, the merge of a target's corpora, and the verdict of the
summary."""

import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "fuzz_campaign.py"
MANIFEST = ROOT / "fuzz" / "Cargo.toml"
SEEDS = ROOT / "fuzz" / "seeds"


def campaign():
    spec = importlib.util.spec_from_file_location("fuzz_campaign", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def targets():
    return re.findall(r'(?m)^\[\[bin\]\]\r?\nname = "([^"]+)"\r?$', MANIFEST.read_text())


def rust_const(path, name):
    """The value of `const NAME: usize = <expression>;` (or a struct field
    `name: <expression>,`) in a Rust source, for expressions of integers, `*`
    and `<<`."""
    source = (ROOT / path).read_text()
    match = (re.search(rf"\bconst {name}: (?:usize|u64|u32) = ([0-9_ *<]+);", source)
             or re.search(rf"\b{name}: ([0-9_ *<]+),", source))
    assert match is not None, f"{path} defines no {name}"
    expression = match.group(1).replace("_", "")
    assert re.fullmatch(r"[0-9 *<]+", expression), expression
    return eval(expression, {"__builtins__": {}})


# A stand-in for a libFuzzer binary. Each invocation takes the next mode of
# FAKE_MODES (by the order of the invocations), appends its arguments and
# ASAN_OPTIONS to FAKE_CALLS, and prints what libFuzzer prints.
FAKE_FUZZER = r'''#!/usr/bin/env python3
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import time

arguments = sys.argv[1:]
flags = dict(argument[1:].split("=", 1) for argument in arguments if argument.startswith("-"))
directories = [argument for argument in arguments if not argument.startswith("-")]
with open(os.environ["FAKE_CALLS"], "a+") as calls:
    fcntl.flock(calls, fcntl.LOCK_EX)
    calls.seek(0)
    index = len(calls.readlines())
    calls.write(json.dumps({"arguments": arguments, "asan": os.environ.get("ASAN_OPTIONS"),
                            "temp": os.environ.get("TMPDIR")}) + "\n")
modes = json.loads(os.environ.get("FAKE_MODES", "[]"))
mode = modes[index] if index < len(modes) else "ok"
out = sys.stdout


def say(line):
    out.write(line + "\n")
    out.flush()


def final(runs):
    say(f"stat::number_of_executed_units: {runs}")
    say(f"stat::average_exec_per_sec:     {runs // 2}")
    say("stat::new_units_added:          2")
    say("stat::slowest_unit_time_sec:    0")
    say("stat::peak_rss_mb:              41")


def keep(directory, data):
    path = Path(directory) / hashlib.sha1(data).hexdigest()
    path.write_bytes(data)


if flags.get("merge") == "1":
    output, inputs = directories[0], directories[1:]
    seen = set()
    for directory in inputs:
        for entry in sorted(Path(directory).iterdir()):
            data = entry.read_bytes()
            if data not in seen:
                seen.add(data)
                keep(output, data)
    say(f"MERGE-OUTER: {len(seen)} new files with {len(seen) * 3} new features added; "
        f"{len(seen) * 2} new coverage edges")
    sys.exit(int(os.environ.get("FAKE_MERGE_EXIT", "0")))
if flags.get("runs") == "0":
    files = list(Path(directories[0]).iterdir())
    size = sum(entry.stat().st_size for entry in files)
    say("INFO: Seed: 1")
    if os.environ.get("FAKE_NO_INITED") != "1":
        say(f"#{len(files)}\tINITED cov: {len(files) * 10} ft: {len(files) * 20} "
            f"corp: {len(files)}/{size}b exec/s: 0 rss: 30Mb")
    say(f"Done {len(files)} runs in 0 second(s)")
    sys.exit(0)

say(f"INFO: Seed: {1000 + index}")
say(f"#2\tINITED cov: 10 ft: 12 corp: 1/1b exec/s: 0 rss: 30Mb")
if mode == "crash":
    say(f"==4242== ERROR: libFuzzer: deadly signal")
    Path(flags["artifact_prefix"] + "crash-0123456789abcdef").write_bytes(b"boom")
    final(50)
    sys.exit(77)
if mode in ("hang", "stubborn"):
    if mode == "hang":
        def interrupted(*_):
            say("==4242== libFuzzer: run interrupted; exiting")
            final(7)
            sys.exit(72)
        signal.signal(signal.SIGINT, interrupted)
    else:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    while True:
        time.sleep(0.05)
if mode == "burn":
    # Charged FAKE_BURN seconds of CPU time, after FAKE_SLEEP of waiting.
    time.sleep(float(os.environ.get("FAKE_SLEEP", "0")))
    while time.process_time() < float(os.environ["FAKE_BURN"]):
        pass
keep(directories[0], f"found by {index}".encode())
if mode == "litter":
    Path(os.environ["TMPDIR"], f"left-by-{index}").write_text("litter")
say(f"#600\tNEW    cov: 11 ft: 14 corp: 2/9b lim: 4 exec/s: 0 rss: 31Mb L: 8/8 MS: 1 CopyPart-")
say(f"#1000\tDONE   cov: 12 ft: 15 corp: 3/12b lim: 4 exec/s: 1000 rss: 31Mb")
say("Done 1000 runs in 1 second(s)")
final(1000 + index)
sys.exit(0)
'''


class Fixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="maki-fuzz-campaign-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.binary = self.root / "fuzzer"
        self.binary.write_text(FAKE_FUZZER)
        self.binary.chmod(0o700)
        self.calls = self.root / "calls.jsonl"
        self.seeds = self.root / "seeds"
        self.seeds.mkdir()
        (self.seeds / "valid-a").write_bytes(b"seed a")
        (self.seeds / "refused-b").write_bytes(b"seed b")
        self.environment = {"FAKE_CALLS": str(self.calls), "FAKE_MODES": "[]"}
        patch = unittest.mock.patch.dict(os.environ, self.environment)
        patch.start()
        self.addCleanup(patch.stop)
        self.campaign = campaign()

    def calls_made(self):
        if not self.calls.exists():
            return []
        return [json.loads(line) for line in self.calls.read_text().splitlines()]



class Plan(unittest.TestCase):
    def test_a_targets_cpu_hours_are_split_into_equal_shares_of_equal_shards(self):
        plan = campaign().plan("all", "24", "5", "16")
        names = targets()
        self.assertGreaterEqual(len(names), 16)
        self.assertEqual(plan["targets"], names)
        # 24 CPU-hours over 4 processes are 6 hours each: two shards whose
        # processes are each charged 3 hours within 5 hours.
        self.assertEqual((plan["workers"], plan["shards"], plan["cpu_seconds"], plan["wall_seconds"]),
                         (4, 2, 10800, 18000))
        self.assertEqual(len(plan["matrix"]), 2 * len(names))
        for entry in plan["matrix"]:
            self.assertEqual(entry["cpu_seconds"] * entry["workers"] * entry["shards"], 24 * 3600)
            self.assertEqual(entry["wall_seconds"], 5 * 3600)
            # The step outlives the shard's wall time, the grace and the kill.
            self.assertGreater(entry["minutes"] * 60, entry["wall_seconds"] + 600 + 60)
            self.assertLessEqual(entry["minutes"], 340)
        self.assertEqual([(entry["target"], entry["shard"]) for entry in plan["matrix"][:3]],
                         [(names[0], 1), (names[0], 2), (names[1], 1)])
        self.assertEqual(plan["max_parallel"], 16)

    def test_the_shares_cover_the_requested_cpu_hours_with_headroom_in_wall_time(self):
        module = campaign()
        for cpu_hours, shard_hours in (("24", "5"), ("24", "1"), ("1", "5"), ("0.1", "5"),
                                       ("100", "4.5"), ("7.25", "2")):
            with self.subTest(cpu_hours=cpu_hours, shard_hours=shard_hours):
                plan = module.plan("format_decoders", cpu_hours, shard_hours, "20")
                charged = plan["shards"] * plan["workers"] * plan["cpu_seconds"]
                self.assertGreaterEqual(charged, float(cpu_hours) * 3600)
                self.assertLess(charged, float(cpu_hours) * 3600 + plan["shards"] * plan["workers"])
                self.assertEqual(plan["wall_seconds"], int(float(shard_hours) * 3600))
                # A process may take half again its share in wall time.
                self.assertLessEqual(plan["cpu_seconds"] * 1.5, plan["wall_seconds"] + 1.5)

    def test_a_list_of_targets_is_read_in_the_manifests_order(self):
        module = campaign()
        plan = module.plan(" witness_etcd,format_decoders  witness_etcd ", "1", "5", "4")
        self.assertEqual(plan["targets"], ["format_decoders", "witness_etcd"])
        self.assertEqual({entry["target"] for entry in plan["matrix"]},
                         {"format_decoders", "witness_etcd"})

    def test_inputs_it_cannot_honour_are_refused(self):
        module = campaign()
        for arguments in (("nope", "24", "5", "16"), ("all;rm", "24", "5", "16"),
                          ("", "24", "5", "16"), ("all", "0", "5", "16"), ("all", "-1", "5", "16"),
                          ("all", "nan", "5", "16"), ("all", "inf", "5", "16"),
                          ("all", "24", "6", "16"), ("all", "24", "0", "16"),
                          ("all", "24", "5", "21"), ("all", "24", "5", "0"),
                          ("all", "24", "5", "2.5"), ("all", "24", "5", "x"),
                          # 16 targets of 1000 CPU-hours in jobs of 1 hour: beyond 256 jobs.
                          ("all", "1000", "1", "20")):
            with self.subTest(arguments=arguments):
                with self.assertRaises(SystemExit):
                    module.plan(*arguments)

    def test_target_names_are_safe_in_artifact_names_and_patterns(self):
        module = campaign()
        with self.assertRaises(SystemExit):
            module.plan("all", "1", "5", "4", available=["good", "bad-name"])

    def test_the_manifest_is_read_whatever_its_line_ends(self):
        module = campaign()
        text = MANIFEST.read_text().replace("\r\n", "\n")
        self.assertEqual(module.manifest_targets(text), targets())
        self.assertEqual(module.manifest_targets(text.replace("\n", "\r\n")), targets())

    def test_the_plan_is_printed_as_step_outputs(self):
        result = subprocess.run([sys.executable, "-B", str(SCRIPT), "plan", "--targets",
                                 "helper_sysfs", "--cpu-hours", "2", "--shard-hours", "5",
                                 "--max-parallel", "8"],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        outputs = dict(line.split("=", 1) for line in result.stdout.splitlines())
        self.assertEqual(sorted(outputs), ["matrix", "max_parallel", "plan", "targets"])
        plan = json.loads(outputs["plan"])
        self.assertEqual(json.loads(outputs["matrix"]), plan["matrix"])
        self.assertEqual(json.loads(outputs["targets"]), ["helper_sysfs"])
        self.assertEqual(outputs["max_parallel"], "8")
        self.assertEqual(plan["cpu_hours"], 2)


class MaxLen(unittest.TestCase):
    """-max_len: libFuzzer neither generates a longer input nor reads more
    of a longer seed, so a limit beyond it is never tested."""

    def test_every_named_target_exists(self):
        self.assertLessEqual(set(campaign().MAX_LEN), set(targets()))

    def test_no_committed_seed_is_longer_than_its_targets_max_len(self):
        module = campaign()
        for target in targets():
            for seed in sorted((SEEDS / target).iterdir()):
                with self.subTest(target=target, seed=seed.name):
                    self.assertLessEqual(seed.stat().st_size, module.max_len(target))

    def test_each_length_lies_beyond_the_bound_its_readers_check(self):
        module = campaign()
        # (target, the shortest input that crosses the bound)
        bounds = {
            # The selector byte and one byte beyond a 4096-byte superblock.
            "format_decoders": 1 + rust_const("crates/maki-format/src/superblock.rs",
                                              "SUPERBLOCK_SIZE") + 1,
            "format_records": 1 + rust_const("crates/maki-format/src/superblock.rs",
                                             "SUPERBLOCK_SIZE") + 1,
            # A method path one byte longer than the limit, in a configuration.
            "config_parse": rust_const("crates/maki-format/src/config/grpc_method_path.rs",
                                       "MAX_GRPC_METHOD_PATH_BYTES") + 1 + 1024,
            "nbd_handshake": rust_const("crates/maki-privileged/src/nbd_kernel/handshake.rs",
                                        "MAX_HANDSHAKE_BYTES") + 1,
            # The selector, then each datagram's sender, length and bytes.
            "nbd_netlink": 1 + rust_const("crates/maki-privileged/src/nbd_kernel/netlink.rs",
                                          "MAX_DATAGRAMS")
            * (3 + rust_const("crates/maki-privileged/src/nbd_kernel/netlink.rs", "MAX_DATAGRAM")),
            "backing_records": 1 + rust_const("crates/maki-backing/src/remote_witness.rs",
                                              "MAX_BYTES") + 1,
            # The selector, the frame's length and one byte beyond the limit.
            "witness_rpc": 1 + 4 + rust_const("crates/maki-witness/src/lib.rs",
                                              "MAX_FRAME_BYTES") + 1,
            "witness_etcd": 1 + rust_const("crates/maki-witness/src/etcd.rs", "MAX_JSON_BYTES") + 1,
            # The selector, the exit byte and one byte beyond the output limit.
            "helper_reports": 2 + rust_const("crates/maki-privileged/src/command.rs",
                                             "max_output_bytes") + 1,
        }
        self.assertEqual(sorted(bounds), sorted(module.MAX_LEN))
        for target, bound in bounds.items():
            with self.subTest(target=target):
                self.assertGreaterEqual(module.max_len(target), bound)
        for target in set(targets()) - set(bounds):
            with self.subTest(target=target):
                self.assertEqual(module.max_len(target), 4096)

    def test_seeds_reach_both_sides_of_etcds_size_limits(self):
        # A run starts from its seeds and keeps a longer input only if it
        # reaches new code: without seeds this long it does not get there.
        answer = rust_const("crates/maki-witness/src/etcd.rs", "MAX_JSON_BYTES")
        state = rust_const("crates/maki-witness/src/etcd.rs", "MAX_STATE_BYTES")
        directory = SEEDS / "witness_etcd"
        sizes = {path.name: path.stat().st_size for path in directory.iterdir()}
        self.assertEqual(sizes.get("valid-range-answer-at-the-limit"), 1 + answer)
        self.assertEqual(sizes.get("refused-range-answer-beyond-the-limit"), 1 + answer + 1)
        # The value's base64 holds as many bytes as a state may, one more,
        # and three more, whose base64 is longer than a state's can be.
        for name, length in (("refused-range-state-at-the-limit", state),
                             ("refused-range-state-beyond-the-limit", state + 1),
                             ("refused-range-value-beyond-the-limit", state + 3)):
            with self.subTest(seed=name):
                body = json.loads((directory / name).read_bytes()[1:])
                value = body["kvs"][0]["value"]
                self.assertEqual(len(base64.b64decode(value, validate=True)), length)
                self.assertEqual(len(value) > (state + 2) // 3 * 4, length == state + 3)

    def test_the_length_is_printed_for_the_fuzz_job(self):
        for target, expected in (("witness_etcd", "270000"), ("journal_scan", "4096")):
            result = subprocess.run([sys.executable, "-B", str(SCRIPT), "max-len", target],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual((result.returncode, result.stdout), (0, expected + "\n"), result.stderr)


@unittest.skipUnless(sys.platform == "linux", "a shard runs on a Linux runner")
class Run(Fixture):
    def run_shard(self, workers=3, cpu_seconds=0.001, wall_seconds=30, **limits):
        out = self.root / "shard"
        self.temp = self.root / "memory"
        self.temp.mkdir(exist_ok=True)
        record = self.campaign.run(self.binary, "witness_etcd", 2, cpu_seconds, wall_seconds,
                                   workers, self.seeds, out, temp=self.temp, **limits)
        self.assertEqual(json.loads((out / "shard.json").read_text()), record)
        return out, record

    def test_each_process_fuzzes_the_shared_corpus_from_the_seeds_within_the_limits(self):
        os.environ["ASAN_OPTIONS"] = "allocator_may_return_null=1"
        out, record = self.run_shard()
        calls = self.calls_made()
        self.assertEqual(len(calls), 3)
        for call in calls:
            # One round: the process was charged its share in it.
            self.assertEqual(call["arguments"], [
                "-max_total_time=1", "-max_len=270000", "-timeout=25", "-rss_limit_mb=2048",
                "-print_final_stats=1", f"-artifact_prefix={out / 'artifacts'}/",
                str(out / "corpus"), str(self.seeds)])
            # As `cargo fuzz run` sets it, after what the environment had.
            self.assertEqual(call["asan"], "allocator_may_return_null=1:detect_odr_violation=0")
            # A temporary directory of the shard's own, removed afterwards.
            self.assertEqual(call["temp"], record["temporary_directory"])
            self.assertEqual(Path(call["temp"]).parent, self.temp)
        self.assertEqual(list(self.temp.iterdir()), [])
        self.assertEqual(record["left_in_temporary_directory"], [])
        self.assertEqual(record["failures"], [])
        self.assertEqual((record["target"], record["shard"], record["cpu_seconds"],
                          record["wall_seconds"], record["max_len"]),
                         ("witness_etcd", 2, 0.001, 30, 270000))
        self.assertEqual(record["seeds"], {"inputs": 2, "bytes": 12})
        self.assertEqual(record["corpus"]["inputs"], 3)
        self.assertEqual(len(record["binary_sha256"]), 64)
        self.assertEqual(sorted(worker["worker"] for worker in record["workers"]), [1, 2, 3])
        for worker in record["workers"]:
            with self.subTest(worker=worker["worker"]):
                self.assertEqual((worker["exit"], worker["signal"], worker["stopped"]), (0, None, False))
                self.assertEqual(worker["rounds_run"], 1)
                self.assertGreaterEqual(worker["cpu_seconds"], 0.001)
                self.assertAlmostEqual(worker["cpu_seconds"],
                                       worker["user_seconds"] + worker["system_seconds"], places=2)
                self.assertGreater(worker["wall_seconds"], 0)
                self.assertGreaterEqual(worker["executions"], 1000)
                self.assertEqual((worker["cov"], worker["ft"]), (12, 15))
                round_, = worker["rounds"]
                self.assertEqual((round_["last_status"], round_["exec_per_second"],
                                  round_["peak_rss_mb"]), ("DONE", round_["executions"] // 2, 41))
                self.assertIsNone(worker["error"])
                self.assertTrue((out / round_["log"]).is_file())
        self.assertEqual(len({worker["seeds"][0] for worker in record["workers"]}), 3)
        self.assertEqual(self.campaign.main(["run", "--binary", str(self.binary), "--target",
                                             "journal_scan", "--shard", "1", "--cpu-seconds", "0.001",
                                             "--wall-seconds", "5", "--workers", "1", "--seeds", str(self.seeds),
                                             "--out", str(self.root / "again")]), 0)

    def test_an_input_a_process_stops_on_fails_the_shard_and_the_others_go_on(self):
        os.environ["FAKE_MODES"] = json.dumps(["ok", "crash", "ok"])
        out, record = self.run_shard()
        self.assertEqual(record["artifacts"],
                         [{"name": "crash-0123456789abcdef", "kind": "crash", "bytes": 4}])
        crashed = [worker for worker in record["workers"] if worker["exit"] == 77]
        self.assertEqual(len(crashed), 1)
        # A process that stopped on an input runs no further round.
        self.assertEqual(crashed[0]["rounds_run"], 1)
        self.assertEqual(crashed[0]["error"], "==4242== ERROR: libFuzzer: deadly signal")
        self.assertEqual(sorted(worker["exit"] for worker in record["workers"]), [0, 0, 77])
        self.assertEqual(record["failures"], [
            f"process {crashed[0]['worker']} ended with status 77: "
            "==4242== ERROR: libFuzzer: deadly signal",
            "crash input crash-0123456789abcdef"])
        os.environ["FAKE_MODES"] = json.dumps(["crash"])
        self.calls.unlink()
        self.assertEqual(self.campaign.main(["run", "--binary", str(self.binary), "--target",
                                             "journal_scan", "--shard", "1", "--cpu-seconds", "0.001",
                                             "--wall-seconds", "5", "--workers", "1", "--seeds", str(self.seeds),
                                             "--out", str(self.root / "again")]), 1)

    def test_what_the_processes_leave_in_their_temporary_directory_is_listed(self):
        os.environ["FAKE_MODES"] = json.dumps(["ok", "litter"])
        out, record = self.run_shard(workers=2)
        self.assertEqual(record["left_in_temporary_directory"], ["left-by-1"])
        self.assertEqual(list(self.temp.iterdir()), [])

    def test_the_temporary_directory_is_on_the_memory_filesystem_where_there_is_one(self):
        root = self.campaign.temporary_root()
        if Path("/dev/shm").is_dir() and os.access("/dev/shm", os.W_OK | os.X_OK):
            self.assertEqual(root, Path("/dev/shm"))
        else:
            self.assertEqual(root, Path(tempfile.gettempdir()))

    def test_a_slow_unit_is_reported_and_is_no_failure(self):
        out = self.root / "shard"
        (out / "artifacts").mkdir(parents=True)
        (out / "artifacts" / "slow-unit-0123").write_bytes(b"slow")
        record = self.campaign.run(self.binary, "journal_scan", 1, 0.001, 5, 1, self.seeds, out,
                                   temp=self.root)
        self.assertEqual(record["artifacts"], [{"name": "slow-unit-0123", "kind": "slow-unit",
                                                "bytes": 4}])
        self.assertEqual(record["failures"], [])

    def test_a_process_that_outlives_its_time_is_interrupted_then_killed(self):
        os.environ["FAKE_MODES"] = json.dumps(["ok", "hang", "stubborn"])
        out, record = self.run_shard(wall_seconds=10, grace=0, kill_after=0.2, poll=0.05)
        workers = sorted(record["workers"], key=lambda worker: worker["seeds"][0])
        ok, hang, stubborn = workers
        self.assertEqual((ok["exit"], ok["stopped"]), (0, False))
        # Interrupted, libFuzzer prints its statistics and exits with 72.
        self.assertEqual((hang["exit"], hang["signal"], hang["stopped"]), (72, None, True))
        self.assertEqual(hang["executions"], 7)
        self.assertEqual((stubborn["exit"], stubborn["signal"], stubborn["stopped"]),
                         (None, signal.SIGKILL, True))
        # Neither starts another round.
        self.assertEqual([worker["rounds_run"] for worker in workers], [1, 1, 1])
        self.assertEqual(sorted(record["failures"]), sorted([
            f"process {hang['worker']} was stopped at its deadline",
            f"process {stubborn['worker']} was stopped at its deadline"]))

    def test_a_step_that_is_interrupted_stops_its_processes_and_keeps_the_record(self):
        # GitHub interrupts a step at its time limit or when the run is
        # cancelled: the processes are interrupted and the record written.
        os.environ["FAKE_MODES"] = json.dumps(["hang", "hang"])
        out = self.root / "shard"
        runner = subprocess.Popen([sys.executable, "-B", str(SCRIPT), "run", "--binary", str(self.binary),
                                   "--target", "journal_scan", "--shard", "1", "--cpu-seconds", "3600",
                                   "--wall-seconds", "3600", "--workers", "2", "--seeds", str(self.seeds), "--out", str(out),
                                   "--temp", str(self.root)],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                  start_new_session=True)
        try:
            # Both processes started and wait for their interrupt.
            for _ in range(400):
                if runner.poll() is not None or len(self.calls_made()) == 2 and all(
                        "INITED" in (out / "logs" / f"worker-{worker}-round-1.log").read_text()
                        for worker in (1, 2)):
                    break
                time.sleep(0.05)
            runner.send_signal(signal.SIGTERM)
            stdout, stderr = runner.communicate(timeout=30)
        finally:
            # The runner and, should it have left them, its processes.
            try:
                os.killpg(runner.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            runner.wait()
        self.assertEqual(runner.returncode, 1, stdout + stderr)
        record = json.loads((out / "shard.json").read_text())
        self.assertEqual([(worker["exit"], worker["stopped"]) for worker in record["workers"]],
                         [(72, True), (72, True)])
        self.assertEqual(len(record["failures"]), 2)

    def test_a_process_fuzzes_in_rounds_until_it_has_been_charged_its_share(self):
        # Each round of this stand-in is charged a quarter of a second.
        os.environ.update(FAKE_MODES=json.dumps(["burn"] * 12), FAKE_BURN="0.25")
        out, record = self.run_shard(workers=2, cpu_seconds=0.6, min_round=1)
        self.assertEqual(record["failures"], [])
        for worker in record["workers"]:
            with self.subTest(worker=worker["worker"]):
                rounds = worker["rounds"]
                self.assertGreaterEqual(len(rounds), 2)
                self.assertGreaterEqual(worker["cpu_seconds"], 0.6)
                # Each round after the first was needed, and lasts at least
                # the minimum round.
                self.assertLess(sum(entry["cpu_seconds"] for entry in rounds[:-1]), 0.6)
                self.assertTrue(all(entry["seconds"] >= 1 for entry in rounds))
                self.assertEqual(worker["executions"],
                                 sum(entry["executions"] for entry in rounds))
                self.assertEqual(worker["wall_seconds"],
                                 round(sum(entry["wall_seconds"] for entry in rounds), 3))
        self.assertEqual(len(self.calls_made()), sum(worker["rounds_run"] for worker in record["workers"]))

    def test_a_process_short_of_its_share_when_its_wall_time_is_spent_fails_the_shard(self):
        # Waits two thirds of a second for each fifth of a second charged.
        os.environ.update(FAKE_MODES=json.dumps(["burn"] * 12), FAKE_BURN="0.2", FAKE_SLEEP="0.7")
        out, record = self.run_shard(workers=1, cpu_seconds=10, wall_seconds=2, min_round=1)
        worker, = record["workers"]
        self.assertLess(worker["cpu_seconds"], 10)
        self.assertLessEqual(worker["rounds_run"], 3)
        self.assertEqual(record["failures"], [
            f"process 1 was charged {worker['cpu_seconds']:.0f} of its 10 CPU seconds in 2 s"])

    def test_a_shard_without_seeds_is_refused(self):
        empty = self.root / "empty"
        empty.mkdir()
        with self.assertRaises(SystemExit):
            self.campaign.run(self.binary, "journal_scan", 1, 1, 5, 1, empty, self.root / "shard")
        self.assertEqual(self.calls_made(), [])

    def test_the_final_statistics_of_a_real_run_are_read(self):
        # libFuzzer's output of `helper_sysfs` (libfuzzer-sys 0.4.13, cargo-fuzz 0.13.2).
        found = self.campaign.parse_log(REAL_LOG)
        self.assertEqual({key: found[key] for key in (
            "seed", "last_status", "runs", "cov", "ft", "corpus_inputs", "inited_cov",
            "executions", "exec_per_second", "new_units", "slowest_unit_seconds",
            "peak_rss_mb", "error")}, REAL_LOG_FOUND)


# Lines of what one `helper_sysfs` process printed in a 30-second run of
# `fuzz_campaign.py run` (cargo-fuzz 0.13.2, libfuzzer-sys 0.4.13,
# nightly-2026-11-24), in their order; the paths shortened.
REAL_LOG = (
    'INFO: Running with entropic power schedule (0xFF, 100).\n'
    'INFO: Seed: 4076967116\n'
    'INFO: Loaded 1 modules   (21244 inline 8-bit counters): 21244 [0x5616ace9ce90, 0x5616acea218c), \n'
    'INFO: Loaded 1 PC tables (21244 PCs): 21244 [0x5616acea2190,0x5616acef5150), \n'
    'INFO:        0 files found in shard/corpus\n'
    'INFO:       49 files found in fuzz/seeds/helper_sysfs\n'
    'INFO: seed corpus: files: 49 min: 43b max: 795b total: 22149b rss: 34Mb\n'
    '#51\tINITED cov: 2866 ft: 5239 corp: 48/20Kb exec/s: 0 rss: 52Mb\n'
    '#53\tNEW    cov: 2867 ft: 5261 corp: 49/20Kb lim: 795 exec/s: 0 rss: 53Mb L: 22/795 MS: 2 ChangeASCIIInt-EraseBytes-\n'
    '#143\tREDUCE cov: 2944 ft: 5421 corp: 83/34Kb lim: 795 exec/s: 0 rss: 68Mb L: 378/795 MS: 1 EraseBytes-\n'
    '#111501\tDONE   cov: 3504 ft: 7681 corp: 860/248Kb lim: 795 exec/s: 3596 rss: 184Mb\n'
    '###### Recommended dictionary. ######\n'
    '"\\377\\377\\377\\377\\377\\377\\377\\377" # Uses: 76\n'
    '"evice" # Uses: 0\n'
    '"\\001\\000\\000\\000\\000\\000\\000\\012" # Uses: 0\n'
    '###### End of recommended dictionary. ######\n'
    'Done 111501 runs in 31 second(s)\n'
    'stat::number_of_executed_units: 111501\n'
    'stat::average_exec_per_sec:     3596\n'
    'stat::new_units_added:          2542\n'
    'stat::slowest_unit_time_sec:    0\n'
    'stat::peak_rss_mb:              184\n'
)
REAL_LOG_FOUND = {
    "seed": 4076967116, "last_status": "DONE", "runs": 111501, "cov": 3504, "ft": 7681,
    "corpus_inputs": 860, "inited_cov": 2866, "executions": 111501, "exec_per_second": 3596,
    "new_units": 2542, "slowest_unit_seconds": 0, "peak_rss_mb": 184, "error": None,
}


@unittest.skipUnless(sys.platform == "linux", "a merge runs on a Linux runner")
class Merge(Fixture):
    def shard(self, name, *inputs):
        corpus = self.root / "shards" / name / "corpus"
        corpus.mkdir(parents=True)
        for index, data in enumerate(inputs):
            (corpus / f"input-{index}").write_bytes(data)

    def test_the_seeds_and_every_shard_corpus_are_merged_and_measured(self):
        self.shard("fuzz-shard-witness_etcd-1", b"one", b"two")
        self.shard("fuzz-shard-witness_etcd-2", b"two", b"three")
        out = self.root / "merged"
        record = self.campaign.merge(self.binary, "witness_etcd", self.seeds, self.root / "shards", out,
                                     temp=self.root)
        self.assertEqual(json.loads((out / "coverage.json").read_text()), record)
        merge, measure = self.calls_made()
        limits = ["-max_len=270000", "-timeout=25", "-rss_limit_mb=2048"]
        self.assertEqual(merge["arguments"], [
            "-merge=1", *limits, f"-artifact_prefix={out / 'artifacts'}/", str(out / "corpus"),
            str(self.seeds), str(self.root / "shards/fuzz-shard-witness_etcd-1/corpus"),
            str(self.root / "shards/fuzz-shard-witness_etcd-2/corpus")])
        self.assertEqual(measure["arguments"], ["-runs=0", *limits, str(out / "corpus")])
        # Both in a temporary directory of the merge's own, removed afterwards.
        self.assertEqual(merge["temp"], measure["temp"])
        self.assertEqual(Path(merge["temp"]).parent, self.root)
        self.assertFalse(Path(merge["temp"]).exists())
        self.assertEqual(record["sources"], [{"shard": "fuzz-shard-witness_etcd-1", "inputs": 2},
                                             {"shard": "fuzz-shard-witness_etcd-2", "inputs": 2}])
        # Two seeds and three distinct shard inputs.
        self.assertEqual((record["inputs"], record["cov"], record["ft"], record["seeds"]),
                         (5, 50, 100, 2))
        self.assertEqual(record["failures"], [])

    def test_a_failed_merge_or_a_coverage_run_without_its_line_fails(self):
        self.shard("fuzz-shard-witness_etcd-1", b"one")
        os.environ["FAKE_MERGE_EXIT"] = "1"
        record = self.campaign.merge(self.binary, "witness_etcd", self.seeds, self.root / "shards",
                                     self.root / "merged")
        self.assertEqual(record["failures"], ["the merge ended with status 1"])
        os.environ["FAKE_MERGE_EXIT"] = "0"
        os.environ["FAKE_NO_INITED"] = "1"
        record = self.campaign.merge(self.binary, "witness_etcd", self.seeds, self.root / "shards",
                                     self.root / "again")
        self.assertEqual(record["failures"], ["the coverage run printed no INITED line"])
        self.assertEqual(self.campaign.main(["merge", "--binary", str(self.binary), "--target",
                                             "witness_etcd", "--seeds", str(self.seeds),
                                             "--shards", str(self.root / "shards"),
                                             "--out", str(self.root / "third")]), 1)


class Summary(unittest.TestCase):
    DIGEST = "ab" * 32

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="maki-fuzz-summary-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.plan = campaign().plan("format_decoders witness_etcd", "1", "5", "4")
        self.environment = {"GITHUB_SHA": "f" * 40, "GITHUB_REF": "refs/heads/main",
                            "GITHUB_SERVER_URL": "https://github.com",
                            "GITHUB_REPOSITORY": "owner/repository", "GITHUB_RUN_ID": "42"}
        build = self.root / "build"
        build.mkdir()
        (build / "SHA256SUMS").write_text(f"{self.DIGEST}  format_decoders\n{self.DIGEST}  witness_etcd\n")
        (build / "versions.txt").write_text("rustc 1.102.0-nightly\ncargo-fuzz 0.13.2\n")
        for target in self.plan["targets"]:
            self.shard(target, 1)
            self.coverage(target)

    def shard(self, target, shard, cpu=None, **changes):
        cpu = self.plan["cpu_seconds"] * 1.0 if cpu is None else cpu
        record = {"target": target, "shard": shard, "binary_sha256": self.DIGEST,
                  "cpu_seconds": self.plan["cpu_seconds"], "wall_seconds": self.plan["wall_seconds"],
                  "artifacts": [], "host": {"vcpus": 4},
                  "workers": [{"worker": worker, "exit": 0, "signal": None, "stopped": False,
                               "cpu_seconds": cpu, "wall_seconds": cpu + 1, "executions": 1000,
                               "error": None} for worker in range(1, 5)]}
        record.update(changes)
        directory = self.root / "stats" / f"fuzz-stats-{target}-{shard}"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "shard.json").write_text(json.dumps(record))

    def coverage(self, target, **changes):
        record = {"target": target, "binary_sha256": self.DIGEST, "merge_exit": 0,
                  "coverage_exit": 0, "cov": 300, "ft": 900, "inputs": 40, "bytes": 5000,
                  "seeds": 30, "error": None}
        record.update(changes)
        directory = self.root / "coverage" / f"fuzz-coverage-{target}"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "coverage.json").write_text(json.dumps(record))

    def summarize(self):
        return campaign().summarize(self.plan, self.root / "stats", self.root / "coverage",
                                    self.root / "build", self.environment)

    def verdicts(self):
        return {row["target"]: row["reasons"] for row in self.summarize()["targets"]}

    def test_a_campaign_whose_processes_were_charged_their_shares_qualifies(self):
        summary = self.summarize()
        self.assertTrue(summary["qualified"], summary)
        self.assertEqual(summary["run"], "https://github.com/owner/repository/actions/runs/42")
        self.assertEqual((summary["revision"], summary["requested_cpu_hours"]), ("f" * 40, 1))
        row = summary["targets"][1]
        self.assertEqual((row["target"], row["max_len"], row["shards"], row["processes"]),
                         ("witness_etcd", 270000, 1, 4))
        self.assertEqual(row["cpu_seconds"], 4 * self.plan["cpu_seconds"])
        self.assertEqual(row["process_seconds"], 4 * (self.plan["cpu_seconds"] + 1))
        self.assertEqual((row["executions"], row["cov"], row["ft"], row["corpus_inputs"]),
                         (4000, 300, 900, 40))
        text = campaign().markdown(summary)
        self.assertIn("| `witness_etcd` | 270,000 | 1.00 | 1.00 | 4,000 | 300 | 900 "
                      "| 40 inputs, 5,000 bytes | none | qualified |", text)
        self.assertIn("rustc 1.102.0-nightly", text)
        self.assertIn("Runner: 4 vCPUs (None), kernel None, image None.", text)
        self.assertIn("run https://github.com/owner/repository/actions/runs/42.", text)
        self.assertTrue(text.rstrip().endswith("Qualified: every target"))

    def test_measured_cpu_time_short_of_the_request_does_not_qualify(self):
        # The processes ran (wall time) but were charged less CPU time.
        self.shard("witness_etcd", 1, cpu=self.plan["cpu_seconds"] * 0.8)
        self.assertEqual(self.verdicts()["witness_etcd"], [
            f"shard 1: process {worker} was charged 720 of its 900 CPU seconds in 18000 s"
            for worker in range(1, 5)] + ["0.80 of 1 CPU-hours"])
        self.assertEqual(self.verdicts()["format_decoders"], [])
        self.assertFalse(self.summarize()["qualified"])

    def test_a_missing_shard_or_merge_does_not_qualify(self):
        self.plan = campaign().plan("format_decoders witness_etcd", "8", "1", "4")
        self.assertEqual(self.plan["shards"], 3)
        for shard in (1, 2):
            self.shard("witness_etcd", shard)
        (self.root / "coverage" / "fuzz-coverage-format_decoders" / "coverage.json").unlink()
        verdicts = self.verdicts()
        self.assertEqual(verdicts["witness_etcd"][0], "no record of shard 3")
        self.assertIn("no record of shard 2, 3", verdicts["format_decoders"])
        self.assertIn("no merged corpus", verdicts["format_decoders"])

    def test_a_crash_a_failed_process_or_a_failed_merge_does_not_qualify(self):
        self.shard("witness_etcd", 1, artifacts=[{"name": "crash-00", "kind": "crash", "bytes": 3},
                                                 {"name": "slow-unit-01", "kind": "slow-unit",
                                                  "bytes": 3}])
        self.coverage("format_decoders", merge_exit=1)
        verdicts = self.verdicts()
        self.assertEqual(verdicts["witness_etcd"], ["shard 1: crash input crash-00"])
        self.assertEqual(verdicts["format_decoders"], ["the merge ended with status 1"])
        text = campaign().markdown(self.summarize())
        self.assertIn("`crash-00` (shard 1)", text)
        self.assertNotIn("slow-unit-01", text.split("| Target |")[1].split("\n")[2])

    def test_a_binary_the_build_did_not_make_does_not_qualify(self):
        self.shard("witness_etcd", 1, binary_sha256="cd" * 32)
        self.assertIn("the shards and the merge fuzzed different binaries",
                      self.verdicts()["witness_etcd"])
        self.coverage("witness_etcd", binary_sha256="cd" * 32)
        self.assertEqual(self.verdicts()["witness_etcd"], ["a binary that is not the build job's"])

    def test_an_unreadable_record_or_no_build_record_does_not_qualify(self):
        (self.root / "stats" / "fuzz-stats-witness_etcd-1" / "shard.json").write_text("{")
        summary = self.summarize()
        self.assertFalse(summary["qualified"])
        self.assertEqual(len(summary["unreadable"]), 1)
        self.shard("witness_etcd", 1)
        for entry in (self.root / "build").iterdir():
            entry.unlink()
        summary = self.summarize()
        self.assertFalse(summary["qualified"])
        self.assertEqual(summary["unreadable"], ["the build job's record (SHA256SUMS) is missing"])

    def test_the_summary_is_written_and_its_status_is_the_verdict(self):
        out = self.root / "summary"
        arguments = ["summary", "--plan", json.dumps(self.plan), "--stats", str(self.root / "stats"),
                     "--coverage", str(self.root / "coverage"), "--build", str(self.root / "build"),
                     "--out", str(out)]
        module = campaign()
        with unittest.mock.patch.dict(os.environ, self.environment):
            self.assertEqual(module.main(arguments), 0)
            self.assertTrue(json.loads((out / "summary.json").read_text())["qualified"])
            self.assertIn("Qualified: every target", (out / "summary.md").read_text())
            self.shard("witness_etcd", 1, cpu=1)
            self.assertEqual(module.main(arguments), 1)
            self.assertFalse(json.loads((out / "summary.json").read_text())["qualified"])


if __name__ == "__main__":
    unittest.main()
