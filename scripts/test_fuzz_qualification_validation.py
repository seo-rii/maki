"""The parser fuzz qualification campaign (scripts/fuzz_campaign.py, run by
.github/workflows/fuzz-qualification.yml): how it splits a target's
CPU-hours, the -max_len each target needs, what one shard records of its
libFuzzer processes, the merge of a target's corpora, and the verdict of the
summary."""

import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
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
import subprocess
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
                            "temp": os.environ.get("TMPDIR"), "pid": os.getpid()}) + "\n")
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


if flags.get("merge") == "1" and os.environ.get("FAKE_MERGE_HANG") == "1":
    # libFuzzer's merge runs an inner process of its own; this one ignores
    # the interrupt, so only a kill of the merge's group ends it.
    inner = subprocess.Popen(["sh", "-c", "trap '' INT; exec sleep 300"])
    Path(os.environ["FAKE_CALLS"] + ".inner").write_text(str(inner.pid))
    while True:
        time.sleep(0.05)
if flags.get("merge") == "1":
    # As libFuzzer's -merge=1 does (clang 18's, run on a target that aborts
    # on one input): an outer process runs an inner one over the inputs. An
    # input that fails the inner one (FAKE_MERGE_FAILS) is written to
    # -artifact_prefix as the FAKE_MERGE_ARTIFACT kind of input (none if it
    # is empty), the outer process starts the inner one again, which leaves
    # that input out, and exits 0. An input FAKE_MERGE_SLOW names is
    # written as a slow unit and kept.
    output, inputs = directories[0], directories[1:]
    entries = [entry for directory in inputs for entry in sorted(Path(directory).iterdir())]
    failing = os.environ.get("FAKE_MERGE_FAILS", "").encode()
    slow = os.environ.get("FAKE_MERGE_SLOW", "").encode()
    say(f"MERGE-OUTER: {len(entries)} files, 0 in the initial corpus, 0 processed earlier")
    attempt = 1
    say(f"MERGE-OUTER: attempt {attempt}")
    seen = set()
    for entry in entries:
        data = entry.read_bytes()
        if failing and data == failing:
            kind = os.environ.get("FAKE_MERGE_ARTIFACT", "crash")
            if kind:
                path = flags["artifact_prefix"] + f"{kind}-{hashlib.sha1(data).hexdigest()}"
                Path(path).write_bytes(data)
                say(f"Test unit written to {path}")
            say("==4243== ERROR: libFuzzer: deadly signal")
            attempt += 1
            say(f"MERGE-OUTER: attempt {attempt}")
            say(f"MERGE-INNER: '{entry}' caused a failure at the previous merge step")
            continue
        if slow and data == slow:
            Path(flags["artifact_prefix"] + f"slow-unit-{hashlib.sha1(data).hexdigest()}"
                 ).write_bytes(data)
        if data not in seen:
            seen.add(data)
            keep(output, data)
    say(f"MERGE-OUTER: successful in {attempt} attempt(s)")
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
    sys.exit(int(os.environ.get("FAKE_COVERAGE_EXIT", "0")))

say(f"INFO: Seed: {1000 + index}")
say(f"#2\tINITED cov: 10 ft: 12 corp: 1/1b exec/s: 0 rss: 30Mb")
if mode == "crash":
    say(f"==4242== ERROR: libFuzzer: deadly signal")
    Path(flags["artifact_prefix"] + "crash-0123456789abcdef").write_bytes(b"boom")
    final(50)
    sys.exit(77)
if mode == "fail":
    # An exit with a nonzero status and no input written.
    final(5)
    sys.exit(1)
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
    # Charged FAKE_BURN seconds of CPU time, then idle to the end of the
    # round's time, as libFuzzer runs to -max_total_time.
    began = time.monotonic()
    while time.process_time() < float(os.environ["FAKE_BURN"]):
        pass
    time.sleep(max(0.0, int(flags["max_total_time"]) - (time.monotonic() - began)))
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
            # LVM's report after the selector, and the output of the
            # filesystem probe and of `dmsetup info` after the selector and
            # the exit byte, each one byte beyond its limit.
            "helper_reports": max(
                1 + rust_const("crates/maki-privileged/src/lvm_preflight.rs", "MAX_REPORT") + 1,
                2 + rust_const("crates/maki-privileged/src/command.rs", "max_output_bytes") + 1),
        }
        # Those are the limits the readers the target calls check on its
        # input, not the drain of a command's output, which it does not run.
        sources = {path: (ROOT / "crates/maki-privileged/src" / path).read_text()
                   for path in ("lvm_preflight.rs", "exec.rs", "recover.rs", "exec_fuzzing.rs")}
        self.assertIn("if bytes.len() > MAX_REPORT ||", sources["lvm_preflight.rs"])
        for path in ("exec.rs", "recover.rs"):
            self.assertIn("output.stdout.len() > command::Policy::PROBE.max_output_bytes",
                          sources[path], path)
        for reader in ("lvm_preflight::validate(", "verify_filesystem_probe(expected, &output)",
                       "recover::fuzzing::removal_info("):
            self.assertIn(reader, sources["exec_fuzzing.rs"])
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

    def test_a_runner_that_is_signalled_stops_its_processes_and_keeps_the_record(self):
        # A signal to the runner's own process (the workflow's step execs
        # it, so GitHub's interrupt reaches it: StepCancellation below).
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
        self.assertTrue(record["interrupted"])
        self.assertEqual(record["failures"], ["the step was interrupted",
                                              "process 1 was interrupted with the step",
                                              "process 2 was interrupted with the step"])

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
        # Charged a fifth of a second in each round of a second.
        os.environ.update(FAKE_MODES=json.dumps(["burn"] * 12), FAKE_BURN="0.2")
        out, record = self.run_shard(workers=1, cpu_seconds=10, wall_seconds=2, min_round=1)
        worker, = record["workers"]
        self.assertLess(worker["cpu_seconds"], 10)
        self.assertLessEqual(worker["rounds_run"], 3)
        self.assertEqual(record["failures"], [
            f"process 1 was charged {worker['cpu_seconds']:.0f} of its 10 CPU seconds in 2 s"])

    def test_a_round_that_fails_is_the_processes_last_though_it_lacks_cpu_time(self):
        # A round that exits nonzero, here at once without writing an input,
        # is not followed by rounds that would charge the process its share.
        os.environ.update(FAKE_MODES=json.dumps(["fail"] + ["burn"] * 12), FAKE_BURN="0.25")
        out, record = self.run_shard(workers=1, cpu_seconds=0.6, wall_seconds=30, min_round=1)
        worker, = record["workers"]
        self.assertEqual((worker["rounds_run"], worker["exit"]), (1, 1))
        self.assertEqual(len(self.calls_made()), 1)
        self.assertEqual(record["failures"], ["process 1 ended with status 1"])

    def test_rounds_that_end_long_before_their_time_are_not_restarted_without_end(self):
        # libFuzzer runs to -max_total_time; a process that exits 0 at once
        # (here the stand-in) is not restarted until the wall time is spent.
        os.environ["FAKE_MODES"] = json.dumps(["ok"] * 50)
        out, record = self.run_shard(workers=1, cpu_seconds=10, wall_seconds=30, min_round=1)
        worker, = record["workers"]
        self.assertEqual(worker["rounds_run"], 3)
        self.assertEqual(len(list((out / "logs").iterdir())), 3)
        self.assertEqual(record["failures"], [
            "process 1 ended 3 rounds in a row before half of their time"])

    def test_a_round_that_ends_early_is_no_failure_once_a_later_one_makes_up_the_time(self):
        # docs/testing.md: a round may end before its time limit; only three
        # such rounds in a row, short of the share, fail the process.
        os.environ.update(FAKE_MODES=json.dumps(["ok"] + ["burn"] * 12), FAKE_BURN="0.6")
        out, record = self.run_shard(workers=1, cpu_seconds=0.5, wall_seconds=30, min_round=1)
        worker, = record["workers"]
        first, *later = worker["rounds"]
        self.assertLess(first["wall_seconds"], first["seconds"] / 2)
        self.assertLess(first["cpu_seconds"], 0.5)
        self.assertTrue(later)
        self.assertEqual((worker["exit"], worker["stopped"], worker["ended_early"]), (0, False, False))
        self.assertGreaterEqual(worker["cpu_seconds"], 0.5)
        self.assertEqual(record["failures"], [])

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
    def shard(self, number, *inputs, extra=()):
        """What the merge job downloads of shard `number`: the directory of
        its artifact, with the archive of the shard's output the fuzz job
        packed (`tar -C "$RUNNER_TEMP" -cf shard.tar shard`), and `extra`
        members after it."""
        packed = self.root / "packed" / str(number) / "shard"
        (packed / "corpus").mkdir(parents=True)
        for index, data in enumerate(inputs):
            (packed / "corpus" / f"input-{index}").write_bytes(data)
        (packed / "shard.json").write_text("{}")
        return self.archive(number, extra, packed)

    def archive(self, number, members, packed=None):
        """A downloaded shard artifact whose archive, in the format GNU tar
        writes, holds `packed` as shard/ and then `members`, (TarInfo, bytes
        or None) pairs."""
        directory = self.root / "shards" / f"fuzz-shard-witness_etcd-{number}"
        directory.mkdir(parents=True)
        with tarfile.open(directory / "shard.tar", "w", format=tarfile.GNU_FORMAT) as archive:
            if packed is not None:
                archive.add(packed, arcname="shard")
            for member, data in members:
                if data is not None:
                    member.size = len(data)
                archive.addfile(member, None if data is None else io.BytesIO(data))
        return directory

    def unpacked(self, number):
        return self.root / "shards" / f"fuzz-shard-witness_etcd-{number}" / "shard" / "corpus"

    def merge(self, out, planned=1):
        return self.campaign.merge(self.binary, "witness_etcd", self.seeds, self.root / "shards",
                                   self.root / out, planned, temp=self.root)

    def main(self, out, planned=1):
        return self.campaign.main(["merge", "--binary", str(self.binary), "--target", "witness_etcd",
                                   "--seeds", str(self.seeds), "--shards", str(self.root / "shards"),
                                   "--planned-shards", str(planned), "--out", str(self.root / out)])

    def test_the_seeds_and_every_shard_corpus_are_merged_and_measured(self):
        self.shard(1, b"one", b"two")
        self.shard(2, b"two", b"three")
        out = self.root / "merged"
        record = self.merge("merged", planned=2)
        self.assertEqual(json.loads((out / "coverage.json").read_text()), record)
        merge, measure = self.calls_made()
        limits = ["-max_len=270000", "-timeout=25", "-rss_limit_mb=2048"]
        # Each shard's corpus, unpacked from its archive in the directory
        # its artifact was downloaded to.
        self.assertEqual(merge["arguments"], [
            "-merge=1", *limits, f"-artifact_prefix={out / 'artifacts'}/", str(out / "corpus"),
            str(self.seeds), str(self.unpacked(1)), str(self.unpacked(2))])
        self.assertEqual(measure["arguments"], ["-runs=0", *limits, str(out / "corpus")])
        # Both in a temporary directory of the merge's own, removed afterwards.
        self.assertEqual(merge["temp"], measure["temp"])
        self.assertEqual(Path(merge["temp"]).parent, self.root)
        self.assertFalse(Path(merge["temp"]).exists())
        self.assertEqual(record["planned_shards"], 2)
        self.assertEqual(record["sources"], [
            {"shard": 1, "artifact": "fuzz-shard-witness_etcd-1", "inputs": 2},
            {"shard": 2, "artifact": "fuzz-shard-witness_etcd-2", "inputs": 2}])
        self.assertEqual(record["unmerged"], [])
        # Two seeds and three distinct shard inputs.
        self.assertEqual((record["inputs"], record["cov"], record["ft"], record["seeds"]),
                         (5, 50, 100, 2))
        # One attempt of the inner process, which wrote no input.
        self.assertEqual((record["attempts"], record["artifacts"]), (1, []))
        self.assertEqual(record["failures"], [])
        # Nothing of the shards' corpora is in the merge's own output, which
        # the merge job uploads.
        self.assertEqual(sorted(path.name for path in out.iterdir()),
                         ["artifacts", "corpus", "coverage.json", "coverage.log", "merge.log"])
        self.assertEqual(self.main("again", planned=2), 0)

    def test_a_planned_shard_whose_corpus_did_not_arrive_fails_the_merge(self):
        # The second wave of run 45983119347: the upload of each shard of
        # four targets failed, the download by pattern found no artifact,
        # and the merge of the seeds alone exited 0, as did its coverage run.
        record = self.merge("seeds-only", planned=2)
        self.assertEqual((record["merge_exit"], record["coverage_exit"], record["attempts"]), (0, 0, 1))
        self.assertEqual((record["inputs"], record["sources"]), (2, []))
        self.assertEqual(record["failures"], [
            "the merge had no corpus of shard 1 (no fuzz-shard-witness_etcd-1/shard.tar)",
            "the merge had no corpus of shard 2 (no fuzz-shard-witness_etcd-2/shard.tar)"])
        self.assertEqual(self.main("seeds-only-again", planned=2), 1)
        # Each way a planned shard's corpus can fail to arrive; the others
        # are merged all the same.
        self.shard(1, b"one")
        # Shard 2's artifact holds no archive. Shard 3's archive is cut in
        # its second member's header and shard 4's after its first input,
        # which tarfile reads as the end of a shorter archive, and shard 5's
        # in the data of its last input. Shard 6's holds only the record;
        # shard 7's and 8's hold a link and a path out of the directory they
        # are unpacked into.
        (self.root / "shards" / "fuzz-shard-witness_etcd-2").mkdir()
        for number, cut in ((3, lambda data: 700), (4, lambda data: data.index(b"three") + 512),
                            (5, lambda data: data.index(b"x" * 2000) + 1000)):
            archive = self.shard(number, b"three", b"x" * 2000) / "shard.tar"
            data = archive.read_bytes()
            archive.write_bytes(data[:cut(data)])
        self.archive(6, [(tarfile.TarInfo("shard/shard.json"), b"{}")])
        link = tarfile.TarInfo("shard/corpus/link")
        link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
        self.shard(7, b"seven", extra=[(link, None)])
        self.shard(8, b"eight", extra=[(tarfile.TarInfo("shard/../../escaped"), b"left")])
        record = self.merge("partly", planned=8)
        merge, _ = self.calls_made()[-2:]
        self.assertEqual(merge["arguments"][-2:], [str(self.seeds), str(self.unpacked(1))])
        self.assertEqual(record["sources"], [{"shard": 1, "artifact": "fuzz-shard-witness_etcd-1",
                                              "inputs": 1}])
        self.assertEqual([entry["shard"] for entry in record["unmerged"]], [2, 3, 4, 5, 6, 7, 8])
        failures = record["failures"]
        self.assertEqual(len(failures), 7, failures)
        self.assertEqual(failures[0],
                         "the merge had no corpus of shard 2 (no fuzz-shard-witness_etcd-2/shard.tar)")
        for index, number in ((1, 3), (2, 4)):
            self.assertEqual(failures[index], f"the merge had no corpus of shard {number} "
                                              f"(fuzz-shard-witness_etcd-{number}/shard.tar does not unpack: "
                                              "it ends before its end-of-archive marker)")
        self.assertRegex(failures[3], r"^the merge had no corpus of shard 5 "
                                      r"\(fuzz-shard-witness_etcd-5/shard\.tar does not unpack: .+\)$")
        self.assertEqual(failures[4], "the merge had no corpus of shard 6 "
                                      "(fuzz-shard-witness_etcd-6/shard.tar holds no shard/corpus)")
        self.assertEqual(failures[5], "the merge had no corpus of shard 7 "
                                      "(fuzz-shard-witness_etcd-7/shard.tar holds 'shard/corpus/link', "
                                      "which is not a file or directory below shard/)")
        self.assertEqual(failures[6], "the merge had no corpus of shard 8 "
                                      "(fuzz-shard-witness_etcd-8/shard.tar holds 'shard/../../escaped', "
                                      "which is not a file or directory below shard/)")
        # A refused archive is not unpacked at all, and what a damaged one
        # began to unpack is removed.
        for number in (3, 4, 5, 7, 8):
            self.assertFalse((self.root / "shards" / f"fuzz-shard-witness_etcd-{number}" / "shard").exists())
        self.assertFalse((self.root / "shards" / "escaped").exists())
        self.assertEqual(self.main("partly-again", planned=8), 1)

    def test_what_an_archive_that_fails_while_it_is_unpacked_left_is_removed(self):
        # An archive whose members all pass, that fails only once they are
        # written out: a member below a file an earlier member made.
        self.shard(1, b"one", extra=[(tarfile.TarInfo("shard/corpus/input-0/below"), b"x")])
        record = self.merge("merged")
        self.assertEqual(record["sources"], [])
        self.assertRegex(record["failures"][0], r"^the merge had no corpus of shard 1 "
                                                r"\(fuzz-shard-witness_etcd-1/shard\.tar does not unpack: .+\)$")
        self.assertFalse((self.root / "shards" / "fuzz-shard-witness_etcd-1" / "shard").exists())

    def test_an_earlier_unpacking_is_replaced_not_merged(self):
        self.shard(1, b"one", b"two")
        stale = self.unpacked(1)
        stale.mkdir(parents=True)
        (stale / "stale").write_bytes(b"not in the archive")
        record = self.merge("merged")
        self.assertEqual(sorted(path.name for path in stale.iterdir()), ["input-0", "input-1"])
        self.assertEqual((record["sources"][0]["inputs"], record["inputs"]), (2, 4))

    def test_an_interrupted_merge_unpacks_no_further_archive(self):
        # The runner's interrupt may come while the archives are unpacked:
        # the merge's record must still be written before its SIGTERM.
        self.shard(1, b"one")
        self.shard(2, b"two")
        interrupted = threading.Event()
        interrupted.set()
        sources, unmerged = self.campaign.shard_corpora(self.root / "shards", "witness_etcd", 2,
                                                        interrupted)
        self.assertEqual(sources, [])
        self.assertEqual(unmerged, [
            {"shard": shard, "artifact": f"fuzz-shard-witness_etcd-{shard}",
             "why": "the merge was interrupted before it unpacked it"} for shard in (1, 2)])
        self.assertFalse(self.unpacked(1).exists())

        # Interrupted once it has begun to unpack the first archive: what it
        # unpacked is not merged, and is left where it is, since removing a
        # tree of 400,000 inputs could outlast the runner's kill.
        unpacked = self.root / "shards" / "fuzz-shard-witness_etcd-1" / "shard"

        class Begun:
            def is_set(self):
                return unpacked.exists()

        sources, unmerged = self.campaign.shard_corpora(self.root / "shards", "witness_etcd", 2,
                                                        Begun())
        self.assertEqual(sources, [])
        self.assertEqual([entry["why"] for entry in unmerged],
                         ["the merge was interrupted while it unpacked it",
                          "the merge was interrupted before it unpacked it"])
        self.assertTrue(unpacked.is_dir())

    def test_an_interrupt_is_answered_while_an_archive_is_listed(self):
        # Listing an archive of 405,755 members took 9.8 s here, and the
        # runner kills the step 10 s after its interrupt: the merge stops
        # reading the archive at the interrupt, before it reaches the member
        # at its end that it would refuse.
        class InterruptedAfter:
            def __init__(self, answers):
                self.answers = answers

            def is_set(self):
                self.answers -= 1
                return self.answers < 0

        link = tarfile.TarInfo("shard/corpus/link")
        link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
        self.shard(1, b"one", extra=[(link, None)])
        sources, unmerged = self.campaign.shard_corpora(self.root / "shards", "witness_etcd", 1,
                                                        InterruptedAfter(2))
        self.assertEqual((sources, [entry["why"] for entry in unmerged]),
                         ([], ["the merge was interrupted while it unpacked it"]))

    def test_an_interrupt_while_the_archives_are_unpacked_is_recorded(self):
        # The merge's handlers are in place before it unpacks: the runner's
        # SIGINT then ends the unpacking and the merge, not the script.
        self.shard(1, b"one")
        unpack = self.campaign.shard_corpora

        def interrupted_meanwhile(*arguments):
            signal.raise_signal(signal.SIGINT)
            return unpack(*arguments)

        self.campaign.shard_corpora = interrupted_meanwhile
        try:
            record = self.merge("merged")
        except KeyboardInterrupt:
            self.fail("the interrupt reached the script before the merge's handlers were in place")
        self.assertTrue(record["interrupted"])
        self.assertEqual(record["failures"], ["the merge was interrupted"])
        self.assertEqual(record["unmerged"], [{"shard": 1, "artifact": "fuzz-shard-witness_etcd-1",
                                               "why": "the merge was interrupted before it unpacked it"}])

    def test_a_failed_merge_or_a_coverage_run_without_its_line_fails(self):
        self.shard(1, b"one")
        os.environ["FAKE_MERGE_EXIT"] = "1"
        record = self.campaign.merge(self.binary, "witness_etcd", self.seeds, self.root / "shards",
                                     self.root / "merged", 1)
        self.assertEqual(record["failures"], ["the merge ended with status 1"])
        os.environ["FAKE_MERGE_EXIT"] = "0"
        os.environ["FAKE_NO_INITED"] = "1"
        record = self.campaign.merge(self.binary, "witness_etcd", self.seeds, self.root / "shards",
                                     self.root / "again", 1)
        self.assertEqual(record["failures"], ["the coverage run printed no INITED line"])
        os.environ["FAKE_NO_INITED"] = "0"
        os.environ["FAKE_COVERAGE_EXIT"] = "1"
        record = self.campaign.merge(self.binary, "witness_etcd", self.seeds, self.root / "shards",
                                     self.root / "measured", 1)
        self.assertEqual(record["coverage_exit"], 1)
        self.assertEqual(record["failures"], ["the coverage run ended with status 1"])
        self.assertEqual(self.main("third"), 1)

    def test_a_merge_of_no_planned_shard_is_refused(self):
        for planned in ("0", "-1", "x"):
            with self.subTest(planned=planned):
                with self.assertRaises(SystemExit):
                    self.campaign.merge(self.binary, "witness_etcd", self.seeds, self.root / "shards",
                                        self.root / f"merged{planned}", planned)
        self.assertEqual(self.calls_made(), [])

    def test_an_input_that_fails_the_merge_fails_it_though_libfuzzer_exits_0(self):
        # libFuzzer's merge survives an input that fails its inner process:
        # it writes the input to -artifact_prefix, starts the inner process
        # again ("MERGE-OUTER: attempt 2"), which leaves the input out, and
        # exits 0; the coverage run of the merged corpus, without it, exits
        # 0 too (clang 18's libFuzzer on a target that aborts on one input).
        self.shard(1, b"one", b"CRASH")
        os.environ["FAKE_MERGE_FAILS"] = "CRASH"
        name = "-" + hashlib.sha1(b"CRASH").hexdigest()
        for index, kind in enumerate(("crash", "timeout", "oom", "leak")):
            with self.subTest(kind=kind):
                os.environ["FAKE_MERGE_ARTIFACT"] = kind
                out = self.root / f"merged-{kind}"
                record = self.merge(f"merged-{kind}")
                self.assertEqual((record["merge_exit"], record["coverage_exit"]), (0, 0))
                # The two seeds and "one".
                self.assertEqual((record["inputs"], record["cov"]), (3, 30))
                self.assertEqual(record["failures"], [
                    "the merge took 2 attempts: an input failed its inner process and was left out",
                    f"the merge wrote the {kind} input {kind}{name}"])
                self.assertEqual(record["attempts"], 2)
                self.assertEqual(record["artifacts"],
                                 [{"name": kind + name, "kind": kind, "bytes": 5}])
                self.assertEqual(json.loads((out / "coverage.json").read_text()), record)
                self.assertEqual(self.main(f"main-{kind}"), 1)
        # An inner process that fails without writing the input (killed, say)
        # shows only in the second attempt.
        os.environ["FAKE_MERGE_ARTIFACT"] = ""
        record = self.merge("merged-killed")
        self.assertEqual(record["failures"], [
            "the merge took 2 attempts: an input failed its inner process and was left out"])
        self.assertEqual((record["merge_exit"], record["artifacts"]), (0, []))

    def test_a_slow_unit_the_merge_wrote_is_listed_and_is_no_failure(self):
        self.shard(1, b"one", b"slow")
        os.environ["FAKE_MERGE_SLOW"] = "slow"
        record = self.merge("merged")
        self.assertEqual(record["failures"], [])
        self.assertEqual(record["artifacts"], [
            {"name": "slow-unit-" + hashlib.sha1(b"slow").hexdigest(), "kind": "slow-unit",
             "bytes": 4}])
        self.assertEqual(record["attempts"], 1)

    def test_a_merge_log_without_an_attempt_fails(self):
        # The second attempt is read from the merge's log: a log that shows
        # no first attempt cannot show a second either.
        self.shard(1, b"one")
        stand_in = self.binary.read_text()
        self.binary.write_text(stand_in.replace('say(f"MERGE-OUTER: attempt {attempt}")\n', "pass\n"))
        record = self.merge("merged")
        self.assertEqual(record["failures"], ["the merge's log shows no attempt of its inner process"])
        self.assertEqual(record["attempts"], 0)

    def test_a_campaign_whose_merge_lacks_a_shards_corpus_does_not_qualify(self):
        # The campaign's records as the summary job downloads them: both
        # shards qualified on their own, but the second one's archive did not
        # reach the merge.
        plan = self.campaign.plan("witness_etcd", "0.004", "0.001", "4")
        self.assertEqual(plan["shards"], 2)
        digest = self.campaign.sha256(self.binary)
        (self.root / "build").mkdir()
        (self.root / "build" / "SHA256SUMS").write_text(f"{digest}  witness_etcd\n")
        for shard in (1, 2):
            directory = self.root / "stats" / f"fuzz-stats-witness_etcd-{shard}"
            directory.mkdir(parents=True)
            (directory / "shard.json").write_text(json.dumps({
                "target": "witness_etcd", "shard": shard, "binary_sha256": digest,
                "cpu_seconds": plan["cpu_seconds"], "wall_seconds": plan["wall_seconds"],
                "artifacts": [],
                "workers": [{"worker": worker, "exit": 0, "signal": None, "stopped": False,
                             "cpu_seconds": plan["cpu_seconds"], "wall_seconds": 3,
                             "executions": 1000, "error": None} for worker in range(1, 5)]}))
        self.shard(1, b"one", b"two")
        coverage = self.root / "coverage"

        def verdict():
            shutil.rmtree(coverage, ignore_errors=True)
            self.merge("coverage/fuzz-coverage-witness_etcd", planned=plan["shards"])
            summary = self.campaign.summarize(plan, self.root / "stats", coverage, self.root / "build",
                                              {})
            row, = summary["targets"]
            return summary["qualified"], row["reasons"]

        self.assertEqual(verdict(), (False, [
            "the merge had no corpus of shard 2 (no fuzz-shard-witness_etcd-2/shard.tar)"]))
        self.shard(2, b"three")
        self.assertEqual(verdict(), (True, []))


def gates():
    """scripts/test_ci_gate_validation.py, which reads the workflow's steps."""
    spec = importlib.util.spec_from_file_location(
        "ci_gates", ROOT / "scripts" / "test_ci_gate_validation.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def running(pid):
    """Whether `pid` is a process that has not ended (a zombie has)."""
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except (OSError, IndexError):
        return False


def cancel_like_the_runner(process):
    """What actions/runner does to a step it cancels or that ran out of
    time (ProcessInvoker.cs): SIGINT to the step's own process, 7.5 s,
    SIGTERM, 2.5 s, then kill. Returns the signal it ended after."""
    for sig, wait in ((signal.SIGINT, 7.5), (signal.SIGTERM, 2.5)):
        process.send_signal(sig)
        try:
            process.wait(timeout=wait)
            return sig
        except subprocess.TimeoutExpired:
            pass
    process.kill()
    process.wait()
    return signal.SIGKILL


@unittest.skipUnless(sys.platform == "linux", "the steps run in bash on Linux runners")
class StepCancellation(Fixture):
    """The workflow's long steps as the runner runs them: their script in
    `bash --noprofile --norc -e -o pipefail <file>` (ScriptHandlerHelpers.cs),
    whose own process alone the runner signals. Bash does not hand a signal
    on to the command it waits for."""

    def setUp(self):
        super().setUp()
        self.jobs = gates().qualification_jobs()
        # A target name of the test's own: its temporary directory on
        # /dev/shm is found and removed by it.
        self.target = f"cancel_probe_{os.getpid()}"
        (self.root / "scripts").mkdir()
        (self.root / "scripts" / "fuzz_campaign.py").write_text(SCRIPT.read_text())
        seeds = self.root / "fuzz" / "seeds" / self.target
        seeds.mkdir(parents=True)
        (seeds / "valid-a").write_bytes(b"seed a")
        self.temp = self.root / "runner-temp"
        (self.temp / "binaries").mkdir(parents=True)
        (self.temp / "binaries" / self.target).write_text(FAKE_FUZZER)
        (self.temp / "binaries" / self.target).chmod(0o700)
        self.addCleanup(self.remove_temporary_directories)

    def remove_temporary_directories(self):
        for root in (Path("/dev/shm"), Path(tempfile.gettempdir())):
            for path in root.glob(f"maki-fuzz-*{self.target}-*"):
                subprocess.run(["rm", "-rf", str(path)], check=False)

    def step(self, job, name, environment, ready):
        """Run the step, cancel it like the runner once `ready()` holds, and
        return the signal it ended after and the pids it started."""
        script = self.root / "step.sh"
        script.write_text(gates().job_step_script(self.jobs[job], name))
        log = open(self.root / "step.log", "wb")
        self.addCleanup(log.close)
        process = subprocess.Popen(["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", str(script)],
                                   cwd=self.root, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                   env=dict(os.environ, RUNNER_TEMP=str(self.temp), TARGET=self.target,
                                            **environment),
                                   start_new_session=True)
        try:
            for _ in range(400):
                if process.poll() is not None or ready():
                    break
                time.sleep(0.05)
            self.assertIsNone(process.poll(), (self.root / "step.log").read_text())
            ended_after = cancel_like_the_runner(process)
            started = [call["pid"] for call in self.calls_made()]
            inner = Path(str(self.calls) + ".inner")
            if inner.exists():
                started.append(int(inner.read_text()))
            # Give a process the kill reached a moment to go.
            for _ in range(20):
                if not any(running(pid) for pid in started):
                    break
                time.sleep(0.05)
            left = [pid for pid in started if running(pid)]
        finally:
            # Whatever the step left behind: its process group, and every
            # process it started, which may have a group of its own.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            inner = Path(str(self.calls) + ".inner")
            for pid in [call["pid"] for call in self.calls_made()] + (
                    [int(inner.read_text())] if inner.exists() else []):
                if running(pid):
                    os.kill(pid, signal.SIGKILL)
        return ended_after, left

    def shard_ready(self):
        logs = self.temp / "shard" / "logs"
        return len(self.calls_made()) == 2 and all(
            "INITED" in (logs / f"worker-{worker}-round-1.log").read_text(errors="replace")
            for worker in (1, 2) if (logs / f"worker-{worker}-round-1.log").exists()) and \
            len(list(logs.glob("worker-*-round-1.log"))) == 2

    def shard(self, modes):
        os.environ["FAKE_MODES"] = json.dumps(modes)
        ended_after, left = self.step("fuzz", "fuzz the shard", {
            "SHARD": "1", "CPU_SECONDS": "3600", "WALL_SECONDS": "3600", "WORKERS": "2"},
            self.shard_ready)
        self.assertEqual(left, [], "fuzzing processes outlived the step")
        record = self.temp / "shard" / "shard.json"
        self.assertTrue(record.is_file(), (self.root / "step.log").read_text())
        # Before the runner's SIGTERM: the record is complete and the
        # uploads that follow (`if: always()`) read the shard as it ended.
        self.assertEqual(ended_after, signal.SIGINT)
        return json.loads(record.read_text())

    def test_a_cancelled_shard_step_keeps_its_record_and_leaves_no_fuzzer(self):
        record = self.shard(["hang", "hang"])
        self.assertTrue(record["interrupted"])
        self.assertEqual([(worker["exit"], worker["stopped"]) for worker in record["workers"]],
                         [(72, True), (72, True)])
        self.assertEqual(record["failures"][0], "the step was interrupted")

    def test_a_process_that_ignores_the_interrupt_is_killed_in_time(self):
        record = self.shard(["hang", "stubborn"])
        self.assertTrue(record["interrupted"])
        self.assertEqual(sorted(((worker["exit"], worker["signal"]) for worker in record["workers"]),
                                key=repr),
                         sorted([(72, None), (None, signal.SIGKILL)], key=repr))

    def test_a_cancelled_merge_step_keeps_its_record_and_leaves_no_fuzzer(self):
        # The shard's archive as the merge job downloads it.
        packed = self.root / "packed" / "shard"
        (packed / "corpus").mkdir(parents=True)
        (packed / "corpus" / "input").write_bytes(b"input")
        downloaded = self.temp / "shards" / f"fuzz-shard-{self.target}-1"
        downloaded.mkdir(parents=True)
        with tarfile.open(downloaded / "shard.tar", "w") as archive:
            archive.add(packed, arcname="shard")
        os.environ["FAKE_MERGE_HANG"] = "1"
        inner = Path(str(self.calls) + ".inner")
        ended_after, left = self.step("merge", "merge the seeds and the shard corpora", {"SHARDS": "1"},
                                      lambda: inner.exists() and len(self.calls_made()) == 1)
        self.assertEqual(left, [], "the merge's processes outlived the step")
        record = self.temp / "merged" / "coverage.json"
        self.assertTrue(record.is_file(), (self.root / "step.log").read_text())
        self.assertEqual(ended_after, signal.SIGINT)
        record = json.loads(record.read_text())
        self.assertTrue(record["interrupted"])
        self.assertEqual(record["failures"][0], "the merge was interrupted")
        self.assertEqual(record["sources"], [{"shard": 1, "artifact": f"fuzz-shard-{self.target}-1",
                                              "inputs": 1}])

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
                  "seeds": 30, "error": None, "attempts": 1, "artifacts": [],
                  "planned_shards": self.plan["shards"],
                  "sources": [{"shard": shard, "artifact": f"fuzz-shard-{target}-{shard}", "inputs": 20}
                              for shard in range(1, self.plan["shards"] + 1)],
                  "unmerged": []}
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

    def test_an_input_the_merge_failed_on_does_not_qualify_and_is_listed(self):
        # Shards that qualify on their own, and a merge that exited 0 with a
        # crash input in its artifacts after a second attempt (the probe's
        # record of clang 18's libFuzzer); a slow unit is only listed.
        merged = [{"name": "crash-1c1b", "kind": "crash", "bytes": 5},
                  {"name": "slow-unit-02", "kind": "slow-unit", "bytes": 4}]
        self.coverage("witness_etcd", attempts=2, artifacts=merged)
        self.coverage("format_decoders", attempts=2)
        summary = self.summarize()
        self.assertFalse(summary["qualified"])
        rows = {row["target"]: row for row in summary["targets"]}
        restarted = "the merge took 2 attempts: an input failed its inner process and was left out"
        self.assertEqual(rows["witness_etcd"]["reasons"],
                         [restarted, "the merge wrote the crash input crash-1c1b"])
        self.assertEqual(rows["format_decoders"]["reasons"], [restarted])
        self.assertEqual(rows["witness_etcd"]["artifacts"],
                         [dict(artifact, merge=True) for artifact in merged])
        text = campaign().markdown(summary)
        row = next(line for line in text.splitlines() if line.startswith("| `witness_etcd`"))
        self.assertIn("| `crash-1c1b` (merge) |", row)
        self.assertNotIn("slow-unit-02", row)
        for case, changes in (("no attempt", {"attempts": 0}), ("older record", {"attempts": None})):
            with self.subTest(case=case):
                self.coverage("witness_etcd", **changes)
                self.assertEqual(self.verdicts()["witness_etcd"],
                                 ["the merge's log shows no attempt of its inner process"])

    def test_a_merge_without_a_corpus_of_every_planned_shard_does_not_qualify(self):
        # Run 45983119347: every shard of four targets qualified on its own
        # record, but none of their corpora reached the merge, which merged
        # the seeds alone.
        self.plan = campaign().plan("format_decoders witness_etcd", "8", "1", "4")
        self.assertEqual(self.plan["shards"], 3)
        for target in self.plan["targets"]:
            for shard in (1, 2, 3):
                self.shard(target, shard)
            self.coverage(target)
        self.assertEqual(self.verdicts(), {"format_decoders": [], "witness_etcd": []})
        self.coverage("witness_etcd", sources=[
            {"shard": shard, "artifact": f"fuzz-shard-witness_etcd-{shard}", "inputs": 20}
            for shard in (1, 3)],
            unmerged=[{"shard": 2, "artifact": "fuzz-shard-witness_etcd-2",
                       "why": "no fuzz-shard-witness_etcd-2/shard.tar"}])
        self.assertEqual(self.verdicts(), {"format_decoders": [], "witness_etcd": [
            "the merge had no corpus of shard 2 (no fuzz-shard-witness_etcd-2/shard.tar)"]})
        summary = self.summarize()
        self.assertFalse(summary["qualified"])
        self.assertIn("not qualified: the merge had no corpus of shard 2", campaign().markdown(summary))
        # The plan decides which shards the merge needed, not the merge's
        # own record; a record that does not say why still fails, and so
        # does one that names its sources otherwise (by their artifact).
        for case, changes in (
                ("seeds alone", {"sources": [], "unmerged": [], "planned_shards": 0}),
                ("no account", {"sources": None, "unmerged": None, "planned_shards": None}),
                ("by artifact", {"sources": [{"shard": f"fuzz-shard-witness_etcd-{shard}", "inputs": 20}
                                             for shard in (1, 2, 3)]})):
            with self.subTest(case=case):
                self.coverage("witness_etcd", **changes)
                self.assertEqual(self.verdicts()["witness_etcd"], [
                    f"the merge had no corpus of shard {shard}" for shard in (1, 2, 3)])

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

    def test_a_plan_without_targets_does_not_qualify(self):
        self.plan = dict(self.plan, targets=[])
        summary = self.summarize()
        self.assertEqual((summary["targets"], summary["unreadable"]), ([], []))
        self.assertFalse(summary["qualified"])
        self.assertTrue(campaign().markdown(summary).rstrip().endswith(
            "Qualified: no, see the verdicts"))

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
