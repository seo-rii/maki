#!/usr/bin/env python3
"""The parser fuzz qualification (.github/workflows/fuzz-qualification.yml).

SPEC §56 asks for 24 CPU-hours of coverage-guided fuzzing per parser target
(docs/testing.md, "Fuzz qualification"). A hosted runner has 4 vCPUs and a
job may run 6 hours, so a target's CPU-hours are split over shards: jobs of
one libFuzzer process per vCPU on one shared corpus, all fuzzing the same
build. The shards' corpora are then merged per target. Subcommands, in the
order the workflow runs them:

plan      the shards of the selected targets, as the fuzzing job's matrix
max-len   a target's -max_len (also used by the fuzz job of ci.yml)
run       one shard: run each of its libFuzzer processes until the kernel
          has charged it its share of CPU time, and record that time, its
          executions and coverage, and the inputs it failed on
merge     merge a target's seeds and shard corpora into one corpus, and
          record the coverage that corpus reaches
summary   every target's evidence and verdict; fails unless every target
          qualified

Only the standard library; Linux (os.waitid, os.wait4).
"""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "fuzz" / "Cargo.toml"

# libFuzzer's own limit when -max_len is not given.
LIBFUZZER_MAX_LEN = 4096
# Targets whose readers check a bound on a longer input: each length lies
# beyond that bound, so a run can reach both sides of it, and is at least
# the target's largest committed seed (libFuzzer cuts a longer input it
# reads to -max_len).
MAX_LEN = {
    # A superblock is a 4096-byte frame after the byte that selects the
    # decoder.
    "format_decoders": 8192,
    "format_records": 8192,
    # A gRPC method path is at most 65,534 bytes long.
    "config_parse": 70000,
    # The handshake client reads at most 64 KiB.
    "nbd_handshake": 70000,
    # The reader takes up to eight datagrams of up to 16 KiB each.
    "nbd_netlink": 140000,
    # The remote witness state is at most 64 KiB long.
    "backing_records": 70000,
    # A frame carries at most 64 KiB.
    "witness_rpc": 70000,
    # etcd's answer is at most 256 KiB long, the witness state in it at
    # most 64 KiB.
    "witness_etcd": 270000,
    # The helper reads at most 64 KiB of a command's output.
    "helper_reports": 70000,
}
# The fuzz job of ci.yml uses the same limits per input.
TIMEOUT_SECONDS = 25
RSS_LIMIT_MB = 2048
# A process is not charged all of its wall time: a target that waits for a
# thread of its own (nbd_handshake's server) or for the filesystem
# (helper_sysfs on a disk, below) is charged less. So each process fuzzes in
# rounds on the
# shard's corpus until it has been charged its share, within the shard's
# wall time, which is this many times the share. A round after the first
# lasts what is missing, and at least a minute.
HEADROOM = 1.5
MIN_ROUND_SECONDS = 60
# A hosted runner has 4 vCPUs; a job may run 6 hours (360 minutes),
# checkout, download and uploads included.
WORKERS = 4
MAX_SHARD_HOURS = 5
JOB_MINUTES = 360
# GitHub runs at most 20 of an account's jobs at once and at most 256 jobs
# of one matrix.
MAX_PARALLEL = 20
MAX_JOBS = 256
# A process that has not ended this long after its time limit is
# interrupted (libFuzzer then prints its final statistics), and killed a
# minute later.
GRACE_SECONDS = 600
KILL_AFTER_SECONDS = 60
# The prefixes of the inputs libFuzzer writes when it stops on one: a crash
# (a panic, an abort or a sanitizer report), an input that ran longer than
# -timeout, one that took more memory than -rss_limit_mb, a leak.
# `slow-unit-` inputs are only reported.
FAILING_ARTIFACTS = ("crash", "timeout", "oom", "leak")
# The processes' temporary directory goes on this memory filesystem where
# there is one: helper_sysfs builds a directory tree for every input, which
# on the runner's disk leaves a process waiting on the filesystem for most
# of its time (a local run: 36 % of its wall time on the CPU on disk, 91 %
# on /dev/shm, with twelve times the executions).
MEMORY_TEMP = Path("/dev/shm")
TARGET_NAME = re.compile(r"[a-z0-9_]+")

STATUS = re.compile(
    r"^#(\d+)\s+(INITED|NEW|REDUCE|pulse|RELOAD|DONE)\s+cov: (\d+) ft: (\d+) corp: (\d+)/(\S+)",
    re.MULTILINE)
FINAL_STATS = {
    "executions": "number_of_executed_units",
    "exec_per_second": "average_exec_per_sec",
    "new_units": "new_units_added",
    "slowest_unit_seconds": "slowest_unit_time_sec",
    "peak_rss_mb": "peak_rss_mb",
}
ERROR = re.compile(r"^(==\d+== ?ERROR: .*|.*panicked at .*|ALARM: working on the last Unit.*)$",
                   re.MULTILINE)


def fail(message):
    raise SystemExit(f"fuzz-campaign: {message}")


def manifest_targets(text):
    """The [[bin]] names of fuzz/Cargo.toml, in order, read line by line: a
    Windows checkout may end its lines with CRLF."""
    lines = [line.strip() for line in text.splitlines()]
    names = []
    for index, line in enumerate(lines):
        if line != "[[bin]]":
            continue
        for following in lines[index + 1:]:
            if following.startswith("["):
                break
            match = re.fullmatch(r'name = "([^"]+)"', following)
            if match:
                names.append(match.group(1))
                break
    return names


def max_len(target):
    return MAX_LEN.get(target, LIBFUZZER_MAX_LEN)


def positive(text, name, highest, integer=False):
    try:
        value = int(text) if integer else float(text)
    except (TypeError, ValueError):
        fail(f"{name} must be a {'whole ' if integer else ''}number, not {text!r}")
    if not math.isfinite(value) or value <= 0 or value > highest:
        fail(f"{name} must be above 0 and at most {highest}, not {text!r}")
    return value


def select(selection, available):
    """The targets `selection` names ("all", or names separated by spaces or
    commas), in the manifest's order."""
    words = [word for word in re.split(r"[\s,]+", selection.strip()) if word]
    if not words:
        fail("no target selected")
    if words == ["all"]:
        return list(available)
    unknown = [word for word in words if word not in available]
    if unknown:
        fail(f"fuzz/Cargo.toml has no target {', '.join(unknown)} "
             f"(it has {', '.join(available)})")
    return [target for target in available if target in words]


def step_minutes(seconds):
    """The fuzzing step's time limit: the shard's wall time, the grace
    before a process is interrupted, the minute before it is killed, and ten
    minutes to record and upload."""
    return math.ceil((seconds + GRACE_SECONDS + KILL_AFTER_SECONDS) / 60) + 10


def plan(selection, cpu_hours, shard_hours, max_parallel, workers=WORKERS, available=None):
    """Split each selected target's CPU-hours into equal shares of the
    processes of equal shards: `workers` processes a shard, each with at
    most `shard_hours` of wall time and a share of CPU time HEADROOM times
    smaller."""
    if available is None:
        available = manifest_targets(MANIFEST.read_text(encoding="utf-8"))
    for target in available:
        if not TARGET_NAME.fullmatch(target):
            fail(f"target name {target!r} is not lower-case letters, digits and underscores")
    cpu_hours = positive(cpu_hours, "cpu_hours", 1000)
    shard_hours = positive(shard_hours, "shard_hours", MAX_SHARD_HOURS)
    max_parallel = positive(max_parallel, "max_parallel", MAX_PARALLEL, integer=True)
    workers = positive(workers, "workers", 64, integer=True)
    targets = select(selection, available)
    wall_seconds = math.floor(shard_hours * 3600)
    per_worker = cpu_hours * 3600 / workers
    shards = math.ceil(per_worker * HEADROOM / wall_seconds)
    cpu_seconds = max(1, math.ceil(per_worker / shards))
    minutes = step_minutes(wall_seconds)
    if minutes > JOB_MINUTES - 20:
        fail(f"a shard of {wall_seconds} s needs a {minutes}-minute step, "
             f"beyond a {JOB_MINUTES}-minute job")
    matrix = [{"target": target, "shard": shard, "shards": shards, "cpu_seconds": cpu_seconds,
               "wall_seconds": wall_seconds, "workers": workers, "max_len": max_len(target),
               "minutes": minutes}
              for target in targets for shard in range(1, shards + 1)]
    if len(matrix) > MAX_JOBS:
        fail(f"{len(matrix)} shards, beyond the {MAX_JOBS} jobs of one matrix: "
             "select fewer targets or raise shard_hours")
    return {"targets": targets, "cpu_hours": cpu_hours, "shard_hours": shard_hours,
            "workers": workers, "shards": shards, "cpu_seconds": cpu_seconds,
            "wall_seconds": wall_seconds, "max_parallel": max_parallel, "matrix": matrix}


def compact(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def files_in(directory):
    """(inputs, bytes) of the regular files directly in `directory`."""
    count = size = 0
    if directory.is_dir():
        for entry in directory.iterdir():
            if entry.is_file():
                count += 1
                size += entry.stat().st_size
    return count, size


def asan_environment():
    """The environment `cargo fuzz run` gives an AddressSanitizer target."""
    environment = dict(os.environ)
    options = environment.get("ASAN_OPTIONS", "")
    environment["ASAN_OPTIONS"] = (options + ":" if options else "") + "detect_odr_violation=0"
    return environment


def parse_log(text):
    """What a libFuzzer process printed: its seed, its last status line, its
    final statistics (-print_final_stats=1) and the first error report."""
    found = {}
    seed = re.search(r"^INFO: Seed: (\d+)$", text, re.MULTILINE)
    found["seed"] = int(seed.group(1)) if seed else None
    statuses = STATUS.findall(text)
    if statuses:
        runs, event, cov, ft, inputs, size = statuses[-1]
        found.update(last_status=event, runs=int(runs), cov=int(cov), ft=int(ft),
                     corpus_inputs=int(inputs), corpus_size=size)
    else:
        found.update(last_status=None, runs=None, cov=None, ft=None, corpus_inputs=None,
                     corpus_size=None)
    inited = [status for status in statuses if status[1] == "INITED"]
    found["inited_cov"] = int(inited[0][2]) if inited else None
    for key, stat in FINAL_STATS.items():
        value = re.search(rf"^stat::{stat}:\s+(\d+)$", text, re.MULTILINE)
        found[key] = int(value.group(1)) if value else None
    error = ERROR.search(text)
    found["error"] = error.group(1).strip() if error else None
    return found


def host():
    model = None
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                model = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    return {"vcpus": os.cpu_count(), "cpu": model, "kernel": platform.release(),
            "image": " ".join(filter(None, (os.environ.get("ImageOS"),
                                            os.environ.get("ImageVersion")))) or None}


def temporary_root():
    if MEMORY_TEMP.is_dir() and os.access(MEMORY_TEMP, os.W_OK | os.X_OK):
        return MEMORY_TEMP
    return Path(tempfile.gettempdir())


def run(binary, target, shard, cpu_seconds, wall_seconds, workers, seeds, out,
        grace=GRACE_SECONDS, kill_after=KILL_AFTER_SECONDS, temp=None,
        min_round=MIN_ROUND_SECONDS, poll=1.0):
    """Fuzz one shard: `workers` libFuzzer processes on one corpus, each in
    rounds until the kernel has charged it `cpu_seconds`, none started once
    `wall_seconds` are spent, with a temporary directory of the shard's own
    below `temp` (by default /dev/shm where it can be written). Returns the
    shard's record."""
    if not TARGET_NAME.fullmatch(target):
        fail(f"target name {target!r} is not lower-case letters, digits and underscores")
    seeds = Path(seeds)
    if not seeds.is_dir() or not any(seeds.iterdir()):
        fail(f"{seeds} holds no seeds")
    out = Path(out)
    corpus, artifacts, logs = out / "corpus", out / "artifacts", out / "logs"
    for directory in (corpus, artifacts, logs):
        directory.mkdir(parents=True, exist_ok=True)
    length = max_len(target)
    options = [f"-max_len={length}", f"-timeout={TIMEOUT_SECONDS}",
               f"-rss_limit_mb={RSS_LIMIT_MB}", "-print_final_stats=1",
               f"-artifact_prefix={artifacts}/"]
    environment = asan_environment()
    shard_temp = Path(tempfile.mkdtemp(prefix=f"maki-fuzz-{target}-{shard}-",
                                       dir=temp if temp is not None else temporary_root()))
    environment["TMPDIR"] = str(shard_temp)
    lock = threading.Lock()
    # pid: [worker, round, deadline, interrupted]
    live = {}
    # Held until every process is reaped here: a Popen object collected
    # while its process runs is reaped by the next Popen's cleanup.
    processes = {}
    finished, interrupted = threading.Event(), threading.Event()
    began = time.monotonic()
    workers_records = {worker: {"worker": worker, "rounds": []}
                       for worker in range(1, workers + 1)}

    def start(worker, seconds):
        rounds = workers_records[worker]["rounds"]
        log = logs / f"worker-{worker}-round-{len(rounds) + 1}.log"
        with open(log, "wb") as handle:
            process = subprocess.Popen(
                [str(binary), f"-max_total_time={seconds}", *options, str(corpus), str(seeds)],
                stdin=subprocess.DEVNULL, stdout=handle, stderr=subprocess.STDOUT,
                env=environment)
        processes[process.pid] = process
        record = {"round": len(rounds) + 1, "seconds": seconds, "stopped": False,
                  "log": str(log.relative_to(out)), "started": time.monotonic()}
        rounds.append(record)
        with lock:
            live[process.pid] = [worker, record, record["started"] + seconds + grace, False]

    def charged(worker):
        return sum(record["cpu_seconds"] for record in workers_records[worker]["rounds"]
                   if "cpu_seconds" in record)

    def next_round(worker, record):
        """The seconds of the worker's next round, or None."""
        if interrupted.is_set() or record["stopped"] or record["exit"] != 0:
            return None
        missing = cpu_seconds - charged(worker)
        left = math.floor(wall_seconds - (time.monotonic() - began))
        seconds = min(max(math.ceil(missing), min_round), left)
        return seconds if missing > 0 and seconds >= min_round else None

    def watchdog():
        # Interrupt a process past its deadline, or every process when the
        # step is interrupted, and kill one that outlives that by kill_after.
        while not finished.wait(poll):
            now = time.monotonic()
            with lock:
                for pid, entry in live.items():
                    if not entry[3] and (interrupted.is_set() or now >= entry[2]):
                        entry[1]["stopped"] = True
                        entry[2], entry[3] = now + kill_after, True
                        os.kill(pid, signal.SIGINT)
                    elif entry[3] and now >= entry[2]:
                        os.kill(pid, signal.SIGKILL)

    for worker in workers_records:
        start(worker, max(1, min(math.ceil(cpu_seconds), wall_seconds)))
    guard = threading.Thread(target=watchdog, daemon=True)
    guard.start()
    previous = {sig: signal.signal(sig, lambda *_: interrupted.set())
                for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        while True:
            with lock:
                if not live:
                    break
            # Wait without reaping, so a process the watchdog signals is
            # still ours; reap it once it is no longer in `live`.
            ended = os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOWAIT)
            if ended is None:
                continue
            with lock:
                entry = live.pop(ended.si_pid, None)
            _, status, usage = os.wait4(ended.si_pid, 0)
            if ended.si_pid in processes:
                # Reaped: the Popen object must not wait for it again.
                processes[ended.si_pid].returncode = os.waitstatus_to_exitcode(status)
            if entry is None:
                continue
            worker, record = entry[0], entry[1]
            record["wall_seconds"] = round(time.monotonic() - record.pop("started"), 3)
            record["exit"] = os.WEXITSTATUS(status) if os.WIFEXITED(status) else None
            record["signal"] = os.WTERMSIG(status) if os.WIFSIGNALED(status) else None
            record["user_seconds"] = round(usage.ru_utime, 3)
            record["system_seconds"] = round(usage.ru_stime, 3)
            record["cpu_seconds"] = round(usage.ru_utime + usage.ru_stime, 3)
            record.update(parse_log((out / record["log"]).read_text(errors="replace")))
            seconds = next_round(worker, record)
            if seconds is not None:
                start(worker, seconds)
    finally:
        finished.set()
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    for worker, record in workers_records.items():
        rounds = record["rounds"]
        last = rounds[-1]
        record.update({
            "rounds_run": len(rounds),
            "cpu_seconds": round(sum(entry["cpu_seconds"] for entry in rounds), 3),
            "user_seconds": round(sum(entry["user_seconds"] for entry in rounds), 3),
            "system_seconds": round(sum(entry["system_seconds"] for entry in rounds), 3),
            "wall_seconds": round(sum(entry["wall_seconds"] for entry in rounds), 3),
            "executions": sum(entry["executions"] or 0 for entry in rounds),
            "exit": last["exit"], "signal": last["signal"],
            "stopped": any(entry["stopped"] for entry in rounds),
            "error": next((entry["error"] for entry in rounds if entry["error"]), None),
            "seeds": [entry["seed"] for entry in rounds],
            "cov": last["cov"], "ft": last["ft"],
        })
    found = []
    for entry in sorted(artifacts.iterdir()):
        if entry.is_file():
            kind = entry.name.split("-", 1)[0] if "-" in entry.name else entry.name
            if entry.name.startswith("slow-unit-"):
                kind = "slow-unit"
            found.append({"name": entry.name, "kind": kind, "bytes": entry.stat().st_size})
    # What the processes left in their temporary directory (helper_sysfs
    # removes its trees: docs/testing.md, "Fuzzing").
    left = sorted(str(path.relative_to(shard_temp)) for path in shard_temp.rglob("*"))
    shutil.rmtree(shard_temp, ignore_errors=True)
    inputs, size = files_in(corpus)
    seed_inputs, seed_bytes = files_in(seeds)
    record = {"target": target, "shard": shard, "cpu_seconds": cpu_seconds,
              "wall_seconds": wall_seconds, "max_len": length,
              "temporary_directory": str(shard_temp), "left_in_temporary_directory": left,
              "timeout_seconds": TIMEOUT_SECONDS, "rss_limit_mb": RSS_LIMIT_MB,
              "command": [Path(binary).name, "-max_total_time=<round>", *options,
                          "corpus/", "seeds/"],
              "binary_sha256": sha256(binary), "seeds": {"inputs": seed_inputs, "bytes": seed_bytes},
              "corpus": {"inputs": inputs, "bytes": size}, "artifacts": found,
              "interrupted": interrupted.is_set(),
              "workers": list(workers_records.values()), "host": host()}
    record["failures"] = shard_failures(record)
    (out / "shard.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return record


def shard_failures(record):
    """Why a shard's processes were not all charged their share, each round
    run to its time limit, without finding an input to stop on."""
    reasons = []
    for worker in record["workers"]:
        if worker.get("stopped"):
            reasons.append(f"process {worker['worker']} was stopped at its deadline")
        elif worker.get("exit") != 0:
            how = (f"signal {worker['signal']}" if worker.get("signal") is not None
                   else f"status {worker.get('exit')}")
            reasons.append(f"process {worker['worker']} ended with {how}"
                           + (f": {worker['error']}" if worker.get("error") else ""))
        elif (worker.get("cpu_seconds") or 0) < record.get("cpu_seconds", 0):
            reasons.append(f"process {worker['worker']} was charged {worker['cpu_seconds']:.0f} "
                           f"of its {record['cpu_seconds']:g} CPU seconds "
                           f"in {record.get('wall_seconds'):g} s")
    for artifact in record["artifacts"]:
        if artifact["kind"] in FAILING_ARTIFACTS:
            reasons.append(f"{artifact['kind']} input {artifact['name']}")
    return reasons


def merge(binary, target, seeds, shards, out, temp=None):
    """Merge `seeds` and every shard corpus below `shards` into one corpus
    (libFuzzer's -merge=1 keeps the inputs that add coverage), then run that
    corpus once to read the coverage it reaches. Returns the record."""
    out = Path(out)
    corpus = out / "corpus"
    corpus.mkdir(parents=True, exist_ok=False)
    (out / "artifacts").mkdir(exist_ok=True)
    length = max_len(target)
    sources = sorted(path for path in Path(shards).glob("*/corpus") if path.is_dir())
    limits = [f"-max_len={length}", f"-timeout={TIMEOUT_SECONDS}", f"-rss_limit_mb={RSS_LIMIT_MB}"]
    environment = asan_environment()
    merge_temp = Path(tempfile.mkdtemp(prefix=f"maki-fuzz-merge-{target}-",
                                       dir=temp if temp is not None else temporary_root()))
    environment["TMPDIR"] = str(merge_temp)
    with open(out / "merge.log", "wb") as log:
        merged = subprocess.run([str(binary), "-merge=1", *limits,
                                 f"-artifact_prefix={out / 'artifacts'}/", str(corpus),
                                 str(seeds), *map(str, sources)],
                                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                env=environment).returncode
    with open(out / "coverage.log", "wb") as log:
        measured = subprocess.run([str(binary), "-runs=0", *limits, str(corpus)],
                                  stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                  env=environment).returncode
    shutil.rmtree(merge_temp, ignore_errors=True)
    found = parse_log((out / "coverage.log").read_text(errors="replace"))
    inputs, size = files_in(corpus)
    seed_inputs, _ = files_in(Path(seeds))
    record = {"target": target, "max_len": length, "binary_sha256": sha256(binary),
              "seeds": seed_inputs,
              "sources": [{"shard": path.parent.name, "inputs": files_in(path)[0]}
                          for path in sources],
              "merge_exit": merged, "coverage_exit": measured, "inputs": inputs, "bytes": size,
              "cov": found["inited_cov"], "ft": None, "error": found["error"]}
    inited = [status for status in STATUS.findall((out / "coverage.log").read_text(errors="replace"))
              if status[1] == "INITED"]
    if inited:
        record["ft"] = int(inited[0][3])
    record["failures"] = merge_failures(record)
    (out / "coverage.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return record


def merge_failures(record):
    reasons = []
    if record["merge_exit"] != 0:
        reasons.append(f"the merge ended with status {record['merge_exit']}")
    if record["coverage_exit"] != 0:
        reasons.append(f"the coverage run ended with status {record['coverage_exit']}")
    if record["cov"] is None:
        reasons.append("the coverage run printed no INITED line")
    return reasons


def load(directory, name):
    """Every JSON file called `name` below `directory`."""
    found = []
    if directory and Path(directory).is_dir():
        for path in sorted(Path(directory).rglob(name)):
            try:
                found.append(json.loads(path.read_text()))
            except (OSError, ValueError) as error:
                found.append({"unreadable": f"{path}: {error}"})
    return found


def build_record(directory):
    """The build job's SHA256SUMS ({binary: digest}) and versions."""
    digests, versions = {}, None
    if directory and Path(directory).is_dir():
        sums = Path(directory) / "SHA256SUMS"
        if sums.is_file():
            for line in sums.read_text().splitlines():
                match = re.fullmatch(r"([0-9a-f]{64})  (\S+)", line.strip())
                if match:
                    digests[match.group(2)] = match.group(1)
        info = Path(directory) / "versions.txt"
        if info.is_file():
            versions = info.read_text().strip()
    return digests, versions


def hours(seconds):
    return f"{seconds / 3600:,.2f}"


def summarize(plan_record, stats, coverage, build=None, environment=None):
    """Each planned target's evidence and verdict."""
    environment = os.environ if environment is None else environment
    digests, versions = build_record(build)
    shards = {}
    unreadable = [] if digests else ["the build job's record (SHA256SUMS) is missing"]
    for record in load(stats, "shard.json"):
        if "unreadable" in record:
            unreadable.append(record["unreadable"])
        else:
            shards[(record.get("target"), record.get("shard"))] = record
    merged = {}
    for record in load(coverage, "coverage.json"):
        if "unreadable" in record:
            unreadable.append(record["unreadable"])
        else:
            merged[record.get("target")] = record
    requested = plan_record["cpu_hours"] * 3600
    rows = []
    for target in plan_record["targets"]:
        found = [shards.get((target, shard)) for shard in range(1, plan_record["shards"] + 1)]
        missing = [shard for shard, record in enumerate(found, 1) if record is None]
        found = [record for record in found if record is not None]
        workers = [worker for record in found for worker in record["workers"]]
        cpu = sum(worker.get("cpu_seconds") or 0 for worker in workers)
        wall = sum(worker.get("wall_seconds") or 0 for worker in workers)
        executions = sum(worker.get("executions") or 0 for worker in workers)
        artifacts = [dict(artifact, shard=record["shard"]) for record in found
                     for artifact in record["artifacts"]]
        reasons = []
        if missing:
            reasons.append("no record of shard " + ", ".join(map(str, missing)))
        for record in found:
            reasons.extend(f"shard {record['shard']}: {reason}"
                           for reason in shard_failures(record))
        if cpu < requested:
            reasons.append(f"{hours(cpu)} of {plan_record['cpu_hours']:g} CPU-hours")
        result = merged.get(target)
        if result is None:
            reasons.append("no merged corpus")
        else:
            reasons.extend(merge_failures(result))
        used = {record["binary_sha256"] for record in found}
        if result is not None:
            used.add(result["binary_sha256"])
        if len(used) > 1:
            reasons.append("the shards and the merge fuzzed different binaries")
        if digests and used and used != {digests.get(target)}:
            reasons.append("a binary that is not the build job's")
        rows.append({"target": target, "max_len": max_len(target),
                     "shards": len(found), "processes": len(workers),
                     "cpu_seconds": round(cpu, 3), "process_seconds": round(wall, 3),
                     "executions": executions,
                     "cov": result.get("cov") if result else None,
                     "ft": result.get("ft") if result else None,
                     "corpus_inputs": result.get("inputs") if result else None,
                     "corpus_bytes": result.get("bytes") if result else None,
                     "seeds": result.get("seeds") if result else None,
                     "artifacts": artifacts, "binary_sha256": sorted(used),
                     "qualified": not reasons, "reasons": reasons})
    server = environment.get("GITHUB_SERVER_URL", "")
    repository = environment.get("GITHUB_REPOSITORY", "")
    run_id = environment.get("GITHUB_RUN_ID", "")
    hosts = sorted({json.dumps(record.get("host"), sort_keys=True) for record in shards.values()})
    return {"revision": environment.get("GITHUB_SHA"), "ref": environment.get("GITHUB_REF"),
            "run": f"{server}/{repository}/actions/runs/{run_id}" if run_id else None,
            "requested_cpu_hours": plan_record["cpu_hours"], "shards": plan_record["shards"],
            "workers": plan_record["workers"], "cpu_seconds": plan_record["cpu_seconds"],
            "wall_seconds": plan_record["wall_seconds"],
            "versions": versions, "hosts": [json.loads(entry) for entry in hosts],
            "unreadable": unreadable, "targets": rows,
            "qualified": bool(rows) and not unreadable and all(row["qualified"] for row in rows)}


def markdown(summary):
    lines = ["# Fuzz qualification", ""]
    lines.append(f"Revision `{summary['revision']}` ({summary['ref']}), "
                 f"run {summary['run'] or '(not on GitHub)'}.")
    lines.append(f"{summary['requested_cpu_hours']:g} CPU-hours requested per target: "
                 f"{summary['shards']} shard(s) of {summary['workers']} libFuzzer processes, "
                 f"each charged {summary['cpu_seconds']} CPU seconds within "
                 f"{summary['wall_seconds']} s.")
    lines.append("")
    if summary["versions"]:
        lines += ["```text", summary["versions"], "```", ""]
    for entry in summary["hosts"]:
        entry = entry or {}
        lines.append(f"Runner: {entry.get('vcpus')} vCPUs ({entry.get('cpu')}), "
                     f"kernel {entry.get('kernel')}, image {entry.get('image')}.")
    if summary["hosts"]:
        lines.append("")
    lines.append("| Target | -max_len | CPU-hours | Process-hours | Executions | Edges | Features "
                 "| Corpus | Inputs it stopped on | Verdict |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---|---|")
    for row in summary["targets"]:
        stopped = ", ".join(f"`{artifact['name']}` (shard {artifact['shard']})"
                            for artifact in row["artifacts"]
                            if artifact["kind"] in FAILING_ARTIFACTS) or "none"
        verdict = "qualified" if row["qualified"] else "not qualified: " + "; ".join(row["reasons"])
        corpus = ("-" if row["corpus_inputs"] is None
                  else f"{row['corpus_inputs']:,} inputs, {row['corpus_bytes']:,} bytes")
        lines.append(" | ".join([
            f"| `{row['target']}`", f"{row['max_len']:,}", hours(row["cpu_seconds"]),
            hours(row["process_seconds"]), f"{row['executions']:,}",
            "-" if row["cov"] is None else f"{row['cov']:,}",
            "-" if row["ft"] is None else f"{row['ft']:,}", corpus, stopped,
            verdict + " |"]))
    for entry in summary["unreadable"]:
        lines.append(f"\nUnreadable record: {entry}")
    lines.append("")
    lines.append("Qualified: " + ("every target" if summary["qualified"] else "no, see the verdicts"))
    return "\n".join(lines) + "\n"


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    planned = commands.add_parser("plan", help="print the plan as GitHub step outputs")
    planned.add_argument("--targets", required=True)
    planned.add_argument("--cpu-hours", required=True)
    planned.add_argument("--shard-hours", required=True)
    planned.add_argument("--max-parallel", required=True)
    planned.add_argument("--workers", default=str(WORKERS))
    length = commands.add_parser("max-len", help="print a target's -max_len")
    length.add_argument("target")
    running = commands.add_parser("run", help="fuzz one shard")
    running.add_argument("--binary", required=True, type=Path)
    running.add_argument("--target", required=True)
    running.add_argument("--shard", required=True, type=int)
    running.add_argument("--cpu-seconds", required=True, type=float)
    running.add_argument("--wall-seconds", required=True, type=int)
    running.add_argument("--workers", required=True, type=int)
    running.add_argument("--seeds", required=True, type=Path)
    running.add_argument("--out", required=True, type=Path)
    merging = commands.add_parser("merge", help="merge a target's shard corpora")
    merging.add_argument("--binary", required=True, type=Path)
    merging.add_argument("--target", required=True)
    merging.add_argument("--seeds", required=True, type=Path)
    merging.add_argument("--shards", required=True, type=Path)
    merging.add_argument("--out", required=True, type=Path)
    summarizing = commands.add_parser("summary", help="every target's evidence and verdict")
    summarizing.add_argument("--plan", required=True, help="the plan step's `plan` output (JSON)")
    summarizing.add_argument("--stats", required=True, type=Path)
    summarizing.add_argument("--coverage", required=True, type=Path)
    summarizing.add_argument("--build", type=Path)
    summarizing.add_argument("--out", required=True, type=Path)
    options = parser.parse_args(arguments)
    if options.command == "plan":
        record = plan(options.targets, options.cpu_hours, options.shard_hours,
                      options.max_parallel, options.workers)
        print(f"{len(record['targets'])} target(s), {record['shards']} shard(s) each of "
              f"{record['workers']} processes charged {record['cpu_seconds']} CPU s within "
              f"{record['wall_seconds']} s", file=sys.stderr)
        print(f"plan={compact(record)}")
        print(f"matrix={compact(record['matrix'])}")
        print(f"targets={compact(record['targets'])}")
        print(f"max_parallel={record['max_parallel']}")
        return 0
    if options.command == "max-len":
        print(max_len(options.target))
        return 0
    if options.command == "run":
        record = run(options.binary, options.target, options.shard, options.cpu_seconds,
                     options.wall_seconds, options.workers, options.seeds, options.out)
        for worker in record["workers"]:
            print(f"process {worker['worker']}: {worker['cpu_seconds']} CPU s in "
                  f"{worker['wall_seconds']} s over {worker['rounds_run']} round(s), "
                  f"{worker['executions']} executions, cov {worker['cov']}, exit {worker['exit']}")
        for reason in record["failures"]:
            print(f"failure: {reason}", file=sys.stderr)
        return 1 if record["failures"] else 0
    if options.command == "merge":
        record = merge(options.binary, options.target, options.seeds, options.shards, options.out)
        print(f"{options.target}: {record['inputs']} inputs from {len(record['sources'])} "
              f"shard corpora and {record['seeds']} seeds, cov {record['cov']}, ft {record['ft']}")
        for reason in record["failures"]:
            print(f"failure: {reason}", file=sys.stderr)
        return 1 if record["failures"] else 0
    try:
        plan_record = json.loads(options.plan)
    except ValueError as error:
        fail(f"the plan is not JSON: {error}")
    summary = summarize(plan_record, options.stats, options.coverage, options.build)
    options.out.mkdir(parents=True, exist_ok=True)
    (options.out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (options.out / "summary.md").write_text(markdown(summary))
    print(markdown(summary))
    return 0 if summary["qualified"] else 1


if __name__ == "__main__":
    sys.exit(main())
