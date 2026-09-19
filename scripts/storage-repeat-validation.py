#!/usr/bin/env python3
"""Repeat existing Linux storage regressions using frozen source and binaries."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid


SUITES = ("phase11_dbsim", "phase12_powerloss", "review_stress",
          "review_r3_space_admission", "review_r3_recovery_memory")
TERMINAL = {"passed", "failed", "cancelled", "incomplete"}


def save_json(path, value):
    temporary = path.with_name(path.name + ".tmp")
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as out:
        json.dump(value, out, indent=2, sort_keys=True)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
    os.replace(temporary, path)


def process_identity(pid):
    try:
        stat = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        if stat[0] == "Z":
            return None
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip() + ":" + stat[19]
    except (OSError, IndexError):
        return None


def alive(controller):
    return bool(controller.get("identity")) and process_identity(controller["pid"]) == controller["identity"]


def passed_count(text):
    matches = re.findall(
        r"test result: ok\. (\d+) passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;", text)
    if len(matches) != 1 or int(matches[0]) < 1:
        raise ValueError("missing, empty, filtered or incomplete test result")
    return int(matches[0])


def run_child(command, cwd, log, stop, timeout, max_bytes=64 << 20, env=None):
    began = time.monotonic()
    if stop.exists():
        return {"exit_code": 130, "reason": "cancelled", "seconds": 0}
    with os.fdopen(os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
        child = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                 stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        reason = "exited"
        try:
            while child.poll() is None:
                if stop.exists():
                    reason = "cancelled"
                elif time.monotonic() - began >= timeout:
                    reason = "timeout"
                elif log.stat().st_size > max_bytes:
                    reason = "output_limit"
                if reason != "exited":
                    break
                time.sleep(.1)
        finally:
            # These test/build children own a process group. Kill the group also
            # after an early leader exit, so descendants cannot outlive the job.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
    if reason == "exited" and log.stat().st_size > max_bytes:
        reason = "output_limit"
    return {"exit_code": child.returncode, "reason": reason,
            "seconds": round(time.monotonic() - began, 3)}


def prepare(directory, config, deadline):
    source = Path(config["source"])
    environment = os.environ.copy()
    environment.update(CARGO_TARGET_DIR=config["target_dir"], CARGO_BUILD_JOBS="2")
    command = ["cargo", "test", "--offline", "--locked", "-p", "maki-core",
               "--no-run", "--message-format=json"]
    for suite in SUITES:
        command.extend(["--test", suite])
    result = run_child(command, source, directory / "build.log", directory / "STOP",
                       min(1800, deadline - time.monotonic()), env=environment)
    if result["exit_code"] != 0 or result["reason"] != "exited":
        raise RuntimeError(f"build did not complete: {result}")
    executables = {}
    for line in (directory / "build.log").read_text(errors="replace").splitlines():
        if not line.startswith("{"):
            continue
        event = json.loads(line)
        name = event.get("target", {}).get("name")
        if event.get("reason") == "compiler-artifact" and name in SUITES and event.get("executable"):
            executables[name] = Path(event["executable"])
    if set(executables) != set(SUITES):
        raise RuntimeError("build did not produce every requested test binary")
    binary_dir = directory / "bin"
    binary_dir.mkdir(mode=0o700)
    manifest = {}
    for name, original in executables.items():
        frozen = binary_dir / name
        shutil.copyfile(original, frozen)
        frozen.chmod(0o500)
        executables[name] = frozen
        manifest[name] = {"sha256": hashlib.sha256(frozen.read_bytes()).hexdigest()}
        result = run_child([str(frozen), "--list", "--include-ignored"], source,
                           directory / f"list-{name}.log", directory / "STOP", 30)
        if result["exit_code"] != 0 or result["reason"] != "exited":
            raise RuntimeError(f"cannot enumerate {name}: {result}")
        count = sum(line.endswith(": test") for line in
                    (directory / f"list-{name}.log").read_text().splitlines())
        if count < 1:
            raise RuntimeError(f"empty suite: {name}")
        manifest[name]["expected_tests"] = count
    save_json(directory / "binaries.json", manifest)
    return executables


def worker(directory):
    os.umask(0o077)
    config = json.loads((directory / "config.json").read_text())
    began = time.monotonic()
    deadline = began + config["max_seconds"]
    status = {"state": "building", "revision": config["revision"], "pid": os.getpid(),
              "identity": process_identity(os.getpid()), "completed_rounds": 0,
              "requested_rounds": config["rounds"], "passed_tests": 0,
              "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    save_json(directory / "status.json", status)
    exit_code = 1
    try:
        binaries = prepare(directory, config, deadline)
        manifest_path = directory / "binaries.json"
        manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
        status["state"] = "running"
        for round_number in range(1, config["rounds"] + 1):
            for name, binary in binaries.items():
                if time.monotonic() >= deadline:
                    status["state"] = "incomplete"
                    raise RuntimeError("campaign wall-time limit reached")
                if shutil.disk_usage(directory).free < (512 << 20):
                    raise RuntimeError("less than 512 MiB free; stopping to preserve evidence")
                status.update(current_round=round_number, current_suite=name,
                              elapsed_seconds=round(time.monotonic() - began, 1))
                save_json(directory / "status.json", status)
                log = directory / f"round-{round_number:04d}-{name}.log"
                result = run_child([str(binary), "--include-ignored", "--test-threads=1", "--color=never"],
                                   Path(config["source"]), log, directory / "STOP",
                                   min(config["suite_timeout"], deadline - time.monotonic()))
                status["last_result"] = {"suite": name, "round": round_number, "log": str(log), **result}
                if result["reason"] != "exited" or result["exit_code"] != 0:
                    status["state"] = {"cancelled": "cancelled", "timeout": "incomplete"}.get(
                        result["reason"], "failed")
                    raise RuntimeError(f"suite did not complete: {status['last_result']}")
                count = passed_count(log.read_text(errors="replace"))
                if name in manifest and count != manifest[name]["expected_tests"]:
                    raise ValueError(f"{name}: passed test count changed")
                status["passed_tests"] += count
                with (directory / "results.jsonl").open("a") as out:
                    out.write(json.dumps({**status["last_result"], "passed_tests": count}) + "\n")
                    out.flush()
                    os.fsync(out.fileno())
            status["completed_rounds"] = round_number
            save_json(directory / "status.json", status)
        status["state"] = "passed"
        exit_code = 0
    except Exception as error:
        if (directory / "STOP").exists():
            status["state"] = "cancelled"
        elif status["state"] not in TERMINAL:
            status["state"] = "failed"
        status["error"] = f"{type(error).__name__}: {error}"
    finally:
        status.update(exit_code=exit_code, elapsed_seconds=round(time.monotonic() - began, 1),
                      finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
        save_json(directory / "status.json", status)
    return exit_code


def start(args):
    repo = Path(__file__).resolve().parents[1]
    subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=repo, check=True)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    logs = Path.home() / "logs"
    logs.mkdir(mode=0o700, exist_ok=True)
    logs.chmod(0o700)
    if shutil.disk_usage(logs).free < (2 << 30):
        raise RuntimeError("at least 2 GiB of free space is required before building")
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = logs / f"maki-storage-{stamp}-{uuid.uuid4().hex[:6]}"
    directory.mkdir(mode=0o700)
    source = directory / "source"
    source.mkdir(mode=0o700)
    archive = directory / "source.tar"
    subprocess.run(["git", "archive", "--format=tar", f"--output={archive}", revision], cwd=repo, check=True)
    subprocess.run(["tar", "-xf", str(archive), "-C", str(source)], check=True)
    runner = directory / "runner.py"
    shutil.copyfile(__file__, runner)
    runner.chmod(0o400)
    save_json(directory / "config.json", {
        "revision": revision, "source": str(source), "target_dir": str(repo / "target"),
        "rounds": args.rounds, "max_seconds": args.max_seconds, "suite_timeout": args.suite_timeout,
        "source_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "runner_sha256": hashlib.sha256(runner.read_bytes()).hexdigest(),
        "suites": SUITES,
        "rustc": subprocess.check_output(["rustc", "-Vv"], text=True),
        "cargo": subprocess.check_output(["cargo", "-V"], text=True).strip(),
    })
    with os.fdopen(os.open(directory / "supervisor.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as log:
        process = subprocess.Popen([sys.executable, "-B", str(runner), "_worker", "--run-dir", str(directory)],
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)
    controller = {"run_dir": str(directory), "pid": process.pid, "identity": process_identity(process.pid)}
    save_json(directory / "controller.json", controller)
    save_json(logs / "maki-storage-latest.json", controller)
    print(json.dumps(controller, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("start", "status", "cancel", "_worker"))
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument("--rounds", type=int, default=100)
    parser.add_argument("--max-seconds", type=int, default=21600)
    parser.add_argument("--suite-timeout", type=int, default=900)
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("this runner requires Linux")
    if min(args.rounds, args.max_seconds, args.suite_timeout) < 1:
        parser.error("budgets must be positive")
    os.umask(0o077)
    if args.action == "start":
        start(args)
        return 0
    directory = args.run_dir or Path(json.loads((Path.home() / "logs/maki-storage-latest.json").read_text())["run_dir"])
    if args.action == "_worker":
        return worker(directory)
    if args.action == "cancel":
        (directory / "STOP").touch(mode=0o600)
    controller = json.loads((directory / "controller.json").read_text())
    status_path = directory / "status.json"
    status = json.loads(status_path.read_text()) if status_path.exists() else {"state": "starting"}
    status.update(run_dir=str(directory), controller_alive=alive(controller))
    if status["state"] not in TERMINAL and not status["controller_alive"]:
        status.update(state="interrupted", detail="controller exited without a terminal report; this is not a pass")
    print(json.dumps(status, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
