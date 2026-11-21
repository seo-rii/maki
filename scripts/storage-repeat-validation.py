#!/usr/bin/env python3
"""Repeat existing Linux storage regressions using frozen source and binaries."""
import argparse
from contextlib import ExitStack
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid


SUITES = ("phase11_dbsim", "phase12_powerloss", "review_stress",
          "review_r3_space_admission", "review_r3_recovery_memory",
          "review_discard_crash", "review_discard_model",
          "review_discard_reclaim_retry")
PROFILES = {
    "storage": {"maki-core": SUITES},
    "rollback": {
        "maki-backing": ("rollback_backing", "rollback_model"),
        "maki-core": ("rollback_protection", "rollback_process"),
    },
}
TERMINAL = {"passed", "failed", "cancelled", "incomplete"}


def suite_groups(config):
    profile = config.get("profile", "storage")
    if profile not in PROFILES:
        raise ValueError(f"unknown storage test profile: {profile}")
    return PROFILES[profile]


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(128 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def save_json(path, value, before_publish=None):
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(value, out, indent=2, sort_keys=True)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        if before_publish is not None and not before_publish():
            return False
        os.replace(temporary, path)
        return True
    finally:
        temporary.unlink(missing_ok=True)


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


RESULT_PREFIX = "test result: ok. "
RESULT_SUFFIX = " passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;"
RESULT_PATTERN = re.compile(re.escape(RESULT_PREFIX) + r"(\d+)" + re.escape(RESULT_SUFFIX))
RESULT_DIGITS = re.compile(r"\d*")


def passed_count(stream):
    # Retain only an unfinished summary, including a partial prefix at a chunk
    # boundary. Even a diagnostic line without newlines can span the entire log.
    if isinstance(stream, str):
        stream = io.StringIO(stream)
    count = None
    carry = ""
    # Libtest's count fits usize. Preserve Python's normal decimal conversion
    # limit as well, and retain one extra digit to reject an oversized match.
    digit_limit = getattr(sys, "get_int_max_str_digits", lambda: 0)() or 4300
    while chunk := stream.read(64 * 1024):
        window = carry + chunk
        end = 0
        for match in RESULT_PATTERN.finditer(window):
            if count is not None or len(match[1]) > digit_limit:
                raise ValueError("duplicate or oversized test result")
            count = int(match[1])
            end = match.end()
        start = window.rfind(RESULT_PREFIX, end)
        if start >= 0:
            digits = RESULT_DIGITS.match(window, start + len(RESULT_PREFIX))
            rest = window[digits.end():]
            if RESULT_SUFFIX.startswith(rest):
                keep = min(digits.end(), digits.start() + digit_limit + 1)
                carry = window[start:keep] + rest
                continue
        carry = window[max(end, len(window) - len(RESULT_PREFIX) + 1):]
    if not count:
        raise ValueError("missing, empty, filtered or incomplete test result")
    return count


def run_child(command, cwd, log, stop, timeout, max_bytes=64 << 20, env=None):
    began = time.monotonic()
    if stop.exists():
        return {"exit_code": 130, "reason": "cancelled", "seconds": 0}

    received_signal = None

    def request_stop(number, _frame):
        nonlocal received_signal
        received_signal = number

    previous = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT)}
    try:
        # Install before Popen, and only record the request in the handler. An
        # exception during Popen could escape before we own its returned child.
        for number in previous:
            signal.signal(number, request_stop)
        with os.fdopen(os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
            child = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                     stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            reason = "exited"
            try:
                # Keep the leader unreaped until group cleanup, so its PID
                # cannot be reused for an unrelated process group.
                while os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                    if received_signal is not None or stop.exists():
                        reason = "cancelled"
                    elif time.monotonic() - began >= timeout:
                        reason = "timeout"
                    elif log.stat().st_size > max_bytes:
                        reason = "output_limit"
                    if reason != "exited":
                        break
                    time.sleep(.1)
            finally:
                # Kill descendants also after an early leader exit.
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait()
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    if received_signal is not None:
        # Reuse the cancellation marker so build-time interruption also
        # reaches worker() as cancellation rather than a build failure.
        stop.touch(mode=0o600)
    # The leader can exit during the polling interval, skipping the loop's
    # limit checks. Cancellation also takes precedence during group cleanup;
    # otherwise retain any limit reason already observed while it was alive.
    if received_signal is not None or stop.exists():
        reason = "cancelled"
    elif reason == "exited":
        if time.monotonic() - began >= timeout:
            reason = "timeout"
        elif log.stat().st_size > max_bytes:
            reason = "output_limit"
    result = {"exit_code": child.returncode, "reason": reason,
              "seconds": round(time.monotonic() - began, 3)}
    if received_signal is not None:
        result["signal"] = received_signal
    return result


def cargo_compiler(source, directory, environment, remaining):
    # Cargo gives build scripts its resolved compiler and both wrapper paths.
    # Run from the same cwd as the campaign so Cargo and rustup load its configuration.
    with tempfile.TemporaryDirectory(dir=directory, prefix="toolchain-") as temporary:
        probe = Path(temporary)
        (probe / "Cargo.toml").write_text(
            '[workspace]\n[package]\nname = "maki-toolchain-probe"\nversion = "0.0.0"\n'
            'edition = "2021"\n[lib]\npath = "lib.rs"\n')
        (probe / "lib.rs").touch()
        (probe / "build.rs").write_text("""
use std::{env, fs, process::Command};

fn main() {
    let compiler = env::var_os("RUSTC").unwrap();
    let mut command = ["RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"].iter()
        .filter_map(env::var_os)
        .filter(|path| !path.is_empty())
        .chain(std::iter::once(compiler.clone()));
    let version = Command::new(command.next().unwrap()).args(command).arg("-vV")
        .current_dir(env::var_os("MAKI_PROBE_SOURCE").unwrap()).output().unwrap();
    assert!(version.status.success(), "{}", String::from_utf8_lossy(&version.stderr));
    fs::write("rustc-path", compiler.as_encoded_bytes()).unwrap();
    fs::write("rustc-version", version.stdout).unwrap();
    fs::write("rust-target", env::var("TARGET").unwrap()).unwrap();
}
""")
        environment = dict(environment, CARGO_TARGET_DIR=str(probe / "target"),
                           CARGO_BUILD_BUILD_DIR=str(probe / "build"), MAKI_PROBE_SOURCE=str(source))
        command = ["cargo", "check", "--quiet", "--offline", "--manifest-path", str(probe / "Cargo.toml")]
        result = run_child(command, source, directory / "toolchain.log", directory / "STOP",
                           remaining(1800), env=environment)
        if result["reason"] == "timeout":
            raise TimeoutError(f"compiler probe timed out: {result}")
        if result["exit_code"] != 0 or result["reason"] != "exited":
            raise RuntimeError(f"compiler probe did not complete (see toolchain.log): {result}")
        return (os.fsdecode((probe / "rustc-path").read_bytes()), (probe / "rustc-version").read_text(),
                (probe / "rust-target").read_text())


def prepare(directory, config, deadline):
    groups = suite_groups(config)
    source = Path(config["source"])
    stop = directory / "STOP"

    def remaining(limit):
        if stop.exists():
            raise RuntimeError("preparation cancelled")
        budget = deadline - time.monotonic()
        if budget <= 0:
            raise TimeoutError("campaign wall-time limit reached during preparation")
        return min(limit, budget)

    environment = os.environ.copy()
    # Separate target directories do not isolate Cargo's intermediate cache
    # when the shell or Cargo configuration supplies a shared build directory.
    environment.update(CARGO_TARGET_DIR=config["target_dir"],
                       CARGO_BUILD_BUILD_DIR=str(directory / "build"), CARGO_BUILD_JOBS="2")
    config["rustc_executable"], config["rustc"], target = cargo_compiler(source, directory, environment, remaining)
    save_json(directory / "config.json", config)
    # Cargo sets a package-specific loader path for each test invocation,
    # including its sysroot and dynamic dependencies in the isolated build.
    # Capture that path without executing the test before it has been frozen.
    remaining(1800)
    runner = directory / "maki-capture-test-environment"
    runner.write_text(
        "#!/usr/bin/env python3\nimport json, os, sys\n"
        "print(json.dumps({'reason': 'maki-test-runtime', 'executable': sys.argv[1], "
        "'library_path': os.environ['LD_LIBRARY_PATH']}))\n")
    runner.chmod(0o500)
    environment["PATH"] = str(runner.parent) + os.pathsep + environment.get("PATH", os.defpath)
    environment["CARGO_TARGET_" + target.upper().replace("-", "_") + "_RUNNER"] = runner.name
    library_paths = {}
    executables = {}
    suites = [suite for group in groups.values() for suite in group]
    for package, selected in groups.items():
        command = ["cargo", "test", "--offline", "--locked", "-p", package,
                   "--message-format=json"]
        for suite in selected:
            command.extend(["--test", suite])
        command.extend(["--", "--list"])
        log = directory / ("build.log" if len(groups) == 1 else f"build-{package}.log")
        result = run_child(command, source, log, stop, remaining(1800), env=environment)
        if result["reason"] == "timeout":
            raise TimeoutError(f"{package} build did not complete: {result}")
        if result["exit_code"] != 0 or result["reason"] != "exited":
            raise RuntimeError(f"{package} build did not complete: {result}")
        remaining(1800)
        for line in log.read_text(errors="replace").splitlines():
            if not line.startswith("{"):
                continue
            event = json.loads(line)
            if event.get("reason") == "maki-test-runtime":
                library_paths[Path(event["executable"])] = event["library_path"]
                continue
            name = event.get("target", {}).get("name")
            if (event.get("reason") == "compiler-artifact" and name in selected
                    and event.get("executable")):
                executables[name] = Path(event["executable"])
    if set(executables) != set(suites):
        raise RuntimeError("build did not produce every requested test binary")
    binary_dir = directory / "bin"
    binary_dir.mkdir(mode=0o700)
    manifest = {}
    for name, original in executables.items():
        remaining(30)
        if original not in library_paths:
            raise RuntimeError(f"Cargo did not report a runtime environment for {name}")
        library_path = library_paths[original]
        frozen = binary_dir / name
        shutil.copyfile(original, frozen)
        frozen.chmod(0o500)
        executables[name] = frozen
        manifest[name] = {"sha256": sha256_file(frozen),
                          "library_path": library_path}
        result = run_child([str(frozen), "--list", "--include-ignored"], source,
                           directory / f"list-{name}.log", stop, remaining(30),
                           env=dict(os.environ, LD_LIBRARY_PATH=library_path))
        if result["reason"] == "timeout":
            raise TimeoutError(f"cannot enumerate {name}: {result}")
        if result["exit_code"] != 0 or result["reason"] != "exited":
            raise RuntimeError(f"cannot enumerate {name}: {result}")
        count = sum(line.endswith(": test") for line in
                    (directory / f"list-{name}.log").read_text().splitlines())
        if count < 1:
            raise RuntimeError(f"empty suite: {name}")
        manifest[name]["expected_tests"] = count
    remaining(30)
    save_json(directory / "binaries.json", manifest)
    return executables


def worker(directory):
    os.umask(0o077)
    config = json.loads((directory / "config.json").read_text())
    began = time.monotonic()
    deadline = began + config["max_seconds"]
    status = {"state": "building", "revision": config["revision"],
              "profile": config.get("profile", "storage"), "pid": os.getpid(),
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
                environment = os.environ.copy()
                if name in manifest:
                    environment["LD_LIBRARY_PATH"] = manifest[name]["library_path"]
                result = run_child([str(binary), "--include-ignored", "--test-threads=1", "--color=never"],
                                   Path(config["source"]), log, directory / "STOP",
                                   min(config["suite_timeout"], deadline - time.monotonic()), env=environment)
                status["last_result"] = {"suite": name, "round": round_number, "log": str(log), **result}
                if result["reason"] != "exited" or result["exit_code"] != 0:
                    status["state"] = {"cancelled": "cancelled", "timeout": "incomplete"}.get(
                        result["reason"], "failed")
                    raise RuntimeError(f"suite did not complete: {status['last_result']}")
                with log.open(errors="replace") as output:
                    count = passed_count(output)
                if name in manifest and count != manifest[name]["expected_tests"]:
                    raise ValueError(f"{name}: passed test count changed")
                status["passed_tests"] += count
                with (directory / "results.jsonl").open("a") as out:
                    out.write(json.dumps({**status["last_result"], "passed_tests": count}) + "\n")
                    out.flush()
                    os.fsync(out.fileno())
            status["completed_rounds"] = round_number
            save_json(directory / "status.json", status)
        # Include final result parsing and persistence in the campaign budget.
        if (directory / "STOP").exists():
            raise RuntimeError("campaign cancelled")
        if time.monotonic() >= deadline:
            raise TimeoutError("campaign wall-time limit reached")
        status["state"] = "passed"
        exit_code = 0
    except Exception as error:
        if (directory / "STOP").exists():
            status["state"] = "cancelled"
        elif isinstance(error, TimeoutError):
            status["state"] = "incomplete"
        elif status["state"] not in TERMINAL:
            status["state"] = "failed"
        status["error"] = f"{type(error).__name__}: {error}"
    finally:
        status.update(exit_code=exit_code, elapsed_seconds=round(time.monotonic() - began, 1),
                      finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat())

        def eligible_to_publish():
            # Completion is decided after the candidate report's blocking
            # flush/fsync, immediately before its atomic publication. Requests
            # arriving after that decision do not revoke a completed campaign.
            return status["state"] != "passed" or (
                not (directory / "STOP").exists() and time.monotonic() < deadline)

        if not save_json(directory / "status.json", status, before_publish=eligible_to_publish):
            cancelled = (directory / "STOP").exists()
            exit_code = 1
            status.update(state="cancelled" if cancelled else "incomplete", exit_code=exit_code,
                          error="campaign cancelled" if cancelled else "campaign wall-time limit reached",
                          elapsed_seconds=round(time.monotonic() - began, 1),
                          finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
            # A rejected candidate remains private. Publish a non-pass once;
            # further cancellation or delay cannot turn it back into success.
            save_json(directory / "status.json", status)
    return exit_code


def qualification_source():
    # The detached worker is a standalone copy; only the launcher needs this module.
    try:
        import qualification_source as snapshot
    except ModuleNotFoundError:
        from scripts import qualification_source as snapshot
    return snapshot


def start(args):
    profile = getattr(args, "profile", "storage")
    groups = suite_groups({"profile": profile})
    repo = Path(__file__).resolve().parents[1]
    snapshot = qualification_source()
    revision = snapshot.clean_revision(repo)
    logs = Path.home() / "logs"
    logs.mkdir(mode=0o700, exist_ok=True)
    logs.chmod(0o700)
    if shutil.disk_usage(logs).free < (2 << 30):
        raise RuntimeError("at least 2 GiB of free space is required before building")
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = logs / f"maki-storage-{stamp}-{uuid.uuid4().hex[:6]}"
    with ExitStack() as preparation:
        directory.mkdir(mode=0o700)
        preparation.callback(shutil.rmtree, directory)
        source = directory / "source"
        source.mkdir(mode=0o700)
        target = directory / "target"
        target.mkdir(mode=0o700)
        archive = directory / "source.tar"
        snapshot.extract_revision(repo, revision, archive, source)
        runner = directory / "runner.py"
        shutil.copyfile(source / "scripts/storage-repeat-validation.py", runner)
        runner.chmod(0o400)
        save_json(directory / "config.json", {
            "revision": revision, "source": str(source), "target_dir": str(target),
            "build_dir": str(directory / "build"),
            "rounds": args.rounds, "max_seconds": args.max_seconds, "suite_timeout": args.suite_timeout,
            "source_sha256": sha256_file(archive),
            "runner_sha256": sha256_file(runner),
            "profile": profile,
            "suites": [suite for group in groups.values() for suite in group],
            "cargo": subprocess.check_output(["cargo", "-V"], cwd=source, text=True).strip(),
        })
        with os.fdopen(os.open(directory / "supervisor.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as log:
            process = subprocess.Popen([sys.executable, "-B", str(runner), "_published_worker", "--run-dir", str(directory)],
                                       stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT,
                                       start_new_session=True)
        # Once the worker exists, preserve its directory and let the
        # publication gate below manage its lifetime.
        preparation.pop_all()
    # The worker waits for this byte before spawning any build. A publication
    # failure or a controller crash closes the pipe without starting a campaign.
    try:
        with process.stdin as gate:
            controller = {"run_dir": str(directory), "pid": process.pid, "identity": process_identity(process.pid)}
            save_json(directory / "controller.json", controller)
            save_json(logs / "maki-storage-latest.json", controller)
            gate.write(b"1")
    except BaseException:
        process.wait()
        raise
    print(json.dumps(controller, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("start", "status", "cancel", "_worker", "_published_worker"))
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument("--profile", choices=tuple(PROFILES), default="storage")
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
    if args.action == "_published_worker":
        if sys.stdin.buffer.read(1) != b"1":
            return 1
        return worker(directory)
    if args.action == "_worker":
        return worker(directory)
    controller = json.loads((directory / "controller.json").read_text())
    status_path = directory / "status.json"
    status = json.loads(status_path.read_text()) if status_path.exists() else {"state": "starting"}
    status.update(run_dir=str(directory), controller_alive=alive(controller))
    if args.action == "cancel":
        if Path(controller["run_dir"]).resolve() != directory.resolve():
            parser.error("controller does not belong to this campaign directory")
        if status["state"] not in TERMINAL and status["controller_alive"]:
            (directory / "STOP").touch(mode=0o600)
    if status["state"] not in TERMINAL and not status["controller_alive"]:
        status.update(state="interrupted", detail="controller exited without a terminal report; this is not a pass")
    print(json.dumps(status, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
