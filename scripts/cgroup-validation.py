#!/usr/bin/env python3
"""Opt-in, disposable userspace NBD faults. This never attaches a block device.

Run under a background supervisor with stdout/stderr redirected from launch.
An existing local image built with cgroup-validation.Dockerfile is required.
The host needs Docker, libnbd.so.0, and Python 3. No Python packages are needed.
"""
import argparse
from contextlib import contextmanager
import ctypes
import hashlib
import json
import os
import pathlib
import socket
import subprocess
import sys
import time
import uuid

try:
    from campaign_io import save_json
except ModuleNotFoundError:
    from scripts.campaign_io import save_json


def ensure(condition, message):
    # Qualification gates must remain active under python -O/PYTHONOPTIMIZE.
    if not condition:
        raise AssertionError(message)


def durable_write(client, ledger, writes, mode):
    """Record only completed barriers; the ledger is outside the killed group."""
    if mode not in ("flush", "fua"):
        raise ValueError("durability mode must be flush or fua")
    pending = []
    for offset, data in writes:
        client.write(offset, data, fua=mode == "fua")
        record = {"offset": offset, "length": len(data),
                  "sha256": hashlib.sha256(data).hexdigest(), "barrier": mode}
        if mode == "fua":
            with ledger.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
        else:
            pending.append(record)
    if mode == "flush":
        client.flush()
        with ledger.open("a", encoding="utf-8") as stream:
            for record in pending:
                stream.write(json.dumps(record) + "\n")
            stream.flush()
            os.fsync(stream.fileno())


def epoch_writes(epoch):
    flush = [(i * 4096, hashlib.sha256(f"{epoch}:{i}".encode()).digest() * 128)
             for i in range(128)]
    fua = [((128 + i) * 4096, bytes([(epoch + i + 1) % 256]) * 4096) for i in range(8)]
    return (("flush", flush), ("fua", fua))


def verify(client, ledger, expected_rounds=None):
    latest = {}
    records = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines()]
    if expected_rounds is not None:
        expected = ({"offset": offset, "length": len(data), "barrier": mode,
                     "sha256": hashlib.sha256(data).hexdigest()}
                    for epoch in range(expected_rounds)
                    for mode, writes in epoch_writes(epoch) for offset, data in writes)
        for recorded, planned in zip(records, expected, strict=True):
            if recorded != planned:
                raise ValueError("durable ACK ledger differs from the planned workload")
    for record in records:
        offset, length = record["offset"], record["length"]
        if offset < 0 or offset % 4096 or length != 4096:
            raise ValueError("oracle accepts aligned, non-overlapping 4 KiB units only")
        latest[offset] = record
    if not latest:
        raise ValueError("an empty oracle cannot qualify durable data")
    for offset, record in latest.items():
        actual = client.read(offset, record["length"])
        if hashlib.sha256(actual).hexdigest() != record["sha256"]:
            raise AssertionError(f"durable data mismatch at offset {offset}")
    return len(latest)


def require_oom(state):
    ensure(not state["Running"], "OOM target is still running")
    ensure(state["OOMKilled"], "exit status alone does not establish OOMKilled")
    ensure(state["ExitCode"] == 137, f"unexpected OOM exit: {state['ExitCode']}")


def require_pressure(progress):
    ensure(progress["completed"] > 0 and progress["attempted"] >= progress["completed"],
           "workload-triggered OOM requires completed pressure I/O")


@contextmanager
def unix_socket_path(path):
    # Linux resolves this short path through the calling process's open directory.
    # Both the socket inode and the Docker bind mount stay in the artifact directory.
    path = pathlib.Path(path)
    directory = os.open(path.parent, os.O_DIRECTORY)
    try:
        yield f"/proc/self/fd/{directory}/{path.name}"
    finally:
        os.close(directory)


class Nbd:
    """Small libnbd synchronous client, always run in a deadline-bound child."""
    def __init__(self, path, connected_fd=None):
        self.lib = ctypes.CDLL("libnbd.so.0")
        signatures = {
            "create": (ctypes.c_void_p, []),
            "get_error": (ctypes.c_char_p, []),
            "connect_unix": (ctypes.c_int, [ctypes.c_void_p, ctypes.c_char_p]),
            "connect_socket": (ctypes.c_int, [ctypes.c_void_p, ctypes.c_int]),
            "can_fua": (ctypes.c_int, [ctypes.c_void_p]),
            "can_flush": (ctypes.c_int, [ctypes.c_void_p]),
            "pwrite": (ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint64, ctypes.c_uint32]),
            "pread": (ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint64, ctypes.c_uint32]),
            "flush": (ctypes.c_int, [ctypes.c_void_p, ctypes.c_uint32]),
            "close": (None, [ctypes.c_void_p]),
        }
        for name, (result, args) in signatures.items():
            function = getattr(self.lib, "nbd_" + name)
            function.restype, function.argtypes = result, args
        self.handle = self.lib.nbd_create()
        if not self.handle:
            raise RuntimeError("libnbd handle allocation failed")
        try:
            with unix_socket_path(path) as address:
                if connected_fd is None:
                    self.check(self.lib.nbd_connect_unix(self.handle, os.fsencode(address)))
                else:
                    # Queue the connection on the frozen server's socket before
                    # telling the controller to start its observation interval.
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                        client.connect(os.fsencode(address))
                        os.write(connected_fd, b"C")
                        os.close(connected_fd)
                        self.check(self.lib.nbd_connect_socket(self.handle, client.fileno()))
                        client.detach()  # libnbd owns the descriptor on success
            ensure(self.lib.nbd_can_fua(self.handle) == 1, "native FUA required")
            ensure(self.lib.nbd_can_flush(self.handle) == 1, "FLUSH required")
        except BaseException:
            self.close()
            raise

    def check(self, result):
        if result < 0:
            raise RuntimeError(self.lib.nbd_get_error().decode(errors="replace"))

    def write(self, offset, data, fua=False):
        buffer = ctypes.create_string_buffer(data)
        self.check(self.lib.nbd_pwrite(self.handle, buffer, len(data), offset, int(fua)))

    def read(self, offset, length):
        buffer = ctypes.create_string_buffer(length)
        self.check(self.lib.nbd_pread(self.handle, buffer, length, offset, 0))
        return buffer.raw

    def flush(self):
        self.check(self.lib.nbd_flush(self.handle, 0))

    def close(self):
        self.lib.nbd_close(self.handle)


def client_main(args):
    client = Nbd(args.socket, args.connected_fd)
    try:
        if args.mode == "verify":
            print(json.dumps({"verified_units": verify(client, args.ledger, args.rounds)}))
        elif args.mode == "pressure":
            # Distinct non-durable writes cannot overwrite the durable oracle.
            # 64 MiB of pending ciphertext deliberately exceeds a 32 MiB cgroup.
            progress = {"attempted": 0, "completed": 0}
            progress_path = args.ledger.with_name("pressure-progress.json")
            for index in range(256):
                progress["attempted"] += 1
                progress_path.write_text(json.dumps(progress))
                client.write((2 << 20) + index * (256 << 10), bytes([index % 251]) * (256 << 10))
                progress["completed"] += 1
                progress_path.write_text(json.dumps(progress))
            print(json.dumps({"pressure_bytes_written": 64 << 20}))
        else:
            for epoch in range(args.start_epoch, args.start_epoch + args.rounds):
                for mode, writes in epoch_writes(epoch):
                    durable_write(client, args.ledger, writes, mode)
            # No barrier for the tail: its survival is not claimed or required.
            client.write(1 << 20, b"T" * 4096)
            print(json.dumps({"flush_acks": args.rounds, "fua_acks": args.rounds * 8}))
    finally:
        client.close()


def run(command, *, timeout=45, check=True):
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"command {command[0:2]} exited {result.returncode}: {result.stderr[-2000:]}")
    return result


@contextmanager
def remove_after(target):
    try:
        yield
    except BaseException as error:
        name = target.pending_identifier or target.identifier
        try:
            target.remove()
        except Exception as cleanup_error:
            raise RuntimeError(f"{type(error).__name__}: {error}; "
                               f"cleanup for {name} failed: {cleanup_error}") from error
        raise
    else:
        target.remove()


class Target:
    def __init__(self, image, directory):
        self.image = image
        self.directory = directory
        self.case = directory / "backing-case"
        self.case.mkdir(mode=0o700)
        self.ledger = directory / "host-acks.jsonl"
        self.identifier = None
        self.pending_identifier = None
        self.serial = 0
        self.token = uuid.uuid4().hex
        self.notify = None
        (self.case / "key").write_bytes(os.urandom(32))
        (self.case / "key").chmod(0o600)
        (self.case / "config.toml").write_text('''config_schema_version = 1
[volume]
name = "cgroup-disposable"
max_virtual_size = "128MiB"
shard_logical_size = "16MiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "cgroup-qualification-v1"
key = { source = "file", name = "/case/key" }
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4124
[backing]
root = "/case/volume"
journal_segment_size = "16MiB"
journal_max_bytes = "128MiB"
checkpoint_reserve_bytes = "16MiB"
journal_emergency_reserve_bytes = "8MiB"
[nbd]
threads = 2
[control]
socket = "/case/control.sock"
''')
        self.one_shot(["/opt/maki/maki", "volume", "create", "/case/config.toml"])

    def one_shot(self, command):
        # Killing the Docker CLI does not terminate its container.
        with remove_after(self):
            self.create("192m", "1", command)
            return run(["docker", "start", "--attach", self.identifier], timeout=120)

    def options(self, memory, cpus):
        # --mount uses CSV, including for a single argv element.
        source = str(self.case).replace('"', '""')
        return ["--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true", "--user", f"{os.getuid()}:{os.getgid()}",
                "--pids-limit", "64", "--memory", memory, "--memory-swap", memory,
                "--cpus", cpus, "--label", "maki.failure-validation=" + self.token,
                "--mount", f'type=bind,"src={source}",dst=/case']

    def state(self, timeout=45):
        return json.loads(run(["docker", "inspect", "--format", "{{json .State}}", self.identifier],
                              timeout=timeout).stdout)

    def wait_for_oom(self):
        until = time.monotonic() + 10
        while (remaining := until - time.monotonic()) > 0:
            try:
                state = self.state(timeout=remaining)
            except subprocess.TimeoutExpired:
                break
            remaining = until - time.monotonic()
            if remaining <= 0:
                break
            if not state["Running"]:
                require_oom(state)
                return state
            time.sleep(min(0.1, remaining))
        raise TimeoutError("container OOM was not observed within 10 seconds")

    def create(self, memory, cpus, command, extra=()):
        ensure(self.identifier is None and self.pending_identifier is None,
               "previous owned container has not been removed")
        self.serial += 1
        # Docker may have created the container even if its CLI did not return success.
        self.pending_identifier = f"maki-fault-{self.token}-{self.serial}"
        run(["docker", "create", "--name", self.pending_identifier, *self.options(memory, cpus),
             *extra, self.image, *command])
        self.identifier = self.pending_identifier
        self.pending_identifier = None

    def start(self, memory="192m", cpus="1"):
        ensure(self.identifier is None and self.pending_identifier is None,
               "previous owned container has not been removed")
        for name in ("nbd.sock", "ready.sock"):
            (self.case / name).unlink(missing_ok=True)
        self.notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        with unix_socket_path(self.case / "ready.sock") as address:
            self.notify.bind(address)
        # Maki is PID 1: no shell, init, sidecar or stress helper is the OOM victim.
        self.create(memory, cpus, [
            "nbdkit", "--foreground", "--threads", "4", "-U", "/case/nbd.sock",
            "/opt/maki/libmaki_nbdkit.so", "config=/case/config.toml",
        ], extra=["--env", "NOTIFY_SOCKET=/case/ready.sock"])
        run(["docker", "start", self.identifier])
        until = time.monotonic() + 30
        while (remaining := until - time.monotonic()) > 0:
            self.notify.settimeout(min(0.1, remaining))
            try:
                if b"READY=1" in self.notify.recv(4096).splitlines():
                    return
            except socket.timeout:
                pass
            remaining = until - time.monotonic()
            if remaining <= 0:
                break
            try:
                state = self.state(timeout=remaining)
            except subprocess.TimeoutExpired:
                break
            if not state["Running"]:
                raise RuntimeError("native startup failed before READY")
        raise TimeoutError("native startup did not announce READY")

    def stats(self):
        result = {}
        # Startup can remain alive without READY. Resolve the current PID,
        # rather than reusing the previous (removed) container's cgroup.
        state = self.state()
        memberships = pathlib.Path(f"/proc/{state['Pid']}/cgroup").read_text().splitlines()
        relative = next(line[3:] for line in memberships if line.startswith("0::"))
        cgroup = pathlib.Path("/sys/fs/cgroup") / relative.lstrip("/")
        for name in ("memory.current", "memory.peak", "memory.max", "memory.swap.max",
                     "memory.events", "cpu.max", "cpu.stat", "pids.max", "pids.events"):
            try:
                result[name] = (cgroup / name).read_text().strip()
            except OSError as error:
                result[name] = f"unavailable: {error.__class__.__name__}"
        try:
            process_status = pathlib.Path(f"/proc/{state['Pid']}/status").read_text().splitlines()
            wanted = {"VmRSS", "VmHWM", "RssAnon", "RssFile", "RssShmem"}
            for line in process_status:
                name, separator, value = line.partition(":")
                if separator and name in wanted:
                    fields = value.split()
                    ensure(len(fields) == 2 and fields[1] == "kB",
                           f"unexpected {name} process status value")
                    result[f"process.{name}.bytes"] = int(fields[0]) * 1024
        except OSError as error:
            result["process.status"] = f"unavailable: {error.__class__.__name__}"
        return result

    def client_command(self, mode, rounds=1, start_epoch=0):
        return [sys.executable, str(pathlib.Path(__file__).resolve()), "--client",
                "--socket", str(self.case / "nbd.sock"), "--ledger", str(self.ledger),
                "--mode", mode, "--rounds", str(rounds), "--start-epoch", str(start_epoch)]

    def client(self, mode, rounds=1, check=True):
        result = run(self.client_command(mode, rounds), timeout=120, check=check)
        record = {"exit_code": result.returncode, "stdout": result.stdout[-2000:], "stderr": result.stderr[-2000:]}
        if check:
            ensure(result.stdout.strip(), "client returned no verification evidence")
        if mode == "verify":
            ensure(json.loads(result.stdout)["verified_units"] == 136, "incomplete recovery readback")
        return record

    def freeze_and_resume(self, directory, start_epoch):
        before = self.ledger.read_bytes()
        run(["docker", "pause", self.identifier])
        receiver, sender = socket.socketpair()
        with receiver, sender, (directory / "paused-client.log").open("w") as stream:
            command = self.client_command("write", start_epoch=start_epoch)
            descriptor = sender.fileno()
            child = subprocess.Popen([*command, "--connected-fd", str(descriptor)],
                                     pass_fds=(descriptor,), stdout=stream, stderr=subprocess.STDOUT)
            sender.close()
            try:
                receiver.settimeout(30)
                ensure(receiver.recv(1) == b"C", "client did not connect to the paused server")
                time.sleep(0.5)
                ensure(child.poll() is None, "paused server unexpectedly completed client")
                ensure(self.ledger.read_bytes() == before, "paused server produced a durable ACK")
                run(["docker", "unpause", self.identifier])
                ensure(child.wait(timeout=120) == 0, "resumed client failed")
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)

    def kill(self):
        run(["docker", "kill", "--signal", "KILL", self.identifier])
        run(["docker", "wait", self.identifier])
        state = self.state()
        ensure(not state["Running"] and state["ExitCode"] == 137 and not state["OOMKilled"],
               "SIGKILL scenario requires signal exit 137 without an OOM")
        return state

    def remove(self):
        if self.notify is not None:
            self.notify.close()
            self.notify = None
        if self.pending_identifier is not None:
            # Only act on the reserved name if Docker also confirms this campaign's label.
            owned = run(["docker", "ps", "--all", "--filter", "label=maki.failure-validation=" + self.token,
                         "--format", "{{.Names}}"])
            if self.pending_identifier in owned.stdout.splitlines():
                self.identifier = self.pending_identifier
            self.pending_identifier = None
        if self.identifier is None:
            return
        state = self.state()
        if state["Running"]:
            try:
                if state.get("Paused"):
                    run(["docker", "unpause", self.identifier])
                run(["docker", "kill", "--signal", "KILL", self.identifier])
                run(["docker", "wait", self.identifier])
            except (RuntimeError, subprocess.TimeoutExpired):
                # The container can exit between inspect and unpause/kill.
                # Only continue cleanup once Docker confirms it has stopped.
                if self.state()["Running"]:
                    raise
        # Logs are inspected/saved only after the container process has exited.
        try:
            output = run(["docker", "logs", "--tail", "60", self.identifier])
            (self.directory / f"container-{self.serial}.log").write_text(output.stdout + output.stderr)
        finally:
            run(["docker", "rm", self.identifier])
            self.identifier = None


def constrained_recovery(target, memory="32m", rounds=1):
    """Report availability at the requested cap without relaxing durability."""
    with remove_after(target):
        try:
            target.start(memory=memory)
        except (TimeoutError, RuntimeError) as error:
            if target.identifier is None:
                raise
            state = target.state()
            if isinstance(error, TimeoutError) and state["Running"]:
                try:
                    resources = target.stats()
                    termination = target.kill()
                except (OSError, RuntimeError, AssertionError, subprocess.TimeoutExpired):
                    # The process can OOM between inspect and reading /proc or killing it.
                    state = target.state()
                    if state["Running"]:
                        raise
                else:
                    return {"ready": False, "outcome": "startup-timeout", "deadline_seconds": 30,
                            "resources": resources, "state_before_cleanup": state,
                            "cleanup_termination": termination}
            require_oom(state)
            return {"ready": False, "outcome": "startup-oom", "termination": state}
        else:
            result = {"ready": True, "outcome": "verified", "verification": target.client("verify", rounds=rounds),
                      "resources": target.stats()}
            target.kill()
            return result


def campaign(args):
    os.umask(0o077)
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    report = {"requested_image": args.image, "provider": "local-aes-gcm-siv", "cases": [], "passed": False}
    try:
        details = json.loads(run(["docker", "info", "--format", "{{json .}}"]).stdout)
        ensure(details["CgroupVersion"] == "2", "cgroup v2 is required")
        for feature in ("MemoryLimit", "SwapLimit", "CpuCfsQuota", "PidsLimit"):
            ensure(details[feature], f"Docker lacks {feature}")
        report.update(kernel=os.uname().release, docker=details["ServerVersion"], cgroup=2)
        image_id = run(["docker", "image", "inspect", "--format", "{{.Id}}", args.image]).stdout.strip()
        report["image"] = image_id
        for scenario in ("cpu-memory-kill", "freeze-resume", "memory-oom"):
            record = {"scenario": scenario, "passed": False}
            report["cases"].append(record)
            directory = args.output / scenario
            directory.mkdir(mode=0o700)
            target = Target(image_id, directory)
            with remove_after(target):
                target.start(memory="96m", cpus="0.25" if scenario == "cpu-memory-kill" else "1")
                record["workload"] = target.client("write", rounds=args.rounds)
                record["resources"] = target.stats()
                if scenario == "cpu-memory-kill":
                    cpu = dict(line.split() for line in record["resources"]["cpu.stat"].splitlines())
                    ensure(int(cpu["nr_throttled"]) > 0, "no observed CPU throttling")
                    record["termination"] = target.kill()
                elif scenario == "freeze-resume":
                    target.freeze_and_resume(directory, args.rounds)
                    record["connected_while_paused"] = True
                    record["pause_seconds"] = 0.5
                    record["termination"] = target.kill()
                else:
                    run(["docker", "update", "--memory", "32m", "--memory-swap", "32m", target.identifier])
                    ensure(target.state()["Running"], "limit shrink killed target before pressure I/O")
                    record["pressure_resources"] = target.stats()
                    record["pressure_client"] = target.client("pressure", check=False)
                    record["pressure_progress"] = json.loads(target.ledger.with_name("pressure-progress.json").read_text())
                    require_pressure(record["pressure_progress"])
                    record["termination"] = target.wait_for_oom()
                target.remove()
                if scenario == "memory-oom":
                    # A safe recovery result is separate from availability at
                    # the original cap. Preserve both outcomes explicitly.
                    memory = f"{args.recovery_memory_mib}m"
                    record[f"recovery_at_{memory}"] = constrained_recovery(target, memory=memory, rounds=args.rounds)
                target.start()
                record["recovery"] = target.client("verify", rounds=args.rounds + int(scenario == "freeze-resume"))
                record["recovery_resources"] = target.stats()
                target.kill()
                target.remove()
                # Offline format/CRC check complements authenticated NBD readback.
                check = target.one_shot(["/opt/maki/maki", "check", "/case/config.toml", "--deep"])
                record["deep_check"] = {"exit_code": check.returncode, "stdout": check.stdout[-2000:]}
            record["passed"] = True
            save_json(args.output / "results.json", report)
            print(json.dumps({"scenario": scenario, "passed": True}), flush=True)
        report["passed"] = True
    except BaseException as error:
        report["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        save_json(args.output / "results.json", report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", help="existing local image; the runner never pulls")
    parser.add_argument("--output", type=pathlib.Path, help="new private artifact directory; parent must exist")
    parser.add_argument("--rounds", type=int, default=8)
    parser.add_argument("--recovery-memory-mib", type=int, default=32,
                        help="memory and swap cap for the post-OOM constrained recovery")
    parser.add_argument("--start-epoch", type=int, default=0, help=argparse.SUPPRESS)
    parser.add_argument("--client", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--socket", help=argparse.SUPPRESS)
    parser.add_argument("--connected-fd", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--ledger", type=pathlib.Path, help=argparse.SUPPRESS)
    parser.add_argument("--mode", choices=("write", "verify", "pressure"), help=argparse.SUPPRESS)
    args = parser.parse_args()
    max_rounds = 65 if args.client and args.mode == "verify" else 64
    if not 1 <= args.rounds <= max_rounds:
        parser.error(f"--rounds must be 1..{max_rounds}")
    if not 32 <= args.recovery_memory_mib <= 4096:
        parser.error("--recovery-memory-mib must be 32..4096")
    if args.client:
        client_main(args)
    else:
        if not args.image or not args.output or not args.output.is_absolute():
            parser.error("--image and a new absolute --output directory are required")
        campaign(args)


if __name__ == "__main__":
    main()
