#!/usr/bin/env python3
"""Opt-in, disposable userspace NBD faults. This never attaches a block device.

Run under a background supervisor with stdout/stderr redirected from launch.
An existing local image built with cgroup-validation.Dockerfile is required.
The host needs Docker, libnbd.so.0, and Python 3. No Python packages are needed.
"""
import argparse
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


def verify(client, ledger):
    latest = {}
    for line in ledger.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
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


class Nbd:
    """Small libnbd synchronous client, always run in a deadline-bound child."""
    def __init__(self, path):
        self.lib = ctypes.CDLL("libnbd.so.0")
        signatures = {
            "create": (ctypes.c_void_p, []),
            "get_error": (ctypes.c_char_p, []),
            "connect_unix": (ctypes.c_int, [ctypes.c_void_p, ctypes.c_char_p]),
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
        self.check(self.lib.nbd_connect_unix(self.handle, os.fsencode(path)))
        ensure(self.lib.nbd_can_fua(self.handle) == 1, "native FUA required")
        ensure(self.lib.nbd_can_flush(self.handle) == 1, "FLUSH required")

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
    client = Nbd(args.socket)
    try:
        if args.mode == "verify":
            print(json.dumps({"verified_units": verify(client, args.ledger)}))
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
            for epoch in range(args.rounds):
                writes = [(index * 4096, hashlib.sha256(f"{epoch}:{index}".encode()).digest() * 128)
                          for index in range(128)]
                durable_write(client, args.ledger, writes, "flush")
                writes = [((128 + index) * 4096, bytes([(epoch + index + 1) % 256]) * 4096)
                          for index in range(8)]
                durable_write(client, args.ledger, writes, "fua")
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


class Target:
    def __init__(self, image, directory):
        self.image = image
        self.directory = directory
        self.case = directory / "backing-case"
        self.case.mkdir(mode=0o700)
        self.ledger = directory / "host-acks.jsonl"
        self.identifier = None
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
        try:
            self.create("192m", "1", command)
            return run(["docker", "start", "--attach", self.identifier], timeout=120)
        finally:
            # Killing the Docker CLI does not terminate its container.
            self.remove()

    def options(self, memory, cpus):
        return ["--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true", "--user", f"{os.getuid()}:{os.getgid()}",
                "--pids-limit", "64", "--memory", memory, "--memory-swap", memory,
                "--cpus", cpus, "--label", "maki.failure-validation=" + self.token,
                "--mount", f"type=bind,src={self.case},dst=/case"]

    def state(self):
        return json.loads(run(["docker", "inspect", "--format", "{{json .State}}", self.identifier]).stdout)

    def create(self, memory, cpus, command, extra=()):
        ensure(self.identifier is None, "previous owned container has not been removed")
        self.serial += 1
        # Preserve an identity even if the create CLI times out before returning its ID.
        self.identifier = f"maki-fault-{self.token}-{self.serial}"
        run(["docker", "create", "--name", self.identifier, *self.options(memory, cpus),
             *extra, self.image, *command])

    def start(self, memory="192m", cpus="1"):
        ensure(self.identifier is None, "previous owned container has not been removed")
        for name in ("nbd.sock", "ready.sock"):
            (self.case / name).unlink(missing_ok=True)
        self.notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.notify.bind(str(self.case / "ready.sock"))
        self.notify.settimeout(0.1)
        # Maki is PID 1: no shell, init, sidecar or stress helper is the OOM victim.
        self.create(memory, cpus, [
            "nbdkit", "--foreground", "--threads", "4", "-U", "/case/nbd.sock",
            "/opt/maki/libmaki_nbdkit.so", "config=/case/config.toml",
        ], extra=["--env", "NOTIFY_SOCKET=/case/ready.sock"])
        run(["docker", "start", self.identifier])
        until = time.monotonic() + 30
        while time.monotonic() < until:
            try:
                if b"READY=1" in self.notify.recv(4096).splitlines():
                    return
            except socket.timeout:
                pass
            if not self.state()["Running"]:
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
        return result

    def client_command(self, mode, rounds=1):
        return [sys.executable, str(pathlib.Path(__file__).resolve()), "--client",
                "--socket", str(self.case / "nbd.sock"), "--ledger", str(self.ledger),
                "--mode", mode, "--rounds", str(rounds)]

    def client(self, mode, rounds=1, check=True):
        result = run(self.client_command(mode, rounds), timeout=120, check=check)
        record = {"exit_code": result.returncode, "stdout": result.stdout[-2000:], "stderr": result.stderr[-2000:]}
        if check:
            ensure(result.stdout.strip(), "client returned no verification evidence")
        return record

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
        if self.identifier is None:
            return
        state = self.state()
        if state.get("Paused"):
            run(["docker", "unpause", self.identifier])
        if self.state()["Running"]:
            self.kill()
        # Logs are inspected/saved only after the container process has exited.
        output = run(["docker", "logs", "--tail", "60", self.identifier])
        (self.directory / f"container-{self.serial}.log").write_text(output.stdout + output.stderr)
        run(["docker", "rm", self.identifier])
        self.identifier = None


def constrained_recovery(target):
    """Report availability at the original cap without relaxing durability."""
    try:
        try:
            target.start(memory="32m")
        except TimeoutError:
            result = {"ready": False, "outcome": "startup-timeout", "deadline_seconds": 30,
                      "resources": target.stats(), "state_before_cleanup": target.state()}
            if target.state()["Running"]:
                result["cleanup_termination"] = target.kill()
            return result
        except RuntimeError:
            state = target.state()
            require_oom(state)
            return {"ready": False, "outcome": "startup-oom", "termination": state}
        else:
            result = {"ready": True, "outcome": "verified", "verification": target.client("verify"),
                      "resources": target.stats()}
            target.kill()
            return result
    finally:
        target.remove()


def campaign(args):
    os.umask(0o077)
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    details = json.loads(run(["docker", "info", "--format", "{{json .}}"]).stdout)
    ensure(details["CgroupVersion"] == "2", "cgroup v2 is required")
    for feature in ("MemoryLimit", "SwapLimit", "CpuCfsQuota", "PidsLimit"):
        ensure(details[feature], f"Docker lacks {feature}")
    image_id = run(["docker", "image", "inspect", "--format", "{{.Id}}", args.image]).stdout.strip()
    report = {"image": image_id, "kernel": os.uname().release, "docker": details["ServerVersion"],
              "cgroup": 2, "provider": "local-aes-gcm-siv", "cases": [], "passed": False}
    try:
        for scenario in ("cpu-memory-kill", "freeze-resume", "memory-oom"):
            directory = args.output / scenario
            directory.mkdir(mode=0o700)
            target = Target(image_id, directory)
            record = {"scenario": scenario}
            report["cases"].append(record)
            try:
                target.start(memory="96m", cpus="0.25" if scenario == "cpu-memory-kill" else "1")
                record["workload"] = target.client("write", rounds=args.rounds)
                record["resources"] = target.stats()
                if scenario == "cpu-memory-kill":
                    cpu = dict(line.split() for line in record["resources"]["cpu.stat"].splitlines())
                    ensure(int(cpu["nr_throttled"]) > 0, "no observed CPU throttling")
                    record["termination"] = target.kill()
                elif scenario == "freeze-resume":
                    before = target.ledger.read_bytes()
                    run(["docker", "pause", target.identifier])
                    with (directory / "paused-client.log").open("w") as stream:
                        child = subprocess.Popen(target.client_command("write"), stdout=stream, stderr=subprocess.STDOUT)
                        try:
                            time.sleep(0.5)
                            ensure(child.poll() is None, "paused server unexpectedly completed client")
                            ensure(target.ledger.read_bytes() == before, "paused server produced a durable ACK")
                            run(["docker", "unpause", target.identifier])
                            ensure(child.wait(timeout=120) == 0, "resumed client failed")
                        finally:
                            if child.poll() is None:
                                child.kill()
                                child.wait(timeout=5)
                    record["pause_seconds"] = 0.5
                    record["termination"] = target.kill()
                else:
                    run(["docker", "update", "--memory", "32m", "--memory-swap", "32m", target.identifier])
                    ensure(target.state()["Running"], "limit shrink killed target before pressure I/O")
                    record["pressure_resources"] = target.stats()
                    record["pressure_client"] = target.client("pressure", check=False)
                    record["pressure_progress"] = json.loads(target.ledger.with_name("pressure-progress.json").read_text())
                    require_pressure(record["pressure_progress"])
                    until = time.monotonic() + 10
                    while target.state()["Running"] and time.monotonic() < until:
                        time.sleep(0.1)
                    record["termination"] = target.state()
                    require_oom(record["termination"])
                target.remove()
                if scenario == "memory-oom":
                    # A safe recovery result is separate from availability at
                    # the original cap. Preserve both outcomes explicitly.
                    record["recovery_at_32m"] = constrained_recovery(target)
                target.start()
                record["recovery"] = target.client("verify")
                record["recovery_resources"] = target.stats()
                target.kill()
                target.remove()
                # Offline format/CRC check complements authenticated NBD readback.
                check = target.one_shot(["/opt/maki/maki", "check", "/case/config.toml", "--deep"])
                record["deep_check"] = {"exit_code": check.returncode, "stdout": check.stdout[-2000:]}
                record["passed"] = True
                print(json.dumps({"scenario": scenario, "passed": True}), flush=True)
            finally:
                target.remove()
        report["passed"] = True
    finally:
        (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", help="existing local image; the runner never pulls")
    parser.add_argument("--output", type=pathlib.Path, help="new private artifact directory; parent must exist")
    parser.add_argument("--rounds", type=int, default=8)
    parser.add_argument("--client", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--socket", help=argparse.SUPPRESS)
    parser.add_argument("--ledger", type=pathlib.Path, help=argparse.SUPPRESS)
    parser.add_argument("--mode", choices=("write", "verify", "pressure"), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not 1 <= args.rounds <= 64:
        parser.error("--rounds must be 1..64")
    if args.client:
        client_main(args)
    else:
        if not args.image or not args.output or not args.output.is_absolute():
            parser.error("--image and a new absolute --output directory are required")
        campaign(args)


if __name__ == "__main__":
    main()
