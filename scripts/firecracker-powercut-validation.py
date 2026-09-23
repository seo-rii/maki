#!/usr/bin/env python3
"""Disposable guest-RAM/kernel-cache loss; the L1 host/storage cache survives.

The supplied data image MUST be a newly formatted disposable ext4 filesystem.
This script never formats, mounts, repairs, or deletes an image on the host.
It kills only its own Firecracker child, never the L1 host. Run under a private
background supervisor. stdout from Firecracker is a serial control channel,
recorded from launch; diagnostic files are inspected only after child exit.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import selectors
import signal
import stat
import subprocess
import time
import uuid

PREFIX = b"MAKI_FC_V1 "
MAX_FRAME = 16384


def expected_records(cycle):
    records = []
    for index in range(16):
        offset = (index % 8) * (16 << 20) + (index // 8) * 4096
        data = hashlib.sha256(f"maki-firecracker-v1:{cycle}:{index}".encode()).digest() * 128
        records.append({"offset": offset, "length": 4096, "sha256": hashlib.sha256(data).hexdigest()})
    return records


def decode_frame(line, token, boot):
    if len(line) > MAX_FRAME:
        raise ValueError("oversized serial line")
    if not line.startswith(PREFIX):
        return None
    value = json.loads(line[len(PREFIX):])
    if not isinstance(value, dict):
        raise ValueError("control frame must be an object")
    if value.get("token") != token or type(value.get("boot")) is not int or value["boot"] != boot:
        raise ValueError("serial frame identity mismatch")
    if not isinstance(value.get("event"), str):
        raise ValueError("missing event")
    return value


def validate_ack(event, cycle):
    mode = "flush" if cycle % 2 == 0 else "fua"
    if (event.get("event") != "ack" or event.get("command") != f"write-{cycle}"
            or type(event.get("cycle")) is not int or event["cycle"] != cycle
            or event.get("mode") != mode
            or json.dumps(event.get("records"), sort_keys=True) != json.dumps(expected_records(cycle), sort_keys=True)):
        raise ValueError("false, incomplete, or unexpected durable ACK")


def record_ack(ledger, event, cycle):
    validate_ack(event, cycle)
    record = {key: event[key] for key in ("event", "command", "cycle", "mode", "records")}
    fd = os.open(ledger, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    # Make first creation durable too; never sync the data image from the host.
    parent = os.open(ledger.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def load_ledger(ledger):
    if ledger.stat().st_size > (1 << 20):
        raise ValueError("oversized ledger")
    raw = ledger.read_text(encoding="utf-8")
    if not raw or not raw.endswith("\n"):
        raise ValueError("empty or truncated ACK ledger")
    latest = None
    for cycle, line in enumerate(raw.splitlines()):
        event = json.loads(line)
        validate_ack(event, cycle)
        latest = event["records"]
    return latest


def verify_readbacks(expected, actual):
    # Both sequence and count matter: duplicate/missing rows cannot hide data.
    if not expected or json.dumps(actual, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise ValueError("acknowledged data mismatch, missing or duplicate readback")


def make_config(args, boot, token):
    if not re.fullmatch("[0-9a-f]{32}", token) or type(boot) is not int or not 0 <= boot <= 64:
        raise ValueError("invalid boot identity")
    return {
        "boot-source": {"kernel_image_path": str(args.kernel), "boot_args":
                        "console=ttyS0 root=/dev/vda ro rootfstype=ext4 reboot=k panic=1 "
                        "pci=off quiet loglevel=0 init=/opt/maki/firecracker-guest-agent.py "
                        f"maki_token={token} maki_boot={boot}"},
        "drives": [
            {"drive_id": "rootfs", "path_on_host": str(args.rootfs), "is_root_device": True,
             "is_read_only": True, "cache_type": "Writeback", "io_engine": "Sync"},
            {"drive_id": "data", "path_on_host": str(args.data), "is_root_device": False,
             "is_read_only": False, "cache_type": "Writeback", "io_engine": "Sync"}],
        "machine-config": {"vcpu_count": args.vcpus, "mem_size_mib": args.memory_mib},
        "entropy": {},
    }


class SerialProcess:
    def __init__(self, command, directory, token, boot):
        directory.mkdir(mode=0o700)
        self.token, self.boot, self.directory = token, boot, directory
        self.buffer, self.total = bytearray(), 0
        self.serial = open(directory / "serial.log", "xb")
        self.stderr = open(directory / "stderr.log", "xb")
        os.chmod(directory / "serial.log", 0o600)
        os.chmod(directory / "stderr.log", 0o600)
        self.selector = selectors.DefaultSelector()
        self.child = None
        try:
            self.child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                          stderr=self.stderr, start_new_session=True, bufsize=0)
            self.selector.register(self.child.stdout, selectors.EVENT_READ)
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def send(self, command):
        raw = json.dumps({"token": self.token, "boot": self.boot, **command}).encode() + b"\n"
        # Requests are tiny (a write command or at most sixteen read offsets).
        # Poll writable with a deadline; never block behind an unresponsive guest.
        if len(raw) > 4096:
            raise ValueError("oversized host command")
        descriptor = self.child.stdin.fileno()
        os.set_blocking(descriptor, False)
        with selectors.DefaultSelector() as writable:
            writable.register(descriptor, selectors.EVENT_WRITE)
            until = time.monotonic() + 5
            while raw:
                if not writable.select(max(0, until - time.monotonic())):
                    raise TimeoutError("guest serial input timeout")
                try:
                    written = os.write(descriptor, raw)
                except BlockingIOError:
                    continue
                if written == 0:
                    raise RuntimeError("guest serial input closed")
                raw = raw[written:]

    def event(self, timeout):
        until = time.monotonic() + timeout
        while True:
            newline = self.buffer.find(b"\n")
            if newline >= 0:
                line = bytes(self.buffer[:newline]).rstrip(b"\r")
                del self.buffer[:newline + 1]
                frame = decode_frame(line, self.token, self.boot)
                if frame is not None:
                    return frame
                continue
            if len(self.buffer) > MAX_FRAME:
                raise ValueError("unterminated oversized serial line")
            left = until - time.monotonic()
            if left <= 0 or not self.selector.select(left):
                raise TimeoutError("guest serial event deadline")
            chunk = os.read(self.child.stdout.fileno(), 4096)
            if not chunk:
                raise RuntimeError("Firecracker exited or closed serial before expected event")
            self.total += len(chunk)
            if self.total > (8 << 20):
                raise ValueError("serial output limit exceeded")
            self.serial.write(chunk)
            self.buffer.extend(chunk)

    def expect(self, event, timeout, command=None):
        frame = self.event(timeout)
        if frame["event"] == "error":
            raise RuntimeError("guest failed: " + str(frame.get("message", "unknown"))[:2048])
        if frame["event"] != event or (command is not None and frame.get("command") != command):
            raise ValueError(f"expected {event}/{command}, received {frame['event']}/{frame.get('command')}")
        return frame

    def crash(self):
        if self.child.poll() is not None:
            raise RuntimeError("Firecracker already exited before requested SIGKILL")
        os.killpg(self.child.pid, signal.SIGKILL)
        status = self.child.wait(timeout=5)
        if status != -signal.SIGKILL:
            raise RuntimeError(f"unexpected Firecracker termination: {status}")
        return {"pid": self.child.pid, "returncode": status, "signal": "SIGKILL"}

    def close(self):
        if self.child is not None:
            if self.child.poll() is None:
                os.killpg(self.child.pid, signal.SIGKILL)
            self.child.wait(timeout=5)
            self.child.stdin.close()
            self.child.stdout.close()
        self.selector.close()
        self.serial.close()
        self.stderr.close()

    def diagnostics(self):
        if self.child is None or self.child.poll() is None:
            raise RuntimeError("diagnostics require reaped child")
        self.serial.flush() if not self.serial.closed else None
        self.stderr.flush() if not self.stderr.closed else None
        parts = []
        for name in ("stderr.log", "serial.log"):
            with open(self.directory / name, "rb") as stream:
                stream.seek(max(0, os.fstat(stream.fileno()).st_size - 4096))
                parts.append(name + ": " + stream.read(4096).decode(errors="replace"))
        return "\n".join(parts)


def save_json(path, value):
    with open(path, "w", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, indent=2)
        stream.write("\n")


def campaign(args):
    os.umask(0o077)
    if not 2 <= args.cycles <= 64 or not 64 <= args.memory_mib <= 16384 or not 1 <= args.vcpus <= 8:
        raise ValueError("require cycles 2..64, memory 64..16384 MiB, vcpus 1..8")
    if not 1 <= args.timeout <= 600:
        raise ValueError("timeout must be 1..600 seconds")
    for name in ("firecracker", "kernel", "rootfs", "data"):
        path = getattr(args, name).resolve(strict=True)
        if not stat.S_ISREG(path.stat().st_mode):
            raise ValueError(f"{name} must be a regular file, never a host device")
        setattr(args, name, path)
    identities = [(p.stat().st_dev, p.stat().st_ino) for p in (args.rootfs, args.data, args.kernel)]
    if len(set(identities)) != 3:
        raise ValueError("rootfs, kernel and data must be distinct files")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    token, ledger = uuid.uuid4().hex, args.output / "host-acks.jsonl"
    result = {"passed": False, "token": token, "cycles": args.cycles, "boots": [],
              "fault_scope": "Firecracker SIGKILL; L1 host and storage cache survive"}
    fs_uuid = None
    try:
        for boot in range(args.cycles + 1):
            config = args.output / f"boot-{boot}.json"
            save_json(config, make_config(args, boot, token))
            process = SerialProcess([str(args.firecracker), "--no-api", "--config-file", str(config)],
                                    args.output / f"boot-{boot}", token, boot)
            entry = {"boot": boot, "verified_units": 0}
            result["boots"].append(entry)
            try:
                with process:
                    ready = process.expect("ready", args.timeout)
                    if not ready.get("fs_uuid") or ready.get("write_cache") != "write back":
                        raise ValueError("missing filesystem identity or guest writeback advertisement")
                    if fs_uuid is not None and fs_uuid != ready["fs_uuid"]:
                        raise ValueError("data filesystem changed across boot")
                    fs_uuid = ready["fs_uuid"]
                    entry["ready"] = ready
                    if boot:
                        expected = load_ledger(ledger)
                        command = f"verify-{boot}"
                        process.send({"command": command, "op": "verify",
                                      "offsets": [r["offset"] for r in expected]})
                        actual = []
                        until = time.monotonic() + args.timeout
                        for _ in expected:
                            frame = process.expect("read", max(0, until - time.monotonic()), command)
                            actual.append(frame["record"])
                        done = process.expect("verified", max(0, until - time.monotonic()), command)
                        verify_readbacks(expected, actual)
                        if done.get("count") != len(expected):
                            raise ValueError("incomplete verification")
                        entry["verified_units"] = len(actual)
                    if boot < args.cycles:
                        mode = "flush" if boot % 2 == 0 else "fua"
                        process.send({"command": f"write-{boot}", "op": "write", "cycle": boot, "mode": mode})
                        ack = process.expect("ack", args.timeout, f"write-{boot}")
                        record_ack(ledger, ack, boot)
                        entry["ack_mode"] = mode
                        entry["acked_units"] = len(ack["records"])
                        entry["cut"] = process.crash()
                    else:
                        entry["verification_cleanup"] = process.crash()
            except BaseException:
                entry["diagnostics"] = process.diagnostics()
                raise
            save_json(args.output / "results.json", result)
        result["passed"] = True
    except BaseException as error:
        result["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        save_json(args.output / "results.json", result)
    print(json.dumps({"passed": True, "cycles": args.cycles, "output": str(args.output)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("firecracker", "kernel", "rootfs", "data", "output"):
        parser.add_argument("--" + name, type=pathlib.Path, required=True)
    parser.add_argument("--cycles", type=int, default=4)
    parser.add_argument("--memory-mib", type=int, default=512)
    parser.add_argument("--vcpus", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=120)
    campaign(parser.parse_args())


if __name__ == "__main__":
    main()
