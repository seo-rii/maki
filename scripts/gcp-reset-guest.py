#!/usr/bin/env python3
"""Run one native Maki write/readback generation inside a disposable GCE VM.

The data disk and its config must already be mounted at /mnt/maki-data. After
the complete ACK frame this process deliberately remains alive without global
sync, unmount, Maki drain, or daemon cleanup. The external host must reset the
whole instance. `--verify-only` is the final read-only campaign boot and exits.
"""
import argparse
import ctypes
import hashlib
import json
import os
import pathlib
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time


PREFIX = b"MAKI_GCP_RESET_V1 "
BOOT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def ensure(condition, message):
    if not condition:
        raise ValueError(message)


def mode_for_cycle(cycle):
    ensure(type(cycle) is int and 0 <= cycle < 64, "invalid cycle")
    return "flush" if cycle % 2 == 0 else "fua"


def offset_for_index(index):
    ensure(type(index) is int and 0 <= index < 16, "invalid block index")
    return (index % 8) * (16 << 20) + (index // 8) * 4096


def index_for_offset(offset):
    offsets = [offset_for_index(index) for index in range(16)]
    ensure(type(offset) is int and offset in offsets, "invalid block offset")
    return offsets.index(offset)


def payload(cycle, index):
    mode_for_cycle(cycle)
    offset_for_index(index)
    return hashlib.sha256(f"maki-gcp-reset-v1:{cycle}:{index}".encode()).digest() * 128


def manifest(cycle, blocks=None):
    rows = []
    for index in range(16):
        block = payload(cycle, index) if blocks is None else blocks[index]
        ensure(isinstance(block, bytes) and len(block) == 4096, "invalid read block")
        rows.append({"offset": offset_for_index(index), "length": 4096,
                     "sha256": hashlib.sha256(block).hexdigest()})
    return rows


class Nbd:
    """Synchronous libnbd I/O; LIBNBD_CMD_FLAG_FUA is one."""
    def __init__(self, socket_path):
        self.lib = ctypes.CDLL("libnbd.so.0")
        handle, pointer = ctypes.c_void_p, ctypes.c_void_p
        size, offset, flags = ctypes.c_size_t, ctypes.c_uint64, ctypes.c_uint32
        signatures = {
            "create": (handle, []), "get_error": (ctypes.c_char_p, []),
            "connect_unix": (ctypes.c_int, [handle, ctypes.c_char_p]),
            "can_fua": (ctypes.c_int, [handle]), "can_flush": (ctypes.c_int, [handle]),
            "pwrite": (ctypes.c_int, [handle, pointer, size, offset, flags]),
            "pread": (ctypes.c_int, [handle, pointer, size, offset, flags]),
            "flush": (ctypes.c_int, [handle, flags]), "close": (None, [handle]),
        }
        for name, (result, arguments) in signatures.items():
            function = getattr(self.lib, "nbd_" + name)
            function.restype, function.argtypes = result, arguments
        self.handle = self.lib.nbd_create()
        ensure(self.handle, "libnbd allocation failed")
        self.check(self.lib.nbd_connect_unix(self.handle, os.fsencode(socket_path)))
        self.can_fua = self.lib.nbd_can_fua(self.handle) == 1
        self.can_flush = self.lib.nbd_can_flush(self.handle) == 1
        ensure(self.can_fua, "native FUA unavailable")
        ensure(self.can_flush, "FLUSH unavailable")

    def check(self, result):
        if result < 0:
            raise RuntimeError(self.lib.nbd_get_error().decode(errors="replace"))

    def write(self, offset, block, fua=False):
        buffer = ctypes.create_string_buffer(block, len(block))
        self.check(self.lib.nbd_pwrite(self.handle, buffer, len(block), offset, int(fua)))

    def read(self, offset):
        buffer = ctypes.create_string_buffer(4096)
        self.check(self.lib.nbd_pread(self.handle, buffer, 4096, offset, 0))
        return buffer.raw

    def flush(self):
        self.check(self.lib.nbd_flush(self.handle, 0))

    def close(self):
        if self.handle:
            self.lib.nbd_close(self.handle)
            self.handle = None


def barrier(client, cycle, mode):
    ensure(mode == mode_for_cycle(cycle), "wrong durability barrier")
    records = []
    for index in range(16):
        block = payload(cycle, index)
        offset = offset_for_index(index)
        client.write(offset, block, fua=mode == "fua")
        records.append({"offset": offset, "length": 4096,
                        "sha256": hashlib.sha256(block).hexdigest()})
    if mode == "flush":
        client.flush()
    return records


def capabilities(client):
    return {"can_flush": client.can_flush is True, "can_fua": client.can_fua is True}


def run_output(command, timeout=10):
    result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                            timeout=timeout, env=dict(os.environ, PATH=SYSTEM_PATH), check=False)
    ensure(len(result.stdout) + len(result.stderr) <= 65536, "setup output limit exceeded")
    if result.returncode != 0:
        raise RuntimeError(f"{command[0]} exited {result.returncode}: "
                           + result.stderr[-2048:].decode(errors="replace"))
    return result.stdout.decode(errors="strict").strip()


def filesystem_uuid(path):
    value = run_output(["findmnt", "-n", "-o", "UUID", "--target", str(path)])
    ensure(BOOT_ID.fullmatch(value) is not None, "persistent filesystem UUID unavailable")
    return value


def shutdown_witness(path):
    state = run_output(["systemctl", "is-active", "maki-reset-witness.service"])
    ensure(state == "active", "graceful shutdown witness service is not active")
    ensure(not path.exists(), "graceful shutdown witness ledger exists")
    return {"witness_service": "active", "graceful_stop_witness": "absent"}


def wait_for_reset():
    while True:
        signal.pause()


def execute_cycle(args, client, emit):
    if args.cycle:
        generation = args.cycle - 1
        blocks = [client.read(offset_for_index(index)) for index in range(16)]
        emit("readback", generation=generation, records=manifest(generation, blocks))
        emit("verified", generation=generation, count=16)
    if args.verify_only:
        ensure(args.cycle > 0, "verify-only requires a prior generation")
        return
    mode = mode_for_cycle(args.cycle)
    records = barrier(client, args.cycle, mode)
    emit("ack", command=f"write-{args.cycle}", mode=mode, records=records)
    wait_for_reset()


def run_nbdkit(args, runtime):
    socket_path = runtime / "nbd.sock"
    notify_path = runtime / "notify.sock"
    log_path = runtime / "nbdkit.log"
    notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    notify.bind(str(notify_path))
    notify.settimeout(0.2)
    environment = dict(os.environ, PATH=SYSTEM_PATH, NOTIFY_SOCKET=str(notify_path))
    log = open(log_path, "xb")
    child = subprocess.Popen([args.nbdkit, "--foreground", "--threads", "4", "-U",
                              str(socket_path), args.plugin, "config=" + args.config],
                             stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                             env=environment, start_new_session=True)
    until = time.monotonic() + args.ready_timeout
    try:
        while True:
            if child.poll() is not None:
                raise RuntimeError(f"nbdkit exited before READY: {child.returncode}")
            if time.monotonic() >= until:
                raise TimeoutError("nbdkit READY deadline")
            try:
                if b"READY=1" in notify.recv(4096).splitlines():
                    return child, log, socket_path
            except socket.timeout:
                pass
    except BaseException:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=5)
        log.close()
        raise
    finally:
        notify.close()


def cleanup(child, log, client):
    if client is not None:
        client.close()
    if child is not None and child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=5)
    if log is not None:
        log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--token", required=True)
    parser.add_argument("--cycle", type=int, required=True)
    parser.add_argument("--config", default="/mnt/maki-data/config.toml")
    parser.add_argument("--plugin", default="/opt/maki/libmaki_nbdkit.so")
    parser.add_argument("--nbdkit", default="nbdkit")
    parser.add_argument("--ready-timeout", type=float, default=90)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    ensure(re.fullmatch(r"[0-9a-f]{32}", args.token) is not None, "invalid token")
    mode_for_cycle(args.cycle)
    ensure(1 <= args.ready_timeout <= 300, "invalid READY timeout")
    config = pathlib.Path(args.config).resolve(strict=True)
    plugin = pathlib.Path(args.plugin).resolve(strict=True)
    ensure(config.is_file() and plugin.is_file(), "config and plugin must be regular files")
    mount = pathlib.Path("/mnt/maki-data").resolve(strict=True)
    ensure(config == mount / "config.toml", "qualification config must be on the persistent data mount")
    fs_uuid = filesystem_uuid(mount)
    witness = shutdown_witness(mount / "graceful-stop.jsonl")
    boot_id = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    ensure(BOOT_ID.fullmatch(boot_id) is not None, "invalid boot identity")
    os.umask(0o077)
    runtime = pathlib.Path(tempfile.mkdtemp(prefix="maki-gcp-reset-", dir="/run"))
    child = log = client = None

    def emit(event, **fields):
        frame = {"token": args.token, "cycle": args.cycle, "boot_id": boot_id,
                 "event": event, **fields}
        raw = PREFIX + json.dumps(frame, separators=(",", ":")).encode() + b"\n"
        ensure(len(raw) <= 16384, "oversized guest frame")
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()

    try:
        child, log, socket_path = run_nbdkit(args, runtime)
        client = Nbd(socket_path)
        features = capabilities(client)
        emit("ready", provider="local-aes-gcm-siv", config=str(config),
             kernel=os.uname().release, fs_uuid=fs_uuid, **features, **witness)
        execute_cycle(args, client, emit)
    except BaseException as error:
        try:
            emit("error", message=f"{type(error).__name__}: {error}"[:2048])
        except BaseException:
            pass
        raise
    finally:
        # A successful write cycle never reaches here: only the external reset
        # ends wait_for_reset. Final verify-only and pre-ACK failures clean up
        # their process-local resources without touching the data mount.
        cleanup(child, log, client)


if __name__ == "__main__":
    main()
