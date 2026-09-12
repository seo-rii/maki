#!/usr/bin/python3
"""PID 1 for the disposable Firecracker campaign; no shutdown/drain before cuts.

Rootfs prerequisites: /opt/maki/{maki,libmaki_nbdkit.so,key}, Python 3,
nbdkit, libnbd.so.0, mount, blkid; /dev/{console,null,ttyS0} device nodes.
The data image is already ext4. Only boot 0 may create the Maki volume.
No host network or kernel NBD device is needed. All sockets/logs are in /run.
"""
import ctypes
import hashlib
import json
import os
import pathlib
import re
import select
import socket
import subprocess
import sys
import termios
import time
import tty

CONFIG = '''config_schema_version = 1
[volume]
name = "firecracker-disposable"
max_virtual_size = "128MiB"
shard_logical_size = "16MiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "firecracker-qualification-v1"
key = { source = "file", name = "/opt/maki/key" }
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4124
[backing]
root = "/data/volume"
journal_segment_size = "16MiB"
journal_max_bytes = "128MiB"
checkpoint_reserve_bytes = "16MiB"
journal_emergency_reserve_bytes = "8MiB"
[nbd]
threads = 2
[control]
socket = "/run/maki/control.sock"
'''
SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def ensure(condition, message):
    if not condition:
        raise ValueError(message)


class Nbd:
    """Synchronous libnbd ACKs; LIBNBD_CMD_FLAG_FUA=1 (not nbdkit's flag=2)."""
    def __init__(self):
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
        for name, (result, args) in signatures.items():
            function = getattr(self.lib, "nbd_" + name)
            function.restype, function.argtypes = result, args
        self.handle = self.lib.nbd_create()
        ensure(self.handle, "libnbd allocation failed")
        self.check(self.lib.nbd_connect_unix(self.handle, b"/run/maki/nbd.sock"))
        ensure(self.lib.nbd_can_fua(self.handle) == 1, "native FUA unavailable")
        ensure(self.lib.nbd_can_flush(self.handle) == 1, "FLUSH unavailable")

    def check(self, result):
        if result < 0:
            raise RuntimeError(self.lib.nbd_get_error().decode(errors="replace"))

    def write(self, offset, payload, fua=False):
        buffer = ctypes.create_string_buffer(payload, len(payload))
        self.check(self.lib.nbd_pwrite(self.handle, buffer, len(payload), offset, int(fua)))

    def read(self, offset):
        buffer = ctypes.create_string_buffer(4096)
        self.check(self.lib.nbd_pread(self.handle, buffer, 4096, offset, 0))
        return buffer.raw

    def flush(self):
        self.check(self.lib.nbd_flush(self.handle, 0))


def barrier(client, cycle, mode):
    ensure(type(cycle) is int and 0 <= cycle < 64, "invalid write generation")
    ensure(mode in ("flush", "fua"), "invalid durability barrier")
    records = []
    for index in range(16):
        offset = (index % 8) * (16 << 20) + (index // 8) * 4096
        payload = hashlib.sha256(f"maki-firecracker-v1:{cycle}:{index}".encode()).digest() * 128
        client.write(offset, payload, fua=mode == "fua")
        records.append({"offset": offset, "length": 4096, "sha256": hashlib.sha256(payload).hexdigest()})
    if mode == "flush":
        client.flush()
    # No serial ACK can be emitted if any write or barrier raised an error.
    return records


def run(command, timeout=30):
    # Setup commands are bounded children. capture_output is inspected only
    # after run() has waited, or after its timeout has killed/reaped the child.
    environment = dict(os.environ, PATH=SYSTEM_PATH)
    result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                            timeout=timeout, env=environment)
    if result.returncode:
        raise RuntimeError(f"{command[0]} exited {result.returncode}: "
                           + result.stderr[-2048:].decode(errors="replace"))
    ensure(len(result.stdout) <= 65536, "setup output limit exceeded")
    return result.stdout.decode(errors="strict").strip()


def mount_guest():
    os.umask(0o077)
    for path in ("/proc", "/sys", "/dev", "/run", "/data"):
        ensure(pathlib.Path(path).is_dir(), f"rootfs missing directory {path}")
    run(["mount", "-t", "proc", "proc", "/proc"])
    run(["mount", "-t", "sysfs", "sysfs", "/sys"])
    # devtmpfs may have been mounted automatically by the guest kernel.
    mounted = pathlib.Path("/proc/mounts").read_text().splitlines()
    if not any(line.split()[1:3] == ["/dev", "devtmpfs"] for line in mounted):
        run(["mount", "-t", "devtmpfs", "devtmpfs", "/dev"])
    run(["mount", "-t", "tmpfs", "-o", "mode=0755,size=32m", "tmpfs", "/run"])
    pathlib.Path("/run/maki").mkdir(mode=0o700)
    # Normal ext4 journal replay is part of recovery. Never fsck -y, noload,
    # format again, remount a failed filesystem, or replace missing Maki data.
    run(["mount", "-t", "ext4", "-o", "rw,data=ordered,errors=remount-ro", "/dev/vdb", "/data"])
    lines = pathlib.Path("/proc/mounts").read_text().splitlines()
    ensure(any(line.split()[:3] == ["/dev/vdb", "/data", "ext4"]
               and "rw" in line.split()[3].split(",") for line in lines), "data mount is not writable ext4")


class Agent:
    def __init__(self):
        self.token, self.boot = None, None
        self.serial = None
        self.daemon = None

    def emit(self, event, **fields):
        raw = b"MAKI_FC_V1 " + json.dumps({"token": self.token, "boot": self.boot,
                                          "event": event, **fields}, separators=(",", ":")).encode() + b"\n"
        ensure(len(raw) <= 16384, "oversized guest event")
        # The host waits for a complete frame and fsyncs its own ledger. A
        # serial flush is never treated as a storage durability operation.
        while raw:
            count = os.write(self.serial, raw)
            ensure(count > 0, "serial closed")
            raw = raw[count:]

    def startup(self):
        mount_guest()
        arguments = dict(part.split("=", 1) for part in pathlib.Path("/proc/cmdline").read_text().split()
                         if part.startswith(("maki_token=", "maki_boot=")))
        self.token, self.boot = arguments["maki_token"], int(arguments["maki_boot"])
        ensure(re.fullmatch("[0-9a-f]{32}", self.token) is not None and 0 <= self.boot <= 64, "boot identity")
        self.serial = os.open("/dev/ttyS0", os.O_RDWR | os.O_NOCTTY)
        tty.setraw(self.serial, when=termios.TCSANOW)
        ensure(len(pathlib.Path("/opt/maki/key").read_bytes()) == 32, "AES key must contain 32 bytes")
        fs_uuid = run(["blkid", "-p", "-s", "UUID", "-o", "value", "/dev/vdb"])
        ensure(fs_uuid, "missing data filesystem UUID")
        config = pathlib.Path("/data/config.toml")
        volume = pathlib.Path("/data/volume")
        if self.boot == 0:
            ensure(not config.exists() and not volume.exists(), "initial data filesystem is not fresh")
            with config.open("x") as stream:
                stream.write(CONFIG)
                stream.flush()
                os.fsync(stream.fileno())
            run(["/opt/maki/maki", "volume", "create", str(config)], timeout=60)
        else:
            ensure(config.read_text() == CONFIG and volume.is_dir(), "existing volume/config missing or changed")
        notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        notify.bind("/run/maki/ready.sock")
        notify.settimeout(0.1)
        env = dict(os.environ, PATH=SYSTEM_PATH, NOTIFY_SOCKET="/run/maki/ready.sock")
        with open("/run/maki/nbdkit.log", "xb") as log:
            self.daemon = subprocess.Popen(["nbdkit", "--foreground", "--threads", "4", "-U", "/run/maki/nbd.sock",
                                            "/opt/maki/libmaki_nbdkit.so", "config=" + str(config)],
                                           stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=env)
        until = time.monotonic() + 90
        try:
            while True:
                if self.daemon.poll() is not None:
                    raise RuntimeError(f"nbdkit failed before READY: {self.daemon.returncode}")
                if time.monotonic() >= until:
                    raise TimeoutError("nbdkit READY deadline")
                try:
                    if b"READY=1" in notify.recv(4096).splitlines():
                        break
                except socket.timeout:
                    pass
        finally:
            notify.close()
        self.client = Nbd()
        self.emit("ready", fs_uuid=fs_uuid,
                  write_cache=pathlib.Path("/sys/block/vdb/queue/write_cache").read_text().strip(),
                  kernel=os.uname().release, nbdkit=run(["nbdkit", "--version"]),
                  provider="local-aes-gcm-siv")

    def commands(self):
        buffer = bytearray()
        seen = set()
        while True:
            if not select.select([self.serial], [], [], 300)[0]:
                raise TimeoutError("host command deadline")
            data = os.read(self.serial, 4096)
            ensure(data, "host serial closed")
            buffer.extend(data)
            ensure(len(buffer) <= 8192, "host command too large")
            while b"\n" in buffer:
                line, _, rest = buffer.partition(b"\n")
                buffer = bytearray(rest)
                request = json.loads(line)
                ensure(request.get("token") == self.token and request.get("boot") == self.boot,
                       "host command identity mismatch")
                command = request.get("command")
                ensure(isinstance(command, str) and command not in seen, "duplicate/invalid command")
                seen.add(command)
                ensure(len(seen) <= 2, "too many commands in one boot")
                if request.get("op") == "verify":
                    offsets = request.get("offsets")
                    ensure(isinstance(offsets, list) and len(offsets) == 16 and len(set(offsets)) == 16,
                           "invalid read manifest")
                    for offset in offsets:
                        ensure(type(offset) is int and 0 <= offset <= (128 << 20) - 4096 and offset % 4096 == 0,
                               "invalid read offset")
                        data = self.client.read(offset)
                        self.emit("read", command=command,
                                  record={"offset": offset, "length": 4096, "sha256": hashlib.sha256(data).hexdigest()})
                    self.emit("verified", command=command, count=len(offsets))
                elif request.get("op") == "write":
                    cycle, mode = request.get("cycle"), request.get("mode")
                    ensure(cycle == self.boot and command == f"write-{cycle}", "write boot mismatch")
                    records = barrier(self.client, cycle, mode)
                    self.emit("ack", command=command, cycle=cycle, mode=mode, records=records)
                else:
                    raise ValueError("unknown host operation")

    def failure(self, error):
        message = f"{type(error).__name__}: {error}"
        if self.daemon is not None:
            if self.daemon.poll() is None:
                self.daemon.kill()
            self.daemon.wait(timeout=5)
            with open("/run/maki/nbdkit.log", "rb") as stream:
                stream.seek(max(0, os.fstat(stream.fileno()).st_size - 2048))
                message += "\n" + stream.read(2048).decode(errors="replace")
        if self.serial is not None:
            self.emit("error", message=message[:4096])
        else:
            print("MAKI guest setup failed: " + message, flush=True)


def main():
    ensure(os.getpid() == 1, "guest agent must run only as guest PID 1")
    agent = Agent()
    try:
        agent.startup()
        agent.commands()
    except BaseException as error:
        agent.failure(error)
    # PID 1 never exits into a kernel panic/graceful reboot and never performs
    # global sync, unmount or Maki drain. The host owns all VM termination.
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
