"""Locked raw-NBD operations for privileged-linux-validation.sh only.

Each operation joins maki-attach's flock and checks the kernel backend before
changing the device. The raw connection is made and removed with the helper's
own provisioning verbs (maki-attach nbd-connect and nbd-disconnect), which take
no lock of their own, so they run inside this one. Helper attach/cleanup must be
called outside this wrapper: the helper owns its separate identifier, trusted
record, and lock lifetime.

`kernel-disconnect` is the one exception: it sends the kernel's own
NBD_CMD_DISCONNECT over generic netlink for a device that shows an
attachment's connection (`maki-<uuid>`), as an operator's tool could, which
the helper's nbd-disconnect refuses by design. The runner uses it to leave a
killed daemon's attachment disconnected, its record in place, for cleanup's
disconnected recovery.
"""
import argparse
import contextlib
import fcntl
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import sys


SYSFS = Path("/sys/block")


@contextlib.contextmanager
def attach_lock(root=Path("/"), owner=0):
    """Open the same private lock as TrustedState without following symlinks."""
    descriptors = []
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        directory = os.open(root, flags)
        descriptors.append(directory)
        for component in (None, "run", "maki-attach"):
            if component is not None:
                try:
                    child = os.open(component, flags, dir_fd=directory)
                except FileNotFoundError:
                    if component != "maki-attach":
                        raise
                    try:
                        os.mkdir(component, 0o700, dir_fd=directory)
                    except FileExistsError:
                        pass
                    child = os.open(component, flags, dir_fd=directory)
                directory = child
                descriptors.append(directory)
            info = os.fstat(directory)
            if info.st_uid != owner or info.st_mode & 0o022:
                raise RuntimeError("attach state must be root-owned and not group/other writable")
        lock = os.open("attach.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW |
                       os.O_NONBLOCK | os.O_CLOEXEC, 0o600, dir_fd=directory)
        descriptors.append(lock)
        info = os.fstat(lock)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or
                info.st_mode & 0o077 or info.st_nlink != 1):
            raise RuntimeError("attach lock must be a private root-owned file with one link")
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)

# Generic netlink, as <linux/netlink.h>, <linux/genetlink.h> and
# <linux/nbd-netlink.h> define it.
NETLINK_GENERIC = 16
NLM_F_REQUEST = 0x1
NLM_F_ACK = 0x4
NLMSG_ERROR = 0x2
GENL_ID_CTRL = 0x10
CTRL_CMD_GETFAMILY = 3
CTRL_ATTR_FAMILY_ID = 1
CTRL_ATTR_FAMILY_NAME = 2
NBD_GENL_VERSION = 1
NBD_CMD_DISCONNECT = 2
NBD_ATTR_INDEX = 1
NETLINK_TIMEOUT = 10


def netlink_attribute(kind, payload):
    length = 4 + len(payload)
    return struct.pack("=HH", length, kind) + payload + bytes(-length % 4)


def netlink_request(family, sequence, command, version, attributes):
    """A generic netlink request that asks for an acknowledgement."""
    payload = struct.pack("=BBH", command, version, 0) + attributes
    return struct.pack("=IHHII", 16 + len(payload), family, NLM_F_REQUEST | NLM_F_ACK,
                       sequence, 0) + payload


def netlink_exchange(sock, request, sequence):
    """Send `request`; return the payloads the kernel answered it with
    before its acknowledgement. A refusal raises OSError with its errno.
    Answers from another sender or to another request are not this one's."""
    sock.send(request)
    replies = []
    while True:
        datagram, (sender, _) = sock.recvfrom(65536)
        if sender != 0:
            continue
        offset = 0
        while offset + 16 <= len(datagram):
            length, kind, _, answered, _ = struct.unpack_from("=IHHII", datagram, offset)
            if length < 16 or offset + length > len(datagram):
                raise RuntimeError("malformed netlink answer")
            payload = datagram[offset + 16:offset + length]
            offset += (length + 3) & ~3
            if answered != sequence:
                continue
            if kind == NLMSG_ERROR:
                (error,) = struct.unpack_from("=i", payload)
                if error:
                    raise OSError(-error, os.strerror(-error))
                return replies
            replies.append(payload)


def family_id(replies):
    """The family identifier CTRL_CMD_GETFAMILY's reply names."""
    for payload in replies:
        offset = 4
        while offset + 4 <= len(payload):
            length, kind = struct.unpack_from("=HH", payload, offset)
            if length < 4:
                break
            if kind & 0x3fff == CTRL_ATTR_FAMILY_ID and length >= 6:
                return struct.unpack_from("=H", payload, offset + 4)[0]
            offset += (length + 3) & ~3
    raise RuntimeError("the kernel did not name the nbd netlink family")


def kernel_disconnect(index, open_socket=socket.socket):
    """NBD_CMD_DISCONNECT for nbd<index>, acknowledged by the kernel."""
    with open_socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC) as sock:
        sock.bind((0, 0))
        sock.settimeout(NETLINK_TIMEOUT)
        name = netlink_attribute(CTRL_ATTR_FAMILY_NAME, b"nbd\0")
        family = family_id(netlink_exchange(
            sock, netlink_request(GENL_ID_CTRL, 1, CTRL_CMD_GETFAMILY, 1, name), 1))
        device = netlink_attribute(NBD_ATTR_INDEX, struct.pack("=I", index))
        netlink_exchange(sock, netlink_request(family, 2, NBD_CMD_DISCONNECT, NBD_GENL_VERSION,
                                               device), 2)


def backend(target):
    directory = SYSFS / target
    # A missing device or an unreadable observation is not a free device.
    directory.stat()
    try:
        with (directory / "backend").open() as source:
            value = source.read(4097).strip()
        if len(value) > 4096:
            raise RuntimeError("NBD backend identifier exceeds the observation limit")
        if value:
            return value
    except FileNotFoundError:
        pass
    try:
        (directory / "pid").lstat()
    except FileNotFoundError:
        return None
    raise RuntimeError("connected NBD device has no readable backend identifier")


def execute(args):
    target = args.device.removeprefix("/dev/")
    with attach_lock():
        observed = backend(target)
        if args.action == "connect":
            if observed == args.identifier:
                return 0
            if observed is not None:
                raise RuntimeError("refusing to connect an occupied NBD device")
            result = subprocess.run([args.helper, "nbd-connect", "--nbd-device", args.device,
                                     "--socket", args.socket, "--block-size", "4096",
                                     "--identifier", args.identifier])
            if result.returncode:
                # The caller retains the identifier even after a partial attach.
                return result.returncode
            if backend(target) != args.identifier:
                raise RuntimeError("NBD connect did not publish the requested backend identifier")
            return 0
        if args.action == "disconnect" and observed is None:
            return 0
        if observed != args.identifier:
            raise RuntimeError("refusing to change an absent or foreign NBD backend")
        if args.action == "kernel-disconnect":
            kernel_disconnect(int(target.removeprefix("nbd")))
            # The connection's attributes stay while anything holds the
            # device open: say what it shows now, which is not a verdict.
            try:
                shown = repr(backend(target))
            except (OSError, RuntimeError) as error:
                shown = f"unreadable ({error})"
            print(f"the kernel acknowledged NBD_CMD_DISCONNECT for {target}; it shows backend {shown}")
            return 0
        commands = {
            "check": None,
            "disconnect": [args.helper, "nbd-disconnect", "--nbd-device", args.device,
                           "--identifier", args.identifier],
            "activate-vg": ["vgchange", "-ay", args.vg],
            "remove-lv": ["lvremove", "--yes", "--force", f"/dev/{args.vg}/{args.lv}"],
            "remove-vg": ["vgremove", "--yes", "--force", args.vg],
            "remove-pv": ["pvremove", "--yes", "--force", args.device],
        }
        command = commands[args.action]
        if command is None:
            return 0
        result = subprocess.run(command)
        if result.returncode and args.action == "remove-lv":
            # lvcreate or lvremove can fail with the validation VG already empty.
            # Confirm that state under the ownership lock before releasing lower layers.
            count = subprocess.run(["vgs", "--noheadings", "-o", "lv_count", args.vg],
                                   stdout=subprocess.PIPE, text=True)
            if count.returncode == 0 and count.stdout.strip() == "0":
                return 0
        if result.returncode == 0 and args.action == "disconnect" and backend(target) is not None:
            raise RuntimeError("NBD disconnect left a live backend; preserving cleanup identity")
        return result.returncode


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", required=True)
    parser.add_argument("--identifier", required=True)
    parser.add_argument("--helper", required=True,
                        help="absolute path of the maki-attach binary this run built")
    parser.add_argument("action", choices=("connect", "check", "disconnect", "activate-vg",
                                           "remove-lv", "remove-vg", "remove-pv",
                                           "kernel-disconnect"))
    parser.add_argument("--socket")
    parser.add_argument("--vg")
    parser.add_argument("--lv")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"/dev/nbd(?:0|[1-9][0-9]{0,2})", args.device) or int(args.device[8:]) > 255:
        parser.error("device must be a canonical /dev/nbdN with N <= 255")
    # Only an attachment's own connection is disconnected by the kernel
    # alone; every other action is on this run's raw connection.
    prefix = "maki-" if args.action == "kernel-disconnect" else "maki-privval-"
    if not re.fullmatch(re.escape(prefix) + r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
                        args.identifier):
        parser.error("invalid validation connection identifier")
    if not args.helper.startswith("/"):
        parser.error("the helper must be an absolute path")
    if args.action == "connect" and (not args.socket or not args.socket.startswith("/")):
        parser.error("connect requires an absolute socket path")
    if args.action in ("activate-vg", "remove-lv", "remove-vg"):
        if not args.vg or not re.fullmatch(r"maki_validation_[0-9]+_[0-9]+", args.vg):
            parser.error("LVM cleanup requires the validation VG name")
    if args.action == "remove-lv" and args.lv != "data":
        parser.error("LVM cleanup requires the validation LV name")
    try:
        return execute(args)
    except (OSError, RuntimeError) as error:
        print(f"validation NBD operation refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
