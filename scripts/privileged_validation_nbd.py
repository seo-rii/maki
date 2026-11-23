"""Locked raw-NBD operations for privileged-linux-validation.sh only.

Each operation joins maki-attach's flock and checks the kernel backend before
changing the device. Helper attach/cleanup must be called outside this wrapper:
the helper owns its separate identifier, trusted record, and lock lifetime.
"""
import argparse
import contextlib
import fcntl
import os
from pathlib import Path
import re
import stat
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
            result = subprocess.run(["nbd-client", "-unix", args.socket, target,
                                     "-b", "4096", "-identifier", args.identifier])
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
        commands = {
            "check": None,
            "disconnect": ["nbd-client", "-d", target],
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
    parser.add_argument("action", choices=("connect", "check", "disconnect", "activate-vg",
                                           "remove-lv", "remove-vg", "remove-pv"))
    parser.add_argument("--socket")
    parser.add_argument("--vg")
    parser.add_argument("--lv")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"/dev/nbd(?:0|[1-9][0-9]{0,2})", args.device) or int(args.device[8:]) > 255:
        parser.error("device must be a canonical /dev/nbdN with N <= 255")
    if not re.fullmatch(r"maki-privval-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", args.identifier):
        parser.error("invalid validation connection identifier")
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
