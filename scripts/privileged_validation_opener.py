"""Hold a kernel NBD device open across a detach's disconnect, for
privileged-linux-validation.sh only.

The kernel acknowledges NBD_CMD_DISCONNECT while anything holds the device
open, and keeps the connection's `pid` and `backend` attributes until the last
opener has closed it; detach and cleanup wait for that (AUD-197). This process
is such an opener. It opens the device before the detach and reads its first
block with O_DIRECT every 50 ms, so that each read reaches the kernel's queue:
the first read that fails shows that the disconnect was acknowledged. It then
notes what the device shows, holds it open for two seconds more (`--hold`),
closes it and requires the attributes to go once it has. Its output says what it saw, with
times from its start.

Exit status 0 only if whole blocks were read while it held the device, a read then
failed with EIO, the device still showed the connection it had shown at the
start both then and just before the close, and showed none within five
seconds after it. Any other outcome, a stop requested with the stop file and
no disconnect within the deadline exit nonzero.
"""
import argparse
import errno
import mmap
import os
from pathlib import Path
import re
import sys
import time


SYSFS = Path("/sys/block")
BLOCK = 4096
INTERVAL = 0.05
HOLD = 2.0
RELEASE = 5.0
DEADLINE = 90.0


def backend(path):
    """The backend identifier the device shows, or None for no connection."""
    try:
        with open(path, encoding="utf-8", errors="replace") as source:
            return source.read(4097).strip() or None
    except FileNotFoundError:
        return None


class Device:
    """The device, opened read-only for direct reads of its first block."""

    def __init__(self, path):
        self.descriptor = os.open(path, os.O_RDONLY | os.O_DIRECT | os.O_CLOEXEC)
        # O_DIRECT needs an aligned buffer; an anonymous mapping is page aligned.
        self.buffer = mmap.mmap(-1, BLOCK)

    def read(self):
        """The number of bytes the read returned."""
        return os.preadv(self.descriptor, [self.buffer], 0)

    def close(self):
        os.close(self.descriptor)


def hold(device, shown, stop_requested, *, clock=time.monotonic, sleep=time.sleep,
         say=print, hold_seconds=HOLD, release_seconds=RELEASE, deadline=DEADLINE):
    """Hold `device` (a Device) across its disconnect; `shown()` reads the
    backend it shows. Returns the exit status."""
    started = clock()

    def note(message):
        say(f"{clock() - started:7.3f}s {message}")

    connection = shown()
    note(f"holding the device open; it shows backend {connection!r}")
    served = 0
    while True:
        if stop_requested():
            note(f"stopped on request after {served} served reads, before any disconnect")
            device.close()
            return 3
        try:
            count = device.read()
        except OSError as error:
            failure = error
            break
        if count != BLOCK:
            # Not a served block, and not the kernel's answer to a disconnect.
            note(f"refused: a read returned {count} bytes, not {BLOCK}, after {served} served reads")
            device.close()
            return 9
        served += 1
        if clock() - started > deadline:
            note(f"no read failed within {deadline:.0f} s: no disconnect was seen")
            device.close()
            return 4
        sleep(INTERVAL)
    reason = errno.errorcode.get(failure.errno, str(failure.errno))
    at_failure = shown()
    # Neither is a disconnect: let the device go at once.
    if served == 0 or connection is None:
        note(f"refused: read failed with {reason} before any read was served while the "
             f"device showed a connection")
        device.close()
        return 6
    if failure.errno != errno.EIO:
        note(f"refused: the failed read reported {reason}, not EIO, after {served} served reads")
        device.close()
        return 7
    note(f"read failed with {reason} after {served} served reads: the kernel acknowledged "
         f"the disconnect; the device shows backend {at_failure!r}")
    sleep(hold_seconds)
    at_close = shown()
    note(f"closing after holding it {hold_seconds:.1f} s more; the device shows backend {at_close!r}")
    device.close()
    closed = clock()
    while shown() is not None:
        if clock() - closed > release_seconds:
            note(f"the device still shows a connection {release_seconds:.0f} s after the close")
            return 5
        sleep(INTERVAL)
    note("the device shows no connection now that it is closed")
    if at_failure != connection or at_close != connection:
        note("refused: the device stopped showing the connection while it was held open, so "
             "a detach's wait for its opener was not exercised")
        return 8
    note("the connection's attributes outlived the acknowledged disconnect until the close")
    return 0


def hold_time(text):
    """A hold of more than nothing and at most a minute."""
    seconds = float(text)
    if not 0 < seconds <= 60:
        raise argparse.ArgumentTypeError("must be more than 0 and at most 60 seconds")
    return seconds


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", required=True)
    parser.add_argument("--stop-file", required=True, type=Path,
                        help="a file whose existence stops the hold before a disconnect")
    parser.add_argument("--hold", type=hold_time, default=HOLD,
                        help=f"seconds to hold the device after the disconnect (default {HOLD:.0f})")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"/dev/nbd(?:0|[1-9][0-9]{0,2})", args.device) or int(args.device[8:]) > 255:
        parser.error("device must be a canonical /dev/nbdN with N <= 255")
    attribute = SYSFS / args.device.removeprefix("/dev/") / "backend"
    try:
        device = Device(args.device)
    except OSError as error:
        print(f"cannot open {args.device}: {error}", flush=True)
        return 2
    return hold(device, lambda: backend(attribute), args.stop_file.exists,
                say=lambda message: print(message, flush=True), hold_seconds=args.hold)


if __name__ == "__main__":
    sys.exit(main())
