"""Process and evidence I/O for the Linux reset qualification campaigns."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import tempfile
import threading
import time


_termination_requested = False


class CampaignTerminated(SystemExit):
    def __str__(self):
        return "received SIGTERM"


@contextmanager
def handle_termination():
    # An exception from the signal handler can interrupt Popen before the
    # caller owns the child, or interrupt the final cleanup and report.
    global _termination_requested

    def request_stop(_number, _frame):
        global _termination_requested
        _termination_requested = True

    previous = signal.signal(signal.SIGTERM, request_stop)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)
        _termination_requested = False


def check_termination():
    if _termination_requested:
        raise CampaignTerminated(128 + signal.SIGTERM)


def save_json(path, value):
    """Publish a complete private report while preserving the previous snapshot on write failure."""
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}-")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        Path(name).unlink(missing_ok=True)


CURRENT_BLOCK_PATTERN = "shake256-4096"
ARCHIVED_BLOCK_PATTERN = "repeated-sha256"


def block_digest(seed, pattern):
    """Compute the controller's expected digest for a recorded 4 KiB block."""
    if pattern == CURRENT_BLOCK_PATTERN:
        block = hashlib.shake_256(seed.encode()).digest(4096)
    elif pattern == ARCHIVED_BLOCK_PATTERN:
        block = hashlib.sha256(seed.encode()).digest() * 128
    else:
        raise ValueError("unknown ACK block pattern")
    return hashlib.sha256(block).hexdigest()


def ledger_block_pattern(record, expected):
    """Read host-only format metadata. Older ledgers have no pattern field."""
    if not isinstance(record, dict):
        raise ValueError("ACK ledger record must be an object")
    pattern = record.pop("block_pattern", ARCHIVED_BLOCK_PATTERN)
    if pattern not in (CURRENT_BLOCK_PATTERN, ARCHIVED_BLOCK_PATTERN):
        raise ValueError("unknown ACK block pattern")
    if expected is not None and pattern != expected:
        raise ValueError("ACK ledger block pattern changed")
    return pattern


def guest_command_output(command, *, timeout, search_path):
    """Capture a setup command with a shared 64 KiB stdout/stderr budget."""
    limit = 65536
    deadline = time.monotonic() + timeout
    with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, start_new_session=True,
                          env=dict(os.environ, PATH=search_path)) as child:
        stdout, stderr = bytearray(), bytearray()
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(child.stdout, selectors.EVENT_READ, stdout)
                ready.register(child.stderr, selectors.EVENT_READ, stderr)
                while True:
                    draining = bool(ready.get_map())
                    # Both pipes can close before the command exits. Keep the
                    # leader unreaped until timeout cleanup can no longer run.
                    exited = not draining and os.waitid(
                        os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(command, timeout)
                    if exited:
                        break
                    if not draining:
                        time.sleep(min(0.01, remaining))
                        continue
                    for key, _ in ready.select(remaining):
                        budget = limit - len(stdout) - len(stderr)
                        chunk = os.read(key.fd, min(8192, budget + 1))
                        if len(chunk) > budget:
                            raise ValueError("setup output limit exceeded")
                        if chunk:
                            key.data.extend(chunk)
                        else:
                            ready.unregister(key.fd)
        except BaseException:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            raise
        status = child.wait()
    if status:
        raise RuntimeError(f"{command[0]} exited {status}: " + stderr[-2048:].decode(errors="replace"))
    return stdout.decode().strip()


class DiagnosticLog:
    """Continuously drain diagnostics even while the controller waits on another process."""
    def __init__(self, pipe, log, limit):
        self.pipe = pipe
        self.log = log
        self.limit = limit
        self.stopped = threading.Event()
        self.error = None
        self.thread = threading.Thread(target=self._drain, name="campaign-stderr", daemon=True)
        self.thread.start()

    def _drain(self):
        remaining = self.limit
        marker = b"\n[stderr truncated]\n"
        try:
            with selectors.DefaultSelector() as readable:
                readable.register(self.pipe, selectors.EVENT_READ)
                while True:
                    stopping = self.stopped.is_set()
                    if not readable.select(0 if stopping else 0.1):
                        if stopping:
                            break
                        continue
                    data = os.read(self.pipe.fileno(), 65536)
                    if not data:
                        break
                    if remaining >= 0:
                        self.log.write(data[:remaining])
                        remaining -= len(data)
                        if remaining < 0:
                            self.log.seek(self.limit - len(marker))
                            self.log.write(marker)
                    if stopping and remaining < 0:
                        break
            self.log.flush()
        except (OSError, ValueError) as error:
            self.error = error
        finally:
            self.pipe.close()

    def finish(self):
        self.stopped.set()
        self.thread.join()
        if self.error is not None:
            raise self.error
