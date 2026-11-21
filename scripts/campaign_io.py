"""Process and evidence I/O for the Linux reset qualification campaigns."""

from contextlib import contextmanager
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
                while ready.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(command, timeout)
                    for key, _ in ready.select(remaining):
                        budget = limit - len(stdout) - len(stderr)
                        chunk = os.read(key.fd, min(8192, budget + 1))
                        if len(chunk) > budget:
                            raise ValueError("setup output limit exceeded")
                        if chunk:
                            key.data.extend(chunk)
                        else:
                            ready.unregister(key.fd)
            status = child.wait(timeout=max(0, deadline - time.monotonic()))
        except BaseException:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            raise
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
