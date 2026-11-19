"""Private host-side evidence I/O shared by the reset qualification controllers."""

import json
import os
from pathlib import Path
import selectors
import tempfile
import threading


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
