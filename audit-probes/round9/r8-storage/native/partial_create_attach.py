#!/usr/bin/env python3.12
"""Round 9: every state in which an interrupted `maki volume create` already
left a volume (a superblock copy exists) must attach through the real plugin,
take a flushed write, survive kill -9, and pass the deep check; and `volume
create` must go on refusing it.

For each traced call of the creation at or after the first superblock name
appears (plain root: the rename; local rollback pair: every call from the
first point where `maki check` passes), kill before that call, then attach.

Usage: partial_create_attach.py plain|local [--discard] [--step K]
"""
import sys, os, re, socket, subprocess, time, signal, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from a9lib import *
import mk

mode = sys.argv[1]
discard = "--discard" in sys.argv
step = int(sys.argv[sys.argv.index("--step") + 1]) if "--step" in sys.argv else 1
tag = f"pca-{mode}{'-v3' if discard else ''}"
base = f"/tmp/a9s/{tag}"
root = f"{base}-root"
wit = f"/dev/shm/a9s-wit/{tag}" if mode == "local" else None
os.makedirs(base, exist_ok=True)
sock, control = f"{base}/nbd.sock", f"{base}/control.sock"
cfg = write_cfg(f"{base}.toml", root=root, witness=wit, control=control)
flags = ["--discard"] if discard else []


def dirs():
    return [d for d in (root, wit) if d]


class Server:
    def start(self, timeout=60):
        for p in (sock,):
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass
        npath = f"{base}/notify.sock"
        try:
            os.unlink(npath)
        except FileNotFoundError:
            pass
        self.notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.notify.bind(npath)
        self.notify.settimeout(0.05)
        self.log = open(f"{base}/nbdkit.log", "wb")
        env = dict(ENV, NOTIFY_SOCKET=npath)
        self.proc = subprocess.Popen(["nbdkit", "--foreground", "-U", sock, PLUGIN, f"config={cfg}"],
                                     stdin=subprocess.DEVNULL, stdout=self.log, stderr=subprocess.STDOUT,
                                     env=env, start_new_session=True)
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                if b"READY=1" in self.notify.recv(4096).split(b"\n"):
                    return None
            except (socket.timeout, BlockingIOError):
                pass
            if self.proc.poll() is not None:
                return "exited before READY: " + open(f"{base}/nbdkit.log", "rb").read().decode("utf-8", "replace")[-500:]
        return "READY timeout"

    def kill(self):
        if self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGKILL)
        self.proc.wait()
        self.notify.close()
        self.log.close()


reset(*dirs())
trace = f"{base}.trace"
r = subprocess.run(["strace", "-f", "-qq", "-e", f"trace={CALLS}", "-o", trace, MAKI, "volume", "create", cfg, *flags],
                   env=ENV, capture_output=True, text=True)
assert r.returncode == 0, r.stderr
per, points = collections.Counter(), []
for line in open(trace).read().splitlines():
    m = re.match(r"\d+\s+(\w+)\(", line)
    if m:
        per[m.group(1)] += 1
        points.append((m.group(1), per[m.group(1)]))

bad, present, tried = [], 0, 0
for index in range(len(points) - 1, -1, -step):
    name, nth = points[index]
    reset(*dirs())
    subprocess.run(["strace", "-f", "-qq", "-e", f"trace={CALLS}", "-o", "/dev/null", "-e",
                    f"inject={name}:signal=SIGKILL:when={nth}", MAKI, "volume", "create", cfg, *flags],
                   env=ENV, capture_output=True, text=True)
    rc, out = run("check", cfg)
    if rc != 0:
        # Walking back from the end: the first stop without a volume ends it
        # (everything before it is the continuation's ground).
        if present:
            break
        continue
    present += 1
    tried += 1
    where = f"killed before call {index} ({name}#{nth})"
    server = Server()
    err = server.start()
    if err:
        bad.append(f"{where}: the volume passes `maki check` but does not attach: {err}")
        server.kill()
        continue
    try:
        h = mk.connect(sock)
        data = mk.pattern(8192, 8192, index + 1)
        h.pwrite(data, 8192)
        h.flush()
        h.shutdown()
    except Exception as e:
        bad.append(f"{where}: I/O after attach: {e}")
    server.kill()
    err = server.start()
    if err:
        bad.append(f"{where}: second attach: {err}")
        server.kill()
        continue
    h = mk.connect(sock)
    if h.pread(8192, 8192) != data:
        bad.append(f"{where}: flushed data lost after kill -9")
    h.shutdown()
    server.kill()
    rc, out = run("check", cfg, "--deep")
    if rc != 0 or "check passed" not in out:
        bad.append(f"{where}: deep check after use: {out[-300:]}")
    rc, out = run("volume", "create", cfg, *flags)
    if rc == 0:
        bad.append(f"{where}: volume create succeeded over a used volume")
    for name_ in ("superblock.a", "superblock.b"):
        if mode == "plain" and not os.path.exists(os.path.join(root, name_)):
            bad.append(f"{where}: {name_} missing after an attach")

for b in bad[:10]:
    print("BAD", b)
print(f"{tag}: {len(points)} calls, {tried} stops left a volume, {len(bad)} violation(s)")
for d in dirs():
    shutil.rmtree(d, ignore_errors=True)
sys.exit(1 if bad else 0)
