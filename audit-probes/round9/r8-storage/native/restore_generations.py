#!/usr/bin/env python3.12
"""Round 9: a local rollback pair whose two directories are restored from
backups of different generations (including a backup taken while the
creation was still running, i.e. an unfinished creation) is never continued
or created over by `maki volume create`."""
import sys, os, shutil, subprocess, socket, time, signal
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from a9lib import *
import mk

base = "/tmp/a9s/rg"
root, wit = f"{base}-root", "/dev/shm/a9s-wit/rg"
os.makedirs(base, exist_ok=True)
sock, control = f"{base}/nbd.sock", f"{base}/control.sock"
cfg = write_cfg(f"{base}.toml", root=root, witness=wit, control=control)

def snap(tag):
    for src, name in ((root, "root"), (wit, "wit")):
        dst = f"{base}/{tag}-{name}"
        shutil.rmtree(dst, ignore_errors=True)
        shutil.copytree(src, dst)

def restore(root_tag, wit_tag):
    for dst, name, tag in ((root, "root", root_tag), (wit, "wit", wit_tag)):
        shutil.rmtree(dst)
        shutil.copytree(f"{base}/{tag}-{name}", dst)

def serve():
    for p in (sock, f"{base}/n.sock"):
        try: os.unlink(p)
        except FileNotFoundError: pass
    n = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); n.bind(f"{base}/n.sock"); n.settimeout(0.05)
    log = open(f"{base}/nbdkit.log", "wb")
    p = subprocess.Popen(["nbdkit", "--foreground", "-U", sock, PLUGIN, f"config={cfg}"], stdin=subprocess.DEVNULL,
                         stdout=log, stderr=subprocess.STDOUT, env=dict(ENV, NOTIFY_SOCKET=f"{base}/n.sock"), start_new_session=True)
    end = time.monotonic() + 60
    while time.monotonic() < end:
        try:
            if b"READY=1" in n.recv(4096).split(b"\n"): return p
        except (socket.timeout, BlockingIOError): pass
        if p.poll() is not None: raise RuntimeError(open(f"{base}/nbdkit.log", "rb").read().decode()[-400:])
    raise RuntimeError("READY timeout")

def stop(p):
    p.send_signal(signal.SIGTERM); p.wait(60)

# An unfinished creation: killed right after the anchor (3rd rename).
reset(root, wit)
subprocess.run(["strace", "-f", "-qq", "-e", f"trace={CALLS}", "-o", "/dev/null", "-e", "inject=renameat:signal=SIGKILL:when=3",
                MAKI, "volume", "create", cfg], env=ENV, capture_output=True)
snap("unfinished")
assert run("volume", "create", cfg)[0] == 0      # continued
snap("created")
p = serve(); h = mk.connect(sock); d1 = mk.pattern(0, 8192, 1); h.pwrite(d1, 0); h.flush(); h.shutdown(); stop(p)
snap("used1")
p = serve(); h = mk.connect(sock); d2 = mk.pattern(8192, 8192, 2); h.pwrite(d2, 8192); h.flush(); h.shutdown(); stop(p)
snap("used2")

bad = []
cases = [("unfinished", "used2"), ("used2", "unfinished"), ("created", "used2"), ("used1", "used2"), ("used2", "used1"),
         ("used2", "created"), ("unfinished", "created"), ("created", "unfinished")]
for root_tag, wit_tag in cases:
    restore(root_tag, wit_tag)
    before = tree(root), sorted((n, os.path.getsize(os.path.join(wit, n))) for n in os.listdir(wit))
    rc, out = run("volume", "create", cfg)
    ck, ckout = run("check", cfg)
    after_root = tree(root)
    print(f"backing={root_tag:10} witness={wit_tag:10}: create -> {rc} {out.splitlines()[0][:150] if out else ''} | check -> {ck}")
    if rc == 0:
        bad.append(f"backing {root_tag} + witness {wit_tag}: volume create succeeded")
# Controls: consistent pairs.
restore("used2", "used2")
p = serve(); h = mk.connect(sock); ok = h.pread(8192, 0) == d1 and h.pread(8192, 8192) == d2; h.shutdown(); stop(p)
print("consistent used2 pair serves its data:", ok)
restore("unfinished", "unfinished")
rc, out = run("volume", "create", cfg); print("consistent unfinished pair: create ->", rc)
for b in bad: print("BAD", b)
print(f"restore_generations: {len(cases)} mismatched pairs, {len(bad)} violation(s)")
shutil.rmtree(base, ignore_errors=True); shutil.rmtree(root, ignore_errors=True); shutil.rmtree(wit, ignore_errors=True)
sys.exit(1 if bad or not ok else 0)
