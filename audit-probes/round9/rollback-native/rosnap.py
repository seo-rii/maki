#!/usr/bin/python3.12
"""Successor probe (docs/remote-witness-service.md 'Snapshot, takeover and restore'):
  * a snapshot raises the fence and keeps the current root;
  * restore only reads the snapshot directory: it works from a read-only bind mount;
  * after the restore the data is the snapshot's; the replaced newer namespace is gone;
  * takeover output: the command reports the released new session.
"""
import os, sys, subprocess, shutil, json, random
import mk9 as mk, rw
import nbd

rng = random.Random(3)
BAD = []


def row(ok, text):
    print(f"  [{'ok ' if ok else 'BAD'}] {text}", flush=True)
    if not ok:
        BAD.append(text)


def last(t):
    t = (t or "").strip()
    return t.splitlines()[-1][:300] if t else ""


base = os.path.join(mk.BASE, f"rosnap-{os.getpid()}")
os.makedirs(base)
root = os.path.join(base, "volume"); os.makedirs(root, mode=0o700)
vol = mk.Vol("rs", discard=True, backing_dir=root, size="1MiB", ckpt_reserve="256KiB", reserve="64KiB", extra_backing="@@R@@")
auth = rw.Authority(os.path.join(vol.dir, "auth"), os.path.join(base, "state"))
text = vol.text
open(vol.cfg, "w").write(text.replace("@@R@@", auth.remote_section("4MiB", "writer")))
admin = os.path.join(vol.dir, "admin.toml")
open(admin, "w").write(text.replace("@@R@@", auth.remote_section("4MiB", "admin"))); os.chmod(admin, 0o644)
ro = os.path.join(base, "ro")
mounted = False


def maki(*a):
    return subprocess.run([mk.MAKI, *a], capture_output=True, text=True, timeout=120)


def record():
    r = maki("volume", "witness", vol.cfg)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def write(vals, n):
    vol.start(timeout=60); h = mk.connect(vol.sock)
    for _ in range(n):
        u = rng.randrange(0, 64); v = rng.randrange(1, 1 << 40)
        h.pwrite(mk.pattern(u * 4096, 4096, v, 3), u * 4096, nbd.CMD_FLAG_FUA); vals[u] = v
    h.shutdown(); vol.term(timeout=60)


def verify(vals, what):
    vol.start(timeout=60); h = mk.connect(vol.sock)
    bad = sum(1 for u, v in vals.items() if bytes(h.pread(4096, u * 4096)) != mk.pattern(u * 4096, 4096, v, 3))
    h.shutdown(); vol.term(timeout=60)
    row(bad == 0, f"{what}: {len(vals)} units, {bad} differ")


try:
    auth.init(); auth.start()
    r = vol.create(check=False)
    assert r.returncode == 0, r.stderr
    vals = {}
    write(vals, 12)
    before = record()
    snap = os.path.join(base, "snap")
    r = maki("volume", "snapshot", vol.cfg, snap)
    row(r.returncode == 0, f"snapshot: rc={r.returncode} {last(r.stderr)}")
    desc = json.loads(r.stdout)
    after = record()
    row(after["fence"] > before["fence"] and after["current"]["anchor"] == before["current"]["anchor"] and after["phase"] == "released",
        f"snapshot raised the fence {before['fence']} -> {after['fence']}, kept generation {before['current']['anchor']['generation']} -> "
        f"{after['current']['anchor']['generation']} and root equal {after['current']['anchor']['root'] == before['current']['anchor']['root']}, phase {after['phase']}")
    old = dict(vals)
    write(vals, 12)
    rec = record()
    # restore from a read-only bind mount of the snapshot
    os.makedirs(ro)
    subprocess.run(["mount", "--bind", snap, ro], check=True)
    subprocess.run(["mount", "-o", "remount,bind,ro", ro], check=True)
    mounted = True
    t = subprocess.run(["touch", os.path.join(ro, "probe")], capture_output=True, text=True)
    row(t.returncode != 0, f"the bind mount is read-only ({last(t.stderr)})")
    r = maki("volume", "restore", admin, ro, str(rec["fence"]), rw.root_hex(rec), bytes(desc["anchor"]["root"]).hex())
    row(r.returncode == 0, f"restore from the read-only snapshot mount: rc={r.returncode} {last(r.stderr) or last(r.stdout)[:200]}")
    if r.returncode == 0:
        res = json.loads(r.stdout)
        row(res["phase"] == "released" and res["current"]["epoch"] == rec["current"]["epoch"] + 1,
            f"restore result: phase {res['phase']}, epoch {rec['current']['epoch']} -> {res['current']['epoch']}, generation "
            f"{rec['current']['anchor']['generation']} -> {res['current']['anchor']['generation']}")
        verify(old, "after the restore: the snapshot's data")
        ns = sorted(n for n in os.listdir(root) if n.startswith("remote-"))
        row(len(ns) == 1, f"namespaces after the restore and the next attach: {ns}")
    # takeover output on a released session (a no-op transition is still a takeover)
    rec = record()
    r = maki("volume", "takeover", admin, str(rec["fence"]), rw.root_hex(rec))
    out = json.loads(r.stdout) if r.returncode == 0 else None
    row(r.returncode == 0 and out["phase"] == "released" and out["fence"] > rec["fence"],
        f"takeover of a released session: rc={r.returncode}, printed phase {out and out['phase']}, fence {rec['fence']} -> {out and out['fence']} {last(r.stderr)}")
finally:
    if mounted:
        subprocess.run(["umount", ro])
    vol.kill9(); auth.kill9()
    shutil.rmtree(base, ignore_errors=True)
    vol.cleanup()
print(f"rosnap: {'FAIL' if BAD else 'ok'}")
sys.exit(1 if BAD else 0)
