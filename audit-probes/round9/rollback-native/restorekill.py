#!/usr/bin/python3.12
"""Successor probe: `maki volume restore` killed -9 at random moments (and `maki volume snapshot`
killed likewise). After each kill the documented procedure (inspect; takeover when the session
is not released) must bring the volume back, and the daemon must serve EITHER the complete
pre-restore state OR the complete snapshot state, never a mix; then the restore is retried
with the new approval and must succeed. Namespaces left after GC are counted.

usage: restorekill.py [--rounds 25] [--seed 1]
"""
import os, sys, subprocess, shutil, time, json, random, argparse, signal
import mk9 as mk, rw
import nbd

P = argparse.ArgumentParser()
P.add_argument("--rounds", type=int, default=25)
P.add_argument("--seed", type=int, default=1)
A = P.parse_args()
rng = random.Random(A.seed)
BAD = []
STATS = {}


def bad(m):
    BAD.append(m); print("BAD " + m, flush=True)


TB, TW = f"/tmp/a9rn-rk-b-{os.getpid()}", f"/tmp/a9rn-rk-w-{os.getpid()}"
for t, size in ((TB, "600m"), (TW, "16m")):
    os.makedirs(t)
    subprocess.run(["mount", "-t", "tmpfs", "-o", f"size={size},mode=0700", "tmpfs", t], check=True)
v = auth = None
try:
    root = os.path.join(TB, "volume"); os.makedirs(root, mode=0o700)
    v = mk.Vol("rk", discard=True, backing_dir=root, size="1MiB", ckpt_reserve="256KiB", reserve="64KiB", extra_backing="@@R@@")
    auth = rw.Authority(os.path.join(v.dir, "auth"), os.path.join(TW, "state"))
    text = v.text
    open(v.cfg, "w").write(text.replace("@@R@@", auth.remote_section("4MiB", "writer")))
    admin = os.path.join(v.dir, "admin.toml")
    open(admin, "w").write(text.replace("@@R@@", auth.remote_section("4MiB", "admin"))); os.chmod(admin, 0o644)
    auth.init(); auth.start()
    assert v.create(check=False).returncode == 0

    def maki(*a):
        return subprocess.run([mk.MAKI, *a], capture_output=True, text=True, timeout=120)

    def record():
        r = maki("volume", "witness", v.cfg)
        assert r.returncode == 0, r.stderr
        return json.loads(r.stdout)

    def procedure(what):
        rec = record()
        if rec["phase"] != "released":
            r = maki("volume", "takeover", admin, str(rec["fence"]), rw.root_hex(rec))
            STATS[f"takeover from {rec['phase']}"] = STATS.get(f"takeover from {rec['phase']}", 0) + 1
            if r.returncode != 0:
                bad(f"{what}: takeover from {rec['phase']} failed: {r.stderr.strip()[-300:]}")
                return None
        return record()

    def state_of():
        v.start(timeout=60); h = mk.connect(v.sock)
        got = tuple(bytes(h.pread(4096, u * 4096)) for u in range(16))
        h.shutdown(); v.term(timeout=60)
        return got

    def write_state(tag):
        v.start(timeout=60); h = mk.connect(v.sock)
        for u in range(16):
            h.pwrite(mk.pattern(u * 4096, 4096, tag * 100 + u, A.seed), u * 4096, nbd.CMD_FLAG_FUA)
        h.shutdown(); v.term(timeout=60)
        return tuple(mk.pattern(u * 4096, 4096, tag * 100 + u, A.seed) for u in range(16))

    snap_state = write_state(1)
    snap = os.path.join(TB, "snap")
    r = maki("volume", "snapshot", v.cfg, snap)
    assert r.returncode == 0, r.stderr
    sroot = bytes(json.loads(r.stdout)["anchor"]["root"]).hex()
    newer = write_state(2)
    current = newer
    for i in range(A.rounds):
        rec = record()
        delay = rng.choice([0.001, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.4])
        kind = rng.choice(["restore", "restore", "restore", "snapshot"])
        if kind == "restore":
            cmd = [mk.MAKI, "volume", "restore", admin, snap, str(rec["fence"]), rw.root_hex(rec), sroot]
        else:
            sd = os.path.join(TB, f"snap-k{i}")
            cmd = [mk.MAKI, "volume", "snapshot", v.cfg, sd]
        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            out, err = p.communicate(timeout=delay)
            killed = False
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL); out, err = p.communicate(); killed = True
        STATS[f"{kind} {'killed' if killed else 'rc=' + str(p.returncode)}"] = STATS.get(f"{kind} {'killed' if killed else 'rc=' + str(p.returncode)}", 0) + 1
        if rng.random() < 0.2:
            auth.kill9(); auth.start()
        after = procedure(f"round {i} ({kind}, killed {killed} after {delay}s)")
        if after is None:
            break
        got = state_of()
        if got == current:
            which = "pre"              # unchanged (also when the pre-restore state already was the snapshot's)
        elif got == snap_state:
            which = "snapshot"
        else:
            bad(f"round {i} ({kind} killed={killed}): the volume serves neither the snapshot nor the pre-restore state")
            break
        STATS[f"serves {which}"] = STATS.get(f"serves {which}", 0) + 1
        if kind == "snapshot" and which != "pre":
            bad(f"round {i}: a killed snapshot changed the data")
        current = got
        if which == "snapshot" and rng.random() < 0.5:
            current = write_state(10 + i)          # move on from the restored state
        ns = sorted(n for n in os.listdir(root) if n.startswith("remote-") or n.startswith(".remote-gc-"))
        STATS["max namespaces"] = max(STATS.get("max namespaces", 0), len(ns))
    # a final, uninterrupted restore with a fresh approval must succeed
    rec = procedure("final")
    if rec:
        r = maki("volume", "restore", admin, snap, str(rec["fence"]), rw.root_hex(rec), sroot)
        if r.returncode != 0:
            bad(f"final restore failed: {r.stderr.strip()[-300:]}")
        elif state_of() != snap_state:
            bad("final restore does not serve the snapshot")
        g = maki("volume", "gc", v.cfg)
        ns = sorted(n for n in os.listdir(root) if n.startswith("remote-") or n.startswith(".remote-gc-"))
        print(f"after the final restore and gc: namespaces {ns}; gc rc={g.returncode}")
        if len(ns) != 1:
            bad(f"{len(ns)} namespaces left after the final restore and a GC pass")
finally:
    for x in (v, auth):
        try:
            x.kill9()
        except Exception:
            pass
    subprocess.run(["pkill", "-9", "-f", TB], stderr=subprocess.DEVNULL)
    if v:
        v.cleanup()
    for t in (TB, TW):
        subprocess.run(["umount", "-l", t]); os.rmdir(t)
print(f"restorekill seed {A.seed} rounds {A.rounds}: {'FAIL' if BAD else 'ok'} {STATS}")
sys.exit(1 if BAD else 0)
