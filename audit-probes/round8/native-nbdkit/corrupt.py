#!/usr/bin/python3.12
"""Media damage under the real plugin. A volume holds, for every unit of a
region, an old checkpointed version and (for half of them) a newer version
that was FLUSHed and lives only in the journal. Each iteration damages a copy
of the backing (bit flips, a zeroed 512-byte block, a truncation, a deleted
file) and opens it through the plugin. Allowed: the daemon refuses to start,
a unit reads EIO, or a unit reads its newest flushed version. Not allowed:
any other content (older version, zeros, another unit), a crash of nbdkit, a
panic in the log.

usage: corrupt.py --seed N [--iters 150] [--discard] [--faults K]
"""
import sys, os, random, shutil, subprocess, signal, nbd, mk
a = sys.argv
SEED = int(a[a.index("--seed") + 1]) if "--seed" in a else 1
ITERS = int(a[a.index("--iters") + 1]) if "--iters" in a else 150
NF = int(a[a.index("--faults") + 1]) if "--faults" in a else 1
DISC = "--discard" in a
rng = random.Random(SEED)
v = mk.Vol(f"cor{SEED}", discard=DISC, size="1MiB", shard="64KiB", jmax="1MiB", seg="64KiB")
stats = dict(iters=0, refused=0, eio_units=0, clean=0, stale=0, wrong=0, crashed=0, panics=0)
fails = []
try:
    v.create(); v.start()
    h = nbd.NBD(); h.connect_unix(v.sock)
    NU = 256
    exp = {}
    for u in range(0, 160):
        h.pwrite(mk.pattern(u * 4096, 4096, 1), u * 4096); exp[u] = 1
    h.flush()
    assert v.maki("checkpoint", v.cfg).returncode == 0
    for u in range(0, 160, 2):
        h.pwrite(mk.pattern(u * 4096, 4096, 2), u * 4096); exp[u] = 2
    if DISC:
        h.trim(8 * 4096, 150 * 4096)
        for u in range(150, 158): exp[u] = 0
    h.flush()
    v.kill9()
    pristine = v.root + ".pristine"
    shutil.copytree(v.root, pristine)
    files = sorted(os.path.relpath(os.path.join(d, f), pristine) for d, _, fs in os.walk(pristine) for f in fs if f != "volume.lock")
    old = {u: mk.pattern(u * 4096, 4096, 1) for u in range(160)}
    for it in range(ITERS):
        shutil.rmtree(v.root); shutil.copytree(pristine, v.root)
        desc = []
        for _ in range(NF):
            f = rng.choice(files); p = os.path.join(v.root, f)
            if not os.path.exists(p):
                continue
            size = os.path.getsize(p)
            kind = rng.choice(["flip", "flip", "flip", "zero512", "truncate", "delete", "garbage512"])
            if kind == "delete" or size == 0:
                if os.path.exists(p): os.unlink(p)
                desc.append(f"delete {f}"); continue
            with open(p, "r+b") as fh:
                if kind == "flip":
                    off = rng.randrange(size); fh.seek(off); b = fh.read(1); fh.seek(off); fh.write(bytes([b[0] ^ (1 << rng.randrange(8))])); desc.append(f"flip {f}@{off}")
                elif kind in ("zero512", "garbage512"):
                    off = rng.randrange(0, size, 512) if size >= 512 else 0; fh.seek(off)
                    fh.write(bytes(min(512, size - off)) if kind == "zero512" else rng.randbytes(min(512, size - off))); desc.append(f"{kind} {f}@{off}")
                else:
                    n = rng.randrange(size); fh.truncate(n); desc.append(f"truncate {f} {size}->{n}")
        stats["iters"] += 1
        try:
            v.start(timeout=60)
        except RuntimeError as e:
            stats["refused"] += 1
            rc = v.proc.returncode
            if rc is not None and rc < 0:
                stats["crashed"] += 1; fails.append(f"iter {it} {desc}: nbdkit died with signal {-rc} at startup")
            if "panic" in v.read_log().lower():
                stats["panics"] += 1; fails.append(f"iter {it} {desc}: panic at startup: {v.read_log()[-300:]}")
            continue
        h = nbd.NBD(); h.connect_unix(v.sock)
        bad_here = 0
        for u in range(NU):
            try:
                got = bytes(h.pread(4096, u * 4096))
            except nbd.Error as e:
                stats["eio_units"] += 1; bad_here += 1
                if h.aio_is_dead() or h.aio_is_closed():
                    stats["crashed"] += 1; fails.append(f"iter {it} {desc}: connection died reading unit {u}"); break
                continue
            want = exp.get(u, 0)
            wantb = mk.pattern(u * 4096, 4096, want) if want else bytes(4096)
            if got != wantb:
                if u in old and got == old[u]:
                    stats["stale"] += 1; fails.append(f"iter {it} {desc}: unit {u} reads its OLD checkpointed version; the flushed newer one (version {want}) is gone, no error")
                else:
                    stats["wrong"] += 1; fails.append(f"iter {it} {desc}: unit {u} reads wrong data: {mk.describe(got[:512])}")
                bad_here += 1
                break
        if not bad_here:
            stats["clean"] += 1
        try: h.shutdown()
        except nbd.Error: pass
        if v.proc.poll() is not None and v.proc.returncode < 0:
            stats["crashed"] += 1; fails.append(f"iter {it} {desc}: nbdkit died with signal {-v.proc.returncode}")
        if "panic" in v.read_log().lower():
            stats["panics"] += 1; fails.append(f"iter {it} {desc}: panic: {[l for l in v.read_log().splitlines() if 'panic' in l.lower()][0][:300]}")
        v.kill9()
finally:
    v.cleanup(); shutil.rmtree(v.root + ".pristine", ignore_errors=True)
print(f"corrupt seed {SEED} {'v3' if DISC else 'v2'} faults/iter {NF}: {stats}; {len(fails)} FAIL(s)")
for f in fails[:15]: print("  " + f[:500])
sys.exit(1 if fails else 0)
