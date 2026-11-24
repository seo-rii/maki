#!/usr/bin/python3.12
"""Systematic (not sampled) power-loss cuts over one small scripted life of a
volume, on the real plugin, with the model and oracle of pl.py.

Phase A: attach a fresh volume, writes (some FUA), FLUSH, `maki checkpoint`,
overwrites, trims/zeros, a write above maximum_io, a second checkpoint, a few
unflushed writes, kill -9.
Phase B: plain restart (page cache kept: recovery of the journal), a few
writes, SIGTERM (unload: drain, checkpoint).

For both phases an image is built right after EVERY sync, directory sync,
creation, unlink, truncate, allocation and hole punch, and after every
`--every`-th write: durable namespace + no unsynced data, and live namespace
+ no unsynced data (plus a mixed/per-file one now and then). Each image is
opened through the plugin and compared with the oracle as of that instant.

usage: exh.py --seed N [--discard] [--every 4] [--profile-extra ...]
"""
import sys, os, random, signal, subprocess, time, copy, shutil
import nbd
import mk

args = sys.argv[1:]
SEED = int(args[args.index("--seed") + 1]) if "--seed" in args else 1
EVERY = int(args[args.index("--every") + 1]) if "--every" in args else 4
DISC = "--discard" in args
src = open(os.path.join(mk.HERE, "pl.py")).read().rsplit("\nmain()", 1)[0]
sys.argv = ["pl.py", "--seed", str(SEED), "--profile", "v3" if DISC else "v2", "--quiet"]
ns = {"__name__": "pl_model"}
exec(compile(src, "pl.py", "exec"), ns)
Run, Model, parse_log, replay_events, Oracle, STATS, FAILS, now = (ns[k] for k in ("Run", "Model", "parse_log", "replay_events", "Oracle", "STATS", "FAILS", "now"))
rng = random.Random(SEED)
UNIT = 4096


def scripted(run, ops):
    """Run `ops` synchronously, recording submit/complete events."""
    h, o, ev = run.h, run.oracle, run.events
    oid = [len(ev) + 1000]
    for op in ops:
        oid[0] += 1
        kind = op[0]
        if kind == "checkpoint":
            r = run.vol.maki("checkpoint", run.vol.cfg)
            assert r.returncode == 0, r.stderr
            continue
        if kind == "flush":
            ev.append((now(), "submit", oid[0], dict(kind="flush")))
            mark = o.ackno
            h.flush()
            ev.append((now(), "complete", oid[0], 0))
            o.flushed(mark)
            continue
        _, off, ln, fua = op
        a, b = off // 512, (off + ln) // 512
        if kind == "write":
            run.ver += 1
            eff = [(s, run.ver) for s in range(a, b)]
            buf = mk.pattern(off, ln, run.ver, SEED)
        elif kind == "zero":
            eff = [(s, 0) for s in range(a, b)]
        else:
            ua = -(-off // UNIT) * UNIT; ub = (off + ln) // UNIT * UNIT
            eff = [(s, 0) for s in range(ua // 512, ub // 512)] if ub > ua else []
        ev.append((now(), "submit", oid[0], dict(kind=kind, fua=fua, effects=eff)))
        fl = nbd.CMD_FLAG_FUA if fua else 0
        if kind == "write":
            h.pwrite(buf, off, fl)
        elif kind == "zero":
            h.zero(ln, off, fl | (nbd.CMD_FLAG_NO_HOLE if rng.random() < 0.5 else 0))
        else:
            h.trim(ln, off, fl)
        ev.append((now(), "complete", oid[0], 0))
        o.add(eff, True, fua)


def rand_ops(n, span_units, can_trim, flush_every=7):
    out = []
    for i in range(n):
        k = rng.random()
        ln = rng.choice([512, 1024, 4096, 4096, 8192, 12288])
        off = rng.randrange(0, span_units * 8 - ln // 512) * 512 if rng.random() < 0.5 else rng.randrange(0, span_units - 3) * UNIT
        fua = rng.random() < 0.25
        if can_trim and k < 0.15:
            out.append(("trim", rng.randrange(0, span_units - 8) * UNIT + rng.choice([0, 512]), UNIT * rng.randint(1, 8), fua))
        elif k < 0.25:
            out.append(("zero", off, ln, fua))
        else:
            out.append(("write", off, ln, fua))
        if i % flush_every == flush_every - 1:
            out.append(("flush",))
    return out


def sweep(run, pre, base_oracle, label):
    """Images at every interesting call boundary of this daemon life."""
    records = [rec for path in run.cycle_logs if os.path.exists(path) for rec in parse_log(path)]
    m = copy.deepcopy(run.baseline)
    r = random.Random(SEED * 31 + len(records))
    nw = n = 0
    for i, rec in enumerate(records):
        m.apply(rec)
        if rec[0] == "W":
            nw += 1
            if nw % EVERY:
                continue
        cut = rec[1] + 1
        nxt = records[i + 1][1] if i + 1 < len(records) else cut + 1
        if nxt <= cut:
            cut = rec[1]
        o = pre if cut < run.t_ready else replay_events(base_oracle, run.events, cut)
        kinds = [("dur", "none"), ("live", "none")]
        if n % 7 == 0:
            kinds.append(("mixed", "perfile"))
        if rec[0] == "H":
            kinds.append(("dur", ("only", m.ino.get(rec[2]))))
        n += 1
        for ns_mode, data_mode in kinds:
            if not run.test_image(m, o, f"{label} after call {i + 1}/{len(records)} ({rec[0]})", ns_mode, data_mode, r):
                return False, records
    return True, records


run = Run()
ok = False
try:
    run.start()
    run.h = run.connect()
    run.size = run.h.get_size()
    run.oracle = Oracle(run.size // 512)
    pre = run.oracle.clone()
    can_trim = run.h.can_trim()
    # ---- phase A
    run.check_device(run.h, run.oracle, "crash", "phase A start", resolve=True)
    base = run.oracle.clone()
    run.events = []
    ops = rand_ops(24, 48, can_trim) + [("flush",), ("checkpoint",)] + rand_ops(20, 48, can_trim) + \
        [("write", 3 * 65536 + 1536, 150 * 1024, False), ("flush",), ("checkpoint",)] + rand_ops(8, 48, can_trim, flush_every=99)
    scripted(run, ops)
    os.killpg(run.vol.proc.pid, signal.SIGKILL); run.vol.proc.wait(); run.vol.notify.close()
    good, records = sweep(run, pre, base, "phase A")
    print(f"phase A: {len(records)} calls, {STATS['images']} images so far, {'ok' if good else 'FAIL'}", flush=True)
    if good:
        # ---- phase B: plain restart
        full = copy.deepcopy(run.baseline)
        for rec in records:
            full.apply(rec)
        run.carry = full
        run.oracle.crashed()
        pre = run.oracle.clone()
        run.start()
        run.h = run.connect()
        run.check_device(run.h, run.oracle, "crash", "phase B after recovery", resolve=True)
        base = run.oracle.clone()
        run.events = []
        scripted(run, rand_ops(6, 48, can_trim, flush_every=99))
        run.h.shutdown()
        rc = run.vol.term(60)
        if rc != 0:
            FAILS.append(f"SIGTERM exit status {rc}")
        good, records = sweep(run, pre, base, "phase B")
        print(f"phase B: {len(records)} calls, {STATS['images']} images in total, {'ok' if good else 'FAIL'}", flush=True)
    ok = good and not FAILS
finally:
    try:
        run.vol.kill9()
    except Exception:
        pass
    shutil.rmtree(run.vol.dir, ignore_errors=True)
    subprocess.run(["umount", "-l", ns["TMPFS"]])
print(f"exh seed {SEED} {'v3' if DISC else 'v2'} every {EVERY}: {'ok' if ok else 'FAIL'} {STATS}")
for f in FAILS[:10]:
    print("  " + f[:900])
sys.exit(0 if ok else 1)
