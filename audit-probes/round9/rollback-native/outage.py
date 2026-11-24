#!/usr/bin/python3.12
"""Round 9 rollback-native: a running daemon and its remote authority.

  1. the authority server dies while the daemon runs: every kind of request is tried and its
     errno recorded; the server comes back (same state) and the same session must serve again
     without a daemon restart (docs/rollback-protection.md: "refuses each operation ... but does
     not stop the session"); every acknowledged write must be there
  2. the authority is stopped (SIGSTOP: connections accepted by the kernel, never answered):
     time per request stays bounded by timeout_ms
  3. an administrator takes the volume over while the old daemon runs, a new daemon attaches and
     writes: the old daemon must not serve a single read (cached or not) and must fail every
     write; errnos recorded; the old daemon must stop on SIGTERM

usage: outage.py [--seed N] [--cache]
"""
import os, sys, subprocess, shutil, random, time, signal, argparse, json, errno
import mk9 as mk, rw
import nbd

P = argparse.ArgumentParser()
P.add_argument("--seed", type=int, default=1)
P.add_argument("--cache", action="store_true")
P.add_argument("--timeout-ms", type=int, default=1500)
P.add_argument("--status-wait", type=float, default=0, help="poll maki status/metrics of the revoked daemon for this many seconds")
A = P.parse_args()
rng = random.Random(A.seed)
TB, TW = f"/tmp/a9rn-out-b-{os.getpid()}", f"/tmp/a9rn-out-w-{os.getpid()}"
FAILS = []
CAP = "4MiB"


def fail(m):
    FAILS.append(m); print("FAIL " + m, flush=True)


def en(e):
    return errno.errorcode.get(e, str(e))


def attempt(h, kind, u, val=None):
    """One request; returns (errno or 0, seconds, data)."""
    t = time.monotonic()
    try:
        if kind == "read":
            return 0, time.monotonic() - t, bytes(h.pread(4096, u * 4096))
        if kind == "write":
            h.pwrite(mk.pattern(u * 4096, 4096, val, A.seed), u * 4096)
        elif kind == "write-fua":
            h.pwrite(mk.pattern(u * 4096, 4096, val, A.seed), u * 4096, nbd.CMD_FLAG_FUA)
        elif kind == "flush":
            h.flush()
        elif kind == "trim":
            h.trim(4096, u * 4096)
        elif kind == "zero":
            h.zero(4096, u * 4096)
        return 0, time.monotonic() - t, None
    except nbd.Error as e:
        return e.errnum, time.monotonic() - t, None


for t, size in ((TB, "500m"), (TW, "16m")):
    os.makedirs(t, exist_ok=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", f"size={size},mode=0700", "tmpfs", t], check=True)
vols = []
auth = None
try:
    root, state = os.path.join(TB, "volume"), os.path.join(TW, "state")
    os.makedirs(root)
    cache = 'mode = "read"\nmax_bytes = "256KiB"\nttl = "60s"' if A.cache else None
    kw = dict(discard=True, backing_dir=root, size="1MiB", ckpt_reserve="256KiB", reserve="64KiB", cache=cache)
    v = mk.Vol("out", extra_backing="@@R@@", **kw); vols.append(v)
    auth = rw.Authority(os.path.join(v.dir, "auth"), state, timeout_ms=A.timeout_ms)
    text = v.text
    open(v.cfg, "w").write(text.replace("@@R@@", auth.remote_section(CAP, "writer")))
    admin_cfg = os.path.join(v.dir, "admin.toml")
    open(admin_cfg, "w").write(text.replace("@@R@@", auth.remote_section(CAP, "admin"))); os.chmod(admin_cfg, 0o644)
    auth.init(); auth.start()
    r = v.create(check=False)
    if r.returncode != 0:
        raise RuntimeError(r.stderr)
    v.start(timeout=60)
    h = mk.connect(v.sock)
    acked = {}
    for u in range(0, 24):
        val = 100 + u
        e, dt, _ = attempt(h, "write-fua", u, val)
        if e:
            fail(f"baseline write failed: {en(e)}")
        acked[u] = val
    for u in range(0, 8):
        attempt(h, "read", u)        # warm the cache (if any)

    # ---- 1. the authority's server dies
    auth.kill9()
    print("authority server killed (connection refused):")
    maybe = {}
    for kind, u in (("read", 1), ("read", 20), ("write", 30), ("write-fua", 31), ("flush", 0), ("trim", 32), ("zero", 33), ("read", 2)):
        val = 900 + u
        e, dt, data = attempt(h, kind, u, val)
        print(f"  {kind:9s} unit {u:2d}: {'ok' if e == 0 else en(e)} in {dt:.2f}s")
        if kind.startswith("write") or kind in ("trim", "zero"):
            maybe[u] = (val if kind.startswith("write") else 0, e == 0)
        if kind == "read" and e == 0:
            fail(f"a read of unit {u} was served while the authority could not be asked (cache={A.cache})")
        if dt > 2 * A.timeout_ms / 1000 + 3:
            fail(f"{kind} took {dt:.1f}s with the authority down (timeout_ms {A.timeout_ms})")
    st = v.maki("status", v.cfg)
    try:
        sj = json.loads(st.stdout)["data"]
        print(f"  status during the outage: state={sj.get('state')} degraded_reason={sj.get('degraded_reason')}")
    except Exception:
        print(f"  status during the outage: rc={st.returncode} {st.stdout[:200]} {st.stderr[:200]}")
    auth.start()
    print("authority server back (same state):")
    stopped = False
    for kind, u in (("read", 1), ("read", 20), ("write", 40), ("write-fua", 41), ("flush", 0), ("trim", 42), ("zero", 43)):
        val = 700 + u
        e, dt, data = attempt(h, kind, u, val)
        print(f"  {kind:9s} unit {u:2d}: {'ok' if e == 0 else en(e)} in {dt:.2f}s")
        if e:
            stopped = True
        elif kind.startswith("write"):
            acked[u] = val
    if stopped:
        log = v.read_log()
        fail("after the authority came back the same session still refuses requests (the documentation says an unreachable "
             f"witness does not stop the session); daemon log tail: {log[-500:]}")
    else:
        # everything acknowledged must read back; the requests refused during the outage may or may not have applied
        for u, val in acked.items():
            e, dt, data = attempt(h, "read", u)
            want = [mk.pattern(u * 4096, 4096, val, A.seed)]
            if e or data not in want:
                fail(f"after the outage unit {u} reads {en(e) if e else mk.describe(data[:512])}, acknowledged version {val}")
        for u, (val, ok) in maybe.items():
            e, dt, data = attempt(h, "read", u)
            allowed = [bytes(4096)] + ([mk.pattern(u * 4096, 4096, val, A.seed)] if val else [])
            if e or data not in allowed:
                fail(f"after the outage unit {u} (request refused during it) reads {en(e) if e else mk.describe(data[:512])}")
        print("  every acknowledged unit reads back")

    # ---- 2. the authority accepts connections and never answers
    os.killpg(auth.proc.pid, signal.SIGSTOP)
    print("authority server stopped (SIGSTOP):")
    for kind, u in (("read", 3), ("write-fua", 50), ("flush", 0)):
        e, dt, data = attempt(h, kind, u, 600 + u)
        print(f"  {kind:9s} unit {u:2d}: {'ok' if e == 0 else en(e)} in {dt:.2f}s")
        if e == 0 and kind == "read":
            fail("a read was served while the authority did not answer")
        if dt > 4 * A.timeout_ms / 1000 + 3:
            fail(f"{kind} took {dt:.1f}s with a silent authority (timeout_ms {A.timeout_ms})")
    os.killpg(auth.proc.pid, signal.SIGCONT)
    time.sleep(0.3)
    e, dt, data = attempt(h, "write-fua", 51, 651)
    print(f"  after SIGCONT: write-fua {'ok' if e == 0 else en(e)} in {dt:.2f}s")
    if e == 0:
        acked[51] = 651
    session_alive = e == 0

    # ---- 3. takeover while the old daemon runs
    if not session_alive:
        print("  (the session did not survive the silent authority; restarting the daemon for part 3)")
        try:
            h.shutdown()
        except nbd.Error:
            pass
        v.kill9()
        rec = json.loads(v.maki("volume", "witness", v.cfg).stdout)
        if rec["phase"] != "released":
            t = v.maki("volume", "takeover", admin_cfg, str(rec["fence"]), rw.root_hex(rec))
            if t.returncode:
                fail(f"takeover after the silent authority failed: {t.stderr[-300:]}")
        v.start(timeout=60); h = mk.connect(v.sock)
        for u, val in acked.items():
            e, dt, data = attempt(h, "read", u)
            if e or data != mk.pattern(u * 4096, 4096, val, A.seed):
                fail(f"after a restart unit {u} reads {en(e) if e else mk.describe(data[:512])}, acknowledged version {val}")
    for u in range(0, 8):
        attempt(h, "read", u)        # cached plaintext in the old daemon
    rec = json.loads(v.maki("volume", "witness", v.cfg).stdout)
    t = v.maki("volume", "takeover", admin_cfg, str(rec["fence"]), rw.root_hex(rec))
    print(f"takeover beside the live daemon: rc={t.returncode} {t.stderr.strip()[-200:]}")
    v2 = mk.Vol("out2", key_file=v.key, extra_backing=auth.remote_section(CAP, "writer"), **kw); vols.append(v2)
    v2.start(timeout=60)
    h2 = mk.connect(v2.sock)
    e, dt, _ = attempt(h2, "write-fua", 0, 4242)
    print(f"  new daemon: write-fua unit 0: {'ok' if e == 0 else en(e)}")
    print("old (revoked) daemon:")
    for kind, u in (("read", 0), ("read", 1), ("read", 20), ("write", 60), ("write-fua", 61), ("flush", 0), ("trim", 62), ("zero", 63)):
        e, dt, data = attempt(h, kind, u, 500 + u)
        print(f"  {kind:9s} unit {u:2d}: {'ok' if e == 0 else en(e)} in {dt:.2f}s")
        if e == 0:
            fail(f"the revoked daemon answered {kind} of unit {u} with success" + (f": {mk.describe(data[:512])}" if data else ""))
    st = v.maki("status", v.cfg)
    try:
        sj = json.loads(st.stdout)["data"]
        print(f"  status of the revoked daemon: state={sj.get('state')} degraded_reason={sj.get('degraded_reason')}")
    except Exception:
        print(f"  status of the revoked daemon: rc={st.returncode} {st.stdout[:200]} {st.stderr[:200]}")
    if A.status_wait:
        t0 = time.monotonic()
        seen = None
        while time.monotonic() - t0 < A.status_wait:
            st = v.maki("status", v.cfg)
            try:
                sj = json.loads(st.stdout)["data"]
                cur = (str(sj.get("state")), str(sj.get("degraded_reason")), sj.get("checkpoint_failures_total"))
            except Exception:
                cur = ("?", st.stdout[:100] + st.stderr[:100], None)
            if cur != seen:
                print(f"  +{time.monotonic() - t0:5.1f}s status of the revoked daemon: state={cur[0]} degraded_reason={cur[1][:200]} checkpoint_failures_total={cur[2]}")
                seen = cur
            e, dt, data = attempt(h, "read", 5)
            if e == 0:
                fail("the revoked daemon served a read later on")
            time.sleep(2)
        mt = v.maki("metrics", v.cfg)
        print("  metrics: " + " ".join(l for l in mt.stdout.splitlines() if "volume_state" in l or "degraded" in l)[:300])
    try:
        h.shutdown()
    except nbd.Error:
        pass
    t0 = time.monotonic()
    rc = v.term(timeout=60)
    print(f"  SIGTERM to the revoked daemon: exit {rc} after {time.monotonic() - t0:.1f}s")
    if rc is None:
        fail("the revoked daemon did not stop within 60 s of SIGTERM")
    # the new daemon is unaffected and holds the old acknowledged data
    for u, val in list(acked.items())[:30]:
        if u == 0:
            val = 4242
        e, dt, data = attempt(h2, "read", u)
        if e or data != mk.pattern(u * 4096, 4096, val, A.seed):
            fail(f"new daemon: unit {u} reads {en(e) if e else mk.describe(data[:512])}, acknowledged version {val}")
    rec = json.loads(v.maki("volume", "witness", v.cfg).stdout)
    print(f"  authority after the old daemon stopped: phase {rec['phase']} fence {rec['fence']}")
    if rec["phase"] != "active":
        fail(f"the revoked daemon's shutdown changed the authority: {rec}")
    h2.shutdown(); v2.term(timeout=60)
finally:
    subprocess.run(["pkill", "-9", "-f", TB], stderr=subprocess.DEVNULL)
    for x in vols:
        try:
            x.kill9()
        except Exception:
            pass
    if auth:
        try:
            os.killpg(auth.proc.pid, signal.SIGCONT)
        except Exception:
            pass
        auth.kill9()
    for x in vols:
        shutil.rmtree(x.dir, ignore_errors=True)
    for t in (TB, TW):
        subprocess.run(["umount", "-l", t])
        try:
            os.rmdir(t)
        except OSError:
            pass
print(f"outage seed {A.seed} cache {A.cache}: {'FAIL' if FAILS else 'ok'}")
for f in FAILS[:20]:
    print("  " + f[:900])
sys.exit(1 if FAILS else 0)
