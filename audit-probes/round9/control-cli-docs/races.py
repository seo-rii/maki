"""Control verbs racing SIGTERM / kill -9, then an immediate restart (BUG-015 angle).

Each round: serve a volume, run NBD writes+flushes with a per-sector oracle while
K control clients loop over status/metrics/checkpoint/reload/drain, stop the daemon
at a random moment (SIGTERM or SIGKILL), then at once: `maki check --deep` (takes
the volume lock) and a restart, and compare every flushed sector.
usage: races.py SEED [ROUNDS]
"""
import sys, os, json, time, socket, random, threading, subprocess, signal
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mk, ctl

seed = int(sys.argv[1]); rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 10
rng = random.Random(seed)
BLK = 4096; NBLK = 256
viol = []
stats = {"term": 0, "kill": 0, "drain_rounds": 0, "ctl_ok": 0, "ctl_err": 0, "ctl_busy": 0, "max_exit": 0.0, "restart_fail": 0}

def ctl_worker(path, stop, wseed, allow_drain, counters):
    r = random.Random(wseed)
    s = None
    while not stop.is_set():
        try:
            if s is None:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(5); s.connect(path)
            verb = r.choice(["status", "metrics", "checkpoint", "checkpoint", "reload", "reload", "reloadbad"] + (["drain"] if allow_drain and r.random() < 0.05 else []))
            if verb == "reload":
                req = {"command": "reload", "section": "cache", "payload": {"max_bytes": r.choice([1, 4096, 65536, 1 << 20]), "ttl": r.choice(["1us", "1ms", "30s"])}}
            elif verb == "reloadbad":
                req = {"command": "reload", "section": r.choice(["retry", "endpoints", "x"])}
            else:
                req = {"command": verb}
            s.sendall((json.dumps(req) + "\n").encode())
            if r.random() < 0.1:
                s.close(); s = None   # abandon the request mid-flight
                continue
            buf = b""
            while not buf.endswith(b"\n"):
                d = s.recv(65536)
                if not d: raise ConnectionError("eof")
                buf += d
            resp = json.loads(buf)
            if resp.get("ok"): counters["ok"] += 1
            elif "busy" in resp.get("error", ""): counters["busy"] += 1
            else: counters["err"] += 1
        except Exception:
            if s:
                try: s.close()
                except Exception: pass
            s = None
            time.sleep(0.005)

v = mk.Vol(tag=f"race{seed}", size="1MiB", cache='mode = "read"\nmax_bytes = "1MiB"\nttl = "30s"')
flushed = {}   # block -> version durable for sure
try:
    v.create()
    for rnd in range(rounds):
        v.start()
        pid = v.proc.pid
        h = mk.connect(v.sock)
        # everything flushed in earlier rounds must be there
        for b, ver in flushed.items():
            got = h.pread(BLK, b * BLK)
            if got != mk.pattern(b * BLK, BLK, ver, seed):
                viol.append(f"round {rnd}: block {b} expected v{ver}, got {mk.describe(got[:512])}")
        stop = threading.Event(); counters = {"ok": 0, "err": 0, "busy": 0}
        allow_drain = rng.random() < 0.4
        ths = [threading.Thread(target=ctl_worker, args=(v.control, stop, rng.random(), allow_drain, counters)) for _ in range(rng.choice([2, 8, 20]))]
        for t in ths: t.start()
        deadline = time.monotonic() + rng.uniform(0.05, 1.5)
        pending = {}; ver = rnd * 100000
        io_err = None
        while time.monotonic() < deadline:
            b = rng.randrange(NBLK); ver += 1
            try:
                h.pwrite(mk.pattern(b * BLK, BLK, ver, seed), b * BLK)
                pending[b] = ver
                if rng.random() < 0.3:
                    h.flush(); flushed.update(pending); pending = {}
            except Exception as e:
                io_err = str(e)[:80]; pending.pop(b, None)
                # an errored write leaves the block unknown: forget the old expectation unless nothing reached it
                flushed.pop(b, None)
                break
        how = rng.choice(["term", "term", "kill"])
        keep_client = rng.random() < 0.5
        if not keep_client:
            try: h.shutdown()
            except Exception: pass
        for b in pending: flushed.pop(b, None)   # unflushed: either version may survive a kill; forget
        t0 = time.monotonic()
        if how == "kill":
            v.kill9(); rc = "killed"
        elif keep_client:
            # nbdkit waits for every connection before .unload (known, round 8):
            # signal first, let control clients race the pending stop, then hang up.
            v.proc.send_signal(signal.SIGTERM)
            time.sleep(rng.uniform(0.0, 0.3))
            try: h.shutdown()
            except Exception: pass
            del h
            rc = v.term(timeout=90)
        else:
            rc = v.term(timeout=90)
        dt = time.monotonic() - t0
        stats[how] += 1; stats["max_exit"] = max(stats["max_exit"], dt)
        stop.set()
        for t in ths: t.join()
        stats["ctl_ok"] += counters["ok"]; stats["ctl_err"] += counters["err"]; stats["ctl_busy"] += counters["busy"]
        if allow_drain: stats["drain_rounds"] += 1
        if how == "term" and rc is None:
            viol.append(f"round {rnd}: SIGTERM did not exit within 90 s"); v.kill9()
        # at once: the lock must be free
        r = v.maki("check", v.cfg, "--deep")
        if "volume lock is held" in r.stdout + r.stderr:
            viol.append(f"round {rnd}: lock still held after {how}: {r.stdout[-200:]}")
        if r.returncode != 0:
            viol.append(f"round {rnd}: check --deep rc {r.returncode} after {how}: {(r.stdout + r.stderr)[-300:]}")
        log = v.read_log()
        if "panic" in log.lower() or "shutdown during unload failed" in log:
            viol.append(f"round {rnd}: log: " + [l for l in log.splitlines() if "panic" in l.lower() or "unload failed" in l][0][:300])
        print(f"round {rnd}: {how} keep_client={keep_client} drain={allow_drain} exit {rc} in {dt:.2f}s io_err={io_err} ctl={counters} flushed={len(flushed)}", flush=True)
    # final verification
    v.start(); h = mk.connect(v.sock)
    for b, ver in flushed.items():
        got = h.pread(BLK, b * BLK)
        if got != mk.pattern(b * BLK, BLK, ver, seed):
            viol.append(f"final: block {b} expected v{ver}, got {mk.describe(got[:512])}")
    h.shutdown(); v.term()
    print("STATS", stats)
    print("VIOLATIONS", len(viol))
    for x in viol[:20]: print("  ", x)
finally:
    if viol:
        print("kept", v.dir); 
        try: v.kill9()
        except Exception: pass
    else:
        v.cleanup()
sys.exit(1 if viol else 0)
