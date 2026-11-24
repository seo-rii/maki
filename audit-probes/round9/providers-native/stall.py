"""Stall policy through the real daemon: the only endpoint stops answering
after attach. What do WRITE / FLUSH / READ / status / SIGTERM do, and what is
on disk afterwards?

usage: stall.py <http|ws|grpc> [heal|term|kill]
  heal: release the endpoint after a while; everything pending must complete
  term: SIGTERM nbdkit while requests are stuck; measure the exit
  kill: kill -9 while stuck, restart on a healthy endpoint, verify
"""
import sys, time, threading, json, os, signal, asyncio
import nbd
import rp

transport = sys.argv[1]
mode = sys.argv[2] if len(sys.argv) > 2 else "heal"
MAKI_LOG = os.environ.get("MAKI_LOG_LEVEL")

beh = rp.Behaviour()
stalled = threading.Event()      # set => stall
release = threading.Event()      # set => stalled requests proceed
seen_stalled = {"n": 0}


def hook(kind, op, req):
    if not stalled.is_set():
        return None
    seen_stalled["n"] += 1
    if kind == "ws":
        async def wait():
            while not release.is_set():
                await asyncio.sleep(0.05)
            return None
        return wait()
    release.wait()
    return None


beh.hook = hook
srv = {"http": rp.HttpServer, "ws": rp.WsServer, "grpc": rp.GrpcServer}[transport](beh)
v = rp.Vol(f"stall-{transport}", transport, [srv.url()], timeout="1s")
env = {"MAKI_LOG": MAKI_LOG} if MAKI_LOG else None
ok = True


def status():
    t = time.monotonic()
    r = v.maki("status", v.cfg, "--timeout", "10", timeout=30)
    dt = time.monotonic() - t
    try:
        d = json.loads(r.stdout)["data"]
        c = d["crypto"]
        return dt, {"state": d.get("state"), "io_state": d.get("io_state"),
                    "circuit": [e["circuit"] for e in c["endpoints"]],
                    "inflight": c.get("inflight_batches"), "pending_items": c.get("pending_items"),
                    "pending_bytes": c.get("pending_bytes"), "retries": c.get("retries_total")}
    except Exception as e:
        return dt, f"rc={r.returncode} {r.stdout[-200:]} {r.stderr[-200:]}"


try:
    v.create()
    v.start(env=env)
    h = rp.connect(v.sock)
    A = rp.pattern(0, 8192, 1)
    h.pwrite(A, 0, nbd.CMD_FLAG_FUA)
    C0 = rp.pattern(131072, 4096, 1)
    h.pwrite(C0, 131072, nbd.CMD_FLAG_FUA)
    print("baseline FUA writes acknowledged; status", status())
    rss0 = v.rss_kb()

    stalled.set()
    done = {}

    def cb(name):
        def f(err):
            done[name] = (time.monotonic() - t0, err.value)
            return 1
        return f

    t0 = time.monotonic()
    B = rp.pattern(65536, 8192, 2)
    cw = h.aio_pwrite(B, 65536, completion=cb("write-B"))
    time.sleep(0.3)
    cf = h.aio_flush(completion=cb("flush"))
    rbuf = nbd.Buffer(4096)
    cr = h.aio_pread(rbuf, 0, completion=cb("read-A"))
    zbuf = nbd.Buffer(4096)
    cz = h.aio_pread(zbuf, 1 << 20, completion=cb("read-hole"))
    # many more writers than nbdkit threads: memory must stay bounded
    extra = []
    big = [rp.pattern(262144 + i * 65536, 65536, 3) for i in range(40)]
    for i, d in enumerate(big):
        extra.append(h.aio_pwrite(d, 262144 + i * 65536, completion=cb(f"w{i}")))

    def pump(seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if h.poll(100) == -1:
                break

    pump(6)
    print("after 6s stalled: completed", {k: v_ for k, v_ in done.items()})
    print("server saw stalled requests:", seen_stalled["n"], "calls", beh.calls)
    print("status while stalled (seconds, summary):", status())
    print("rss kB before/after", rss0, v.rss_kb())
    log = v.read_log()
    print("log lines so far:", len(log.splitlines()))
    for line in log.splitlines()[-6:]:
        print("   LOG", line[:300])

    if mode == "heal":
        pump(8)
        print("status after 14s stalled:", status())
        stalled.clear(); release.set()
        t1 = time.monotonic()
        while len(done) < 44 and time.monotonic() - t1 < 60:
            h.poll(200)
        print("after heal: %d/44 completed in %.1fs; errors: %s" % (
            len(done), time.monotonic() - t1, {k: e for k, (t, e) in done.items() if e}))
        if len(done) < 44 or any(e for (t, e) in done.values()):
            ok = False
            print("FAIL: pending requests did not all complete cleanly after the endpoint healed")
        got = h.pread(8192, 65536)
        if got != B:
            ok = False
            print("FAIL: B readback", rp.describe(got[:512]))
        for i, d in enumerate(big):
            if h.pread(65536, 262144 + i * 65536) != d:
                ok = False
                print("FAIL: big", i)
        h.flush()
        print("status after heal:", status())
        h.shutdown()
        print("term rc", v.term())
        v.start(env=env)
        h = rp.connect(v.sock)
        assert h.pread(8192, 0) == A and h.pread(8192, 65536) == B
        for i, d in enumerate(big):
            assert h.pread(65536, 262144 + i * 65536) == d, i
        print("restart readback ok")
        h.shutdown()
        print("term rc", v.term())
    elif mode == "term":
        t1 = time.monotonic()
        v.proc.send_signal(signal.SIGTERM)
        rc = None
        for _ in range(300):
            if v.proc.poll() is not None:
                rc = v.proc.returncode
                break
            time.sleep(0.1)
            try:
                h.poll(0)
            except Exception:
                pass
        print("SIGTERM while stalled: exit=%s after %.1fs (None = still running after 30s)" % (rc, time.monotonic() - t1))
        print("completions at that point:", {k: e for k, (t, e) in done.items()})
        if rc is None:
            # second SIGTERM, then the client goes away
            v.proc.send_signal(signal.SIGTERM)
            time.sleep(3)
            print("after 2nd SIGTERM: poll", v.proc.poll())
            # the client goes away without a clean NBD shutdown
            try:
                import socket as _s
                dead = h          # keep the handle (and its fd number) alive
                _s.socket(fileno=os.dup(h.aio_get_fd())).shutdown(_s.SHUT_RDWR)
            except Exception as e:
                print("close err", e)
            time.sleep(5)
            print("after client disconnect +5s: poll", v.proc.poll())
            # now heal: does it exit on its own?
            stalled.clear(); release.set()
            for _ in range(300):
                if v.proc.poll() is not None:
                    break
                time.sleep(0.1)
            print("after heal: poll", v.proc.poll(), "%.1fs after SIGTERM" % (time.monotonic() - t1))
        for line in v.read_log().splitlines()[-12:]:
            print("   LOG", line[:300])
        v.kill9()
        stalled.clear(); release.set()
        v.start(env=env)
        h = rp.connect(v.sock)
        assert h.pread(8192, 0) == A, "acknowledged FUA write A lost"
        assert h.pread(4096, 131072) == C0, "acknowledged FUA write C0 lost"
        b = h.pread(8192, 65536)
        print("B after restart:", rp.describe(b[:512]), "(unacknowledged: either is fine)")
        h.shutdown(); print("term rc", v.term())
    elif mode == "kill":
        v.kill9()
        stalled.clear(); release.set()
        v.start(env=env)
        h = rp.connect(v.sock)
        assert h.pread(8192, 0) == A, "acknowledged FUA write A lost"
        assert h.pread(4096, 131072) == C0
        b = h.pread(8192, 65536)
        print("B after kill -9 + restart:", rp.describe(b[:512]))
        h.shutdown(); print("term rc", v.term())
except Exception as e:
    ok = False
    import traceback; traceback.print_exc()
    print(v.read_log()[-3000:])
finally:
    release.set()
    raw = v.all_logs_bytes()
    samples = [("A", rp.pattern(0, 512, 1)), ("B", rp.pattern(65536, 512, 2)), ("big", rp.pattern(262144, 512, 3))]
    print("secret grep in daemon logs:", rp.grep_secrets(raw, samples) or "none", "(%d log bytes)" % len(raw))
    v.cleanup()
    try:
        srv.stop()
    except Exception:
        pass
print("RESULT", "ok" if ok else "FAIL")
