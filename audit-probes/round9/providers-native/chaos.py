"""Seeded chaos soak through the real daemon: concurrent NBD workload with a
per-sector oracle while the endpoint(s) misbehave in transport-class ways
(errors, stalls, dead connections, redirects, throttling), with daemon
kill -9 / SIGTERM restarts in between.

Under `stall` + retry_safe no client-visible error is ever expected. Under
bounded-error or retry_safe=false errors are allowed; a failed or
unacknowledged write leaves each of its sectors old or new.

usage: chaos.py <http|ws|grpc> --seed N [--seconds 40] [--policy stall|bounded-error]
                [--unsafe] [--endpoints 1|2] [--kills 2] [--tls] [--cache]
"""
import argparse, asyncio, base64, json, os, random, signal, sys, threading, time
import nbd
import rp

ap = argparse.ArgumentParser()
ap.add_argument("transport")
ap.add_argument("--seed", type=int, default=1)
ap.add_argument("--seconds", type=float, default=40)
ap.add_argument("--policy", default="stall")
ap.add_argument("--unsafe", action="store_true")
ap.add_argument("--endpoints", type=int, default=1)
ap.add_argument("--kills", type=int, default=2)
ap.add_argument("--cache", action="store_true")
ap.add_argument("--badness", type=float, default=0.35)
args = ap.parse_args()
rng = random.Random(args.seed)
transport = args.transport
UNIT = 4096
SIZE = 4 << 20
SECT = 512

class Chaos:
    """Per-endpoint misbehaviour state shared with the server hook."""
    def __init__(self, name):
        self.name = name
        self.mode = "ok"
        self.p = 0.0
        self.rng = random.Random(args.seed * 1000 + hash(name) % 997)
        self.count = {}

    def pick(self):
        if self.mode == "ok" or self.rng.random() >= self.p:
            return "ok"
        m = self.mode
        if m == "mix":
            m = self.rng.choice(MODES[transport])
        self.count[m] = self.count.get(m, 0) + 1
        return m


MODES = {
    "http": ["503", "429", "stall", "truncate", "redirect", "401", "slow", "drop", "500"],
    "ws": ["retryable", "throttled", "stall", "abort", "close", "stale", "dup", "slow"],
    "grpc": ["unavailable", "exhausted", "stall", "cancel", "unauth", "internal", "deadline", "slow"],
}


def make_hook(beh, chaos):
    def hook(kind, op, req):
        m = chaos.pick()
        if m == "ok":
            return None
        if kind == "http":
            if m == "503": return dict(status=503)
            if m == "500": return dict(status=500, body=b"oops")
            if m == "429": return dict(status=429, headers={"retry-after": "5"})
            if m == "401": return dict(status=401)
            if m == "redirect": return dict(status=307, headers={"location": "http://127.0.0.1:9/x"})
            if m == "stall":
                time.sleep(2.5); return dict(status=503)
            if m == "slow":
                time.sleep(0.3); return None
            if m == "truncate":
                return dict(body=b'{"items":[{"unit":1,"data":"AAAA', declared_length=4000, cut_after=20)
            if m == "drop":
                h = req["handler"]
                try:
                    h.connection.shutdown(2)
                except Exception:
                    pass
                h.close_connection = True
                return "handled"
        if kind == "ws":
            j, ws = req["json"], req["ws"]
            if m == "retryable": return {"id": j["id"], "error": {"class": "retryable"}}
            if m == "throttled": return {"id": j["id"], "error": {"class": "throttled"}}
            async def go():
                if m == "stall":
                    await asyncio.sleep(2.5); return "handled"
                if m == "slow":
                    await asyncio.sleep(0.3); return None
                if m == "abort":
                    ws.transport.abort(); return "handled"
                if m == "close":
                    await ws.close(1001, "going away"); return "handled"
                if m == "stale":
                    await ws.send(json.dumps({"id": j["id"] + 7777777, "items": []})); return None
                if m == "dup":
                    items = [(i["unit"], base64.b64decode(i["data"])) for i in j["items"]]
                    try:
                        out = beh.run(op, j.get("volume"), j.get("profile"), j.get("format"), items)
                    except rp.IntegrityError:
                        return None
                    msg = json.dumps({"id": j["id"], "items": [{"unit": u, "data": rp.b64(d)} for u, d in out]})
                    await ws.send(msg); await ws.send(msg); return "handled"
                return None
            return go()
        if kind == "grpc":
            import grpc
            ctx = req["context"]
            if m == "unavailable": ctx.abort(grpc.StatusCode.UNAVAILABLE, "x")
            if m == "exhausted": ctx.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, "x")
            if m == "unauth": ctx.abort(grpc.StatusCode.UNAUTHENTICATED, "x")
            if m == "internal": ctx.abort(grpc.StatusCode.INTERNAL, "x")
            if m == "deadline": ctx.abort(grpc.StatusCode.DEADLINE_EXCEEDED, "x")
            if m == "stall":
                time.sleep(2.5); ctx.abort(grpc.StatusCode.UNAVAILABLE, "x")
            if m == "slow":
                time.sleep(0.3); return None
            if m == "cancel":
                ctx.cancel(); return "handled"
        return None
    return hook


cipher = rp.Cipher()
servers, chaoses = [], []
for i in range(args.endpoints):
    beh = rp.Behaviour(cipher)
    ch = Chaos(f"ep{i}")
    beh.hook = make_hook(beh, ch)
    servers.append({"http": rp.HttpServer, "ws": rp.WsServer, "grpc": rp.GrpcServer}[transport](beh))
    chaoses.append(ch)

cfg = dict(timeout="1s", size="4MiB", retry_safe=not args.unsafe, policy=args.policy,
           jmax="1MiB", seg="64KiB")
if args.policy != "stall":
    cfg["max_operation_time"] = "2s"
if args.cache:
    cfg["cache"] = 'mode = "read"\nmax_bytes = "1MiB"\nttl = "2s"'
v = rp.Vol(f"chaos-{transport}-{args.seed}", transport, [s.url() for s in servers], **cfg)
strict = args.policy == "stall" and not args.unsafe

nsect = SIZE // SECT
acked = [0] * nsect                 # version each sector is known to hold (0 = zeros)
maybe = [set() for _ in range(nsect)]   # other versions it may hold
problems = []
stats = {"w": 0, "r": 0, "f": 0, "z": 0, "err": 0, "kill": 0, "term": 0, "verified": 0}
version = [0]


def expected_ok(off, data):
    for i in range(len(data) // SECT):
        s = off // SECT + i
        sec = data[i * SECT:(i + 1) * SECT]
        ok = [acked[s]] + list(maybe[s])
        if not any((sec == bytes(SECT)) if ver == 0 else (sec == rp.pattern(s * SECT, SECT, ver)) for ver in ok):
            return s, rp.describe(sec), ok
    return None


class Driver:
    def __init__(self):
        self.h = None
        self.inflight = {}   # cookie -> (kind, off, len, ver, buf)
        self.busy = set()    # unit indexes in flight

    def connect(self):
        self.h = rp.connect(v.sock)
        self.inflight.clear(); self.busy.clear()

    def region(self):
        for _ in range(50):
            units = rng.choice([1, 1, 1, 2, 3, 4, 8, 16])
            first = rng.randrange(0, SIZE // UNIT - units + 1)
            span = set(range(first, first + units))
            if not span & self.busy:
                # sub-unit alignment sometimes
                off = first * UNIT
                length = units * UNIT
                if rng.random() < 0.3:
                    cut = rng.randrange(0, 8) * SECT
                    off += cut; length -= cut
                    tail = rng.randrange(0, 8) * SECT
                    if length - tail >= SECT:
                        length -= tail
                return span, off, length
        return None

    def submit(self):
        r = self.region()
        if r is None:
            return
        span, off, length = r
        kind = rng.choices(["w", "r", "f", "z"], [5, 4, 1, 1])[0]
        key = object()

        def done(err, key=key):
            self.finish(key, err.value)
            return 1
        if kind == "w":
            version[0] += 1
            data = rp.pattern(off, length, version[0])
            fua = nbd.CMD_FLAG_FUA if rng.random() < 0.3 else 0
            self.inflight[key] = ("w", off, length, version[0], None, span)
            self.busy |= span
            for i in range(length // SECT):
                maybe[off // SECT + i].add(version[0])
            self.h.aio_pwrite(data, off, completion=done, flags=fua)
        elif kind == "z":
            self.inflight[key] = ("z", off, length, 0, None, span)
            self.busy |= span
            for i in range(length // SECT):
                maybe[off // SECT + i].add(0)
            self.h.aio_zero(length, off, completion=done, flags=nbd.CMD_FLAG_NO_HOLE)
        elif kind == "r":
            buf = nbd.Buffer(length)
            self.inflight[key] = ("r", off, length, 0, buf, span)
            self.busy |= span
            self.h.aio_pread(buf, off, completion=done)
        else:
            self.inflight[key] = ("f", 0, 0, 0, None, set())
            self.h.aio_flush(completion=done)

    def finish(self, key, err):
        if key not in self.inflight:
            return      # a request of a connection that died with its daemon
        kind, off, length, ver, buf, span = self.inflight.pop(key)
        self.busy -= span
        stats[kind] += 1
        if err:
            stats["err"] += 1
            if strict:
                problems.append(f"{kind} at {off}+{length} failed errno {err} under stall+retry_safe")
            return          # failed write/zero: old or new stays acceptable
        if kind in ("w", "z"):
            for i in range(length // SECT):
                s = off // SECT + i
                acked[s] = ver
                maybe[s] = set()
        elif kind == "r":
            bad = expected_ok(off, buf.to_bytearray())
            stats["verified"] += 1
            if bad:
                problems.append(f"READ WRONG DATA at sector {bad[0]}: got {bad[1]}, acceptable versions {bad[2]}")

    def pump(self, seconds, target=8):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            while len(self.inflight) < target:
                self.submit()
            if self.h.poll(50) == -1:
                break

    def drain(self, seconds):
        end = time.monotonic() + seconds
        while self.inflight and time.monotonic() < end:
            self.h.poll(100)
        return not self.inflight


def verify_all(tag):
    h = rp.connect(v.sock)
    bad = 0
    for off in range(0, SIZE, 65536):
        got = h.pread(65536, off)
        b = expected_ok(off, got)
        if b:
            bad += 1
            problems.append(f"{tag}: sector {b[0]} holds {b[1]}, acceptable {b[2]}")
    h.shutdown()
    return bad


def set_chaos(mode, p=1.0, which=None):
    for i, ch in enumerate(chaoses):
        if which is None or i in which:
            ch.mode, ch.p = mode, p


t_start = time.monotonic()
try:
    v.create()
    v.start()
    d = Driver(); d.connect()
    phases = max(4, int(args.seconds / 4))
    kill_at = set(rng.sample(range(1, phases), min(args.kills, phases - 1)))
    for phase in range(phases):
        roll = rng.random()
        if roll < args.badness:
            mode = rng.choice(MODES[transport] + ["mix", "mix"])
            which = None if args.endpoints == 1 or rng.random() < 0.4 else {rng.randrange(args.endpoints)}
            set_chaos(mode, rng.choice([0.3, 0.7, 1.0]), which)
        elif roll < args.badness + 0.15:
            set_chaos("mix", 0.2)
        else:
            set_chaos("ok")
        d.pump(args.seconds / phases)
        if phase in kill_at:
            hard = rng.random() < 0.7
            if hard:
                stats["kill"] += 1
                v.kill9()
            else:
                stats["term"] += 1
                set_chaos("ok")
                if not d.drain(30):
                    problems.append("requests still pending 30 s after the endpoints healed (before SIGTERM)")
                d.h.shutdown()
                rc = v.term(60)
                if rc != 0:
                    problems.append(f"SIGTERM exit {rc}")
                    v.kill9()
            # in-flight requests are unacknowledged: old or new (already in `maybe`)
            d.inflight.clear(); d.busy.clear()
            set_chaos("ok")
            v.start()
            bad = verify_all(f"after {'kill -9' if hard else 'SIGTERM'} in phase {phase}")
            # after a verified restart, collapse nothing: maybe-sets stay until rewritten
            d.connect()
    set_chaos("ok")
    if not d.drain(60):
        problems.append(f"{len(d.inflight)} request(s) still pending 60 s after every endpoint healed")
    else:
        d.h.flush()
        d.h.shutdown()
    st = v.maki("status", v.cfg, "--timeout", "10", timeout=30)
    try:
        c = json.loads(st.stdout)["data"]["crypto"]
        tail = {"circuit": [e["circuit"] for e in c["endpoints"]], "inflight": c["inflight_batches"],
                "pending_items": c["pending_items"], "pending_bytes": c["pending_bytes"]}
        if d.inflight == {} and (c["inflight_batches"] or c["pending_items"] or c["pending_bytes"]):
            problems.append(f"scheduler accounting not back to zero when idle: {tail}")
    except Exception as e:
        tail = f"status failed: {st.returncode} {st.stderr[-200:]}"
    rc = v.term(60)
    if rc != 0:
        problems.append(f"final SIGTERM exit {rc}")
        v.kill9()
    v.start()
    verify_all("final restart")
    rc = v.term(60)
except Exception as e:
    import traceback; traceback.print_exc()
    problems.append(f"exception {e!r}")
    try:
        print(v.read_log()[-2000:])
    except Exception:
        pass
finally:
    logs = v.all_logs_bytes()
    warn = [l for l in logs.decode("utf-8", "replace").splitlines() if " WARN " in l or " ERROR " in l or "panic" in l.lower()]
    v.cleanup()
    for s in servers:
        try:
            s.stop()
        except Exception:
            pass
counts = {c.name: c.count for c in chaoses}
print(f"{'FAIL' if problems else 'ok'} {transport} seed={args.seed} policy={args.policy} unsafe={args.unsafe} eps={args.endpoints} "
      f"{stats} chaos={counts} warn_lines={len(warn)} {time.monotonic() - t_start:.0f}s")
for p in problems[:12]:
    print("   -", p)
if problems:
    for l in warn[:8]:
        print("   LOG", l[:260])
sys.exit(1 if problems else 0)
