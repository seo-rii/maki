"""Round 9 (takeover): control plane while the only endpoint is stalled
(stall policy) with writes waiting for encryption. `maki checkpoint`,
`maki drain` (both bounded with --timeout), `maki status`; then heal, the
pending writes must complete, a retried drain must succeed, every
acknowledged write must read back after a restart, and the log must not
carry plaintext.

usage: stall_ctl.py <http|ws|grpc>
"""
import asyncio, json, os, sys, threading, time
import nbd
import rp

transport = sys.argv[1]
beh = rp.Behaviour()
stalled, release = threading.Event(), threading.Event()


def hook(kind, op, req):
    if not stalled.is_set():
        return None
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
v = rp.Vol(f"sctl-{transport}", transport, [srv.url()], timeout="1s")
problems = []


def ctl(*args, t=8):
    t0 = time.monotonic()
    r = v.maki(*args, v.cfg, "--timeout", str(t), timeout=t + 30)
    try:
        d = json.loads(r.stdout)
    except Exception:
        d = None
    return round(time.monotonic() - t0, 1), r.returncode, d, (r.stderr.strip().splitlines() or [""])[-1][:120]


try:
    v.create()
    v.start()
    h = rp.connect(v.sock)
    acked = {}
    for i in range(8):
        data = rp.pattern(i * 8192, 8192, 1)
        h.pwrite(data, i * 8192, nbd.CMD_FLAG_FUA)
        acked[i * 8192] = data
    stalled.set()
    pend = {}
    for i in range(8, 24):
        data = rp.pattern(i * 8192, 8192, 2)
        pend[i * 8192] = data
        h.aio_pwrite(nbd.Buffer.from_bytearray(bytearray(data)), i * 8192)
    t = time.monotonic()
    while time.monotonic() - t < 3:
        h.poll(100)
    print("pending in libnbd:", h.aio_in_flight())
    dt, rc, d, err = ctl("status", t=5)
    print(f"status during stall: {dt}s rc={rc} io_state={d and d['data'].get('io_state')} state={d and d['data'].get('state')}")
    dt, rc, d, err = ctl("checkpoint", t=8)
    print(f"checkpoint during stall: {dt}s rc={rc} {json.dumps(d)[:160] if d else err}")
    dt, rc, d, err = ctl("drain", t=8)
    print(f"drain during stall: {dt}s rc={rc} {json.dumps(d)[:160] if d else err}")
    dt, rc, d, err = ctl("status", t=5)
    print(f"status after timed-out drain: {dt}s rc={rc} io_state={d and d['data'].get('io_state')} drain_error={d and d['data'].get('drain_error')}")
    # a new request now: admission is closed
    late = []
    h.aio_pwrite(nbd.Buffer.from_bytearray(bytearray(b"x" * 512)), 512 * 1000,
                 completion=lambda e, l=late: l.append(e.value) or 1)
    t = time.monotonic()
    while not late and time.monotonic() - t < 5:
        h.poll(100)
    print("write after drain started:", "no answer in 5 s" if not late else f"answered errno={late[0]}", flush=True)
    stalled.clear(); release.set()
    t = time.monotonic()
    while h.aio_in_flight() and time.monotonic() - t < 30:
        h.poll(100)
    print("pending after heal:", h.aio_in_flight(), f"{time.monotonic() - t:.1f}s")
    for k in range(10):
        dt, rc, d, err = ctl("status", t=5)
        print(f"status +{k*2}s after heal: io_state={d and d['data'].get('io_state')} drain_error={d and d['data'].get('drain_error')} state={d and d['data'].get('state')}")
        dt, rc, d, err = ctl("drain", t=30)
        print(f"drain retry +{k*2}s after heal: {dt}s rc={rc} {json.dumps(d)[:160] if d else err}")
        if rc == 0:
            break
        time.sleep(2)
    if rc != 0:
        problems.append(f"drain after heal failed rc={rc} {err}")
    h.shutdown()
    print("term rc", v.term())
    v.start()
    h = rp.connect(v.sock)
    bad = 0
    for off, data in acked.items():
        if h.pread(len(data), off) != data:
            bad += 1
    for off, data in pend.items():
        got = h.pread(len(data), off)
        if got not in (data, bytes(len(data))):
            bad += 1
    print(f"after restart: {len(acked)} acknowledged + {len(pend)} healed-pending regions checked, bad={bad}")
    if bad:
        problems.append(f"{bad} bad regions")
    h.shutdown()
    v.term()
    logs = v.all_logs_bytes()
    hits = rp.grep_secrets(logs, [(f'a{o}', d) for o, d in list(acked.items())[:4]] + [(f'p{o}', d) for o, d in list(pend.items())[:4]])
    print("log bytes", len(logs), "plaintext hits", hits or "none")
    if hits:
        problems.append("plaintext in log")
except Exception as e:
    import traceback; traceback.print_exc()
    problems.append(repr(e))
    print(v.read_log()[-1500:])
finally:
    release.set()
    v.cleanup(); srv.stop()
print("RESULT", "ok" if not problems else "FAIL", transport, problems)
