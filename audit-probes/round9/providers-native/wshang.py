"""Does the daemon stop answering under bursts of concurrent one-sector
reads over the WebSocket transport? (seen once in memscan.py ws)"""
import sys, time, os, json, subprocess
import nbd, rp
transport = sys.argv[1] if len(sys.argv) > 1 else "ws"
rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 40
N, UNIT, SECT = 64, 4096, 512
beh = rp.Behaviour()
srv = {"http": rp.HttpServer, "ws": rp.WsServer, "grpc": rp.GrpcServer}[transport](beh)
v = rp.Vol(f"hang-{transport}", transport, [srv.url()], size="4MiB")
v.create(); v.start()
h = rp.connect(v.sock)
for u in range(N):
    h.pwrite(rp.pattern(u * UNIT, UNIT, 1), u * UNIT)
h.flush()
ok = True
for rnd in range(rounds):
    done, bufs = [], []
    for u in range(N):
        buf = nbd.Buffer(SECT); bufs.append(buf)
        h.aio_pread(buf, u * UNIT + 3 * SECT, completion=lambda e, d=done: d.append(e.value) or 1)
    t = time.monotonic()
    while len(done) < N and time.monotonic() - t < 20:
        h.poll(100)
    if len(done) < N:
        ok = False
        print(f"round {rnd}: only {len(done)}/{N} reads completed after 20 s; in flight per libnbd: {h.aio_in_flight()}")
        st = json.loads(v.maki("status", v.cfg, "--timeout", "10").stdout)["data"]
        print("   status crypto:", {k: st["crypto"][k] for k in ("inflight_batches", "pending_items", "pending_bytes", "batches_total")}, "endpoints", st["crypto"]["endpoints"])
        m = v.maki("metrics", v.cfg, "--timeout", "10").stdout
        for key in ("maki_active_requests", "maki_admission_slots", "maki_plaintext_bytes", "maki_requests_success_total", "maki_requests_error_total", "maki_requests_cancelled_total"):
            for line in m.splitlines():
                if f'"{key}"' in line:
                    print("   ", line.strip())
        print("   server calls", beh.calls, "ws connections", len(getattr(srv, "connections", [])))
        out = subprocess.run(["gdb", "-p", str(v.proc.pid), "-batch", "-ex", "thread apply all bt 12"], capture_output=True, text=True, timeout=120).stdout
        open(os.path.join(rp.HERE, "logs", f"wshang-{transport}-gdb.txt"), "w").write(out)
        import collections
        tops = collections.Counter()
        for block in out.split("\nThread ")[1:]:
            frames = [l for l in block.splitlines() if l.startswith("#")]
            sig = " <- ".join(f.split(" in ")[-1].split(" (")[0][:60] for f in frames[1:5])
            tops[sig] += 1
        for sig, c in tops.most_common(8):
            print(f"   {c:3} threads: {sig}")
        print(v.read_log()[-800:])
        break
    if any(done):
        print(f"round {rnd}: errors {[e for e in done if e]}")
print("RESULT", "ok" if ok else "HANG", transport, "rounds", rounds, "calls", beh.calls)
if ok:
    h.shutdown(); v.term()
v.cleanup(); srv.stop()
