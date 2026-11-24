"""Journal barrier sync failures on a warm volume: attach strace to the serving nbdkit, fail every
fdatasync for a while, detach, and compare status/metrics with what the client saw."""
import sys, os, json, time, subprocess, signal
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mk, ctl
def pick(d, *keys): return {k: d.get(k) for k in keys}
KS = ("state", "last_observed_state", "degraded_reason", "journal_sync_failures_total", "journal_writeback_uncertain", "durable_sequence", "appended_sequence", "checkpoint_sequence", "journal_pending_bytes", "checkpoint_failures_total")
KM = ("maki_volume_state", "maki_requests_error_total", "maki_flush_seconds_count", "maki_flush_request_seconds_count", "maki_journal_sync_seconds_count", "maki_journal_sync_failures_total", "maki_journal_writeback_uncertain")
v = mk.Vol(tag="syncfail2")
try:
    v.create(); v.start(); h = mk.connect(v.sock)
    for i in range(4):
        h.pwrite(mk.pattern(i * 4096, 4096, 1), i * 4096); h.flush()
    print("warm:", pick(ctl.status(v.control), *KS))
    tr = os.path.join(v.dir, "inj.trace")
    st = subprocess.Popen(["strace", "-f", "-qq", "-p", str(v.proc.pid), "-e", "trace=fdatasync", "-e", "inject=fdatasync:error=EIO", "-o", tr], stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    def op(i, ver, fua=False):
        import nbd
        w = f = "-"
        try: h.pwrite(mk.pattern(i * 4096, 4096, ver), i * 4096, nbd.CMD_FLAG_FUA if fua else 0); w = "ok"
        except Exception as e: w = "EIO" if "Input/output" in str(e) else str(e)[-40:]
        if not fua:
            try: h.flush(); f = "ok"
            except Exception as e: f = "EIO" if "Input/output" in str(e) else str(e)[-40:]
        return w, f
    acked = {i: 1 for i in range(4)}
    print("-- every fdatasync fails --")
    for i in range(4, 8):
        w, f = op(i, 2, fua=(i == 7))
        s = ctl.status(v.control); m = ctl.metrics(v.control)
        print(f" op {i}: write {w} flush {f}\n    status {pick(s, *KS)}\n    metrics {pick(m, *KM)}")
    r = ctl.call(v.control, {"command": "checkpoint"}); print(" checkpoint verb:", r)
    print("    status", pick(ctl.status(v.control), *KS))
    r = ctl.call(v.control, {"command": "drain"}, timeout=60); print(" drain verb:", r)
    s = ctl.status(v.control); print("    status", pick(s, *KS), pick(s, "io_state", "drain_error"))
    st.send_signal(signal.SIGINT); st.wait()
    print("-- injection removed --")
    for i in range(8, 11):
        w, f = op(i, 3)
        if w == f == "ok": acked[i] = 3
        s = ctl.status(v.control); m = ctl.metrics(v.control)
        print(f" op {i}: write {w} flush {f}\n    status {pick(s, *KS)} {pick(s, 'io_state', 'drain_error')}\n    metrics {pick(m, *KM)}")
    r = ctl.call(v.control, {"command": "drain"}, timeout=60); print(" drain verb again:", r)
    s = ctl.status(v.control); print("    status", pick(s, *KS), pick(s, "io_state", "drain_error"))
    h.shutdown(); print("term rc", v.term())
    for line in v.read_log().splitlines()[:14]: print("LOG:", line[:330])
    print("injected:", sum(1 for l in open(tr) if "INJECTED" in l))
    # restart and read back what was acknowledged with a successful flush
    v.start(); h = mk.connect(v.sock)
    for i, ver in acked.items():
        got = h.pread(4096, i * 4096)
        print(" block", i, "expected v%d:" % ver, "ok" if got == mk.pattern(i * 4096, 4096, ver) else "MISMATCH " + mk.describe(got[:512]))
    print("after restart:", pick(ctl.status(v.control), *KS))
    h.shutdown(); v.term()
finally:
    v.cleanup()
