"""What status/metrics report against what was actually done.
usage: truth.py [counters] [enospc] [syncfail]"""
import sys, os, json, time, subprocess, shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mk, ctl
which = set(sys.argv[1:]) or {"counters", "enospc", "syncfail"}
bad = []
def expect(name, got, want):
    ok = got == want
    print(f"  {'ok ' if ok else 'MISMATCH'} {name}: reported {got!r}, truth {want!r}")
    if not ok: bad.append(name)


def term_traced(v, timeout=60):
    """SIGTERM the traced nbdkit (child of strace), then wait for strace."""
    kids = subprocess.run(["pgrep", "-P", str(v.proc.pid)], capture_output=True, text=True).stdout.split()
    for k in kids: os.kill(int(k), 15)
    try: rc = v.proc.wait(timeout)
    except subprocess.TimeoutExpired: rc = None
    v.notify.close()
    return rc

def pick(d, *keys): return {k: d.get(k) for k in keys}

if "counters" in which:
    print("== counters ==")
    v = mk.Vol(tag="truth", discard=True, cache='mode = "read"\nmax_bytes = "1MiB"\nttl = "30s"')
    try:
        v.create(); v.start(); h = mk.connect(v.sock)
        m0 = ctl.metrics(v.control); s0 = ctl.status(v.control)
        N, M, F, R, T = 37, 5, 4, 11, 3
        for i in range(N): h.pwrite(mk.pattern(i * 4096, 4096, 1), i * 4096)
        for i in range(M): h.flush()
        import nbd
        for i in range(F): h.pwrite(mk.pattern((100 + i) * 4096, 4096, 2), (100 + i) * 4096, nbd.CMD_FLAG_FUA)
        for i in range(R): h.pread(4096, i * 4096)
        for i in range(T): h.trim(4096, (200 + i) * 4096)
        # two refused requests: beyond the end, misaligned
        errs = 0
        for off, ln in ((4 * 1024 * 1024, 4096),):
            try: h.pwrite(b"\0" * ln, off)
            except Exception: errs += 1
        m = ctl.metrics(v.control); s = ctl.status(v.control)
        d = lambda k: m[k] - m0[k]
        expect("maki_write_request_seconds_count", d("maki_write_request_seconds_count"), N + F)
        expect("maki_flush_request_seconds_count", d("maki_flush_request_seconds_count"), M)
        expect("maki_flush_seconds_count", d("maki_flush_seconds_count"), M)
        expect("maki_fua_request_seconds_count", d("maki_fua_request_seconds_count"), F)
        expect("maki_fua_seconds_count", d("maki_fua_seconds_count"), F)
        expect("maki_read_request_seconds_count", d("maki_read_request_seconds_count"), R)
        expect("maki_trim_request_seconds_count", d("maki_trim_request_seconds_count"), T)
        expect("maki_requests_success_total", d("maki_requests_success_total"), N + M + F + R + T)
        expect("maki_request_seconds_count", d("maki_request_seconds_count"), N + M + F + R + T)
        expect("maki_requests_error_total", d("maki_requests_error_total"), 0)
        expect("appended_sequence", s["appended_sequence"], N + F + T)
        print("  status:", pick(s, "appended_sequence", "durable_sequence", "checkpoint_sequence", "journal_bytes", "journal_pending_bytes", "checkpoints_total"))
        print("  metrics:", pick(m, "maki_overlay_units", "maki_overlay_bytes", "maki_ciphertext_bytes", "maki_journal_segments", "maki_checkpoint_lag_bytes", "maki_cache_entries", "maki_cache_hits_total", "maki_cache_misses_total", "maki_active_requests", "maki_admission_slots", "maki_plaintext_bytes"))
        h.flush()
        s = ctl.status(v.control)
        expect("durable == appended after FLUSH", s["durable_sequence"], s["appended_sequence"])
        expect("journal_pending_bytes after FLUSH", s["journal_pending_bytes"], 0)
        r = ctl.call(v.control, {"command": "checkpoint"})
        s2 = ctl.status(v.control); m2 = ctl.metrics(v.control)
        expect("checkpoint verb returned sequence", r["data"]["checkpoint_sequence"], s["durable_sequence"])
        expect("status checkpoint_sequence", s2["checkpoint_sequence"], s["durable_sequence"])
        expect("checkpoints_total +1", s2["checkpoints_total"] - s["checkpoints_total"], 1)
        expect("overlay empty after checkpoint", m2["maki_overlay_units"], 0)
        expect("checkpoint lag 0", m2["maki_checkpoint_lag_bytes"], 0)
        print("  after checkpoint:", pick(s2, "journal_bytes", "journal_pending_bytes"), pick(m2, "maki_journal_segments", "maki_ciphertext_bytes"))
        # idle checkpoint again: counted? sequence unchanged
        r = ctl.call(v.control, {"command": "checkpoint"}); s3 = ctl.status(v.control)
        print("  second (no-op) checkpoint:", r, "checkpoints_total", s3["checkpoints_total"])
        h.shutdown(); print("  term rc", v.term())
    finally:
        v.cleanup()

if "enospc" in which:
    print("== ENOSPC on a small tmpfs ==")
    mnt = "/tmp/a9c-tmpfs-truth"
    os.makedirs(mnt, exist_ok=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "size=3m", "tmpfs", mnt], check=True)
    v = mk.Vol(tag="enospc", size="16MiB", backing_dir=os.path.join(mnt, "volume"), shard="1MiB", seg="256KiB", jmax="1MiB", max_io="64KiB")
    try:
        v.create(); v.start(); h = mk.connect(v.sock)
        ok = err = 0; first_err = None
        t0 = time.monotonic()
        import random; r = random.Random(1)
        while err < 40 and time.monotonic() - t0 < 60:
            b = r.randrange(4096)
            try:
                h.pwrite(os.urandom(4096), b * 4096); ok += 1
                if ok % 16 == 0: h.flush()
            except Exception as e:
                err += 1; first_err = first_err or str(e)
        s = ctl.status(v.control); m = ctl.metrics(v.control)
        print(f"  writes ok {ok}, failed {err}; first error: {first_err}")
        print("  status:", pick(s, "state", "last_observed_state", "degraded_reason", "io_state", "backing_free_bytes", "checkpoint_failures_total", "checkpoints_total", "journal_sync_failures_total", "journal_writeback_uncertain", "appended_sequence", "durable_sequence", "checkpoint_sequence"))
        print("  metrics:", pick(m, "maki_volume_state", "maki_requests_error_total", "maki_requests_success_total", "maki_backing_free_bytes", "maki_checkpoint_failures_total"))
        print("  statvfs free now:", os.statvfs(mnt).f_bavail * os.statvfs(mnt).f_frsize)
        r2 = ctl.call(v.control, {"command": "checkpoint"}); print("  checkpoint verb under ENOSPC:", r2)
        s = ctl.status(v.control); print("  status after:", pick(s, "state", "degraded_reason", "checkpoint_failures_total"))
        # make room: enlarge the tmpfs
        subprocess.run(["mount", "-o", "remount,size=64m", mnt], check=True)
        okw = 0
        for i in range(20):
            try: h.pwrite(os.urandom(4096), i * 4096); h.flush(); okw += 1
            except Exception as e: last = str(e)
        r3 = ctl.call(v.control, {"command": "checkpoint"})
        s = ctl.status(v.control)
        print(f"  after space returned: {okw}/20 write+flush ok; checkpoint {r3}")
        print("  status:", pick(s, "state", "degraded_reason", "checkpoint_failures_total", "checkpoints_total", "backing_free_bytes"))
        h.shutdown(); print("  term rc", v.term())
        for line in v.read_log().splitlines()[:12]: print("  LOG:", line[:260])
    finally:
        v.cleanup(); subprocess.run(["umount", mnt]); os.rmdir(mnt)

if "syncfail" in which:
    print("== failed fdatasync (strace injection) ==")
    v = mk.Vol(tag="syncfail")
    try:
        v.create()
        # inject EIO into the 6th..8th fdatasync of the serving process (startup uses some; found by trial)
        tr = os.path.join(v.dir, "count.trace")
        v.start(); v.term()                      # first start of a fresh volume
        v.start(wrapper=("strace", "-f", "-qq", "-e", "trace=fdatasync", "-o", tr))
        time.sleep(1.0)
        k = sum(1 for l in open(tr) if "fdatasync(" in l)
        term_traced(v)
        total = sum(1 for l in open(tr) if "fdatasync(" in l)
        print(f"  fdatasync calls: {k} until READY, {total} with the clean stop of an idle volume")
        nfail = int(os.environ.get("SYNC_FAILS", "2"))
        v.start(wrapper=("strace", "-f", "-qq", "-e", "trace=fdatasync", "-e", f"inject=fdatasync:error=EIO:when={k + 1}..{k + nfail}", "-o", os.path.join(v.dir, "inj.trace")))
        h = mk.connect(v.sock)
        s = ctl.status(v.control); print("  before:", pick(s, "state", "journal_sync_failures_total", "journal_writeback_uncertain"))
        acked = {}
        for i in range(8):
            w = f = "-"
            try: h.pwrite(mk.pattern(i * 4096, 4096, 9), i * 4096); w = "ok"
            except Exception as e: w = "EIO" if "Input/output" in str(e) else str(e)[:40]
            try:
                h.flush(); f = "ok"
                if w == "ok": acked[i] = 9
            except Exception as e: f = "EIO" if "Input/output" in str(e) else str(e)[:40]
            s = ctl.status(v.control); m = ctl.metrics(v.control)
            print(f"  op {i}: write {w:3} flush {f:3} status", pick(s, "state", "degraded_reason", "journal_sync_failures_total", "journal_writeback_uncertain", "durable_sequence", "appended_sequence", "journal_pending_bytes"), "metrics", pick(m, "maki_volume_state", "maki_requests_error_total", "maki_flush_seconds_count", "maki_flush_request_seconds_count", "maki_journal_sync_seconds_count"))
            if i == 3:
                print("   checkpoint verb while uncertain/after:", ctl.call(v.control, {"command": "checkpoint"}), pick(ctl.status(v.control), "state", "degraded_reason", "checkpoint_failures_total"))
        for i, ver in acked.items():
            assert h.pread(4096, i * 4096) == mk.pattern(i * 4096, 4096, ver), i
        h.shutdown(); print("  term rc", term_traced(v))
        for line in v.read_log().splitlines()[:10]: print("  LOG:", line[:300])
        print("  injected:", sum(1 for l in open(os.path.join(v.dir, "inj.trace")) if "INJECTED" in l))
    finally:
        v.cleanup()
print("MISMATCHES:", bad)
