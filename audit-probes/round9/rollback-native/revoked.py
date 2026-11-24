#!/usr/bin/python3.12
"""Successor probe: what `maki status` / `maki metrics` report for a daemon whose remote
rollback session has stopped for good (taken over by an administrator) while every I/O
returns EIO. Prints the status/metrics fields once per second for --secs seconds.

usage: revoked.py [--secs 40] [--interval 1]
"""
import os, sys, subprocess, shutil, time, json, argparse
import mk9 as mk, rw
import nbd

P = argparse.ArgumentParser()
P.add_argument("--secs", type=float, default=40)
P.add_argument("--interval", type=float, default=1)
P.add_argument("--checkpoint-first", action="store_true", help="run `maki checkpoint` (everything checkpointed, journal empty) before the takeover")
P.add_argument("--quiet-log", action="store_true")
A = P.parse_args()
base = os.path.join(mk.BASE, f"revoked-{os.getpid()}")
os.makedirs(base)
root = os.path.join(base, "volume"); os.makedirs(root, mode=0o700)
v = mk.Vol("rv", discard=True, backing_dir=root, size="1MiB", ckpt_reserve="256KiB", reserve="64KiB", extra_backing="@@R@@")
auth = rw.Authority(os.path.join(v.dir, "auth"), os.path.join(base, "state"), timeout_ms=1500)
text = v.text
open(v.cfg, "w").write(text.replace("@@R@@", auth.remote_section("4MiB", "writer")))
admin = os.path.join(v.dir, "admin.toml")
open(admin, "w").write(text.replace("@@R@@", auth.remote_section("4MiB", "admin"))); os.chmod(admin, 0o644)


def fields():
    st = v.maki("status", v.cfg)
    mt = v.maki("metrics", v.cfg)
    try:
        s = json.loads(st.stdout)["data"]
        m = json.loads(mt.stdout)["data"]
        return (s.get("state"), s.get("degraded_reason"), s.get("journal_sync_failures_total"), s.get("journal_writeback_uncertain"),
                s.get("checkpoint_failures_total"), s.get("io_state"), m.get("maki_volume_state"))
    except Exception as e:
        return ("?", f"{st.returncode} {st.stdout[:150]} {st.stderr[:150]} {mt.stdout[:100]}", None, None, None, None, None)


v2 = None
try:
    auth.init(); auth.start()
    r = v.create(check=False)
    assert r.returncode == 0, r.stderr
    v.start(timeout=60)
    h = mk.connect(v.sock)
    for u in range(8):
        h.pwrite(mk.pattern(u * 4096, 4096, 100 + u, 1), u * 4096, nbd.CMD_FLAG_FUA)
    if A.checkpoint_first:
        c = v.maki("checkpoint", v.cfg)
        print(f"maki checkpoint: rc={c.returncode} {c.stdout.strip()[:200]} {c.stderr.strip()[:200]}")
    print("before takeover:", fields())
    rec = json.loads(v.maki("volume", "witness", v.cfg).stdout)
    t = v.maki("volume", "takeover", admin, str(rec["fence"]), rw.root_hex(rec))
    print(f"takeover beside the live daemon: rc={t.returncode} {t.stderr.strip()[-200:]}")
    for kind in ("write-fua", "flush", "read"):
        try:
            if kind == "write-fua":
                h.pwrite(mk.pattern(9 * 4096, 4096, 999, 1), 9 * 4096, nbd.CMD_FLAG_FUA)
            elif kind == "flush":
                h.flush()
            else:
                h.pread(4096, 0)
            print(f"  old daemon {kind}: ok")
        except nbd.Error as e:
            print(f"  old daemon {kind}: {e}")
    t0 = time.monotonic()
    seen = None
    while time.monotonic() - t0 < A.secs:
        f = fields()
        if f != seen:
            print(f"  +{time.monotonic() - t0:5.1f}s state={f[0]} degraded_reason={str(f[1])[:160]} journal_sync_failures_total={f[2]} "
                  f"journal_writeback_uncertain={f[3]} checkpoint_failures_total={f[4]} io_state={f[5]} maki_volume_state={f[6]}", flush=True)
            seen = f
        try:
            h.pread(4096, 0)
            print("  the revoked daemon served a read")
        except nbd.Error:
            pass
        time.sleep(A.interval)
    log = v.read_log()
    print("daemon log (WARN/ERROR lines):")
    lines = [l for l in log.splitlines() if "WARN" in l or "ERROR" in l]
    if A.quiet_log:
        lines = [l for l in lines if "request failed" not in l] + [f"({sum(1 for l in log.splitlines() if 'request failed' in l)} 'request failed' WARN lines omitted)"]
    for l in lines:
        if True:
            print("   " + l[:260])
finally:
    v.kill9(); auth.kill9()
    shutil.rmtree(base, ignore_errors=True)
    v.cleanup()
