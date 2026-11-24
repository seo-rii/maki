#!/usr/bin/python3.12
"""Successor probe (F2, local witness): the witness anchor of a running LOCAL rollback-protected
daemon is replaced by an older copy; the session must stop (EIO). What do `maki status` and
`maki metrics` report afterwards?"""
import os, sys, subprocess, shutil, time, json
import mk9 as mk
import nbd

TB, TW = f"/tmp/a9rn-lr-b-{os.getpid()}", f"/tmp/a9rn-lr-w-{os.getpid()}"
for t in (TB, TW):
    os.makedirs(t)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "size=200m,mode=0700", "tmpfs", t], check=True)
v = None
try:
    root, wroot = os.path.join(TB, "volume"), os.path.join(TW, "witness")
    os.makedirs(root); os.makedirs(wroot)
    rb = f'[backing.rollback_protection]\nwitness_root = "{wroot}"\ncapacity = "8MiB"\n'
    v = mk.Vol("lr", discard=True, backing_dir=root, size="2MiB", ckpt_reserve="256KiB", reserve="64KiB", extra_backing=rb)
    v.create()
    v.start(); h = mk.connect(v.sock)
    h.pwrite(mk.pattern(0, 4096, 1, 1), 0, nbd.CMD_FLAG_FUA)
    old = open(os.path.join(wroot, "anchor"), "rb").read()
    for u in range(1, 8):
        h.pwrite(mk.pattern(u * 4096, 4096, 1 + u, 1), u * 4096, nbd.CMD_FLAG_FUA)
    c = v.maki("checkpoint", v.cfg)
    print(f"maki checkpoint: rc={c.returncode}")
    with open(os.path.join(wroot, "anchor.tmp"), "wb") as f:
        f.write(old)
    os.rename(os.path.join(wroot, "anchor.tmp"), os.path.join(wroot, "anchor"))
    print("older anchor put back under the running daemon")
    for kind in ("write-fua", "flush", "read"):
        try:
            if kind == "write-fua":
                h.pwrite(mk.pattern(9 * 4096, 4096, 999, 1), 9 * 4096, nbd.CMD_FLAG_FUA)
            elif kind == "flush":
                h.flush()
            else:
                h.pread(4096, 0)
            print(f"  {kind}: ok")
        except nbd.Error as e:
            print(f"  {kind}: {e}")
    t0 = time.monotonic()
    seen = None
    while time.monotonic() - t0 < 45:
        s = json.loads(v.maki("status", v.cfg).stdout)["data"]
        m = json.loads(v.maki("metrics", v.cfg).stdout)["data"]
        cur = (s["state"], s["degraded_reason"], s["checkpoint_failures_total"], s["journal_sync_failures_total"], m["maki_volume_state"])
        if cur != seen:
            print(f"  +{time.monotonic() - t0:5.1f}s state={cur[0]} degraded_reason={str(cur[1])[:150]} checkpoint_failures_total={cur[2]} "
                  f"journal_sync_failures_total={cur[3]} maki_volume_state={cur[4]}", flush=True)
            seen = cur
        try:
            h.pread(4096, 0)
            print("  read served")
        except nbd.Error:
            pass
        time.sleep(2)
finally:
    if v:
        v.kill9(); v.cleanup()
    for t in (TB, TW):
        subprocess.run(["umount", "-l", t]); os.rmdir(t)
