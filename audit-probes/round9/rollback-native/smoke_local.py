#!/usr/bin/python3.12
"""Smoke: a local rollback-protected volume through the real CLI and plugin."""
import os, sys, subprocess, shutil, time
import mk9 as mk
import nbd

TB, TW = "/tmp/a9rn-smoke-b", "/tmp/a9rn-smoke-w"
for t, size in ((TB, "256m"), (TW, "16m")):
    os.makedirs(t, exist_ok=True)
    subprocess.run(["umount", "-l", t], stderr=subprocess.DEVNULL)
    subprocess.run(["mount", "-t", "tmpfs", "-o", f"size={size},mode=0700", "tmpfs", t], check=True)
try:
    root, wroot = os.path.join(TB, "volume"), os.path.join(TW, "witness")
    os.makedirs(root); os.makedirs(wroot)
    rb = f'[backing.rollback_protection]\nwitness_root = "{wroot}"\ncapacity = "{sys.argv[1] if len(sys.argv) > 1 else "8MiB"}"\n'
    v = mk.Vol("smoke", discard=True, backing_dir=root, size="2MiB", ckpt_reserve="256KiB", reserve="64KiB", extra_backing=rb)
    r = v.create(check=False)
    print("create:", r.returncode, r.stdout.strip(), r.stderr.strip())
    print(sorted(os.listdir(root)), sorted(os.listdir(wroot)))
    for f in sorted(os.listdir(root)):
        print(f, os.path.getsize(os.path.join(root, f)))
    t = time.time(); v.start(); print("start s", time.time() - t)
    h = mk.connect(v.sock)
    print("size", h.get_size(), "trim", h.can_trim(), "fua", h.can_fua())
    h.pwrite(mk.pattern(0, 8192, 1), 0, nbd.CMD_FLAG_FUA)
    h.flush()
    print(mk.describe(bytes(h.pread(512, 0))))
    print(v.maki("status", v.cfg).stdout[:300])
    h.shutdown(); print("term rc", v.term())
    for cmd in (["check", v.cfg], ["check", v.cfg, "--deep"], ["volume", "inspect", v.cfg]):
        r = v.maki(*cmd); print(cmd, r.returncode, r.stdout.strip()[-300:], r.stderr.strip()[-300:])
    print(v.read_log()[-600:])
finally:
    try: v.cleanup()
    except Exception: pass
    for t in (TB, TW):
        subprocess.run(["umount", "-l", t])
        os.rmdir(t)
