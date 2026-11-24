#!/usr/bin/python3.12
"""A default (no rollback protection) `maki volume create` that fails part-way
(here: the backing filesystem runs out of inodes) leaves a root that the next
`maki volume create` refuses and that cannot attach either. Nothing but
emptying the root by hand continues it.

usage: create_interrupted.py [--discard]
"""
import sys, os, subprocess, mk
DISCARD = "--discard" in sys.argv
wedged = 0
for inodes in range(3, 16):
    T = f"/tmp/a8n-ci-{os.getpid()}-{inodes}"
    os.makedirs(T)
    subprocess.run(["mount", "-t", "tmpfs", "-o", f"size=16m,mode=0700,nr_inodes={inodes}", "tmpfs", T], check=True)
    try:
        v = mk.Vol("ci", discard=DISCARD, backing_dir=os.path.join(T, "volume"))
        first = v.create(check=False)
        left = sorted(os.path.relpath(os.path.join(d, f), v.root) for d, _, fs in os.walk(v.root) for f in fs) if os.path.isdir(v.root) else []
        if first.returncode == 0:
            print(f"nr_inodes={inodes}: create succeeded"); continue
        # the cause is removed: plenty of inodes now
        subprocess.run(["mount", "-o", "remount,nr_inodes=4096", T], check=True)
        second = v.create(check=False)
        try:
            v.start(); attach = "attached"
        except RuntimeError as e:
            attach = str(e).strip().splitlines()[-1][-120:]
        stuck = second.returncode != 0 and attach != "attached"
        wedged += stuck
        print(f"nr_inodes={inodes}: first create rc={first.returncode} ({first.stderr.strip()[-70:]}); left {left}\n"
              f"    second create rc={second.returncode}: {second.stderr.strip()[-150:]}\n    attach: {attach}  => {'WEDGED' if stuck else 'ok'}")
    finally:
        try: v.kill9()
        except Exception: pass
        import shutil; shutil.rmtree(v.dir, ignore_errors=True)
        subprocess.run(["umount", "-l", T]); os.rmdir(T)
print(f"{wedged} interrupted creation(s) that neither `create` nor attach accepts")
sys.exit(1 if wedged else 0)
