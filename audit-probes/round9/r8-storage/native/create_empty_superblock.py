#!/usr/bin/python3.12
"""`maki volume create` whose first superblock write fails (plshim makes the
ftruncate right after `superblock.a` is created fail with EIO; a kill, ENOSPC
or a power loss at that point leave the same root): the root now holds an
empty superblock.a. `volume create` says the superblock is already present,
and inspect, check and the daemon say there is no valid superblock."""
import sys, os, subprocess, mk
T = f"/tmp/a8n-ces-{os.getpid()}"; os.makedirs(T)
subprocess.run(["mount", "-t", "tmpfs", "-o", "size=16m,mode=0700", "tmpfs", T], check=True)
try:
    v = mk.Vol("ces", backing_dir=os.path.join(T, "volume"))
    env = dict(os.environ, LD_PRELOAD=os.path.join(mk.HERE, "plshim.so"), PLSHIM_ROOT=T, PLSHIM_LOG=os.path.join(v.dir, "c.log"),
               PLSHIM_FAULT=f"trunc=1.0,after={os.environ.get('AFTER', '48')}")
    r = subprocess.run([mk.MAKI, "volume", "create", v.cfg], capture_output=True, text=True, env=env)
    print("1. create with the failing call: rc", r.returncode, "|", r.stderr.strip()[-120:])
    print("   root now:", sorted((os.path.relpath(os.path.join(d, f), v.root), os.path.getsize(os.path.join(d, f))) for d, _, fs in os.walk(v.root) for f in fs))
    r2 = v.create(check=False)
    print("2. create again:  rc", r2.returncode, "|", r2.stderr.strip()[-120:])
    r3 = v.maki("volume", "inspect", v.cfg); print("3. volume inspect: rc", r3.returncode, "|", (r3.stdout + r3.stderr).strip()[-120:])
    r4 = v.maki("check", v.cfg); print("4. check:          rc", r4.returncode, "|", (r4.stdout + r4.stderr).strip()[-120:])
    try:
        v.start(); print("5. daemon: attached")
        stuck = False
    except RuntimeError as e:
        print("5. daemon:", str(e).strip().splitlines()[-1][-150:]); stuck = True
    sys.exit(1 if (stuck and r2.returncode != 0) else 0)
finally:
    try: v.kill9()
    except Exception: pass
    import shutil; shutil.rmtree(v.dir, ignore_errors=True)
    subprocess.run(["umount", "-l", T]); os.rmdir(T)
