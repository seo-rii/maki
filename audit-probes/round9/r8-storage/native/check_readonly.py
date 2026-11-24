#!/usr/bin/python3.12
"""Offline commands must not change the backing: run `maki check`, `check
--deep` and `volume inspect` under plshim on a volume killed with an
uncheckpointed journal and list every modifying call they make."""
import os, sys, subprocess, hashlib, nbd, mk
ns = {"__name__": "x"}
src = open(os.path.join(mk.HERE, "pl.py")).read().rsplit("\nmain()", 1)[0]
argv = sys.argv; sys.argv = ["pl.py", "--seed", "0"]
exec(compile(src.replace('required=True', 'default=0'), "pl.py", "exec"), ns)
parse_log = ns["parse_log"]
T = f"/tmp/a8n-ro-{os.getpid()}"; os.makedirs(T)
subprocess.run(["mount", "-t", "tmpfs", "-o", "size=64m,mode=0700", "tmpfs", T], check=True)
bad = 0
try:
    for discard in (False, True):
        v = mk.Vol("ro", discard=discard, backing_dir=os.path.join(T, f"volume{int(discard)}"))
        v.create(); v.start()
        h = nbd.NBD(); h.connect_unix(v.sock)
        for i in range(60):
            h.pwrite(mk.pattern(i * 8192, 8192, i + 1), i * 8192)
        if discard: h.trim(65536, 131072)
        h.flush(); v.kill9()
        def digest():
            out = {}
            for d, _, fs in os.walk(v.root):
                for f in fs:
                    p = os.path.join(d, f); out[os.path.relpath(p, v.root)] = hashlib.sha256(open(p, "rb").read()).hexdigest()
            return out
        before = digest()
        for cmd in (["check", v.cfg], ["check", v.cfg, "--deep"], ["volume", "inspect", v.cfg]):
            logp = os.path.join(v.dir, "ro.log")
            if os.path.exists(logp): os.unlink(logp)
            env = dict(os.environ, LD_PRELOAD=os.path.join(mk.HERE, "plshim.so"), PLSHIM_ROOT=T, PLSHIM_LOG=logp)
            r = subprocess.run([mk.MAKI] + cmd, capture_output=True, text=True, env=env)
            recs = parse_log(logp) if os.path.exists(logp) else []
            kinds = "".join(x[0] for x in recs)
            after = digest()
            changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
            ok = not changed and not any(c in kinds for c in "WTAHU")
            bad += not ok
            print(f"{'PASS' if ok else 'FAIL'} {'v3' if discard else 'v2'} maki {' '.join(cmd[:1] + cmd[2:])}: rc={r.returncode}, modifying calls logged: {kinds!r}, files changed: {changed}")
        v.start(); h = nbd.NBD(); h.connect_unix(v.sock)
        okd = all(bytes(h.pread(8192, i * 8192)) == mk.pattern(i * 8192, 8192, i + 1) for i in range(60) if not (discard and 16 <= i < 24))
        print(f"{'PASS' if okd else 'FAIL'} data intact after the offline commands"); bad += not okd
        v.cleanup()
finally:
    subprocess.run(["umount", "-l", T]); os.rmdir(T)
sys.exit(1 if bad else 0)
