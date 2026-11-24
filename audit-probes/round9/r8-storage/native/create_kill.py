#!/usr/bin/env python3
"""Round 9: `maki volume create` stopped at EVERY traced call (SIGKILL, or
one failed call), on real directories, for a plain root and a local
rollback pair; then the commands an operator may run before trying again
(`check`, `check --deep`, `volume inspect`), then `volume create` again.

Requirement checked for every stop:
  * local rollback pair: exactly one of "the volume opens and passes the deep
    check" and "create continues it" (#382: nothing is stranded);
  * plain root: the same, or the documented refusal that tells the operator
    to empty the root (a plain root is never initialized again);
  * a second create never succeeds over a root whose deep check passes;
  * a create that reports success leaves a volume whose deep check passes.

Usage: create_kill.py plain|local kill|EIO|ENOSPC [--discard] [--step K]
       [--second same|discard|shard|capacity] [--mid]
"""
import sys, os, json, collections, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from a9lib import *

mode, fault = sys.argv[1], sys.argv[2]
opts = sys.argv[3:]
discard = "--discard" in opts
step = int(opts[opts.index("--step") + 1]) if "--step" in opts else 1
second = opts[opts.index("--second") + 1] if "--second" in opts else "same"
mid = "--mid" in opts
tag = f"{mode}-{fault}{'-v3' if discard else ''}-{second}{'-mid' if mid else ''}"
root = f"/tmp/a9s/{tag}-root"
wit = f"/dev/shm/a9s-wit/{tag}" if mode == "local" else None
cfg = write_cfg(f"/tmp/a9s/{tag}.toml", root=root, witness=wit)
kw2 = dict(root=root, witness=wit)
flags1 = ["--discard"] if discard else []
flags2 = list(flags1)
if second == "discard":
    flags2 = [] if discard else ["--discard"]
elif second == "shard":
    kw2["shard"] = "4MiB"
elif second == "capacity":
    kw2["capacity"] = "16MiB"
cfg2 = write_cfg(f"/tmp/a9s/{tag}-2.toml", **kw2)
MUT = "pwrite64,fdatasync,fsync,ftruncate,fallocate,rename,renameat,renameat2,unlink,unlinkat,mkdir,mkdirat,linkat"
SET = CALLS if fault == "kill" else MUT

def dirs():
    return [d for d in (root, wit) if d]

# Which calls does an undisturbed create make? strace counts `when=` for
# each system call of a set separately, so a stop is (call name, its n-th
# use); SIGKILL on entering a call aborts it, so the process dies between
# the call before and this one.
reset(*dirs())
trace = f"/tmp/a9s/{tag}.trace"
cmd = ["strace", "-f", "-qq", "-e", f"trace={SET}", "-o", trace, MAKI, "volume", "create", cfg, *flags1]
r = subprocess.run(cmd, env=ENV, capture_output=True, text=True)
assert r.returncode == 0, r.stderr
per_call = collections.Counter()
points = []
for line in open(trace).read().splitlines():
    m = re.match(r"\d+\s+(\w+)\(", line)
    if not m:
        continue
    per_call[m.group(1)] += 1
    points.append((m.group(1), per_call[m.group(1)], line.split(None, 1)[1][:90]))
total = len(points)
print(f"{tag}: an undisturbed create makes {total} calls of the set: {dict(per_call)}", flush=True)

def stopped_create(point):
    name, nth, _ = point
    inj = f"{name}:signal=SIGKILL:when={nth}" if fault == "kill" else f"{name}:error={fault}:when={nth}"
    cmd = ["strace", "-f", "-qq", "-e", f"trace={SET}", "-o", "/dev/null", "-e", f"inject={inj}",
           MAKI, "volume", "create", cfg, *flags1]
    r = subprocess.run(cmd, env=ENV, capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr).strip()

def deep_ok(c=cfg):
    rc, out = run("check", c, "--deep")
    return rc == 0 and "check passed" in out, out

counts = collections.Counter()
bad = []
for index in range(0, total, step):
    n = (index, points[index])
    reset(*dirs())
    rc1, out1 = stopped_create(points[index])
    t1 = tree(root)
    w1 = sorted(os.listdir(wit)) if wit else []
    if rc1 == 0:
        ok, out = deep_ok()
        counts["first create reported success"] += 1
        if not ok:
            bad.append((n, "SUCCESS-WITHOUT-VOLUME", out1[:200], out[-300:], t1))
        if fault == "kill":
            bad.append((n, "KILL-NOT-DELIVERED", out1[:100]))
            continue
    if mid:
        # What an operator, or the unit, may run in between.
        for args in (["check", cfg], ["check", cfg, "--deep"], ["volume", "inspect", cfg]):
            run(*args)
    before, before_out = deep_ok()
    rc2, out2 = run("volume", "create", cfg2, *flags2)
    after, after_out = deep_ok(cfg2)
    if rc2 == 0:
        if before:
            bad.append((n, "CREATED-OVER-A-VOLUME", out2[:200], before_out[-200:], t1))
        elif not after:
            bad.append((n, "CONTINUED-WITHOUT-VOLUME", out2[:200], after_out[-300:], t1))
        counts["second create continued"] += 1
    else:
        first_line = out2.splitlines()[0] if out2 else ""
        # A volume the first run completed far enough to open: the refusal
        # is right whatever the second configuration says, and that volume
        # must still pass under the configuration it was created with.
        if before and deep_ok()[0]:
            counts["second create refused: a volume is present"] += 1
        elif mode == "plain" and ("use an empty root" in out2 or "empty the backing root" in out2):
            counts["second create refused: plain root to be emptied (documented)"] += 1
        elif second == "capacity" and "reserved capacity" in out2:
            counts["second create refused: other capacity named"] += 1
            # the way out the message names must work
            rc3, out3 = run("volume", "create", cfg, *flags1)
            ok3, o3 = deep_ok()
            if rc3 != 0 or not ok3:
                bad.append((n, "CAPACITY-WAY-OUT-FAILS", out3[:300], o3[-200:], t1))
        else:
            counts["STRANDED"] += 1
            bad.append((n, "STRANDED", first_line[:400], before_out[-300:], t1, w1))

print(json.dumps(counts, indent=1))
for b in bad[:12]:
    print("BAD", b)
print(f"{tag}: {len(bad)} violation(s)")
for d in dirs():
    shutil.rmtree(d, ignore_errors=True)
sys.exit(1 if bad else 0)
