#!/usr/bin/env python3
"""Round 9 L1 (successor rerun): `maki volume create` on a local rollback pair
whose backing root holds an entry no creation writes (`lost+found`, as on a
freshly formatted filesystem mounted there) and no rollback.format. The
refusal says "running volume create again continues"; run it again and see
the same refusal. Exit 1 = reproduced."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import a9lib

base = "/tmp/a9l1"
root, witness = os.path.join(base, "backing"), "/dev/shm/a9l1-witness"
a9lib.reset(root, witness)
os.makedirs(os.path.join(root, "lost+found"), mode=0o700)
cfg = a9lib.write_cfg(os.path.join(base, "volume.toml"), root=root, witness=witness)
outs = []
for attempt in (1, 2):
    rc, out = a9lib.run("volume", "create", cfg)
    outs.append((rc, out))
    print(f"create #{attempt}: exit {rc}\n  {out}\n  root now: {a9lib.tree(root)}  witness: {a9lib.tree(witness)}")
for args in (("check", cfg), ("volume", "inspect", cfg)):
    rc, out = a9lib.run(*args)
    print(f"{' '.join(args[:2])}: exit {rc}\n  {out[:600]}")
bad = all(rc != 0 and "running volume create again continues" in out for rc, out in outs)
print("REPRODUCED" if bad else "not reproduced")
sys.exit(1 if bad else 0)
