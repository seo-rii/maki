#!/usr/bin/python3.12
"""Successor probe, docs/rollback-protection.md 'Backup and recovery procedure' step 4: a stopped
local-witness backing copied SPARSE (cp --sparse=always) and put back under its current witness;
`maki check --deep` 'verifies structural consistency and restores physical reservations'.
Prints allocated bytes of rollback.arena / manifests before and after the check, then attaches."""
import os, sys, subprocess, shutil, json
import mk9 as mk
import nbd

TB, TW = f"/tmp/a9rn-sp-b-{os.getpid()}", f"/tmp/a9rn-sp-w-{os.getpid()}"
for t in (TB, TW):
    os.makedirs(t)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "size=200m,mode=0700", "tmpfs", t], check=True)
v = None
BAD = []
try:
    root, wroot = os.path.join(TB, "volume"), os.path.join(TW, "witness")
    os.makedirs(root); os.makedirs(wroot)
    rb = f'[backing.rollback_protection]\nwitness_root = "{wroot}"\ncapacity = "8MiB"\n'
    v = mk.Vol("sp", discard=True, backing_dir=root, size="2MiB", ckpt_reserve="256KiB", reserve="64KiB", extra_backing=rb)
    v.create()
    v.start(); h = mk.connect(v.sock)
    for u in range(16):
        h.pwrite(mk.pattern(u * 4096, 4096, 7 + u, 1), u * 4096, nbd.CMD_FLAG_FUA)
    h.shutdown(); v.term()

    def alloc(d):
        out = {}
        for n in sorted(os.listdir(d)):
            p = os.path.join(d, n)
            if os.path.isfile(p) and n.startswith("rollback."):
                st = os.stat(p)
                out[n] = (st.st_size, st.st_blocks * 512)
        return out
    print("original:", alloc(root))
    sparse = os.path.join(TB, "sparse")
    subprocess.run(["cp", "-a", "--sparse=always", root, sparse], check=True)
    shutil.rmtree(root)
    os.rename(sparse, root)
    print("sparse copy put back:", alloc(root))
    r = v.maki("check", v.cfg, "--deep")
    print(f"check --deep: rc={r.returncode} {(r.stdout.strip() or r.stderr.strip()).splitlines()[-1][:200]}")
    after = alloc(root)
    print("after check --deep:", after)
    for n, (size, blocks) in after.items():
        if blocks < size:
            BAD.append(f"{n}: {blocks} allocated bytes < {size} after check --deep")
    v.start(); h = mk.connect(v.sock)
    ok = all(bytes(h.pread(4096, u * 4096)) == mk.pattern(u * 4096, 4096, 7 + u, 1) for u in range(16))
    h.shutdown(); v.term()
    print(f"attach after the check: data {'ok' if ok else 'WRONG'}; allocation {alloc(root)}")
    if not ok:
        BAD.append("data wrong after the sparse restore")
finally:
    if v:
        v.kill9(); v.cleanup()
    for t in (TB, TW):
        subprocess.run(["umount", "-l", t]); os.rmdir(t)
print("sparse_restore:", "FAIL " + "; ".join(BAD) if BAD else "ok")
