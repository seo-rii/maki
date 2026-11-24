#!/usr/bin/env python3.12
"""Round 9 finding F2 through the real plugin: a shard that was checkpointed
into once, then loses its newest catalog copy, its newest allocation copy and
the tail of its data file, serves ZEROS for a checkpointed unit beyond the
cut (exit 1 = reproduced; EIO there would be exit 0)."""
import os, struct, sys
import mk

UNIT, SLOT = 4096, 4608
v = mk.Vol("f2", discard=("--discard" in sys.argv), size="1MiB", unit=UNIT, shard="64KiB", seg="16KiB", jmax="256KiB", max_io="16KiB")
try:
    v.create()
    v.start()
    h = mk.connect(v.sock)
    a, b = mk.pattern(1 * UNIT, UNIT, 1), mk.pattern(9 * UNIT, UNIT, 2)
    h.pwrite(a, 1 * UNIT)
    h.pwrite(b, 9 * UNIT)
    h.flush()
    assert v.maki("checkpoint", v.cfg).returncode == 0
    # The same session rewrites unit 1 only: no allocation bit changes, the
    # journal rolls, and the checkpoint reclaims the first segments.
    for _ in range(16):
        h.pwrite(a, 1 * UNIT)
        h.flush()
    assert v.maki("checkpoint", v.cfg).returncode == 0
    assert h.pread(UNIT, 9 * UNIT) == b
    h.shutdown()
    v.kill9()
    print("files:", sorted(os.listdir(v.root)), sorted(os.listdir(os.path.join(v.root, "data"))),
          sorted(os.listdir(os.path.join(v.root, "journal"))))

    def gen(path):
        with open(path, "rb") as f:
            d = f.read(20)
        return struct.unpack("<Q", d[12:20])[0]

    def damage_newest(stem):
        pa, pb = stem + ".a", stem + ".b"
        newest = pa if gen(pa) >= gen(pb) else pb
        print(f"damage {os.path.relpath(newest, v.root)} (generations a {gen(pa)}, b {gen(pb)})")
        os.truncate(newest, os.path.getsize(newest) - 1)

    damage_newest(os.path.join(v.root, "shard-catalog"))
    damage_newest(os.path.join(v.root, "data", "shard-00000000.alloc"))
    dat = os.path.join(v.root, "data", "shard-00000000.dat")
    print(f"truncate data file {os.path.getsize(dat)} -> {5 * SLOT + 447}")
    os.truncate(dat, 5 * SLOT + 447)

    r = v.maki("check", v.cfg, "--deep")
    print("deep check before attach: exit", r.returncode, [l for l in (r.stdout + r.stderr).splitlines() if "verdict" in l or l.startswith(("ERROR", "error", "warning"))][:8])
    v.start()
    h = mk.connect(v.sock)
    assert h.pread(UNIT, 1 * UNIT) == a, "unit 1 (before the cut) must be served"
    print("unit 1: served from its slot header")
    try:
        got = h.pread(UNIT, 9 * UNIT)
    except Exception as e:
        print("unit 9: error, as required:", str(e)[:120])
        sys.exit(0)
    if got == bytes(UNIT):
        print("unit 9: ZEROS for a checkpointed, flushed unit whose slot the truncation removed")
        sys.exit(1)
    print("unit 9:", mk.describe(got[:512]))
    sys.exit(2)
finally:
    v.cleanup()
