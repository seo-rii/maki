#!/usr/bin/python3.12
"""Largest requests the NBD wire allows, on an 8 GiB discard volume with the
packaged request limits (maximum_io 1 MiB): offsets above 4 GiB, a trim and a
zero of 4 GiB - 4096, a 64 MiB write and read (nbdkit's own payload limit)."""
import sys, time, errno, nbd, mk
v = mk.Vol("big", discard=True, size="8GiB", shard="64MiB", max_io="1MiB", seg="4MiB", jmax="64MiB", block=4096)
fails = 0
def note(ok, what, detail=""):
    global fails
    print(("PASS " if ok else "FAIL ") + what + (" :: " + str(detail) if detail else ""), flush=True)
    fails += 0 if ok else 1
try:
    v.create(); v.start()
    h = nbd.NBD(); h.set_strict_mode(0); h.connect_unix(v.sock)
    size = h.get_size(); note(size == 8 << 30, "export size 8 GiB", size)
    big = (4 << 30) - 4096
    # data on both sides of the 4 GiB line and at the very end
    spots = [0, (4 << 30) - 4096, 4 << 30, (4 << 30) + 4096, (6 << 30) + 12288, size - 4096]
    for i, off in enumerate(spots):
        h.pwrite(mk.pattern(off, 4096, i + 1), off)
    ok = all(bytes(h.pread(4096, off)) == mk.pattern(off, 4096, i + 1) for i, off in enumerate(spots))
    note(ok, "writes at offsets around and above 4 GiB read back")
    t = time.monotonic(); h.trim(big, 4096); dt = time.monotonic() - t
    note(True, f"trim of {big} bytes at 4096 took {dt:.2f}s")
    note(bytes(h.pread(4096, 0)) == mk.pattern(0, 4096, 1), "unit before the trim intact")
    note(bytes(h.pread(4096, (4 << 30) - 4096)) == bytes(4096), "last trimmed unit reads zeros")
    note(bytes(h.pread(4096, 4 << 30)) == mk.pattern(4 << 30, 4096, 3), "unit after the trim intact")
    t = time.monotonic(); h.zero(big, 4 << 30); dt = time.monotonic() - t
    note(True, f"zero (may trim) of {big} bytes at 4 GiB took {dt:.2f}s")
    note(bytes(h.pread(4096, (6 << 30) + 12288)) == bytes(4096), "zeroed unit reads zeros")
    note(bytes(h.pread(4096, size - 4096)) == mk.pattern(size - 4096, 4096, 6), "last unit of the export intact after a zero that ends right before it")
    d = mk.pattern(1 << 30, 64 << 20, 77)
    t = time.monotonic(); h.pwrite(d, 1 << 30, nbd.CMD_FLAG_FUA); dt = time.monotonic() - t
    note(True, f"64 MiB FUA write (nbdkit's maximum payload) took {dt:.2f}s")
    t = time.monotonic(); got = bytes(h.pread(64 << 20, 1 << 30)); dt2 = time.monotonic() - t
    note(got == d, f"64 MiB read back in {dt2:.2f}s")
    try:
        h.pwrite(bytes((64 << 20) + 4096), 0); note(False, "write above 64 MiB refused")
    except nbd.Error as e:
        note(True, "write above 64 MiB refused by nbdkit", e.errnum)
        h = nbd.NBD(); h.set_strict_mode(0)
        import time as _t
        for _ in range(200):
            try:
                h.connect_unix(v.sock); break
            except nbd.Error:
                _t.sleep(0.05); h = nbd.NBD(); h.set_strict_mode(0)
    v.kill9(); v.start()
    h = nbd.NBD(); h.connect_unix(v.sock)
    note(bytes(h.pread(64 << 20, 1 << 30)) == d, "64 MiB FUA write intact after kill -9")
    note(bytes(h.pread(4096, 0)) == mk.pattern(0, 4096, 1) and bytes(h.pread(4096, size - 4096)) == mk.pattern(size - 4096, 4096, 6), "edges intact after kill -9")
    h.shutdown()
    log = v.all_logs()
    note("panic" not in log.lower(), "no panic in logs")
finally:
    v.cleanup()
print(f"{fails} FAIL(s)"); sys.exit(1 if fails else 0)
