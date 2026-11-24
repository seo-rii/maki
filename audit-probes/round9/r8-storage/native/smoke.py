import sys, mk, subprocess, time
v = mk.Vol("smoke", discard=("--discard" in sys.argv))
try:
    r = v.create(check=False); print("create", r.returncode, r.stdout[-300:], r.stderr[-600:])
    v.start()
    print(subprocess.run(["nbdinfo", "nbd+unix:///?socket=" + v.sock], capture_output=True, text=True).stdout)
    h = mk.connect(v.sock)
    print("size", h.get_size(), "ro", h.is_read_only(), "flush", h.can_flush(), "fua", h.can_fua(), "trim", h.can_trim(),
          "zero", h.can_zero(), "fast_zero", h.can_fast_zero(), "multi", h.can_multi_conn(), "cache", h.can_cache(),
          "df", h.can_df(), "meta", h.can_meta_context("base:allocation"), "rot", h.is_rotational())
    import nbd
    print("bs", h.get_block_size(nbd.SIZE_MINIMUM), h.get_block_size(nbd.SIZE_PREFERRED), h.get_block_size(nbd.SIZE_MAXIMUM), h.get_block_size(nbd.SIZE_PAYLOAD))
    d = mk.pattern(0, 8192, 1)
    h.pwrite(d, 0)
    assert h.pread(8192, 0) == d
    h.flush()
    h.shutdown()
    print(v.maki("status", v.cfg).stdout[:1500])
    rc = v.term(); print("term rc", rc)
    print(v.read_log()[-1500:])
finally:
    v.cleanup()
