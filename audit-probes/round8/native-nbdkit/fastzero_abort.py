#!/usr/bin/python3.12
"""One NBD_CMD_WRITE_ZEROES with NBD_CMD_FLAG_FAST_ZERO (which the export does
not advertise) aborts the whole nbdkit process serving a Maki volume.

nbdkit's validate_request() accepts the flag for WRITE_ZEROES without looking
at the advertised flags (server/protocol.c), and backend_zero() then asserts
`c->can_fast_zero == 1` (server/backend.c:752 in 1.36.3 and 1.38.5, :770 on
master). The plugin answers `can_fast_zero` with 0 (plugin.rs:279), so the
assertion fails before `zero_v2` and its ENOTSUP guard (plugin.rs:366) run.
"""
import sys, signal, subprocess, nbd, mk
v = mk.Vol("fz")
try:
    v.create(); v.start()
    h = nbd.NBD(); h.connect_unix(v.sock)
    print("advertised: can_zero", h.can_zero(), "can_fast_zero", h.can_fast_zero())
    d = mk.pattern(0, 8192, 1); h.pwrite(d, 0, nbd.CMD_FLAG_FUA)
    h.set_strict_mode(0)   # libnbd would otherwise refuse to send an unadvertised flag
    try:
        h.zero(4096, 0, nbd.CMD_FLAG_FAST_ZERO)
        print("zero succeeded?!")
    except nbd.Error as e:
        print("client saw:", e)
    try:
        rc = v.proc.wait(10)
    except subprocess.TimeoutExpired:
        rc = None
    print("nbdkit exit status:", rc, "(SIGABRT)" if rc == -signal.SIGABRT else "")
    print("nbdkit log tail:", v.read_log()[-300:].strip())
    v.notify.close()
    v.start()
    h = nbd.NBD(); h.connect_unix(v.sock)
    print("after restart, FUA data intact:", bytes(h.pread(8192, 0)) == d)
    h.shutdown()
    sys.exit(0 if rc == 0 or rc is None else 1)
finally:
    v.cleanup()
