#!/usr/bin/python3.12
"""Single-connection NBD semantics against a byte-exact model.

usage: sem.py [--only NAME]
Each scenario creates a fresh volume, serves it through the real plugin and
drives it with libnbd with client-side strictness off, so every odd request
reaches nbdkit. Prints PASS/FAIL lines; exit status 1 on any FAIL.
"""
import sys, os, random, errno, time, traceback
import nbd
import mk

FAILS = []


def note(ok, what, detail=""):
    print(("PASS " if ok else "FAIL ") + what + (" :: " + detail if detail else ""), flush=True)
    if not ok:
        FAILS.append(what + " :: " + detail)


class Dev:
    def __init__(self, vol, unit, strict=False, meta=False):
        self.vol = vol
        self.unit = unit
        self.h = nbd.NBD()
        if not strict:
            self.h.set_strict_mode(0)
        if meta:
            self.h.add_meta_context("base:allocation")
        self.h.connect_unix(vol.sock)
        self.size = self.h.get_size()
        self.model = bytearray(self.size)
        self.ver = 0

    def reconnect(self, meta=False):
        try:
            self.h.shutdown()
        except nbd.Error:
            pass
        self.h = nbd.NBD()
        self.h.set_strict_mode(0)
        if meta:
            self.h.add_meta_context("base:allocation")
        for _ in range(100):
            try:
                self.h.connect_unix(self.vol.sock)
                return
            except nbd.Error as e:
                time.sleep(0.05)
                self.h = nbd.NBD(); self.h.set_strict_mode(0)
                if meta:
                    self.h.add_meta_context("base:allocation")
        raise RuntimeError("reconnect failed")

    def data(self, off, ln):
        self.ver += 1
        if off % 512 == 0 and ln % 512 == 0:
            return mk.pattern(off, ln, self.ver)
        return random.Random(self.ver).randbytes(ln)

    def w(self, off, ln, flags=0):
        d = self.data(off, ln)
        self.h.pwrite(d, off, flags)
        self.model[off:off + ln] = d

    def z(self, off, ln, flags=0):
        self.h.zero(ln, off, flags)
        self.model[off:off + ln] = bytes(ln)

    def t(self, off, ln, flags=0):
        """Maki's documented trim: whole units inside the range read zeros;
        partial edge units are left untouched."""
        self.h.trim(ln, off, flags)
        u = self.unit
        a = -(-off // u) * u
        b = (off + ln) // u * u
        if b > a:
            self.model[a:b] = bytes(b - a)

    def read(self, off, ln):
        return bytes(self.h.pread(ln, off))

    def verify(self, what, off=0, ln=None, chunk=65536):
        ln = self.size - off if ln is None else ln
        bad = None
        pos = off
        while pos < off + ln:
            n = min(chunk, off + ln - pos)
            try:
                got = self.read(pos, n)
            except nbd.Error as e:
                note(False, what, f"read {pos}+{n} failed: {e}")
                return False
            if got != self.model[pos:pos + n]:
                for s in range(0, n, 512):
                    if got[s:s + 512] != self.model[pos + s:pos + s + 512]:
                        bad = (pos + s, mk.describe(bytes(got[s:s + 512]).ljust(512, b"\0")),
                               mk.describe(bytes(self.model[pos + s:pos + s + 512]).ljust(512, b"\0")))
                        break
                break
            pos += n
        note(bad is None, what, "" if bad is None else f"first bad sector at {bad[0]}: got {bad[1]}, want {bad[2]}")
        return bad is None

    def expect_err(self, what, fn, allowed):
        before = bytes(self.model)
        try:
            fn()
        except nbd.Error as e:
            ok = e.errnum in allowed
            note(ok, what, f"errno={e.errnum} ({errno.errorcode.get(e.errnum)}) {e.string[:120]}")
            # A refused request must leave the connection usable or cleanly dead.
            return e.errnum
        note(False, what, "request unexpectedly succeeded")
        return 0


def boundaries(dev, tag):
    u, size = dev.unit, dev.size
    shard = 65536
    cases = [
        ("one unit", 0, u), ("sub-unit sector", 512, 512), ("sub-unit tail", u - 512, 512),
        ("across unit", u - 512, 1024), ("across 3 units unaligned", u + 512, 2 * u),
        ("up to shard end", shard - u, u), ("across shard", shard - u, 2 * u),
        ("across shard unaligned", shard - 512, 1024), ("across shard big", shard - 1536, 3 * u + 1024),
        ("last sector", size - 512, 512), ("last unit-ish", size - u, u) if size % u == 0 else ("tail", size - 1024, 1024),
        ("max_io aligned", 2 * shard, 65536), ("max_io unaligned (17 units)", 3 * shard + 512, 65536),
        ("> max_io", 5 * shard + 1536, 3 * 65536 + 512), ("1MiB", 1 << 20, 1 << 20),
        ("to the end", size - (3 * 65536 + 512), 3 * 65536 + 512),
    ]
    for name, off, ln in cases:
        if off < 0 or off + ln > size:
            continue
        try:
            dev.w(off, ln)
            got = dev.read(off, ln)
            note(got == dev.model[off:off + ln], f"{tag} write+read {name} ({off}+{ln})")
        except nbd.Error as e:
            note(False, f"{tag} write {name} ({off}+{ln})", str(e))
    dev.verify(f"{tag} full verify after boundary writes")
    # One read larger than maximum_io and one of the whole device.
    dev.verify(f"{tag} whole-device single read", chunk=dev.size)
    dev.verify(f"{tag} odd-chunk reads", chunk=3 * 65536 + 1536)


def refusals(dev, tag):
    size = dev.size
    E = (errno.EINVAL, errno.ENOSPC, errno.EIO, errno.ENOTSUP, errno.EOVERFLOW, errno.EPERM)
    dev.expect_err(f"{tag} write past end", lambda: dev.h.pwrite(bytes(512), size), (errno.ENOSPC, errno.EINVAL))
    dev.expect_err(f"{tag} write straddling end", lambda: dev.h.pwrite(bytes(1024), size - 512), (errno.ENOSPC, errno.EINVAL))
    dev.expect_err(f"{tag} read straddling end", lambda: dev.h.pread(1024, size - 512), (errno.EINVAL, errno.ENOSPC))
    dev.expect_err(f"{tag} read at 2^63-512", lambda: dev.h.pread(512, (1 << 63) - 512), (errno.EINVAL, errno.ENOSPC, errno.EOVERFLOW))
    dev.expect_err(f"{tag} zero straddling end", lambda: dev.h.zero(1024, size - 512), (errno.ENOSPC, errno.EINVAL))
    dev.expect_err(f"{tag} zero-length read", lambda: dev.h.pread(0, 0), (errno.EINVAL,))
    dev.expect_err(f"{tag} zero-length write", lambda: dev.h.pwrite(b"", 0), (errno.EINVAL, errno.ENOSPC))
    dev.expect_err(f"{tag} zero-length zero", lambda: dev.h.zero(0, 0), (errno.EINVAL, errno.ENOSPC))
    dev.expect_err(f"{tag} unaligned write off=7 len=100", lambda: dev.h.pwrite(b"x" * 100, 7), (errno.EINVAL,))
    dev.expect_err(f"{tag} unaligned write off=512 len=100", lambda: dev.h.pwrite(b"x" * 100, 512), (errno.EINVAL,))
    dev.expect_err(f"{tag} unaligned read off=1 len=512", lambda: dev.h.pread(512, 1), (errno.EINVAL,))
    dev.expect_err(f"{tag} unaligned zero off=0 len=511", lambda: dev.h.zero(511, 0), (errno.EINVAL,))
    # FAST_ZERO aborts nbdkit (finding F1, fastzero_abort.py); not sent here.
    dev.expect_err(f"{tag} cache", lambda: dev.h.cache(4096, 0), (errno.EINVAL, errno.ENOTSUP))
    if not dev.h.can_trim():
        dev.expect_err(f"{tag} trim on a non-discard volume", lambda: dev.h.trim(4096, 0), (errno.EINVAL, errno.ENOTSUP))
    # connection must still work, data unchanged
    dev.verify(f"{tag} model unchanged after refused requests")


def zeroes(dev, tag):
    u, size = dev.unit, dev.size
    # fill a working area first
    base = 8 * 65536
    dev.w(base, 6 * 65536)
    combos = [(0, "plain"), (nbd.CMD_FLAG_NO_HOLE, "no-hole"), (nbd.CMD_FLAG_FUA, "fua"),
              (nbd.CMD_FLAG_FUA | nbd.CMD_FLAG_NO_HOLE, "fua+no-hole")]
    shapes = [("sub-unit", 512, 512), ("one unit", u, u), ("head partial", u - 512, u + 512),
              ("tail partial", 4 * u, u + 512), ("both partial", 7 * u + 512, 3 * u),
              ("inside one unit", 12 * u + 512, 1024), ("across shard", 65536 - 512, 2 * u + 1024),
              ("> max_io unaligned", 2 * 65536 + 512, 2 * 65536 + 1024)]
    i = 0
    for flags, fname in combos:
        for sname, rel, ln in shapes:
            off = base + rel
            # rewrite the neighbourhood so each case starts from data
            dev.w(off - 512 if rel >= 512 else off, ln + 1024)
            try:
                dev.z(off, ln, flags)
            except nbd.Error as e:
                note(False, f"{tag} zero {fname} {sname}", str(e)); continue
            lo = max(0, off - 2 * u); hi = min(size, off + ln + 2 * u)
            got = dev.read(lo, hi - lo)
            note(got == dev.model[lo:hi], f"{tag} zero {fname} {sname} ({off}+{ln})")
    # whole device in one request (far above maximum_io), then data again
    try:
        dev.z(0, size)
        dev.verify(f"{tag} zero whole device in one request")
        dev.w(65536 - 512, 2048)
        dev.z(0, size, nbd.CMD_FLAG_NO_HOLE | nbd.CMD_FLAG_FUA)
        dev.verify(f"{tag} zero whole device no-hole+fua")
    except nbd.Error as e:
        note(False, f"{tag} zero whole device", str(e))


def trims(dev, tag):
    u, size = dev.unit, dev.size
    base = 16 * 65536
    shapes = [("sub-unit", 512, 512), ("one unit", u, u), ("head partial", u - 512, u + 512),
              ("tail partial", 4 * u, u + 512), ("both partial", 7 * u + 512, 3 * u),
              ("inside one unit", 12 * u + 512, 1024), ("across shard", 65536 - 512, 2 * u + 1024),
              ("> max_io unaligned", 2 * 65536 + 512, 2 * 65536 + 1024)]
    for flags, fname in [(0, "plain"), (nbd.CMD_FLAG_FUA, "fua")]:
        for sname, rel, ln in shapes:
            off = base + rel
            dev.w(off - 512 if rel >= 512 else off, ln + 1024)
            try:
                dev.t(off, ln, flags)
            except nbd.Error as e:
                note(False, f"{tag} trim {fname} {sname}", str(e)); continue
            lo = max(0, off - 2 * u); hi = min(size, off + ln + 2 * u)
            got = dev.read(lo, hi - lo)
            note(got == dev.model[lo:hi], f"{tag} trim {fname} {sname} ({off}+{ln})")
    # trim of never-written space, a double trim, then write into a trimmed unit
    dev.t(30 * 65536, 65536)
    dev.t(base, 4 * 65536); dev.t(base, 4 * 65536)
    dev.w(base + u + 512, 512)
    dev.verify(f"{tag} verify after trims")
    dev.t(0, size)
    dev.verify(f"{tag} trim whole device in one request")
    dev.w(size - 512, 512); dev.w(0, 512)
    dev.verify(f"{tag} writes after whole-device trim")


def restart_checks(vol, dev, tag, start_kw):
    # everything so far, without a client flush: clean SIGTERM must keep it
    dev.w(5 * 4096 + 512, 512)
    try:
        dev.h.shutdown()
    except nbd.Error:
        pass
    rc = vol.term(60)
    note(rc == 0, f"{tag} SIGTERM exit status", f"rc={rc}")
    log = vol.read_log()
    note("panic" not in log.lower(), f"{tag} no panic in nbdkit log", log[-400:] if "panic" in log.lower() else "")
    vol.start(**start_kw)
    dev.reconnect()
    dev.verify(f"{tag} verify after clean restart")
    dev.w(9 * 4096, 4096, nbd.CMD_FLAG_FUA)
    dev.w(11 * 4096 + 512, 1024)
    dev.h.flush()
    vol.kill9()
    vol.start(**start_kw)
    dev.reconnect()
    dev.verify(f"{tag} verify after kill -9 restart")
    r = vol.maki("checkpoint", vol.cfg)
    note(r.returncode == 0, f"{tag} maki checkpoint", r.stdout[-200:] + r.stderr[-200:])
    dev.verify(f"{tag} verify after checkpoint")
    vol.kill9()
    r = vol.maki("check", vol.cfg, "--deep")
    note(r.returncode == 0, f"{tag} offline maki check --deep", (r.stdout + r.stderr)[-300:])
    vol.start(**start_kw)
    dev.reconnect()
    dev.verify(f"{tag} verify after second kill -9 restart")


def scenario(name, discard=False, unit=4096, start_kw=None, **cfg):
    start_kw = start_kw or {}
    vol = mk.Vol(name, discard=discard, unit=unit, **cfg)
    try:
        vol.create()
        vol.start(**start_kw)
        dev = Dev(vol, unit)
        note(dev.h.can_trim() == discard, f"{name} can_trim == discard")
        dev.verify(f"{name} fresh volume reads zeros")
        boundaries(dev, name)
        refusals(dev, name)
        zeroes(dev, name)
        if discard:
            trims(dev, name)
        dev.verify(f"{name} final verify")
        restart_checks(vol, dev, name, start_kw)
        log = vol.all_logs()
        note("panic" not in log.lower(), f"{name} no panic in any nbdkit log")
        if os.environ.get("A8N_SHOWLOG"):
            print(log[-3000:])
    except Exception as e:
        note(False, f"{name} scenario aborted", repr(e) + "\n" + traceback.format_exc()[-1500:])
        print(vol.all_logs()[-3000:])
    finally:
        vol.cleanup()


SCENARIOS = {
    "v2": lambda: scenario("v2"),
    "v3": lambda: scenario("v3", discard=True),
    "v2-cache": lambda: scenario("v2-cache", cache='mode = "read"\nmax_bytes = "256KiB"\nttl = "30s"'),
    "v3-cache": lambda: scenario("v3-cache", discard=True, cache='mode = "read"\nmax_bytes = "256KiB"\nttl = "30s"'),
    "v3-oddsize": lambda: scenario("v3-oddsize", discard=True, size="4195840B"),
    "v2-oddsize": lambda: scenario("v2-oddsize", size="4195840B"),
    "v3-unit8k": lambda: scenario("v3-unit8k", discard=True, unit=8192),
    "v3-xts": lambda: scenario("v3-xts", discard=True, provider="local-aes-xts"),
}

if __name__ == "__main__":
    only = None
    if "--only" in sys.argv:
        only = sys.argv[sys.argv.index("--only") + 1].split(",")
    for n, fn in SCENARIOS.items():
        if only and n not in only:
            continue
        print(f"=== {n}", flush=True)
        fn()
    print(f"\n{len(FAILS)} FAIL(s)")
    for f in FAILS:
        print("  " + f[:400])
    sys.exit(1 if FAILS else 0)
