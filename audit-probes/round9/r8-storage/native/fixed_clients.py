#!/usr/bin/python3.12
"""Stock clients against a plugin that advertises fast zero and refuses it:
nbdinfo, libnbd (strict), qemu-io `write -z -n` (BDRV_REQ_NO_FALLBACK, i.e.
NBD_CMD_FLAG_FAST_ZERO), qemu-img convert onto the export.
Run with MAKI_PLUGIN=<fixed libmaki_nbdkit.so>."""
import sys, os, subprocess, errno, hashlib, time, nbd, mk
fails = 0
def note(ok, what, detail=""):
    global fails
    print(("PASS " if ok else "FAIL ") + what + (" :: " + str(detail)[-300:] if detail else ""), flush=True)
    fails += 0 if ok else 1
def run(*a):
    for _ in range(100):
        r = subprocess.run(a, capture_output=True, text=True)
        if not any(m in r.stderr for m in ("no export named", "Failed to connect", "export not available")):
            return r
        time.sleep(0.05)
    return r
for discard in (False, True):
    tag = "v3" if discard else "v2"
    v = mk.Vol("fzc", discard=discard, size="8MiB", shard="1MiB", jmax="4MiB", seg="512KiB")
    uri = "nbd+unix:///?socket=" + v.sock
    try:
        v.create(); v.start()
        r = run("nbdinfo", uri)
        note("can_fast_zero: true" in r.stdout and "can_zero: true" in r.stdout, f"{tag} nbdinfo reports can_fast_zero: true")
        h = nbd.NBD(); h.connect_unix(v.sock)      # default strict mode: only advertised flags are sent
        d = mk.pattern(0, 65536, 1); h.pwrite(d, 0, nbd.CMD_FLAG_FUA)
        for flags, name in ((nbd.CMD_FLAG_FAST_ZERO, "fast"), (nbd.CMD_FLAG_FAST_ZERO | nbd.CMD_FLAG_NO_HOLE, "fast+no-hole"), (nbd.CMD_FLAG_FAST_ZERO | nbd.CMD_FLAG_FUA, "fast+fua")):
            try:
                h.zero(16384, 4096, flags); note(False, f"{tag} libnbd zero {name} refused", "succeeded")
            except nbd.Error as e:
                note(e.errnum == errno.ENOTSUP, f"{tag} libnbd zero {name} refused with ENOTSUP", e.errnum)
        note(bytes(h.pread(65536, 0)) == d, f"{tag} export unchanged after refused fast zeros")
        h.zero(16384, 4096); want = bytearray(d); want[4096:4096 + 16384] = bytes(16384)
        note(bytes(h.pread(65536, 0)) == bytes(want), f"{tag} plain zero still served")
        h.shutdown()
        note(v.proc.poll() is None, f"{tag} server still running after libnbd fast zeros")
        r = run("qemu-io", "-f", "raw", "-c", "write -z -n 65536 65536", uri)
        out = r.stdout + r.stderr
        note("not supported" in out.lower() and v.proc.poll() is None, f"{tag} qemu-io write -z -n (no fallback) fails with ENOTSUP, server alive", out.strip())
        r = run("qemu-io", "-f", "raw", "-c", "write -P 0x5a 65536 65536", "-c", "write -z 69632 8192", "-c", "read -P 0 69632 8192", "-c", "read -P 0x5a 65536 4096", uri)
        note(r.returncode == 0 and "Pattern verification failed" not in r.stdout + r.stderr, f"{tag} qemu-io write, write -z, verified reads", (r.stdout + r.stderr).strip()[-200:])
        src = os.path.join(v.dir, "src.raw")
        with open(src, "wb") as f:
            f.truncate(8 << 20); f.seek(1 << 20); f.write(os.urandom(300000)); f.seek(5 << 20); f.write(os.urandom(700000))
        r = run("qemu-img", "convert", "-n", "-f", "raw", "-O", "raw", src, uri)
        note(r.returncode == 0, f"{tag} qemu-img convert -n onto the export", r.stderr.strip())
        out = os.path.join(v.dir, "out.raw")
        r = run("qemu-img", "convert", "-f", "raw", "-O", "raw", uri, out)
        same = r.returncode == 0 and hashlib.sha256(open(src, "rb").read()).digest() == hashlib.sha256(open(out, "rb").read()).digest()
        note(same, f"{tag} export equals the converted image", r.stderr.strip())
        log = v.all_logs()
        note("Assertion" not in log and "panic" not in log.lower() and v.proc.poll() is None, f"{tag} no assertion, no panic, server alive")
    finally:
        v.cleanup()
print(f"{fails} FAIL(s)"); sys.exit(1 if fails else 0)
