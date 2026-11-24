#!/usr/bin/python3.12
"""Stock NBD client tools against the plugin: nbdinfo --map (BLOCK_STATUS),
nbdcopy in both directions with requests above maximum_io, and a file system
made and checked through nbdfuse, across a kill -9 of nbdkit."""
import sys, os, subprocess, time, hashlib, signal, nbd, mk
fails = 0
def note(ok, what, detail=""):
    global fails
    print(("PASS " if ok else "FAIL ") + what + (" :: " + str(detail)[-400:] if detail else ""), flush=True)
    fails += 0 if ok else 1
def run(*a, **k):
    # one connection at a time: the previous tool's connection may still be closing
    for _ in range(100):
        r = subprocess.run(a, capture_output=True, text=True, **k)
        if "server has no export named" not in r.stderr:
            return r
        time.sleep(0.05)
    return r
v = mk.Vol("tools", discard=True, size="32MiB", shard="1MiB", jmax="4MiB", seg="512KiB")
uri = "nbd+unix:///?socket=" + v.sock
mnt = os.path.join(v.dir, "mnt")
try:
    v.create(); v.start()
    # --- nbdcopy in, with a sparse source (zeros become WRITE_ZEROES / skipped)
    src = os.path.join(v.dir, "src.img")
    with open(src, "wb") as f:
        f.truncate(32 << 20)
        for off in (0, 3 << 20, (7 << 20) + 512, (31 << 20) + 4096 * 20):
            f.seek(off); f.write(os.urandom(700_000 if off else 1_300_000))
    r = run("nbdcopy", "--request-size=1048576", "--flush", src, uri)
    note(r.returncode == 0, "nbdcopy file -> export (1 MiB requests, 64 KiB maximum_io)", r.stderr)
    out = os.path.join(v.dir, "out.img")
    r = run("nbdcopy", "--request-size=4194304", uri, out)
    note(r.returncode == 0, "nbdcopy export -> file (4 MiB requests)", r.stderr)
    same = hashlib.sha256(open(src, "rb").read()).digest() == hashlib.sha256(open(out, "rb").read()).digest()
    note(same, "export content equals the source image")
    r = run("nbdinfo", "--map", uri)
    lines = r.stdout.strip().splitlines()
    note(r.returncode == 0 and len(lines) == 1 and lines[0].split()[:3] == ["0", str(32 << 20), "0"], "BLOCK_STATUS: the whole export is reported allocated data (no extents callback)", r.stdout + r.stderr)
    # --- a file system through nbdfuse
    os.mkdir(mnt)
    time.sleep(0.3)
    fuse = subprocess.Popen(["nbdfuse", mnt, uri], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    dev = os.path.join(mnt, "nbd")
    for _ in range(100):
        if os.path.exists(dev): break
        time.sleep(0.05)
    note(os.path.exists(dev) and os.path.getsize(dev) == 32 << 20, "nbdfuse exposes the export")
    r = run("mkfs.ext4", "-q", "-F", "-b", "1024", "-E", "nodiscard", dev)
    note(r.returncode == 0, "mkfs.ext4 -b 1024 through nbdfuse", r.stderr)
    r = run("e2fsck", "-fn", dev)
    note(r.returncode == 0, "e2fsck clean after mkfs", r.stdout[-300:] + r.stderr[-200:])
    # populate with debugfs (no mount needed), 512-byte direct I/O at odd sectors with dd, then fsync
    blob = os.path.join(v.dir, "blob"); open(blob, "wb").write(os.urandom(3_000_000))
    r = run("debugfs", "-w", "-R", f"write {blob} blob", dev)
    note(r.returncode == 0, "debugfs write of a 3 MB file", r.stderr)
    r = run("dd", f"if={blob}", f"of={dev}", "bs=512", "seek=60001", "count=37", "oflag=direct", "conv=notrunc,fsync")
    note(r.returncode == 0, "dd bs=512 oflag=direct at an odd sector, fsync", r.stderr)
    r = run("sync", dev)
    note(r.returncode == 0, "fsync of the nbdfuse file (NBD FLUSH)", r.stderr)
    fsck_before = run("e2fsck", "-fn", dev)
    expect = open(dev, "rb").read()
    # discard through the FUSE file, then data again
    r = run("fallocate", "-p", "-o", str(20 << 20), "-l", str(2 << 20), dev)
    note(r.returncode == 0, "fallocate --punch-hole through nbdfuse (NBD TRIM / zero)", r.stderr)
    r = run("sync", dev)
    expect2 = open(dev, "rb").read()
    note(expect2[20 << 20:22 << 20] == bytes(2 << 20), "punched range reads zeros")
    expect = expect2
    # kill -9 the server under the mounted client
    v.kill9()
    subprocess.run(["umount", "-l", mnt], capture_output=True); 
    try: fuse.wait(10)
    except subprocess.TimeoutExpired: fuse.kill()
    v.start()
    out2 = os.path.join(v.dir, "after.img")
    r = run("nbdcopy", uri, out2)
    note(r.returncode == 0, "nbdcopy after kill -9 restart", r.stderr)
    got = open(out2, "rb").read()
    note(got == expect, "every byte flushed before the kill is back", f"first diff at {next((i for i in range(0, len(got), 512) if got[i:i+512] != expect[i:i+512]), None)}")
    r = run("e2fsck", "-fn", out2)
    strip = lambda t: [l for l in t.splitlines() if "tools-" not in l]
    note(r.returncode == fsck_before.returncode and strip(r.stdout) == strip(fsck_before.stdout), "e2fsck verdict on the recovered export equals the one before the kill", f"before rc={fsck_before.returncode} after rc={r.returncode}")
    r2 = subprocess.run(["debugfs", "-R", "cat blob", out2], capture_output=True)
    note(r2.stdout == open(blob, "rb").read(), "file written before the kill reads back identical")
    log = v.all_logs()
    note("panic" not in log.lower(), "no panic in logs")
finally:
    subprocess.run(["umount", "-l", mnt], capture_output=True)
    v.cleanup()
print(f"{fails} FAIL(s)"); sys.exit(1 if fails else 0)
