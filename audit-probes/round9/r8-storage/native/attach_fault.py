#!/usr/bin/env python3.12
"""Round 9 (r8-storage), item 4: #386's "empty an undecodable A/B side,
fdatasync, then write it" through the real plugin on a real directory, with
one failed system call at EVERY ftruncate / fdatasync / pwrite64 / fsync of
the attach that meets torn sides.

1. A volume is created and used through nbdkit + the plugin (pattern writes
   over several shards, FLUSH, `maki checkpoint` in between), then killed.
2. Every A/B pair of the volume gets what a store cut by a power loss
   leaves in its target: the OLDER side is replaced by a prefix of itself,
   zeros, garbage, or an empty file (the newer side, the durable copy, is
   left alone).
3. For every call (name, n-th use) the attach makes: a copy of that torn
   volume is attached under strace with that one call failing (EIO, ENOSPC
   for writes), whatever happens the server is then killed, and the copy is
   attached again without faults. Then every acknowledged sector is read
   back and `maki check --deep` must pass.

Usage: attach_fault.py [--discard] [--seed N] [--step K] [--errno EIO|ENOSPC]
"""
import sys, os, re, shutil, struct, random, subprocess, time, collections
import mk

args = sys.argv[1:]
discard = "--discard" in args
seed = int(args[args.index("--seed") + 1]) if "--seed" in args else 1
step = int(args[args.index("--step") + 1]) if "--step" in args else 1
errno_name = args[args.index("--errno") + 1] if "--errno" in args else "EIO"
rng = random.Random(seed)
SET = "ftruncate,fdatasync,pwrite64,fsync"
UNIT = 4096
SIZE = 2 << 20


def cfg_kw():
    return dict(size="2MiB", unit=UNIT, shard="64KiB", seg="64KiB", jmax="512KiB")


def build():
    v = mk.Vol("af", discard=discard, **cfg_kw())
    v.create()
    v.start()
    h = mk.connect(v.sock)
    acked = {}
    ver = 0
    for round_ in range(4):
        for _ in range(24):
            off = rng.randrange(0, SIZE // UNIT) * UNIT
            ver += 1
            h.pwrite(mk.pattern(off, UNIT, ver, seed), off)
            acked[off] = ver
        if discard and round_ >= 1:
            for _ in range(4):
                off = rng.randrange(0, SIZE // UNIT) * UNIT
                h.trim(UNIT, off)
                acked[off] = 0
        h.flush()
        r = v.maki("checkpoint", v.cfg)
        assert r.returncode == 0, r.stdout + r.stderr
    # A tail that only the journal holds.
    for _ in range(6):
        off = rng.randrange(0, SIZE // UNIT) * UNIT
        ver += 1
        h.pwrite(mk.pattern(off, UNIT, ver, seed), off)
        acked[off] = ver
    h.flush()
    v.kill9()
    return v, acked


def ab_pairs(root):
    names = []
    for base, _dirs, files in os.walk(root):
        for n in files:
            if n.endswith(".a") and os.path.exists(os.path.join(base, n[:-2] + ".b")):
                names.append(os.path.join(base, n[:-2]))
    return sorted(names)


def generation(path):
    try:
        with open(path, "rb") as f:
            data = f.read(20)
        return struct.unpack("<Q", data[12:20])[0] if len(data) == 20 else -1
    except FileNotFoundError:
        return -1


def tear(root):
    """What a cut store leaves in its target, for every pair."""
    done = []
    for stem in ab_pairs(root):
        a, b = stem + ".a", stem + ".b"
        older = a if generation(a) <= generation(b) else b
        size = os.path.getsize(older)
        kind = rng.choice(["prefix", "zeros", "garbage", "empty", "hole"])
        with open(older, "r+b") as f:
            data = bytearray(f.read())
            if kind == "prefix":
                keep = rng.randrange(0, max(1, size))
                data[keep:] = bytes(size - keep)
            elif kind == "zeros":
                data = bytearray(size)
            elif kind == "garbage":
                data = bytearray(rng.randbytes(size))
            elif kind == "hole":
                at = rng.randrange(0, max(1, size))
                data[at:at + 16] = bytes(len(data[at:at + 16]))
            elif kind == "empty":
                data = bytearray()
            f.seek(0)
            f.truncate(0)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        done.append(f"{os.path.relpath(older, root)}:{kind}")
    return done


def attach_calls(v):
    """The calls of the set an undisturbed attach of the torn volume makes."""
    trace = os.path.join(v.dir, "attach.trace")
    v.start(wrapper=["strace", "-f", "-y", "-qq", "-e", f"trace={SET}", "-o", trace])
    v.kill9()
    per, points = collections.Counter(), []
    for line in open(trace).read().splitlines():
        m = re.match(r"\d+\s+(\w+)\((.*)", line)
        if m:
            per[m.group(1)] += 1
            where = re.search(r"<([^>]*)>", m.group(2))
            what = os.path.relpath(where.group(1), v.root) if where else "?"
            size = re.search(r">, (\d+)\)", m.group(2))
            points.append((m.group(1), per[m.group(1)], what + (f" len {size.group(1)}" if size and m.group(1) == "ftruncate" else "")))
    return points, open(trace).read()


def clone(src, tag):
    """A copy of the volume directory with its own configuration."""
    dst = mk.Vol(tag, discard=discard, key_file=src.key, **cfg_kw())
    shutil.rmtree(dst.root, ignore_errors=True)
    shutil.copytree(src.root, dst.root, symlinks=True)
    return dst


def verify(v, acked, what):
    h = mk.connect(v.sock)
    bad = []
    for off, ver in sorted(acked.items()):
        got = h.pread(UNIT, off)
        want = bytes(UNIT) if ver == 0 else mk.pattern(off, UNIT, ver, seed)
        if got != want:
            bad.append(f"{what}: offset {off}: wanted version {ver}, read {mk.describe(got[:512])}")
    h.shutdown()
    return bad


base, acked = build()
torn = tear(base.root)
print(f"torn sides: {torn}", flush=True)
# The offline check of the torn volume: a cut store's leftovers are what
# the next attach repairs, so they are warnings, never errors.
torn_check = base.maki("check", base.cfg, "--deep")
torn_text = torn_check.stdout + torn_check.stderr
print("deep check of the torn volume: exit", torn_check.returncode,
      [l for l in torn_text.splitlines() if "verdict" in l or l.startswith("error")][:6], flush=True)
probe = clone(base, "afp")
points, text = attach_calls(probe)
probe.cleanup()
empties = len(re.findall(r"ftruncate\(\d+<[^>]*>, 0\)", text))
print(f"an undisturbed attach of the torn volume makes {len(points)} calls of the set, "
      f"{empties} of them ftruncate(fd, 0)", flush=True)
assert empties > 0, "the attach emptied no side: nothing of #386 is exercised"

failures, outcomes, tolerated = [], collections.Counter(), []
if torn_check.returncode != 0 or "check passed" not in torn_text:
    failures.append("deep check of the torn volume reports errors: " + torn_text[-600:])
for index in range(0, len(points), step):
    name, nth, where = points[index]
    if errno_name == "ENOSPC" and name in ("fdatasync", "fsync"):
        continue
    v = clone(base, "afc")
    try:
        trace = os.path.join(v.dir, "fault.trace")
        wrapper = ["strace", "-f", "-qq", "-e", f"trace={SET}", "-o", trace,
                   "-e", f"inject={name}:error={errno_name}:when={nth}"]
        try:
            v.start(wrapper=wrapper, timeout=60)
            outcomes["attached despite the failed call"] += 1
            tolerated.append(f"{name}#{nth} {where}")
            failures += verify(v, acked, f"{name}#{nth} live")
        except RuntimeError as e:
            outcomes["attach refused"] += 1
        v.kill9()
        try:
            v.start(timeout=60)
        except RuntimeError as e:
            failures.append(f"{name}#{nth}: the clean attach after the failed one is refused: {str(e)[-400:]}")
            continue
        failures += verify(v, acked, f"{name}#{nth} after a clean attach")
        rc = v.term()
        r = v.maki("check", v.cfg, "--deep")
        if r.returncode != 0 or "check passed" not in r.stdout + r.stderr:
            failures.append(f"{name}#{nth}: deep check: {(r.stdout + r.stderr)[-400:]}")
    finally:
        v.cleanup()

base.cleanup()
print(dict(outcomes))
print("attach went on after a failed:", tolerated)
for f in failures[:10]:
    print("BAD", f)
print(f"attach_fault discard={discard} seed={seed} errno={errno_name}: {len(points)} calls, {len(failures)} violation(s)")
sys.exit(1 if failures else 0)
