"""Offline tools and maki-benchmark pointed at a volume another process is serving (strace: no
modifying call below the backing root), and kill -9 of the offline tools mid-run."""
import sys, os, json, time, random, subprocess, threading, re, shutil, signal
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mk, ctl
BIN = os.path.dirname(mk.MAKI)
MAKI_CHECK = os.path.join(BIN, "maki-check"); BENCH = os.path.join(BIN, "maki-benchmark")
seed = int(sys.argv[1]) if len(sys.argv) > 1 else 1
rng = random.Random(seed)
BLK = 4096; NBLK = 512
v = mk.Vol(tag=f"live{seed}", size="2MiB", shard="64KiB", seg="64KiB", jmax="512KiB")
truth = {}; lock = threading.Lock(); stop = threading.Event(); findings = []
LOCKS = []
RDWR = {}
SYNCS = {}
def io_thread():
    h = mk.connect(v.sock); r = random.Random(seed + 1); ver = 0; pending = {}
    while not stop.is_set():
        b = r.randrange(NBLK); ver += 1
        h.pwrite(mk.pattern(b * BLK, BLK, ver, seed), b * BLK); pending[b] = ver
        if r.random() < 0.2:
            h.flush()
            with lock: truth.update(pending)
            pending = {}
        if r.random() < 0.02:
            try: ctl.call(v.control, {"command": "checkpoint"})
            except Exception: pass
    h.flush()
    with lock: truth.update(pending)
    h.shutdown()
MOD = re.compile(r"^\d+\s+(openat|unlinkat|renameat2?|mkdirat|linkat|symlinkat|ftruncate|fallocate|truncate|pwrite64|pwritev2?|write|fsync|fdatasync)\((.*)$")
def modifying_calls(trace, root, name="?"):
    """Calls that change something below the backing root. FileBacking resolves names through
    directory descriptors, so paths are relative; an O_RDWR open of an existing file is not a
    change by itself and is only counted (RDWR)."""
    out = []
    for line in open(trace, errors="replace"):
        m = MOD.match(line)
        if not m: continue
        call, rest = m.groups()
        if call == "write":
            if re.match(r"[012],", rest): continue          # stdout/stderr
            if re.search(r'"\\1\\0\\0\\0\\0\\0\\0\\0", 8\)', rest): continue   # tokio eventfd wake-up
        if call in ("fsync", "fdatasync"):
            SYNCS[name] = SYNCS.get(name, 0) + 1; continue     # directory syncs at open (configuration.md "Backing directory identity")
        if call == "openat":
            if re.search(r'"(/dev/|/proc/|/sys/|/etc/|/usr/|/lib)', rest): continue
            if "volume.lock" in rest:
                LOCKS.append(name + ": " + re.sub(r"^\d+\s+", "", line.strip())[:120]); continue
            if re.search(r"O_CREAT|O_TRUNC|O_APPEND", rest) and "= -1" not in rest.split(")")[-1]:
                out.append(line.strip()[:200])
            elif re.search(r"O_RDWR|O_WRONLY", rest):
                RDWR[name] = RDWR.get(name, 0) + 1
            continue
        if "= -1" in rest.rsplit(")", 1)[-1] and call in ("unlinkat",): continue
        out.append(line.strip()[:200])
    return out
try:
    v.create(); v.start()
    t = threading.Thread(target=io_thread); t.start()
    time.sleep(0.3)
    tools = [
        ("maki check", [mk.MAKI, "check", v.cfg]),
        ("maki check --deep", [mk.MAKI, "check", v.cfg, "--deep"]),
        ("maki-check", [MAKI_CHECK, v.root]),
        ("maki-check --deep", [MAKI_CHECK, v.root, "--deep"]),
        ("maki volume inspect", [mk.MAKI, "volume", "inspect", v.cfg]),
        ("maki volume create", [mk.MAKI, "volume", "create", v.cfg]),
        ("maki volume create --discard", [mk.MAKI, "volume", "create", v.cfg, "--discard"]),
        ("maki-benchmark", [BENCH, v.cfg, "16", "4096"]),
        ("maki-benchmark --destroy-data", [BENCH, "--destroy-data", v.cfg, "16", "4096"]),
        ("maki status", [mk.MAKI, "status", v.cfg]),
    ]
    tally = {}
    for i in range(int(sys.argv[2]) if len(sys.argv) > 2 else 60):
        name, cmd = tools[i % len(tools)]
        tr = os.path.join(v.dir, "tool.trace")
        r = subprocess.run(["strace", "-f", "-qq", "-o", tr, "-e", "trace=openat,unlinkat,renameat,renameat2,mkdirat,linkat,symlinkat,ftruncate,fallocate,truncate,pwrite64,pwritev,pwritev2,write,fsync,fdatasync"] + cmd, capture_output=True, text=True, timeout=120)
        out = (r.stdout + r.stderr).strip()
        mods = modifying_calls(tr, v.root, name)
        key = (name, r.returncode, (out.splitlines()[-1] if out else "")[:110])
        tally[key] = tally.get(key, 0) + 1
        if mods: findings.append(f"{name}: MODIFYING CALLS on a live volume: {mods[:4]}")
        if r.returncode not in (0, 1, 2) or "panicked" in out: findings.append(f"{name}: rc {r.returncode}: {out[-300:]}")
        if name.startswith("maki-benchmark") and r.returncode == 0: findings.append(f"{name}: RAN against a live volume: {out[-200:]}")
        if name.startswith("maki volume create") and r.returncode == 0: findings.append(f"{name}: created over a live volume")
        errs = [l for l in out.splitlines() if l.startswith("ERROR")]
        if name in ("maki check", "maki-check") and r.returncode == 1: tally[("spurious plain-check failure", 1, (errs[0] if errs else out[-100:])[:150])] = tally.get(("spurious plain-check failure", 1, (errs[0] if errs else out[-100:])[:150]), 0) + 1
    stop.set(); t.join()
    for k, n in sorted(tally.items()): print(f"  {n:3} x {k[0]:30} rc={k[1]} {k[2]}")
    st = ctl.status(v.control); print("daemon still ready:", st["state"], st["io_state"])
    rc = v.term(); print("term rc", rc)
    # kill -9 the offline tools mid-run on the stopped volume, then attach
    kills = 0
    for i in range(40):
        name, cmd = tools[rng.randrange(5)]
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(rng.uniform(0, 0.03))
        if p.poll() is None:
            p.kill(); kills += 1
        p.wait()
    print("offline tools killed mid-run:", kills, "of 40")
    rc, out = 0, subprocess.run([mk.MAKI, "check", v.cfg, "--deep"], capture_output=True, text=True)
    print("check --deep after kills:", out.returncode, out.stdout.strip().splitlines()[-1])
    v.start(); h = mk.connect(v.sock); bad = 0
    for b, ver in truth.items():
        if h.pread(BLK, b * BLK) != mk.pattern(b * BLK, BLK, ver, seed): bad += 1
    print("restart ok; flushed blocks checked:", len(truth), "wrong:", bad)
    if bad: findings.append(f"{bad} wrong blocks")
    h.shutdown(); v.term()
    print("volume.lock opens by tool:", sorted(set(re.sub(r"= \\d+$", "", l) for l in LOCKS)))
    print("fsync/fdatasync calls (no write precedes them):", SYNCS)
    print("O_RDWR opens of existing files (no change by themselves):", RDWR)
    print("FINDINGS", len(findings))
    for f in findings[:20]: print("  ", f[:600])
finally:
    stop.set()
    v.cleanup()
