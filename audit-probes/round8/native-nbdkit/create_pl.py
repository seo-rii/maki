#!/usr/bin/python3.12
"""Power loss during `maki volume create`, at every logged call boundary.

`maki volume create` runs under plshim.so on a fresh tmpfs. For every prefix
of its write/sync log, images are built (durable namespace + no unsynced data;
live namespace + no unsynced data; mixed + per-file). On each image the
operator's obvious next steps must lead to a serving, all-zero volume:
attach; if that is refused, `maki volume create` again, then attach.
An interrupted creation that left no readable superblock copy is documented
as "not a volume; empty the root" (docs/operations.md); every other outcome
that can neither be attached nor created again is a wedge.

usage: create_pl.py [--discard] [--step K]
"""
import sys, os, subprocess, shutil, random, copy, importlib.util, time
import nbd, mk

sys.argv_saved = sys.argv
DISCARD = "--discard" in sys.argv
STEP = int(sys.argv[sys.argv.index("--step") + 1]) if "--step" in sys.argv else 1
# reuse the replay model of pl.py without running its main()
src = open(os.path.join(mk.HERE, "pl.py")).read().rsplit("\nmain()", 1)[0]
sys.argv = ["pl.py", "--seed", "0"]
ns = {"__name__": "pl_model"}
exec(compile(src.replace('P.add_argument("--seed", type=int, required=True)', 'P.add_argument("--seed", type=int, default=0)'), "pl.py", "exec"), ns)
Model, parse_log = ns["Model"], ns["parse_log"]

T = f"/tmp/a8n-cr-{os.getpid()}"
os.makedirs(T)
subprocess.run(["mount", "-t", "tmpfs", "-o", "size=64m,mode=0700", "tmpfs", T], check=True)
fails = []
stats = dict(images=0, attach_first_try=0, needed_recreate=0, create_refused_but_attach_ok=0)
try:
    live = os.path.join(T, "live"); os.mkdir(live, 0o700)
    v = mk.Vol("cr", discard=DISCARD, backing_dir=os.path.join(live, "volume"))
    logp = os.path.join(v.dir, "create.log")
    baseline = Model(live)
    env = dict(os.environ, LD_PRELOAD=os.path.join(mk.HERE, "plshim.so"), PLSHIM_ROOT=live, PLSHIM_LOG=logp)
    r = subprocess.run([mk.MAKI, "volume", "create", v.cfg] + (["--discard"] if DISCARD else []), capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    records = parse_log(logp)
    print(f"create logged {len(records)} calls: " + "".join(x[0] for x in records))
    rnd = random.Random(1)
    m = copy.deepcopy(baseline)
    n = 0
    for i in range(0, len(records) + 1):
        if i > 0:
            m.apply(records[i - 1])
        if i % STEP and i != len(records):
            continue
        for ns_mode, data_mode in (("dur", "none"), ("live", "none"), ("mixed", "perfile"), ("live", "subset")):
            n += 1
            img = os.path.join(T, f"img-{n}")
            copy.deepcopy(m).image(img, ns_mode, data_mode, rnd)
            root = os.path.join(img, "volume")
            iv = mk.Vol("cri", discard=DISCARD, backing_dir=root, key_file=v.key)
            label = f"after call {i}/{len(records)} ({records[i-1][0] if i else '-'}) [{ns_mode}/{data_mode}]"
            try:
                stats["images"] += 1
                steps = []
                ok = False
                try:
                    iv.start(); ok = True; stats["attach_first_try"] += 1
                except RuntimeError as e:
                    steps.append("attach: " + str(e).strip().splitlines()[-1][-200:])
                    cr = iv.create(check=False)
                    steps.append(f"create rc={cr.returncode}: " + (cr.stdout + cr.stderr).strip().splitlines()[0][-200:] if (cr.stdout + cr.stderr).strip() else f"create rc={cr.returncode}")
                    try:
                        iv.start(); ok = True; stats["needed_recreate"] += 1
                    except RuntimeError as e2:
                        steps.append("attach again: " + str(e2).strip().splitlines()[-1][-300:])
                if not ok and "no valid superblock" in steps[0] and "use an empty root" in steps[1]:
                    # documented (docs/operations.md:94-97): not a volume; the operator empties the root
                    stats["documented_empty_by_hand"] = stats.get("documented_empty_by_hand", 0) + 1
                    shutil.rmtree(root)
                    cr = iv.create(check=False)
                    try:
                        iv.start(); ok = True
                    except RuntimeError as e3:
                        steps.append(f"after emptying the root: create rc={cr.returncode}, attach: " + str(e3).strip().splitlines()[-1][-200:])
                if not ok:
                    fails.append(f"{label}: WEDGED: " + " | ".join(steps))
                    print("FAIL " + fails[-1], flush=True)
                    keep = f"/tmp/a8n/create-wedge-{os.getpid()}-{n}"
                    shutil.copytree(img, keep); print("  image kept at", keep)
                    continue
                h = nbd.NBD()
                for _ in range(200):
                    try:
                        h.connect_unix(iv.sock); break
                    except nbd.Error:
                        time.sleep(0.02); h = nbd.NBD()
                size = h.get_size()
                data = bytes(h.pread(size, 0))
                if data != bytes(size):
                    fails.append(f"{label}: a new volume does not read zeros"); print("FAIL " + fails[-1], flush=True)
                h.pwrite(mk.pattern(0, 4096, 1), 0, nbd.CMD_FLAG_FUA)
                h.shutdown()
            finally:
                try: iv.kill9()
                except Exception: pass
                shutil.rmtree(iv.dir, ignore_errors=True); shutil.rmtree(img, ignore_errors=True)
    print(f"{'v3' if DISCARD else 'v2'} create: {stats} ; {len(fails)} FAIL(s)")
finally:
    subprocess.run(["umount", "-l", T]); 
    try: os.rmdir(T)
    except OSError: pass
sys.exit(1 if fails else 0)
