"""Offline tools on damaged volumes vs what attach then does.

Per seed: build a golden volume (clean stop or kill -9 with journal content, v2 or v3),
then N times: restore it, apply 1-3 random damages to backing files, run
`maki check`, `maki check --deep`, `maki-check --deep`, `maki volume inspect`
(the tree must not change; exit status 0/1; no panic; deep verdicts agree), then
attach under nbdkit and read every block.
Oracle: deep `check passed` => attach succeeds and no block is EIO or wrong;
        deep `check FAILED` => attach refuses or some block is EIO;
        a flushed block is never wrong, an unwritten block never non-zero.
usage: damage.py SEED [ITERS] [--mode clean|kill] [--discard]
"""
import sys, os, json, time, random, shutil, subprocess, hashlib, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mk, ctl
ap = argparse.ArgumentParser(); ap.add_argument("seed", type=int); ap.add_argument("iters", type=int, nargs="?", default=40)
ap.add_argument("--mode", default=None); ap.add_argument("--discard", action="store_true"); ap.add_argument("--keep", action="store_true")
a = ap.parse_args()
rng = random.Random(a.seed)
mode = a.mode or rng.choice(["clean", "kill", "kill"])
discard = a.discard or rng.random() < 0.4
MAKI_CHECK = os.path.join(os.path.dirname(mk.MAKI), "maki-check")
BLK = 4096; NBLK = 256
v = mk.Vol(tag=f"dmg{a.seed}", size="1MiB", discard=discard, shard="64KiB", seg="64KiB", jmax="512KiB")
golden = v.root + ".golden"
truth = {}     # block -> version flushed (durable)
maybe = {}     # block -> set of acceptable versions (unflushed tail on kill)
findings = []; stats = {"iters": 0, "deep_pass": 0, "deep_fail": 0, "attach_refused": 0, "eio_blocks": 0, "pessimistic": 0}

def tree_hash(root):
    out = []
    for dp, dn, fn in sorted(os.walk(root)):
        for n in sorted(fn):
            p = os.path.join(dp, n)
            st = os.lstat(p)
            with open(p, "rb") as f: h = hashlib.sha256(f.read()).hexdigest()
            out.append((os.path.relpath(p, root), st.st_size, h))
        for n in sorted(dn):
            out.append((os.path.relpath(os.path.join(dp, n), root) + "/", 0, ""))
    return out

def run(*args):
    r = subprocess.run(args, capture_output=True, text=True, timeout=120)
    return r.returncode, r.stdout, r.stderr

try:
    v.create(); v.start(); h = mk.connect(v.sock)
    ver = 0
    for rnd in range(rng.randint(2, 5)):
        for _ in range(rng.randint(10, 60)):
            b = rng.randrange(NBLK); ver += 1
            h.pwrite(mk.pattern(b * BLK, BLK, ver, a.seed), b * BLK); truth[b] = ver
        if discard and rng.random() < 0.6:
            for _ in range(rng.randint(1, 6)):
                b = rng.randrange(NBLK); h.trim(BLK, b * BLK); truth[b] = 0
        h.flush()
        if rng.random() < 0.6: ctl.call(v.control, {"command": "checkpoint"})
    if mode == "kill":
        # an unflushed tail: either version may survive
        for _ in range(rng.randint(0, 10)):
            b = rng.randrange(NBLK); ver += 1
            h.pwrite(mk.pattern(b * BLK, BLK, ver, a.seed), b * BLK)
            maybe.setdefault(b, {truth.get(b, 0)}).add(ver)
        v.kill9()
    else:
        h.shutdown(); v.term()
    shutil.copytree(v.root, golden)
    files = [os.path.relpath(os.path.join(dp, n), golden) for dp, _, fn in os.walk(golden) for n in fn if n != "volume.lock"]
    print(f"seed {a.seed}: mode={mode} discard={discard} files={len(files)} blocks={len(truth)}", flush=True)
    for it in range(a.iters):
        shutil.rmtree(v.root); shutil.copytree(golden, v.root)
        dmg = []
        for _ in range(rng.choice([1, 1, 1, 2, 3])):
            rel = rng.choice(files); p = os.path.join(v.root, rel)
            if not os.path.exists(p): continue
            size = os.path.getsize(p)
            kind = rng.choice(["flip", "flip", "flip", "zero", "zero", "trunc", "delete", "extend"])
            if kind == "delete":
                os.unlink(p); dmg.append(f"delete {rel}")
            elif kind == "trunc":
                n = rng.randrange(size + 1) if size else 0
                os.truncate(p, n); dmg.append(f"trunc {rel} {size}->{n}")
            elif kind == "extend":
                with open(p, "ab") as f: f.write(bytes(rng.randrange(256) for _ in range(rng.choice([1, 512, 4096]))))
                dmg.append(f"extend {rel}")
            elif size:
                off = rng.randrange(size)
                with open(p, "r+b") as f:
                    if kind == "flip":
                        f.seek(off); c = f.read(1); f.seek(off); f.write(bytes([c[0] ^ (1 << rng.randrange(8))])); dmg.append(f"flip {rel}@{off}")
                    else:
                        off -= off % 512; f.seek(off); f.write(bytes(min(512, size - off))); dmg.append(f"zero {rel}@{off}")
        before = tree_hash(v.root)
        res = {}
        for name, cmd in (("check", [mk.MAKI, "check", v.cfg]), ("deep", [mk.MAKI, "check", v.cfg, "--deep"]),
                          ("mcheck", [MAKI_CHECK, v.root]), ("mdeep", [MAKI_CHECK, v.root, "--deep"]), ("inspect", [mk.MAKI, "volume", "inspect", v.cfg])):
            rc, out, err = run(*cmd); res[name] = (rc, out, err)
            if rc not in (0, 1) or "panicked" in out + err or "RUST_BACKTRACE" in out + err:
                findings.append(f"it {it} {dmg}: {name} rc={rc} {(out + err)[-300:]}")
            if mk.KEY_HEX in out + err:
                findings.append(f"it {it}: {name} printed the key")
        after = tree_hash(v.root)
        if after != before:
            diff = [x for x in after if x not in before] + [("gone",) + x for x in before if x not in after]
            # documented: a deep check recreates a missing volume.lock
            if not all(d[0] == "volume.lock" or (d[0] == "gone" and False) for d in diff):
                findings.append(f"it {it} {dmg}: OFFLINE TOOL CHANGED THE TREE: {diff[:4]}")
        deep_rc, deep_out, deep_err = res["deep"]
        m_rc, m_out, m_err = res["mdeep"]
        verdict = lambda o: [l for l in o.splitlines() if "deep check verdict" in l]
        if (deep_rc, verdict(deep_out)) != (m_rc, verdict(m_out)):
            findings.append(f"it {it} {dmg}: maki check --deep (rc {deep_rc} {verdict(deep_out)}) != maki-check --deep (rc {m_rc} {verdict(m_out)}) :: {deep_err[-150:]} :: {m_err[-150:]}")
        if res["check"][0] != res["mcheck"][0]:
            findings.append(f"it {it} {dmg}: maki check rc {res['check'][0]} != maki-check rc {res['mcheck'][0]}")
        if res["check"][0] == 1 and deep_rc == 0:
            findings.append(f"it {it} {dmg}: plain check fails but deep check passes: {res['check'][1][-200:]}{res['check'][2][-200:]}")
        # attach
        attach_ok = True; eio = []; wrong = []
        try:
            v.start(timeout=60)
        except RuntimeError as e:
            attach_ok = False; attach_err = str(e)[-260:]
        if attach_ok:
            h = mk.connect(v.sock)
            for b in range(NBLK):
                try:
                    got = h.pread(BLK, b * BLK)
                except Exception as e:
                    eio.append(b); continue
                ok_versions = maybe.get(b, {truth.get(b, 0)})
                if not any(got == (bytes(BLK) if vv == 0 else mk.pattern(b * BLK, BLK, vv, a.seed)) for vv in ok_versions):
                    wrong.append((b, mk.describe(got[:512]), sorted(ok_versions)))
            h.shutdown(); rc = v.term()
            if rc != 0: findings.append(f"it {it} {dmg}: clean stop rc {rc}")
        else:
            try: v.notify.close()
            except Exception: pass
        stats["iters"] += 1
        stats["deep_pass" if deep_rc == 0 else "deep_fail"] += 1
        stats["attach_refused"] += (not attach_ok); stats["eio_blocks"] += len(eio)
        if wrong:
            findings.append(f"it {it} {dmg}: WRONG DATA after attach: {wrong[:3]} (deep rc {deep_rc})")
        if deep_rc == 0 and (not attach_ok or eio):
            findings.append(f"it {it} {dmg}: deep check PASSED ({verdict(deep_out)}) but " + (f"attach refused: {attach_err}" if not attach_ok else f"{len(eio)} blocks EIO e.g. {eio[:4]}"))
        if deep_rc == 1 and attach_ok and not eio and not wrong:
            stats["pessimistic"] += 1
            errs = [l for l in (deep_out + deep_err).splitlines() if l.startswith("ERROR") or l.startswith("error")]
            findings.append(f"it {it} {dmg}: deep check FAILED but attach served every block: {errs[:3]}")
    print("STATS", stats)
    print("FINDINGS", len(findings))
    for f in findings: print("  ", f[:900])
finally:
    try: v.kill9()
    except Exception: pass
    if a.keep and findings: print("kept", v.dir)
    else: v.cleanup()
sys.exit(1 if findings else 0)
