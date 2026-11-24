#!/usr/bin/python3.12
"""Round 9 rollback-native: rollback / replay / swap attacks on a LOCAL rollback-protected
pair through the real commands. Every committed generation's backing directory is saved
while the daemon is stopped; each is then put back under the current witness (and the
reverse), and every command an operator could try is run on it: the daemon, `maki check`,
`maki check --deep`, `maki volume inspect`, `maki volume create`. None may accept the pair,
none may change it into one that is accepted, and none may damage the current pair.

usage: attacks_local.py [--gens 6] [--seed N]
"""
import os, sys, subprocess, shutil, struct, hashlib, random, argparse, time
import mk9 as mk
import nbd

P = argparse.ArgumentParser()
P.add_argument("--gens", type=int, default=6)
P.add_argument("--seed", type=int, default=1)
A = P.parse_args()
rng = random.Random(A.seed)
TB, TW = f"/tmp/a9rn-atk-b-{os.getpid()}", f"/tmp/a9rn-atk-w-{os.getpid()}"
FAILS = []
ROWS = []


def fail(m):
    FAILS.append(m); print("FAIL " + m, flush=True)


def tree_hash(d):
    h = hashlib.sha256()
    for dp, dn, fn in sorted(os.walk(d)):
        dn.sort()
        for f in sorted(fn):
            p = os.path.join(dp, f)
            h.update(os.path.relpath(p, d).encode() + b"\0")
            with open(p, "rb") as fh:
                h.update(hashlib.sha256(fh.read()).digest())
    return h.hexdigest()


def gen(wdir):
    try:
        b = open(os.path.join(wdir, "anchor"), "rb").read()
        return struct.unpack_from("<Q", b, 32)[0] if len(b) == 104 else None
    except OSError:
        return None


def vol_for(root, wroot, key=None, tag="atk"):
    rb = f'[backing.rollback_protection]\nwitness_root = "{wroot}"\ncapacity = "8MiB"\n'
    return mk.Vol(tag, discard=True, backing_dir=root, key_file=key, size="2MiB", ckpt_reserve="256KiB", reserve="64KiB", extra_backing=rb)


def commands(v, label, expect_ok):
    """Run every command against the pair of `v`; returns the list of (name, accepted, message)."""
    out = []
    for name, args in (("check", ["check", v.cfg]), ("check --deep", ["check", v.cfg, "--deep"]), ("volume inspect", ["volume", "inspect", v.cfg]),
                       ("volume create", ["volume", "create", v.cfg, "--discard"])):
        r = v.maki(*args)
        msg = (r.stderr.strip() or r.stdout.strip()).splitlines()[-1][:230] if (r.stderr.strip() or r.stdout.strip()) else ""
        accepted = r.returncode == 0
        out.append((name, accepted, msg))
        if "panicked" in r.stderr:
            fail(f"{label}: {name} panicked: {r.stderr[-300:]}")
    try:
        v.start(timeout=30)
        h = mk.connect(v.sock)
        first = bytes(h.pread(512, 0))
        h.shutdown(); v.term()
        out.append(("daemon", True, mk.describe(first)))
    except RuntimeError as e:
        out.append(("daemon", False, str(e).strip().splitlines()[-1][:230]))
    for name, accepted, msg in out:
        want = (name != "volume create") if expect_ok else False
        mark = "ok " if accepted == want else "BAD"
        ROWS.append(f"  [{mark}] {label}: {name}: {'ACCEPTED' if accepted else 'refused'}: {msg}")
        print(ROWS[-1], flush=True)
        if accepted != want:
            fail(f"{label}: {name} {'accepted' if accepted else 'refused'} the pair: {msg}")
    return out


for t, size in ((TB, "700m"), (TW, "32m")):
    os.makedirs(t, exist_ok=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", f"size={size},mode=0700", "tmpfs", t], check=True)
vols = []
try:
    root, wroot = os.path.join(TB, "volume"), os.path.join(TW, "witness")
    os.makedirs(root); os.makedirs(wroot)
    v = vol_for(root, wroot); vols.append(v)
    v.create()
    saves = []          # (generation, backing copy, witness copy, version written)
    for g in range(A.gens):
        v.start()
        h = mk.connect(v.sock)
        for k in range(rng.randint(1, 4)):
            off = rng.randrange(0, 64) * 4096
            h.pwrite(mk.pattern(off, 4096, g * 10 + k + 1, A.seed), off, nbd.CMD_FLAG_FUA)
        h.pwrite(mk.pattern(0, 4096, 1000 + g, A.seed), 0, nbd.CMD_FLAG_FUA)
        h.flush(); h.shutdown()
        if v.term() != 0:
            fail(f"generation {g}: daemon did not stop cleanly")
        b, w = os.path.join(TB, f"save-b-{g}"), os.path.join(TW, f"save-w-{g}")
        shutil.copytree(root, b); shutil.copytree(wroot, w)
        saves.append((gen(wroot), b, w, 1000 + g))
        print(f"saved state {g}: witness generation {gen(wroot)}")
    cur_gen = gen(wroot)
    cur_b, cur_w = saves[-1][1], saves[-1][2]

    # 0. controls: the current pair is accepted, and offline commands do not advance the witness
    c = vol_for(os.path.join(TB, "ctl-b"), os.path.join(TW, "ctl-w"), key=v.key, tag="ctl"); vols.append(c)
    shutil.copytree(cur_b, c.root); shutil.copytree(cur_w, os.path.join(TW, "ctl-w"))
    g0 = gen(os.path.join(TW, "ctl-w"))
    for args in (["check", c.cfg], ["check", c.cfg, "--deep"], ["volume", "inspect", c.cfg]):
        r = c.maki(*args)
        if r.returncode != 0:
            fail(f"control: {args} failed on the current pair: {r.stderr[-300:]}")
        if gen(os.path.join(TW, "ctl-w")) != g0:
            fail(f"control: {' '.join(args[:2])} advanced the witness generation {g0} -> {gen(os.path.join(TW, 'ctl-w'))}")
    print(f"control: offline commands left the witness at generation {gen(os.path.join(TW, 'ctl-w'))} (was {g0})")
    commands(c, "control (current backing, current witness)", True)

    n = 0
    def attack(label, bsrc, wsrc, also_then_current=True):
        """Put bsrc/wsrc together, run every command, then check the commands did not turn the
        pair into an accepted one and did not make the witness refuse its real backing."""
        global n
        n += 1
        b, w = os.path.join(TB, f"atk-b-{n}"), os.path.join(TW, f"atk-w-{n}")
        shutil.copytree(bsrc, b); shutil.copytree(wsrc, w)
        a = vol_for(b, w, key=v.key, tag=f"a{n}"); vols.append(a)
        commands(a, label, False)
        commands(a, label + " (second pass, after every command ran once)", False)
        if also_then_current:
            # the witness these commands touched must still accept the backing that belongs to it
            real_b = [s for s in saves if os.path.realpath(s[2]) == os.path.realpath(wsrc)]
            if real_b:
                b2 = os.path.join(TB, f"atk-b-{n}-real")
                shutil.copytree(real_b[0][1], b2)
                a2 = vol_for(b2, w, key=v.key, tag=f"a{n}r"); vols.append(a2)
                try:
                    a2.start(timeout=30)
                    h = mk.connect(a2.sock)
                    got = bytes(h.pread(4096, 0))
                    h.shutdown(); a2.term()
                    if got != mk.pattern(0, 4096, real_b[0][3], A.seed):
                        fail(f"{label}: after the attack the witness's own backing serves {mk.describe(got[:512])}, expected version {real_b[0][3]}")
                    else:
                        print(f"  [ok ] {label}: afterwards the witness still accepts its own backing with the right data")
                except RuntimeError as e:
                    fail(f"{label}: after the attack the witness refuses its own backing: {str(e)[-300:]}")
                shutil.rmtree(b2, ignore_errors=True)
        shutil.rmtree(b, ignore_errors=True); shutil.rmtree(w, ignore_errors=True)

    # 1. backing restored to each earlier state, witness current
    for g, b, w, ver in saves[:-1]:
        attack(f"backing of generation {g} under the current witness (generation {cur_gen})", b, cur_w)
    # 2. witness restored to each earlier state, backing current
    for g, b, w, ver in saves[:-1]:
        attack(f"witness of generation {g} under the current backing (generation {cur_gen})", cur_b, w, also_then_current=False)
    # 3. another volume's backing or witness (same key, same geometry)
    o = vol_for(os.path.join(TB, "other-b"), os.path.join(TW, "other-w"), key=v.key, tag="other"); vols.append(o)
    os.makedirs(o.root); os.makedirs(os.path.join(TW, "other-w"))
    o.create()
    o.start(); h = mk.connect(o.sock); h.pwrite(mk.pattern(0, 4096, 7777, A.seed), 0, nbd.CMD_FLAG_FUA); h.shutdown(); o.term()
    ob, ow = os.path.join(TB, "save-other-b"), os.path.join(TW, "save-other-w")
    shutil.copytree(o.root, ob); shutil.copytree(os.path.join(TW, "other-w"), ow)
    saves.append((gen(ow), ob, ow, 7777))
    attack("another volume's backing under this volume's witness", ob, cur_w)
    attack("this volume's backing under another volume's witness", cur_b, ow)
    # 4. missing or emptied witness, missing manifest slots
    ew = os.path.join(TW, "empty-w"); os.makedirs(ew)
    attack("current backing with an empty witness directory (witness not mounted)", cur_b, ew, also_then_current=False)
    lw = os.path.join(TW, "lockonly-w"); os.makedirs(lw); open(os.path.join(lw, "witness.lock"), "w").close()
    attack("current backing with a witness directory holding only witness.lock", cur_b, lw, also_then_current=False)
    # 5. both manifest slots of an older state combined with the current arena, and the reverse
    for g, b, w, ver in saves[:1]:
        mix = os.path.join(TB, "mix-b"); shutil.copytree(cur_b, mix)
        shutil.copy(os.path.join(b, "rollback.arena"), os.path.join(mix, "rollback.arena"))
        attack(f"current manifests with the arena of generation {g}", mix, cur_w)
        shutil.rmtree(mix)
        mix = os.path.join(TB, "mix-b"); shutil.copytree(cur_b, mix)
        for s in ("rollback.manifest.0", "rollback.manifest.1"):
            shutil.copy(os.path.join(b, s), os.path.join(mix, s))
        attack(f"current arena with the manifest slots of generation {g}", mix, cur_w)
        shutil.rmtree(mix)
finally:
    for x in vols:
        try:
            x.cleanup()
        except Exception:
            pass
    for t in (TB, TW):
        subprocess.run(["umount", "-l", t])
        try:
            os.rmdir(t)
        except OSError:
            pass
print(f"attacks_local seed {A.seed}: {len(ROWS)} command runs, {'FAIL' if FAILS else 'ok'}")
for f in FAILS[:30]:
    print("  " + f[:600])
sys.exit(1 if FAILS else 0)
