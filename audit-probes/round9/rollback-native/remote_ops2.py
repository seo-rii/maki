#!/usr/bin/python3.12
"""remote_ops2.py = remote_ops.py with the final pkill restricted to its own directories (successor).
Round 9 rollback-native: a REMOTE rollback-protected volume through the real commands.

  attacks  the backing root restored to each earlier state under the current authority, the
           authority state directory restored under the current backing, another volume's
           authority or backing: every command (daemon, takeover, gc, snapshot, create,
           resume-enrollment) must refuse, change nothing, and leave the real pair usable
  conc     the daemon serves verified FUA I/O while gc, witness, snapshot, a second daemon,
           check, inspect and create run against the same root and are killed at random;
           then, without a daemon, daemon starts / takeovers / gc / snapshots race and are
           killed -9; after every round the documented procedure (inspect, takeover if the
           session is not released) must bring the volume back with the acknowledged data
  restore  snapshot, more writes, restore of the snapshot, GC; then the pre-restore backing
           put back under the restored authority

usage: remote_ops.py [attacks] [conc] [restore] [--seed N] [--rounds N]
"""
import os, sys, subprocess, shutil, random, time, signal, argparse, collections, json, hashlib
import mk9 as mk, rw
import nbd

P = argparse.ArgumentParser()
P.add_argument("parts", nargs="*", default=["attacks", "conc", "restore"])
P.add_argument("--seed", type=int, default=1)
P.add_argument("--rounds", type=int, default=60)
P.add_argument("--keep", action="store_true")
A = P.parse_args()
rng = random.Random(A.seed)
TB, TW = f"/tmp/a9rn-ro-b-{os.getpid()}", f"/tmp/a9rn-ro-w-{os.getpid()}"
FAILS = []
MSG = collections.Counter()
CAP = "4MiB"


def fail(m):
    FAILS.append(m); print("FAIL " + m, flush=True)


class Site:
    def __init__(self, tag, root, state, like=None):
        self.root, self.state = root, state
        self.vol = mk.Vol(tag, discard=True, backing_dir=root, key_file=like.vol.key if like else None, size="1MiB",
                          ckpt_reserve="256KiB", reserve="64KiB", extra_backing="@@R@@")
        if like is None:
            self.auth = rw.Authority(os.path.join(self.vol.dir, "auth"), state)
        else:
            self.auth = rw.Authority.__new__(rw.Authority)
            self.auth.__dict__.update(like.auth.__dict__)
            self.auth.base = os.path.join(self.vol.dir, "auth"); os.makedirs(self.auth.base)
            self.auth.state = state; self.auth.port = rw.free_port()
            self.auth.cfg = os.path.join(self.auth.base, "server.toml"); self.auth.proc = None; self.auth.n = 0
            self.auth.write_config()
        self.text = self.vol.text
        self.write_cfgs()

    def write_cfgs(self):
        with open(self.vol.cfg, "w") as f:
            f.write(self.text.replace("@@R@@", self.auth.remote_section(CAP, "writer")))
        self.admin = os.path.join(self.vol.dir, "admin.toml")
        with open(self.admin, "w") as f:
            f.write(self.text.replace("@@R@@", self.auth.remote_section(CAP, "admin")))
        os.chmod(self.admin, 0o644)

    def maki(self, *a, timeout=120):
        return subprocess.run([mk.MAKI, *a], capture_output=True, text=True, timeout=timeout)

    def record(self):
        r = self.maki("volume", "witness", self.vol.cfg)
        if r.returncode != 0:
            raise RuntimeError("volume witness: " + r.stderr.strip()[-300:])
        return json.loads(r.stdout)

    def recover(self):
        rec = self.record()
        if rec["phase"] != "released":
            r = self.maki("volume", "takeover", self.admin, str(rec["fence"]), rw.root_hex(rec))
            if r.returncode != 0:
                return False, f"takeover (phase {rec['phase']}, fence {rec['fence']}): {r.stderr.strip()[-400:]}"
        return True, ""

    def namespaces(self):
        return sorted(n for n in os.listdir(self.root) if n.startswith("remote-") or n.startswith(".remote-gc-"))

    def stop(self):
        for f in (self.vol.kill9, self.auth.kill9):
            try:
                f()
            except Exception:
                pass


def mount():
    for t, size in ((TB, "900m"), (TW, "32m")):
        os.makedirs(t, exist_ok=True)
        subprocess.run(["mount", "-t", "tmpfs", "-o", f"size={size},mode=0700", "tmpfs", t], check=True)


def last_line(text):
    text = text.strip()
    return text.splitlines()[-1][:260] if text else ""


class Data:
    def __init__(self):
        self.ver = {}

    def write(self, h, n, fua=True):
        for _ in range(n):
            u = rng.randrange(0, 96)
            val = rng.randrange(1, 1 << 40)
            h.pwrite(mk.pattern(u * 4096, 4096, val, A.seed), u * 4096, nbd.CMD_FLAG_FUA if fua else 0)
            self.ver[u] = val

    def verify(self, h, what):
        for u, val in self.ver.items():
            got = bytes(h.pread(4096, u * 4096))
            if got != mk.pattern(u * 4096, 4096, val, A.seed):
                fail(f"{what}: unit {u} holds {mk.describe(got[:512])}, acknowledged version {val}")
                return False
        return True


def part_attacks():
    print("== attacks")
    s = Site("ra", os.path.join(TB, "volume"), os.path.join(TW, "state"))
    os.makedirs(s.root)
    s.auth.init(); s.auth.start()
    r = s.vol.create(check=False)
    if r.returncode != 0:
        raise RuntimeError(r.stderr)
    d = Data()
    saves = []
    for g in range(4):
        s.vol.start(timeout=60)
        h = mk.connect(s.vol.sock)
        d.write(h, 3)
        h.pwrite(mk.pattern(0, 4096, 5000 + g, A.seed), 0, nbd.CMD_FLAG_FUA); d.ver[0] = 5000 + g
        h.shutdown()
        if s.vol.term(timeout=60) != 0:
            fail(f"state {g}: daemon did not stop cleanly: {s.vol.read_log()[-300:]}")
        rec = s.record()
        s.auth.kill9()
        b, w = os.path.join(TB, f"save-b-{g}"), os.path.join(TW, f"save-w-{g}")
        shutil.copytree(s.root, b); shutil.copytree(s.state, w)
        saves.append((rec, b, w, dict(d.ver)))
        print(f"saved state {g}: phase {rec['phase']} fence {rec['fence']} generation {rec['current']['anchor']['generation']} namespaces {s.namespaces()}")
        s.auth.start()
    s.auth.kill9()
    cur = saves[-1]
    n = [0]

    def attack(label, bsrc, wsrc, own_backing=None, expect_refused=True):
        n[0] += 1
        b, w = os.path.join(TB, f"atk-b-{n[0]}"), os.path.join(TW, f"atk-w-{n[0]}")
        shutil.copytree(bsrc, b); shutil.copytree(wsrc, w); os.chmod(w, 0o700)
        a = Site(f"a{n[0]}", b, w, like=s)
        a.auth.start()
        before = a.record()
        results = []
        snapdir = os.path.join(TB, f"snap-{n[0]}")
        for name, args in (("volume gc", ["volume", "gc", a.vol.cfg]), ("volume snapshot", ["volume", "snapshot", a.vol.cfg, snapdir]),
                           ("volume create", ["volume", "create", a.vol.cfg, "--discard"]),
                           ("volume takeover", ["volume", "takeover", a.admin, str(before["fence"]), rw.root_hex(before)]),
                           ("volume resume-enrollment", ["volume", "resume-enrollment", a.admin, str(before["fence"]), s.auth.identity, "--discard"]),
                           ("check --deep", ["check", a.vol.cfg, "--deep"]), ("volume inspect", ["volume", "inspect", a.vol.cfg])):
            if name == "volume takeover" and not expect_refused:
                now_rec = a.record()        # the control's snapshot raised the fence
                args = ["volume", "takeover", a.admin, str(now_rec["fence"]), rw.root_hex(now_rec)]
            r = a.maki(*args)
            results.append((name, r.returncode == 0, last_line(r.stderr) or last_line(r.stdout)))
            if "panicked" in r.stderr:
                fail(f"{label}: {name} panicked: {r.stderr[-300:]}")
        try:
            a.vol.start(timeout=60)
            h = mk.connect(a.vol.sock)
            first = bytes(h.pread(4096, 0))
            h.shutdown(); a.vol.term(timeout=60)
            results.append(("daemon", True, mk.describe(first[:512])))
        except RuntimeError as e:
            results.append(("daemon", False, last_line(str(e))))
        after = a.record()
        for name, accepted, msg in results:
            always_refused = name in ("volume create", "volume resume-enrollment", "check --deep", "volume inspect")
            want = False if (expect_refused or always_refused) else True
            mark = "ok " if accepted == want else "BAD"
            print(f"  [{mark}] {label}: {name}: {'ACCEPTED' if accepted else 'refused'}: {msg}", flush=True)
            MSG[f"{name}: {'ACCEPTED' if accepted else 'refused'}: {msg[:150]}"] += 1
            if accepted != want:
                fail(f"{label}: {name} {'accepted' if accepted else 'refused'}: {msg}")
        if expect_refused and after != before:
            fail(f"{label}: the refused commands changed the authority: {before} -> {after}")
        if own_backing is not None and expect_refused:
            # the authority these commands were pointed at must still accept its own backing
            a.vol.kill9()
            shutil.rmtree(b); shutil.copytree(own_backing[1], b)
            try:
                a.vol.start(timeout=60)
                h = mk.connect(a.vol.sock)
                dd = Data(); dd.ver = own_backing[3]
                if dd.verify(h, f"{label}: afterwards, the authority's own backing"):
                    print(f"  [ok ] {label}: afterwards the authority still accepts its own backing with the right data")
                h.shutdown(); a.vol.term(timeout=60)
            except RuntimeError as e:
                fail(f"{label}: afterwards the authority refuses its own backing: {last_line(str(e))}")
        a.stop()
        for p in (b, w, snapdir, a.vol.dir):
            shutil.rmtree(p, ignore_errors=True)

    attack("control: current backing, current authority", cur[1], cur[2], expect_refused=False)
    for g, (rec, b, w, ver) in enumerate(saves[:-1]):
        attack(f"backing root of state {g} (fence {rec['fence']}) under the current authority (fence {cur[0]['fence']})", b, cur[2], own_backing=cur)
    for g, (rec, b, w, ver) in enumerate(saves[:-1]):
        attack(f"authority state of state {g} (fence {rec['fence']}) under the current backing root", cur[1], w)
    # another volume: its own authority (same CA, same server name), same key and geometry
    o = Site("ro", os.path.join(TB, "other"), os.path.join(TW, "other-state"), like=s)
    o.auth.identity = "7e5c0a11-0000-4000-8000-00000000beef"
    os.makedirs(o.root)
    o.auth.init(); o.auth.start()
    r = o.vol.create(check=False)
    if r.returncode != 0:
        raise RuntimeError(r.stderr)
    o.vol.start(timeout=60); h = mk.connect(o.vol.sock); od = Data(); od.write(h, 3); h.shutdown(); o.vol.term(timeout=60)
    orec = o.record(); o.auth.kill9()
    ob, ow = os.path.join(TB, "save-other-b"), os.path.join(TW, "save-other-w")
    shutil.copytree(o.root, ob); shutil.copytree(o.state, ow)
    other = (orec, ob, ow, dict(od.ver))
    attack("this volume's backing root under another volume's authority", cur[1], ow, own_backing=other)
    attack("another volume's backing root under this volume's authority", ob, cur[2], own_backing=cur)
    o.stop(); s.stop()
    for k, c in sorted(MSG.items()):
        print(f"  {c:3d}  {k}")
    MSG.clear()


def part_conc():
    print("== conc")
    s = Site("rc", os.path.join(TB, "cvolume"), os.path.join(TW, "cstate"))
    os.makedirs(s.root)
    s.auth.init(); s.auth.start()
    r = s.vol.create(check=False)
    if r.returncode != 0:
        raise RuntimeError(r.stderr)
    s2 = mk.Vol("rc2", discard=True, backing_dir=s.root, key_file=s.vol.key, size="1MiB", ckpt_reserve="256KiB", reserve="64KiB",
                extra_backing=s.auth.remote_section(CAP, "writer"))
    d = Data()
    snapn = [0]

    def competitor(with_admin):
        k = rng.choice(["gc", "gc", "witness", "snapshot", "daemon2", "check", "inspect", "create", "wi"] + (["takeover"] if with_admin else []))
        if k == "gc":
            return "volume gc", [mk.MAKI, "volume", "gc", s.vol.cfg]
        if k == "witness":
            return "volume witness", [mk.MAKI, "volume", "witness", s.vol.cfg]
        if k == "snapshot":
            snapn[0] += 1
            return "volume snapshot", [mk.MAKI, "volume", "snapshot", s.vol.cfg, os.path.join(TB, f"csnap-{snapn[0]}")]
        if k == "daemon2":
            try:
                os.unlink(s2.sock)
            except OSError:
                pass
            return "second daemon", ["nbdkit", "--foreground", "-U", s2.sock, mk.PLUGIN, f"config={s2.cfg}"]
        if k == "check":
            return "check --deep", [mk.MAKI, "check", s.vol.cfg, "--deep"]
        if k == "inspect":
            return "volume inspect", [mk.MAKI, "volume", "inspect", s.vol.cfg]
        if k == "create":
            return "volume create", [mk.MAKI, "volume", "create", s.vol.cfg, "--discard"]
        if k == "wi":
            return "maki-witness inspect", [mk.WITNESS, "inspect", s.auth.client_config(os.path.join(s.vol.dir, "wi.toml"))]
        try:
            rec = s.record()
            return "volume takeover", [mk.MAKI, "volume", "takeover", s.admin, str(rec["fence"]), rw.root_hex(rec)]
        except Exception:
            return "volume witness", [mk.MAKI, "volume", "witness", s.vol.cfg]

    # ---- phase A: a live daemon
    s.vol.start(timeout=60)
    h = mk.connect(s.vol.sock)
    d.write(h, 10)
    for i in range(A.rounds):
        name, cmd = competitor(False)
        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        killed = False
        try:
            out, err = p.communicate(timeout=rng.choice([0.003, 0.02, 0.1, 20, 20, 20]))
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL); out, err = p.communicate(); killed = True
        try:
            d.write(h, 2)
        except nbd.Error as e:
            fail(f"phase A round {i}: the daemon's I/O failed after {name}{' (killed)' if killed else ''}: {e}; log {s.vol.read_log()[-400:]}")
            break
        if not killed:
            MSG[f"A {name}: rc={p.returncode}: {(last_line(err) or last_line(out))[:170]}"] += 1
            if name not in ("volume gc", "volume witness", "maki-witness inspect") and p.returncode == 0:
                fail(f"phase A: {name} succeeded beside a live writer: {out[-200:]} {err[-200:]}")
            if name in ("volume gc", "volume witness", "maki-witness inspect") and p.returncode != 0:
                MSG[f"A NOTE {name} failed beside a live writer: {last_line(err)[:170]}"] += 1
            if "panicked" in err:
                fail(f"phase A: {name} panicked: {err[-300:]}")
        subprocess.run(["pkill", "-9", "-f", s2.cfg], stderr=subprocess.DEVNULL)
    d.verify(h, "phase A, live daemon")
    rec = s.record()
    if rec["phase"] != "active":
        fail(f"phase A: the authority is {rec['phase']} while the daemon runs")
    print(f"phase A done; namespaces {s.namespaces()}")
    try:
        h.shutdown()
    except nbd.Error:
        pass
    s.vol.kill9()

    # ---- phase B: no daemon; racing, killed commands
    worst = 0
    for i in range(A.rounds):
        procs = []
        for _ in range(rng.randint(1, 3)):
            name, cmd = competitor(True)
            p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
            procs.append((name, p, time.monotonic() + rng.choice([0.0, 0.005, 0.02, 0.05, 0.1, 0.2, 0.5, 20])))
            time.sleep(rng.choice([0, 0, 0.01, 0.05]))
        for name, p, when in procs:
            try:
                out, err = p.communicate(timeout=max(0.001, when - time.monotonic()))
                if name != "second daemon":
                    MSG[f"B {name}: rc={p.returncode}: {(last_line(err) or last_line(out))[:150]}"] += 1
                if "panicked" in err:
                    fail(f"phase B round {i}: {name} panicked: {err[-300:]}")
                if name == "volume create" and p.returncode == 0:
                    fail(f"phase B round {i}: volume create succeeded on an existing volume")
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL); p.communicate()
        subprocess.run(["pkill", "-9", "-f", s2.cfg], stderr=subprocess.DEVNULL)
        if rng.random() < 0.15:
            s.auth.kill9(); s.auth.start()      # the authority server restarts (state kept)
        worst = max(worst, len(s.namespaces()))
        if i % 4 == 3 or i == A.rounds - 1:
            ok, text = s.recover()
            if not ok:
                fail(f"phase B round {i}: the documented procedure fails: {text}; namespaces {s.namespaces()}; free {shutil.disk_usage(TB).free >> 20} MiB")
                break
            try:
                s.vol.start(timeout=60)
            except RuntimeError as e:
                fail(f"phase B round {i}: the daemon does not start after the procedure: {last_line(str(e))}; namespaces {s.namespaces()}")
                break
            h = mk.connect(s.vol.sock)
            if not d.verify(h, f"phase B round {i}"):
                break
            d.write(h, 3)
            h.shutdown()
            if rng.random() < 0.5:
                s.vol.kill9()
            elif s.vol.term(timeout=60) != 0:
                fail(f"phase B round {i}: SIGTERM stop failed: {s.vol.read_log()[-300:]}")
    # in the end: one clean start, one gc; what is left in the root?
    ok, text = s.recover()
    if ok:
        g = s.maki("volume", "gc", s.vol.cfg)
        left = s.namespaces()
        print(f"phase B done; most namespaces at once {worst}; after recovery and gc: {left}; gc: {g.stdout.strip()[:600]} {g.stderr.strip()[:200]}")
        full = [n for n in left if os.path.exists(os.path.join(s.root, n, "rollback.arena"))]
        if len(full) > 1:
            fail(f"phase B: {len(full)} full-size namespaces remain after a recovery and a GC pass with no process alive: {full}")
    else:
        fail(f"final: the documented procedure fails: {text}")
    for k, c in sorted(MSG.items()):
        print(f"  {c:4d}  {k}")
    MSG.clear()
    s.stop()


def part_restore():
    print("== restore")
    s = Site("rr", os.path.join(TB, "rvolume"), os.path.join(TW, "rstate"))
    os.makedirs(s.root)
    s.auth.init(); s.auth.start()
    r = s.vol.create(check=False)
    if r.returncode != 0:
        raise RuntimeError(r.stderr)
    d = Data()
    s.vol.start(timeout=60); h = mk.connect(s.vol.sock); d.write(h, 8); h.shutdown(); s.vol.term(timeout=60)
    snap = os.path.join(TB, "rsnap")
    r = s.maki("volume", "snapshot", s.vol.cfg, snap)
    if r.returncode != 0:
        fail(f"snapshot failed: {r.stderr[-300:]}"); return
    desc = json.loads(r.stdout)
    old = dict(d.ver)
    s.vol.start(timeout=60); h = mk.connect(s.vol.sock); d.write(h, 8); h.shutdown(); s.vol.term(timeout=60)
    newer = dict(d.ver)
    rec = s.record()
    pre_b, pre_w = os.path.join(TB, "pre-restore-b"), os.path.join(TW, "pre-restore-w")
    s.auth.kill9(); shutil.copytree(s.root, pre_b); shutil.copytree(s.state, pre_w); s.auth.start()
    # wrong approvals first
    bad_root = "00" * 32
    for label, args in (("wrong approved snapshot root", [snap, str(rec["fence"]), rw.root_hex(rec), bad_root]),
                        ("wrong current root", [snap, str(rec["fence"]), bad_root, bytes(desc["anchor"]["root"]).hex()]),
                        ("stale fence", [snap, str(rec["fence"] - 1), rw.root_hex(rec), bytes(desc["anchor"]["root"]).hex()])):
        r = s.maki("volume", "restore", s.admin, *args)
        print(f"  restore with {label}: rc={r.returncode} {last_line(r.stderr)}")
        if r.returncode == 0:
            fail(f"restore with {label} succeeded")
    r = s.maki("volume", "restore", s.vol.cfg, snap, str(rec["fence"]), rw.root_hex(rec), bytes(desc["anchor"]["root"]).hex())
    print(f"  restore with the writer certificate: rc={r.returncode} {last_line(r.stderr)}")
    if r.returncode == 0:
        fail("restore with the writer certificate succeeded")
    if s.record() != rec:
        fail(f"refused restores changed the authority: {rec} -> {s.record()}")
    r = s.maki("volume", "restore", s.admin, snap, str(rec["fence"]), rw.root_hex(rec), bytes(desc["anchor"]["root"]).hex())
    print(f"  restore: rc={r.returncode} {last_line(r.stderr)} {r.stdout.strip()[:200]}")
    if r.returncode != 0:
        fail(f"restore failed: {r.stderr[-300:]}"); return
    after = s.record()
    if after["current"]["anchor"]["generation"] != rec["current"]["anchor"]["generation"] + 1 or after["current"]["epoch"] != rec["current"]["epoch"] + 1:
        fail(f"restore did not advance generation and epoch exactly once: {rec['current']} -> {after['current']}")
    s.vol.start(timeout=60); h = mk.connect(s.vol.sock)
    dd = Data(); dd.ver = old
    dd.verify(h, "after the restore (snapshot contents)")
    h.shutdown(); s.vol.term(timeout=60)
    print(f"  after restore: namespaces {s.namespaces()}")
    # the pre-restore backing root (newer data) put back under the restored authority
    s.auth.kill9()
    b2 = os.path.join(TB, "replay-b"); shutil.copytree(pre_b, b2)
    a = Site("rrb", b2, s.state, like=s)
    a.auth.start()
    rec2 = a.record()
    for name, args in (("daemon", None), ("volume takeover", ["volume", "takeover", a.admin, str(rec2["fence"]), rw.root_hex(rec2)]), ("volume gc", ["volume", "gc", a.vol.cfg])):
        if args is None:
            try:
                a.vol.start(timeout=60); a.vol.kill9()
                fail("the pre-restore backing root was accepted by the daemon after the restore")
            except RuntimeError as e:
                print(f"  pre-restore backing under the restored authority: daemon refused: {last_line(str(e))}")
        else:
            r = a.maki(*args)
            print(f"  pre-restore backing under the restored authority: {name}: rc={r.returncode} {last_line(r.stderr)}")
            if r.returncode == 0:
                fail(f"pre-restore backing under the restored authority: {name} succeeded")
    a.stop(); s.stop()


mount()
try:
    for part in A.parts:
        {"attacks": part_attacks, "conc": part_conc, "restore": part_restore}[part]()
finally:
    subprocess.run(["pkill", "-9", "-f", TB], stderr=subprocess.DEVNULL)
    subprocess.run(["pkill", "-9", "-f", "/tmp/a9rn/(ra|rc|rc2|ro|rr|rrb|a[0-9]+|a[0-9]+r)-"], stderr=subprocess.DEVNULL)  # remote_ops2: do not match rrpl*/img* of concurrent sweeps
    time.sleep(0.3)
    for t in (TB, TW):
        subprocess.run(["umount", "-l", t])
        try:
            os.rmdir(t)
        except OSError:
            pass
    if not A.keep:
        for n in os.listdir(mk.BASE):
            if n.startswith(("ra-", "a", "ro-", "rc-", "rc2-", "rr-", "rrb-")) and not n.startswith(("rpl", "rrpl", "img")):
                shutil.rmtree(os.path.join(mk.BASE, n), ignore_errors=True)
print(f"remote_ops parts {A.parts} seed {A.seed}: {'FAIL' if FAILS else 'ok'}")
for f in FAILS[:25]:
    print("  " + f[:900])
sys.exit(1 if FAILS else 0)
