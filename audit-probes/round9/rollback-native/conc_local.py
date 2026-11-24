#!/usr/bin/python3.12
"""Round 9 rollback-native: processes competing for one LOCAL rollback-protected pair.

Phase A: the daemon serves verified FUA I/O while short-lived `maki check`, `check --deep`,
`volume inspect`, `volume create` and a second daemon (same backing and witness, its own
sockets) are started against the same pair and killed at random moments. The daemon must not
notice; every competitor must fail with a message that says the volume is in use.
Phase B: no daemon. The same commands race each other, each killed -9 at a random moment;
after every round a daemon start must succeed and serve the acknowledged data, and
`check --deep` must pass. Lock files must never block the next start.

usage: conc_local.py [--seed N] [--rounds 150]
"""
import os, sys, subprocess, shutil, random, time, signal, argparse, collections
import mk9 as mk
import nbd

P = argparse.ArgumentParser()
P.add_argument("--seed", type=int, default=1)
P.add_argument("--rounds", type=int, default=150)
A = P.parse_args()
rng = random.Random(A.seed)
TB, TW = f"/tmp/a9rn-cl-b-{os.getpid()}", f"/tmp/a9rn-cl-w-{os.getpid()}"
FAILS = []
MSG = collections.Counter()


def fail(m):
    FAILS.append(m); print("FAIL " + m, flush=True)


for t, size in ((TB, "200m"), (TW, "16m")):
    os.makedirs(t, exist_ok=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", f"size={size},mode=0700", "tmpfs", t], check=True)
v = v2 = None
try:
    root, wroot = os.path.join(TB, "volume"), os.path.join(TW, "witness")
    os.makedirs(root); os.makedirs(wroot)
    rb = f'[backing.rollback_protection]\nwitness_root = "{wroot}"\ncapacity = "8MiB"\n'
    kw = dict(discard=True, backing_dir=root, size="2MiB", ckpt_reserve="256KiB", reserve="64KiB", extra_backing=rb)
    v = mk.Vol("cl", **kw)
    v.create()
    v2 = mk.Vol("cl2", key_file=v.key, **kw)      # the same pair, other sockets
    ver = {}

    def write_some(h, n):
        for _ in range(n):
            u = rng.randrange(0, 128)
            val = ver.get(u, 0) + 1 + rng.randrange(1000) * 1000
            h.pwrite(mk.pattern(u * 4096, 4096, val, A.seed), u * 4096, nbd.CMD_FLAG_FUA)
            ver[u] = val

    def verify(h, what):
        for u, val in ver.items():
            if bytes(h.pread(4096, u * 4096)) != mk.pattern(u * 4096, 4096, val, A.seed):
                fail(f"{what}: unit {u} does not hold acknowledged version {val}")
                return False
        return True

    def competitor():
        k = rng.randrange(5)
        if k == 0:
            return "check", [mk.MAKI, "check", v.cfg]
        if k == 1:
            return "check --deep", [mk.MAKI, "check", v.cfg, "--deep"]
        if k == 2:
            return "volume inspect", [mk.MAKI, "volume", "inspect", v.cfg]
        if k == 3:
            return "volume create", [mk.MAKI, "volume", "create", v.cfg, "--discard"]
        return "second daemon", ["nbdkit", "--foreground", "-U", v2.sock, mk.PLUGIN, f"config={v2.cfg}"]

    def run_competitor(kill_after):
        name, cmd = competitor()
        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        killed = False
        try:
            out, err = p.communicate(timeout=kill_after)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            out, err = p.communicate()
            killed = True
        return name, p.returncode, killed, (err.strip() or out.strip())

    # ---- phase A
    v.start()
    h = mk.connect(v.sock)
    write_some(h, 20)
    for i in range(A.rounds):
        name, rc, killed, text = run_competitor(rng.choice([0.002, 0.01, 0.05, 5.0, 5.0, 5.0]))
        write_some(h, 2)
        if not killed:
            last = text.splitlines()[-1][:200] if text else ""
            MSG[f"A {name}: rc={rc}: {last}"] += 1
            if rc == 0:
                fail(f"phase A: {name} succeeded against a pair the daemon holds: {text[-300:]}")
            if "panicked" in text:
                fail(f"phase A: {name} panicked: {text[-300:]}")
        if v.proc.poll() is not None:
            fail(f"phase A round {i}: the daemon died (rc {v.proc.returncode}) after {name}: {v.read_log()[-500:]}")
            break
    verify(h, "phase A, live daemon")
    st = v.maki("status", v.cfg)
    if '"degraded_reason": null' not in st.stdout:
        fail(f"phase A: daemon status after the competitors: {st.stdout[:400]} {st.stderr[:200]}")
    v.kill9()
    print(f"phase A done: {A.rounds} competitors, {len(ver)} units verified")

    # ---- phase B
    for i in range(A.rounds):
        procs = []
        for _ in range(rng.randint(1, 4)):
            name, cmd = competitor()
            p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
            procs.append((name, p, time.monotonic() + rng.choice([0.0, 0.003, 0.01, 0.03, 0.1, 1.0, 5.0])))
        for name, p, when in procs:
            try:
                out, err = p.communicate(timeout=max(0.001, when - time.monotonic()))
                text = (err.strip() or out.strip())
                last = text.splitlines()[-1][:160] if text else ""
                if name != "second daemon":
                    MSG[f"B {name}: rc={p.returncode}: {last}"] += 1
                if "panicked" in text:
                    fail(f"phase B round {i}: {name} panicked: {text[-300:]}")
                if name == "volume create" and p.returncode == 0:
                    fail(f"phase B round {i}: volume create succeeded on an existing volume")
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.communicate()
        subprocess.run(["pkill", "-9", "-f", v2.cfg], stderr=subprocess.DEVNULL)
        if i % 5 == 4 or i == A.rounds - 1:
            try:
                v.start(timeout=30)
            except RuntimeError as e:
                fail(f"phase B round {i}: the daemon does not start after the competitors were killed: {str(e)[-400:]}")
                break
            h = mk.connect(v.sock)
            if not verify(h, f"phase B round {i}"):
                break
            write_some(h, 3)
            h.shutdown()
            if rng.random() < 0.5:
                v.kill9()
            else:
                v.term()
            r = v.maki("check", v.cfg, "--deep")
            if r.returncode != 0:
                fail(f"phase B round {i}: check --deep fails after the daemon served the data: {r.stdout[-300:]} {r.stderr[-300:]}")
                break
    print(f"phase B done: {A.rounds} rounds")
    for k, n in sorted(MSG.items()):
        print(f"  {n:4d}  {k}")
finally:
    subprocess.run(["pkill", "-9", "-f", TB], stderr=subprocess.DEVNULL)
    for x in (v, v2):
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
print(f"conc_local seed {A.seed}: {'FAIL' if FAILS else 'ok'}")
for f in FAILS[:20]:
    print("  " + f[:700])
sys.exit(1 if FAILS else 0)
