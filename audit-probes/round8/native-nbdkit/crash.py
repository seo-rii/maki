#!/usr/bin/python3.12
"""Randomized workload over the real plugin with kill -9 / SIGTERM at random
moments, restart through the plugin's recovery, and a per-sector oracle.

usage: crash.py --seed N [--cycles C] [--profile v2|v3|v3cache|v2tight|...]
                [--preload SPEC] [--term-prob P] [--keep]

Oracle (NBD contract only, per 512-byte sector):
  dur[s]    set of versions allowed as "what a power cut may leave at least"
  cands[s]  ordered (ackno, version, definite) written after that point
A write/zero/trim acknowledged with FUA, or acknowledged before a FLUSH was
*sent* that was itself acknowledged, is durable. Requests in flight at the
kill, and requests that failed, are indefinite candidates. After a kill each
sector must hold a version from dur ∪ cands; after a clean exit (status 0) or
during the run it must hold the newest definite candidate (or an indefinite
one after it). Sector contents name their own sector, version and seed, so
another offset's data or a torn sector is recognised.
"""
import sys, os, random, time, signal, subprocess, struct, argparse, traceback, errno
import nbd
import mk

P = argparse.ArgumentParser()
P.add_argument("--seed", type=int, required=True)
P.add_argument("--cycles", type=int, default=30)
P.add_argument("--profile", default=None)
P.add_argument("--term-prob", type=float, default=0.15)
P.add_argument("--inflight", type=int, default=24)
P.add_argument("--preload", default=None, help="fault spec passed to the LD_PRELOAD shim (see faultfs.c)")
P.add_argument("--base", default=None)
P.add_argument("--keep", action="store_true")
P.add_argument("--quiet", action="store_true")
P.add_argument("--max-run", type=float, default=1.5)
P.add_argument("--tmpfs", default=None, help="put the volume on a fresh tmpfs of this size (e.g. 16m) with a ballast file")
P.add_argument("--free", type=int, default=0, help="KiB left free on the tmpfs after the ballast")
P.add_argument("--reserve", default="0B")
P.add_argument("--ckpt-reserve", default=None)
P.add_argument("--allow-errors", action="store_true", help="request errors are expected (full filesystem, injected faults)")
P.add_argument("--filters", default="", help="comma-separated nbdkit filters, outermost first")
P.add_argument("--filter-params", default="", help="space-separated key=value parameters for the filters")
P.add_argument("--threads", type=int, default=None)
P.add_argument("--recovery-kills", type=float, default=0.3, help="probability per cycle of killing the daemon again during its recovery (1-3 times)")
P.add_argument("--plant", type=float, default=0.0, help="harness self-test: forget this fraction of acknowledged FUA writes in the oracle; the run must then FAIL")
A = P.parse_args()

SEED = A.seed
rng = random.Random(SEED)
PROFILES = {
    "v2": dict(discard=False),
    "v3": dict(discard=True),
    "v3cache": dict(discard=True, cache='mode = "read"\nmax_bytes = "64KiB"\nttl = "1s"'),
    "v2cache": dict(discard=False, cache='mode = "read"\nmax_bytes = "64KiB"\nttl = "1s"'),
    "v2tight": dict(discard=False, extra_limits='max_overlay_bytes = "160KiB"\nmax_journal_pending_bytes = "16KiB"\nmax_plaintext_bytes = "160KiB"\nmax_active_callbacks = 3'),
    "v3tight": dict(discard=True, extra_limits='max_overlay_bytes = "160KiB"\nmax_journal_pending_bytes = "16KiB"\nmax_plaintext_bytes = "160KiB"\nmax_active_callbacks = 3'),
    "v3unit512": dict(discard=True, unit=512, shard="16KiB", size="1MiB"),
    "v3blk4k": dict(discard=True, block=4096),
    "v2unit16k": dict(discard=False, unit=16384, shard="256KiB", jmax="1MiB"),
    "v3unit16k": dict(discard=True, unit=16384, shard="256KiB", jmax="1MiB"),
    "v3unit1k": dict(discard=True, unit=1024, shard="32KiB", size="2MiB"),
}
profile = A.profile or rng.choice(["v2", "v3", "v3cache", "v2tight", "v3tight", "v2cache"])
cfg = dict(PROFILES[profile])
DISCARD = cfg.pop("discard")
UNIT = cfg.get("unit", 4096)
BLOCK = cfg.get("block", 512)
SPB = BLOCK // 512

cfg["reserve"] = A.reserve
if A.ckpt_reserve:
    cfg["ckpt_reserve"] = A.ckpt_reserve
TMPFS = None
if A.tmpfs:
    TMPFS = f"/tmp/a8n-tmpfs-{SEED}-{os.getpid()}"
    os.makedirs(TMPFS, exist_ok=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", f"size={A.tmpfs},mode=0700", "tmpfs", TMPFS], check=True)
    if not A.free:
        A.free = rng.choice([300, 600, 1000, 1536, 2500])
ERRNOS = {}


def ballast(on):
    """Fill the tmpfs so that only --free KiB remain (on), or release it."""
    path = os.path.join(TMPFS, "ballast")
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    if on:
        st = os.statvfs(TMPFS)
        spare = st.f_bavail * st.f_frsize - A.free * 1024
        if spare > 0:
            fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
            os.posix_fallocate(fd, 0, spare)
            os.close(fd)


FAILS = []
STATS = dict(ops=0, acked=0, errors=0, kills=0, terms=0, verified_sectors=0, flushes=0, inflight_at_kill=0,
             recovered_new=0, checkpoints=0)


def fail(msg):
    FAILS.append(msg)
    print("FAIL " + msg, flush=True)


def log(msg):
    if not A.quiet:
        print(msg, flush=True)


def decode(buf, s):
    """Version held by one 512-byte sector, or a string describing garbage."""
    if buf == ZERO:
        return 0
    sec, ver, seed = struct.unpack_from("<QQQ", buf)
    if sec == s and seed == SEED and mk.pattern(s * 512, 512, ver, SEED) == buf:
        return ver
    return "foreign/garbage: " + mk.describe(bytes(buf))


ZERO = bytes(512)


class Oracle:
    def __init__(self, nsect):
        self.n = nsect
        self.dur = [{0} for _ in range(nsect)]
        self.cands = {}
        self.ackno = 0

    def add(self, effects, definite, fua):
        self.ackno += 1
        for s, ver in effects:
            if definite and fua:
                self.dur[s] = {ver}
                self.cands.pop(s, None)
            else:
                self.cands.setdefault(s, []).append((self.ackno, ver, definite))

    def flushed(self, mark):
        for s in list(self.cands):
            lst = self.cands[s]
            covered = [c for c in lst if c[0] <= mark]
            if not covered:
                continue
            rest = [c for c in lst if c[0] > mark]
            j = max((i for i, c in enumerate(covered) if c[2]), default=None)
            if j is None:
                self.dur[s] = self.dur[s] | {c[1] for c in covered}
            else:
                self.dur[s] = {covered[j][1]} | {c[1] for c in covered[j + 1:]}
            if rest:
                self.cands[s] = rest
            else:
                del self.cands[s]

    def current(self, s):
        lst = self.cands.get(s)
        if not lst:
            return self.dur[s]
        j = max((i for i, c in enumerate(lst) if c[2]), default=None)
        if j is None:
            return self.dur[s] | {c[1] for c in lst}
        return {lst[j][1]} | {c[1] for c in lst[j + 1:]}

    def after_crash(self, s):
        lst = self.cands.get(s)
        if not lst:
            return self.dur[s]
        return self.dur[s] | {c[1] for c in lst}

    def resolve(self, s, ver):
        self.dur[s] = {ver}
        self.cands.pop(s, None)


class Run:
    def __init__(self):
        self.vol = mk.Vol(f"crash{SEED}", discard=DISCARD, base=A.base,
                          backing_dir=os.path.join(TMPFS, "volume") if TMPFS else None, **cfg)
        self.vol.create()
        self.env = {}
        if A.preload:
            self.env = {"LD_PRELOAD": os.path.join(mk.HERE, "faultfs.so"), "FAULTFS": A.preload,
                        "FAULTFS_ROOT": self.vol.root}
        self.size = None
        self.oracle = None
        self.ver = 0
        self.h = None

    def start(self):
        params = A.filter_params.split()
        self.trigger = os.path.join(self.vol.dir, "inject")
        if "error" in A.filters.split(","):
            params.append(f"error-file={self.trigger}")   # nbdkit injects only while this file exists
            if os.path.exists(self.trigger):
                os.unlink(self.trigger)
        self.vol.start(env=self.env, filters=[f for f in A.filters.split(",") if f],
                       filter_params=params, threads=A.threads)

    def connect(self):
        last = None
        for _ in range(200):
            h = nbd.NBD()
            h.set_strict_mode(0)
            try:
                h.connect_unix(self.vol.sock)
                self.h = h
                if self.size is None:
                    self.size = h.get_size()
                    self.oracle = Oracle(self.size // 512)
                return
            except nbd.Error as e:
                last = e
                time.sleep(0.02)
        raise RuntimeError(f"cannot connect: {last}")

    # ---- verification ---------------------------------------------------
    def verify(self, rule, what):
        """rule: 'crash' or 'current'. Resolves the oracle to what is there."""
        o = self.oracle
        bad = 0
        chunk = rng.choice([65536, 1 << 20, 196608 + BLOCK * 3, self.size])
        pos = 0
        newer = 0
        while pos < self.size:
            n = min(chunk, self.size - pos)
            try:
                got = bytes(self.h.pread(n, pos))
            except nbd.Error as e:
                fail(f"{what}: read {pos}+{n} failed: {e}")
                return False
            for i in range(0, n, 512):
                s = (pos + i) // 512
                v = decode(got[i:i + 512], s)
                allowed = o.after_crash(s) if rule == "crash" else o.current(s)
                if v not in allowed:
                    bad += 1
                    if bad <= 5:
                        fail(f"{what}: sector {s} (offset {s * 512}, unit {s * 512 // UNIT}) holds {v!r}; allowed versions {sorted(allowed)} "
                             f"(dur={sorted(o.dur[s])} cands={o.cands.get(s)})")
                else:
                    if v not in o.dur[s]:
                        newer += 1
                    o.resolve(s, v)
            pos += n
        STATS["verified_sectors"] += self.size // 512
        STATS["recovered_new"] += newer
        if bad:
            fail(f"{what}: {bad} bad sector(s) in total")
        return bad == 0

    # ---- workload --------------------------------------------------------
    def pick_range(self, kind):
        size = self.size
        r = rng.random()
        if r < 0.20:
            ln = BLOCK
        elif r < 0.45:
            ln = BLOCK * rng.randint(1, max(1, UNIT // BLOCK))
        elif r < 0.65:
            ln = UNIT * rng.randint(1, 3)
        elif r < 0.92:
            ln = BLOCK * rng.randint(1, 65536 // BLOCK)
        else:
            ln = BLOCK * rng.randint(65536 // BLOCK, 4 * 65536 // BLOCK)
        if kind in ("trim", "zero") and rng.random() < 0.3:
            ln = UNIT * rng.randint(1, 64)
        hot = 6 * 65536
        span = hot if rng.random() < 0.75 else size
        ln = min(ln, span)
        if rng.random() < 0.5:
            off = rng.randrange(0, (span - ln) // UNIT + 1) * UNIT
        else:
            off = rng.randrange(0, (span - ln) // BLOCK + 1) * BLOCK
        if rng.random() < 0.05:
            off = size - ln  # touch the end of the export
        return off, ln

    def workload(self, budget_ops, budget_time, mode):
        """Runs until the budget, then kills (mode 'kill') or SIGTERMs
        (mode 'term') the server with requests still in flight."""
        h, o = self.h, self.oracle
        busy = bytearray(o.n)
        inflight = {}
        done = []
        counter = [0]
        can_trim = h.can_trim()

        def submit():
            kinds = ["write"] * 55 + ["zero"] * 10 + ["flush"] * 8 + ["read"] * 17 + (["trim"] * 10 if can_trim else [])
            kind = rng.choice(kinds)
            counter[0] += 1
            oid = counter[0]
            if kind == "flush":
                op = dict(kind=kind, mark=o.ackno, sectors=None)
                inflight[oid] = op
                h.aio_flush(lambda e, oid=oid: done.append((oid, e.value)) or 1, 0)
                return True
            for _ in range(8):
                off, ln = self.pick_range(kind)
                a, b = off // 512, (off + ln) // 512
                if not any(busy[a:b]):
                    break
            else:
                return False
            busy[a:b] = b"\x01" * (b - a)
            op = dict(kind=kind, off=off, ln=ln, sectors=(a, b), fua=False, effects=[])
            cb = lambda e, oid=oid: done.append((oid, e.value)) or 1
            if kind == "read":
                op["buf"] = nbd.Buffer(ln)
                h.aio_pread(op["buf"], off, cb, 0)
            elif kind == "write":
                self.ver += 1
                op["fua"] = rng.random() < 0.2
                op["effects"] = [(s, self.ver) for s in range(a, b)]
                h.aio_pwrite(mk.pattern(off, ln, self.ver, SEED), off, cb, nbd.CMD_FLAG_FUA if op["fua"] else 0)
            elif kind == "zero":
                op["fua"] = rng.random() < 0.2
                flags = (nbd.CMD_FLAG_FUA if op["fua"] else 0) | (nbd.CMD_FLAG_NO_HOLE if rng.random() < 0.5 else 0)
                op["effects"] = [(s, 0) for s in range(a, b)]
                h.aio_zero(ln, off, cb, flags)
            elif kind == "trim":
                op["fua"] = rng.random() < 0.2
                ua = -(-off // UNIT) * UNIT
                ub = (off + ln) // UNIT * UNIT
                op["effects"] = [(s, 0) for s in range(ua // 512, ub // 512)] if ub > ua else []
                h.aio_trim(ln, off, cb, nbd.CMD_FLAG_FUA if op["fua"] else 0)
            inflight[oid] = op
            return True

        def complete(oid, err, dead):
            op = inflight.pop(oid)
            STATS["ops"] += 1
            if op["kind"] == "flush":
                if err == 0:
                    STATS["flushes"] += 1
                    o.flushed(op["mark"])
                elif not dead:
                    STATS["errors"] += 1
                    self.on_error(op, err)
                return
            a, b = op["sectors"]
            busy[a:b] = bytes(b - a)
            if op["kind"] == "read":
                if err == 0:
                    got = op["buf"].to_bytearray()
                    for i, s in enumerate(range(a, b)):
                        v = decode(bytes(got[i * 512:(i + 1) * 512]), s)
                        if v not in o.current(s):
                            fail(f"live read: sector {s} (offset {s * 512}) holds {v!r}; allowed {sorted(o.current(s))} "
                                 f"dur={sorted(o.dur[s])} cands={o.cands.get(s)}")
                            break
                elif not dead:
                    STATS["errors"] += 1
                    self.on_error(op, err)
                return
            if err == 0:
                STATS["acked"] += 1
                if A.plant and op["fua"] and op["kind"] == "write" and rng.random() < A.plant:
                    return  # planted oracle hole (self-test)
                o.add(op["effects"], True, op["fua"])
            else:
                o.add(op["effects"], False, False)
                if dead:
                    STATS["inflight_at_kill"] += 1
                else:
                    STATS["errors"] += 1
                    self.on_error(op, err)

        start = time.monotonic()
        completed = 0
        ckpt = None
        try:
            while completed < budget_ops and time.monotonic() - start < budget_time:
                while len(inflight) < A.inflight:
                    if not submit():
                        break
                if ckpt is None and rng.random() < 0.01:
                    ckpt = subprocess.Popen([mk.MAKI, "checkpoint", self.vol.cfg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    STATS["checkpoints"] += 1
                h.poll(100)
                while done:
                    oid, err = done.pop(0)
                    complete(oid, err, False)
                    completed += 1
        except nbd.Error as e:
            fail(f"connection failed during the workload before any kill: {e}")
        # stop the server with requests in flight
        if mode == "kill":
            os.killpg(self.vol.proc.pid, signal.SIGKILL)
            STATS["kills"] += 1
        else:
            self.vol.proc.send_signal(signal.SIGTERM)
            STATS["terms"] += 1
        deadline = time.monotonic() + 60
        while not (h.aio_is_dead() or h.aio_is_closed()) and time.monotonic() < deadline:
            try:
                h.poll(100)
            except nbd.Error:
                break
            if mode == "term" and not inflight and not done:
                # all replies drained; nbdkit waits for the client to go away
                try:
                    h.shutdown()
                except nbd.Error:
                    pass
                break
            while done:
                oid, err = done.pop(0)
                # A reply the server managed to send is a real outcome.
                complete(oid, err, err != 0)
        while done:
            oid, err = done.pop(0)
            complete(oid, err, err != 0)
        STATS["inflight_at_kill"] += len(inflight)
        for oid in list(inflight):
            op = inflight[oid]
            if op["kind"] not in ("flush", "read"):
                o.add(op["effects"], False, False)
            inflight.pop(oid)
        if ckpt is not None:
            try:
                ckpt.wait(30)
            except subprocess.TimeoutExpired:
                ckpt.kill()
                fail("maki checkpoint did not return within 30 s of the server stopping")
        if mode == "kill":
            self.vol.proc.wait()
            self.vol.notify.close()
            return None
        try:
            rc = self.vol.proc.wait(90)
        except subprocess.TimeoutExpired:
            fail("nbdkit did not exit within 90 s of SIGTERM")
            os.killpg(self.vol.proc.pid, signal.SIGKILL)
            self.vol.proc.wait()
            rc = None
        self.vol.notify.close()
        return rc

    def on_error(self, op, err):
        msg = f"request failed without a fault: {op['kind']} off={op.get('off')} len={op.get('ln')} errno={err} ({errno.errorcode.get(err)})"
        ERRNOS[(op["kind"], errno.errorcode.get(err, err))] = ERRNOS.get((op["kind"], errno.errorcode.get(err, err)), 0) + 1
        if A.allow_errors:
            return
        if A.preload:
            log("  (fault run) " + msg)
        else:
            fail(msg)


def main():
    run = Run()
    ok = True
    try:
        log(f"seed {SEED} profile {profile} dir {run.vol.dir}")
        if TMPFS:
            ballast(True)
        run.start()
        run.connect()
        mode_prev = None
        for cycle in range(A.cycles):
            mode = "term" if rng.random() < A.term_prob else "kill"
            budget_ops = rng.choice([3, 10, 30, 100, 300, 1000])
            budget_time = rng.uniform(0.02, A.max_run)
            relieved = False
            if TMPFS and cycle % 4 == 3:
                # space comes back while the daemon is running: writes must resume without a restart
                ballast(False)
                relieved = True
                time.sleep(0.3)
                budget_ops, budget_time = 300, 3.0
            before = (STATS["acked"], STATS["errors"])
            if "error" in A.filters.split(","):
                open(run.trigger, "w").close()
            rc = run.workload(budget_ops, budget_time, mode)
            if relieved:
                acked, errors = STATS["acked"] - before[0], STATS["errors"] - before[1]
                STATS["relieved_cycles"] = STATS.get("relieved_cycles", 0) + 1
                log(f"cycle {cycle}: space released before the workload: {acked} acknowledged, {errors} failed")
                if acked == 0 and errors > 20:
                    fail(f"cycle {cycle}: after space was released on the backing filesystem, no write succeeded ({errors} failed): {ERRNOS}; "
                         f"status: {run.vol.read_log()[-800:]}")
            logtxt = run.vol.read_log()
            if "panic" in logtxt.lower():
                fail(f"cycle {cycle}: panic in nbdkit log: " + [l for l in logtxt.splitlines() if "panic" in l.lower()][0][:400])
            unload_failed = "shutdown during unload failed" in logtxt
            if mode == "term":
                if unload_failed and A.allow_errors:
                    STATS["unload_failed"] = STATS.get("unload_failed", 0) + 1
                if rc != 0:
                    fail(f"cycle {cycle}: SIGTERM exit status {rc}; log tail: {logtxt[-600:]}")
                if unload_failed and not A.preload and not A.allow_errors:
                    fail(f"cycle {cycle}: unload reported a failed shutdown: {logtxt[-600:]}")
            if rng.random() < 0.15:
                r = run.vol.maki("check", run.vol.cfg, "--deep", timeout=120)
                if r.returncode != 0 and not A.preload and not A.allow_errors:
                    fail(f"cycle {cycle}: offline `maki check --deep` after {mode}: rc={r.returncode} {(r.stdout + r.stderr)[-500:]}")
            if rng.random() < A.recovery_kills:
                for _ in range(rng.randint(1, 3)):
                    run.vol.start(env=run.env, wait=False)
                    time.sleep(rng.choice([0.0, 0.005, 0.02, 0.05, 0.1, 0.2, 0.4]) * rng.random() * 2)
                    os.killpg(run.vol.proc.pid, signal.SIGKILL)
                    run.vol.proc.wait(); run.vol.notify.close()
                    STATS["recovery_kills"] = STATS.get("recovery_kills", 0) + 1
            try:
                run.start()
            except RuntimeError as e:
                if TMPFS:
                    STATS["restart_refused_full"] = STATS.get("restart_refused_full", 0) + 1
                    log(f"cycle {cycle}: restart refused on the full filesystem: {str(e)[-400:]}")
                    ballast(False)
                    try:
                        run.start()
                    except RuntimeError as e2:
                        fail(f"cycle {cycle}: volume does not recover after space was freed ({mode}): {str(e2)[-1500:]}")
                        ok = False
                        break
                elif A.preload:
                    log(f"cycle {cycle}: restart refused under faults: {str(e)[-300:]}")
                    # the fault spec applies to recovery too; retry without faults
                    saved, run.env = run.env, {}
                    try:
                        run.start()
                    except RuntimeError as e2:
                        fail(f"cycle {cycle}: volume does not recover even without faults after {mode}: {str(e2)[-1500:]}")
                        ok = False
                        break
                    run.env = saved
                else:
                    fail(f"cycle {cycle}: restart after {mode} failed: {str(e)[-1500:]}")
                    ok = False
                    break
            run.connect()
            rule = "current" if (mode == "term" and rc == 0 and not unload_failed) else "crash"
            good = run.verify(rule, f"cycle {cycle} after {mode} (rule {rule})")
            if not good:
                ok = False
                break
            if rng.random() < 0.25:
                # nothing written since: a second kill must not change anything
                os.killpg(run.vol.proc.pid, signal.SIGKILL)
                run.vol.proc.wait(); run.vol.notify.close()
                STATS["kills"] += 1
                run.start(); run.connect()
                if not run.verify("current", f"cycle {cycle} second restart with no writes in between"):
                    ok = False
                    break
            if TMPFS and not os.path.exists(os.path.join(TMPFS, "ballast")):
                ballast(True)
            log(f"cycle {cycle} {mode} ok; stats {STATS} errnos {ERRNOS}")
        run.vol.kill9()
        r = run.vol.maki("check", run.vol.cfg, "--deep", timeout=120)
        if r.returncode != 0 and not A.preload:
            fail(f"final offline `maki check --deep`: rc={r.returncode} {(r.stdout + r.stderr)[-500:]}")
    except Exception as e:
        fail(f"harness exception: {e!r}\n{traceback.format_exc()[-2000:]}")
        ok = False
    finally:
        if FAILS and not A.quiet:
            print(run.vol.all_logs()[-4000:])
        if A.keep or FAILS:
            print(f"kept {run.vol.dir}")
            try:
                run.vol.kill9()
            except Exception:
                pass
        else:
            run.vol.cleanup()
        if TMPFS:
            try:
                run.vol.kill9()
            except Exception:
                pass
            if FAILS:
                keep = f"/tmp/a8n/kept-tmpfs-{SEED}"
                subprocess.run(["cp", "-a", os.path.join(TMPFS, "volume"), keep])
                print(f"copied the volume directory to {keep}")
            subprocess.run(["umount", "-l", TMPFS])
    print(f"errnos {ERRNOS} free_kib {A.free}")
    print(f"seed {SEED} profile {profile} cycles {A.cycles}: {'FAIL' if FAILS else 'ok'} {STATS}")
    for f in FAILS[:20]:
        print("  " + f[:600])
    sys.exit(1 if FAILS else 0)


main()
