# ---- remote mode: backing root + authority state directory -------------------
import rw, json

class Pair:
    def __init__(self, root, wroot):
        self.m = [Model(root), Model(wroot)]
        self.m[1].is_witness = True

    def apply(self, rec):
        self.m[rec[6]].apply(rec)

    def live_tree(self):
        out = {"B:" + k: v for k, v in self.m[0].live_tree().items()}
        out.update({"W:" + k: v for k, v in self.m[1].live_tree().items()})
        return out


MODES = [("dur", "none"), ("dur", "none"), ("live", "none"), ("live", "all"), ("live", "all"), ("dur", "all"),
         ("mixed", "subset"), ("mixed", "perfile"), ("dur", "subset"), ("live", "subset"), ("dur", "perfile")]


def mode_name(m):
    return f"{m[0]}/{m[1] if isinstance(m[1], str) else 'only-that-file'}"


def parse_logs(paths):
    """paths: list of (path, dev). Records of all processes merged by timestamp."""
    out = []
    for path, dev in paths:
        if os.path.exists(path):
            for rec in parse_log(path):
                out.append(rec[:6] + (dev,))
    out.sort(key=lambda x: x[1])
    return out


class Site:
    """A backing root, an authority state directory, its server and the volume configurations."""

    def __init__(self, tag, root, state, authority=None, base=None, shim=False):
        self.root, self.state = root, state
        self.shim = shim
        self.vol = mk.Vol(tag, discard=DISCARD, backing_dir=root, key_file=base.vol.key if base else None, **VCFG,
                          extra_backing="@@REMOTE@@")
        if authority is None:
            self.auth = rw.Authority(os.path.join(self.vol.dir, "auth"), state, timeout_ms=A.witness_timeout)
        else:
            # the same PKI and identity, another state directory and port
            self.auth = rw.Authority.__new__(rw.Authority)
            self.auth.__dict__.update(authority.__dict__)
            self.auth.base = os.path.join(self.vol.dir, "auth")
            os.makedirs(self.auth.base)
            self.auth.state = state
            self.auth.port = rw.free_port()
            self.auth.cfg = os.path.join(self.auth.base, "server.toml")
            self.auth.proc = None
            self.auth.n = 0
            self.auth.write_config()
        text = self.vol.text
        with open(self.vol.cfg, "w") as f:
            f.write(text.replace("@@REMOTE@@", self.auth.remote_section(A.capacity, "writer")))
        self.admin_cfg = os.path.join(self.vol.dir, "admin.toml")
        with open(self.admin_cfg, "w") as f:
            f.write(text.replace("@@REMOTE@@", self.auth.remote_section(A.capacity, "admin")))
        os.chmod(self.admin_cfg, 0o644)
        self.logs = []          # (path, dev) of every shimmed process of the current cycle
        self.nlog = 0

    def env(self, dev):
        if not self.shim:
            return None
        self.nlog += 1
        path = os.path.join(self.vol.dir, f"shim-{self.nlog}.log")
        self.logs.append((path, dev))
        return {"LD_PRELOAD": SHIM, "PLSHIM_ROOT": self.root if dev == 0 else self.state, "PLSHIM_LOG": path}

    def start_witness(self):
        self.auth.start(env=self.env(1))

    def maki(self, *args, timeout=180):
        e = dict(os.environ)
        extra = self.env(0)
        if extra:
            e.update(extra)
        return subprocess.run([mk.MAKI, *args], capture_output=True, text=True, timeout=timeout, env=e)

    def record(self):
        r = subprocess.run([mk.MAKI, "volume", "witness", self.vol.cfg], capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise RuntimeError(f"volume witness failed: {r.stderr.strip()[-400:]}")
        return json.loads(r.stdout)

    def recover(self):
        """The documented procedure after a crash: inspect; a session that is not released is taken
        over with the administrator configuration. Returns (ok, text)."""
        rec = self.record()
        steps = [f"phase={rec['phase']} fence={rec['fence']}"]
        if rec["current"] is None:
            return False, "authority has no current descriptor"
        if rec["phase"] != "released":
            r = self.maki("volume", "takeover", self.admin_cfg, str(rec["fence"]), rw.root_hex(rec))
            steps.append(f"takeover rc={r.returncode} {r.stderr.strip()[-500:]}")
            STATS["takeovers"] = STATS.get("takeovers", 0) + 1
            if r.returncode != 0:
                return False, "; ".join(steps)
        return True, "; ".join(steps)

    def start_daemon(self):
        self.vol.start(env=self.env(0), timeout=60)

    def stop_all(self):
        for f in (self.vol.kill9, self.auth.kill9):
            try:
                f()
            except Exception:
                pass


class Run:
    def __init__(self):
        for t, size in ((TMPFS, A.tmpfs), (TMPW, "24m")):
            os.makedirs(t, exist_ok=True)
            subprocess.run(["mount", "-t", "tmpfs", "-o", f"size={size},mode=0700", "tmpfs", t], check=True)
        self.root = os.path.join(TMPFS, "volume")
        self.state = os.path.join(TMPW, "state")
        os.makedirs(self.root, mode=0o700)
        self.site = Site(f"rrpl{SEED}", self.root, self.state, shim=True)
        self.vol = self.site.vol
        self.site.auth.init()
        self.site.auth.start()          # creation is not logged: the baseline is scanned after it
        r = self.vol.create(check=False)
        if r.returncode != 0:
            raise RuntimeError(f"create failed: {r.stdout} {r.stderr}")
        self.site.auth.kill9()
        self.size = None
        self.oracle = None
        self.ver = 0
        self.h = None
        self.events = []
        self.imgno = 0
        self.witness_up = False

    def begin_cycle(self, carried):
        self.baseline = carried if carried is not None else Pair(self.root, self.state)
        self.site.logs = []

    def bring_up(self):
        """Witness (if down), recovery procedure, daemon."""
        self.t_start = now()
        if not self.witness_up:
            self.site.start_witness()
            self.witness_up = True
        ok, text = self.site.recover()
        if not ok:
            raise RuntimeError("recovery procedure failed: " + text)
        self.site.start_daemon()
        self.t_ready = now()
        return text

    connect = lambda self, vol=None: _connect(vol or self.vol)

    def test_image(self, bmodel, wmodel, o, label, bmode, wmode, r, expect="ok"):
        self.imgno += 1
        img = os.path.join(TMPFS, f"img-{self.imgno}")
        wimg = os.path.join(TMPW, f"wimg-{self.imgno}")
        bmodel.image(img, bmode[0], bmode[1], r)
        wmodel.image(wimg, wmode[0], wmode[1], r)
        os.chmod(wimg, 0o700)
        site = Site(f"img{SEED}", img, wimg, authority=self.site.auth, base=self.site)
        what = f"{label} [backing {mode_name(bmode)}, authority {mode_name(wmode)}]"
        ok = True
        try:
            stage = "witness serve"
            try:
                site.start_witness()
                stage = "recovery procedure (inspect, takeover)"
                good, text = site.recover()
                if not good:
                    raise RuntimeError(text)
                if r.random() < A.gc_prob:
                    g = site.maki("volume", "gc", site.vol.cfg)
                    STATS["gc_runs"] = STATS.get("gc_runs", 0) + 1
                    if g.returncode != 0:
                        raise RuntimeError(f"volume gc failed: {g.stderr.strip()[-400:]}")
                stage = "daemon start"
                site.start_daemon()
                started = True
            except RuntimeError as e:
                started = False
                reason = f"{stage}: {str(e)[-900:]}"
            if not started:
                if expect == "ok":
                    STATS["refused_images"] += 1
                    fail(f"{what}: this power-loss image cannot be brought back with the documented procedure: {reason}")
                    ok = False
                else:
                    STATS[expect + "_refused"] += 1
                    key = classify(reason)
                    STATS.setdefault(expect + "_reasons", {})
                    STATS[expect + "_reasons"][key] = STATS[expect + "_reasons"].get(key, 0) + 1
            else:
                h = _connect(site.vol)
                bad, newer, msgs = check_device(self, h, o, "crash", what, resolve=False, quiet=(expect == "wrb"))
                STATS["images"] += 1
                STATS["image_sectors"] += self.size // 512
                if expect == "ok":
                    ok = bad == 0
                elif expect == "rb":
                    if bad:
                        fail(f"{what}: ROLLBACK ACCEPTED: an earlier backing state opened against the current authority and serves older data")
                        ok = False
                    else:
                        STATS["rb_accepted_same"] += 1
                else:
                    STATS["wrb_accepted"] += 1
                    if bad:
                        STATS["wrb_accepted_stale"] += 1
                try:
                    h.shutdown()
                except nbd.Error:
                    pass
                # a clean stop must release the authority
                rc = site.vol.term(timeout=60)
                if expect == "ok":
                    rec = site.record()
                    if rc != 0 or rec["phase"] != "released":
                        fail(f"{what}: after SIGTERM (rc {rc}) the authority is {rec['phase']}, not released")
                        ok = False
                    left = sorted(n for n in os.listdir(img) if n.startswith("remote-") or n.startswith(".remote-gc-"))
                    STATS["namespaces_left_max"] = max(STATS.get("namespaces_left_max", 0), len(left))
            if not ok:
                keep = os.path.join(mk.BASE, f"rrpl-fail-{SEED}-{self.imgno}")
                shutil.rmtree(keep, ignore_errors=True)
                os.makedirs(keep)
                shutil.copytree(wimg, keep + "/state-after")
                print(f"kept the authority state (after the failed procedure) at {keep}; daemon log {getattr(site.vol, 'logpath', None)}")
                try:
                    print(site.vol.read_log()[-1500:])
                    print(site.auth.read_log()[-800:])
                    print(sorted(os.listdir(img)))
                except Exception:
                    pass
        finally:
            site.stop_all()
            shutil.rmtree(site.vol.dir, ignore_errors=True)
            shutil.rmtree(img, ignore_errors=True)
            shutil.rmtree(wimg, ignore_errors=True)
        return ok


def classify(reason):
    for key in ("does not hold the remote authority's current generation", "no exact remote witnessed manifest", "page authentication failed",
                "remote witness changed", "predecessor conflict", "not a remote rollback backing", "namespace is not valid in this root",
                "rollback namespace entry not found", "No such file", "not initialized", "invalid remote witness", "empty"):
        if key in reason:
            return key
    tail = reason.strip().splitlines()[-1] if reason.strip() else "?"
    return "other: " + tail[-200:]


def _connect(vol):
    last = None
    for _ in range(300):
        h = nbd.NBD()
        h.set_strict_mode(0)
        try:
            h.connect_unix(vol.sock)
            return h
        except nbd.Error as e:
            last = e
            time.sleep(0.02)
    raise RuntimeError(f"cannot connect: {last}")


import importlib.util as _u
_spec = _u.spec_from_file_location("rpl_tail_funcs", os.path.join(mk.HERE, "rpl_shared.py"))
_shared = _u.module_from_spec(_spec)
_shared.__dict__.update(dict(A=A, rng=rng, mk=mk, nbd=nbd, STATS=STATS, fail=fail, log=log, now=now, decode=decode, UNIT=UNIT,
                             BLOCK=BLOCK, SEED=SEED, time=time, os=os, signal=signal, errno=errno))
_spec.loader.exec_module(_shared)
check_device = _shared.check_device
Run.pick_range = _shared.pick_range
Run.workload = _shared.workload
Run.on_error = _shared.on_error


def main():
    run = Run()
    site = run.site
    try:
        log(f"seed {SEED} profile {profile} dir {run.vol.dir} tmpfs {TMPFS} {TMPW}")
        run.begin_cycle(None)
        run.bring_up()
        run.h = run.connect()
        run.size = run.h.get_size()
        run.oracle = Oracle(run.size // 512)
        pre = run.oracle.clone()
        for cycle in range(A.cycles):
            bad, newer, _ = check_device(run, run.h, run.oracle, "crash", f"cycle {cycle}: main line after recovery", resolve=True)
            if bad:
                break
            base_oracle = run.oracle.clone()
            run.events = []
            budget_ops = rng.choice([3, 10, 30, 100, 300])
            kill_witness_first = rng.random() < A.witness_outage
            run.workload(budget_ops, rng.uniform(0.02, A.max_run), witness_kill=(site.auth if kill_witness_first else None))
            # the daemon is dead; the authority server dies too in most cycles (another machine: it may also survive)
            witness_dies = kill_witness_first or rng.random() < 0.7
            if witness_dies:
                site.auth.kill9()
                run.witness_up = False
            t_kill = now()
            logtxt = run.vol.read_log()
            if "panic" in logtxt.lower():
                fail(f"cycle {cycle}: panic in nbdkit log: " + [l for l in logtxt.splitlines() if "panic" in l.lower()][0][:400])
            if "panic" in site.auth.read_log().lower():
                fail(f"cycle {cycle}: panic in maki-witness log: {site.auth.read_log()[-400:]}")
            records = parse_logs(site.logs)
            STATS["records"] += len(records)
            baseline = run.baseline
            full = copy.deepcopy(baseline)
            for rec in records:
                full.apply(rec)
            want = full.live_tree()
            have = {"B:" + k: v for k, v in disk_tree(run.root).items()}
            have.update({"W:" + k: v for k, v in disk_tree(run.state).items()})
            diff = [k for k in set(want) | set(have) if want.get(k) != have.get(k)]
            if len(diff) == 1:
                STATS["unlogged_last_call"] = STATS.get("unlogged_last_call", 0) + 1
            elif diff:
                fail(f"cycle {cycle}: HARNESS: shim logs do not reproduce the live trees; differing files: {sorted(diff)[:8]} "
                     f"(sizes model/disk: {[(k, len(want.get(k, b'')), len(have.get(k, b''))) for k in sorted(diff)[:4]]})")
                break
            r = random.Random(SEED * 7919 + cycle)
            t0 = records[0][1] if records else run.t_start
            final_oracle = replay_events(base_oracle, run.events, None)
            plan = []
            for k in range(A.cuts + A.rollbacks):
                cut = r.randrange(t0, t_kill) if t_kill > t0 else t_kill
                x = r.random()
                if x < 0.35 and records:
                    # inside the recovery procedure and the attach (takeover, claim, fork, activation, GC)
                    early = [y[1] for y in records if y[1] < run.t_ready]
                    if early:
                        cut = r.choice(early) + r.choice([1, 1, -1])
                elif x < 0.8 and records:
                    cls = r.choice(["SD", "SD", "R", "RU", "UCTH", "D", "D"])
                    dev = r.choice([None, 0, 1, 1])
                    marks = [y[1] for y in records if y[0] in cls and (dev is None or y[6] == dev)]
                    if marks:
                        cut = r.choice(marks) + r.choice([1, 1, -1])
                plan.append((cut, "pl" if k < A.cuts else "rb"))
            plan.sort(key=lambda y: y[0])
            m = copy.deepcopy(baseline)
            pos = 0
            for k, (cut, kind) in enumerate(plan):
                while pos < len(records) and records[pos][1] <= cut:
                    m.apply(records[pos])
                    pos += 1
                where = f"cycle {cycle} cut {k} (+{(cut - run.t_start) / 1e6:.1f} ms of {(t_kill - run.t_start) / 1e6:.1f}, ready at {(run.t_ready - run.t_start) / 1e6:.1f})"
                if kind == "pl":
                    if cut < run.t_ready:
                        o = pre
                        STATS["cuts_in_recovery"] += 1
                    else:
                        o = replay_events(base_oracle, run.events, cut)
                    bmode, wmode = r.choice(MODES), r.choice(MODES)
                    if r.random() < 0.4:
                        bmode, wmode = r.choice([(("dur", "none"), ("live", "all")), (("live", "all"), ("dur", "none")),
                                                 (("dur", "none"), ("dur", "none")), (("dur", "all"), ("live", "none"))])
                    if not run.test_image(m.m[0], m.m[1], o, where, bmode, wmode, r):
                        raise StopIteration
                else:
                    STATS["rb_images"] += 1
                    bmode = r.choice(MODES)
                    if not run.test_image(m.m[0], full.m[1], final_oracle, where + " BACKING ROLLED BACK", bmode, ("live", "all"), r, expect="rb"):
                        raise StopIteration
            for bmode, wmode in ((("dur", "none"), ("dur", "none")), (("dur", "none"), ("live", "all")),
                                 (("live", "all"), ("dur", "none")), (("mixed", "perfile"), ("mixed", "perfile"))):
                if not run.test_image(full.m[0], full.m[1], final_oracle, f"cycle {cycle} kill point", bmode, wmode, r):
                    raise StopIteration
            # -- continue the main line
            carried = None
            if not diff and r.random() < A.restart_prob:
                desc = "restart" + ("" if witness_dies else ", authority server kept running")
                carried = full
                STATS["plain_restarts"] = STATS.get("plain_restarts", 0) + 1
            else:
                if not witness_dies:
                    site.auth.kill9()
                    run.witness_up = False
                bmode, wmode = r.choice(MODES), r.choice(MODES)
                desc = f"backing {mode_name(bmode)}, authority {mode_name(wmode)}"
                newroot = os.path.join(TMPFS, "next")
                neww = os.path.join(TMPW, "next")
                full.m[0].image(newroot, bmode[0], bmode[1], r)
                full.m[1].image(neww, wmode[0], wmode[1], r)
                shutil.rmtree(run.root)
                os.rename(newroot, run.root)
                shutil.rmtree(run.state)
                os.rename(neww, run.state)
                os.chmod(run.state, 0o700)
            run.oracle.crashed()
            pre = run.oracle.clone()
            run.begin_cycle(carried)
            try:
                text = run.bring_up()
            except RuntimeError as e:
                fail(f"cycle {cycle}: main line [{desc}]: cannot be brought back with the documented procedure: {str(e)[-1200:]}")
                break
            run.h = run.connect()
            log(f"cycle {cycle} ok [{desc}; {text}] records {len(records)}; stats {STATS}")
    except StopIteration:
        pass
    except Exception as e:
        fail(f"harness exception: {e!r}\n{traceback.format_exc()[-2500:]}")
    finally:
        site.stop_all()
        if FAILS and not A.quiet:
            print(run.vol.all_logs()[-2500:])
        if A.keep or FAILS:
            print(f"kept {run.vol.dir}")
        else:
            shutil.rmtree(run.vol.dir, ignore_errors=True)
        for t in (TMPFS, TMPW):
            subprocess.run(["umount", "-l", t])
            try:
                os.rmdir(t)
            except OSError:
                pass
    print(f"seed {SEED} profile {profile} cycles {A.cycles} fault {A.fault}: {'FAIL' if FAILS else 'ok'} {STATS}")
    for f in FAILS[:12]:
        print("  " + f[:1500])
    sys.exit(1 if FAILS else 0)


main()
