# ---- backing + witness pair ------------------------------------------------
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


def anchor_generation(witness_model, live=True):
    """Generation in the witness anchor of a model (live or durable view), or None."""
    d = witness_model.root
    o = (d.live if live else d.dur).get("anchor")
    if o is None:
        return None
    data = bytes(o.live if live else (o.dur or b""))
    if len(data) != 104 or data[:8] != b"MAKIWIT1":
        return None
    return struct.unpack_from("<Q", data, 32)[0]


MODES = [("dur", "none"), ("dur", "none"), ("live", "none"), ("live", "all"), ("live", "all"), ("dur", "all"),
         ("mixed", "subset"), ("mixed", "perfile"), ("dur", "subset"), ("live", "subset"), ("dur", "perfile")]


def mode_name(m):
    return f"{m[0]}/{m[1] if isinstance(m[1], str) else 'only-that-file'}"


# ---- the run -----------------------------------------------------------------
class Run:
    def __init__(self):
        for t, size in ((TMPFS, "400m"), (TMPW, "24m")):
            os.makedirs(t, exist_ok=True)
            subprocess.run(["mount", "-t", "tmpfs", "-o", f"size={size},mode=0700", "tmpfs", t], check=True)
        self.root = os.path.join(TMPFS, "volume")
        self.wroot = os.path.join(TMPW, "witness")
        os.makedirs(self.root, mode=0o700)
        os.makedirs(self.wroot, mode=0o700)
        self.vcfg = dict(cfg)
        self.vcfg.update(size=A.size, ckpt_reserve="256KiB", reserve="64KiB")
        self.vol = mk.Vol(f"rpl{SEED}", discard=DISCARD, backing_dir=self.root,
                          extra_backing=self.rb(self.wroot), **self.vcfg)
        self.vol.create()
        self.size = None
        self.oracle = None
        self.ver = 0
        self.h = None
        self.events = []
        self.imgno = 0
        self.gate = os.path.join(self.vol.dir, "faults-on")

    @staticmethod
    def rb(wroot):
        return f'[backing.rollback_protection]\nwitness_root = "{wroot}"\ncapacity = "{A.capacity}"\n'

    def start(self):
        self.t_start = now()
        for attempt in (0, 1):
            logpath = os.path.join(self.vol.dir, f"shim-{self.vol.n + 1}.log")
            self.cycle_logs.append(logpath)
            env = {"LD_PRELOAD": SHIM, "PLSHIM_ROOT": self.root, "PLSHIM_ROOT2": self.wroot, "PLSHIM_LOG": logpath}
            if A.fault and attempt == 0:
                env["PLSHIM_FAULT"] = A.fault + f",seed={SEED * 1000 + self.vol.n}"
                env["PLSHIM_FAULT_GATE"] = self.gate
                if rng.random() < 0.25:
                    open(self.gate, "w").close()
                elif os.path.exists(self.gate):
                    os.unlink(self.gate)
            try:
                self.vol.start(env=env)
                break
            except RuntimeError as e:
                if not A.fault or attempt == 1:
                    raise
                STATS["starts_defeated_by_faults"] = STATS.get("starts_defeated_by_faults", 0) + 1
                log(f"  start under faults failed: {str(e)[-200:].strip()}")
        self.t_ready = now()

    def connect(self, vol=None):
        vol = vol or self.vol
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

    def check_device(self, h, o, rule, what, resolve, quiet=False):
        """Compare every sector with oracle `o`; returns (bad, newer, messages)."""
        bad = newer = 0
        msgs = []
        try:
            got = bytes(h.pread(self.size, 0))
        except nbd.Error:
            got = bytearray()
            pos = 0
            errs = []
            while pos < self.size:
                try:
                    got += h.pread(4096, pos)
                except nbd.Error as e2:
                    errs.append((pos, e2.errnum))
                    got += b"\xff" * 4096
                pos += 4096
            msgs.append(f"{what}: {len(errs)} unit read(s) failed, first at offset {errs[0][0]} errno {errs[0][1]}: allowed there "
                        f"{sorted(o.after_crash(errs[0][0] // 512))}")
            if not quiet:
                fail(msgs[-1])
            return len(errs), 0, msgs
        for s in range(self.size // 512):
            v = decode(got[s * 512:(s + 1) * 512], s)
            allowed = o.after_crash(s) if rule == "crash" else o.current(s)
            if v not in allowed:
                bad += 1
                if bad <= 4:
                    msgs.append(f"{what}: sector {s} (offset {s * 512}, unit {s * 512 // UNIT}) holds {v!r}; allowed {sorted(allowed)} "
                                f"(dur={sorted(o.dur[s])} cands={o.cands.get(s)})")
                    if not quiet:
                        fail(msgs[-1])
            else:
                if v not in o.dur[s]:
                    newer += 1
                if resolve:
                    o.resolve(s, v)
        if bad and not quiet:
            fail(f"{what}: {bad} bad sector(s) in total")
        return bad, newer, msgs

    def pick_range(self, kind):
        size = self.size
        r = rng.random()
        if r < 0.20:
            ln = BLOCK
        elif r < 0.45:
            ln = BLOCK * rng.randint(1, 8)
        elif r < 0.65:
            ln = UNIT * rng.randint(1, 3)
        elif r < 0.92:
            ln = BLOCK * rng.randint(1, 128)
        else:
            ln = BLOCK * rng.randint(128, 512)
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
            off = size - ln
        return off, ln

    def workload(self, budget_ops, budget_time):
        h, o = self.h, self.oracle
        ev = self.events
        busy = bytearray(o.n)
        inflight = {}
        done = []
        counter = [0]
        can_trim = h.can_trim()

        def submit():
            kinds = ["write"] * 55 + ["zero"] * 10 + ["flush"] * 10 + ["read"] * 10 + (["trim"] * 10 if can_trim else [])
            kind = rng.choice(kinds)
            counter[0] += 1
            oid = counter[0]
            cb = lambda e, oid=oid: done.append((oid, e.value)) or 1
            if kind == "flush":
                op = dict(kind=kind, mark=o.ackno, sectors=None)
                inflight[oid] = op
                ev.append((now(), "submit", oid, dict(kind="flush")))
                h.aio_flush(cb, 0)
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
            buf = None
            if kind == "read":
                op["buf"] = nbd.Buffer(ln)
            elif kind == "write":
                self.ver += 1
                op["fua"] = rng.random() < 0.25
                op["effects"] = [(s, self.ver) for s in range(a, b)]
                buf = mk.pattern(off, ln, self.ver, SEED)
            elif kind == "zero":
                op["fua"] = rng.random() < 0.25
                op["nohole"] = rng.random() < 0.5
                op["effects"] = [(s, 0) for s in range(a, b)]
            elif kind == "trim":
                op["fua"] = rng.random() < 0.25
                ua = -(-off // UNIT) * UNIT
                ub = (off + ln) // UNIT * UNIT
                op["effects"] = [(s, 0) for s in range(ua // 512, ub // 512)] if ub > ua else []
            inflight[oid] = op
            ev.append((now(), "submit", oid, dict(kind=kind, fua=op["fua"], effects=op["effects"])))
            fua = nbd.CMD_FLAG_FUA if op["fua"] else 0
            if kind == "read":
                h.aio_pread(op["buf"], off, cb, 0)
            elif kind == "write":
                h.aio_pwrite(buf, off, cb, fua)
            elif kind == "zero":
                h.aio_zero(ln, off, cb, fua | (nbd.CMD_FLAG_NO_HOLE if op["nohole"] else 0))
            else:
                h.aio_trim(ln, off, cb, fua)
            return True

        def complete(oid, err, dead):
            op = inflight.pop(oid)
            STATS["ops"] += 1
            if dead and err != 0:
                inflight[oid] = op
                return
            ev.append((now(), "complete", oid, err))
            if op["kind"] == "flush":
                if err == 0:
                    STATS["flushes"] += 1
                    o.flushed(op["mark"])
                else:
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
                            fail(f"live read: sector {s} holds {v!r}; allowed {sorted(o.current(s))}")
                            break
                else:
                    STATS["errors"] += 1
                    self.on_error(op, err)
                return
            if err == 0:
                STATS["acked"] += 1
                o.add(op["effects"], True, op["fua"])
            else:
                o.add(op["effects"], False, False)
                STATS["errors"] += 1
                self.on_error(op, err)

        start = time.monotonic()
        completed = 0
        try:
            while completed < budget_ops and time.monotonic() - start < budget_time:
                while len(inflight) < A.inflight:
                    if not submit():
                        break
                h.poll(100)
                while done:
                    oid, err = done.pop(0)
                    complete(oid, err, False)
                    completed += 1
        except nbd.Error as e:
            fail(f"connection failed during the workload before the kill: {e}")
        os.killpg(self.vol.proc.pid, signal.SIGKILL)
        STATS["kills"] += 1
        deadline = time.monotonic() + 30
        while not (h.aio_is_dead() or h.aio_is_closed()) and time.monotonic() < deadline:
            try:
                h.poll(100)
            except nbd.Error:
                break
            while done:
                oid, err = done.pop(0)
                complete(oid, err, True)
        while done:
            oid, err = done.pop(0)
            complete(oid, err, True)
        for oid, op in inflight.items():
            if op["kind"] not in ("flush", "read"):
                o.add(op["effects"], False, False)
        self.vol.proc.wait()
        self.vol.notify.close()

    def on_error(self, op, err):
        if A.fault or A.allow_errors:
            STATS.setdefault("errnos", {}).setdefault(f"{op['kind']}:{errno.errorcode.get(err, err)}", 0)
            STATS["errnos"][f"{op['kind']}:{errno.errorcode.get(err, err)}"] += 1
        else:
            fail(f"request failed without a fault: {op['kind']} off={op.get('off')} len={op.get('ln')} errno={err}")

    def offline(self, iv):
        """maki check --deep and volume inspect; returns (ok, text)."""
        STATS["checks"] += 1
        c = iv.maki("check", iv.cfg, "--deep", timeout=120)
        i = iv.maki("volume", "inspect", iv.cfg, timeout=120)
        text = f"check --deep rc={c.returncode} {c.stdout.strip()[-400:]} {c.stderr.strip()[-400:]} | inspect rc={i.returncode} {i.stderr.strip()[-300:]}"
        if (c.returncode == 0) != (i.returncode == 0):
            # inspect only reads the superblock; check can fail on more. Only "check ok, inspect not" is a contradiction.
            if c.returncode == 0:
                fail(f"check --deep passed but volume inspect failed: {text}")
        if "panicked" in c.stderr or "panicked" in i.stderr:
            fail(f"panic in an offline command: {text}")
        return c.returncode == 0 and "check passed" in c.stdout, text

    def test_image(self, bmodel, wmodel, o, label, bmode, wmode, r, expect="ok"):
        """Build one image (backing from bmodel, witness from wmodel), open it through the
        plugin, compare with `o`. expect: "ok" (a power-loss image: must open and satisfy o),
        "rb" (backing rolled back: refuse, or satisfy o), "wrb" (witness rolled back: outcome recorded)."""
        self.imgno += 1
        img = os.path.join(TMPFS, f"img-{self.imgno}")
        wimg = os.path.join(TMPW, f"wimg-{self.imgno}")
        bmodel.image(img, bmode[0], bmode[1], r)
        wmodel.image(wimg, wmode[0], wmode[1], r)
        iv = mk.Vol(f"img{SEED}", discard=DISCARD, backing_dir=img, key_file=self.vol.key,
                    extra_backing=self.rb(wimg), **self.vcfg)
        what = f"{label} [backing {mode_name(bmode)}, witness {mode_name(wmode)}]"
        ok = True
        offline_first = offline_after = None
        try:
            order = None
            if r.random() < A.check_prob:
                order = r.choice(["before", "after", "both"])
            if order in ("before", "both"):
                offline_first = self.offline(iv)
            started = True
            try:
                iv.start()
            except RuntimeError as e:
                started = False
                reason = str(e)[-700:]
            if not started:
                if expect == "ok":
                    STATS["refused_images"] += 1
                    fail(f"{what}: the plugin refuses to recover this power-loss image: {reason}")
                    ok = False
                elif expect == "rb":
                    STATS["rb_refused"] += 1
                    STATS.setdefault("rb_reasons", {})
                    key = classify(reason)
                    STATS["rb_reasons"][key] = STATS["rb_reasons"].get(key, 0) + 1
                else:
                    STATS["wrb_refused"] += 1
                    STATS.setdefault("wrb_reasons", {})
                    key = classify(reason)
                    STATS["wrb_reasons"][key] = STATS["wrb_reasons"].get(key, 0) + 1
                if offline_first is not None and offline_first[0]:
                    fail(f"{what}: maki check --deep passed on an image the daemon refuses: {offline_first[1]} / daemon: {reason}")
                    ok = False
            else:
                h = self.connect(iv)
                bad, newer, msgs = self.check_device(h, o, "crash", what, resolve=False, quiet=(expect == "wrb"))
                STATS["images"] += 1
                STATS["image_sectors"] += self.size // 512
                if expect == "ok":
                    ok = bad == 0
                elif expect == "rb":
                    if bad:
                        fail(f"{what}: ROLLBACK ACCEPTED: an earlier backing state opened against the current witness and serves older data")
                        ok = False
                    else:
                        STATS["rb_accepted_same"] += 1
                else:
                    STATS["wrb_accepted"] += 1
                    if bad:
                        STATS["wrb_accepted_stale"] += 1
                        if STATS["wrb_accepted_stale"] <= 2:
                            log(f"  note (witness rolled back, accepted with older data): {msgs[0][:300] if msgs else ''}")
                try:
                    h.shutdown()
                except nbd.Error:
                    pass
                iv.kill9()
                if offline_first is not None and not offline_first[0] and expect == "ok":
                    fail(f"{what}: maki check --deep failed on an image the daemon then served correctly: {offline_first[1]}")
                    ok = False
                if order in ("after", "both"):
                    offline_after = self.offline(iv)
                    if not offline_after[0] and expect == "ok":
                        fail(f"{what}: maki check --deep failed after the daemon recovered and served this image: {offline_after[1]}")
                        ok = False
            if not ok:
                keep = os.path.join(mk.BASE, f"rpl-fail-{SEED}-{self.imgno}")
                shutil.rmtree(keep, ignore_errors=True)
                os.makedirs(keep)
                shutil.copytree(img, keep + "/backing-after")
                shutil.copytree(wimg, keep + "/witness-after")
                print(f"kept the image (after the failed recovery/verify) at {keep}; log {iv.logpath}")
                print(iv.read_log()[-1500:])
        finally:
            try:
                iv.kill9()
            except Exception:
                pass
            shutil.rmtree(iv.dir, ignore_errors=True)
            shutil.rmtree(img, ignore_errors=True)
            shutil.rmtree(wimg, ignore_errors=True)
        return ok


def classify(reason):
    for key in ("no exact witnessed manifest", "page authentication failed", "arena size mismatch", "witness anchor",
                "no valid superblock", "holds no anchor", "no format marker", "capacity mismatch", "VOLUME_ALREADY_ATTACHED",
                "noncanonical or foreign", "invalid rollback"):
        if key in reason:
            return key
    tail = reason.strip().splitlines()[-1] if reason.strip() else "?"
    return "other: " + tail[-160:]


def main():
    run = Run()
    try:
        log(f"seed {SEED} profile {profile} dir {run.vol.dir} tmpfs {TMPFS} {TMPW}")
        run.start()
        run.h = run.connect()
        run.size = run.h.get_size()
        run.oracle = Oracle(run.size // 512)
        pre = run.oracle.clone()
        for cycle in range(A.cycles):
            bad, newer, _ = run.check_device(run.h, run.oracle, "crash", f"cycle {cycle}: main line after recovery", resolve=True)
            if bad:
                break
            base_oracle = run.oracle.clone()
            run.events = []
            PLANT["until"] = run.t_ready if getattr(run, "restarted", False) else 0
            if A.fault:
                open(run.gate, "w").close()
            budget_ops = rng.choice([3, 10, 30, 100, 300])
            run.workload(budget_ops, rng.uniform(0.02, A.max_run))
            t_kill = now()
            logtxt = run.vol.read_log()
            if "panic" in logtxt.lower():
                fail(f"cycle {cycle}: panic in nbdkit log: " + [l for l in logtxt.splitlines() if "panic" in l.lower()][0][:400])
            records = [rec for path in run.cycle_logs if os.path.exists(path) for rec in parse_log(path)]
            STATS["records"] += len(records)
            baseline = run.baseline
            full = copy.deepcopy(baseline)
            for rec in records:
                full.apply(rec)
            want = full.live_tree()
            have = {"B:" + k: v for k, v in disk_tree(run.root).items()}
            have.update({"W:" + k: v for k, v in disk_tree(run.wroot).items()})
            diff = [k for k in set(want) | set(have) if want.get(k) != have.get(k)]
            if len(diff) == 1:
                STATS["unlogged_last_call"] = STATS.get("unlogged_last_call", 0) + 1
            elif diff:
                fail(f"cycle {cycle}: HARNESS: shim log does not reproduce the live tree; differing files: {sorted(diff)[:8]} "
                     f"(sizes model/disk: {[(k, len(want.get(k, b'')), len(have.get(k, b''))) for k in sorted(diff)[:4]]})")
                break
            g_final = anchor_generation(full.m[1])
            r = random.Random(SEED * 7919 + cycle)
            t0 = records[0][1] if records else run.t_start
            final_oracle = replay_events(base_oracle, run.events, None)
            # -- cut instants: power-loss images (same instant on both filesystems, independent modes)
            #    and rollback images (one side earlier)
            plan = []
            for k in range(A.cuts + A.rollbacks):
                cut = r.randrange(t0, t_kill) if t_kill > t0 else t_kill
                if r.random() < 0.7 and records:
                    cls = r.choice(["SD", "SD", "R", "RU", "UCTH", "D", "D", "X"])
                    dev = r.choice([None, 0, 1, 1])
                    marks = [x[1] for x in records if x[0] in cls and (dev is None or x[6] == dev)]
                    if marks:
                        cut = r.choice(marks) + r.choice([1, 1, -1])
                plan.append((cut, "pl" if k < A.cuts else r.choice(["rb", "rb", "wrb"])))
            plan.sort(key=lambda x: x[0])
            m = copy.deepcopy(baseline)
            pos = 0
            for k, (cut, kind) in enumerate(plan):
                while pos < len(records) and records[pos][1] <= cut:
                    m.apply(records[pos])
                    pos += 1
                where = f"cycle {cycle} cut {k} (+{(cut - run.t_start) / 1e6:.1f} ms of {(t_kill - run.t_start) / 1e6:.1f})"
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
                elif kind == "rb":
                    # the backing as of `cut` (any power-loss view of it), the witness as it is now
                    STATS["rb_images"] += 1
                    bmode = r.choice(MODES)
                    g_then = anchor_generation(m.m[1])
                    if not run.test_image(m.m[0], full.m[1], final_oracle, where + f" BACKING ROLLED BACK (witness generation then {g_then}, now {g_final})",
                                          bmode, ("live", "all"), r, expect="rb"):
                        raise StopIteration
                else:
                    STATS["wrb_images"] += 1
                    wmode = r.choice(MODES)
                    g_then = anchor_generation(m.m[1], live=(wmode[0] != "dur"))
                    if not run.test_image(full.m[0], m.m[1], final_oracle, where + f" WITNESS ROLLED BACK (generation then {g_then}, now {g_final})",
                                          ("live", "all"), wmode, r, expect="wrb"):
                        raise StopIteration
            # -- images of the kill point
            for bmode, wmode in ((("dur", "none"), ("dur", "none")), (("dur", "none"), ("live", "all")),
                                 (("live", "all"), ("dur", "none")), (("mixed", "perfile"), ("mixed", "perfile"))):
                if not run.test_image(full.m[0], full.m[1], final_oracle, f"cycle {cycle} kill point", bmode, wmode, r):
                    raise StopIteration
            STATS["witness_generations"] = g_final
            # -- continue: a plain process restart (page cache kept; K-01), or one image of the kill point
            if not diff and r.random() < A.restart_prob:
                desc = "restart"
                run.carry = full
                run.restarted = True
                STATS["plain_restarts"] = STATS.get("plain_restarts", 0) + 1
            else:
                run.restarted = False
                bmode, wmode = r.choice(MODES), r.choice(MODES)
                desc = f"backing {mode_name(bmode)}, witness {mode_name(wmode)}"
                newroot = os.path.join(TMPFS, "next")
                neww = os.path.join(TMPW, "next")
                full.m[0].image(newroot, bmode[0], bmode[1], r)
                full.m[1].image(neww, wmode[0], wmode[1], r)
                shutil.rmtree(run.root)
                os.rename(newroot, run.root)
                shutil.rmtree(run.wroot)
                os.rename(neww, run.wroot)
            run.oracle.crashed()
            pre = run.oracle.clone()
            try:
                run.start()
            except RuntimeError as e:
                fail(f"cycle {cycle}: main line [{desc}]: the plugin refuses to recover the power-loss image: {str(e)[-1200:]}")
                break
            run.h = run.connect()
            log(f"cycle {cycle} ok [{desc}] records {len(records)} gen {g_final}; stats {STATS}")
    except StopIteration:
        pass
    except Exception as e:
        fail(f"harness exception: {e!r}\n{traceback.format_exc()[-2500:]}")
    finally:
        try:
            run.vol.kill9()
        except Exception:
            pass
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
        print("  " + f[:1200])
    sys.exit(1 if FAILS else 0)


_orig_start = Run.start


def _start(self):
    carried = getattr(self, "carry", None)
    self.baseline = carried if carried is not None else Pair(self.root, self.wroot)
    self.carry = None
    self.cycle_logs = []
    _orig_start(self)


Run.start = _start
main()
