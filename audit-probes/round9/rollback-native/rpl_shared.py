"""Workload and verification shared by rrpl.py (extracted from rpl.py; globals are injected by the caller)."""


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


def workload(self, budget_ops, budget_time, witness_kill=None):
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
    self.errors_ok = False
    outage_at = rng.uniform(0, budget_time * 0.7) if witness_kill is not None else None
    try:
        while completed < budget_ops and time.monotonic() - start < budget_time:
            if outage_at is not None and time.monotonic() - start >= outage_at:
                # the authority's machine dies while the daemon keeps running
                self.errors_ok = True
                ev.append((now(), "outage", 0, None))
                witness_kill.kill9()
                STATS["witness_outages"] = STATS.get("witness_outages", 0) + 1
                outage_at = None
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
    if A.fault or A.allow_errors or getattr(self, 'errors_ok', False):
        STATS.setdefault("errnos", {}).setdefault(f"{op['kind']}:{errno.errorcode.get(err, err)}", 0)
        STATS["errnos"][f"{op['kind']}:{errno.errorcode.get(err, err)}"] += 1
    else:
        fail(f"request failed without a fault: {op['kind']} off={op.get('off')} len={op.get('ln')} errno={err}")


