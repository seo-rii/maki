#!/usr/bin/python3.12
"""Round 9 (rollback-native): power-loss images of the real data path of a LOCAL
rollback-protected volume (backing directory and witness directory on two
tmpfs mounts). Adapted from round 8's pl.py; what is new:

  * plshim2.so logs both filesystems (device index in each record); the model
    is a pair (backing, witness), and every image picks the namespace and data
    modes of the two filesystems INDEPENDENTLY (backing kept more than the
    witness and the reverse, each from "nothing unsynced" to "everything").
  * rollback images: the backing as of an EARLIER instant with the witness as
    of the kill point (and the reverse). A backing image is acceptable only
    if the daemon refuses it or every sector satisfies the oracle of the kill
    point; a silent older state is a FAIL.
  * `maki check --deep` and `maki volume inspect` are run on a share of the
    images, before or after the daemon, and must agree with it.

Original description:

Power-loss images of the real data path.

nbdkit + the plugin run under plshim.so (LD_PRELOAD), which logs every write,
truncate, allocation, sync, creation, unlink and rename on the tmpfs that holds
the volume, with payloads and CLOCK_MONOTONIC timestamps. The NBD client
(libnbd, same clock) records when each request was submitted and
acknowledged. After a kill -9 the log is replayed into a strict POSIX model:

  file data is durable up to the file's last successful fsync/fdatasync;
  a directory entry is durable up to the directory's last fsync.

For the kill point and for random earlier instants ("cuts"), power-loss images
are built: durable namespace or live namespace, with none / all / a random,
sector-torn subset of the unsynced data. Each image is opened through the
plugin (without the shim) and every sector is compared with the oracle as of
that instant: FUA writes and writes covered by a FLUSH acknowledged before the
cut must be there; anything submitted before the cut may be there; nothing
else. One image of the kill point becomes the volume for the next cycle.

usage: pl.py --seed N [--cycles C] [--profile P] [--cuts K] [--fault SPEC] [--plant-sync] [--keep]
"""
import sys, os, random, time, signal, subprocess, struct, argparse, traceback, errno, copy, shutil
import nbd
import mk9 as mk

P = argparse.ArgumentParser()
P.add_argument("--seed", type=int, required=True)
P.add_argument("--cycles", type=int, default=12)
P.add_argument("--profile", default=None)
P.add_argument("--cuts", type=int, default=4)
P.add_argument("--inflight", type=int, default=16)
P.add_argument("--fault", default=None, help="PLSHIM_FAULT spec, e.g. sync=0.02,write=0.01,after=50")
P.add_argument("--restart-prob", type=float, default=0.4, help="probability that the main line continues with a process restart instead of a power-loss image")
P.add_argument("--marks", type=int, default=0, help="per cycle, up to this many extra images cut right after an unlink (namespace live, data none) or a hole punch (that file's unsynced calls applied, nothing else)")
P.add_argument("--plant-k01", action="store_true", help="self-test: after a plain restart the replay ignores every sync recovery made before READY; the run must FAIL")
P.add_argument("--plant-sync", action="store_true", help="self-test: the replay ignores every 3rd journal sync; the run must FAIL")
P.add_argument("--keep", action="store_true")
P.add_argument("--allow-errors", action="store_true")
P.add_argument("--capacity", default="8MiB")
P.add_argument("--size", default="2MiB")
P.add_argument("--rollbacks", type=int, default=3, help="per cycle, rollback images (backing earlier than the witness, and the reverse)")
P.add_argument("--check-prob", type=float, default=0.34, help="share of images on which maki check --deep / volume inspect also run")
P.add_argument("--plant-witness", action="store_true", help="self-test: the replay ignores every witness directory sync; the run must FAIL")
P.add_argument("--quiet", action="store_true")
P.add_argument("--max-run", type=float, default=1.0)
A = P.parse_args()

SEED = A.seed
rng = random.Random(SEED)
PROFILES = {
    "v2": dict(discard=False),
    "v3": dict(discard=True),
    "v3cache": dict(discard=True, cache='mode = "read"\nmax_bytes = "64KiB"\nttl = "1s"'),
    "v2tight": dict(discard=False, extra_limits='max_overlay_bytes = "160KiB"\nmax_journal_pending_bytes = "16KiB"\nmax_plaintext_bytes = "160KiB"\nmax_active_callbacks = 3'),
    "v3tight": dict(discard=True, extra_limits='max_overlay_bytes = "160KiB"\nmax_journal_pending_bytes = "16KiB"\nmax_plaintext_bytes = "160KiB"\nmax_active_callbacks = 3'),
    "v2cache": dict(discard=False, cache='mode = "read"\nmax_bytes = "64KiB"\nttl = "1s"'),
    "v3seg": dict(discard=True, seg="16KiB", jmax="256KiB", max_io="16KiB"),
    "v2seg": dict(discard=False, seg="16KiB", jmax="256KiB", max_io="16KiB"),
}
profile = A.profile or rng.choice(list(PROFILES))
cfg = dict(PROFILES[profile])
DISCARD = cfg.pop("discard")
UNIT = 4096
BLOCK = 512
ZERO = bytes(512)
SHIM = os.path.join(mk.HERE, "plshim2.so")
TMPFS = f"/tmp/a9rn-b-{SEED}-{os.getpid()}"
TMPW = f"/tmp/a9rn-w-{SEED}-{os.getpid()}"
PLANT = {}
FAILS = []
STATS = dict(ops=0, acked=0, errors=0, kills=0, images=0, image_sectors=0, flushes=0, records=0, cuts_in_recovery=0,
             lost_unsynced_sectors=0, refused_images=0, rb_images=0, rb_refused=0, rb_accepted_same=0, wrb_images=0,
             wrb_refused=0, wrb_accepted=0, wrb_accepted_stale=0, checks=0, witness_generations=0)


def fail(msg):
    FAILS.append(msg)
    print("FAIL " + msg, flush=True)


def log(msg):
    if not A.quiet:
        print(msg, flush=True)


def now():
    return time.monotonic_ns()


def decode(buf, s):
    if buf == ZERO:
        return 0
    sec, ver, seed = struct.unpack_from("<QQQ", buf)
    if sec == s and seed == SEED and mk.pattern(s * 512, 512, ver, SEED) == buf:
        return ver
    return "foreign/garbage: " + mk.describe(bytes(buf))


# ---- oracle (same rules as crash.py) ---------------------------------------
class Oracle:
    def __init__(self, nsect):
        self.n = nsect
        self.dur = [frozenset({0})] * nsect
        self.cands = {}
        self.ackno = 0

    def clone(self):
        o = Oracle.__new__(Oracle)
        o.n, o.ackno = self.n, self.ackno
        o.dur = list(self.dur)
        o.cands = {s: list(v) for s, v in self.cands.items()}
        return o

    def add(self, effects, definite, fua):
        self.ackno += 1
        for s, ver in effects:
            if definite and fua:
                self.dur[s] = frozenset({ver})
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
                self.dur[s] = frozenset({covered[j][1]} | {c[1] for c in covered[j + 1:]})
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
        return frozenset({lst[j][1]} | {c[1] for c in lst[j + 1:]})

    def after_crash(self, s):
        lst = self.cands.get(s)
        if not lst:
            return self.dur[s]
        return self.dur[s] | {c[1] for c in lst}

    def crashed(self):
        """A crash happened: nothing un-flushed is definite any more."""
        for s, lst in self.cands.items():
            self.cands[s] = [(a, v, False) for a, v, _ in lst]

    def resolve(self, s, ver):
        self.dur[s] = frozenset({ver})
        self.cands.pop(s, None)


def replay_events(base, events, cut):
    """Oracle as of monotonic time `cut` (None: everything)."""
    o = base.clone()
    pending = {}
    for ts, kind, oid, payload in events:
        if cut is not None and ts >= cut:
            break
        if kind == "submit":
            op = dict(payload)
            if op["kind"] == "flush":
                op["mark"] = o.ackno
            pending[oid] = op
        else:
            op = pending.pop(oid)
            err = payload
            if op["kind"] == "flush":
                if err == 0:
                    o.flushed(op["mark"])
            elif op["kind"] != "read":
                if err == 0:
                    o.add(op["effects"], True, op["fua"])
                else:
                    o.add(op["effects"], False, False)
    for op in pending.values():
        if op["kind"] not in ("flush", "read"):
            o.add(op["effects"], False, False)
    return o


# ---- the storage model replayed from the shim log --------------------------
class FObj:
    kind = "f"

    def __init__(self, data=b"", durable=False):
        self.live = bytearray(data)
        self.dur = bytearray(data) if durable else None
        self.pending = []      # ops since the last successful sync
        self.uncertain = []    # ops whose sync failed (never promoted unless their pages are rewritten and synced)
        self.nlink = 0
        self.linked_once = False


class DObj:
    kind = "d"

    def __init__(self):
        self.live = {}
        self.dur = {}
        self.nlink = 0
        self.linked_once = False


REC = struct.Struct("<cB2xIQQQQ")


def parse_log(path):
    out = []
    with open(path, "rb") as f:
        data = f.read()
    pos = 0
    while pos + REC.size <= len(data):
        typ, dev, ln, ts, ino, a, b = REC.unpack_from(data, pos)
        pos += REC.size
        if pos + ln > len(data):
            break  # record cut by the kill
        out.append((typ.decode(), ts, ino, a, b, data[pos:pos + ln], dev))
        pos += ln
    return out


class Model:
    is_witness = False

    def __init__(self, root):
        self.ino = {}
        self.root = self._scan(root)
        self.synccount = 0

    def _scan(self, path):
        st = os.stat(path)
        d = DObj(); d.nlink = 1; d.linked_once = True
        self.ino[st.st_ino] = d
        for name in os.listdir(path):
            p = os.path.join(path, name)
            cst = os.lstat(p)
            if os.path.isdir(p):
                c = self._scan(p)
            else:
                with open(p, "rb") as f:
                    c = FObj(f.read(), durable=True)
                c.nlink = 1; c.linked_once = True
                self.ino[cst.st_ino] = c
            d.live[name] = c
        d.dur = dict(d.live)
        return d

    def _file(self, ino):
        o = self.ino.get(ino)
        if o is None or (o.kind == "f" and o.nlink == 0 and o.linked_once):
            o = FObj()  # unnamed (O_TMPFILE) file, or the inode number of a deleted file reused
            self.ino[ino] = o
        return o

    @staticmethod
    def _apply(buf, op):
        k = op[0]
        if k == "W":
            off, data = op[1], op[2]
            if len(buf) < off:
                buf.extend(bytes(off - len(buf)))
            buf[off:off + len(data)] = data
        elif k == "T":
            size = op[1]
            if size < len(buf):
                del buf[size:]
            else:
                buf.extend(bytes(size - len(buf)))
        elif k == "A":
            end = op[1] + op[2]
            if end > len(buf):
                buf.extend(bytes(end - len(buf)))
        elif k == "H":
            off, ln = op[1], op[2]
            end = min(len(buf), off + ln)
            if end > off:
                buf[off:end] = bytes(end - off)

    def apply(self, rec):
        typ, ts, ino, a, b, payload = rec[:6]
        if typ in "WTAH":
            o = self._file(ino)
            op = {"W": ("W", a, payload), "T": ("T", a), "A": ("A", a, b), "H": ("H", a, b)}[typ]
            self._apply(o.live, op)
            o.pending.append(op)
        elif typ == "S":
            o = self._file(ino)
            self.synccount += 1
            if A.plant_k01 and PLANT.get("until", 0) > ts:
                return  # planted: recovery's sync "did not happen"
            if A.plant_sync and self.synccount % 3 == 0 and len(o.pending) and o.pending[0][0] == "W":
                return  # planted: pretend this sync did not happen
            if not o.uncertain:
                if o.dur is None:
                    o.dur = bytearray(o.live)
                else:
                    # dur + pending == live: apply the pending calls instead of copying the file
                    for op in o.pending:
                        self._apply(o.dur, op)
            else:
                # a sync after a failed one writes back only pages dirtied since
                pages = set()
                for op in o.pending:
                    if op[0] == "W":
                        pages.update(range(op[1] // 4096, (op[1] + len(op[2]) + 4095) // 4096))
                    else:
                        pages = None
                        break
                if pages is None:
                    o.dur = bytearray(o.live); o.uncertain = []
                else:
                    d = bytearray(o.dur or b"")
                    if len(d) < len(o.live):
                        d.extend(bytes(len(o.live) - len(d)))
                    for pg in pages:
                        d[pg * 4096:(pg + 1) * 4096] = o.live[pg * 4096:(pg + 1) * 4096]
                    del d[len(o.live):]
                    o.dur = d
                    keep = []
                    for op in o.uncertain:
                        if op[0] == "W" and set(range(op[1] // 4096, (op[1] + len(op[2]) + 4095) // 4096)) <= pages:
                            continue
                        keep.append(op)
                    o.uncertain = keep
            o.pending = []
        elif typ == "X":
            o = self._file(ino)
            o.uncertain.extend(o.pending)
            o.pending = []
        elif typ == "D":
            d = self.ino.get(ino)
            if A.plant_witness and self.is_witness:
                return  # planted: the witness directory sync "did not happen"
            if d is not None and d.kind == "d":
                d.dur = dict(d.live)
        elif typ == "C":
            parent = self.ino.get(ino)
            if parent is None:
                return
            name = payload.decode()
            existing = self.ino.get(a)
            if name in parent.live and parent.live[name] is existing and existing is not None:
                return
            if existing is None or (existing.nlink == 0 and existing.linked_once) or (b and existing.kind != "d") or (not b and existing.kind != "f"):
                existing = DObj() if b else FObj()
                self.ino[a] = existing
            old = parent.live.get(name)
            if old is not None:
                old.nlink -= 1
            parent.live[name] = existing
            existing.nlink += 1
            existing.linked_once = True
        elif typ == "U":
            parent = self.ino.get(ino)
            if parent is None:
                return
            o = parent.live.pop(payload.decode(), None)
            if o is not None:
                o.nlink -= 1
        elif typ == "R":
            sp, dp = self.ino.get(ino), self.ino.get(a)
            old, new = payload.split(b"\0", 1)
            o = sp.live.pop(old.decode(), None) if sp else None
            if dp is not None and o is not None:
                prev = dp.live.get(new.decode())
                if prev is not None:
                    prev.nlink -= 1
                dp.live[new.decode()] = o

    def content(self, o, data_mode, r):
        if isinstance(data_mode, tuple):       # ("only", object): that file's unsynced calls, nothing else
            data_mode = "all" if o is data_mode[1] else "none"
        if data_mode == "perfile":
            data_mode = r.choice(["none", "all", "subset"])
        if data_mode == "all" and not o.uncertain:
            return bytes(o.live)
        buf = bytearray(o.dur or b"")
        ops = list(o.uncertain) + (list(o.pending) if data_mode != "none" else [])
        if data_mode == "none" and not o.uncertain:
            return bytes(buf)
        nun = len(o.uncertain)
        for i, op in enumerate(ops):
            x = r.random()
            if data_mode == "all" and i >= nun:
                x = 1.0
            if x < 0.45:
                continue
            if op[0] == "W" and x < 0.65 and len(op[2]) > 512:
                # torn: each 512-byte block of the file independently
                off, data = op[1], op[2]
                pos = off
                while pos < off + len(data):
                    nxt = min(off + len(data), (pos // 512 + 1) * 512)
                    if r.random() < 0.5:
                        self._apply(buf, ("W", pos, data[pos - off:nxt - off]))
                    pos = nxt
            else:
                self._apply(buf, op)
        return bytes(buf)

    def image(self, out, ns_mode, data_mode, r):
        def emit(d, path):
            os.mkdir(path, 0o700)
            if ns_mode == "dur":
                entries = d.dur
            elif ns_mode == "live":
                entries = d.live
            else:
                entries = d.dur if r.random() < 0.5 else d.live
            for name, o in entries.items():
                p = os.path.join(path, name)
                if o.kind == "d":
                    emit(o, p)
                else:
                    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    os.write(fd, self.content(o, data_mode, r))
                    os.close(fd)
        emit(self.root, out)

    def live_tree(self):
        out = {}

        def walk(d, prefix):
            for name, o in d.live.items():
                if o.kind == "d":
                    walk(o, prefix + name + "/")
                else:
                    out[prefix + name] = bytes(o.live)
        walk(self.root, "")
        return out


def disk_tree(root):
    out = {}
    for dp, dn, fn in os.walk(root):
        for f in fn:
            p = os.path.join(dp, f)
            with open(p, "rb") as fh:
                out[os.path.relpath(p, root)] = fh.read()
    return out


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


def unlogged_calls(diff, want, have, per_device):
    """Whether the differences between the replayed model and the files are what calls cut
    between the system call and its log record leave: one call per killed process (one per
    filesystem when per_device). A rename shows as two names: the model still has the old
    name, the files have its content under the new one."""
    groups = {}
    for k in diff:
        groups.setdefault(k[:2] if per_device else "", []).append(k)
    for names in groups.values():
        if len(names) == 1:
            continue
        if len(names) == 2:
            a, b = names
            for old, new in ((a, b), (b, a)):
                if old in want and old not in have and have.get(new) == want[old]:
                    break
            else:
                return False
            continue
        return False
    return True


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
            if diff and unlogged_calls(diff, want, have, False):
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
