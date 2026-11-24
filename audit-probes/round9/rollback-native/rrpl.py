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
P.add_argument("--tmpfs", default="700m")
P.add_argument("--witness-timeout", type=int, default=5000)
P.add_argument("--witness-outage", type=float, default=0.15, help="share of cycles in which the authority server is killed while the daemon runs")
P.add_argument("--gc-prob", type=float, default=0.3, help="share of images on which maki volume gc runs between the takeover and the daemon start")
P.add_argument("--capacity", default="4MiB")
P.add_argument("--size", default="1MiB")
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
TMPFS = f"/tmp/a9rn-rb-{SEED}-{os.getpid()}"
TMPW = f"/tmp/a9rn-rw-{SEED}-{os.getpid()}"
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
        if kind == "outage":
            continue
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



VCFG = dict(cfg)
VCFG.update(size=A.size, ckpt_reserve="256KiB", reserve="64KiB")
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
            if diff and unlogged_calls(diff, want, have, True):
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
