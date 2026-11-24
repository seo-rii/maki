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


