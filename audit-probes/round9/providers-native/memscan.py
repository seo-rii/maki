"""Plaintext left in the daemon's memory after remote crypto I/O.

The NBD client only ever touches ONE 512-byte sector of each 4096-byte
crypto unit (sector 3 for reads, sector 2 for writes), so nbdkit's own
request buffers never hold the rest of a unit. Maki decrypts and encrypts
whole units through the provider, so any copy of a unit's sector 5 in the
process (raw, or inside the unit's base64 text) was made by Maki or by its
transport stack. The daemon is restarted after the volume is filled, so
nothing else ever put that plaintext into this process.

Scan: every readable private mapping of the nbdkit process via
/proc/<pid>/mem, at idle (no request in flight for `--idle` seconds).

usage: memscan.py <http|ws|grpc> [--tls] [--idle 3] [--cache] [--lock off|secure-buffers]
"""
import argparse, base64, os, re, sys, time
import nbd
import rp

ap = argparse.ArgumentParser()
ap.add_argument("transport")
ap.add_argument("--tls", action="store_true")
ap.add_argument("--idle", type=float, default=3)
ap.add_argument("--units", type=int, default=64)
ap.add_argument("--during", action="store_true", help="also scan while a request is stalled in the provider")
args = ap.parse_args()
transport = args.transport
UNIT, SECT = 4096, 512
N = args.units

beh = rp.Behaviour()
tls_cfg, tls = "", None
if args.tls:
    pki = rp.Pki(os.path.join(rp.BASE, "pkim-%d" % os.getpid()))
    cert = pki.leaf("good")
    tls = rp.grpc_creds(*cert) if transport == "grpc" else rp.server_ssl_context(*cert)
    tls_cfg = f'ca_file = "{pki.ca_path}"'
srv = {"http": rp.HttpServer, "ws": rp.WsServer, "grpc": rp.GrpcServer}[transport](beh, tls=tls)
v = rp.Vol(f"mem-{transport}", transport, [srv.url("localhost" if args.tls else None)], tls=tls_cfg, size="4MiB")


def unit_plain(u, version_of_sector2=1):
    d = bytearray(rp.pattern(u * UNIT, UNIT, 1))
    if version_of_sector2 != 1:
        d[2 * SECT:3 * SECT] = rp.pattern(u * UNIT + 2 * SECT, SECT, version_of_sector2)
    return bytes(d)


def needles(units, version_of_sector2=1):
    out = []
    for u in units:
        plain = unit_plain(u, version_of_sector2)
        raw = plain[5 * SECT + 24:5 * SECT + 24 + 64]          # the sector's 64-byte digest
        win = plain[2562:2562 + 96]                             # 3-aligned window inside sector 5
        out.append((u, "raw", raw))
        out.append((u, "b64", base64.b64encode(win)))
        out.append((u, "hex", raw[:32].hex().encode()))
    return out


ZERO = bytes(4096)
where = {}


def scan(pid, nd, label):
    hits = {}
    where.clear()
    total = 0
    with open(f"/proc/{pid}/maps") as f:
        maps = f.read().splitlines()
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem:
        for line in maps:
            m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+) \S+ \S+ \S+\s*(.*)", line)
            if not m:
                continue
            lo, hi, perms, name = int(m.group(1), 16), int(m.group(2), 16), m.group(3), m.group(4)
            if "r" not in perms or name in ("[vvar]", "[vsyscall]", "[vdso]"):
                continue
            if hi - lo > (1 << 30):
                continue
            try:
                mem.seek(lo)
                blob = mem.read(hi - lo)
            except (OSError, ValueError, OverflowError):
                continue
            # keep only runs of pages that are not all zero (most of the
            # address space is untouched stack/arena reservation)
            runs, start = [], None
            for off in range(0, len(blob), 4096):
                zero = blob[off:off + 4096] == ZERO[:len(blob) - off if len(blob) - off < 4096 else 4096]
                if zero and start is not None:
                    runs.append(blob[start:off]); start = None
                elif not zero and start is None:
                    start = off
            if start is not None:
                runs.append(blob[start:])
            blob = b"\0".join(runs)
            total += len(blob)
            for u, kind, needle in nd:
                c = blob.count(needle)
                if c:
                    key = (kind, name or "anon", perms)
                    hits[key] = hits.get(key, 0) + c
                    where.setdefault(key, []).append((u, hex(lo)))
    print(f"   scan[{label}]: {total >> 20} MiB of non-zero pages scanned; hits: {hits or 'none'}")
    for key, places in where.items():
        print(f"      {key}: units {sorted(set(u for u, _ in places))[:20]} in mappings {sorted(set(m for _, m in places))[:6]}")
    return hits


problems = []
try:
    v.create()
    v.start()
    h = rp.connect(v.sock)
    for u in range(N):
        h.pwrite(unit_plain(u), u * UNIT)
    h.flush(); h.shutdown()
    assert v.term() == 0
    # a fresh process that has never seen this plaintext
    v.start()
    pid = v.proc.pid
    h = rp.connect(v.sock)
    nd = needles(range(N))
    base = scan(pid, nd, "fresh process, before any I/O")
    if base:
        problems.append(f"baseline not clean: {base}")

    # reads of one sector per unit
    for u in range(N):
        got = h.pread(SECT, u * UNIT + 3 * SECT)
        assert got == rp.pattern(u * UNIT + 3 * SECT, SECT, 1)
    time.sleep(args.idle)
    r = scan(pid, nd, f"after {N} one-sector reads, idle {args.idle}s")
    if r:
        problems.append(f"after reads: {r}")

    # sub-unit writes (read-modify-write of the whole unit through the provider)
    for u in range(N):
        h.pwrite(rp.pattern(u * UNIT + 2 * SECT, SECT, 2), u * UNIT + 2 * SECT, nbd.CMD_FLAG_FUA)
    time.sleep(args.idle)
    w = scan(pid, needles(range(N), 2), f"after {N} one-sector FUA writes, idle {args.idle}s")
    if w:
        problems.append(f"after writes: {w}")

    # heavier, concurrent traffic then idle
    done = []
    for rnd in range(4):
        for u in range(N):
            buf = nbd.Buffer(SECT)
            h.aio_pread(buf, u * UNIT + 3 * SECT, completion=lambda e, d=done: d.append(1) or 1)
        t_round = time.monotonic()
        while len(done) < (rnd + 1) * N and time.monotonic() - t_round < 30:
            h.poll(100)
        if len(done) < (rnd + 1) * N:
            import json, subprocess, collections
            print(f"   HANG: round {rnd}: {len(done) - rnd * N}/{N} reads completed after 30 s; libnbd in flight {h.aio_in_flight()}")
            st = json.loads(v.maki("status", v.cfg, "--timeout", "10").stdout)["data"]
            print("   status crypto:", {k: st["crypto"][k] for k in ("inflight_batches", "pending_items", "pending_bytes", "batches_total", "batched_items_total")}, st["crypto"]["endpoints"])
            m = v.maki("metrics", v.cfg, "--timeout", "10").stdout
            for line in m.splitlines():
                if any(k in line for k in ("maki_active_requests", "maki_admission_slots", "maki_plaintext_bytes", "maki_requests_", "maki_active_callbacks")):
                    print("     ", line.strip())
            print("   server calls", beh.calls, beh.items)
            out = subprocess.run(["gdb", "-p", str(pid), "-batch", "-ex", "thread apply all bt 14"], capture_output=True, text=True, timeout=180).stdout
            open(os.path.join(rp.HERE, "logs", f"memscan-hang-{transport}-gdb.txt"), "w").write(out)
            tops = collections.Counter()
            for block in out.split("\nThread ")[1:]:
                frames = [l for l in block.splitlines() if l.startswith("#")]
                sig = " <- ".join(f.split(" in ")[-1].split(" (")[0][:50] for f in frames[1:6])
                tops[sig] += 1
            for sig, cnt in tops.most_common(8):
                print(f"   {cnt:3} threads: {sig}")
            problems.append("HANG in concurrent reads")
            raise RuntimeError("hang")
    time.sleep(args.idle)
    c = scan(pid, needles(range(N), 2), f"after {4 * N} concurrent reads, idle {args.idle}s")
    if c:
        problems.append(f"after concurrent reads: {c}")
    st = v.maki("status", v.cfg, "--timeout", "10").stdout
    print("   scheduler idle:", '"inflight_batches": 0' in st, '"pending_items": 0' in st)
    h.shutdown()
    print("   term", v.term())
except Exception as e:
    import traceback; traceback.print_exc()
    problems.append(repr(e))
    print(v.read_log()[-1500:])
finally:
    v.cleanup(); srv.stop()
print(("RESIDUE " if problems else "CLEAN ") + transport + (" tls" if args.tls else " plain"))
for p in problems:
    print("  -", p)
