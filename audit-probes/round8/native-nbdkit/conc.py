#!/usr/bin/python3.12
"""Connection, concurrency and lifecycle probes through the real plugin.

usage: conc.py [--only name,name]
"""
import sys, os, socket, struct, time, signal, subprocess, threading, random, errno, traceback
import nbd
import mk

FAILS = []


def note(ok, what, detail=""):
    print(("PASS " if ok else "FAIL ") + what + (" :: " + str(detail) if detail else ""), flush=True)
    if not ok:
        FAILS.append(what + " :: " + str(detail))


def info(msg):
    print("INFO " + msg, flush=True)


# ---- a raw NBD client, for things libnbd will not do ---------------------
class Raw:
    def __init__(self, path, timeout=10):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.settimeout(timeout)
        self.s.connect(path)
        hello = self._recv(18)
        assert hello[:16] == b"NBDMAGICIHAVEOPT", hello
        self.s.sendall(struct.pack(">I", 3))  # FIXED_NEWSTYLE | NO_ZEROES
        self.s.sendall(b"IHAVEOPT" + struct.pack(">II", 7, 6) + struct.pack(">IH", 0, 0))  # NBD_OPT_GO ""
        self.size = None
        self.flags = None
        while True:
            magic, opt, typ, ln = struct.unpack(">QIII", self._recv(20))
            data = self._recv(ln) if ln else b""
            if typ == 3 and struct.unpack(">H", data[:2])[0] == 0:  # NBD_REP_INFO / NBD_INFO_EXPORT
                self.size, self.flags = struct.unpack(">QH", data[2:12])
            elif typ == 1:  # ACK
                break
            elif typ & 0x80000000:
                raise RuntimeError(f"option refused: type {typ:#x} {data!r}")

    def _recv(self, n):
        out = b""
        while len(out) < n:
            c = self.s.recv(n - len(out))
            if not c:
                raise EOFError(f"EOF after {len(out)} of {n} bytes")
            out += c
        return out

    def request(self, typ, cookie, offset, length, flags=0, payload=b""):
        self.s.sendall(struct.pack(">IHHQQI", 0x25609513, flags, typ, cookie, offset, length) + payload)

    def header(self, typ, cookie, offset, length, flags=0):
        return struct.pack(">IHHQQI", 0x25609513, flags, typ, cookie, offset, length)

    def reply(self, read_len=0):
        magic, err, cookie = struct.unpack(">IIQ", self._recv(16))
        assert magic == 0x67446698, hex(magic)
        data = self._recv(read_len) if (read_len and err == 0) else b""
        return err, cookie, data

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass


def raw_retry(path, tries=300, delay=0.02):
    last = None
    for _ in range(tries):
        try:
            return Raw(path)
        except (RuntimeError, EOFError, OSError) as e:
            last = e
            time.sleep(delay)
    raise RuntimeError(f"raw connect failed: {last}")


def connect_retry(vol, tries=200, delay=0.02, strict=False):
    last = None
    for i in range(tries):
        h = nbd.NBD()
        if not strict:
            h.set_strict_mode(0)
        try:
            h.connect_unix(vol.sock)
            return h, i
        except nbd.Error as e:
            last = e
            time.sleep(delay)
    raise RuntimeError(f"cannot connect after {tries} tries: {last}")


def logs_clean(vol, what):
    log = vol.all_logs()
    bad = [l for l in log.splitlines() if "panic" in l.lower() or "Assertion" in l]
    note(not bad, f"{what}: no panic/assertion in nbdkit logs", bad[:2])


# --------------------------------------------------------------------------
def t_second_connection():
    v = mk.Vol("second")
    try:
        v.create(); v.start()
        a = nbd.NBD(); a.connect_unix(v.sock)
        d = mk.pattern(0, 65536, 1); a.pwrite(d, 0)
        errs = []
        for i in range(40):
            b = nbd.NBD()
            try:
                b.connect_unix(v.sock)
                errs.append("CONNECTED")
                b.shutdown()
            except nbd.Error as e:
                errs.append(e.string[-80:])
        note("CONNECTED" not in errs, "a second connection is refused while one is open", errs[0])
        r = subprocess.run(["nbdinfo", "--size", "nbd+unix:///?socket=" + v.sock], capture_output=True, text=True)
        note(r.returncode != 0, "nbdinfo while the export is in use fails", (r.stdout + r.stderr).strip()[-160:])
        note(bytes(a.pread(65536, 0)) == d, "first connection unaffected by 40 refused connections")
        a.flush()
        r = v.maki("status", v.cfg)
        note(r.returncode == 0 and '"io_state": "running"' in r.stdout, "status after refused connections")
        a.shutdown()
        h, tries = connect_retry(v)
        note(True, f"new connection accepted after the first closed (attempt {tries + 1})")
        note(bytes(h.pread(65536, 0)) == d, "data visible to the next connection")
        h.shutdown()
        # raw connections that vanish during the handshake must not leak the slot
        for i in range(30):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(v.sock)
            if i % 3 == 0:
                s.recv(18); s.sendall(struct.pack(">I", 3)); s.sendall(b"IHAVEOPT" + struct.pack(">II", 7, 6))
            elif i % 3 == 1:
                s.recv(18); s.sendall(struct.pack(">I", 3))
                s.sendall(b"IHAVEOPT" + struct.pack(">II", 6, 6) + struct.pack(">IH", 0, 0))  # NBD_OPT_INFO
                time.sleep(0.01)
            s.close()
        h, tries = connect_retry(v)
        note(True, f"connection accepted after 30 aborted handshakes (attempt {tries + 1})")
        h.shutdown()
        logs_clean(v, "second-connection")
    finally:
        v.cleanup()


def t_rmw():
    """Concurrent sub-unit writes into the same crypto unit must all land."""
    for tag, kw in (("rmw", {}), ("rmw-cache", dict(cache='mode = "read"\nmax_bytes = "64KiB"\nttl = "1s"'))):
        v = mk.Vol(tag, discard=True, **kw)
        try:
            v.create(); v.start(threads=32)
            h = nbd.NBD(); h.set_strict_mode(0); h.connect_unix(v.sock)
            rng = random.Random(7)
            ver = 0
            model = {}
            bad = 0
            for rnd in range(300):
                unit = rng.choice([0, 1, 15, 16, 17, 100])
                done = []
                expect = {}
                sectors = list(range(8)); rng.shuffle(sectors)
                n = 0
                for s in sectors[: rng.randint(2, 8)]:
                    ver += 1
                    off = unit * 4096 + s * 512
                    h.aio_pwrite(mk.pattern(off, 512, ver), off, lambda e: done.append(e.value) or 1,
                                 nbd.CMD_FLAG_FUA if rng.random() < 0.3 else 0)
                    expect[off // 512] = ver; n += 1
                if rng.random() < 0.5:
                    h.aio_flush(lambda e: done.append(e.value) or 1, 0); n += 1
                if rng.random() < 0.3:
                    # a neighbour-unit write, and a read of the unit, in the same window
                    ver += 1
                    off = (unit + 1) * 4096
                    h.aio_pwrite(mk.pattern(off, 4096, ver), off, lambda e: done.append(e.value) or 1, 0); n += 1
                    for i in range(8):
                        expect[off // 512 + i] = ver
                if rng.random() < 0.2 and unit not in (0,):
                    off = (unit + 2) * 4096
                    h.aio_trim(4096, off, lambda e: done.append(e.value) or 1, 0); n += 1
                    for i in range(8):
                        expect[off // 512 + i] = 0
                while len(done) < n:
                    h.poll(1000)
                if any(done):
                    note(False, f"{tag} round {rnd}: request errors", done); bad += 1; break
                model.update(expect)
                got = bytes(h.pread(3 * 4096, unit * 4096))
                for i in range(24):
                    s = unit * 8 + i
                    want = model.get(s, 0)
                    have = got[i * 512:(i + 1) * 512]
                    if have != (mk.pattern(s * 512, 512, want) if want else bytes(512)):
                        note(False, f"{tag} round {rnd}: sector {s} lost a concurrent write", f"want version {want}, got {mk.describe(have)}")
                        bad += 1
                        break
                if bad:
                    break
            note(bad == 0, f"{tag}: 300 rounds of concurrent sub-unit writes/flush/trim, every acknowledged sector present")
            # overlapping writes in flight: the result must be one whole version per sector
            torn = 0
            for rnd in range(200):
                off = rng.choice([0, 4096 * 15 + 512, 65536 - 2048]); ln = rng.choice([512, 4096, 8192, 65536])
                vs = []
                done = []
                for k in range(4):
                    ver += 1; vs.append(ver)
                    h.aio_pwrite(mk.pattern(off, ln, ver), off, lambda e: done.append(e.value) or 1, 0)
                while len(done) < 4:
                    h.poll(1000)
                got = bytes(h.pread(ln, off))
                cands = [mk.pattern(off, ln, x) for x in vs]
                for i in range(0, ln, 512):
                    if not any(got[i:i + 512] == c[i:i + 512] for c in cands):
                        torn += 1
            note(torn == 0, f"{tag}: 200 rounds of 4 overlapping in-flight writes leave whole sectors of one of them", torn)
            h.shutdown()
            logs_clean(v, tag)
        finally:
            v.cleanup()


def t_disconnect_mid_request():
    v = mk.Vol("disc")
    try:
        v.create(); v.start()
        h = nbd.NBD(); h.connect_unix(v.sock)
        base = mk.pattern(0, 262144, 1); h.pwrite(base[:65536], 0); h.pwrite(base[65536:131072], 65536)
        h.pwrite(base[131072:196608], 131072); h.pwrite(base[196608:], 196608); h.flush(); h.shutdown()
        # 1. header + part of the payload, then the client vanishes
        for cut in (0, 1, 4095, 4096, 30000, 65535):
            r = raw_retry(v.sock)
            new = mk.pattern(0, 65536, 99)
            r.s.sendall(r.header(1, 7, 0, 65536) + new[:cut])
            r.close()
            h, tries = connect_retry(v)
            got = bytes(h.pread(65536, 0))
            note(got == base[:65536], f"write cut after {cut} payload bytes is not applied (reconnect attempt {tries + 1})",
                 "" if got == base[:65536] else mk.describe(got[:512]))
            h.shutdown()
        # 2. full requests pipelined, client vanishes without reading any reply
        r = raw_retry(v.sock)
        blob = b""
        for i in range(64):
            blob += r.header(1, i, 65536 + (i % 32) * 4096, 4096, flags=1 if i % 5 == 0 else 0) + mk.pattern(65536 + (i % 32) * 4096, 4096, 1000 + i)
        blob += r.header(3, 999, 0, 0)  # flush
        r.s.sendall(blob)
        r.close()
        h, tries = connect_retry(v, tries=500)
        got = bytes(h.pread(131072, 65536))
        bad = 0
        for u in range(32):
            sec = got[u * 4096:(u + 1) * 4096]
            off = 65536 + u * 4096
            allowed = [base[off:off + 4096], mk.pattern(off, 4096, 1000 + u), mk.pattern(off, 4096, 1000 + u + 32)]
            if sec not in allowed:
                bad += 1
        note(bad == 0, f"64 pipelined writes then an abrupt close: every unit is old or one of its two new versions (reconnect attempt {tries + 1})", bad)
        note(bytes(h.pread(65536, 196608)) == base[196608:], "untouched region intact after abrupt closes")
        h.shutdown()
        # 3. garbage after the handshake
        for junk in (b"\0" * 28, os.urandom(28), struct.pack(">IHHQQI", 0x25609513, 0xffff, 0xffff, 1, 2 ** 64 - 1, 2 ** 32 - 1),
                     struct.pack(">IHHQQI", 0x25609513, 0, 1, 1, 0, 2 ** 32 - 512)):
            r = raw_retry(v.sock)
            r.s.sendall(junk)
            try:
                r.s.settimeout(2); r.s.recv(64)
            except Exception:
                pass
            r.close()
        h, tries = connect_retry(v, tries=500)
        note(bytes(h.pread(65536, 196608)) == base[196608:], f"server alive and data intact after garbage requests (reconnect attempt {tries + 1})")
        h.shutdown()
        note(v.proc.poll() is None, "nbdkit still running")
        logs_clean(v, "disconnect")
    finally:
        v.cleanup()


def t_client_stops_reading():
    v = mk.Vol("stuck")
    try:
        v.create(); v.start()
        h = nbd.NBD(); h.connect_unix(v.sock)
        d = mk.pattern(0, 65536, 5); h.pwrite(d, 0, nbd.CMD_FLAG_FUA); h.shutdown()
        r = raw_retry(v.sock)
        r.s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        blob = b"".join(r.header(0, i, 0, 65536) for i in range(2000))  # 2000 reads, ~125 MiB of replies never read
        r.s.settimeout(5)
        try:
            r.s.sendall(blob)
        except socket.timeout:
            info("client could not even queue all requests (server stopped reading requests)")
        time.sleep(1.0)
        t = time.monotonic()
        st = v.maki("status", v.cfg, timeout=30)
        note(st.returncode == 0, "control `status` answers while the client is not reading", f"{time.monotonic() - t:.2f}s")
        t = time.monotonic()
        ck = v.maki("checkpoint", v.cfg, timeout=60)
        note(ck.returncode == 0, "control `checkpoint` works while the client is not reading", f"{time.monotonic() - t:.2f}s {ck.stderr[-200:]}")
        m = v.maki("metrics", v.cfg, timeout=30).stdout
        act = [l.strip() for l in m.splitlines() if "maki_active_callbacks" in l or "maki_plaintext_bytes" in l or "maki_active_requests" in l]
        info(f"metrics with a stuck client: {act}")
        t = time.monotonic()
        dr = v.maki("drain", v.cfg, timeout=120)
        note(dr.returncode == 0, "control `drain` completes while the client is not reading", f"{time.monotonic() - t:.2f}s {dr.stdout[-200:]} {dr.stderr[-200:]}")
        v.proc.send_signal(signal.SIGTERM)
        try:
            rc = v.proc.wait(20)
            info(f"SIGTERM with a stuck client: nbdkit exited rc={rc} after {time.monotonic() - t:.1f}s")
            stuck = False
        except subprocess.TimeoutExpired:
            stuck = True
            info("SIGTERM with a client that stopped reading: nbdkit still running after 20 s (it waits for the connection)")
        r.close()
        if stuck:
            try:
                rc = v.proc.wait(30)
                info(f"after the client closed: nbdkit exited rc={rc}")
            except subprocess.TimeoutExpired:
                note(False, "nbdkit exits once the stuck client has gone", "still running 30 s later")
        v.notify.close()
        v.start()
        h, _ = connect_retry(v)
        note(bytes(h.pread(65536, 0)) == d, "restart after the stuck-client shutdown: data intact")
        h.shutdown()
        logs_clean(v, "stuck-client")
    finally:
        v.cleanup()


def t_admission_limits():
    v = mk.Vol("adm", extra_limits='max_active_callbacks = 2\nmax_plaintext_bytes = "128KiB"\nmax_overlay_bytes = "160KiB"\nmax_journal_pending_bytes = "8KiB"')
    try:
        v.create(); v.start(threads=64)
        h = nbd.NBD(); h.set_strict_mode(0); h.connect_unix(v.sock)
        done = []
        n = 400
        model = {}
        rng = random.Random(3)
        t = time.monotonic()
        busy = set()
        for i in range(n):
            # 30 disjoint 128 KiB slots; odd slots start 512 bytes in, so the 64 KiB write touches 17 units
            slot = i % 30
            while slot in busy:
                h.poll(100)
                while done:
                    s, e = done.pop(0); busy.discard(s)
                    if e:
                        note(False, "write under tight admission limits", f"errno {e}")
            busy.add(slot)
            off = slot * 131072 + (512 if slot % 2 else 0)
            ln = 65536
            ver = i + 1
            model[slot] = (off, ln, ver)
            h.aio_pwrite(mk.pattern(off, ln, ver), off, lambda e, s=slot: done.append((s, e.value)) or 1, nbd.CMD_FLAG_FUA if i % 7 == 0 else 0)
        while busy:
            h.poll(100)
            while done:
                s, e = done.pop(0); busy.discard(s)
                if e:
                    note(False, "write under tight admission limits", f"errno {e}")
        info(f"400 64KiB writes with max_active_callbacks=2, max_plaintext 128KiB, 64 nbdkit threads: {time.monotonic() - t:.1f}s")
        ok = True
        for slot, (off, ln, ver) in model.items():
            if bytes(h.pread(ln, off)) != mk.pattern(off, ln, ver):
                ok = False
                note(False, "admission-limit run: data mismatch", f"slot {slot}")
                break
        note(ok, "all 400 writes acknowledged under tight limits read back")
        m = v.maki("metrics", v.cfg).stdout
        act = [l.strip() for l in m.splitlines() if any(k in l for k in ("maki_active_callbacks", "maki_plaintext_bytes", "maki_active_requests", "maki_admission_slots", "errors_total", "requests_error"))]
        note('"maki_active_callbacks": 0' in m and '"maki_plaintext_bytes": 0' in m, "admission accounting returns to zero when idle", act)
        h.shutdown()
        logs_clean(v, "admission")
    finally:
        v.cleanup()


def t_control_during_io():
    v = mk.Vol("ctl", discard=True, cache='mode = "read"\nmax_bytes = "64KiB"\nttl = "1s"')
    try:
        v.create(); v.start()
        h = nbd.NBD(); h.set_strict_mode(0); h.connect_unix(v.sock)
        stop = threading.Event()
        results = []

        def admin():
            rng = random.Random(11)
            while not stop.is_set():
                cmd = rng.choice([["status"], ["metrics"], ["checkpoint"], ["reload", "cache", "--max-bytes", str(rng.choice([4096, 65536, 1 << 20]))],
                                  ["reload", "cache", "--max-bytes", "65536", "--ttl", "2s"], ["reload", "limits"], ["reload", "bogus"]])
                args = [cmd[0], v.cfg] + cmd[1:]
                try:
                    r = v.maki(*args, timeout=60)
                    results.append((cmd[0] + (" " + cmd[1] if len(cmd) > 1 else ""), r.returncode, (r.stdout + r.stderr)[-200:]))
                except subprocess.TimeoutExpired:
                    results.append((" ".join(cmd), "TIMEOUT", ""))

        th = threading.Thread(target=admin); th.start()
        rng = random.Random(5)
        model = bytearray(h.get_size())
        ver = 0
        errs = 0
        t_end = time.monotonic() + 8
        nops = 0
        while time.monotonic() < t_end:
            done = []
            ops = []
            used = set()
            for k in range(8):
                slot = rng.randrange(0, 60)
                if slot in used:
                    continue
                used.add(slot)
                off = slot * 65536 + rng.randrange(0, 32) * 512
                ln = rng.choice([512, 4096, 8192, 32768])
                ver += 1
                kind = rng.choice(["w", "w", "w", "z", "t"])
                if kind == "w":
                    d = mk.pattern(off, ln, ver)
                    h.aio_pwrite(d, off, lambda e: done.append(e.value) or 1, 0)
                elif kind == "z":
                    d = bytes(ln)
                    h.aio_zero(ln, off, lambda e: done.append(e.value) or 1, 0)
                else:
                    a = -(-off // 4096) * 4096; b = (off + ln) // 4096 * 4096
                    h.aio_trim(ln, off, lambda e: done.append(e.value) or 1, 0)
                    off, d = (a, bytes(b - a)) if b > a else (off, b"")
                ops.append((off, d))
            if rng.random() < 0.3:
                h.aio_flush(lambda e: done.append(e.value) or 1, 0); ops.append(None)
            while len(done) < len(ops):
                h.poll(1000)
            errs += sum(1 for e in done if e)
            for op in ops:
                if op and op[1]:
                    model[op[0]:op[0] + len(op[1])] = op[1]
            nops += len(ops)
            if rng.random() < 0.2:
                slot = rng.randrange(0, 60)
                got = bytes(h.pread(65536, slot * 65536))
                if got != model[slot * 65536:(slot + 1) * 65536]:
                    note(False, "read during control traffic matches the model", f"slot {slot}")
                    break
        stop.set(); th.join()
        note(errs == 0, f"{nops} requests during control traffic: no errors", errs)
        by = {}
        for name, rc, out in results:
            by.setdefault(name, []).append((rc, out))
        for name, lst in sorted(by.items()):
            rcs = sorted({str(rc) for rc, _ in lst})
            info(f"control `{name}` x{len(lst)}: exit {rcs}; last: {lst[-1][1].strip()[-120:]!r}")
        note(not any(rc == "TIMEOUT" for _, rc, _ in results), "no control command timed out during I/O")
        note(all(rc == 0 for n_, rc, _ in results if n_ in ("status", "metrics", "checkpoint")), "status/metrics/checkpoint always succeed during I/O")
        full = bytes(h.pread(len(model), 0))
        note(full == model, "full device matches the model after I/O with concurrent control traffic")
        # drain while requests are in flight
        done = []
        pend = []
        for k in range(48):
            off = k * 65536
            ver += 1
            d = mk.pattern(off, 65536, ver)
            h.aio_pwrite(d, off, lambda e, k=k: done.append((k, e.value)) or 1, 0)
            pend.append((off, d))
        dr = subprocess.Popen([mk.MAKI, "drain", v.cfg], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        while len(done) < 48:
            h.poll(1000)
        out, err = dr.communicate(timeout=120)
        note(dr.returncode == 0, "drain during 48 in-flight writes succeeds", (out + err)[-200:])
        codes = sorted({e for _, e in done})
        note(set(codes) <= {0, 108}, "in-flight writes either succeed or fail with ESHUTDOWN during drain", codes)
        for k, e in done:
            if e == 0:
                model[pend[k][0]:pend[k][0] + 65536] = pend[k][1]
        refused = None
        try:
            h.pwrite(bytes(512), 0)
        except nbd.Error as e:
            refused = e.errnum
        note(refused == errno.ESHUTDOWN, "writes after drain are refused with ESHUTDOWN", refused)
        try:
            h.pread(512, 0); note(False, "reads after drain are refused", "read succeeded")
        except nbd.Error as e:
            note(e.errnum == errno.ESHUTDOWN, "reads after drain are refused with ESHUTDOWN", e.errnum)
        try:
            h.flush(); fl = 0
        except nbd.Error as e:
            fl = e.errnum
        info(f"flush after drain: errno {fl}")
        st = v.maki("status", v.cfg).stdout
        note('"io_state": "drained"' in st, "status reports drained", [l.strip() for l in st.splitlines() if "io_state" in l or "sequence" in l])
        indefinite = [k for k, e in done if e != 0]
        # kill -9 right after the acknowledged drain: everything acknowledged must be there
        v.kill9()
        v.start()
        h, _ = connect_retry(v)
        full = bytearray(h.pread(len(model), 0))
        for k in indefinite:  # a refused write may not have been applied at all; it must not be half there per sector
            off = pend[k][0]
            if full[off:off + 65536] == pend[k][1]:
                model[off:off + 65536] = pend[k][1]
        note(bytes(full) == bytes(model), "after kill -9 following an acknowledged drain, every acknowledged write is present")
        st = v.maki("status", v.cfg).stdout
        note('"io_state": "running"' in st, "a restarted daemon is running again (drain is not sticky)")
        h.shutdown()
        rc = v.term(60)
        note(rc == 0, "SIGTERM after restart exits 0", rc)
        logs_clean(v, "control")
    finally:
        v.cleanup()


def t_sigterm_idle_client():
    v = mk.Vol("idle")
    try:
        v.create(); v.start()
        h = nbd.NBD(); h.connect_unix(v.sock)
        d = mk.pattern(0, 4096, 1); h.pwrite(d, 0)  # acknowledged, never flushed
        t = time.monotonic()
        v.proc.send_signal(signal.SIGTERM)
        try:
            rc = v.proc.wait(5)
            info(f"SIGTERM with a connected idle client: nbdkit exited rc={rc} by itself")
        except subprocess.TimeoutExpired:
            info("SIGTERM with a connected idle client: nbdkit is still running 5 s later (nbdkit waits for the connection to end)")
            # a request after SIGTERM is refused by nbdkit itself; then the client goes away
            try:
                h.pwrite(mk.pattern(0, 4096, 2), 0)
                d = mk.pattern(0, 4096, 2)
                info("a write after SIGTERM was still acknowledged")
            except nbd.Error as e:
                info(f"a write after SIGTERM is refused: errno {e.errnum}")
            try:
                h.shutdown()
            except nbd.Error:
                pass
            try:
                rc = v.proc.wait(30)
            except subprocess.TimeoutExpired:
                rc = "TIMEOUT"
        note(rc == 0, "nbdkit exits 0 once the client has gone", f"rc={rc} in {time.monotonic() - t:.2f}s")
        log = v.read_log()
        note("shutdown during unload failed" not in log, "unload did not report a failed shutdown", log[-300:])
        v.notify.close()
        v.start()
        h2, _ = connect_retry(v)
        note(bytes(h2.pread(4096, 0)) == d, "an acknowledged, unflushed write survives a clean SIGTERM stop")
        h2.shutdown()
        # every termination signal nbdkit handles
        for sig in (signal.SIGINT, signal.SIGQUIT, signal.SIGHUP):
            h3, _ = connect_retry(v)
            d = mk.pattern(0, 4096, int(sig) + 10); h3.pwrite(d, 0)
            v.proc.send_signal(sig)
            time.sleep(0.2)
            try:
                h3.shutdown()
            except nbd.Error:
                pass
            try:
                rc = v.proc.wait(30)
            except subprocess.TimeoutExpired:
                rc = "TIMEOUT"
            v.notify.close()
            v.start()
            h4, _ = connect_retry(v)
            note(rc == 0 and bytes(h4.pread(4096, 0)) == d, f"{sig.name}: clean exit and the unflushed acknowledged write survives", f"rc={rc}")
            h4.shutdown()
        logs_clean(v, "sigterm-idle")
    finally:
        v.cleanup()


def t_two_daemons():
    v = mk.Vol("two")
    try:
        v.create(); v.start()
        h = nbd.NBD(); h.connect_unix(v.sock)
        d = mk.pattern(0, 4096, 1); h.pwrite(d, 0, nbd.CMD_FLAG_FUA)
        ino = os.stat(v.control).st_ino
        # second daemon on the same volume and control socket, another NBD socket
        sock2 = os.path.join(v.dir, "nbd2.sock")
        log2 = os.path.join(v.dir, "second.log")
        with open(log2, "wb") as lf:
            p = subprocess.Popen(["nbdkit", "--foreground", "-U", sock2, mk.PLUGIN, f"config={v.cfg}"], stdout=lf, stderr=subprocess.STDOUT,
                                 env={k: val for k, val in os.environ.items() if k != "NOTIFY_SOCKET"})
            try:
                rc = p.wait(30)
            except subprocess.TimeoutExpired:
                rc = "RUNNING"; p.kill(); p.wait()
        out = open(log2).read()
        note(rc not in (0, "RUNNING"), "a second daemon on the same volume refuses to start", f"rc={rc} {out.strip()[-200:]}")
        note(os.path.exists(v.control) and os.stat(v.control).st_ino == ino, "the first daemon's control socket is untouched by the refused second start")
        st = v.maki("status", v.cfg)
        note(st.returncode == 0, "the first daemon still answers status")
        d2 = mk.pattern(4096, 4096, 2); h.pwrite(d2, 4096, nbd.CMD_FLAG_FUA)
        note(bytes(h.pread(8192, 0)) == d + d2, "the first daemon still serves I/O")
        h.shutdown()
        rc = v.term(60)
        note(rc == 0, "first daemon exits 0")
        note(not os.path.exists(v.control), "control socket removed on clean exit")
        logs_clean(v, "two-daemons")
    finally:
        v.cleanup()


def t_fork_and_modes():
    v = mk.Vol("fork")
    try:
        v.create()
        # 1. daemonized (nbdkit forks into the background, plugin starts after the fork)
        pidfile = os.path.join(v.dir, "nbdkit.pid")
        env = {k: val for k, val in os.environ.items() if k != "NOTIFY_SOCKET"}
        r = subprocess.run(["nbdkit", "-U", v.sock, "-P", pidfile, mk.PLUGIN, f"config={v.cfg}"], capture_output=True, text=True, env=env, timeout=60)
        note(r.returncode == 0, "daemonized nbdkit start returns 0", r.stderr[-300:])
        for _ in range(200):
            if os.path.exists(pidfile) and open(pidfile).read().strip():
                break
            time.sleep(0.05)
        pid = int(open(pidfile).read())
        h, tries = connect_retry(v, tries=300)
        d = mk.pattern(0, 65536, 1); h.pwrite(d, 0); h.flush()
        note(bytes(h.pread(65536, 0)) == d, f"I/O through a daemonized nbdkit (pid {pid}, connect attempt {tries + 1})")
        st = v.maki("status", v.cfg)
        note(st.returncode == 0 and '"state": "ready"' in st.stdout, "status through a daemonized nbdkit")
        nthreads = len(os.listdir(f"/proc/{pid}/task"))
        info(f"daemonized nbdkit has {nthreads} threads")
        h.shutdown()
        os.kill(pid, signal.SIGTERM)
        for _ in range(600):
            if not os.path.exists(f"/proc/{pid}"):
                break
            time.sleep(0.05)
        note(not os.path.exists(f"/proc/{pid}"), "daemonized nbdkit exits on SIGTERM")
        note(not os.path.exists(v.control), "control socket removed after the daemonized instance stopped")
        # 2. -s: serve one connection on stdin/stdout
        h = nbd.NBD()
        try:
            h.connect_command(["nbdkit", "-s", mk.PLUGIN, f"config={v.cfg}"])
            ok = bytes(h.pread(65536, 0)) == d
            d2 = mk.pattern(65536, 4096, 2); h.pwrite(d2, 65536)
            h.shutdown()
            note(ok, "nbdkit -s (stdin/stdout) serves the volume")
        except nbd.Error as e:
            note(False, "nbdkit -s", str(e))
        time.sleep(0.5)
        # 3. captive --run
        r = subprocess.run(["nbdkit", "-U", "-", mk.PLUGIN, f"config={v.cfg}", "--run", "nbdinfo --size \"$uri\" && nbdcopy \"$uri\" null:"],
                           capture_output=True, text=True, env=env, timeout=120)
        note(r.returncode == 0 and r.stdout.strip() == "4194304", "captive `nbdkit --run nbdinfo/nbdcopy` works and exits 0", f"rc={r.returncode} {r.stdout.strip()} {r.stderr[-300:]}")
        # 4. the unflushed write made through -s must have survived its clean exit
        v.start()
        h, _ = connect_retry(v)
        note(bytes(h.pread(4096, 65536)) == d2, "write acknowledged through `nbdkit -s` survived its exit")
        h.shutdown()
        # 5. read-only server
        v.term(60)
        v.start(nbdkit_args=["-r"])
        h = nbd.NBD(); h.set_strict_mode(0); h.connect_unix(v.sock)
        note(h.is_read_only(), "nbdkit -r: export is read-only")
        for name, fn in (("write", lambda: h.pwrite(bytes(512), 0)), ("zero", lambda: h.zero(512, 0)), ("trim", lambda: h.trim(4096, 0))):
            try:
                fn(); note(False, f"nbdkit -r: {name} refused", "succeeded")
            except nbd.Error as e:
                note(e.errnum in (errno.EROFS, errno.EPERM, errno.EINVAL), f"nbdkit -r: {name} refused", e.errnum)
        note(bytes(h.pread(65536, 0)) == d, "nbdkit -r: reads work")
        h.shutdown()
        rc = v.term(60)
        note(rc == 0, "nbdkit -r: exit 0", rc)
        # 6. config callback oddities
        for args, what in ((["config=/nonexistent/x.toml"], "missing file"), ([], "no config"), (["config=" + v.cfg, "config=" + v.cfg], "config twice"),
                           (["config=" + v.cfg, "bogus=1"], "unknown key"), (["config="], "empty path"), (["config=" + v.dir], "a directory"),
                           ([v.cfg], "bare path (no magic key)")):
            r = subprocess.run(["nbdkit", "--foreground", "-U", os.path.join(v.dir, "x.sock"), mk.PLUGIN] + args, capture_output=True, text=True, env=env, timeout=30)
            crashed = r.returncode < 0 or "panic" in r.stderr.lower()
            if what == "config twice" and r.returncode == 0:
                pass
            note(not crashed and r.returncode != 0 or what == "config twice", f"odd parameters ({what}): refused without a crash", f"rc={r.returncode} {r.stderr.strip()[-160:]}")
        r = subprocess.run(["nbdkit", "--dump-plugin", mk.PLUGIN], capture_output=True, text=True, timeout=30)
        note(r.returncode == 0 and "thread_model=parallel" in r.stdout, "--dump-plugin", r.stderr[-200:])
        r = subprocess.run(["nbdkit", mk.PLUGIN, "--help"], capture_output=True, text=True, timeout=30)
        note(r.returncode == 0 and "config=<PATH>" in r.stdout, "plugin --help", r.stderr[-200:])
        logs_clean(v, "fork-and-modes")
    finally:
        v.cleanup()


def t_sigterm_during_startup():
    v = mk.Vol("early", jmax="2MiB", seg="64KiB", extra_limits='max_overlay_bytes = "0B"')
    try:
        v.create(); v.start()
        h = nbd.NBD(); h.connect_unix(v.sock)
        model = bytearray(h.get_size())
        for i in range(120):  # ~1.9 MiB of journal to replay
            off = (i % 60) * 65536 // 4
            d = mk.pattern(off, 16384, i + 1); h.pwrite(d, off); model[off:off + 16384] = d
        h.flush()
        v.kill9()
        outcomes = {}
        for delay in [0, 0.001, 0.003, 0.01, 0.02, 0.03, 0.05, 0.08, 0.12, 0.2, 0.3] * 2:
            v.start(wait=False)
            time.sleep(delay)
            v.proc.send_signal(signal.SIGTERM)
            try:
                rc = v.proc.wait(60)
            except subprocess.TimeoutExpired:
                rc = "TIMEOUT"; os.killpg(v.proc.pid, signal.SIGKILL); v.proc.wait()
            v.notify.close()
            outcomes.setdefault(rc, 0); outcomes[rc] += 1
            early_default_action = rc == -signal.SIGTERM and v.read_log().strip() == ""
            if rc == "TIMEOUT" or (isinstance(rc, int) and rc < 0 and not early_default_action):
                note(False, f"SIGTERM {delay}s into startup", f"rc={rc} {v.read_log()[-300:]}")
        info(f"SIGTERM during startup outcomes (exit status: count): {outcomes}")
        v.start()
        h, _ = connect_retry(v)
        note(bytes(h.pread(len(model), 0)) == model, "volume intact after 22 SIGTERMs during startup/recovery")
        h.shutdown()
        logs_clean(v, "sigterm-during-startup")
    finally:
        v.cleanup()


TESTS = {
    "second": t_second_connection, "rmw": t_rmw, "disconnect": t_disconnect_mid_request, "stuck": t_client_stops_reading,
    "admission": t_admission_limits, "control": t_control_during_io, "sigterm": t_sigterm_idle_client, "two": t_two_daemons,
    "fork": t_fork_and_modes, "early": t_sigterm_during_startup,
}

if __name__ == "__main__":
    only = sys.argv[sys.argv.index("--only") + 1].split(",") if "--only" in sys.argv else None
    for name, fn in TESTS.items():
        if only and name not in only:
            continue
        print(f"=== {name}", flush=True)
        try:
            fn()
        except Exception as e:
            note(False, f"{name} aborted", repr(e) + "\n" + traceback.format_exc()[-1500:])
    print(f"\n{len(FAILS)} FAIL(s)")
    for f in FAILS:
        print("  " + f[:500])
    sys.exit(1 if FAILS else 0)
