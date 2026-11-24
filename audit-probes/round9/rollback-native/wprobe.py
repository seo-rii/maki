#!/usr/bin/python3.12
"""Round 9 rollback-native: the maki-witness service as a network peer.

  tls      wrong CA, expired client/server certificate, wrong server name, no client
           certificate, TLS 1.2, unlisted certificate, writer attempting admin actions
  slow     silent and half-open peers, authenticated peers that never send a request:
           bound on connections, time per connection, service to a prompt client meanwhile
  fuzz     malformed, oversized and mutated requests from an allow-listed certificate;
           after every batch the server must still answer and hold a valid record

usage: wprobe.py [tls] [slow] [fuzz] [--seed N] [--requests N]
"""
import os, sys, ssl, socket, struct, json, time, random, shutil, tempfile, subprocess, datetime, uuid, threading, argparse
import mk9 as mk, rw

P = argparse.ArgumentParser()
P.add_argument("parts", nargs="*", default=["tls", "slow", "fuzz"])
P.add_argument("--seed", type=int, default=1)
P.add_argument("--requests", type=int, default=6000)
P.add_argument("--keep", action="store_true")
A = P.parse_args()
rng = random.Random(A.seed)
FAILS = []
NOTES = []


def fail(m):
    FAILS.append(m); print("FAIL " + m, flush=True)


def note(m):
    NOTES.append(m); print("  " + m, flush=True)


def make_cert(pki, name, not_before, not_after, server=False, ca_key=None, ca_cert=None):
    """A leaf with arbitrary validity (python cryptography)."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    import ipaddress
    cak = serialization.load_pem_private_key(open(ca_key or pki.ca_key, "rb").read(), None)
    cac = x509.load_pem_x509_certificate(open(ca_cert or pki.ca, "rb").read())
    key = ec.generate_private_key(ec.SECP256R1())
    b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
         .issuer_name(cac.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(not_before).not_valid_after(not_after)
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False))
    if server:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName("witness.test"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
    cert = b.sign(cak, hashes.SHA256())
    crt, kp = os.path.join(pki.dir, name + ".pem"), os.path.join(pki.dir, name + ".key")
    open(crt, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(kp, "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    os.chmod(kp, 0o600)
    return crt, kp


class Wire:
    """One request on one TLS 1.3 connection, as the Rust client does it."""

    def __init__(self, auth, cert=None, key=None, ca=None, name="witness.test", tls12=False, nocert=False):
        self.auth = auth
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if tls12:
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        else:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_verify_locations(ca or auth.pki.ca)
        if not nocert:
            ctx.load_cert_chain(cert or auth.writer_cert, key or auth.writer_key)
        self.ctx, self.name = ctx, name

    def open(self, timeout=10):
        s = socket.create_connection(("127.0.0.1", self.auth.port), timeout=timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return self.ctx.wrap_socket(s, server_hostname=self.name)

    def raw(self, payload, timeout=10, header=None):
        """Send one frame (payload bytes); returns the response frame bytes or raises."""
        t = self.open(timeout)
        try:
            t.sendall((header if header is not None else struct.pack(">I", len(payload))) + payload)
            head = b""
            while len(head) < 4:
                c = t.recv(4 - len(head))
                if not c:
                    raise EOFError("closed before a response")
                head += c
            n = struct.unpack(">I", head)[0]
            body = b""
            while len(body) < n:
                c = t.recv(n - len(body))
                if not c:
                    raise EOFError("closed inside a response")
                body += c
            return body
        finally:
            try:
                t.close()
            except Exception:
                pass

    def call(self, request, rid=None, version=2, timeout=10):
        rid = rid or str(uuid.uuid4())
        body = self.raw(json.dumps({"version": version, "id": rid, "request": request}, separators=(",", ":")).encode(), timeout)
        resp = json.loads(body)
        if resp.get("id") != rid:
            raise RuntimeError(f"response id mismatch: {resp}")
        return resp


def inspect_req():
    return {"operation_id": list(uuid.uuid4().bytes), "expected": None, "action": {"type": "inspect"}}


def healthy(auth, what):
    try:
        r = Wire(auth).call(inspect_req())
    except Exception as e:
        fail(f"{what}: the server no longer answers a valid inspect: {e!r}; log: {auth.read_log()[-600:]}")
        return None
    if r.get("error") is not None or r.get("response") is None:
        fail(f"{what}: the server answers a valid inspect with {r}; log: {auth.read_log()[-600:]}")
        return None
    if auth.proc.poll() is not None:
        fail(f"{what}: maki-witness exited {auth.proc.returncode}")
    return r["response"]


def cli_inspect(auth, base, **kw):
    p = auth.client_config(os.path.join(base, f"c-{rng.randrange(1 << 30)}.toml"), **kw)
    r = subprocess.run([mk.WITNESS, "inspect", p], capture_output=True, text=True, timeout=60)
    return r.returncode, (r.stdout + r.stderr).strip()


def part_tls(base):
    print("== tls")
    auth = rw.Authority(os.path.join(base, "tls"), os.path.join(base, "tls", "state"))
    auth.init(); auth.start()
    now = datetime.datetime.utcnow()
    day = datetime.timedelta(days=1)
    other = rw.Pki(os.path.join(base, "tls", "otherpki"), "otherca")
    oc, ok = other.leaf("writer-other")
    exp_c, exp_k = make_cert(auth.pki, "writer-expired", now - 10 * day, now - day)
    fut_c, fut_k = make_cert(auth.pki, "writer-future", now + day, now + 10 * day)
    unl_c, unl_k = auth.pki.leaf("unlisted")
    cases = [
        ("valid writer", dict(), 0, "identity"),
        ("client certificate from another CA", dict(cert=oc, key=ok), 1, None),
        ("expired client certificate (trusted CA, would be allow-listed by fingerprint)", dict(cert=exp_c, key=exp_k), 1, None),
        ("not-yet-valid client certificate", dict(cert=fut_c, key=fut_k), 1, None),
        ("trusted but unlisted client certificate", dict(cert=unl_c, key=unl_k), 1, "denied"),
        ("server verified against another CA", dict(ca=other.ca), 1, None),
        ("wrong server name", dict(server_name="other.test"), 1, None),
    ]
    # allow-list the expired and future certificates by fingerprint: the validity must still refuse them
    auth.kill9()
    auth.write_config(principals=[(auth.writer_cert, "writer"), (auth.admin_cert, "admin"), (exp_c, "writer"), (fut_c, "admin")])
    auth.start()
    for name, kw, want_rc, needle in cases:
        rc, text = cli_inspect(auth, base, **kw)
        good = (rc == want_rc) and (needle is None or needle in text)
        print(f"  {name}: rc={rc} {text[:160]!r}")
        if not good:
            fail(f"tls: {name}: rc={rc} (want {want_rc}) {text[:300]}")
        if "panicked" in text:
            fail(f"tls: {name}: client panicked: {text[:300]}")
    # raw clients
    for name, kw in (("no client certificate", dict(nocert=True)), ("TLS 1.2 only", dict(tls12=True))):
        try:
            r = Wire(auth, **kw).call(inspect_req(), timeout=8)
            fail(f"tls: {name}: the server answered {r}")
        except Exception as e:
            print(f"  {name}: refused ({type(e).__name__}: {str(e)[:100]})")
    # the unlisted certificate gets a denial bound to its request id, and a writer cannot take over
    r = Wire(auth, cert=unl_c, key=unl_k).call(inspect_req())
    print(f"  unlisted certificate, raw: {r}")
    if r.get("error") != "permission_denied":
        fail(f"tls: unlisted certificate was answered {r}")
    rec = healthy(auth, "tls")
    for action in ({"type": "takeover"}, {"type": "recover_enrollment"}):
        r = Wire(auth).call({"operation_id": list(uuid.uuid4().bytes), "expected": rec, "action": action, "authorization": list(os.urandom(32))})
        print(f"  writer attempts {action['type']}: {r.get('error')}")
        if r.get("error") != "permission_denied":
            fail(f"tls: a writer certificate's {action['type']} was answered {r}")
    # expired SERVER certificate
    auth.kill9()
    sc, sk = make_cert(auth.pki, "server-expired", now - 10 * day, now - day, server=True)
    good_cert, good_key = auth.server_cert, auth.server_key
    auth.server_cert, auth.server_key = sc, sk
    auth.write_config()
    try:
        auth.start()
        rc, text = cli_inspect(auth, base)
        print(f"  expired server certificate: client rc={rc} {text[:160]!r}")
        if rc == 0:
            fail(f"tls: the client accepted an expired server certificate: {text[:200]}")
    except RuntimeError as e:
        print(f"  expired server certificate: serve refused to start: {str(e)[:200]}")
    auth.kill9()
    auth.server_cert, auth.server_key = good_cert, good_key
    if "panic" in auth.read_log().lower():
        fail("tls: panic in the server log: " + auth.read_log()[-400:])


def threads_fds(pid):
    try:
        return len(os.listdir(f"/proc/{pid}/task")), len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return None, None


def part_slow(base):
    print("== slow")
    W, T = 2, 2000
    auth = rw.Authority(os.path.join(base, "slow"), os.path.join(base, "slow", "state"), timeout_ms=T, max_connections=W)
    auth.init(); auth.start()
    base_tf = threads_fds(auth.proc.pid)
    print(f"  max_connections={W} timeout_ms={T}; idle threads/fds {base_tf}")
    # 1. silent peers: far more than 4*W pending slots
    socks = []
    t0 = time.monotonic()
    for i in range(60):
        s = socket.create_connection(("127.0.0.1", auth.port), timeout=5)
        socks.append(s)
    time.sleep(0.2)
    tf = threads_fds(auth.proc.pid)
    print(f"  60 silent connections: server threads/fds {tf}")
    if tf[0] is not None and tf[0] > base_tf[0] + 5 * W + 2:
        fail(f"slow: {tf[0]} server threads with 60 silent connections (bound is 5 per worker = {5 * W})")
    t1 = time.monotonic()
    rec = healthy(auth, "slow/silent")
    print(f"  a prompt client is answered in {time.monotonic() - t1:.3f}s while they are open")
    # every silent connection must be closed by the server within its deadline
    deadline = time.monotonic() + T / 1000 + 3
    open_left = len(socks)
    for s in socks:
        s.settimeout(max(0.05, deadline - time.monotonic()))
        try:
            if s.recv(1) == b"":
                open_left -= 1
        except (socket.timeout, TimeoutError):
            pass
        except OSError:
            open_left -= 1
    print(f"  silent connections still open {T / 1000 + 3:.0f}s later: {open_left} (total elapsed {time.monotonic() - t0:.1f}s)")
    if open_left:
        fail(f"slow: {open_left} silent connections outlived the server's {T} ms deadline")
    for s in socks:
        s.close()
    # 2. authenticated, allow-listed peers that never send a request: they take the workers
    w = Wire(auth)
    held = []
    for i in range(W):
        held.append(w.open())
    time.sleep(0.2)
    t1 = time.monotonic()
    try:
        r = Wire(auth).call(inspect_req(), timeout=T / 1000 + 5)
        waited = time.monotonic() - t1
        print(f"  with {W} authenticated idle peers holding every worker a prompt client waited {waited:.2f}s: {('answered' if r.get('response') else r)}")
    except Exception as e:
        waited = time.monotonic() - t1
        print(f"  with {W} authenticated idle peers holding every worker a prompt client failed after {waited:.2f}s: {type(e).__name__} {str(e)[:80]}")
    if waited > T / 1000 + 2.5:
        fail(f"slow: a prompt client waited {waited:.1f}s, beyond the deadline")
    for t in held:
        t.close()
    time.sleep(0.3)
    healthy(auth, "slow/after idle peers")
    # 3. churn: many short connections, then the thread and descriptor counts return
    for i in range(400):
        s = socket.create_connection(("127.0.0.1", auth.port), timeout=5)
        if i % 3 == 0:
            s.sendall(os.urandom(rng.randrange(1, 200)))
        elif i % 3 == 1:
            s.sendall(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" + os.urandom(40))   # start of a ClientHello
        s.close()
    time.sleep(T / 1000 + 1.0)
    tf = threads_fds(auth.proc.pid)
    print(f"  after 400 churned connections and one deadline: threads/fds {tf} (idle {base_tf})")
    if tf[0] is None or tf[0] > base_tf[0] + 1 or tf[1] > base_tf[1] + 1:
        fail(f"slow: threads/fds did not return to idle: {tf} vs {base_tf}")
    healthy(auth, "slow/after churn")
    if "panic" in auth.read_log().lower():
        fail("slow: panic in the server log: " + auth.read_log()[-400:])
    auth.kill9()


EDGE_INTS = [0, 1, 2, 255, 256, 2**31, 2**32, 2**53, 2**63 - 1, 2**63, 2**64 - 1, 2**64, -1, 1.5, 1e308, "1", None, True, [], {}]


def mutate(value, depth=0):
    """A structurally mutated copy of a JSON value."""
    x = rng.random()
    if isinstance(value, dict) and value and x < 0.75:
        v = dict(value)
        k = rng.choice(list(v))
        y = rng.random()
        if y < 0.12:
            del v[k]
        elif y < 0.2:
            v[k + "x"] = v.pop(k)
        elif y < 0.26:
            v["extra"] = rng.choice(EDGE_INTS)
        else:
            v[k] = mutate(v[k], depth + 1)
        return v
    if isinstance(value, list) and x < 0.8:
        v = list(value)
        y = rng.random()
        if not v or y < 0.15:
            v.append(rng.choice(EDGE_INTS))
        elif y < 0.3:
            v.pop(rng.randrange(len(v)))
        elif y < 0.4:
            v = v * rng.choice([0, 2, 8])
        elif y < 0.5:
            v = [0] * len(v)
        elif y < 0.6:
            v = [255] * len(v)
        else:
            i = rng.randrange(len(v))
            v[i] = mutate(v[i], depth + 1)
        return v
    if isinstance(value, str) and x < 0.8:
        return rng.choice([
            "", value[:-1], value + "0", value.upper(), value.replace("remote-", "remote_"),
            "remote-" + "0" * 16 + "-" + "1" * 32, "remote-" + "f" * 16 + "-" + "f" * 32, "remote-" + "0" * 15 + "1-" + "0" * 32,
            "../" + value[3:], value[:22] + "é" + value[24:], value[:7] + "é" * 8 + value[23:], "é" * 28, value[:55] + "\u0000",
            "remote-" + "1" * 16 + "/" + "1" * 32, "A" * 56, "A" * 100000, rng.choice(["released", "claimed", "restore_claimed", "active", "Active"]),
            rng.choice(["inspect", "claim", "takeover", "recover_enrollment", "claim_restore", "activate", "advance", "release"])])
    if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
        return rng.choice(EDGE_INTS + [value])
    return rng.choice(EDGE_INTS)


def ns(fence, session):
    return "remote-%016x-%s" % (fence, bytes(session).hex())


def part_fuzz(base):
    print("== fuzz")
    auth = rw.Authority(os.path.join(base, "fuzz"), os.path.join(base, "fuzz", "state"), timeout_ms=3000, max_connections=8)
    auth.init(); auth.start()
    writer, admin = Wire(auth), Wire(auth, cert=auth.admin_cert, key=auth.admin_key)
    identity = healthy(auth, "fuzz/start")["identity"]
    stats = dict(sent=0, answered=0, closed=0, ok=0, errors={}, phases={}, legit=0, raw=0)
    token = [list(os.urandom(32))]
    known = [True]      # whether token[0] is the current session's capability

    def legit_step(rec):
        """A request that the state machine should accept from the current record, or None."""
        op = list(uuid.uuid4().bytes)
        phase = rec["phase"]
        choices = []
        if not known[0] and phase != "released":
            # a mutated request installed a session whose capability the fuzzer does not hold: the
            # administrator installs a new one
            return admin, {"operation_id": op, "expected": rec, "authorization": list(os.urandom(32)),
                           "action": {"type": "takeover" if rec["current"] else "recover_enrollment"}}
        if phase == "released":
            choices.append((writer, {"type": "claim"}))
            if rec["current"]:
                choices.append((admin, {"type": "takeover"}))
                choices.append((admin, {"type": "claim_restore", "source": rec["current"]}))
            else:
                choices.append((admin, {"type": "recover_enrollment"}))
        elif phase == "claimed":
            name = ns(rec["fence"], rec["session"])
            if rec["current"]:
                d = dict(rec["current"]); d["namespace"] = name
            else:
                d = {"anchor": {"identity": identity, "generation": 0, "root": list(os.urandom(32))}, "epoch": 0, "namespace": name}
            choices += [(writer, {"type": "activate", "descriptor": d}), (writer, {"type": "release"})]
        elif phase == "restore_claimed":
            cur = rec["current"]
            d = {"anchor": {"identity": identity, "generation": cur["anchor"]["generation"] + 1, "root": list(os.urandom(32))},
                 "epoch": cur["epoch"] + 1, "namespace": ns(rec["fence"], rec["session"])}
            choices += [(admin, {"type": "activate", "descriptor": d}), (admin, {"type": "release"})]
        else:
            a = {"identity": identity, "generation": rec["current"]["anchor"]["generation"] + 1, "root": list(os.urandom(32))}
            choices += [(writer, {"type": "advance", "anchor": a})] * 3 + [(writer, {"type": "release"})]
        w, action = rng.choice(choices)
        # a request that installs a session brings its own new capability; the others use the session's
        installs = action["type"] in ("claim", "takeover", "claim_restore", "recover_enrollment")
        return w, {"operation_id": op, "expected": rec, "action": action, "authorization": list(os.urandom(32)) if installs else token[0]}

    rec = healthy(auth, "fuzz")
    last_good = None
    history = []
    mode_prev = sent_prev = resp_prev = None
    t0 = time.monotonic()
    for i in range(A.requests):
        w, req = legit_step(rec)
        x = rng.random()
        mode = "legit"
        if i:
            history.append((i - 1, mode_prev, json.dumps(sent_prev)[:1500] if not isinstance(sent_prev, bytes) else "raw", str(resp_prev)[:300]))
            del history[:-6]
        try:
            if x < 0.30:
                stats["legit"] += 1
                resp = w.call(req)
            elif x < 0.80:
                mode = "mutated"
                m = req
                for _ in range(rng.choice([1, 1, 1, 2, 3])):
                    m = mutate(m)
                if rng.random() < 0.15:
                    w = rng.choice([writer, admin])
                resp = w.call(m)
            elif x < 0.86:
                mode = "replay"
                if last_good:
                    w2, old = last_good
                    resp = rng.choice([w2, writer, admin]).call(old if rng.random() < 0.6 else dict(old, action=rng.choice([{"type": "release"}, {"type": "claim"}])))
                else:
                    resp = w.call(req)
            else:
                mode = "raw"
                stats["raw"] += 1
                good = json.dumps({"version": 2, "id": str(uuid.uuid4()), "request": req}, separators=(",", ":")).encode()
                k = rng.randrange(9)
                if k == 0:
                    body = w.raw(os.urandom(rng.randrange(1, 4000)))
                elif k == 1:
                    body = w.raw(good[:rng.randrange(1, len(good))])
                elif k == 2:
                    body = w.raw(good, header=struct.pack(">I", rng.choice([0, 1, 65536, 65537, 2**31, 2**32 - 1, len(good) + 5, len(good) - 5])))
                elif k == 3:
                    body = w.raw((b"[" * rng.choice([100, 200, 5000, 30000])) + b"]")
                elif k == 4:
                    body = w.raw(json.dumps({"version": rng.choice(EDGE_INTS), "id": rng.choice(["", "x", str(uuid.uuid4()), 5, None]), "request": req}).encode())
                elif k == 5:
                    pad = b" " * rng.choice([1000, 60000, 65000, 66000])
                    body = w.raw(good[:-1] + pad + b"}")
                elif k == 6:
                    body = w.raw(good + good)
                elif k == 7:
                    b2 = bytearray(good)
                    for _ in range(rng.randrange(1, 6)):
                        b2[rng.randrange(len(b2))] = rng.randrange(256)
                    body = w.raw(bytes(b2))
                else:
                    body = w.raw(b'{"version":2,"id":"%s","request":%s,"request":%s}' % (str(uuid.uuid4()).encode(), json.dumps(req).encode(), json.dumps(inspect_req()).encode()))
                resp = json.loads(body)
            stats["sent"] += 1
            stats["answered"] += 1
            if resp.get("response") is not None:
                stats["ok"] += 1
                if mode == "legit":
                    last_good = (w, req)
                if resp["response"].get("session") != rec.get("session"):
                    sent = m if mode == "mutated" else req if mode == "legit" else None
                    auth_sent = sent.get("authorization") if isinstance(sent, dict) else None
                    if isinstance(auth_sent, list) and len(auth_sent) == 32 and all(isinstance(b, int) and not isinstance(b, bool) and 0 <= b < 256 for b in auth_sent):
                        token[0] = auth_sent
                        known[0] = True
                    else:
                        known[0] = False
                    stats["sessions_by_mutants"] = stats.get("sessions_by_mutants", 0) + 1
            else:
                e = resp.get("error")
                stats["errors"][e] = stats["errors"].get(e, 0) + 1
                if mode == "legit":
                    fail(f"fuzz: request {i}: a request built from the current record was refused: {resp['error']} for action {json.dumps(req['action'])[:300]} "
                         f"phase {rec['phase']} fence {rec['fence']} token known {known[0]}; previous: {history[-4:]}")
                    if len(FAILS) > 5:
                        break
        except (EOFError, ConnectionError, ssl.SSLError, socket.timeout, TimeoutError, json.JSONDecodeError, OSError) as e:
            stats["sent"] += 1
            stats["closed"] += 1
            if mode == "legit":
                fail(f"fuzz: request {i}: a valid request got no answer: {e!r}")
        mode_prev, sent_prev = mode, (m if mode == "mutated" else req if mode == "legit" else mode)
        resp_prev = locals().get("resp")
        if i % 25 == 0 or mode != "legit":
            new = healthy(auth, f"fuzz request {i} ({mode})")
            if new is None:
                break
            # the public record must stay within what the state machine allows
            if new["identity"] != identity or new["fence"] < rec["fence"] or \
               (rec["current"] and (new["current"] is None or new["current"]["anchor"]["generation"] < rec["current"]["anchor"]["generation"]
                                    or new["current"]["epoch"] < rec["current"]["epoch"])):
                fail(f"fuzz request {i} ({mode}): the authority moved backwards: {rec} -> {new}")
                break
            if new.get("session") != rec.get("session") and mode in ("replay", "raw"):
                known[0] = False
            rec = new
            stats["phases"][rec["phase"]] = stats["phases"].get(rec["phase"], 0) + 1
        else:
            rec = resp.get("response") or rec
    print(f"  {stats} in {time.monotonic() - t0:.0f}s; final fence {rec['fence']} generation {rec['current'] and rec['current']['anchor']['generation']}")
    log = auth.read_log()
    if "panic" in log.lower():
        fail("fuzz: panic in the server log: " + log[-600:])
    # the state directory must hold a record that a restart serves
    auth.kill9(); auth.start()
    again = healthy(auth, "fuzz/restart")
    if again != rec:
        fail(f"fuzz: the restarted server serves another record: {again} vs {rec}")
    auth.kill9()


base = tempfile.mkdtemp(prefix="wprobe-", dir="/tmp")
try:
    for part in A.parts:
        {"tls": part_tls, "slow": part_slow, "fuzz": part_fuzz}[part](base)
finally:
    subprocess.run(["pkill", "-9", "-f", f"maki-witness serve {base}"], stderr=subprocess.DEVNULL)
    if not A.keep and not FAILS:
        shutil.rmtree(base, ignore_errors=True)
    else:
        print("kept", base)
print(f"wprobe parts {A.parts} seed {A.seed}: {'FAIL' if FAILS else 'ok'}")
for f in FAILS[:20]:
    print("  " + f[:1500])
sys.exit(1 if FAILS else 0)
