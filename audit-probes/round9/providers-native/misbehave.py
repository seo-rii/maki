"""Misbehaving endpoint matrix through the real daemon (single endpoint,
retry_safe, stall policy unless A9P_POLICY=bounded-error).

Each scenario misbehaves for the first K matching provider calls and then
serves normally. Expectation per scenario:
  transparent: the NBD request succeeds (ridden out by retries), data right
  eio:         the NBD request fails with EIO (contract/integrity class) and
               a later identical request succeeds once the endpoint behaves

After all scenarios: every acknowledged write is read back, the daemon is
restarted and everything is read back again; daemon logs, `maki status`
output and the backing directory are searched for plaintext, for the bearer
credential and for every marker string an endpoint sent.

usage: misbehave.py <http|ws|grpc> [scenario ...]
"""
import asyncio, base64, json, os, socket, struct, sys, threading, time
import nbd
import rp

transport = sys.argv[1]
only = sys.argv[2:]
POLICY = os.environ.get("A9P_POLICY", "stall")
LOGLEVEL = os.environ.get("A9P_MAKI_LOG")
MARK = "EVILMARK"
ESC = "\x1b[31m" + MARK + "-esc\x1b[0m"
TOKEN = "s3cr3t-bearer-token-A9P-0123456789abcdef"
UNIT = 4096

beh = rp.Behaviour()
state = {"left": 0, "op": None, "fn": None, "fired": 0}
trap_hits = []


class Trap(rp.http.server.BaseHTTPRequestHandler):
    def do_any(self):
        n = int(self.headers.get("content-length", "0") or 0)
        body = self.rfile.read(n) if n else b""
        trap_hits.append((self.command, self.path, dict(self.headers), body))
        self.send_response(200); self.send_header("content-length", "2"); self.end_headers(); self.wfile.write(b"{}")
    do_GET = do_POST = do_PUT = do_any
    def log_message(self, *a): pass


trap = rp._ThreadingHTTPServer(("127.0.0.1", 0), Trap)
threading.Thread(target=trap.serve_forever, daemon=True).start()
TRAP_URL = f"http://127.0.0.1:{trap.server_address[1]}/v1/trap"


def hook(kind, op, req):
    if state["left"] <= 0 or state["fn"] is None:
        return None
    if state["op"] not in (None, op):
        return None
    state["left"] -= 1
    state["fired"] += 1
    return state["fn"](kind, op, req)


beh.hook = hook

# ---------------------------------------------------------------- scenarios

def normal_items(op, req):
    """Serve the request normally, returning [(unit, data)]."""
    if "json" in req and "handler" in req:
        j = req["json"]
        items = [(i["unit"], base64.b64decode(i["data"])) for i in j["items"]]
        return beh.run(op, j.get("volume"), j.get("profile"), j.get("format"), items)
    if "ws" in req:
        j = req["json"]
        items = [(i["unit"], base64.b64decode(i["data"])) for i in j["items"]]
        return beh.run(op, j.get("volume"), j.get("profile"), j.get("format"), items)
    r = req["request"]
    return beh.run(op, r.volume_id, r.compatibility_id, r.format_version, [(i.unit_index, i.data) for i in r.items])


def request_items(req):
    if "json" in req:
        return [(i["unit"], base64.b64decode(i["data"])) for i in req["json"]["items"]]
    return [(i.unit_index, i.data) for i in req["request"].items]


def reply(kind, req, items, **kw):
    """A well-formed success reply carrying `items` on any transport."""
    if kind == "http":
        return dict(body=json.dumps({"items": [{"unit": u, "data": rp.b64(d)} for u, d in items]}).encode(), **kw)
    if kind == "ws":
        return {"id": req["json"]["id"], "items": [{"unit": u, "data": rp.b64(d)} for u, d in items]}
    pb = req["server"].pb
    return pb.CryptoBatchResponse(items=[pb.CryptoItem(unit_index=u, data=d) for u, d in items]).SerializeToString()


def grpc_abort(req, code, message="", metadata=()):
    import grpc
    ctx = req["context"]
    if metadata:
        ctx.set_trailing_metadata(tuple(metadata))
    ctx.abort(getattr(grpc.StatusCode, code), message)


def s_unavailable(kind, op, req):
    if kind == "http":
        return dict(status=503, body=(MARK + "-503-body\n" + ESC).encode(), headers={"x-evil": MARK + "-hdr"})
    if kind == "ws":
        return {"id": req["json"]["id"], "error": {"class": "retryable", "message": MARK + "-wsmsg " + ESC}}
    grpc_abort(req, "UNAVAILABLE", MARK + "-grpcmsg " + ESC + "\nINJECTED LINE")


def s_throttle(kind, op, req):
    if kind == "http":
        return dict(status=429, headers={"retry-after": "30"})
    if kind == "ws":
        return {"id": req["json"]["id"], "error": {"class": "throttled", "message": MARK}}
    grpc_abort(req, "RESOURCE_EXHAUSTED", MARK)


def s_redirect(kind, op, req):
    if kind == "http":
        return dict(status=307, headers={"location": TRAP_URL})
    if kind == "ws":   # an error frame cannot redirect; tested at upgrade separately
        return {"id": req["json"]["id"], "error": {"class": "retryable"}}
    grpc_abort(req, "UNAVAILABLE")


def s_redirect_301(kind, op, req):
    return dict(status=301, headers={"location": TRAP_URL}) if kind == "http" else s_redirect(kind, op, req)


def s_redirect_308_https(kind, op, req):
    return dict(status=308, headers={"location": TRAP_URL.replace("http://", "http://user:pw@")}) if kind == "http" else s_redirect(kind, op, req)


def s_auth(kind, op, req):
    if kind == "http":
        return dict(status=401, headers={"www-authenticate": 'Basic realm="' + MARK + '-realm"'}, body=(MARK + "-401").encode())
    if kind == "ws":
        return {"id": req["json"]["id"], "error": {"class": "retryable"}}
    grpc_abort(req, "UNAUTHENTICATED", MARK + "-unauth")


def s_truncated(kind, op, req):
    out = normal_items(op, req)
    if kind == "http":
        r = reply(kind, req, out)
        return dict(body=r["body"], declared_length=len(r["body"]) + 100, cut_after=len(r["body"]) // 2)
    if kind == "ws":
        async def go():
            req["ws"].transport.abort()
            return "handled"
        return go()
    # gRPC: cancel mid-call
    req["context"].cancel()
    return "handled"


def s_wrong_unit(kind, op, req):
    out = normal_items(op, req)
    out = [(u + 1, d) for u, d in out]
    return reply(kind, req, out)


def s_fewer_items(kind, op, req):
    out = normal_items(op, req)
    return reply(kind, req, out[:-1])


def s_more_items(kind, op, req):
    out = normal_items(op, req)
    return reply(kind, req, out + [out[-1]])


def s_swapped(kind, op, req):
    out = normal_items(op, req)
    if len(out) < 2:
        out = [(out[0][0] ^ 1, out[0][1])]
    else:
        out = [out[1], out[0]] + out[2:]
    return reply(kind, req, out)


def s_plaintext_echo(kind, op, req):
    """encrypt answers with the plaintext itself, padded to look like ciphertext."""
    items = request_items(req)
    return reply(kind, req, [(u, d) for u, d in items])


def s_plaintext_embedded(kind, op, req):
    items = request_items(req)
    return reply(kind, req, [(u, os.urandom(12) + d + os.urandom(16)) for u, d in items])


def s_short_plain(kind, op, req):
    """decrypt answers with a plaintext of the wrong size."""
    out = normal_items(op, req)
    return reply(kind, req, [(u, d[:-1]) for u, d in out])


def s_empty_cipher(kind, op, req):
    items = request_items(req)
    return reply(kind, req, [(u, b"") for u, d in items])


def s_oversized_cipher(kind, op, req):
    items = request_items(req)
    return reply(kind, req, [(u, os.urandom(len(d) + rp.OVERHEAD + 1)) for u, d in items])


def s_integrity(kind, op, req):
    if kind == "http":
        return dict(status=422, headers={"maki-crypto-error": "auth-tag-mismatch"})
    if kind == "ws":
        return {"id": req["json"]["id"], "error": {"class": "integrity", "reason": "auth-tag-mismatch", "message": MARK}}
    grpc_abort(req, "FAILED_PRECONDITION", MARK, [("maki-crypto-error", "auth-tag-mismatch")])


def s_bad_request(kind, op, req):
    if kind == "http":
        return dict(status=400, body=(MARK + "-400").encode())
    if kind == "ws":
        return {"id": req["json"]["id"], "error": {"class": "bad-request", "message": MARK}}
    grpc_abort(req, "INVALID_ARGUMENT", MARK)


def s_garbage(kind, op, req):
    if kind == "http":
        return dict(body=b"<html><body>" + (MARK + "-html").encode() + b"</body></html>", headers={"content-type": "text/html"})
    if kind == "ws":
        async def go():
            await req["ws"].send("this is not json " + MARK)
            return "handled"
        return go()
    return b"\xff\xff\xff\xff" + MARK.encode()


def s_bad_base64(kind, op, req):
    out = normal_items(op, req)
    if kind == "http":
        return dict(body=json.dumps({"items": [{"unit": u, "data": rp.b64(d)[:-3] + "!$~"} for u, d in out]}).encode())
    if kind == "ws":
        return {"id": req["json"]["id"], "items": [{"unit": u, "data": rp.b64(d)[:-3] + "!$~"} for u, d in out]}
    return s_garbage(kind, op, req)


def s_huge(kind, op, req):
    big = 9 << 20   # above the 8 MiB default limits (4 MiB for gRPC)
    if kind == "http":
        return dict(body=b'{"items":[' + b" " * big + b"]}")
    if kind == "ws":
        async def go():
            try:
                await req["ws"].send('{"id":%d,"pad":"%s"}' % (req["json"]["id"], "x" * big))
            except Exception:
                pass
            return "handled"
        return go()
    return b"\x0a" + b"\x80\x80\x80\x08" + b"x" * 1024


def s_deep_json(kind, op, req):
    deep = "[" * 100000 + "]" * 100000
    if kind == "http":
        return dict(body=('{"items":' + deep + "}").encode())
    if kind == "ws":
        async def go():
            await req["ws"].send('{"id":%d,"items":%s}' % (req["json"]["id"], deep))
            return "handled"
        return go()
    return s_garbage(kind, op, req)


def s_slowloris(kind, op, req):
    out = normal_items(op, req)
    if kind == "http":
        h = req["handler"]
        body = reply(kind, req, out)["body"]
        h.send_response(200); h.send_header("content-length", str(len(body))); h.end_headers(); h.wfile.flush()
        try:
            for i in range(0, min(len(body), 40)):
                h.wfile.write(body[i:i + 1]); h.wfile.flush(); time.sleep(0.1)
        except Exception:
            pass
        h.close_connection = True
        return "handled"
    if kind == "ws":
        async def go():
            await asyncio.sleep(3.0)
            return None
        return go()
    time.sleep(3.0)
    return None


def s_close_delimited(kind, op, req):
    if kind != "http":
        return s_truncated(kind, op, req)
    out = normal_items(op, req)
    h = req["handler"]
    body = reply(kind, req, out)["body"]
    h.send_response(200); h.send_header("connection", "close"); h.end_headers()
    h.wfile.write(body); h.wfile.flush(); h.close_connection = True
    return "handled"


def s_evil_headers(kind, op, req):
    """Error whose every endpoint-controlled string carries a marker."""
    if kind == "http":
        h = req["handler"]
        payload = (MARK + "-body " + ESC + "\r\nFAKE LOG LINE level=ERROR " + MARK).encode()
        h.wfile.write(b"HTTP/1.1 500 " + (MARK + "-reason").encode() + b" \x1b[31mred\r\n")
        h.wfile.write(b"x-evil: " + (MARK + "-hdrval").encode() + b"\x1b[2J\r\n")
        h.wfile.write(b"maki-crypto-error: " + (MARK + "-token").encode() + b"\r\n")
        h.wfile.write(b"content-length: %d\r\n\r\n" % len(payload)); h.wfile.write(payload); h.wfile.flush()
        return "handled"
    if kind == "ws":
        async def go():
            await req["ws"].close(1011, (MARK + "-close " + ESC)[:100])
            return "handled"
        return go()
    grpc_abort(req, "INTERNAL", MARK + "-status " + ESC + "\r\nFAKE LOG LINE",
               [("x-evil", MARK + "-md"), ("maki-crypto-error", MARK + "-token")])


def s_stale_id(kind, op, req):
    """WebSocket: answer under an id nobody asked, twice, then properly."""
    if kind != "ws":
        return None
    out = normal_items(op, req)
    async def go():
        ws, j = req["ws"], req["json"]
        good = {"id": j["id"], "items": [{"unit": u, "data": rp.b64(d)} for u, d in out]}
        await ws.send(json.dumps({"id": j["id"] + 100000, "items": good["items"]}))
        await ws.send(json.dumps({"id": 0, "items": good["items"]}))
        await ws.send(json.dumps(good))
        await ws.send(json.dumps(good))     # duplicate
        return "handled"
    return go()


def s_binary_frame(kind, op, req):
    if kind != "ws":
        return None
    async def go():
        await req["ws"].send(b"\x00\x01binary" + MARK.encode())
        return "handled"
    return go()


def s_bad_probe_envelope(kind, op, req):
    if kind == "http":
        return dict(status=422, headers={"maki-crypto-error": ["auth-tag-mismatch", "context-mismatch"]})
    if kind == "ws":
        return {"id": req["json"]["id"], "error": {"class": "integrity", "reason": MARK}}
    grpc_abort(req, "FAILED_PRECONDITION", MARK, [("maki-crypto-error", "auth-tag-mismatch"), ("maki-crypto-error", "context-mismatch")])


# name, fn, op, K, expect-write, expect-read
SCENARIOS = [
    ("unavailable", s_unavailable, None, 6, "transparent", "transparent"),
    ("throttle", s_throttle, None, 4, "transparent", "transparent"),
    ("redirect-307", s_redirect, None, 3, "transparent", "transparent"),
    ("redirect-301", s_redirect_301, None, 3, "transparent", "transparent"),
    ("redirect-308-userinfo", s_redirect_308_https, None, 3, "transparent", "transparent"),
    ("auth-401", s_auth, None, 3, "transparent", "transparent"),
    ("truncated", s_truncated, None, 3, "transparent", "transparent"),
    ("slowloris", s_slowloris, None, 2, "transparent", "transparent"),
    ("evil-headers", s_evil_headers, None, 3, "transparent", "transparent"),
    ("stale-id", s_stale_id, None, 3, "transparent", "transparent"),
    ("wrong-unit", s_wrong_unit, None, 1, "eio", "eio"),
    ("fewer-items", s_fewer_items, None, 1, "eio", "eio"),
    ("more-items", s_more_items, None, 1, "eio", "eio"),
    ("swapped", s_swapped, None, 1, "eio", "eio"),
    ("garbage", s_garbage, None, 1, "eio", "eio"),
    ("bad-base64", s_bad_base64, None, 1, "eio", "eio"),
    ("huge", s_huge, None, 1, "eio", "eio"),
    ("deep-json", s_deep_json, None, 1, "eio", "eio"),
    ("close-delimited", s_close_delimited, None, 1, "eio-http", "eio-http"),
    ("binary-frame", s_binary_frame, None, 1, "eio-ws", "eio-ws"),
    ("bad-request", s_bad_request, None, 1, "eio", "eio"),
    ("bad-probe-envelope", s_bad_probe_envelope, None, 1, "eio", "eio"),
    ("plaintext-echo", s_plaintext_echo, "encrypt", 1, "eio", None),
    ("plaintext-embedded", s_plaintext_embedded, "encrypt", 1, "eio", None),
    ("empty-ciphertext", s_empty_cipher, "encrypt", 1, "eio", None),
    ("oversized-ciphertext", s_oversized_cipher, "encrypt", 1, "eio", None),
    ("integrity-on-read", s_integrity, "decrypt", 1, None, "eio"),
    ("short-plaintext", s_short_plain, "decrypt", 1, None, "eio"),
]


def resolve(expect):
    if expect in ("eio-http", "eio-ws"):
        return "eio" if expect.endswith(transport) else "transparent"
    return expect


# ---------------------------------------------------------------- run

srv = {"http": rp.HttpServer, "ws": rp.WsServer, "grpc": rp.GrpcServer}[transport](beh)
extra = {}
env = {"MAKI_CREDENTIAL_TOKEN": TOKEN}
if transport == "http":
    extra["http_headers"] = '[crypto.http.{op}.headers]\nAuthorization = { source = "env", name = "token", format = "Bearer {}" }'
if transport == "grpc":
    extra["metadata"] = 'authorization = { source = "env", name = "token", format = "Bearer {}" }'
if transport == "http":
    # config_text formats the mapping per op; give each its own header table
    orig = rp.HTTP_MAPPING
    hdr = 'Authorization = {{ source = "env", name = "token", format = "Bearer {{}}" }}'
    rp.HTTP_MAPPING = orig.replace("{headers}", "[crypto.http.{op}.headers]\n" + hdr)
    extra.pop("http_headers")
if LOGLEVEL:
    env["MAKI_LOG"] = LOGLEVEL
cfg = dict(timeout="1s", size="8MiB", **extra)
if POLICY != "stall":
    cfg.update(policy=POLICY, max_operation_time="3s")
v = rp.Vol(f"mis-{transport}", transport, [srv.url()], **cfg)

oracle = {}        # offset -> acceptable byte strings (list)
samples = []       # (label, plaintext sample) for the secret grep
problems = []
version = [10]
outputs = []       # CLI output collected for the grep


def write(h, off, length, fua=True):
    version[0] += 1
    d = rp.pattern(off, length, version[0])
    samples.append((f"v{version[0]}@{off}", d[:512]))
    try:
        h.pwrite(d, off, nbd.CMD_FLAG_FUA if fua else 0)
        oracle[off] = [d]
        return None, d
    except nbd.Error as e:
        oracle[off] = oracle.get(off, [bytes(length)]) + [d]
        return e.errnum, d


def read(h, off, length):
    try:
        return None, h.pread(length, off)
    except nbd.Error as e:
        return e.errnum, None


def status_text():
    out = ""
    for cmd in ("status", "metrics"):
        r = v.maki(cmd, v.cfg, "--timeout", "10", timeout=30, env=env)
        out += r.stdout + r.stderr
    outputs.append(out)
    return out


try:
    r = v.create(env=env)
    outputs.append(r.stdout + r.stderr)
    v.start(env=env)
    h = rp.connect(v.sock)
    names = [s for s in SCENARIOS if not only or s[0] in only]
    for index, (name, fn, op, k, exp_w, exp_r) in enumerate(names):
        exp_w, exp_r = resolve(exp_w), resolve(exp_r)
        base = (index + 1) * 16 * UNIT
        # a healthy baseline region for the read half
        e, d0 = write(h, base, 2 * UNIT)
        if e:
            problems.append(f"{name}: baseline write failed errno {e}")
            continue
        line = [name]
        if exp_w:
            state.update(left=k, op=op if op else "encrypt", fn=fn, fired=0)
            t = time.monotonic()
            e, d = write(h, base + 4 * UNIT, 2 * UNIT)
            dt = time.monotonic() - t
            line.append(f"write: errno={e} fired={state['fired']} {dt:.1f}s")
            if exp_w == "transparent" and e is not None:
                problems.append(f"{name}: write expected transparent, got errno {e}")
            if exp_w == "eio" and e != 5:
                problems.append(f"{name}: write expected EIO, got {e} (fired={state['fired']})")
            state.update(left=0, fn=None)
            # the endpoint behaves again: the same write must succeed
            e2, d2 = write(h, base + 4 * UNIT, 2 * UNIT)
            if e2 is not None:
                problems.append(f"{name}: write after heal failed errno {e2}")
            er, got = read(h, base + 4 * UNIT, 2 * UNIT)
            if er is not None or got != d2:
                problems.append(f"{name}: readback after heal errno={er} match={got == d2}")
        if exp_r:
            state.update(left=k, op=op if op else "decrypt", fn=fn, fired=0)
            t = time.monotonic()
            er, got = read(h, base, 2 * UNIT)
            dt = time.monotonic() - t
            line.append(f"read: errno={er} fired={state['fired']} {dt:.1f}s")
            if exp_r == "transparent" and (er is not None or got != d0):
                problems.append(f"{name}: read expected transparent, errno={er} match={got == d0}")
            if exp_r == "eio" and er != 5:
                problems.append(f"{name}: read expected EIO, got errno={er} data={'MATCH' if got == d0 else 'OTHER'} (fired={state['fired']})")
            if er is None and got != d0:
                problems.append(f"{name}: READ RETURNED WRONG DATA {rp.describe(got[:512])}")
            state.update(left=0, fn=None)
            er, got = read(h, base, 2 * UNIT)
            if er is not None or got != d0:
                problems.append(f"{name}: read after heal errno={er} match={got == d0}")
        st = status_text()
        try:
            c = json.loads(st.split("\n}\n")[0] + "\n}")["data"]["crypto"]
            line.append(f"circuit={[e_['circuit'] for e_ in c['endpoints']]}")
        except Exception:
            pass
        print("  ", " | ".join(line)); sys.stdout.flush()

    def verify(tag):
        bad = 0
        for off, accept in sorted(oracle.items()):
            er, got = read(h, off, len(accept[0]))
            if er is not None or got not in accept:
                bad += 1
                problems.append(f"{tag}: offset {off} errno={er} got={rp.describe(got[:512]) if got else None}")
        print(f"   {tag}: {len(oracle)} regions checked, {bad} bad")

    verify("final")
    h.flush()
    h.shutdown()
    print("   term rc", v.term())
    v.start(env=env)
    h = rp.connect(v.sock)
    verify("after restart")
    h.shutdown()
    v.term()
except Exception as e:
    import traceback; traceback.print_exc()
    problems.append(f"exception {e!r}")
    print(v.read_log()[-2500:])
finally:
    logs = v.all_logs_bytes()
    cli = "".join(outputs).encode()
    # backing directory content
    disk = b""
    for dirpath, _, files in os.walk(v.root):
        for f in files:
            with open(os.path.join(dirpath, f), "rb") as fh:
                disk += fh.read()
    for label, blob in (("daemon log", logs), ("cli output", cli), ("backing dir", disk)):
        hits = rp.grep_secrets(blob, samples) if label != "backing dir" else [
            (l, "raw") for l, s in samples if s[24:88] in blob]
        tok = TOKEN.encode() in blob or base64.b64encode(TOKEN.encode()) in blob
        marks = blob.count(MARK.encode())
        esc = blob.count(b"\x1b")
        print(f"   {label}: {len(blob)} bytes; plaintext hits={hits[:4] or 'none'}; token={tok}; marker occurrences={marks}; ESC bytes={esc}")
        if hits or tok:
            problems.append(f"SECRET in {label}: {hits[:4]} token={tok}")
        if marks or (esc and label != "backing dir"):
            problems.append(f"endpoint-controlled text in {label}: marks={marks} esc={esc}")
            i = blob.find(MARK.encode())
            print("      context:", blob[max(0, i - 200):i + 120])
    print("   trap hits:", len(trap_hits), [(m, p) for m, p, _, _ in trap_hits[:3]])
    if trap_hits:
        problems.append(f"REDIRECT FOLLOWED: {len(trap_hits)} request(s) reached the trap")
    with open(os.path.join(rp.HERE, "logs", f"misbehave-{transport}-{POLICY}-{LOGLEVEL or 'info'}.daemon.log"), "wb") as f:
        f.write(logs)
    v.cleanup()
    try:
        srv.stop()
    except Exception:
        pass
print("PROBLEMS" if problems else "CLEAN", transport)
for p in problems:
    print("  -", p)
