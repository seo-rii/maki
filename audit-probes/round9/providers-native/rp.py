"""Round 9, providers-native: reference crypto provider servers (HTTP,
WebSocket, gRPC) with switchable misbehaviour, TLS material, volume
configuration and nbdkit/libnbd helpers.

Run every probe with /usr/bin/python3.12 (python3-libnbd, python3-websockets,
python3-grpcio, python3-h2, python3-cryptography from apt).

The servers run inside the probe's own process (threads), so a probe flips a
behaviour switch between two NBD requests. Nothing here touches the checkout
under audit; the plugin and the `maki` CLI are copies of the debug build in
./bin.
"""
import asyncio, base64, datetime, hashlib, http.server, ipaddress, json, os, shutil, signal
import socket, socketserver, ssl, struct, subprocess, sys, tempfile, threading, time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN = os.environ.get("MAKI_PLUGIN", os.path.join(HERE, "bin", "libmaki_nbdkit.so"))
MAKI = os.environ.get("MAKI_BIN", os.path.join(HERE, "bin", "maki"))
BASE = os.environ.get("A9P_BASE", "/tmp/a9p")
OVERHEAD = 28  # nonce 12 + tag 16


# ------------------------------------------------------------------ cipher

class IntegrityError(Exception):
    pass


class Cipher:
    """AES-256-GCM, random nonce, the whole crypto context as AAD."""

    def __init__(self, key=bytes(range(32)), bind=True):
        self.aead = AESGCM(key)
        self.bind = bind

    def aad(self, volume, profile, fmt, unit):
        if not self.bind:
            return b""
        return f"{volume}|{profile}|{fmt}|{unit}".encode()

    def enc(self, volume, profile, fmt, unit, pt):
        nonce = os.urandom(12)
        return nonce + self.aead.encrypt(nonce, pt, self.aad(volume, profile, fmt, unit))

    def dec(self, volume, profile, fmt, unit, ct):
        if len(ct) < OVERHEAD:
            raise IntegrityError("short")
        try:
            return self.aead.decrypt(ct[:12], ct[12:], self.aad(volume, profile, fmt, unit))
        except Exception:
            raise IntegrityError("tag")


class Behaviour:
    """Shared switches. `hook(kind, op, req)` may return a transport-specific
    action; None means "serve normally". Counters are for assertions."""

    def __init__(self, cipher=None):
        self.cipher = cipher or Cipher()
        self.hook = None
        self.lock = threading.Lock()
        self.calls = {"encrypt": 0, "decrypt": 0}
        self.items = {"encrypt": 0, "decrypt": 0}
        self.seen_plain = []      # optional capture of plaintexts (set capture=True)
        self.capture = False
        self.log = []

    def note(self, op, n):
        with self.lock:
            self.calls[op] += 1
            self.items[op] += n

    def run(self, op, volume, profile, fmt, items):
        """items: [(unit, bytes)] -> [(unit, bytes)]; raises IntegrityError."""
        self.note(op, len(items))
        out = []
        for unit, data in items:
            if op == "encrypt":
                if self.capture:
                    self.seen_plain.append(data)
                out.append((unit, self.cipher.enc(volume, profile, fmt, unit, data)))
            else:
                out.append((unit, self.cipher.dec(volume, profile, fmt, unit, data)))
        return out


# ------------------------------------------------------------------ TLS material

class Pki:
    def __init__(self, directory):
        self.dir = directory
        os.makedirs(directory, exist_ok=True)
        self.ca_key, self.ca_cert = self._ca("a9p test CA")
        self.ca_path = self.write("ca.pem", self.ca_cert.public_bytes(serialization.Encoding.PEM))

    def write(self, name, data, mode=0o644):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as f:
            f.write(data)
        os.chmod(path, mode)
        return path

    def _ca(self, cn):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        now = datetime.datetime.utcnow()
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=30))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
                .sign(key, hashes.SHA256()))
        return key, cert

    def other_ca(self, cn="a9p other CA"):
        return self._ca(cn)

    def leaf(self, name, dns=("localhost",), ips=("127.0.0.1", "::1"), not_before=None,
             not_after=None, client=False, ca=None, pad_bytes=0):
        ca_key, ca_cert = ca or (self.ca_key, self.ca_cert)
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.utcnow()
        san = [x509.DNSName(d) for d in dns] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
        b = (x509.CertificateBuilder()
             .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
             .issuer_name(ca_cert.subject).public_key(key.public_key())
             .serial_number(x509.random_serial_number())
             .not_valid_before(not_before or now - datetime.timedelta(days=1))
             .not_valid_after(not_after or now + datetime.timedelta(days=7))
             .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
             .add_extension(x509.ExtendedKeyUsage(
                 [ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
        if san:
            b = b.add_extension(x509.SubjectAlternativeName(san), critical=False)
        if pad_bytes:
            b = b.add_extension(x509.UnrecognizedExtension(
                x509.ObjectIdentifier("1.3.6.1.4.1.55555.1"), b"P" * pad_bytes), critical=False)
        cert = b.sign(ca_key, hashes.SHA256())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
        cp = self.write(f"{name}.crt", cert_pem)
        kp = self.write(f"{name}.key", key_pem, 0o600)
        return cp, kp


def server_ssl_context(cert, key, ca=None, require_client=False, alpn=None, tls12=False):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    if ca:
        ctx.load_verify_locations(ca)
    if require_client:
        ctx.verify_mode = ssl.CERT_REQUIRED
    if alpn:
        ctx.set_alpn_protocols(alpn)
    if tls12:
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    return ctx


# ------------------------------------------------------------------ HTTP server

def b64(b):
    return base64.b64encode(b).decode()


class _HttpHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "a9p"

    def log_message(self, *a):
        pass

    def do_POST(self):
        beh = self.server.behaviour
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        op = "encrypt" if self.path.split("?")[0].endswith("/encrypt") else "decrypt"
        self.server.requests.append((self.path, dict(self.headers), body if self.server.keep_bodies else None))
        try:
            req = json.loads(body)
        except Exception:
            req = None
        if beh.hook:
            action = beh.hook("http", op, {"handler": self, "json": req, "raw": body})
            if action == "handled":
                return
            if isinstance(action, dict):
                return self.reply(**action)
        if req is None:
            return self.reply(status=400)
        try:
            items = [(i["unit"], base64.b64decode(i["data"])) for i in req["items"]]
            out = beh.run(op, req.get("volume"), req.get("profile"), req.get("format"), items)
        except IntegrityError:
            return self.reply(status=422, headers={"maki-crypto-error": "auth-tag-mismatch"})
        self.reply(body=json.dumps({"items": [{"unit": u, "data": b64(d)} for u, d in out]}).encode())

    do_PUT = do_POST

    def reply(self, status=200, headers=None, body=b"", chunked=False, close=False,
              delay_before=0, delay_mid=0, declared_length=None, cut_after=None):
        if delay_before:
            time.sleep(delay_before)
        self.send_response(status)
        for k, v in (headers or {}).items():
            if isinstance(v, (list, tuple)):
                for one in v:
                    self.send_header(k, one)
            else:
                self.send_header(k, v)
        if chunked:
            self.send_header("transfer-encoding", "chunked")
        else:
            self.send_header("content-length", str(len(body) if declared_length is None else declared_length))
        if close:
            self.send_header("connection", "close")
        self.end_headers()
        self.wfile.flush()
        data = body if cut_after is None else body[:cut_after]
        if chunked:
            data = b"%x\r\n" % len(data) + data + b"\r\n" + (b"0\r\n\r\n" if cut_after is None else b"")
        half = len(data) // 2
        self.wfile.write(data[:half])
        self.wfile.flush()
        if delay_mid:
            time.sleep(delay_mid)
        self.wfile.write(data[half:])
        self.wfile.flush()
        if close or cut_after is not None:
            self.close_connection = True


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 256

    def handle_error(self, request, client_address):
        pass


class _ThreadingHTTPServer6(_ThreadingHTTPServer):
    address_family = socket.AF_INET6


class HttpServer:
    def __init__(self, behaviour, host="127.0.0.1", port=0, tls=None, keep_bodies=False):
        cls = _ThreadingHTTPServer6 if ":" in host else _ThreadingHTTPServer
        self.srv = cls((host, port), _HttpHandler)
        self.srv.behaviour = behaviour
        self.srv.requests = []
        self.srv.keep_bodies = keep_bodies
        self.tls = tls
        if tls:
            self.srv.socket = tls.wrap_socket(self.srv.socket, server_side=True, do_handshake_on_connect=False)
            orig = self.srv.get_request

            def get_request():
                s, a = orig()
                return s, a
            self.srv.get_request = get_request
        self.port = self.srv.server_address[1]
        self.host = host
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.thread.start()

    @property
    def requests(self):
        return self.srv.requests

    def url(self, name=None):
        host = name or (f"[{self.host}]" if ":" in self.host else self.host)
        return f"{'https' if self.tls else 'http'}://{host}:{self.port}"

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


# ------------------------------------------------------------------ WebSocket server

class WsServer:
    """`behaviour.hook("ws", op, {"ws": ws, "json": req, "server": self})` may be
    a coroutine function result; return "handled" to suppress the reply."""

    def __init__(self, behaviour, host="127.0.0.1", port=0, tls=None, max_size=64 << 20,
                 process_request=None):
        import websockets
        self.behaviour = behaviour
        self.loop = asyncio.new_event_loop()
        self.connections = []
        self.frames = []       # raw request frames (kept only if keep_frames)
        self.keep_frames = False
        self.tls = tls
        self.host = host
        ready = threading.Event()

        async def handler(ws, path=None):
            self.connections.append(ws)
            try:
                async for message in ws:
                    if self.keep_frames:
                        self.frames.append(message)
                    try:
                        req = json.loads(message)
                    except Exception:
                        continue
                    asyncio.ensure_future(self.serve(ws, req))
            except Exception:
                pass

        async def main():
            self.server = await websockets.serve(handler, host, port, ssl=tls, max_size=max_size,
                                                 process_request=process_request, ping_interval=None)
            self.port = self.server.sockets[0].getsockname()[1]
            ready.set()

        def run():
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(main())
            self.loop.run_forever()

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        ready.wait(10)

    async def serve(self, ws, req):
        beh = self.behaviour
        op = req.get("op")
        try:
            if beh.hook:
                action = beh.hook("ws", op, {"ws": ws, "json": req, "server": self})
                if asyncio.iscoroutine(action):
                    action = await action
                if action == "handled":
                    return
                if isinstance(action, dict):
                    await ws.send(json.dumps(action))
                    return
            try:
                items = [(i["unit"], base64.b64decode(i["data"])) for i in req["items"]]
                out = beh.run(op, req.get("volume"), req.get("profile"), req.get("format"), items)
            except IntegrityError:
                await ws.send(json.dumps({"id": req["id"], "error": {"class": "integrity", "reason": "auth-tag-mismatch"}}))
                return
            await ws.send(json.dumps({"id": req["id"], "items": [{"unit": u, "data": b64(d)} for u, d in out]}))
        except Exception as e:
            beh.log.append(f"ws serve error {e!r}")

    def url(self, name=None):
        host = name or (f"[{self.host}]" if ":" in self.host else self.host)
        return f"{'wss' if self.tls else 'ws'}://{host}:{self.port}"

    def call(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(10)

    def close_all(self, code=1000, reason=""):
        async def go():
            for ws in list(self.connections):
                try:
                    await ws.close(code, reason)
                except Exception:
                    pass
        self.call(go())

    def abort_all(self):
        async def go():
            for ws in list(self.connections):
                try:
                    ws.transport.abort()
                except Exception:
                    pass
        self.call(go())

    def stop(self):
        async def go():
            self.server.close()
        try:
            self.call(go())
        except Exception:
            pass
        self.loop.call_soon_threadsafe(self.loop.stop)


# ------------------------------------------------------------------ gRPC server

def _pb():
    """Compile the repo's proto once into ./pb and import it."""
    out = os.path.join(HERE, "pb")
    if not os.path.exists(os.path.join(out, "maki_crypto_pb2.py")):
        os.makedirs(out, exist_ok=True)
        src = os.path.join(HERE, "pb", "maki_crypto.proto")
        shutil.copy(os.environ.get("MAKI_PROTO", "/home/user/wt/audit9/packaging/examples/maki-crypto.proto"), src)
        from grpc_tools import protoc
        rc = protoc.main(["protoc", f"-I{out}", f"--python_out={out}", src])
        assert rc == 0
    if out not in sys.path:
        sys.path.insert(0, out)
    import maki_crypto_pb2
    return maki_crypto_pb2


class GrpcServer:
    """`behaviour.hook("grpc", op, {"request": msg, "context": ctx})` may return
    bytes (the raw response message), "handled" (it aborted the call itself),
    or None."""

    def __init__(self, behaviour, host="127.0.0.1", port=0, tls=None, max_workers=64,
                 max_msg=64 << 20, prefix=""):
        import grpc
        from concurrent import futures
        pb = _pb()
        self.pb = pb
        self.behaviour = behaviour
        self.grpc = grpc
        self.tls = tls
        self.host = host
        outer = self

        def serve(op):
            def unary(request, context):
                beh = outer.behaviour
                if beh.hook:
                    action = beh.hook("grpc", op, {"request": request, "context": context, "server": outer})
                    if isinstance(action, (bytes, bytearray)):
                        return bytes(action)
                    if action == "handled":
                        return b""
                try:
                    out = beh.run(op, request.volume_id, request.compatibility_id, request.format_version,
                                  [(i.unit_index, i.data) for i in request.items])
                except IntegrityError:
                    context.set_trailing_metadata((("maki-crypto-error", "auth-tag-mismatch"),))
                    context.abort(grpc.StatusCode.FAILED_PRECONDITION, "integrity")
                return pb.CryptoBatchResponse(
                    items=[pb.CryptoItem(unit_index=u, data=d) for u, d in out]).SerializeToString()
            return grpc.unary_unary_rpc_method_handler(
                unary, request_deserializer=pb.CryptoBatchRequest.FromString, response_serializer=lambda b: b)

        class Handler(grpc.GenericRpcHandler):
            def service(self, details):
                m = details.method
                if m == prefix + "/maki.CryptoService/EncryptBatch":
                    return serve("encrypt")
                if m == prefix + "/maki.CryptoService/DecryptBatch":
                    return serve("decrypt")
                return None

        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=max_workers),
                                  handlers=[Handler()],
                                  options=[("grpc.max_receive_message_length", max_msg),
                                           ("grpc.max_send_message_length", max_msg),
                                           ("grpc.so_reuseport", 0)])
        bind = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        if tls:
            self.port = self.server.add_secure_port(bind, tls)
        else:
            self.port = self.server.add_insecure_port(bind)
        self.server.start()

    def url(self, name=None):
        host = name or (f"[{self.host}]" if ":" in self.host else self.host)
        return f"{'https' if self.tls else 'http'}://{host}:{self.port}"

    def stop(self, grace=0):
        self.server.stop(grace)


def grpc_creds(cert, key, ca=None, require_client=False):
    import grpc
    with open(key, "rb") as f:
        k = f.read()
    with open(cert, "rb") as f:
        c = f.read()
    root = None
    if ca:
        with open(ca, "rb") as f:
            root = f.read()
    return grpc.ssl_server_credentials([(k, c)], root_certificates=root, require_client_auth=require_client)


# ------------------------------------------------------------------ volume config

HTTP_MAPPING = """
[crypto.http.{op}]
method = "POST"
path = "/v1/{op}"
{headers}
[crypto.http.{op}.body]
type = "json"
items_path = "/items"
[crypto.http.{op}.body.fields]
"/volume" = {{ source = "volume_id" }}
"/profile" = {{ source = "compatibility_id" }}
"/format" = {{ source = "format_version" }}
[crypto.http.{op}.body.item_fields]
"/unit" = {{ source = "unit_index" }}
"/data" = {{ source = "payload", encoding = "base64" }}
[crypto.http.{op}.response]
type = "json"
items_path = "/items"
item_index_path = "/unit"
data_path = "/data"
encoding = "base64"
"""


def config_text(root, control, transport, urls, name="a9vol", size="4MiB", unit=4096, block=512,
                shard="64KiB", max_io="64KiB", seg="64KiB", jmax="1MiB",
                integrity="contractual", context_binding="contractual", retry_safe=True,
                policy="stall", max_operation_time=None, timeout="2s", tls="", extra_transport="",
                extra_crypto="", extra_limits="", extra_batch="", extra_nbd="", extra_top="",
                retry='initial_delay = "20ms"\nmax_delay = "200ms"',
                budget='retry_ratio = 1.0\nburst = 64\nminimum_probe_rate = "50/s"',
                breaker='failure_threshold = 3\nopen_initial = "200ms"\nopen_max = "1s"',
                http_headers="", cache=None, extra_backing="", metadata=""):
    section = {"http": "http", "ws": "websocket", "grpc": "grpc"}[transport]
    provider = {"http": "remote-http", "ws": "remote-websocket", "grpc": "remote-grpc"}[transport]
    eps = "".join(f'[[crypto.{section}.endpoint]]\nname = "ep{i}"\nurl = "{u}"\n' for i, u in enumerate(urls))
    mapping = ""
    if transport == "http":
        mapping = HTTP_MAPPING.format(op="encrypt", headers=http_headers) + HTTP_MAPPING.format(op="decrypt", headers=http_headers)
    mot = f'max_operation_time = "{max_operation_time}"\n' if max_operation_time else ""
    tls_s = f"[crypto.{section}.tls]\n{tls}\n" if tls else ""
    md = f"[crypto.grpc.metadata]\n{metadata}\n" if metadata else ""
    cache_s = f"[cache]\n{cache}\n" if cache else ""
    return f"""
config_schema_version = 1
{extra_top}
[volume]
name = "{name}"
max_virtual_size = "{size}"
device_block_size = {block}
crypto_unit_size = {unit}
shard_logical_size = "{shard}"
[crypto]
provider = "{provider}"
crypto_compatibility_id = "a9p-profile-v1"
availability_policy = "{policy}"
{mot}{extra_crypto}
[crypto.capabilities]
supported_plaintext_sizes = [{unit}]
max_ciphertext_size = {unit + OVERHEAD}
retry_safe = {"true" if retry_safe else "false"}
integrity = "{integrity}"
context_binding = "{context_binding}"
[crypto.retry]
{retry}
[crypto.retry_budget]
{budget}
[crypto.circuit_breaker]
{breaker}
[crypto.batch]
{extra_batch}
[crypto.{section}]
timeout = "{timeout}"
{extra_transport}
{eps}
{tls_s}{md}{mapping}
[backing]
root = "{root}"
journal_segment_size = "{seg}"
journal_max_bytes = "{jmax}"
journal_emergency_reserve_bytes = "0B"
{extra_backing}
[limits]
{extra_limits}
{cache_s}
[nbd]
minimum_io = {block}
maximum_io = "{max_io}"
{extra_nbd}
[control]
socket = "{control}"
"""


class Vol:
    def __init__(self, tag, transport, urls, base=None, **cfg):
        os.makedirs(base or BASE, exist_ok=True)
        self.dir = tempfile.mkdtemp(prefix=f"{tag}-", dir=base or BASE)
        os.chmod(self.dir, 0o700)
        self.root = os.path.join(self.dir, "volume")
        self.cfg = os.path.join(self.dir, "volume.toml")
        self.sock = os.path.join(self.dir, "nbd.sock")
        self.control = os.path.join(self.dir, "control.sock")
        self.transport = transport
        self.proc = None
        self.n = 0
        self.cfgargs = dict(cfg)
        self.write_config(urls)

    def write_config(self, urls, **over):
        args = dict(self.cfgargs)
        args.update(over)
        self.text = config_text(self.root, self.control, self.transport, urls, **args)
        with open(self.cfg, "w") as f:
            f.write(self.text)
        os.chmod(self.cfg, 0o644)

    def create(self, check=True, env=None):
        e = dict(os.environ)
        if env:
            e.update(env)
        r = subprocess.run([MAKI, "volume", "create", self.cfg], capture_output=True, text=True, env=e, timeout=120)
        if check and r.returncode != 0:
            raise RuntimeError(f"create failed: {r.returncode} {r.stdout} {r.stderr}")
        return r

    def maki(self, *args, timeout=60, env=None):
        e = dict(os.environ)
        if env:
            e.update(env)
        return subprocess.run([MAKI, *args], capture_output=True, text=True, timeout=timeout, env=e)

    def start(self, env=None, wait=True, timeout=60, threads=None, nbdkit_args=()):
        try:
            os.unlink(self.sock)
        except FileNotFoundError:
            pass
        self.n += 1
        npath = os.path.join(self.dir, f"notify-{self.n}.sock")
        self.notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.notify.bind(npath)
        self.notify.settimeout(0.05)
        self.logpath = os.path.join(self.dir, f"nbdkit-{self.n}.log")
        self.log = open(self.logpath, "wb")
        cmd = ["nbdkit", "--foreground", "-U", self.sock]
        if threads:
            cmd += ["-t", str(threads)]
        cmd += list(nbdkit_args) + [PLUGIN, f"config={self.cfg}"]
        e = dict(os.environ)
        e["NOTIFY_SOCKET"] = npath
        e.pop("LIBNBD_DEBUG", None)
        if env:
            e.update(env)
        self.proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=self.log,
                                     stderr=subprocess.STDOUT, env=e, start_new_session=True)
        if wait:
            self.wait_ready(timeout)
        return self.proc

    def wait_ready(self, timeout=60):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                data = self.notify.recv(4096)
                if b"READY=1" in data.split(b"\n"):
                    return True
            except (socket.timeout, BlockingIOError):
                pass
            if self.proc.poll() is not None:
                raise RuntimeError(f"nbdkit exited {self.proc.returncode} before READY: {self.read_log()[-3000:]}")
        raise RuntimeError(f"READY timeout: {self.read_log()[-3000:]}")

    def read_log(self, n=None):
        try:
            self.log.flush()
        except Exception:
            pass
        with open(self.logpath if n is None else os.path.join(self.dir, f"nbdkit-{n}.log"), "rb") as f:
            return f.read().decode("utf-8", "replace")

    def all_logs_bytes(self):
        out = b""
        for i in range(1, self.n + 1):
            p = os.path.join(self.dir, f"nbdkit-{i}.log")
            if os.path.exists(p):
                with open(p, "rb") as f:
                    out += f.read()
        return out

    def kill9(self):
        if self.proc and self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGKILL)
        if self.proc:
            self.proc.wait()
        try:
            self.notify.close()
        except Exception:
            pass

    def term(self, timeout=60):
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
        try:
            rc = self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            rc = None
        try:
            self.notify.close()
        except Exception:
            pass
        return rc

    def rss_kb(self):
        try:
            with open(f"/proc/{self.proc.pid}/status") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        return int(line.split()[1])
        except Exception:
            return None

    def cleanup(self):
        try:
            self.kill9()
        except Exception:
            pass
        if not os.environ.get("A9P_KEEP"):
            shutil.rmtree(self.dir, ignore_errors=True)


def connect(sock, **kw):
    import nbd
    h = nbd.NBD()
    for k, v in kw.items():
        getattr(h, k)(v)
    h.connect_unix(sock)
    return h


def pattern(offset, length, version, seed=0):
    """Self-describing data: every 512-byte sector carries its sector number,
    the write version and a keyed digest."""
    assert offset % 512 == 0 and length % 512 == 0
    out = bytearray()
    for s in range(offset // 512, (offset + length) // 512):
        head = struct.pack("<QQQ", s, version, seed)
        body = hashlib.blake2b(head, digest_size=64).digest()
        out += (head + body * 8)[:512]
    return bytes(out)


def describe(sector):
    if sector == bytes(512):
        return "zeros"
    s, v, seed = struct.unpack("<QQQ", sector[:24])
    if pattern(s * 512, 512, v, seed) == sector:
        return f"sector={s} version={v} seed={seed}"
    return "garbage:" + sector[:24].hex()


def forms(data):
    """Encodings of a plaintext sample a log or error text could carry."""
    return {
        "raw": data,
        "b64": base64.b64encode(data),
        "b64url": base64.urlsafe_b64encode(data).rstrip(b"="),
        "hex": data.hex().encode(),
        "HEX": data.hex().upper().encode(),
        "debug": repr(list(data))[1:-1].encode(),
    }


def grep_secrets(blob, samples, window=24):
    """Search `blob` for any `window`-byte slice of each encoded sample."""
    hits = []
    for label, data in samples:
        for kind, enc in forms(data).items():
            for start in range(0, max(1, len(enc) - window + 1), max(1, window // 2)):
                piece = enc[start:start + window]
                if len(piece) >= min(window, len(enc)) and piece in blob:
                    hits.append((label, kind, start))
                    break
    return hits
