"""Round 9 (takeover): attach while every endpoint fails, by endpoint count and
policy. One raw TLS listener per endpoint presents a certificate for another
name (or requires a client certificate); it counts connection attempts.

Per case prints: whether nbdkit exited within WAIT s, the daemon's log lines,
whether the control socket exists, the sd_notify messages received, how many
TLS connections each endpoint saw, the RSS, and what SIGTERM then does.

usage: attach_stall2.py [WAIT]
"""
import os, signal, socket, ssl, sys, threading, time
import rp

WAIT = float(sys.argv[1]) if len(sys.argv) > 1 else 30.0
pki = rp.Pki(os.path.join(rp.BASE, "pkias2-%d" % os.getpid()))
other = pki.leaf("as2other", dns=("other.example",), ips=())
good = pki.leaf("as2good")
CA = f'ca_file = "{pki.ca_path}"'


class Listener:
    def __init__(self, cert, require_client=False):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(*cert)
        self.ctx.set_alpn_protocols(["h2", "http/1.1"])
        if require_client:
            self.ctx.load_verify_locations(pki.ca_path)
            self.ctx.verify_mode = ssl.CERT_REQUIRED
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        self.accepts = 0
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            self.accepts += 1
            threading.Thread(target=self.one, args=(c,), daemon=True).start()

    def one(self, c):
        t = None
        try:
            t = self.ctx.wrap_socket(c, server_side=True, do_handshake_on_connect=False)
            t.settimeout(3)
            t.do_handshake()
            time.sleep(0.5)
        except (ssl.SSLError, OSError):
            pass
        try:
            (t or c).close()
        except OSError:
            pass

    def url(self, transport):
        return {"http": "https", "ws": "wss", "grpc": "https"}[transport] + f"://localhost:{self.port}"

    def stop(self):
        self.sock.close()


def notify_messages(v):
    out = []
    while True:
        try:
            out.append(v.notify.recv(4096).decode(errors="replace").replace("\n", "|"))
        except (socket.timeout, BlockingIOError, OSError):
            return out


def run(name, transport, n, policy, mode):
    if mode == "mismatch":
        ls = [Listener(other) for _ in range(n)]
        tls = CA
    else:  # server requires a client certificate the client does not have
        ls = [Listener(good, require_client=True) for _ in range(n)]
        tls = CA
    extra = {"max_operation_time": "4s"} if policy == "bounded-error" else {}
    v = rp.Vol(f"as2-{name}", transport, [l.url(transport) for l in ls], tls=tls, policy=policy, **extra)
    v.create()
    t = time.monotonic()
    v.start(wait=False)
    while time.monotonic() - t < WAIT and v.proc.poll() is None:
        time.sleep(0.25)
    waited = time.monotonic() - t
    lines = [l for l in v.read_log().splitlines() if l.strip()]
    rss = v.rss_kb()
    msgs = notify_messages(v)
    line = (f"{name:30} after {waited:4.1f}s exit={v.proc.poll()} log_lines={len(lines)} "
            f"control_sock={os.path.exists(v.control)} notify={msgs} tls_accepts={[l.accepts for l in ls]} rss_kb={rss}")
    if v.proc.poll() is None:
        v.proc.send_signal(signal.SIGTERM)
        t2 = time.monotonic()
        while time.monotonic() - t2 < 10 and v.proc.poll() is None:
            time.sleep(0.25)
        line += f" | SIGTERM: exit={v.proc.poll()} after {time.monotonic() - t2:.1f}s"
    print(line, flush=True)
    for l in lines[-3:]:
        print("      LOG", l[:200], flush=True)
    v.cleanup()
    for l in ls:
        l.stop()


for transport in ("http", "ws", "grpc"):
    run(f"{transport}-mismatch-1ep-stall", transport, 1, "stall", "mismatch")
    run(f"{transport}-mismatch-2ep-stall", transport, 2, "stall", "mismatch")
run("grpc-noclientcert-1ep-stall", "grpc", 1, "stall", "clientcert")
run("grpc-noclientcert-2ep-stall", "grpc", 2, "stall", "clientcert")
run("http-mismatch-1ep-bounded", "http", 1, "bounded-error", "mismatch")
