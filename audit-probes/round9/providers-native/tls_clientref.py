"""Round 9 (takeover): how each transport classifies a server-side refusal of
the client certificate, with the SAME raw TLS listener for all three.

The listener speaks no application protocol: it accepts, runs the TLS
handshake with a client certificate required, and on failure either keeps
the socket open for HOLD seconds (so the client reads the server's alert
before anything else) or closes it at once (the alert may be lost to the
RST that the client's first application write provokes).

Attach runs under bounded-error (4 s) so the daemon exits; the line printed
is the daemon's "startup failed" line, which carries the error class.

usage: tls_clientref.py [http|ws|grpc ...]
"""
import os, socket, ssl, sys, threading, time
import rp

transports = sys.argv[1:] or ["http", "ws", "grpc"]
pki = rp.Pki(os.path.join(rp.BASE, "pkicr-%d" % os.getpid()))
server = pki.leaf("crserver")
client = pki.leaf("crclient", dns=(), ips=(), client=True)
other_ca = pki.other_ca()
foreign = pki.leaf("crforeign", dns=(), ips=(), client=True, ca=other_ca)
CA = f'ca_file = "{pki.ca_path}"'


def mtls(c):
    return CA + f'\nclient_cert_file = "{c[0]}"\nclient_key = {{ source = "file", name = "{c[1]}" }}'


class Listener:
    def __init__(self, hold, tls12=False):
        self.hold = hold
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(*server)
        self.ctx.load_verify_locations(pki.ca_path)
        self.ctx.verify_mode = ssl.CERT_REQUIRED
        self.ctx.set_alpn_protocols(["h2", "http/1.1"])
        if tls12:
            self.ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        self.failures = []
        self.stop_flag = False
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while not self.stop_flag:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.one, args=(c,), daemon=True).start()

    def one(self, c):
        t = None
        try:
            t = self.ctx.wrap_socket(c, server_side=True, do_handshake_on_connect=False)
            t.do_handshake()
            self.failures.append("handshake-ok")
            t.close()
            return
        except ssl.SSLError as e:
            self.failures.append(e.reason or str(e))
        except OSError as e:
            self.failures.append(f"os:{e.errno}")
        if t is not None:
            try:
                c = socket.socket(fileno=t.detach())
            except OSError:
                return
        if self.hold:
            c.settimeout(0.2)
            end = time.monotonic() + self.hold
            while time.monotonic() < end:
                try:
                    if not c.recv(65536):
                        break
                except socket.timeout:
                    pass
                except OSError:
                    break
        try:
            c.close()
        except OSError:
            pass

    def url(self, transport):
        scheme = {"http": "https", "ws": "wss", "grpc": "https"}[transport]
        return f"{scheme}://localhost:{self.port}"

    def stop(self):
        self.stop_flag = True
        self.sock.close()


CASES = [
    # name, client identity, hold seconds, tls12
    ("tls13-missing-hold", None, 3.0, False),
    ("tls13-missing-close", None, 0.0, False),
    ("tls13-foreign-hold", foreign, 3.0, False),
    ("tls13-foreign-close", foreign, 0.0, False),
    ("tls12-missing-hold", None, 3.0, True),
    ("tls12-foreign-hold", foreign, 3.0, True),
]

for transport in transports:
    for name, ident, hold, tls12 in CASES:
        if transport == "grpc" and tls12:
            # tonic needs TLS 1.3 ALPN h2 over TLS 1.2 is allowed; keep it.
            pass
        lst = Listener(hold, tls12)
        tls = mtls(ident) if ident else CA
        v = rp.Vol(f"cr-{transport}-{name}", transport, [lst.url(transport)], tls=tls,
                   policy="bounded-error", max_operation_time="4s")
        v.create()
        t = time.monotonic()
        v.start(wait=False)
        while time.monotonic() - t < 30 and v.proc.poll() is None:
            time.sleep(0.25)
        log = v.read_log()
        last = [l for l in log.splitlines() if "startup failed" in l or "quarantined" in l]
        print(f"{transport:5} {name:22} exit={v.proc.poll()} after {time.monotonic() - t:4.1f}s "
              f"server-saw={sorted(set(lst.failures))} :: {(last or ['<no line>'])[-1][-140:]}", flush=True)
        v.cleanup()
        lst.stop()
