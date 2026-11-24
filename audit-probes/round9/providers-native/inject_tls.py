"""Round 9 (takeover): endpoint-controlled TLS strings in the daemon's log.

The endpoint presents a certificate whose subject CN and DNS SANs carry a
marker, terminal escapes, CR/LF and a long tail, for another name than the
one configured (so verification fails and every layer that formats the
failure sees the presented names). A second case presents a certificate the
client trusts and then answers the client with garbage TLS records. Run at
MAKI_LOG=trace and at the default level, bounded-error 3 s, each transport.
The daemon log and the `maki status` output (absent: no control socket) are
searched for the marker (any case), for ESC and for raw CR inside a line.
"""
import datetime, ipaddress, os, socket, ssl, sys, threading, time
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import rp

pki = rp.Pki(os.path.join(rp.BASE, "pkiinj-%d" % os.getpid()))
MARK = "EvIlMaRk"
evil_cn = MARK + "-cn \x1b[31mRED\x1b[0m\r\nFAKE LOG LINE level=ERROR " + "Z" * 3000
evil_dns = [MARK.lower() + "-san.example", MARK.lower() + "-\x1b[2J.example", "x" * 60 + "." + MARK.lower() + ".example"]


def evil_leaf():
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, evil_cn[:64]),
                                  x509.NameAttribute(NameOID.ORGANIZATION_NAME, evil_cn)]))
         .issuer_name(pki.ca_cert.subject).public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(days=1))
         .not_valid_after(now + datetime.timedelta(days=7))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(d) for d in evil_dns]), critical=False)
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
    cert = b.sign(pki.ca_key, hashes.SHA256())
    cp = pki.write("evil.crt", cert.public_bytes(serialization.Encoding.PEM))
    kp = pki.write("evil.key", key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                 serialization.NoEncryption()), 0o600)
    return cp, kp


class Listener:
    """mode "mismatch": TLS with the evil certificate. mode "garbage": accept
    TCP and answer the ClientHello with a fake TLS alert record and text."""
    def __init__(self, mode, cert):
        self.mode = mode
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(*cert)
        self.ctx.set_alpn_protocols(["h2", "http/1.1"])
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.one, args=(c,), daemon=True).start()

    def one(self, c):
        try:
            if self.mode == "garbage":
                c.settimeout(2)
                c.recv(4096)
                c.sendall(b"HTTP/1.1 400 " + MARK.encode() + b"\x1b[31m\r\n\r\n" + (MARK + "\x1b[2J\r\nFAKE").encode() * 50)
            else:
                t = self.ctx.wrap_socket(c, server_side=True, do_handshake_on_connect=False)
                t.settimeout(2)
                t.do_handshake()
                c = t
        except (ssl.SSLError, OSError):
            pass
        time.sleep(0.3)
        try:
            c.close()
        except OSError:
            pass

    def url(self, transport):
        return {"http": "https", "ws": "wss", "grpc": "https"}[transport] + f"://localhost:{self.port}"


cert = evil_leaf()
problems = []
for level in ("trace", None):
    for mode in ("mismatch", "garbage"):
        for transport in ("http", "ws", "grpc"):
            lst = Listener(mode, cert)
            v = rp.Vol(f"inj-{transport}-{mode}", transport, [lst.url(transport)],
                       tls=f'ca_file = "{pki.ca_path}"', policy="bounded-error", max_operation_time="3s")
            v.create()
            env = {"MAKI_LOG": level} if level else None
            v.start(wait=False, env=env)
            t = time.monotonic()
            while time.monotonic() - t < 30 and v.proc.poll() is None:
                time.sleep(0.25)
            blob = v.all_logs_bytes()
            marks = blob.lower().count(MARK.lower().encode())
            esc = blob.count(b"\x1b")
            cr = blob.count(b"\r")
            last = [l for l in blob.decode("utf-8", "replace").splitlines() if "startup failed" in l]
            print(f"{str(level):5} {mode:8} {transport:5} exit={v.proc.poll()} log={len(blob)}B marker={marks} "
                  f"ESC={esc} CR={cr} :: {(last or ['<none>'])[-1][-110:]}", flush=True)
            if marks or esc or cr:
                problems.append((level, mode, transport, marks, esc, cr))
                idx = blob.lower().find(MARK.lower().encode())
                print("     context:", blob[max(0, idx - 200): idx + 200])
            v.cleanup()
            lst.sock.close()
print("PROBLEMS" if problems else "CLEAN", problems)
