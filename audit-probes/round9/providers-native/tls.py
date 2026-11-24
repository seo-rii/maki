"""TLS matrix through the real daemon: each transport x trust/identity case.
One line per case: transport case expected got [last daemon error line]."""
import sys, os, time, datetime, re
import rp

only_t = [a for a in sys.argv[1:] if a in ("http", "ws", "grpc")] or ["http", "ws", "grpc"]
only_c = [a for a in sys.argv[1:] if a not in ("http", "ws", "grpc")]

pki = rp.Pki(os.path.join(rp.BASE, "pki-%d" % os.getpid()))
now = datetime.datetime.utcnow()
good = pki.leaf("good")
dns_only = pki.leaf("dnsonly", dns=("localhost", "127.0.0.1"), ips=())
other_name = pki.leaf("othername", dns=("other.example",), ips=())
expired = pki.leaf("expired", not_before=now - datetime.timedelta(days=10), not_after=now - datetime.timedelta(days=1))
future = pki.leaf("future", not_before=now + datetime.timedelta(days=1), not_after=now + datetime.timedelta(days=10))
big = pki.leaf("big", pad_bytes=60000)
huge = pki.leaf("huge", pad_bytes=200000)
other_ca = pki.other_ca()
foreign = pki.leaf("foreign", ca=other_ca)
client = pki.leaf("client", dns=(), ips=(), client=True)
foreign_client = pki.leaf("foreignclient", dns=(), ips=(), client=True, ca=other_ca)
empty_store = pki.write("empty.pem", b"")

CA = f'ca_file = "{pki.ca_path}"'


def mtls(c):
    return CA + f'\nclient_cert_file = "{c[0]}"\nclient_key = {{ source = "file", name = "{c[1]}" }}'


# name, server cert, host in URL, bind host, tls section, env, expected, server opts
CASES = [
    ("pinned-dns", good, "localhost", "127.0.0.1", CA, {}, "ok", {}),
    ("pinned-ipv4", good, None, "127.0.0.1", CA, {}, "ok", {}),
    # pinned-ipv6: this kernel has no IPv6 (see v6shim.c / tls_v6.py)
    ("ip-literal-dns-san-only", dns_only, None, "127.0.0.1", CA, {}, "refuse", {}),
    ("default-trust-env", good, "localhost", "127.0.0.1", "", {"SSL_CERT_FILE": pki.ca_path}, "ok", {}),
    ("no-trust", good, "localhost", "127.0.0.1", "", {"SSL_CERT_FILE": empty_store, "SSL_CERT_DIR": "/nonexistent"}, "refuse", {}),
    ("name-mismatch", other_name, "localhost", "127.0.0.1", CA, {}, "refuse", {}),
    ("expired", expired, "localhost", "127.0.0.1", CA, {}, "refuse", {}),
    ("not-yet-valid", future, "localhost", "127.0.0.1", CA, {}, "refuse", {}),
    ("foreign-ca", foreign, "localhost", "127.0.0.1", CA, {}, "refuse", {}),
    ("big-cert-60k", big, "localhost", "127.0.0.1", CA, {}, "any", {}),
    ("huge-cert-200k", huge, "localhost", "127.0.0.1", CA, {}, "any", {}),
    ("tls12-only", good, "localhost", "127.0.0.1", CA, {}, "ok", {"tls12": True}),
    ("mtls-ok", good, "localhost", "127.0.0.1", mtls(client), {}, "ok", {"client": True}),
    ("mtls-missing-client-cert", good, "localhost", "127.0.0.1", CA, {}, "refuse", {"client": True}),
    ("mtls-foreign-client-cert", good, "localhost", "127.0.0.1", mtls(foreign_client), {}, "refuse", {"client": True}),
]

failures = 0
POLICY = os.environ.get("A9P_POLICY", "bounded-error")
MOT = None if POLICY == "stall" else "4s"
READY_TIMEOUT = float(os.environ.get("A9P_READY_TIMEOUT", "40"))
for transport in only_t:
    for name, cert, urlhost, bind, tls, env, expected, opts in CASES:
        if only_c and name not in only_c:
            continue
        beh = rp.Behaviour()
        try:
            if transport == "grpc":
                creds = rp.grpc_creds(cert[0], cert[1], ca=pki.ca_path if opts.get("client") else None,
                                      require_client=bool(opts.get("client")))
                if opts.get("tls12"):
                    print(transport, name, "SKIP (grpcio server cannot be capped at TLS 1.2 here)")
                    continue
                srv = rp.GrpcServer(beh, host=bind, tls=creds)
            else:
                ctx = rp.server_ssl_context(cert[0], cert[1], ca=pki.ca_path if opts.get("client") else None,
                                            require_client=bool(opts.get("client")), tls12=bool(opts.get("tls12")))
                srv = (rp.HttpServer if transport == "http" else rp.WsServer)(beh, host=bind, tls=ctx)
        except Exception as e:
            print(transport, name, "SERVER SETUP FAILED", repr(e))
            continue
        v = rp.Vol(f"tls-{transport}-{name}", transport, [srv.url(urlhost)], tls=tls, policy=POLICY, max_operation_time=MOT)
        got, detail = "?", ""
        try:
            r = v.create(check=False, env=env)
            if r.returncode != 0:
                got, detail = "refuse(create)", (r.stderr.strip().splitlines() or [""])[-1]
            else:
                try:
                    v.start(env=env, timeout=READY_TIMEOUT)
                    h = rp.connect(v.sock)
                    d = rp.pattern(0, 8192, 7)
                    h.pwrite(d, 0)
                    h.flush()
                    assert h.pread(8192, 0) == d
                    h.shutdown()
                    got = "ok"
                    rc = v.term()
                    detail = f"term={rc} calls={beh.calls}"
                except RuntimeError as e:
                    got = "refuse"
                    lines = [l for l in v.read_log().splitlines() if l.strip()]
                    detail = " || ".join(lines[-3:])[:900]
        finally:
            log = v.all_logs_bytes()
            v.cleanup()
            try:
                srv.stop()
            except Exception:
                pass
        verdict = "PASS" if expected in ("any", got) or (expected == "refuse" and got.startswith("refuse")) else "MISMATCH"
        if verdict != "PASS":
            failures += 1
        # no private key material or PEM bodies in daemon output
        leak = b"PRIVATE KEY" in log or b"BEGIN CERT" in log
        print(f"{verdict} {transport:5} {name:28} expected={expected:7} got={got:15} leak={leak} {detail}")
        sys.stdout.flush()
print("failures", failures)
