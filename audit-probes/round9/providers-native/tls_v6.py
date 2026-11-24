"""IPv6 literal endpoints ([::1]) through the real daemon, on a kernel
without IPv6, via v6shim.so (see v6shim.c). Cases per transport:
  plain    http://[::1] / ws://[::1]   (loopback plaintext is allowed)
  tls-ip   certificate with IP SAN ::1           -> must attach
  tls-dns  certificate with DNS SAN "::1" only   -> must be refused
  tls-v4   certificate with IP SAN 127.0.0.1 only-> must be refused
"""
import sys, os, time
import rp
only = sys.argv[1:] or ["http", "ws", "grpc"]
pki = rp.Pki(os.path.join(rp.BASE, "pki6-%d" % os.getpid()))
ip6 = pki.leaf("ip6", dns=(), ips=("::1",))
dns6 = pki.leaf("dns6", dns=("localhost",), ips=())
v4only = pki.leaf("v4only", dns=(), ips=("127.0.0.1",))
SHIM = os.path.join(rp.HERE, "v6shim.so")
env = {"LD_PRELOAD": SHIM, "V6SHIM_LOG": "1"}
CA = f'ca_file = "{pki.ca_path}"'
bad = 0
for transport in only:
    for name, cert, expected in [("plain", None, "ok"), ("tls-ip", ip6, "ok"), ("tls-dns", dns6, "refuse"), ("tls-v4", v4only, "refuse")]:
        beh = rp.Behaviour()
        tls = None
        if cert:
            tls = rp.grpc_creds(*cert) if transport == "grpc" else rp.server_ssl_context(*cert)
        srv = {"http": rp.HttpServer, "ws": rp.WsServer, "grpc": rp.GrpcServer}[transport](beh, tls=tls)
        url = srv.url("[::1]")
        v = rp.Vol(f"v6-{transport}-{name}", transport, [url], tls=CA if cert else "",
                   policy="bounded-error", max_operation_time="4s")
        got, detail = "?", ""
        try:
            r = v.create(check=False, env=env)
            if r.returncode != 0:
                got, detail = "refuse(create)", r.stderr.strip().splitlines()[-1][:300]
            else:
                try:
                    v.start(env=env, timeout=40)
                    h = rp.connect(v.sock)
                    d = rp.pattern(0, 8192, 3)
                    h.pwrite(d, 0); h.flush()
                    assert h.pread(8192, 0) == d
                    h.shutdown()
                    got, detail = "ok", f"term={v.term()} calls={beh.calls}"
                except RuntimeError:
                    got = "refuse"
                    lines = [l for l in v.read_log().splitlines() if l.strip() and "v6shim" not in l]
                    detail = " || ".join(lines[-2:])[:400]
            shim = v.all_logs_bytes().count(b"v6shim: connect")
        finally:
            v.cleanup(); srv.stop()
        verdict = "PASS" if got.startswith(expected) else "MISMATCH"
        bad += verdict != "PASS"
        print(f"{verdict} {transport:5} {url.split('://')[0]:5} [::1] {name:8} expected={expected:7} got={got:8} shim_connects={shim} {detail}")
        sys.stdout.flush()
print("mismatches", bad)
