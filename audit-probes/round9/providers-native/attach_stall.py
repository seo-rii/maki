"""Attach while the provider cannot be used, default `stall` policy.
What does the operator see, and can the daemon be stopped?
cases: tls-mismatch (certificate for another name), refused (nothing
listens), http-401, and the same with two endpoints."""
import sys, os, time, signal, socket
import rp
pki = rp.Pki(os.path.join(rp.BASE, "pkia-%d" % os.getpid()))
other = pki.leaf("othername", dns=("other.example",), ips=())
CA = f'ca_file = "{pki.ca_path}"'

def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

def run(name, transport, urls, tls, servers, wait=35):
    v = rp.Vol(f"as-{name}", transport, urls, tls=tls)
    v.create()
    t = time.monotonic()
    v.start(wait=False)
    while time.monotonic() - t < wait and v.proc.poll() is None:
        time.sleep(0.5)
    waited = time.monotonic() - t
    log = v.read_log()
    lines = [l for l in log.splitlines() if l.strip()]
    st = v.maki("status", v.cfg, "--timeout", "3", timeout=20)
    line = f"{name:22} after {waited:4.1f}s: exit={v.proc.poll()} log_lines={len(lines)} status_rc={st.returncode} ({(st.stderr.strip().splitlines() or [''])[-1][:90]})"
    if v.proc.poll() is None:
        v.proc.send_signal(signal.SIGTERM)
        t2 = time.monotonic()
        while time.monotonic() - t2 < 15 and v.proc.poll() is None:
            time.sleep(0.25)
        line += f" | SIGTERM: exit={v.proc.poll()} after {time.monotonic() - t2:.1f}s; log_lines={len([l for l in v.read_log().splitlines() if l.strip()])}"
    print(line)
    for l in lines[-3:]:
        print("      LOG", l[:230])
    v.cleanup()
    for s in servers:
        s.stop()

beh = rp.Behaviour()
ctx = rp.server_ssl_context(*other)
for transport, cls in (("http", rp.HttpServer), ("ws", rp.WsServer), ("grpc", None)):
    if transport == "grpc":
        s1 = rp.GrpcServer(beh, tls=rp.grpc_creds(*other)); s2 = rp.GrpcServer(beh, tls=rp.grpc_creds(*other))
    else:
        s1 = cls(beh, tls=ctx); s2 = cls(beh, tls=ctx)
    run(f"{transport}-tls-mismatch-1ep", transport, [s1.url("localhost")], CA, [])
    run(f"{transport}-tls-mismatch-2ep", transport, [s1.url("localhost"), s2.url("localhost")], CA, [s1, s2])
    scheme = {"http": "http", "ws": "ws", "grpc": "http"}[transport]
    run(f"{transport}-refused-1ep", transport, [f"{scheme}://127.0.0.1:{free_port()}"], "", [])
