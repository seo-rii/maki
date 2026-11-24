import sys, os, time, datetime
import rp
transport = sys.argv[1]
pki = rp.Pki(os.path.join(rp.BASE, "pki1-%d" % os.getpid()))
other = pki.leaf("othername", dns=("other.example",), ips=())
beh = rp.Behaviour()
ctx = rp.server_ssl_context(other[0], other[1])
srv = rp.HttpServer(beh, tls=ctx) if transport == "http" else rp.WsServer(beh, tls=ctx) if transport == "ws" else rp.GrpcServer(beh, tls=rp.grpc_creds(other[0], other[1]))
v = rp.Vol(f"tls1-{transport}", transport, [srv.url("localhost")], tls=f'ca_file = "{pki.ca_path}"')
r = v.create(check=False); print("create", r.returncode, r.stderr[-300:])
t = time.monotonic()
v.start(wait=False)
for i in range(40):
    time.sleep(0.5)
    if v.proc.poll() is not None:
        break
print("after %.1fs: nbdkit rc=%s" % (time.monotonic() - t, v.proc.poll()))
print(v.read_log()[-2500:])
r = v.maki("status", v.cfg, timeout=20); print("status", r.returncode, r.stdout[-300:], r.stderr[-300:])
v.cleanup(); srv.stop()
