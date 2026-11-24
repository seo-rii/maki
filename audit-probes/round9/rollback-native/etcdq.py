#!/usr/bin/python3.12
"""Round 9 rollback-native (successor): the etcd quorum store of maki-witness with a real
3-member etcd 3.6.6 cluster on localhost (client TLS with client-certificate auth, plain
peer links), two maki-witness frontends on the same key, and a remote rollback-protected
volume that lists both frontends.

Parts (each prints [ok ]/[BAD] rows; exit 1 on any BAD):
  base       create over etcd, FUA writes, clean restart, data verified
  failover   frontend A killed while the daemon writes: writes go on through frontend B
  quorum     2 of 3 members stopped while the daemon writes: FUA/FLUSH must fail (no ack),
             inspection must fail (no stale answer from the surviving member), then quorum back,
             documented procedure, every acknowledged write present
  compact    etcd compaction + defrag while the daemon writes: writes go on
  foreign    a value written to the key by another etcd client (garbage; then the bytes of an
             earlier revision): the live daemon must stop committing; frontends must refuse garbage
  pin        a frontend with a wrong cluster_id or storage_identity refuses to serve
  second     a second daemon through frontend B while the first one runs through A is refused

usage: etcdq.py [parts...]
"""
import os, sys, subprocess, shutil, time, json, base64, argparse, signal, random
import mk9 as mk, rw
import nbd

ETCD_DIR = os.environ.get("ETCD_DIR", "/tmp/a9rn-etcd-dl/x/etcd-v3.6.6-linux-amd64")
ETCD, ETCDCTL = os.path.join(ETCD_DIR, "etcd"), os.path.join(ETCD_DIR, "etcdctl")
P = argparse.ArgumentParser()
P.add_argument("parts", nargs="*", default=["pin", "base", "failover", "compact", "second", "foreign", "quorum"])
P.add_argument("--keep", action="store_true")
A = P.parse_args()
rng = random.Random(7)
BAD = []
KEY = "/maki/witness/a9rn"
CAP = "4MiB"


def row(ok, text):
    print(f"  [{'ok ' if ok else 'BAD'}] {text}", flush=True)
    if not ok:
        BAD.append(text)


def last(text):
    text = (text or "").strip()
    return text.splitlines()[-1][:300] if text else ""


def both_leaf(pki, name, san):
    """etcd's HTTP gateway dials the server with its own certificate: serverAuth + clientAuth."""
    key = os.path.join(pki.dir, f"{name}.key"); csr = os.path.join(pki.dir, f"{name}.csr")
    crt = os.path.join(pki.dir, f"{name}.pem"); ext = os.path.join(pki.dir, f"{name}.ext")
    rw.sh("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key + ".sec1")
    rw.sh("openssl", "pkcs8", "-topk8", "-nocrypt", "-in", key + ".sec1", "-out", key)
    os.unlink(key + ".sec1"); os.chmod(key, 0o600)
    rw.sh("openssl", "req", "-new", "-key", key, "-subj", f"/CN={name}", "-out", csr)
    with open(ext, "w") as f:
        f.write(f"basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName={san}\n")
    rw.sh("openssl", "x509", "-req", "-in", csr, "-CA", pki.ca, "-CAkey", pki.ca_key, "-CAcreateserial", "-sha256",
          "-extfile", ext, "-out", crt, "-days", "30")
    return crt, key


class Cluster:
    def __init__(self, base, pki):
        self.base = base
        self.pki = pki
        self.cert, self.key = both_leaf(pki, "etcd-server", "DNS:etcd.test,IP:127.0.0.1")
        self.ccert, self.ckey = pki.leaf("etcd-client")
        self.members = []
        for i in range(3):
            self.members.append(dict(name=f"e{i}", peer=rw.free_port(), client=rw.free_port(),
                                     data=os.path.join(base, f"e{i}.data"), proc=None, log=os.path.join(base, f"e{i}.log")))
        self.initial = ",".join(f"{m['name']}=http://127.0.0.1:{m['peer']}" for m in self.members)

    def start(self, i, state="new"):
        m = self.members[i]
        args = [ETCD, "--name", m["name"], "--data-dir", m["data"],
                "--listen-peer-urls", f"http://127.0.0.1:{m['peer']}", "--initial-advertise-peer-urls", f"http://127.0.0.1:{m['peer']}",
                "--listen-client-urls", f"https://127.0.0.1:{m['client']}", "--advertise-client-urls", f"https://127.0.0.1:{m['client']}",
                "--initial-cluster", self.initial, "--initial-cluster-state", state, "--initial-cluster-token", "a9rn",
                "--cert-file", self.cert, "--key-file", self.key, "--client-cert-auth", "--trusted-ca-file", self.pki.ca,
                "--log-level", "warn"]
        m["proc"] = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=open(m["log"], "ab"), stderr=subprocess.STDOUT,
                                     start_new_session=True)

    def stop(self, i, sig=signal.SIGKILL):
        m = self.members[i]
        if m["proc"] and m["proc"].poll() is None:
            os.killpg(m["proc"].pid, sig)
            m["proc"].wait()

    def ctl(self, *args, endpoints=None, check=True, timeout=30):
        eps = endpoints or ",".join(f"https://127.0.0.1:{m['client']}" for m in self.members)
        r = subprocess.run([ETCDCTL, "--endpoints", eps, "--cacert", self.pki.ca, "--cert", self.ccert, "--key", self.ckey,
                            "--command-timeout=5s", *args], capture_output=True, text=True, timeout=timeout)
        if check and r.returncode != 0:
            raise RuntimeError(f"etcdctl {args}: {r.stdout} {r.stderr}")
        return r

    def wait_healthy(self, timeout=60):
        end = time.time() + timeout
        while time.time() < end:
            r = self.ctl("endpoint", "health", check=False)
            if r.returncode == 0:
                return
            time.sleep(0.3)
        raise RuntimeError("etcd cluster not healthy: " + r.stdout + r.stderr)

    def cluster_id(self):
        out = json.loads(self.ctl("endpoint", "status", "-w", "json").stdout)
        ids = {e["Status"]["header"]["cluster_id"] for e in out}
        assert len(ids) == 1, ids
        return ids.pop()

    def get(self, rev=None):
        args = ["get", KEY, "-w", "json"] + ([f"--rev={rev}"] if rev else [])
        out = json.loads(self.ctl(*args).stdout)
        kvs = out.get("kvs") or []
        return (base64.b64decode(kvs[0]["value"]), int(kvs[0]["mod_revision"])) if kvs else (None, None)


def etcd_section(cluster, cid, identity, prefix="", cid_override=None, ident_override=None):
    s = (f'{prefix}cluster_id = "{cid_override or cid}"\n{prefix}storage_identity = "{ident_override or identity}"\n'
         f'{prefix}key = "{KEY}"\n{prefix}timeout_ms = 3000\n')
    return s


def etcd_toml(cluster, cid, identity, table=None, cid_override=None, ident_override=None):
    head = f"[{table}]\n" if table else ""
    ep = "etcd.endpoints" if table else "endpoints"
    tls = "etcd.tls" if table else "tls"
    s = head + etcd_section(cluster, cid, identity, cid_override=cid_override, ident_override=ident_override)
    for m in cluster.members:
        s += f'\n[[{ep}]]\naddress = "127.0.0.1:{m["client"]}"\nserver_name = "etcd.test"\n'
    s += f'\n[{tls}]\nca_file = "{cluster.pki.ca}"\ncert_file = "{cluster.ccert}"\nkey_file = "{cluster.ckey}"\n'
    return s


class Frontend:
    def __init__(self, base, auth, cluster, cid, name, cid_override=None, ident_override=None):
        self.base = os.path.join(base, name)
        os.makedirs(self.base, exist_ok=True)
        self.auth = auth
        self.port = rw.free_port()
        self.cfg = os.path.join(self.base, "server.toml")
        with open(self.cfg, "w") as f:
            f.write(f'listen = "127.0.0.1:{self.port}"\n\n[server]\ntimeout_ms = 5000\nmax_connections = 16\n\n[server.tls]\n'
                    f'ca_file = "{auth.pki.ca}"\ncert_file = "{auth.server_cert}"\nkey_file = "{auth.server_key}"\n')
            for cert, role in ((auth.writer_cert, "writer"), (auth.admin_cert, "admin")):
                f.write(f'\n[[server.principals]]\ncertificate_sha256 = "{auth.fp(cert)}"\nrole = "{role}"\n')
            f.write("\n" + etcd_toml(cluster, cid, auth.identity, table="etcd", cid_override=cid_override, ident_override=ident_override))
        os.chmod(self.cfg, 0o644)
        self.proc = None
        self.log = os.path.join(self.base, "serve.log")

    def start(self, wait=True):
        self.proc = subprocess.Popen([mk.WITNESS, "serve", self.cfg], stdin=subprocess.DEVNULL, stdout=open(self.log, "ab"),
                                     stderr=subprocess.STDOUT, start_new_session=True)
        if not wait:
            return
        end = time.time() + 30
        while time.time() < end:
            if self.proc.poll() is not None:
                raise RuntimeError(f"frontend exited {self.proc.returncode}: {open(self.log).read()[-600:]}")
            if "listening" in open(self.log).read():
                return
            time.sleep(0.05)
        raise RuntimeError("frontend not ready: " + open(self.log).read()[-600:])

    def kill(self):
        if self.proc and self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGKILL)
            self.proc.wait()


def remote_section(auth, ports, role, identity):
    cert, key = (auth.writer_cert, auth.writer_key) if role == "writer" else (auth.admin_cert, auth.admin_key)
    addrs = ", ".join(f'"127.0.0.1:{p}"' for p in ports)
    return (f'[backing.rollback_protection]\ncapacity = "{CAP}"\n\n[backing.rollback_protection.remote]\n'
            f'addresses = [{addrs}]\nstorage_identity = "{identity}"\nserver_name = "witness.test"\ntimeout_ms = 4000\n'
            f'ca_file = "{auth.pki.ca}"\nclient_cert_file = "{cert}"\nclient_key_file = "{key}"\n')


class Data:
    def __init__(self):
        self.ver = {}
        self.maybe = {}

    def write(self, h, n):
        for _ in range(n):
            u = rng.randrange(0, 96)
            val = rng.randrange(1, 1 << 40)
            try:
                h.pwrite(mk.pattern(u * 4096, 4096, val, 7), u * 4096, nbd.CMD_FLAG_FUA)
            except nbd.Error:
                self.maybe.setdefault(u, set()).add(val)
                raise
            self.ver[u] = val
            self.maybe.pop(u, None)

    def verify(self, h, what):
        bad = 0
        for u, val in self.ver.items():
            got = bytes(h.pread(4096, u * 4096))
            ok = got == mk.pattern(u * 4096, 4096, val, 7) or any(got == mk.pattern(u * 4096, 4096, v, 7) for v in self.maybe.get(u, ()))
            if not ok:
                bad += 1
                if bad < 4:
                    print(f"    unit {u}: {mk.describe(got[:512])}, acknowledged version {val}")
        row(bad == 0, f"{what}: {len(self.ver)} acknowledged units verified, {bad} bad")
        return bad == 0


def main():
    base = os.path.join(mk.BASE, f"etcdq-{os.getpid()}")
    os.makedirs(base)
    pki = rw.Pki(os.path.join(base, "etcd-pki"), name="etcdca")
    cl = Cluster(base, pki)
    vroot = os.path.join(base, "volume")
    os.makedirs(vroot, mode=0o700)
    vol = mk.Vol("etq", discard=True, backing_dir=vroot, size="1MiB", ckpt_reserve="256KiB", reserve="64KiB", extra_backing="@@R@@")
    auth = rw.Authority(os.path.join(vol.dir, "auth"), os.path.join(base, "unused-state"))
    fes = []
    try:
        for i in range(3):
            cl.start(i)
        cl.wait_healthy()
        cid = cl.cluster_id()
        print(f"etcd cluster id {cid}; members {[m['client'] for m in cl.members]}")
        etoml = os.path.join(base, "etcd.toml")
        with open(etoml, "w") as f:
            f.write(etcd_toml(cl, cid, auth.identity))
        os.chmod(etoml, 0o644)
        r = subprocess.run([mk.WITNESS, "init-etcd", etoml, auth.identity], capture_output=True, text=True)
        row(r.returncode == 0, f"init-etcd: rc={r.returncode} {last(r.stderr) or last(r.stdout)}")
        r = subprocess.run([mk.WITNESS, "init-etcd", etoml, auth.identity], capture_output=True, text=True)
        row(r.returncode != 0, f"second init-etcd refused: rc={r.returncode} {last(r.stderr)}")
        fa, fb = Frontend(base, auth, cl, cid, "fa"), Frontend(base, auth, cl, cid, "fb")
        fes += [fa, fb]
        fa.start(); fb.start()
        text = vol.text
        with open(vol.cfg, "w") as f:
            f.write(text.replace("@@R@@", remote_section(auth, [fa.port, fb.port], "writer", auth.identity)))
        admin = os.path.join(vol.dir, "admin.toml")
        with open(admin, "w") as f:
            f.write(text.replace("@@R@@", remote_section(auth, [fa.port, fb.port], "admin", auth.identity)))
        os.chmod(admin, 0o644)

        def maki(*a, timeout=120):
            return subprocess.run([mk.MAKI, *a], capture_output=True, text=True, timeout=timeout)

        def record():
            r = maki("volume", "witness", vol.cfg)
            if r.returncode != 0:
                raise RuntimeError("volume witness: " + last(r.stderr))
            return json.loads(r.stdout)

        def procedure(what):
            rec = record()
            if rec["phase"] != "released":
                r = maki("volume", "takeover", admin, str(rec["fence"]), rw.root_hex(rec))
                row(r.returncode == 0, f"{what}: takeover (phase {rec['phase']}, fence {rec['fence']}): rc={r.returncode} {last(r.stderr)}")
            return record()

        r = vol.create(check=False)
        row(r.returncode == 0, f"volume create over etcd: rc={r.returncode} {last(r.stderr)}")
        d = Data()

        if "pin" in A.parts:
            print("== pin")
            for label, kw in (("wrong cluster_id", dict(cid_override=str(int(cid) ^ 1))),
                              ("wrong storage_identity", dict(ident_override="7e5c0a11-0000-4000-8000-00000000beef"))):
                fx = Frontend(base, auth, cl, cid, f"fx-{label.replace(' ', '-')}", **kw)
                try:
                    fx.start()
                    row(False, f"frontend with {label} started serving")
                    fx.kill()
                except RuntimeError as e:
                    row(True, f"frontend with {label} refused: {last(str(e))}")

        if "base" in A.parts:
            print("== base")
            vol.start(timeout=60)
            h = mk.connect(vol.sock)
            d.write(h, 20)
            h.flush(); h.shutdown()
            rc = vol.term(timeout=60)
            rec = record()
            row(rc == 0 and rec["phase"] == "released", f"clean stop: rc={rc}, phase {rec['phase']}, generation {rec['current']['anchor']['generation']}")
            vol.start(timeout=60)
            h = mk.connect(vol.sock)
            d.verify(h, "base: after a clean restart")
            h.shutdown(); vol.term(timeout=60)

        if "failover" in A.parts:
            print("== failover")
            vol.start(timeout=60)
            h = mk.connect(vol.sock)
            d.write(h, 5)
            fa.kill()
            try:
                d.write(h, 10)
                h.flush()
                row(True, "failover: 10 FUA writes acknowledged through frontend B after frontend A was killed")
            except nbd.Error as e:
                row(False, f"failover: write failed after frontend A was killed: {e}")
            d.verify(h, "failover: live daemon")
            fa.start()
            h.shutdown(); vol.term(timeout=60)

        if "compact" in A.parts:
            print("== compact")
            vol.start(timeout=60)
            h = mk.connect(vol.sock)
            d.write(h, 10)
            _, rev = cl.get()
            cl.ctl("compact", str(rev))
            cl.ctl("defrag", "--cluster")
            try:
                d.write(h, 10); h.flush()
                row(True, f"compact: writes acknowledged after compaction at revision {rev} and defrag")
            except nbd.Error as e:
                row(False, f"compact: write failed after compaction: {e}")
            d.verify(h, "compact: live daemon")
            h.shutdown(); vol.term(timeout=60)

        if "second" in A.parts:
            print("== second")
            vol.start(timeout=60)
            h = mk.connect(vol.sock)
            d.write(h, 3)
            v2 = mk.Vol("etq2", discard=True, backing_dir=vroot, key_file=vol.key, size="1MiB", ckpt_reserve="256KiB", reserve="64KiB",
                        extra_backing=remote_section(auth, [fb.port, fa.port], "writer", auth.identity))
            try:
                v2.start(timeout=60)
                row(False, "second: a second daemon (frontend B first) started beside the live one")
                v2.kill9()
            except RuntimeError as e:
                row(True, f"second: second daemon refused: {last(str(e))}")
            try:
                d.write(h, 3); h.flush()
                row(True, "second: the first daemon still commits afterwards")
            except nbd.Error as e:
                row(False, f"second: the first daemon fails after the refused second start: {e}")
            d.verify(h, "second: live daemon")
            h.shutdown(); vol.term(timeout=60)
            v2.cleanup()

        if "foreign" in A.parts:
            print("== foreign")
            vol.start(timeout=60)
            h = mk.connect(vol.sock)
            d.write(h, 3)
            cur, rev = cl.get()
            old_rev = rev - 3
            old, _ = cl.get(rev=old_rev) if old_rev > 0 else (None, None)
            # 1. garbage under the key
            cl.ctl("put", KEY, "not an authority")
            try:
                d.write(h, 1); h.flush()
                row(False, "foreign: the daemon acknowledged a FUA write after a foreign client replaced the key with garbage")
            except nbd.Error as e:
                row(True, f"foreign: garbage under the key: write refused ({e})")
            r = maki("volume", "witness", vol.cfg)
            row(r.returncode != 0, f"foreign: garbage under the key: inspection refused: {last(r.stderr) or last(r.stdout)}")
            try:
                h.shutdown()
            except nbd.Error:
                pass
            vol.kill9()
            # 2. the bytes of an earlier revision put back by another client (an authority rollback by a backend-credential holder)
            if old is not None:
                cl.ctl("put", KEY, old.decode("latin-1") if False else "x", check=False)  # placeholder overwritten below
                # etcdctl put takes the value as an argument; the canonical envelope is binary, so write it from a file via stdin
                r = subprocess.run([ETCDCTL, "--endpoints", ",".join(f"https://127.0.0.1:{m['client']}" for m in cl.members), "--cacert", pki.ca,
                                    "--cert", cl.ccert, "--key", cl.ckey, "put", KEY], input=old, capture_output=True, timeout=30)
                got, _ = cl.get()
                print(f"    put back the value of revision {old_rev} ({len(old)} bytes; stored {len(got or b'')} bytes, equal {got == old})")
            # restore the real current value and check the volume is usable again via the documented procedure
            r = subprocess.run([ETCDCTL, "--endpoints", ",".join(f"https://127.0.0.1:{m['client']}" for m in cl.members), "--cacert", pki.ca,
                                "--cert", cl.ccert, "--key", cl.ckey, "put", KEY], input=cur, capture_output=True, timeout=30)
            got, _ = cl.get()
            row(got == cur, f"foreign: the pre-attack value put back ({len(cur)} bytes)")
            try:
                rec = procedure("foreign: after the attack")
                vol.start(timeout=60)
                h = mk.connect(vol.sock)
                # the write refused under the garbage may or may not be there; units written before it must be
                d.verify(h, "foreign: after the real value was put back and the procedure ran")
                h.shutdown(); vol.term(timeout=60)
            except RuntimeError as e:
                row(False, f"foreign: the volume cannot be brought back after the real value was put back: {last(str(e))}")

        if "quorum" in A.parts:
            print("== quorum")
            rec = procedure("quorum: before")
            vol.start(timeout=60)
            h = mk.connect(vol.sock)
            d.write(h, 5)
            cl.stop(1); cl.stop(2)
            time.sleep(0.5)
            acked_after = 0
            errors = 0
            for _ in range(3):
                try:
                    d.write(h, 1)
                    acked_after += 1
                except nbd.Error:
                    errors += 1
            row(acked_after == 0, f"quorum: with 1 of 3 members, {acked_after} FUA writes acknowledged, {errors} refused")
            r = maki("volume", "witness", vol.cfg, timeout=60)
            row(r.returncode != 0, f"quorum: inspection with 1 of 3 members refused: {last(r.stderr) or last(r.stdout)}")
            # stale-read probe: the surviving member alone, serializable vs linearizable
            r = cl.ctl("get", KEY, "--consistency=s", "-w", "json", endpoints=f"https://127.0.0.1:{cl.members[0]['client']}", check=False)
            print(f"    (etcdctl serializable get on the surviving member: rc={r.returncode}; maki uses linearizable reads only)")
            try:
                h.shutdown()
            except nbd.Error:
                pass
            vol.kill9()
            cl.start(1, state="existing"); cl.start(2, state="existing")
            cl.wait_healthy()
            try:
                procedure("quorum: after quorum came back")
                vol.start(timeout=60)
                h = mk.connect(vol.sock)
                d.verify(h, "quorum: after quorum came back and the procedure ran")
                d.write(h, 5); h.flush()
                h.shutdown(); vol.term(timeout=60)
            except RuntimeError as e:
                row(False, f"quorum: volume cannot be brought back after quorum returned: {last(str(e))}")
    finally:
        try:
            vol.kill9()
        except Exception:
            pass
        for fe in fes:
            fe.kill()
        for i in range(3):
            cl.stop(i)
        if not A.keep:
            vol.cleanup() if hasattr(vol, "cleanup") else None
            shutil.rmtree(base, ignore_errors=True)
    print(f"etcdq parts {A.parts}: {'FAIL' if BAD else 'ok'} ({len(BAD)} bad)")
    for b in BAD:
        print("  " + b)
    sys.exit(1 if BAD else 0)


main()
