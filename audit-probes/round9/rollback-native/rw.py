"""Remote witness environment for the round-9 rollback-native probes: a CA,
server / writer / admin certificates (openssl), a `maki-witness` state
directory and server, and the volume configuration sections that use it."""
import os, subprocess, socket, time, signal, json, uuid
import mk9 as mk


def sh(*args, **kw):
    r = subprocess.run(args, capture_output=True, text=True, **kw)
    if r.returncode != 0:
        raise RuntimeError(f"{args}: {r.stdout} {r.stderr}")
    return r.stdout


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Pki:
    """One CA and leaf certificates under `dir`."""

    def __init__(self, d, name="ca"):
        self.dir = d
        os.makedirs(d, exist_ok=True)
        self.ca_key = os.path.join(d, f"{name}.key")
        self.ca = os.path.join(d, f"{name}.pem")
        if not os.path.exists(self.ca):
            sh("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", self.ca_key)
            sh("openssl", "req", "-x509", "-new", "-key", self.ca_key, "-sha256", "-days", "30",
               "-subj", f"/CN=a9rn {name}", "-out", self.ca,
               "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")

    def leaf(self, name, server=False, days=30, san="DNS:witness.test,IP:127.0.0.1", start=None, end=None):
        key = os.path.join(self.dir, f"{name}.key")
        csr = os.path.join(self.dir, f"{name}.csr")
        crt = os.path.join(self.dir, f"{name}.pem")
        ext = os.path.join(self.dir, f"{name}.ext")
        raw = os.path.join(self.dir, f"{name}.sec1")
        sh("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", raw)
        sh("openssl", "pkcs8", "-topk8", "-nocrypt", "-in", raw, "-out", key)
        os.unlink(raw)
        os.chmod(key, 0o600)
        sh("openssl", "req", "-new", "-key", key, "-subj", f"/CN={name}", "-out", csr)
        with open(ext, "w") as f:
            f.write("basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n")
            if server:
                f.write(f"extendedKeyUsage=serverAuth\nsubjectAltName={san}\n")
            else:
                f.write("extendedKeyUsage=clientAuth\n")
        args = ["openssl", "x509", "-req", "-in", csr, "-CA", self.ca, "-CAkey", self.ca_key, "-CAcreateserial",
                "-sha256", "-extfile", ext, "-out", crt]
        if start or end:
            # openssl x509 -req has no -startdate; use `openssl ca`-free trick: -days with faketime is unavailable,
            # so expired certificates are made with -not_before/-not_after (OpenSSL 3.x)
            args += ["-not_before", start, "-not_after", end]
        else:
            args += ["-days", str(days)]
        sh(*args)
        return crt, key


class Authority:
    """A maki-witness state directory and server."""

    def __init__(self, base, state_dir, pki=None, identity=None, timeout_ms=5000, max_connections=16):
        self.base = base
        os.makedirs(base, exist_ok=True)
        self.state = state_dir
        self.pki = pki or Pki(os.path.join(base, "pki"))
        self.identity = identity or str(uuid.uuid4())
        self.port = free_port()
        self.server_cert, self.server_key = self.pki.leaf("server", server=True)
        self.writer_cert, self.writer_key = self.pki.leaf("writer")
        self.admin_cert, self.admin_key = self.pki.leaf("admin")
        self.timeout_ms = timeout_ms
        self.max_connections = max_connections
        self.cfg = os.path.join(base, "server.toml")
        self.proc = None
        self.n = 0
        self.write_config()

    def fp(self, cert):
        return sh(mk.WITNESS, "fingerprint", cert).strip()

    def write_config(self, principals=None, extra=""):
        principals = principals or [(self.writer_cert, "writer"), (self.admin_cert, "admin")]
        with open(self.cfg, "w") as f:
            f.write(f'state_dir = "{self.state}"\nlisten = "127.0.0.1:{self.port}"\n\n[server]\ntimeout_ms = {self.timeout_ms}\n'
                    f'max_connections = {self.max_connections}\n\n[server.tls]\nca_file = "{self.pki.ca}"\n'
                    f'cert_file = "{self.server_cert}"\nkey_file = "{self.server_key}"\n')
            for cert, role in principals:
                f.write(f'\n[[server.principals]]\ncertificate_sha256 = "{self.fp(cert)}"\nrole = "{role}"\n')
            f.write(extra)
        os.chmod(self.cfg, 0o644)

    def init(self, check=True):
        r = subprocess.run([mk.WITNESS, "init", self.state, self.identity], capture_output=True, text=True)
        if check and r.returncode != 0:
            raise RuntimeError(f"witness init failed: {r.stdout} {r.stderr}")
        return r

    def start(self, env=None, wait=True, timeout=30):
        self.n += 1
        self.logpath = os.path.join(self.base, f"witness-{self.n}.log")
        self.log = open(self.logpath, "wb")
        e = dict(os.environ)
        if env:
            e.update(env)
        self.proc = subprocess.Popen([mk.WITNESS, "serve", self.cfg], stdin=subprocess.DEVNULL, stdout=self.log,
                                     stderr=subprocess.STDOUT, env=e, start_new_session=True)
        if wait:
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                if self.proc.poll() is not None:
                    raise RuntimeError(f"maki-witness exited {self.proc.returncode}: {self.read_log()[-2000:]}")
                if b"listening" in open(self.logpath, "rb").read():
                    return self.proc
                time.sleep(0.01)
            raise RuntimeError("maki-witness did not report readiness: " + self.read_log()[-2000:])
        return self.proc

    def read_log(self):
        try:
            self.log.flush()
        except Exception:
            pass
        with open(self.logpath, "rb") as f:
            return f.read().decode("utf-8", "replace")

    def kill9(self):
        if self.proc and self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGKILL)
        if self.proc:
            self.proc.wait()

    def remote_section(self, capacity, role="writer", timeout_ms=None, port=None, extra=""):
        cert, key = (self.writer_cert, self.writer_key) if role == "writer" else (self.admin_cert, self.admin_key)
        return (f'[backing.rollback_protection]\ncapacity = "{capacity}"\n\n[backing.rollback_protection.remote]\n'
                f'address = "127.0.0.1:{port or self.port}"\nserver_name = "witness.test"\ntimeout_ms = {timeout_ms or self.timeout_ms}\n'
                f'ca_file = "{self.pki.ca}"\nclient_cert_file = "{cert}"\nclient_key_file = "{key}"\n{extra}')

    def client_config(self, path, role="writer", cert=None, key=None, ca=None, server_name="witness.test", timeout_ms=None, port=None):
        c, k = (self.writer_cert, self.writer_key) if role == "writer" else (self.admin_cert, self.admin_key)
        with open(path, "w") as f:
            f.write(f'address = "127.0.0.1:{port or self.port}"\nserver_name = "{server_name}"\ntimeout_ms = {timeout_ms or self.timeout_ms}\n\n'
                    f'[tls]\nca_file = "{ca or self.pki.ca}"\ncert_file = "{cert or c}"\nkey_file = "{key or k}"\n')
        os.chmod(path, 0o644)
        return path

    def inspect(self, role="writer"):
        p = self.client_config(os.path.join(self.base, f"client-{role}.toml"), role)
        r = subprocess.run([mk.WITNESS, "inspect", p], capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"inspect failed: {r.stderr}")
        return json.loads(r.stdout)


def root_hex(record):
    return bytes(record["current"]["anchor"]["root"]).hex()
