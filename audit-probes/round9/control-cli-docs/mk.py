"""Shared helpers for the round-9 control-cli-docs probes (copied from audit8-native-nbdkit/mk.py).

Run every probe with /usr/bin/python3.12 (the interpreter python3-libnbd
1.20 is built for). Nothing here touches the checkout under audit; the
plugin and the `maki` CLI are copies of the debug build of 956e354 in
./bin (sha256 in NOTES.md).
"""
import os, socket, subprocess, time, signal, shutil, tempfile, json, struct, hashlib, random, errno

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN = os.environ.get("MAKI_PLUGIN", os.path.join(HERE, "bin", "libmaki_nbdkit.so"))
MAKI = os.environ.get("MAKI_BIN", os.path.join(HERE, "bin", "maki"))
KEY_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
BASE = os.environ.get("A9C_BASE", "/tmp/a9c")


def config_text(root, control, name="a9cvol", size="4MiB", unit=4096, block=512,
                shard="64KiB", min_io=None, max_io="64KiB", seg="64KiB",
                jmax="512KiB", provider="local-aes-gcm-siv", key_path=None,
                extra_backing="", extra_limits="", extra_nbd="", extra_volume="",
                extra_crypto="", extra_top="", cache=None, reserve="0B",
                ckpt_reserve=None, nbd_socket=None):
    min_io = block if min_io is None else min_io
    max_ct = unit + 64
    cache_s = ""
    if cache:
        cache_s = f"[cache]\n{cache}\n"
    ck = "" if ckpt_reserve is None else f'checkpoint_reserve_bytes = "{ckpt_reserve}"\n'
    sock = "" if nbd_socket is None else f'socket = "{nbd_socket}"\n'
    return f"""
config_schema_version = 1
{extra_top}
[volume]
name = "{name}"
max_virtual_size = "{size}"
device_block_size = {block}
crypto_unit_size = {unit}
shard_logical_size = "{shard}"
{extra_volume}
[crypto]
provider = "{provider}"
crypto_compatibility_id = "local-profile-v1"
key = {{ source = "file", name = "{key_path}" }}
{extra_crypto}
[crypto.capabilities]
supported_plaintext_sizes = [{unit}]
max_ciphertext_size = {max_ct}
[backing]
root = "{root}"
journal_segment_size = "{seg}"
journal_max_bytes = "{jmax}"
journal_emergency_reserve_bytes = "{reserve}"
{ck}{extra_backing}
[limits]
{extra_limits}
{cache_s}
[nbd]
minimum_io = {min_io}
maximum_io = "{max_io}"
{sock}{extra_nbd}
[control]
socket = "{control}"
"""


class Vol:
    """One disposable volume directory with its config, key and sockets."""

    def __init__(self, tag="v", discard=False, base=None, backing_dir=None, key_file=None, **cfg):
        os.makedirs(base or BASE, exist_ok=True)
        self.dir = tempfile.mkdtemp(prefix=f"{tag}-", dir=base or BASE)
        os.chmod(self.dir, 0o700)
        self.root = backing_dir or os.path.join(self.dir, "volume")
        self.key = key_file or os.path.join(self.dir, "vol.key")
        self.cfg = os.path.join(self.dir, "volume.toml")
        self.sock = os.path.join(self.dir, "nbd.sock")
        self.control = os.path.join(self.dir, "control.sock")
        self.discard = discard
        self.proc = None
        self.log = None
        self.n = 0
        if not key_file:
            with open(self.key, "w") as f:
                f.write(KEY_HEX)
            os.chmod(self.key, 0o600)
        self.text = config_text(self.root, self.control, key_path=self.key, **cfg)
        with open(self.cfg, "w") as f:
            f.write(self.text)
        os.chmod(self.cfg, 0o644)

    def create(self, check=True):
        args = [MAKI, "volume", "create", self.cfg] + (["--discard"] if self.discard else [])
        r = subprocess.run(args, capture_output=True, text=True)
        if check and r.returncode != 0:
            raise RuntimeError(f"create failed: {r.returncode} {r.stdout} {r.stderr}")
        return r

    def maki(self, *args, timeout=60):
        return subprocess.run([MAKI, *args], capture_output=True, text=True, timeout=timeout)

    def start(self, nbdkit_args=(), filters=(), filter_params=(), env=None, wait=True,
              timeout=30, wrapper=(), threads=None):
        """Start nbdkit in the foreground; wait for the plugin's READY=1."""
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
        cmd = list(wrapper) + ["nbdkit", "--foreground", "-U", self.sock]
        if threads:
            cmd += ["-t", str(threads)]
        cmd += list(nbdkit_args)
        for f in filters:
            cmd += [f"--filter={f}"]
        cmd += [PLUGIN, f"config={self.cfg}"] + list(filter_params)
        e = dict(os.environ)
        e["NOTIFY_SOCKET"] = npath
        e.pop("LIBNBD_DEBUG", None)
        if env:
            e.update(env)
        self.cmd = cmd
        self.proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=self.log,
                                     stderr=subprocess.STDOUT, env=e, start_new_session=True)
        if wait:
            self.wait_ready(timeout)
        return self.proc

    def wait_ready(self, timeout=30):
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

    def read_log(self):
        try:
            self.log.flush()
        except Exception:
            pass
        with open(self.logpath, "rb") as f:
            return f.read().decode("utf-8", "replace")

    def all_logs(self):
        out = []
        for i in range(1, self.n + 1):
            p = os.path.join(self.dir, f"nbdkit-{i}.log")
            if os.path.exists(p):
                with open(p, "rb") as f:
                    out.append(f"--- nbdkit-{i}.log ---\n" + f.read().decode("utf-8", "replace"))
        return "\n".join(out)

    def kill9(self):
        if self.proc and self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGKILL)
        if self.proc:
            self.proc.wait()
        self.notify.close()

    def term(self, timeout=60):
        """SIGTERM and wait; returns exit status (None on timeout)."""
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
        try:
            rc = self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            rc = None
        self.notify.close()
        return rc

    def cleanup(self):
        try:
            self.kill9()
        except Exception:
            pass
        shutil.rmtree(self.dir, ignore_errors=True)


def connect(sock, **kw):
    import nbd
    h = nbd.NBD()
    for k, v in kw.items():
        getattr(h, k)(v)
    h.connect_unix(sock)
    return h


def pattern(offset, length, version, seed=0):
    """Self-describing data: every 512-byte sector encodes its own absolute
    sector number, the write version and a keyed digest, so data from another
    offset or a mix of versions is recognisable."""
    assert offset % 512 == 0 and length % 512 == 0
    out = bytearray()
    for s in range(offset // 512, (offset + length) // 512):
        head = struct.pack("<QQQ", s, version, seed)
        body = hashlib.blake2b(head, digest_size=64).digest()
        sector = (head + body * 8)[:512]
        out += sector
    return bytes(out)


def describe(sector_bytes):
    if sector_bytes == bytes(512):
        return "zeros"
    s, v, seed = struct.unpack("<QQQ", sector_bytes[:24])
    if pattern(s * 512, 512, v, seed) == sector_bytes:
        return f"sector={s} version={v} seed={seed}"
    return "garbage:" + sector_bytes[:24].hex()
