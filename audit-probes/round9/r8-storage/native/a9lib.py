"""Round 9 helpers: configurations for plain and local-rollback volumes and
strace-driven kills / single failed syscalls of the real `maki` CLI."""
import os, shutil, subprocess, sys, re

HERE = os.path.dirname(os.path.abspath(__file__))
MAKI = os.environ.get("MAKI_BIN", os.path.join(HERE, "bin", "maki"))
PLUGIN = os.environ.get("MAKI_PLUGIN", os.path.join(HERE, "bin", "libmaki_nbdkit.so"))
KEY = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
ENV = dict(os.environ, RUST_BACKTRACE="0", MAKI_CREDENTIAL_PROBE_KEY=KEY)
# Every call that changes the backing or decides a path: the set a kill or
# a failure is placed in.
CALLS = "openat,pwrite64,write,fdatasync,fsync,ftruncate,fallocate,rename,renameat,renameat2,unlink,unlinkat,mkdir,mkdirat,linkat,flock"


def config(root, witness=None, capacity="8MiB", size="16MiB", shard="8MiB", unit=4096,
           control=None, nbd_socket=None, name="probe"):
    rb = "" if witness is None else f'''
[backing.rollback_protection]
witness_root = "{witness}"
capacity = "{capacity}"
'''
    ctl = "" if control is None else f'\n[control]\nsocket = "{control}"\n'
    nbd = "" if nbd_socket is None else f'\n[nbd]\nsocket = "{nbd_socket}"\n'
    return f'''
config_schema_version = 1
[volume]
name = "{name}"
max_virtual_size = "{size}"
shard_logical_size = "{shard}"
device_block_size = 4096
crypto_unit_size = {unit}
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "local-aes-gcm-siv-v1"
key = {{ source = "env", name = "probe-key" }}
[crypto.capabilities]
supported_plaintext_sizes = [{unit}]
max_ciphertext_size = {unit + 288}
[backing]
root = "{root}"
journal_segment_size = "1MiB"
journal_max_bytes = "8MiB"
checkpoint_reserve_bytes = "2MiB"
journal_emergency_reserve_bytes = "2MiB"
{rb}{ctl}{nbd}'''


def write_cfg(path, **kw):
    with open(path, "w") as f:
        f.write(config(**kw))
    os.chmod(path, 0o644)
    return path


def run(*args, timeout=120):
    r = subprocess.run([MAKI, *args], env=ENV, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()


def strace(args, inject=None, out=None, timeout=180):
    """Run `maki args` under strace. `inject` is the text after -e inject=."""
    cmd = ["strace", "-f", "-qq", "-e", f"trace={CALLS}", "-o", out or "/dev/null"]
    if inject:
        cmd += ["-e", f"inject={inject}"]
    cmd += [MAKI, *args]
    r = subprocess.run(cmd, env=ENV, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()


def tree(root):
    out = []
    for base, dirs, files in os.walk(root):
        for n in sorted(files):
            p = os.path.join(base, n)
            out.append(f"{os.path.relpath(p, root)}:{os.path.getsize(p)}")
        for n in sorted(dirs):
            out.append(os.path.relpath(os.path.join(base, n), root) + "/")
    return sorted(out)


def reset(*dirs):
    for d in dirs:
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d, mode=0o700)
