#!/usr/bin/env python3
"""Run every verb of maki, maki-check, maki-witness and maki-benchmark with
misuse, a failing input, and closed/full stdout and stderr; print the status.

Usage: cli_probe.py <bin-dir> <work-dir>
"""
import os
import subprocess
import sys

BIN, WORK = sys.argv[1], sys.argv[2]
os.makedirs(WORK, exist_ok=True)
KEY = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
ENV = dict(os.environ, RUST_BACKTRACE="0", MAKI_CREDENTIAL_PROBE_KEY=KEY)


def closed_pipe():
    r, w = os.pipe()
    os.close(r)
    return w


def run(argv, stdout="pipe", stderr="pipe", env=ENV):
    fds = []

    def target(kind):
        if kind == "pipe":
            return subprocess.PIPE
        if kind == "closed":
            fd = closed_pipe()
            fds.append(fd)
            return fd
        if kind == "full":
            fd = os.open("/dev/full", os.O_WRONLY)
            fds.append(fd)
            return fd
        raise ValueError(kind)

    p = subprocess.Popen(
        argv, stdin=subprocess.DEVNULL, stdout=target(stdout), stderr=target(stderr), env=env
    )
    for fd in fds:
        os.close(fd)
    out, err = p.communicate(timeout=120)
    return p.returncode, (out or b"").decode("utf-8", "replace"), (err or b"").decode("utf-8", "replace")


def show(label, argv, expect=None, **kw):
    code, out, err = run(argv, **kw)
    flag = ""
    if expect is not None and code != expect:
        flag = f"   <== expected {expect}"
    first_err = err.strip().splitlines()[0][:150] if err.strip() else ""
    print(f"{code:4}  {label:70} {first_err}{flag}")
    return code, out, err


root = os.path.join(WORK, "vol")
cfg = os.path.join(WORK, "volume.toml")
with open(cfg, "w") as f:
    f.write(
        f'''
config_schema_version = 1
[volume]
name = "probe"
max_virtual_size = "1MiB"
shard_logical_size = "64KiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "local-aes-gcm-siv-v1"
key = {{ source = "env", name = "probe-key" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "{root}"
'''
    )
os.chmod(cfg, 0o644)
maki = os.path.join(BIN, "maki")
check = os.path.join(BIN, "maki-check")
witness = os.path.join(BIN, "maki-witness")
bench = os.path.join(BIN, "maki-benchmark")

print("== maki")
show("maki (no args)", [maki], 2)
for flag in ["--help", "-h", "help", "--version", "-V"]:
    show(f"maki {flag}", [maki, flag], 0)
    show(f"maki {flag} [stdout closed]", [maki, flag], 0, stdout="closed")
    show(f"maki {flag} [stdout full]", [maki, flag], 1, stdout="full")
show("maki bogus", [maki, "bogus"], 2)
show("maki volume", [maki, "volume"], 2)
show("maki volume create", [maki, "volume", "create"], 2)
show("maki volume create cfg --bogus", [maki, "volume", "create", cfg, "--bogus"], 2)
show("maki volume create /nonexistent", [maki, "volume", "create", "/nonexistent.toml"], 1)
show("maki volume create cfg", [maki, "volume", "create", cfg], 0)
show("maki volume create cfg (again)", [maki, "volume", "create", cfg], 1)
show("maki volume create cfg (again) [stderr closed]", [maki, "volume", "create", cfg], 1, stderr="closed")
show("maki volume inspect", [maki, "volume", "inspect"], 2)
show("maki volume inspect cfg", [maki, "volume", "inspect", cfg], 0)
show("maki volume inspect cfg [stdout closed]", [maki, "volume", "inspect", cfg], 0, stdout="closed")
show("maki volume inspect cfg [stdout full]", [maki, "volume", "inspect", cfg], 1, stdout="full")
show("maki volume inspect cfg extra", [maki, "volume", "inspect", cfg, "extra"], 2)
show("maki volume inspect /nonexistent", [maki, "volume", "inspect", "/nonexistent.toml"], 1)
for verb, tails in {
    "witness": [[], ["extra"]],
    "gc": [[], ["extra"]],
    "snapshot": [[], ["d"], ["d", "extra"]],
    "takeover": [[], ["1"], ["x", "00" * 32], ["1", "zz"], ["1", "00" * 32]],
    "restore": [[], ["d", "1", "00" * 32], ["d", "x", "00" * 32, "00" * 32], ["d", "1", "00" * 32, "00" * 32]],
    "resume-enrollment": [[], ["1"], ["x", "6f1d3a52-3c0f-4a39-9d53-0d6ad0d7a001"], ["1", "nope"],
                          ["1", "00000000-0000-0000-0000-000000000000"],
                          ["1", "6f1d3a52-3c0f-4a39-9d53-0d6ad0d7a001"],
                          ["1", "6f1d3a52-3c0f-4a39-9d53-0d6ad0d7a001", "--discard"],
                          ["1", "6f1d3a52-3c0f-4a39-9d53-0d6ad0d7a001", "--bogus"]],
}.items():
    for tail in tails:
        show(f"maki volume {verb} cfg {' '.join(t[:12] for t in tail)}", [maki, "volume", verb, cfg] + tail)
show("maki volume bogus cfg", [maki, "volume", "bogus", cfg], 2)
show("maki check", [maki, "check"], 2)
show("maki check cfg", [maki, "check", cfg], 0)
show("maki check cfg --deep", [maki, "check", cfg, "--deep"], 0)
show("maki check cfg --deep [stdout closed]", [maki, "check", cfg, "--deep"], 0, stdout="closed")
show("maki check cfg --deep [stdout full]", [maki, "check", cfg, "--deep"], 1, stdout="full")
show("maki check cfg --deep [stderr closed]", [maki, "check", cfg, "--deep"], 0, stderr="closed")
show("maki check cfg --bogus", [maki, "check", cfg, "--bogus"], 2)
show("maki check --deep cfg", [maki, "check", "--deep", cfg])
show("maki check /nonexistent", [maki, "check", "/nonexistent.toml"], 1)
show("maki check cfg --timeout 5", [maki, "check", cfg, "--timeout", "5"], 2)
show("maki check cfg --socket /x", [maki, "check", cfg, "--socket", "/x"], 2)
for verb in ["status", "metrics", "checkpoint", "drain"]:
    show(f"maki {verb}", [maki, verb], 2)
    show(f"maki {verb} cfg (no daemon)", [maki, verb, cfg], 1)
    show(f"maki {verb} cfg extra", [maki, verb, cfg, "extra"], 2)
    show(f"maki {verb} --socket /nonexistent.sock", [maki, verb, "--socket", "/nonexistent.sock"], 1)
    show(f"maki {verb} --socket", [maki, verb, "--socket"], 2)
    show(f"maki {verb} cfg --timeout 0", [maki, verb, cfg, "--timeout", "0"], 2)
    show(f"maki {verb} cfg --timeout", [maki, verb, cfg, "--timeout"], 2)
    show(f"maki {verb} cfg --timeout 5 --timeout 6", [maki, verb, cfg, "--timeout", "5", "--timeout", "6"])
    show(f"maki {verb} --socket /a --socket /b", [maki, verb, "--socket", "/a", "--socket", "/b"])
show("maki reload", [maki, "reload"], 2)
show("maki reload cfg", [maki, "reload", cfg], 2)
show("maki reload cfg cache", [maki, "reload", cfg, "cache"], 2)
show("maki reload cfg cache --max-bytes", [maki, "reload", cfg, "cache", "--max-bytes"], 2)
show("maki reload cfg cache --max-bytes 1 --ttl 0", [maki, "reload", cfg, "cache", "--max-bytes", "1", "--ttl", "0"], 2)
show("maki reload cfg cache --max-bytes 1", [maki, "reload", cfg, "cache", "--max-bytes", "1"], 1)
show("maki reload cfg limits", [maki, "reload", cfg, "limits"], 1)
show("maki reload cfg limits extra", [maki, "reload", cfg, "limits", "extra"], 2)
for verb in ["attach", "detach", "grow"]:
    show(f"maki {verb}", [maki, verb], 3)
    show(f"maki {verb} --volume v [stderr closed]", [maki, verb, "--volume", "v"], 3, stderr="closed")
    show(f"maki --timeout 5 {verb}", [maki, "--timeout", "5", verb], 3)
    show(f"maki --socket /x {verb}", [maki, "--socket", "/x", verb])
show("maki \\xff", [maki.encode(), b"\xff"], 2)
show("maki volume inspect \\xff", [maki.encode(), b"volume", b"inspect", b"/tmp/\xff.toml"], 1)
show("maki check \\xff", [maki.encode(), b"check", b"/tmp/\xff.toml"], 2)

print("== maki-check")
show("maki-check", [check], 2)
for flag in ["--help", "-h", "--version", "-V"]:
    show(f"maki-check {flag}", [check, flag], 0)
    show(f"maki-check {flag} [stdout closed]", [check, flag], 0, stdout="closed")
    show(f"maki-check {flag} [stdout full]", [check, flag], 1, stdout="full")
show("maki-check help", [check, "help"])
show("maki-check root", [check, root], 0)
show("maki-check root --deep", [check, root, "--deep"], 0)
show("maki-check root --deep [stdout closed]", [check, root, "--deep"], 0, stdout="closed")
show("maki-check root --deep [stdout full]", [check, root, "--deep"], 1, stdout="full")
show("maki-check root --deep [stderr closed]", [check, root, "--deep"], 0, stderr="closed")
show("maki-check root extra", [check, root, "extra"], 2)
show("maki-check --bogus root", [check, "--bogus", root], 2)
show("maki-check /nonexistent", [check, "/nonexistent-root"], 1)
show("maki-check root --journal-segment-size", [check, root, "--journal-segment-size"], 2)
show("maki-check root --journal-segment-size x", [check, root, "--journal-segment-size", "x"], 2)
show("maki-check root --deep --journal-segment-size 0", [check, root, "--deep", "--journal-segment-size", "0"])
show("maki-check root --deep --journal-segment-size 1", [check, root, "--deep", "--journal-segment-size", "1"])
show("maki-check root --deep --journal-segment-size 18446744073709551615",
     [check, root, "--deep", "--journal-segment-size", "18446744073709551615"])
show("maki-check root --deep --deep", [check, root, "--deep", "--deep"])
show("maki-check root --help", [check, root, "--help"])
show("maki-check cfg(file)", [check, cfg], 1)

print("== maki-witness")
state = os.path.join(WORK, "wstate")
os.makedirs(state, mode=0o700, exist_ok=True)
os.chmod(state, 0o700)
uuid = "6f1d3a52-3c0f-4a39-9d53-0d6ad0d7a001"
show("maki-witness", [witness], 2)
for flag in ["--help", "-h", "--version", "-V"]:
    show(f"maki-witness {flag}", [witness, flag], 0)
    show(f"maki-witness {flag} [stdout closed]", [witness, flag], 0, stdout="closed")
    show(f"maki-witness {flag} [stdout full]", [witness, flag], 1, stdout="full")
show("maki-witness help", [witness, "help"])
show("maki-witness bogus", [witness, "bogus"], 2)
show("maki-witness init", [witness, "init"], 2)
show("maki-witness init dir", [witness, "init", state], 2)
show("maki-witness init dir not-uuid", [witness, "init", state, "nope"], 2)
show("maki-witness init dir nil-uuid", [witness, "init", state, "00000000-0000-0000-0000-000000000000"])
show("maki-witness init dir uuid [stdout full]", [witness, "init", state, uuid], 0, stdout="full")
show("maki-witness init dir uuid (again)", [witness, "init", state, uuid], 1)
show("maki-witness init dir uuid (again) [stderr closed]", [witness, "init", state, uuid], 1, stderr="closed")
show("maki-witness init-etcd", [witness, "init-etcd"], 2)
show("maki-witness init-etcd /nonexistent nope", [witness, "init-etcd", "/nonexistent.toml", "nope"], 2)
show("maki-witness init-etcd /nonexistent uuid", [witness, "init-etcd", "/nonexistent.toml", uuid], 1)
show("maki-witness serve", [witness, "serve"], 2)
show("maki-witness serve /nonexistent", [witness, "serve", "/nonexistent.toml"], 1)
show("maki-witness serve a b", [witness, "serve", "a", "b"], 2)
show("maki-witness inspect", [witness, "inspect"], 2)
show("maki-witness inspect /nonexistent", [witness, "inspect", "/nonexistent.toml"], 1)
show("maki-witness fingerprint", [witness, "fingerprint"], 2)
show("maki-witness fingerprint /nonexistent", [witness, "fingerprint", "/nonexistent.pem"], 1)
show("maki-witness fingerprint \\xff", [witness.encode(), b"fingerprint", b"/tmp/\xff.pem"], 2)
show("maki-witness init --help", [witness, "init", "--help"])
show("maki-witness --help extra", [witness, "--help", "extra"], 2)

if os.path.exists(bench):
    print("== maki-benchmark")
    show("maki-benchmark", [bench], 2)
    for flag in ["--help", "-h", "--version", "-V"]:
        show(f"maki-benchmark {flag}", [bench, flag], 0)
        show(f"maki-benchmark {flag} [stdout closed]", [bench, flag], 0, stdout="closed")
        show(f"maki-benchmark {flag} [stdout full]", [bench, flag], 1, stdout="full")
    show("maki-benchmark --bogus", [bench, "--bogus"], 2)
    show("maki-benchmark /nonexistent", [bench, "/nonexistent.toml"])
