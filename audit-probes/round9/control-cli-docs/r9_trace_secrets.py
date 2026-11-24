"""(successor) MAKI_LOG=trace across every tool and the daemon: no key material, no plaintext.
A distinctive plaintext marker is written through NBD; the outputs of create, inspect, check,
check --deep, maki-check --deep, status, metrics, checkpoint, drain, reload, the daemon log
(I/O, checkpoint, kill -9 + recovery) and maki-benchmark are searched for the key (hex, raw,
base64) and the marker (raw, hex, base64, utf-16). Run with /usr/bin/python3.12."""
import sys, os, subprocess, base64, binascii, glob
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mk, ctl

HERE = os.path.dirname(os.path.abspath(__file__))
MAKI_CHECK = os.path.join(HERE, "bin", "maki-check")
BENCH = os.path.join(HERE, "bin", "maki-benchmark")
ENV = {"MAKI_LOG": "trace"}

key = bytes.fromhex(mk.KEY_HEX)
marker = b"A9C-PLAINTEXT-MARKER-7f3e91"
needles = {
    "key hex": mk.KEY_HEX.encode(), "key HEX": mk.KEY_HEX.upper().encode(),
    "key raw": key, "key b64": base64.b64encode(key)[:24], "key half hex": mk.KEY_HEX[16:48].encode(),
    "marker": marker, "marker hex": binascii.hexlify(marker), "marker b64": base64.b64encode(marker * 3)[4:28],
    "marker bytes list": ", ".join(str(b) for b in marker[:8]).encode(),
}
outputs = {}


def run(label, *a, timeout=300):
    e = dict(os.environ); e.update(ENV)
    r = subprocess.run(a, capture_output=True, timeout=timeout, env=e)
    outputs[label] = r.stdout + r.stderr
    return r.returncode


v = mk.Vol(tag="r9trace")
try:
    print("create", run("create", mk.MAKI, "volume", "create", v.cfg))
    v.start(env=ENV, timeout=60)
    h = mk.connect(v.sock)
    block = (marker * (4096 // len(marker) + 1))[:4096]
    for i in range(8):
        h.pwrite(block, i * 4096)
    h.flush()
    assert h.pread(4096, 0) == block
    for verb in ("status", "metrics", "checkpoint"):
        print(verb, run(verb, mk.MAKI, verb, v.cfg))
    print("reload cache", run("reload", mk.MAKI, "reload", v.cfg, "cache", "--max-bytes", "1048576"))
    for i in range(8, 12):
        h.pwrite(block, i * 4096)
    h.flush()
    print("drain", run("drain", mk.MAKI, "drain", v.cfg))
    h.shutdown(); v.term()
    v.start(env=ENV, timeout=60); h = mk.connect(v.sock)
    for i in range(12, 16):
        h.pwrite(block, i * 4096)
    h.flush(); h.pwrite(block, 16 * 4096)
    v.kill9()
    print("check", run("check", mk.MAKI, "check", v.cfg))
    print("check --deep", run("check --deep", mk.MAKI, "check", v.cfg, "--deep"))
    print("maki-check --deep", run("maki-check --deep", MAKI_CHECK, v.root, "--deep"))
    print("inspect", run("inspect", mk.MAKI, "volume", "inspect", v.cfg))
    v.start(env=ENV, timeout=60); h = mk.connect(v.sock)
    assert h.pread(4096, 15 * 4096) == block
    h.shutdown(); v.term()
    print("benchmark", run("benchmark", BENCH, "--json", "--destroy-data", v.cfg, "64", "4096"))
    for p in sorted(glob.glob(os.path.join(v.dir, "nbdkit-*.log"))):
        outputs["daemon " + os.path.basename(p)] = open(p, "rb").read()
    total = 0
    for label, data in outputs.items():
        total += len(data)
        hits = [n for n, needle in needles.items() if needle in data]
        print(f"{label:28s} {len(data):8d} bytes  hits: {hits}")
    print("total output bytes", total)
finally:
    v.cleanup()
