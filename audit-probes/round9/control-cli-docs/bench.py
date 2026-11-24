"""maki-benchmark: documented commands and options (docs/benchmark.md, docs/performance.md), report
arithmetic, refusals before backing creation, kill -9 and what it leaves."""
import sys, os, json, subprocess, shutil, time, signal, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mk
BENCH = os.path.join(os.path.dirname(mk.MAKI), "maki-benchmark")
def run(*a, timeout=600):
    r = subprocess.run([BENCH, *a], capture_output=True, text=True, timeout=timeout); return r.returncode, r.stdout, r.stderr.strip()
issues = []
def note(ok, what):
    print(("ok   " if ok else "ISSUE") + " " + what)
    if not ok: issues.append(what)

# a "default-ish" benchmark configuration: only what configuration.md requires, defaults elsewhere
base = "/tmp/a9c/bench"; shutil.rmtree(base, ignore_errors=True); os.makedirs(base)
key = base + "/k.key"; open(key, "w").write(mk.KEY_HEX); os.chmod(key, 0o600)
def cfg(name, size="256MiB", extra=""):
    p = f"{base}/{name}.toml"
    open(p, "w").write(f'''config_schema_version = 1
[volume]
name = "{name}"
max_virtual_size = "{size}"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "bench-v1"
key = {{ source = "file", name = "{key}" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4124
[backing]
root = "{base}/{name}"
{extra}
[control]
socket = "{base}/{name}.sock"
''')
    return p
try:
    # docs/performance.md example 1 (smaller op count): default positional, 128 KiB I/O
    c = cfg("perf1")
    rc, out, err = run("--json", c, "300", "131072")
    note(rc == 0, f"performance.md example `--json <cfg> N 131072` rc={rc} {err[-200:]}")
    if rc == 0:
        j = json.loads(out)
        for k in ("schema_version", "provider", "operations", "io_size_bytes", "concurrency", "fua", "read_verified", "read_verification", "verified_read_operations", "flush_us", "write", "read", "flush", "workload", "setup", "verification", "resources"):
            note(k in j, f"report field {k}")
        w, r = j["write"], j["read"]
        note(w["latency"]["samples"] == 300 and r["latency"]["samples"] == 300, f"phased: 300 writes and 300 reads sampled ({w['latency']['samples']}, {r['latency']['samples']})")
        note(abs(w["iops"] - 300 / w["elapsed_seconds"]) < 1e-6 * w["iops"] + 1e-9, "write iops = samples / elapsed")
        note(abs(w["mib_per_second"] - w["iops"] * 131072 / 1048576) < 1e-6 * w["mib_per_second"], "MiB/s = iops * io_size")
        note(j["flush"]["latency"]["samples"] == 1 and abs(j["flush_us"] - j["flush"]["latency"]["max_us"]) < 1.0, f"one final FLUSH; flush_us equals it ({j['flush_us']:.1f} vs {j['flush']['latency']['max_us']})")
        note(w["latency"]["p50_upper_us"] <= w["latency"]["p95_upper_us"] <= w["latency"]["p99_upper_us"] <= w["latency"]["max_us"] + 1e-9, "p50<=p95<=p99<=max")
        note(j["read_verified"] is True and j["read_verification"] == "passed" and j["verified_read_operations"] == 300, "read verification passed/300")
        note(j["verification"]["written_slots"] == 300 and j["verification"]["final_sweep_verified_slots"] == 300, f"final sweep 300 slots {j['verification']}")
        note(j["workload"]["working_set_bytes"] == 300 * 131072, f"default working set = min(ops, slots) x io ({j['workload']['working_set_bytes']})")
        note(j["resources"]["rss_source"] == "linux-proc-self-status-VmHWM" and j["resources"]["pending_operations_at_exit"] == 0, f"resources {j['resources']}")
    # the run above left an existing volume
    rc, out, err = run("--json", c, "10", "4096"); note(rc == 2 and "--destroy-data" in err, f"existing volume without --destroy-data refused rc={rc}: {err[-120:]}")
    rc, out, err = run("--json", "--destroy-data", "--fua", c, "50", "4096"); note(rc == 0 and json.loads(out)["fua"] is True, f"--destroy-data --fua on the existing volume rc={rc} {err[-150:]}")
    # docs example 2 (concurrent mixed), scaled op count
    c2 = cfg("perf2")
    rc, out, err = run("--json", "--concurrency", "8", "--access", "random", "--read-percent", "70", "--working-set", "64MiB", "--flush-every", "1000", "--seed", "12", c2, "5000", "4096")
    note(rc == 0, f"benchmark.md mixed example rc={rc} {err[-200:]}")
    if rc == 0:
        j = json.loads(out)
        note(j["read"]["latency"]["samples"] == 3500 and j["write"]["latency"]["samples"] == 1500, f"reads = floor(ops*70/100): {j['read']['latency']['samples']}/{j['write']['latency']['samples']}")
        note(j["setup"]["writes"] == 64 * 1024 * 1024 // 4096 and j["setup"]["flushes"] == 1, f"setup initializes the whole working set: {j['setup']}")
        note(j["flush"]["latency"]["samples"] == 5, f"--flush-every 1000 over 5000 ops -> 5 barriers ({j['flush']['latency']['samples']})")
        note(j["workload"]["mode"] == "mixed" and j["workload"]["access"] == "random" and j["workload"]["seed"] == 12, f"workload {j['workload']}")
        note(j["verification"]["final_sweep_verified_slots"] == 16384, f"mixed final sweep covers the whole working set ({j['verification']})")
        note(j["resources"]["peak_pending_operations"] <= 8, f"peak pending <= concurrency ({j['resources']['peak_pending_operations']})")
        note(abs(j["read"]["elapsed_seconds"] - j["write"]["elapsed_seconds"]) < 1e-9, "mixed: both classes divide by the whole measured time")
    for n, ops, want in ((0, 100, 0), (100, 100, 100), (33, 10, 3), (1, 99, 0)):
        cz = cfg(f"rp{n}_{ops}", size="16MiB")
        rc, out, err = run("--json", "--read-percent", str(n), cz, str(ops), "4096")
        if rc == 0:
            j = json.loads(out)
            note(j["read"]["latency"]["samples"] == want and j["read_verified"] == (want > 0) and j["read_verification"] == ("passed" if want else "skipped"), f"--read-percent {n} ops {ops}: reads {j['read']['latency']['samples']} verified={j['read_verified']} {j['read_verification']}")
        else: note(False, f"--read-percent {n} rc={rc} {err[-200:]}")
    # refusals must not create the backing
    def refused(name, args, want_rc=2, size="16MiB"):
        cx = cfg(name, size=size)
        rc, out, err = run(*args(cx))
        created = os.path.exists(f"{base}/{name}")
        note(rc == want_rc and not created, f"refused before backing creation: {name}: rc={rc} created={created} :: {err.splitlines()[0][:150] if err else ''}")
    refused("r_ops0", lambda c: (c, "0"))
    refused("r_opsmax", lambda c: (c, "1000000001"))
    refused("r_io0", lambda c: (c, "10", "0"))
    refused("r_iomis", lambda c: (c, "10", "1000"))
    refused("r_iobig", lambda c: (c, "10", "2097152"))
    refused("r_conc0", lambda c: ("--concurrency", "0", c))
    refused("r_conc257", lambda c: ("--concurrency", "257", c))
    refused("r_dup", lambda c: ("--json", "--json", c))
    refused("r_unknown", lambda c: ("--frobnicate", c))
    refused("r_rp101", lambda c: ("--read-percent", "101", c))
    refused("r_ws0", lambda c: ("--working-set", "0", c))
    refused("r_wsodd", lambda c: ("--working-set", "4097", c))
    refused("r_wsbig", lambda c: ("--working-set", "32MiB", c))
    refused("r_fe0", lambda c: ("--flush-every", "0", c))
    refused("r_missing", lambda c: ("--seed", c))
    refused("r_oracle", lambda c: ("--working-set", str(8388609 * 4096), c, "10", "4096"), size="64GiB")
    cx = cfg("r_oracle_ok", size="64GiB"); rc, out, err = run("--working-set", str(8388608 * 4096), "--access", "random", cx, "10", "4096"); note(rc == 0, f"8,388,608-slot working set accepted rc={rc} {err[-200:]}")
    rc, out, err = run("--help"); note(rc == 0 and "usage" in out, "--help exit 0")
    rc, out, err = run("--version"); note(rc == 0 and out.startswith("maki-benchmark "), "--version exit 0")
    # kill -9 mid-run, what it leaves, and the rerun
    ck = cfg("kill", size="64MiB")
    before = set(os.listdir(base)) | set(os.listdir("/tmp"))
    p = subprocess.Popen([BENCH, "--json", "--fua", ck, "100000", "4096"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0); p.kill(); p.wait()
    left = (set(os.listdir(base)) | set(os.listdir("/tmp"))) - before
    print("after kill -9: new entries:", sorted(left), "| root:", sorted(os.listdir(f"{base}/kill")))
    rc, out, err = run("--json", ck, "10", "4096"); note(rc == 2, f"after kill: rerun without --destroy-data refused rc={rc}: {err[-100:]}")
    r = subprocess.run([mk.MAKI, "check", ck, "--deep"], capture_output=True, text=True); note(r.returncode == 0, f"after kill: maki check --deep rc={r.returncode} {r.stdout.strip().splitlines()[-1]}")
    rc, out, err = run("--json", "--destroy-data", ck, "100", "4096"); note(rc == 0, f"after kill: rerun with --destroy-data rc={rc} {err[-200:]}")
    # stdout closed / full
    cq = cfg("dev_full", size="16MiB")
    r = subprocess.run([BENCH, "--json", cq, "10", "4096"], stdout=open("/dev/full", "w"), stderr=subprocess.PIPE, text=True); note(r.returncode == 1 and "writing the report failed" in r.stderr, f"report to /dev/full: rc={r.returncode} {r.stderr.strip()[-120:]}")
    print("ISSUES", len(issues)); [print("  ", i) for i in issues]
finally:
    shutil.rmtree(base, ignore_errors=True)
