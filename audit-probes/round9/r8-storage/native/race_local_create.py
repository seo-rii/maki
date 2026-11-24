#!/usr/bin/env python3
"""Race `maki volume create` against itself and against `maki check` on one
local rollback pair (real processes, real flock), with and without an
interrupted creation's leftovers. Exactly one create may succeed per pair,
and the result must pass `maki check --deep`.

Usage: race_local_create.py <maki> <work-dir> <witness-parent-on-another-fs> <rounds>
"""
import os, shutil, subprocess, sys, signal, random, time

maki, work, wparent, rounds = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
env = dict(os.environ, RUST_BACKTRACE="0",
           MAKI_CREDENTIAL_PROBE_KEY="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
random.seed(8)
bad = []
stats = {"created": 0, "refused": 0, "killed_rounds": 0}
for n in range(rounds):
    root = os.path.join(work, f"vol{n}")
    wit = os.path.join(wparent, f"audit8-race-wit{n}")
    for d in (root, wit):
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d, mode=0o700)
    cfg = os.path.join(work, f"volume{n}.toml")
    with open(cfg, "w") as f:
        f.write(f'''
config_schema_version = 1
[volume]
name = "probe"
max_virtual_size = "16MiB"
shard_logical_size = "8MiB"
device_block_size = 4096
crypto_unit_size = 4096
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "local-aes-gcm-siv-v1"
key = {{ source = "env", name = "probe-key" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "{root}"
journal_segment_size = "1MiB"
journal_max_bytes = "8MiB"
checkpoint_reserve_bytes = "2MiB"
journal_emergency_reserve_bytes = "2MiB"
[backing.rollback_protection]
witness_root = "{wit}"
capacity = "8MiB"
''')
    os.chmod(cfg, 0o644)
    mode = n % 3
    if mode == 1:
        # an interrupted creation: kill a create somewhere on its way
        p = subprocess.Popen([maki, "volume", "create", cfg], env=env,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(random.uniform(0.0, 0.02))
        p.send_signal(signal.SIGKILL)
        p.wait()
        stats["killed_rounds"] += 1
    procs = [subprocess.Popen([maki, "volume", "create", cfg], env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(3)]
    if mode == 2:
        procs += [subprocess.Popen([maki, "check", cfg], env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
    results = []
    for p in procs:
        out, err = p.communicate(timeout=120)
        results.append((p.args[1], p.returncode, err.decode("utf-8", "replace").strip().splitlines()[:1]))
    creates = [r for r in results if r[0] == "volume"]
    ok = [r for r in creates if r[1] == 0]
    codes = sorted({r[1] for r in results})
    if any(c not in (0, 1) for c in codes):
        bad.append((n, "unexpected exit status", results))
    final = subprocess.run([maki, "check", cfg, "--deep"], env=env, capture_output=True, text=True)
    if len(ok) == 1:
        stats["created"] += 1
        if final.returncode != 0:
            bad.append((n, "one create succeeded but the volume does not check", results, final.stderr[-300:]))
    elif len(ok) == 0:
        # an earlier (killed) creation may have got past the anchor: then the
        # volume opens, or it is the documented stop-after-anchor state.
        stats["refused"] += 1
        again = subprocess.run([maki, "volume", "create", cfg], env=env, capture_output=True, text=True)
        if again.returncode != 0 and final.returncode != 0:
            bad.append((n, "no create succeeded, a later create is refused and the volume does not check",
                        results, again.stderr[-300:], final.stderr[-300:],
                        sorted(os.listdir(root)), sorted(os.listdir(wit))))
    else:
        bad.append((n, "more than one create succeeded", results))
    for d in (root, wit):
        shutil.rmtree(d, ignore_errors=True)
    os.unlink(cfg)
print(stats)
for b in bad[:10]:
    print("VIOLATION", b)
print(f"{len(bad)} violations in {rounds} rounds")
