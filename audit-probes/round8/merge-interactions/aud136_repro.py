#!/usr/bin/env python3
"""AUD-136 (open list): SIGKILL `maki volume create` (local rollback mode)
after it published the witness anchor and before the inner volume is
initialized; then show what create, check, inspect say.

Usage: aud136_repro.py <maki> <work-dir> <witness-parent-on-another-fs> <attempts>
"""
import os, shutil, subprocess, sys, signal, time
maki, work, wparent, attempts = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
env = dict(os.environ, RUST_BACKTRACE="0",
           MAKI_CREDENTIAL_PROBE_KEY="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
root = os.path.join(work, "vol"); wit = os.path.join(wparent, "audit8-aud136-wit")
cfg = os.path.join(work, "volume.toml")
os.makedirs(work, exist_ok=True)
open(cfg, "w").write(f'''
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
hits = pre = done = 0
shown = False
for n in range(attempts):
    for d in (root, wit):
        shutil.rmtree(d, ignore_errors=True); os.makedirs(d, mode=0o700)
    p = subprocess.Popen([maki, "volume", "create", cfg], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.004 + 0.00015 * (n % 120))
    p.send_signal(signal.SIGKILL); status = p.wait()
    if status == 0:
        done += 1; continue
    anchor = os.path.exists(os.path.join(wit, "anchor"))
    check = subprocess.run([maki, "check", cfg], env=env, capture_output=True, text=True)
    if not anchor:
        pre += 1; continue
    if check.returncode == 0:
        done += 1; continue
    hits += 1
    if not shown:
        shown = True
        print("backing:", sorted(os.listdir(root)), "witness:", sorted(os.listdir(wit)))
        for args in (["volume", "create", cfg], ["check", cfg], ["check", cfg, "--deep"], ["volume", "inspect", cfg]):
            r = subprocess.run([maki, *args], env=env, capture_output=True, text=True)
            print(f"$ maki {' '.join(a if a != cfg else '<cfg>' for a in args)}  -> exit {r.returncode}")
            for line in (r.stdout + r.stderr).strip().splitlines()[:4]:
                print("   ", line[:300])
print(f"{attempts} kills: {pre} before the anchor, {hits} after the anchor with an unusable volume, {done} completed")
for d in (root, wit):
    shutil.rmtree(d, ignore_errors=True)
