#!/usr/bin/env python3
"""Extract TOML blocks that look like attach configurations from maintained docs, plus shipped attach.toml files, and run them through `maki-attach attach --plan`."""
import os, re, subprocess, sys, pathlib
root = pathlib.Path(sys.argv[1]); helper = sys.argv[2]; out = pathlib.Path(sys.argv[3]); out.mkdir(parents=True, exist_ok=True)
keys = ("volume_uuid", "vg_name", "lv_name", "mountpoint", "fs_uuid", "lvm_identity", "nbd_device", "init_sentinel", "device_block_size =")
docs = [p for p in list(root.glob("*.md")) + list(root.glob("docs/**/*.md")) + list(root.glob("packaging/**/*.md")) + list(root.glob("examples/**/*.md")) if "docs/qualification" not in str(p)]
n = 0
for doc in sorted(docs):
    text = doc.read_text()
    for m in re.finditer(r"```toml\n(.*?)```", text, re.S):
        block = m.group(1)
        if not any(k in block for k in keys[:6]) or "[volume]" in block or "config_schema_version" in block or "[backing" in block or "[crypto" in block:
            continue
        line = text[:m.start()].count("\n") + 2
        n += 1
        f = out / f"block{n}.toml"; f.write_text(block)
        for verb in ("attach", "detach", "grow"):
            cmd = [helper, verb, "--volume", "pg", "--config", str(f), "--plan"] + (["--size-bytes", "1073741824"] if verb == "grow" else [])
            r = subprocess.run(cmd, capture_output=True, text=True)
            print(f"{doc.relative_to(root)}:{line} [{verb}] exit={r.returncode} {(r.stderr.strip().splitlines() or [''])[0][:160]}")
for f in list(root.glob("packaging/examples/attach.toml")) + list(root.glob("examples/**/attach.toml")):
    r = subprocess.run([helper, "attach", "--volume", "pg", "--config", str(f), "--plan"], capture_output=True, text=True)
    print(f"{f.relative_to(root)} [attach] exit={r.returncode} {(r.stderr.strip().splitlines() or [''])[0][:200]}")
    print("   " + "\n   ".join(r.stdout.strip().splitlines()[:9]))
