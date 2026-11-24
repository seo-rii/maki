#!/usr/bin/env python3
"""Backticked or double-quoted multi-word phrases in maintained docs that look like program messages, and whether the sources contain them."""
import os, re, sys, pathlib
root = pathlib.Path(sys.argv[1])
src = []
for base in ("crates", "bins", "scripts", "packaging"):
    for p in (root / base).rglob("*"):
        if p.is_file() and p.suffix in (".rs", ".py", ".sh", ".spec", ".service", ".conf") and "/target/" not in str(p):
            try: src.append(p.read_text(errors="replace"))
            except Exception: pass
blob = "\n".join(src)
# Rust string continuation: backslash-newline + indentation -> nothing
norm = re.sub(r"\\\n\s*", "", blob)
norm = re.sub(r"\s+", " ", norm)
skip_start = ("maki ", "maki-", "systemctl", "sudo", "cargo", "python", "apt", "dnf", "rpm ", "git ", "install ", "chown", "chmod", "cp ", "gh ", "nbdkit", "dmsetup", "vgchange", "lvextend", "pvcreate", "vgs", "lvs", "pvs", "ls ", "cat ", "sha256sum", "dpkg", "ausearch", "restorecon", "modprobe", "echo ", "find ", "journalctl", "blkid", "mount ", "umount", "openssl", "curl", "rustup", "sh ", "bash", "set ", "export ", "type_transition", "Requires", "Depends", "ExecStart", "pg_", "chattr", "fio", "nbd", "lvm", "xfs", "mkfs", "wait_stopped", "rmdir", "dd ", "truncate", "flock", "exec ", "import ", "str(", "bytes(")
docs = sys.argv[2:]
for doc in docs:
    text = (root / doc).read_text()
    for ln, line in enumerate(text.split("\n"), 1):
        for tok in re.findall(r"`([^`\n]{12,200})`", line):
            t = tok.strip()
            words = t.split()
            if len(words) < 3 or t.startswith(skip_start) or t.startswith(("/", "--", "<", "[", "$", "#")):
                continue
            if re.search(r"[=|{}\\]|\.toml|\.rs\b|\.py\b|::|->", t) and not re.search(r"[a-z] [a-z]+ [a-z]", t):
                continue
            if not re.search(r"[a-z]{3,} [a-z]{2,}", t):
                continue
            probe = re.sub(r"\s+", " ", t)
            # allow placeholders like <volume>, nbd3, pg, (...) and an ellipsis to split the phrase
            parts = [p.strip() for p in re.split(r"…|\.\.\.|<[^>]+>|\(\.\.\.\)", probe) if len(p.strip()) >= 10]
            if not parts: continue
            missing = [p for p in parts if p not in norm]
            if missing:
                print(f"{doc}:{ln}: {t!r} -> not found: {missing!r}")
