#!/usr/bin/python3
"""Totals of a sweep summary (logs/<name>.summary)."""
import sys, re, ast
for path in sys.argv[1:]:
    tot = {}; n = 0; bad = []
    for line in open(path):
        m = re.match(r"rc=(\d+) seed (\d+) .*?: (ok|FAIL) (\{.*\})", line.strip())
        if not m:
            if 'NO SUMMARY' in line or line.startswith('rc='):
                bad.append(line.strip()[:200])
            continue
        n += 1
        if m.group(1) != '0' or m.group(3) != 'ok':
            bad.append(line.strip()[:300])
        d = ast.literal_eval(m.group(4))
        for k, v in d.items():
            if isinstance(v, bool):
                continue
            if isinstance(v, int):
                tot[k] = tot.get(k, 0) + v
            elif isinstance(v, dict):
                t = tot.setdefault(k, {})
                for a, b in v.items():
                    t[a] = t.get(a, 0) + b
    tot.pop("witness_generations", None); tot.pop("image_sectors", None); tot.pop("lost_unsynced_sectors", None)
    print(f"{path}: {n} seeds; {tot}")
    for b in bad:
        print("  BAD", b)
