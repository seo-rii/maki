#!/usr/bin/env python3
"""Check backticked .rs file names and test fn identifiers in a doc against the tree."""
import re, subprocess, sys, os
root = sys.argv[1]
doc = sys.argv[2]
text = open(os.path.join(root, doc)).read()
ticks = set(re.findall(r'`([^`\n]+)`', text))
# index all rs files and all fn names
rs_files = subprocess.run(['git', '-C', root, 'ls-files'], capture_output=True, text=True).stdout.split('\n')
names = {}
for f in rs_files:
    names.setdefault(os.path.basename(f), []).append(f)
fns = set()
for f in rs_files:
    if f.endswith('.rs') or f.endswith('.py') or f.endswith('.sh'):
        try:
            src = open(os.path.join(root, f), errors='replace').read()
        except Exception:
            continue
        fns.update(re.findall(r'\bfn\s+([A-Za-z0-9_]+)', src))
        fns.update(re.findall(r'\bdef\s+([A-Za-z0-9_]+)', src))
        fns.update(re.findall(r'\bmod\s+([A-Za-z0-9_]+)', src))
lines = text.split('\n')
def where(tok):
    return [i+1 for i,l in enumerate(lines) if '`'+tok+'`' in l][:3]
for t in sorted(ticks):
    t0 = t.strip()
    # file-looking tokens
    m = re.fullmatch(r'([\w./\-*]+\.(rs|py|sh|toml|yml|md|service|conf|proto))', t0)
    if m:
        base = os.path.basename(t0)
        if '*' in t0:
            continue
        if os.path.exists(os.path.join(root, t0)) or os.path.exists(os.path.join(root, os.path.dirname(doc), t0)):
            continue
        if base in names:
            # check path suffix match
            if any(f.endswith(t0) for f in names[base]) or '/' not in t0:
                continue
            # crate-relative 'maki-x/tests/foo.rs'
            if any(('crates/'+t0) == f or ('bins/'+t0)==f for f in names[base]):
                continue
            print(f'PATH? {t0} lines {where(t)} candidates {names[base][:3]}')
            continue
        print(f'MISSING FILE {t0} lines {where(t)}')
        continue
    # fn-looking tokens: snake_case with at least 2 underscores, all lowercase/digits
    if re.fullmatch(r'[a-z][a-z0-9]*(_[a-z0-9]+){2,}', t0):
        if t0 in fns:
            continue
        print(f'MISSING FN? {t0} lines {where(t)}')
