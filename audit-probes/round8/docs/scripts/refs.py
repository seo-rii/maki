#!/usr/bin/env python3
"""List backticked file names and test-like identifiers in maintained docs that do not exist in the tree."""
import os, re, subprocess, sys
ROOT = sys.argv[1]
DOCS = sys.argv[2:]
# index of all file basenames and relative paths
paths = set(); bases = {}
for d, dirs, files in os.walk(ROOT):
    if any(p in d for p in ("/.git", "/target", "/vendor/")) and "/vendor/" not in d.replace(ROOT, "")[:8]:
        pass
    dirs[:] = [x for x in dirs if x not in (".git", "target")]
    for f in files:
        rel = os.path.relpath(os.path.join(d, f), ROOT)
        paths.add(rel); bases.setdefault(f, []).append(rel)
src_cache = {}
def grep(word):
    if word in src_cache: return src_cache[word]
    r = subprocess.run(["grep", "-rIl", "--exclude-dir=.git", "--exclude-dir=target", "--include=*.rs", "--include=*.py", "--include=*.sh", "--include=*.yml", "--include=*.toml", "-w", word, ROOT + "/crates", ROOT + "/bins", ROOT + "/scripts", ROOT + "/.github", ROOT + "/packaging", ROOT + "/fuzz"], capture_output=True, text=True)
    src_cache[word] = bool(r.stdout.strip()); return src_cache[word]
for doc in DOCS:
    text = open(os.path.join(ROOT, doc), encoding="utf-8").read()
    for ln, line in enumerate(text.split("\n"), 1):
        for tok in re.findall(r"`([^`\n]+)`", line):
            tok = tok.strip()
            # file-like
            m = re.fullmatch(r"[\w./@<>*-]+\.(rs|py|sh|yml|toml|service|target|conf|spec|json|proto|md)", tok)
            if m and "<" not in tok and "*" not in tok and not tok.startswith("/") :
                base = os.path.basename(tok)
                if tok in paths: continue
                if any(p.endswith("/" + tok) or p == tok for p in paths): continue
                if "/" not in tok and base in bases: continue
                print(f"{doc}:{ln}: FILE? {tok}")
                continue
            # test-like identifier: snake_case, >= 3 underscores, all lowercase/digits
            if re.fullmatch(r"[a-z][a-z0-9]*(_[a-z0-9]+){2,}", tok):
                if not grep(tok):
                    print(f"{doc}:{ln}: IDENT? {tok}")
