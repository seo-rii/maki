"""Differential check: links/anchors seen by check_docs_links.py vs pandoc's GFM reader."""
import importlib.util, json, os, pathlib, subprocess, sys, urllib.parse

ROOT = pathlib.Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location("cdl", ROOT / "scripts/check_docs_links.py")
cdl = importlib.util.module_from_spec(spec); spec.loader.exec_module(cdl)

def checker_targets(text):
    definitions = cdl.reference_definitions(text)
    labels = frozenset(d[3] for d in definitions)
    out = [d[4] for d in definitions]
    definition_lines = {n for first, last, *_ in definitions for n in range(first, last + 1)}
    for number, line, masked, targets in cdl.inline_lines(text, definition_lines, labels):
        out.extend(targets)
    return out

def pandoc(text):
    data = json.loads(subprocess.run(["pandoc", "-f", "gfm", "-t", "json"], input=text, capture_output=True, text=True, check=True).stdout)
    links, headers = [], []
    def walk(node):
        if isinstance(node, dict):
            t = node.get("t")
            if t in ("Link", "Image"):
                links.append(node["c"][2][0])
            if t == "Header":
                headers.append(node["c"][1][0])
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
    walk(data)
    return links, headers

def internal(t):
    return t and not t.startswith("//") and not cdl.URI_SCHEME.match(t)

def norm(t):
    return urllib.parse.unquote(t)

files = subprocess.check_output(["git", "-C", str(ROOT), "ls-files", "*.md"], text=True).split()
only = sys.argv[2:] 
for rel in files:
    if only and not any(rel.startswith(o) for o in only):
        continue
    text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
    mine = {norm(t) for t in checker_targets(text) if internal(t)}
    links, headers = pandoc(text)
    theirs = {norm(t) for t in links if internal(t)}
    missed = theirs - mine
    extra = mine - theirs
    anchors = cdl.document_anchors(text)
    hmiss = set(headers) - anchors
    if missed or extra or hmiss:
        print(f"== {rel}")
        for t in sorted(missed): print(f"   checker-missed: {t!r}")
        for t in sorted(extra): print(f"   checker-only:   {t!r}")
        for h in sorted(hmiss): print(f"   anchor-missed:  {h!r}")
