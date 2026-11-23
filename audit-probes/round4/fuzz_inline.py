import importlib.util, json, pathlib, random, subprocess, sys, urllib.parse
ROOT = pathlib.Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location("cdl", ROOT / "scripts/check_docs_links.py")
cdl = importlib.util.module_from_spec(spec); spec.loader.exec_module(cdl)
rng = random.Random(int(sys.argv[2])); count = int(sys.argv[3])
outdir = pathlib.Path(sys.argv[4]); outdir.mkdir(exist_ok=True)

def checker_targets(text):
    definitions = cdl.reference_definitions(text)
    labels = frozenset(d[3] for d in definitions)
    out = [d[4] for d in definitions]
    dl = {n for first, last, *_ in definitions for n in range(first, last + 1)}
    for _, _, _, targets in cdl.inline_lines(text, dl, labels):
        out.extend(targets)
    return out

def pandoc_targets(text):
    data = json.loads(subprocess.run(["pandoc", "-f", "gfm", "-t", "json"], input=text, capture_output=True, text=True, check=True).stdout)
    links = []
    def walk(node):
        if isinstance(node, dict):
            if node.get("t") in ("Link", "Image"):
                links.append(node["c"][2][0])
            for v in node.values(): walk(v)
        elif isinstance(node, list):
            for v in node: walk(v)
    walk(data)
    return links

toks = ["[", "]", "(", ")", "`", "``", "\\", "*", "_", "<", ">", "!", "\n", " ", "x", "a b", "&amp;", "\"t\"", "'t'", "<b>", "</b>", "<!--", "-->", "http://e.com", "www.e.com", ":", "|", "\\[", "\\]", "\\(", "\\)", "#", "[^n]"]
n = 0
def target():
    global n; n += 1
    t = rng.choice([f"m{n}.md", f"m{n}.md#frag", f"<m{n} x.md>", f"m{n}(1).md", f"m{n}.md \"ti(t)le\"", f"m%20{n}.md", f"m{n}\\).md", f"m{n}.md 'q'"])
    return t
bad = 0
for i in range(count):
    n = 0
    parts = []
    defs = []
    for _ in range(rng.randint(3, 14)):
        r = rng.random()
        if r < 0.25:
            parts.append(f"[{rng.choice(['t', 'a [b] c', '`c`', '*e*', 'x\ny', '![i](i' + str(rng.randint(0,9)) + '.md)'])}]({target()})")
        elif r < 0.35:
            lab = f"L{len(defs)}"; parts.append(rng.choice([f"[t][{lab}]", f"[{lab}][]", f"[{lab}]"])); defs.append((lab, f"d{len(defs)}.md"))
        else:
            parts.append(rng.choice(toks))
    para = "".join(rng.choice(["", " ", " ", "\n"]) + p for p in parts).strip()
    if not para:
        continue
    text = para + "\n\n" + "".join(f"[{l}]: {t}\n" for l, t in defs)
    def internal(t): return t and not t.startswith("//") and not cdl.URI_SCHEME.match(t)
    mine = {urllib.parse.unquote(t) for t in checker_targets(text) if internal(t)}
    theirs = {urllib.parse.unquote(t) for t in pandoc_targets(text) if internal(t)}
    missed = theirs - mine
    if missed:
        bad += 1
        p = outdir / f"inline-{sys.argv[2]}-{i}.md"; p.write_text(text)
        print(f"{p}: missed {sorted(missed)} extra {sorted(mine - theirs)}")
print("documents with missed links:", bad, "/", count)
