import importlib.util, json, pathlib, random, subprocess, sys, urllib.parse
ROOT = pathlib.Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location("cdl", ROOT / "scripts/check_docs_links.py")
cdl = importlib.util.module_from_spec(spec); spec.loader.exec_module(cdl)
rng = random.Random(int(sys.argv[2])); count = int(sys.argv[3])
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
            if node.get("t") in ("Link", "Image"): links.append(node["c"][2][0])
            for v in node.values(): walk(v)
        elif isinstance(node, list):
            for v in node: walk(v)
    walk(data); return links
bad = 0
for i in range(count):
    lines = []; uses = []
    for k in range(rng.randint(1, 5)):
        lab = rng.choice([f"r{k}", f"R {k}", f"r{k} ", f" r{k}", f"r\\]{k}", f"Ünï{k}", f"r{k}\nx"])
        dest = rng.choice([f"d{k}.md", f"<d{k} s.md>", f"d{k}.md#a", f"d{k}(x).md", f"<d{k}.md>", f"d{k}%20.md"])
        title = rng.choice(["", f' "t{k}"', f" 't'", f" (t)", f'\n"t{k}"', f' "bad', f"\n'multi\nline'"])
        sep = rng.choice([" ", "", "\n", "  "])
        prefix = rng.choice(["", "   ", "> ", "- ", "    ", "\t"])
        before = rng.choice(["", "\n", "para\n", "# H\n", "***\n", "para\n\n"])
        lines.append(before + prefix + f"[{lab}]:{sep}{dest}{title}")
        uses.append(rng.choice([f"[x][{lab.strip()}]", f"[{lab.strip()}]", f"[{lab.strip()}][]"]))
    text = "\n".join(lines) + "\n\n" + " ".join(uses) + "\n"
    def internal(t): return t and not t.startswith("//") and not cdl.URI_SCHEME.match(t)
    mine = {urllib.parse.unquote(t) for t in checker_targets(text) if internal(t)}
    theirs = {urllib.parse.unquote(t) for t in pandoc_targets(text) if internal(t)}
    if theirs - mine:
        bad += 1
        if bad <= 12: print(repr(text), "\n   missed:", sorted(theirs - mine))
print("bad", bad, "/", count)
