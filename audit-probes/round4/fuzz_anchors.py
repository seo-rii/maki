import importlib.util, json, pathlib, random, subprocess, sys
ROOT = pathlib.Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location("cdl", ROOT / "scripts/check_docs_links.py")
cdl = importlib.util.module_from_spec(spec); spec.loader.exec_module(cdl)
rng = random.Random(int(sys.argv[2]))
atoms = ["Foo", "bar", "`code`", "*em*", "_u_", "**b**", "[link](x.md)", "&amp;", "&copy;", "a—b", "x-y", "(paren)", "1.2", "C++", "über", "日本", "<kbd>K</kbd>", "foo_bar", "a  b", "\\*", "#", "\\#", "--", "&#42;", "snake_case_", "~~del~~", "![img](i.png)", ".", "?", "'quote'", "\"dq\"", "émoji 🎉", "Σ", "_", "*", "<br>", "&lt;tag&gt;", "x|y"]
docs = []
for i in range(400):
    hs = []
    for _ in range(rng.randint(1, 4)):
        text = " ".join(rng.choice(atoms) for _ in range(rng.randint(1, 4)))
        hs.append(rng.choice(["## " + text, text + "\n---", "# " + text + " ##"]))
    if rng.random() < .3: hs.append(hs[0])
    docs.append("\n\n".join(hs) + "\n")
bad = 0
for d in docs:
    data = json.loads(subprocess.run(["pandoc", "-f", "gfm", "-t", "json"], input=d, capture_output=True, text=True, check=True).stdout)
    theirs = {b["c"][1][0] for b in data["blocks"] if b["t"] == "Header"}
    mine = cdl.document_anchors(d)
    if theirs != mine:
        bad += 1
        if bad <= 25:
            print(repr(d)); print("   pandoc-only:", sorted(theirs - mine), " checker-only:", sorted(mine - theirs))
print("differences:", bad)
