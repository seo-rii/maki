"""Random GFM documents: links the checker extracts vs links pandoc (GFM) renders."""
import importlib.util, json, pathlib, random, subprocess, sys, urllib.parse

ROOT = pathlib.Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location("cdl", ROOT / "scripts/check_docs_links.py")
cdl = importlib.util.module_from_spec(spec); spec.loader.exec_module(cdl)
seed = int(sys.argv[2]); count = int(sys.argv[3])
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

class Gen:
    def __init__(self, rng):
        self.rng = rng; self.n = 0; self.defs = []
    def target(self):
        self.n += 1
        return f"m{self.n}.md"
    def inline(self):
        r = self.rng
        parts = []
        for _ in range(r.randint(1, 4)):
            k = r.randint(0, 12)
            t = self.target()
            if k == 0: parts.append(f"[a]({t})")
            elif k == 1: parts.append(f"`code [x]({t})`")
            elif k == 2: parts.append(f"![img]({t})")
            elif k == 3:
                lab = f"r{self.n}"; parts.append(f"[b][{lab}]"); self.defs.append((lab, t))
            elif k == 4: parts.append(f"\\[c]({t})")
            elif k == 5: parts.append(f"[d]( <{t}> \"title\")")
            elif k == 6: parts.append(f"*em [e]({t})*")
            elif k == 7: parts.append(f"<span>[f]({t})</span>")
            elif k == 8: parts.append(f"[g [h]({t})]")
            elif k == 9: parts.append(f"word \\| pipe [i]({t})")
            elif k == 10: parts.append(f"``a ` [j]({t}) ``")
            elif k == 11:
                lab = f"s{self.n}"; parts.append(f"[{lab}]"); self.defs.append((lab, t))
            else: parts.append("plain text")
        return " ".join(parts)
    def block(self, depth=0):
        r = self.rng
        k = r.randint(0, 14 if depth < 2 else 7)
        if k == 0: return ["#" * r.randint(1, 6) + " H " + self.inline()]
        if k == 1: return [self.inline(), r.choice(["===", "---"])]
        if k == 2: return [self.inline(), self.inline()]
        if k == 3: return ["```" + r.choice(["", "rust", " x"]), self.inline(), "```"]
        if k == 4: return ["    " + self.inline()]
        if k == 5: return ["<div>", self.inline(), "</div>"] if r.random() < .5 else ["<div>", "", self.inline(), "", "</div>"]
        if k == 6: return ["| a | b |", "|---|---|", f"| {self.inline()} | x |", f"| y \\| z | {self.inline()} |"]
        if k == 7: return ["<!-- " + self.inline(), "-->"]
        if k == 8:
            marker = r.choice(["- ", "* ", "1. ", "2) ", "-   "])
            width = len(marker.expandtabs(4)) if "\t" not in marker else 2
            inner = self.blocks(depth + 1)
            out = []
            for i, line in enumerate(inner):
                if i == 0: out.append(marker + line)
                elif r.random() < 0.15 and line: out.append(line)  # lazy
                else: out.append((" " * width + line) if line else "")
            return out
        if k == 9:
            inner = self.blocks(depth + 1)
            return [("> " + l.replace("\t","    ")) if (l or r.random() < .5) else ">" for l in inner]
        if k == 10:
            inner = self.blocks(depth + 1)
            return [f"[^f{self.n}]: " + inner[0]] + [("    " + l) if l else "" for l in inner[1:]]
        if k == 11: return ["-"]  # empty item
        if k == 12: return ["  " + self.inline()]
        if k == 13: return ["~~~", self.inline(), "~~~~"]
        return ["***"]
    def blocks(self, depth=0):
        r = self.rng
        out = []
        for _ in range(r.randint(1, 3)):
            if out: out.extend([""] * r.choice([0, 1, 1, 2]))
            out.extend(self.block(depth))
        return out
    def document(self):
        lines = self.blocks()
        lines.append("")
        for lab, t in self.defs:
            lines.append(f"[{lab}]: {t}")
        return "\n".join(lines) + "\n"

rng = random.Random(seed)
bad = 0
for i in range(count):
    g = Gen(rng)
    text = g.document()
    mine = sorted(t for t in checker_targets(text))
    theirs = sorted(t for t in pandoc_targets(text))
    # checker records each definition's destination once; pandoc expands each reference use.
    ms, ts = set(mine), set(theirs)
    missed = ts - ms
    if missed:
        bad += 1
        p = outdir / f"case-{seed}-{i}.md"
        p.write_text(text)
        print(f"{p}: checker-missed {sorted(missed)}")
print(f"seed {seed}: {bad}/{count} documents with links pandoc renders but checker skips")
