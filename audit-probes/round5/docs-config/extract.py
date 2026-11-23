"""Extract every TOML fence from the docs in scope into raw/ (one file each) and print an index."""
import re, pathlib, tomllib, sys, glob
root = pathlib.Path('/home/user/wt/audit5')
out = pathlib.Path(sys.argv[1]); out.mkdir(exist_ok=True)
files = ['README.md', 'docs/configuration.md', 'docs/random-plaintext-prefix.md', 'docs/key-rotation.md',
         'docs/transport-memory.md', 'docs/observability.md', 'docs/performance.md', 'docs/benchmark.md',
         'docs/space-reclamation.md', 'examples/postgres-local/README.md', 'examples/postgres-local/checklist.md']
files += sorted(str(p.relative_to(root)) for p in (root/'docs/getting-started').glob('*.md'))
files += sorted(str(p.relative_to(root)) for p in (root/'docs/deployment').glob('*.md'))
n = 0
for f in files:
    text = (root/f).read_text()
    for m in re.finditer(r'^([ \t>]*)```(\w*)[^\n]*\n(.*?)^[ \t>]*```', text, re.S | re.M):
        indent, lang, body = m.group(1), m.group(2), m.group(3)
        line = text[:m.start()].count('\n') + 1
        body = '\n'.join(l[len(indent):] if l.startswith(indent) else l for l in body.split('\n'))
        looks_toml = lang == 'toml' or (lang in ('', 'ini', 'text') and re.search(r'^\[[\w.\[\]]+\]\s*$', body, re.M) and '=' in body and 'Service]' not in body and '[Unit]' not in body)
        if not looks_toml:
            continue
        n += 1
        name = f'{n:03d}-{f.replace("/", "_")}-{line}.toml'
        (out/name).write_text(body)
        try:
            doc = tomllib.loads(body)
            kind = 'FULL' if 'config_schema_version' in doc else 'FRAG'
            print(kind, lang or '-', f'{f}:{line}', sorted(doc)[:8])
        except Exception as e:
            print('UNPARSEABLE', lang or '-', f'{f}:{line}', e)
