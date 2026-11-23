"""Build cases/: full configs verbatim, fragments merged into the quickstart base."""
import re, pathlib, tomllib, json, copy, sys
root = pathlib.Path('/home/user/wt/audit5')
here = pathlib.Path(__file__).resolve().parent
raw = here / 'raw'
cases = here / 'cases'
for old in cases.glob('*.toml'):
    old.unlink()

def ser_value(v):
    if isinstance(v, bool): return 'true' if v else 'false'
    if isinstance(v, (int, float)): return repr(v)
    if isinstance(v, str): return json.dumps(v)
    if isinstance(v, list): return '[' + ', '.join(ser_value(x) for x in v) + ']'
    if isinstance(v, dict): return '{ ' + ', '.join(f'{json.dumps(k)} = {ser_value(x)}' for k, x in v.items()) + ' }'
    raise TypeError(type(v))

INLINE = {'key', 'client_key'}
def ser(d, prefix=()):
    lines, tables = [], []
    for k, v in d.items():
        if isinstance(v, dict) and k not in INLINE and not (len(prefix) >= 1 and prefix[-1] in ('headers', 'fields', 'item_fields', 'metadata', 'query')):
            tables.append((k, v))
        elif isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
            tables.append((k, v))
        else:
            lines.append(f'{json.dumps(k)} = {ser_value(v)}')
    for k, v in tables:
        name = '.'.join(json.dumps(p) for p in prefix + (k,))
        if isinstance(v, list):
            for item in v:
                lines.append(f'\n[[{name}]]'); lines.append(ser(item, prefix + (k,)))
        else:
            lines.append(f'\n[{name}]'); lines.append(ser(v, prefix + (k,)))
    return '\n'.join(lines)

def merge(a, b):
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(a.get(k), dict): merge(a[k], v)
        else: a[k] = v

base_text = next(raw.glob('*quickstart*')).read_text()
base = tomllib.loads(base_text)

# verbatim full files
(cases / 'full-quickstart.toml').write_text(base_text)
(cases / 'full-packaging-postgres-prod.toml').write_text((root / 'packaging/examples/postgres-prod.toml').read_text())
(cases / 'full-examples-postgres-local-volume.toml').write_text((root / 'examples/postgres-local/volume.toml').read_text())

def frag(name, glob, tweak=None, base_override=None):
    doc = tomllib.loads(next(raw.glob(glob)).read_text())
    cfg = copy.deepcopy(base_override or base)
    merge(cfg, doc)
    if tweak: tweak(cfg)
    (cases / name).write_text(ser(cfg) + '\n')

# configuration.md:917 memory budget, merged as-is
frag('frag-configuration-memory-budget.toml', '*configuration.md-917*')
# random-plaintext-prefix.md:28 merged as-is ("merge them into an otherwise complete volume configuration")
frag('frag-random-prefix.toml', '*random-plaintext-prefix.md-28*')
# configuration.md:84 remote witness endpoint set: fragment alone (no capacity) ...
frag('expect-fail-frag-configuration-remote-witness-asis.toml', '*configuration.md-84*')
# ... and with the capacity + reserves a rollback volume needs
def with_capacity(cfg):
    cfg['backing']['rollback_protection']['capacity'] = '1GiB'
    cfg['backing']['checkpoint_reserve_bytes'] = '256MiB'
    cfg['backing']['journal_emergency_reserve_bytes'] = '128MiB'
    cfg['backing']['journal_segment_size'] = '16MiB'
    cfg['backing']['journal_max_bytes'] = '128MiB'
frag('frag-configuration-remote-witness-with-capacity.toml', '*configuration.md-84*', with_capacity)
# configuration.md:141 websocket TLS: needs the provider switched; TLS files must exist on this host
tls = here / 'tls'; tls.mkdir(exist_ok=True)
for f in ('crypto-ca.pem', 'client-cert.pem'): (tls / f).write_text('placeholder\n')
def ws(cfg):
    cfg['crypto']['provider'] = 'remote-websocket'
    del cfg['crypto']['key']
    cfg['crypto']['capabilities']['integrity'] = 'contractual'
def ws_local_files(cfg):
    ws(cfg)
    cfg['crypto']['websocket']['tls']['ca_file'] = str(tls / 'crypto-ca.pem')
    cfg['crypto']['websocket']['tls']['client_cert_file'] = str(tls / 'client-cert.pem')
frag('expect-fail-frag-configuration-websocket-tls-asis-paths-missing.toml', '*configuration.md-141*', ws)
frag('frag-configuration-websocket-tls-existing-files.toml', '*configuration.md-141*', ws_local_files)
print('\n'.join(sorted(p.name for p in cases.glob('*.toml'))))
