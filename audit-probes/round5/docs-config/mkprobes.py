"""Probe cases for rules quoted in docs/configuration.md (expect-fail-* must be refused)."""
import pathlib, tomllib, copy, sys, re
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from mkcases import ser, merge, base, cases, root, here  # re-runs mkcases (rebuilds cases/)
prod = tomllib.loads((root / 'packaging/examples/postgres-prod.toml').read_text())
local = tomllib.loads((root / 'examples/postgres-local/volume.toml').read_text())

def case(name, cfg):
    (cases / name).write_text(ser(cfg) + '\n')

def mod(src, fn):
    cfg = copy.deepcopy(src); fn(cfg); return cfg

# examples/postgres-local/README.md: "replace the [crypto] sections with postgres-prod.toml"
c = copy.deepcopy(local); c['crypto'] = copy.deepcopy(prod['crypto']); case('probe-postgres-local-with-prod-crypto.toml', c)

def setp(path, value):
    def f(cfg):
        cur = cfg
        for k in path[:-1]:
            cur = cur.setdefault(k, {})
        cur[path[-1]] = value
    return f

P = [
 ('expect-fail-probe-keyring-source.toml', base, setp(['crypto', 'key'], {'source': 'keyring', 'name': 'k'})),
 ('expect-fail-probe-mode-hybrid.toml', base, setp(['crypto', 'capabilities', 'mode'], 'hybrid')),
 ('expect-fail-probe-mode-probed.toml', base, setp(['crypto', 'capabilities', 'mode'], 'probed')),
 ('expect-fail-probe-bounded-error-without-time.toml', base, setp(['crypto', 'availability_policy'], 'bounded-error')),
 ('expect-fail-probe-threads-0.toml', base, setp(['nbd', 'threads'], 0)),
 ('expect-fail-probe-threads-257.toml', base, setp(['nbd', 'threads'], 257)),
 ('probe-threads-256.toml', base, setp(['nbd', 'threads'], 256)),
 ('expect-fail-probe-minimum-io-128k.toml', base, lambda c: c['nbd'].update(minimum_io=131072, preferred_io=131072)),
 ('probe-minimum-io-64k.toml', base, lambda c: c['nbd'].update(minimum_io=65536, preferred_io=65536)),
 ('expect-fail-probe-preferred-io-64m.toml', base, lambda c: (c['nbd'].update(preferred_io=64 << 20, maximum_io='64MiB'), c.setdefault('limits', {}).update(max_plaintext_bytes='128MiB', max_overlay_bytes=0))),
 ('expect-fail-probe-connections-2.toml', base, setp(['nbd', 'connections'], 2)),
 ('expect-fail-probe-lock-off-default-cache.toml', base, setp(['security', 'memory_lock_mode'], 'off')),
 ('probe-lock-off-cache-lock-false.toml', base, lambda c: (c.setdefault('security', {}).update(memory_lock_mode='off'), c.setdefault('cache', {}).update(lock_memory=False))),
 ('probe-zeroize-on-evict-false-accepted.toml', base, lambda c: c.setdefault('cache', {}).update(mode='read', zeroize_on_evict=False)),
 ('probe-lock-memory-false-secure-buffers-accepted.toml', base, lambda c: c.setdefault('cache', {}).update(mode='read', lock_memory=False)),
 ('expect-fail-probe-duration-bare-integer.toml', base, setp(['cache', 'ttl'], 30)),
 ('probe-duration-2m.toml', base, setp(['cache', 'ttl'], '2m')),
 ('expect-fail-probe-duration-1h.toml', base, setp(['cache', 'ttl'], '1h')),
 ('probe-bytesize-plain-string.toml', base, setp(['cache', 'max_bytes'], '4096')),
 ('probe-overlay-bounds-zero.toml', base, lambda c: c.setdefault('limits', {}).update(max_overlay_bytes=0, max_overlay_entries=0)),
 ('expect-fail-probe-max-pending-items-zero.toml', base, setp(['limits', 'max_pending_crypto_items'], 0)),
 ('expect-fail-probe-relative-backing-root.toml', base, setp(['backing', 'root'], 'var/lib/maki/demo')),
 ('expect-fail-probe-madv-without-core-dump.toml', base, setp(['security', 'disable_core_dump'], False)),
 ('expect-fail-probe-memory-budget-two-fields.toml', base, setp(['security', 'memory_budget'], {'max_bytes': '256MiB', 'startup_headroom_bytes': '16MiB'})),
 ('expect-fail-probe-volume-name-65.toml', base, setp(['volume', 'name'], 'a' * 65)),
 ('probe-volume-name-64.toml', base, lambda c: (c['volume'].update(name='a' * 64), c['nbd'].pop('socket'), c['control'].pop('socket'))),
 ('expect-fail-probe-volume-name-leading-dash.toml', base, setp(['volume', 'name'], '-demo')),
 ('expect-fail-probe-prefix-8.toml', base, setp(['crypto', 'random_prefix_bytes'], 8)),
 ('expect-fail-probe-prefix-272.toml', base, setp(['crypto', 'random_prefix_bytes'], 272)),
 # batch byte limit of exactly one crypto unit (4096) with a 32-byte prefix: doc says only "smaller than one crypto unit" is refused
 ('expect-fail-probe-batch-bytes-one-crypto-unit-with-prefix.toml', base, lambda c: (c['crypto'].update(random_prefix_bytes=32, batch={'max_bytes': 4096, 'target_bytes': 4096}), c['crypto']['capabilities'].update(supported_plaintext_sizes=[4128], max_ciphertext_size=4156))),
 ('probe-batch-bytes-one-provider-unit-with-prefix.toml', base, lambda c: (c['crypto'].update(random_prefix_bytes=32, batch={'max_bytes': 4128, 'target_bytes': 4096}), c['crypto']['capabilities'].update(supported_plaintext_sizes=[4128], max_ciphertext_size=4156))),
 # remote HTTP rules
 ('expect-fail-probe-http-plaintext-non-loopback.toml', prod, lambda c: c['crypto']['http']['endpoint'][0].update(url='http://crypto-a.internal')),
 ('probe-http-plaintext-loopback.toml', prod, lambda c: c['crypto']['http'].update(endpoint=[{'name': 'a', 'url': 'http://127.0.0.1:8080'}, {'name': 'b', 'url': 'http://[::1]:8080'}, {'name': 'c', 'url': 'http://localhost:8080'}])),
 ('expect-fail-probe-http-userinfo.toml', prod, lambda c: c['crypto']['http']['endpoint'][0].update(url='https://user:pw@crypto-a.internal')),
 ('expect-fail-probe-http-tls-server-name.toml', prod, lambda c: c['crypto']['http'].update(tls={'server_name': 'x'})),
 ('expect-fail-probe-http-literal-authorization.toml', prod, lambda c: c['crypto']['http']['encrypt']['headers'].update(Authorization='Bearer abc')),
 ('expect-fail-probe-http-literal-x-vault-token.toml', prod, lambda c: c['crypto']['http']['encrypt']['headers'].update({'X-Vault-Token': 'abc'})),
 ('probe-http-literal-x-tenant.toml', prod, lambda c: c['crypto']['http']['encrypt']['headers'].update({'X-Tenant': 'abc'})),
 ('expect-fail-probe-http-format-two-placeholders.toml', prod, lambda c: c['crypto']['http']['encrypt']['headers'].update(Authorization={'source': 'credential', 'name': 'crypto-token', 'format': '{} {}'})),
 ('expect-fail-probe-http-same-name-other-source.toml', prod, lambda c: c['crypto']['http']['decrypt']['headers'].update(Authorization={'source': 'env', 'name': 'crypto-token', 'format': 'Bearer {}'})),
 ('expect-fail-probe-http-batch-without-item-index.toml', prod, lambda c: c['crypto']['http']['encrypt']['response'].pop('item_index_path')),
 ('expect-fail-probe-http-payload-in-batch-fields.toml', prod, lambda c: c['crypto']['http']['encrypt']['body']['fields'].update({'/p': {'source': 'payload'}})),
 ('expect-fail-probe-http-overlap-pointers.toml', prod, lambda c: c['crypto']['http']['encrypt']['body']['fields'].update({'/volume/profile': {'source': 'compatibility_id'}})),
 ('expect-fail-probe-http-context-binding-missing-format.toml', prod, lambda c: c['crypto']['http']['encrypt']['body']['fields'].pop('/format')),
 ('probe-http-method-put-lowercase.toml', prod, lambda c: c['crypto']['http']['encrypt'].update(method='put')),
 ('expect-fail-probe-http-method-get.toml', prod, lambda c: c['crypto']['http']['encrypt'].update(method='GET')),
 ('expect-fail-probe-http-timeout-zero.toml', prod, lambda c: c['crypto']['http'].update(timeout='0s')),
 ('expect-fail-probe-http-max-response-zero.toml', prod, lambda c: c['crypto']['http'].update(max_response_bytes=0)),
 ('probe-http-hex-alias.toml', prod, lambda c: (c['crypto']['http']['encrypt']['body']['item_fields'].update({'/data': {'source': 'payload', 'encoding': 'hex'}}), c['crypto']['http']['encrypt']['response'].update(encoding='hex-upper'))),
 ('expect-fail-probe-http-encoding-on-unit-index.toml', prod, lambda c: c['crypto']['http']['encrypt']['body']['item_fields'].update({'/unit': {'source': 'unit_index', 'encoding': 'base64'}})),
 ('expect-fail-probe-key-on-remote.toml', prod, setp(['crypto', 'key'], {'source': 'credential', 'name': 'k'})),
 ('expect-fail-probe-local-with-http-section.toml', base, setp(['crypto', 'http'], copy.deepcopy(prod['crypto']['http']))),
]
for name, src, fn in P:
    case(name, mod(src, fn))

# gRPC probes built from prod
def grpc(extra=None):
    c = copy.deepcopy(prod)
    c['crypto']['provider'] = 'remote-grpc'
    del c['crypto']['http']
    c['crypto']['grpc'] = {'endpoint': [{'name': 'a', 'url': 'https://crypto-a.internal:7443'}]}
    if extra: extra(c['crypto']['grpc'])
    return c
case('probe-grpc-defaults.toml', grpc())
case('probe-grpc-ip-literal-v6.toml', grpc(lambda g: g.update(endpoint=[{'name': 'a', 'url': 'https://[2001:db8::10]:7443'}, {'name': 'b', 'url': 'https://192.0.2.10:7443'}])))
case('expect-fail-probe-grpc-metadata-te.toml', grpc(lambda g: g.update(metadata={'te': 'trailers'})))
case('expect-fail-probe-grpc-metadata-bin.toml', grpc(lambda g: g.update(metadata={'x-trace-bin': 'abc'})))
case('expect-fail-probe-grpc-path-fragment.toml', grpc(lambda g: g.update(encrypt_path='/svc/Encrypt#x')))
case('expect-fail-probe-grpc-path-star.toml', grpc(lambda g: g.update(encrypt_path='*')))
case('expect-fail-probe-grpc-path-bare-query.toml', grpc(lambda g: g.update(encrypt_path='?a=b')))
case('probe-grpc-path-with-query.toml', grpc(lambda g: g.update(encrypt_path='/gw/maki.CryptoService/EncryptBatch?tenant=demo')))
case('expect-fail-probe-grpc-plaintext-non-loopback.toml', grpc(lambda g: g.update(endpoint=[{'name': 'a', 'url': 'http://crypto-a.internal:7000'}])))
case('expect-fail-probe-grpc-message-limit-too-small.toml', grpc(lambda g: g.update(max_message_bytes='256KiB')))
# websocket
def ws(extra=None):
    c = copy.deepcopy(prod)
    c['crypto']['provider'] = 'remote-websocket'
    del c['crypto']['http']
    c['crypto']['websocket'] = {'endpoint': [{'name': 'a', 'url': 'wss://crypto.example:8443'}]}
    if extra: extra(c['crypto']['websocket'])
    return c
case('probe-ws-defaults-no-tls-section.toml', ws())
case('expect-fail-probe-ws-http-scheme.toml', ws(lambda w: w.update(endpoint=[{'name': 'a', 'url': 'https://crypto.example:8443'}])))
case('expect-fail-probe-ws-frame-limit-too-small.toml', ws(lambda w: w.update(max_frame_bytes='512KiB')))
# remote witness with the default reserves (4GiB + 1GiB) cannot validate: capacity is capped at 1GiB
def witness_defaults(c):
    c['backing'] = {'root': '/var/lib/maki/demo', 'rollback_protection': {'capacity': '1GiB', 'remote': {
        'address': '192.0.2.10:9443', 'server_name': 'witness.example.test', 'timeout_ms': 5000,
        'ca_file': '/etc/maki/witness-ca.pem', 'client_cert_file': '/etc/maki/writer.cert.pem', 'client_key_file': '/etc/maki/witness/writer.key.pem'}}}
case('expect-fail-probe-rollback-with-default-reserves.toml', mod(base, witness_defaults))
print(len(list(cases.glob('*.toml'))), 'case files')
