# Configuration

Maki uses a versioned TOML configuration per volume. Parsing rejects unknown
fields, and validation checks geometry, limits, provider capabilities, endpoint
contracts, and credential references before a volume is created or attached.

The complete schema is normative in SPEC §57. A production-oriented remote
HTTP example is available at
[`packaging/examples/postgres-prod.toml`](../packaging/examples/postgres-prod.toml).

## Top-level sections

| Section | Purpose |
|---|---|
| `volume` | Name, maximum virtual size, block size, crypto unit size, and shard size |
| `crypto` | Provider selection, compatibility identity, availability policy, and capabilities |
| `crypto.http` | HTTP endpoints, request/response mapping, credentials, and TLS |
| `crypto.websocket` | WebSocket endpoints, TLS, timeout, and frame-size limit |
| `crypto.grpc` | gRPC endpoints, TLS, method paths, metadata, and message-size limit |
| `limits` | Request, byte, queue, batch, endpoint concurrency, and in-memory overlay bounds |
| `backing` | Backing root, slot alignment, journal sizing, and reserves |
| `backing.rollback_protection` | Experimental Linux COW format: preallocated logical-page `capacity` and exactly one independent local `witness_root` or mTLS `remote` authority (new volumes only; [remote service](remote-witness-service.md)) |
| `cache` | Read-cache mode, size, TTL, and hit verification (`lock_memory` and `zeroize_on_evict` are accepted but select nothing; see [read cache](#read-cache)) |
| `nbd` | Socket, negotiated I/O geometry, and Tokio runtime worker count |
| `control` | Administrative socket and group |
| `security` | Core-dump, memory-lock, and secure-swap policy |

Byte sizes use values such as `4096`, `256KiB`, `64MiB`, or `16TiB`: a bare
integer number of bytes, or a quoted string with the unit `B`, `KiB`, `MiB`,
`GiB` or `TiB`. Nine byte-valued keys are plain integers and take only the
bare number (`4096`, never `"4KiB"`): `volume.device_block_size`,
`volume.crypto_unit_size`, `crypto.random_prefix_bytes`,
`crypto.capabilities.supported_plaintext_sizes`,
`crypto.capabilities.max_ciphertext_size`, `backing.slot_alignment`,
`nbd.device_block_size`, `nbd.minimum_io` and `nbd.preferred_io`. A string
there is a schema error, reported with its line and column only.
Durations use values such as `150us`, `50ms`, `5s`, or `2m` (minutes), always
as a quoted string with a unit. Unlike byte sizes, a bare integer is rejected.
(The remote witness `timeout_ms` is not such a duration: it is an integer
number of milliseconds.)

`volume.name` is an operational identifier of 1–64 ASCII bytes, using only
letters, digits, `_` and `-`, and must not start with `-`, matching the
privileged helper's argument contract. Validation rejects invalid names before creating
or opening the backing. The bound leaves room for the default control socket
pathname and the name in the official bounded status response.

See [Rollback-protected backing](rollback-protection.md) for the witness trust
boundary, capacity/reserve sizing, creation and systemd access requirements.
This option is off by default and does not upgrade existing volumes.

## Configuration file

The configuration decides where a volume's plaintext goes: the provider and
its endpoints, TLS trust, credential references, the backing root and the
rollback witness. Every loader (the daemon, each `maki` command that takes a
`<config.toml>`, and `maki-benchmark`) therefore refuses, before parsing it, a
file that another user could change or substitute (SPEC §8). On Unix the file
must be:

- named by its own path: a final symlink is refused (directories above it may
  be symlinks; they are not checked);
- a regular file with exactly one hard link, of at most 1 MiB;
- owned by root or by the user the loading process runs as;
- not writable by its group or by others (no `0020` or `0002` bit; a POSIX ACL
  that grants write access sets the group bits too).

Group and other read are allowed, because the file holds credential
references, never secrets. Install it as `root:maki 0640`:

```bash
install -m 0640 -o root -g maki volume.toml /etc/maki/volumes/<volume>.toml
```

The daemon user reads that file through its group, and commands run as root or
as the daemon user accept it. A file owned by the daemon user is accepted by
the daemon and by commands run as that user (`runuser -u maki -- …`), but
refused by commands run as root. A configuration a user writes for
their own runs, such as a disposable one below `/tmp`, is accepted with the
usual `0600` or `0644`. A configuration tool that installs the file as a
symlink, or as a hard link into a store, must copy it instead. Keep the
directory holding it root-owned and not writable by others, as the package's
`/etc/maki/volumes` (`root:maki 0750`) is. The error names the file and the
problem, for example `has mode 0664: it is writable by the group or by others`.
Non-Unix builds check only that the file is a regular file of at most 1 MiB.


## Remote witness endpoint sets

A single authority retains the existing numeric `address` field. To share one
etcd-backed authority through several frontends, replace it with an explicit
endpoint set and independently approved outer storage identity:

```toml
[backing.rollback_protection.remote]
addresses = ["192.0.2.10:9443", "192.0.2.11:9443"]
storage_identity = "01234567-89ab-cdef-0123-456789abcdef"
server_name = "witness.example.test"
timeout_ms = 5000
ca_file = "/etc/maki/witness-ca.pem"
client_cert_file = "/etc/maki/writer.cert.pem"
client_key_file = "/etc/maki/witness/writer.key.pem"
```

Select exactly one of `address` or `addresses`; an endpoint set contains 1–8
unique numeric socket addresses with nonzero ports. `storage_identity` is
mandatory for a set, optional for a single address, and cannot be nil. It pins
the outer witness identity, distinct from the inner superblock UUID. All
frontends use the same verified `server_name`, approved identity and shared
etcd key. Independently copied local witness directories cannot provide HA.

`client_key_file` is a secret file: it is opened without following a symlink,
must be a regular file owned by root or by the user the loading process runs
as (the daemon user for the packaged service), and must not be accessible to
group or others (0600 or 0400). A key owned by any other user is refused
whatever its mode, because its owner can read or replace it. `ca_file` and
`client_cert_file` are public and may have any owner, but must not contain a
private key.

One deadline of `timeout_ms` (1–60000 ms) covers the entire endpoint attempt
sequence. A stalled frontend receives a bounded share, leaving time for later
frontends. Transport failures retry the identical operation ID and predecessor;
permission, identity, malformed-response and comparison errors stop immediately.
Backend quorum loss refuses freshness checks and durable advances. See the
[service guide](remote-witness-service.md) for backend initialization and TLS
configuration; this configuration creates no infrastructure.

## Providers

| `crypto.provider` | Transport | Integrity | TLS status |
|---|---|---|---|
| `local-aes-gcm-siv` | Local | Authenticated and context-bound | Not applicable |
| `local-aes-xts` | Local | No authenticated integrity | Not applicable |
| `remote-http` | HTTP | Declared by provider contract | HTTPS, custom CA, and mTLS supported |
| `remote-websocket` | WebSocket | Declared by provider contract | WSS, custom CA, and mTLS supported |
| `remote-grpc` | gRPC | Declared by provider contract | HTTPS, custom CA, and mTLS supported |
| `fake` | In-process test provider | Test-only | Refused unless built with `--features fake-provider` |

The `fake` provider is not compiled into a default build; `maki volume create`,
`maki volume resume-enrollment` and attach reject it at validation time,
before the backing or a remote witness changes. Enable the `fake-provider`
feature of `maki-nbdkit` only for development and benchmark builds.

All three remote transports verify server certificates and the hostname in the
endpoint URL, and all three trust the same roots:

- the host's trust store: the system CA bundle, or the files that
  `SSL_CERT_FILE` and `SSL_CERT_DIR` name when either is set. It is read best
  effort: a missing store adds nothing and a certificate in it that does not
  parse is skipped;
- the public roots compiled into the binary (the `webpki-roots` set);
- the certificates of a configured `ca_file`, which add to the other two and
  replace neither. Every certificate in it must parse, and a file without one
  is refused at attach.

The TLS section is therefore optional when the endpoint's chain leads to a
public root or to a private CA installed in the host's trust store. Because the
compiled-in roots are always there, a provider is built even on a host whose
trust store is empty; an endpoint that none of the roots vouches for is refused
at the TLS handshake. The roots are read when the provider is built at daemon
start, so a CA added to the host's store later takes effect at the next
restart (a WebSocket provider without a TLS section also reads the host's
store again for each new connection). There is no certificate-verification
bypass setting. The [remote witness](#remote-witness-endpoint-sets) is
different: it trusts only its own `ca_file`.

For example, a WebSocket endpoint with private-CA trust and mutual TLS uses:

```toml
[[crypto.websocket.endpoint]]
name = "primary"
url = "wss://crypto.example:8443"

[crypto.websocket.tls]
ca_file = "/etc/maki/crypto-ca.pem"
client_cert_file = "/etc/maki/client-cert.pem"
client_key = { source = "credential", name = "crypto-client-key" }
```

For gRPC, use `crypto.grpc.endpoint`, an `https://` URL and `crypto.grpc.tls`
with the same fields. A gRPC endpoint named by an IP literal
(`https://192.0.2.10:7443`, `https://[2001:db8::10]:7443`) is verified against
the certificate's IP-address SANs; a DNS SAN does not match it.
WebSocket and gRPC require `client_cert_file` and
`client_key` together; the private key is loaded through the existing credential
router. Omit both for server-only TLS. HTTP also retains support for a combined
certificate/private-key PEM in `client_cert_file`; such a file is a secret file
like a `file` credential: it is opened without following a symlink and, when it
holds a private key, must be owned by root or by the user the process runs as
and must not be readable by group or others (0600 or 0400).
Every TLS file must be a regular file of at most 1 MiB; CA bundles and
certificates paired with `client_key` may be symlinks. A CA bundle, or a
WebSocket/gRPC `client_cert_file`, that contains a private key is refused at
attach: those files are read as public material, so the key must come through
`client_key`.

These transports have local certificate, hostname, mTLS and actual daemon I/O
regressions. All three also passed scoped cross-host reference-provider
campaigns under the shipped sandbox; see [current status](status.md#crypto-providers).
Those results do not qualify a commercial service or a different deployment.

## Capability declarations and checks

`crypto.capabilities.mode` supports only `declared` (also the default).
`hybrid` and `probed` are rejected because endpoint capability discovery is
not implemented. Replace either old mode with `declared` and confirm the
configured limits against the endpoint's documented contract.

| Mode / claim | Runtime behavior |
|---|---|
| `declared` | Use configured limits; mandatory round-trip, response-shape, declared security and cross-endpoint checks still run. |
| `hybrid`, `probed` | Configuration error; no discovery or volume attach occurs. |
| Remote `none` | Capability is absent. |
| Remote `contractual` or legacy `verified` | Capability is contractual; a TOML declaration is not independent verification. |
| Intrinsic local AEAD capability | Remains verified by the local implementation. |

Endpoint status `validated` means the configured volume's conformance and
key checks passed. It does not mean that every limit was discovered, that
all possible inputs were checked, or that replay protection was proven.
Changing a mode cannot bypass the mandatory integrity/context tests.

## Validation rules

`validate()` runs before a volume is created and before every attach. TOML and
schema parse errors report only `invalid TOML or configuration schema`, with
line and column when available. Their Display and Debug output omit the source
text, values, unknown field names and the parser's free-form message; inspect
the configuration locally at the reported location to diagnose the problem.
Semantic validation errors can name a known field or endpoint. Endpoint URLs
are shown as `scheme://host[:port]` without userinfo, path or query; HTTP
operation paths, credential names and credential templates are never shown.
Beyond schema, geometry, and secret-literal checks validation rejects:

- any zero count or byte limit under `[limits]`, `[crypto.batch]`,
  `[crypto.circuit_breaker]`, and `[crypto.retry_budget]` (except
  `limits.max_overlay_bytes` and `limits.max_overlay_entries`, where `0`
  disables the bound), a non-finite or
  negative `retry_ratio`, a `minimum_probe_rate` outside `(0, 1000]/s` or whose reciprocal cannot
  be represented by `Duration`, an
  `initial_delay` above `max_delay`, an `open_initial` above `open_max`, batch
  targets above their maxima, or a `crypto.batch.max_bytes` smaller than one
  provider plaintext unit (`volume.crypto_unit_size +
  crypto.random_prefix_bytes`);
- a retry strategy other than `exponential-full-jitter`, a
  `capabilities.mode` other than `declared`, `availability_policy = "bounded-error"` without a
  positive `max_operation_time`, and a `security.memory_lock_mode` outside
  `secure-buffers | all | off`;
- a `backing.root` that is not an absolute path;
- an `nbd.threads` value outside `1..=256`; the worker count is never
  silently reduced;
- NBD I/O sizes that are not powers of two or not ordered
  `device_block_size <= minimum_io <= preferred_io <= maximum_io` (an unset
  `nbd.preferred_io` is the crypto unit size, raised to `minimum_io`), an
  `nbd.device_block_size` that differs from the volume's, a `minimum_io`
  above 64 KiB, a configured or defaulted `preferred_io` above 32 MiB (nbdkit
  refuses a larger preferred block size, failing every client handshake), an
  export size that is not a multiple of `minimum_io`, a `maximum_io` that does
  not fit in the NBD 32-bit wire field, or a `limits.max_plaintext_bytes` too
  small for every crypto unit touched by one permitted NBD request. The charge
  rounds to whole crypto units, including partial units at both ends, and
  accounts for `minimum_io` alignment and the export size. For example, 1 KiB
  requests with 512-byte alignment and 4 KiB crypto units can touch two units
  and need 8 KiB, not 5 KiB;
- a `cache.mode = "read"` with a zero size or TTL, and empty `control` values;
- missing or foreign provider sections: local providers need `[crypto].key` and
  must not carry transport sections; `remote-http` needs `[crypto.http]` with at
  least one endpoint and both `encrypt` and `decrypt` mappings; `remote-websocket`
  and `remote-grpc` need their section with at least one endpoint;
- endpoint URLs without a scheme or host, with userinfo, with duplicate or empty
  names, or with a scheme the transport does not speak;
- **plaintext transports to non-loopback hosts**: `http://`, `ws://`, and gRPC
  `http://` endpoints are accepted only for `localhost`, `127.0.0.0/8`, and
  `::1`. Use `https://` or `wss://` for remote endpoints. An explicit TLS section
  requires encrypted URLs for every endpoint in that transport, including
  loopback, so TLS options cannot be silently ignored;
- HTTP batch layouts (`body.items_path`) whose response mapping lacks
  `items_path` or `item_index_path`: every batch element must echo its unit
  index so reordered, dropped, or duplicated results are detected. Only a
  `type = "json"` body with `items_path` is a batch; a raw body is sent one
  item per request;
- HTTP JSON body mappings the provider cannot build or send as written
  (validation and the provider use one parser): an unknown field `source` or
  payload `encoding`, an `encoding` on a source other than `payload`, a
  request pointer or `items_path` that does not start with `/`, and request
  pointers that would replace one another on the wire. After RFC 6901
  decoding, no pointer of one JSON object may equal another or address a
  field inside it (`/volume` with `/volume/profile`, or `/x~2` with `/x~02`),
  and no top-level field may sit at, under or above the batch `items_path`;
  each batch element's `item_fields` are checked as their own object.
  `/vol` and `/volume`, or `/a~1b` (the key `a/b`) and `/a/b`, are distinct;
- HTTP JSON body fields that no request carries: a `payload`, `unit_index`
  or `batch_index` source among the top-level `fields` of a batch (they are
  evaluated once per request, with no item, and would be sent as an empty
  payload or zero; map them in `item_fields`), and a non-empty
  `item_fields` table on a per-item body, which sends only `fields`;
- a gRPC `encrypt_path` or `decrypt_path` that the provider would not send
  as written (validation and the provider apply one rule): it must start
  with `/`, be at most 65534 bytes long, and contain only RFC 3986 path and
  query characters (letters, digits, `-._~!$&'()*+,;=:@/?` and `%XX`
  escapes), as HTTP/2 requires of the `:path` it is sent as. A `#` fragment
  (never sent), a space or other character that needs escaping, and `*` or
  a bare `?query` (no method) are refused. Errors never quote the path;
- a declared `capabilities.context_binding` whose context does not reach
  the provider: each of `volume_id`, `compatibility_id` and `format_version`
  must be a source in the JSON `fields`, or in `item_fields` of a batch
  layout (a raw body sends no fields), and the attach self-test's
  unit-index probe needs a per-item `unit_index`: in `fields` of a per-item
  body, in `item_fields` of a batch;
- a transport limit that cannot carry one full crypto batch, including the
  declared maximum ciphertext size. The maximum batch is bounded by both
  `crypto.batch.max_items` and the number of provider plaintext units that fit
  `crypto.batch.max_bytes`; unused byte capacity does not enlarge it. Thus a
  one-item batch can use a smaller transport cap even if its plaintext-byte
  ceiling is large. gRPC `max_message_bytes` (default 4 MiB)
  includes protobuf field tags, lengths, indices, context and the singleton
  negative profile probe used by attach self-tests. WebSocket
  `max_frame_bytes` (default 8 MiB) includes each item's base64 padding, JSON
  structure, escaped profile, and maximum-width numeric fields. HTTP
  `max_response_bytes` (default 8 MiB) covers each operation's response mapping,
  base64/base64url/hex encoding, JSON pointer wrappers and echoed indices; raw
  and single-item responses are checked too. JSON bounds cover compact documents
  containing the declared fields, including the required null-filled
  array prefixes selected by numeric JSON-pointer tokens. Response pointers
  accept only the RFC 6901 `~0` and `~1` escapes (a request pointer keeps any
  other `~` literally, as in `/x~2` above). Optional provider metadata, non-null
  data in unmapped array siblings, whitespace and redundant escaping need
  additional response capacity. Remote responses still obey the hard
  runtime cap. A zero limit is rejected;
- a zero `timeout` for any remote transport;
- TLS material that does not exist or cannot be read, `client_key` without
  `client_cert_file`, and `server_name` (unsupported: put the certificate's name
  in the endpoint URL);
- the `keyring` credential source, which this build does not implement, the
  same credential name declared with different sources, a credential name the
  loaders cannot read or an `env` name no environment variable can have, and
  a credential `format` without exactly one `{}`
  placeholder or on a reference that is not a header or metadata value (see
  [credentials](#credentials-and-secrets)).

The providers additionally refuse unreadable or invalid TLS material at
construction or handshake, and read `client_key` from its credential source to
complete the client identity. Certificate and hostname failures prevent
successful attachment; they do not trigger a plaintext fallback.

## Compatibility identity

`crypto.random_prefix_bytes` can prepend random bytes to each plaintext unit
before encryption. It defaults to zero; enabled lengths are 16–256 in multiples
of 16. Provider plaintext capabilities must include the expanded unit size, and
the ciphertext bound must include the provider's full result. Enabled volumes
use a derived compatibility ID that includes the prefix length, so changing
this option requires a new volume. See [random plaintext prefixes](random-plaintext-prefix.md)
for configuration, batch accounting and security limits.

`crypto_compatibility_id` identifies the cryptographic profile rather than a
network endpoint. Every endpoint in a failover set must decrypt ciphertext from
every other endpoint. Changing keys, algorithms, nonce layout, context binding,
or payload encoding without a compatible migration requires a new identity and
must not attach to an existing volume.

Maki stores the provider type, compatibility identity, and key name in the
superblock and refuses attach when the configuration disagrees, before it
loads any provider credential or builds a provider transport. Process
hardening (the memory budget, core dumps, memory locking and the swap policy)
comes first, and so do opening the backing and recovery, since the superblock
that is compared is the one recovery selects inside the backing; with a remote
witness, opening it loads the witness client's TLS identity and claims a writer
at the authority. `maki check` reports each setting that
disagrees (see [Operations](operations.md#volume-lifecycle)). The provider
self-test verifies supported unit sizes, ciphertext bounds, response ordering,
round trips, and integrity claims; the key canary (see
[Operations](operations.md#key-binding-at-first-attach)) then proves that the
key material itself matches, which the self-test alone cannot.

## Credentials and secrets

Sensitive values must be credential references. Literal authorization headers,
API keys, tokens, and similar fields are rejected during validation. An HTTP
header or gRPC metadata name counts as sensitive when it is one of the classic
names (`Authorization`, `Cookie`, `X-Api-Key`, ...) or contains `auth`, `token`,
`secret`, `passw`, `cookie`, `session`, `signature`, `credential`, `apikey`,
`api_key`, `-key` or `_key`, which covers vendor headers such as
`X-Vault-Token`, `X-Goog-Api-Key` and `Ocp-Apim-Subscription-Key`. Any other
header may still use a credential reference, and every reference is validated.
Query parameters (`[crypto.http.*.query]`) accept only literals, so never put a
secret there. Production
deployments should use systemd credentials; environment-backed credentials are
intended for development.

The data-plane service receives credentials through `LoadCredential`;
systemd 257 and later write those files `0440` for the service's group, which
Maki accepts in the credentials directory only (R5-037). The
privileged attach helper has no crypto dependency and no credential directive.

A `file` credential must be a regular file with no group or other permission
bits (for example `0600` or `0400`), and
every credential file, in the credentials directory too, must be owned by root
or by the user the loading process runs as (the daemon user for the packaged
service). A file owned by any other user is refused whatever its mode, because
its owner can read or replace it; a process run as root therefore refuses a
key owned by the daemon user, so run it as that user instead.

Every credential reference is loaded from exactly the `source` it declares:
`credential` reads `$CREDENTIALS_DIRECTORY/<name>` and fails closed when the
directory is unset, `file` reads the named file (an absolute path: a relative
one would resolve against whichever process's working directory reads it), `env`
reads `MAKI_CREDENTIAL_<NAME>`. TLS `ca_file` and `client_cert_file` paths must
be absolute for the same reason. There is no fallback between sources, so a production
daemon cannot attach on a stray environment variable.
A `credential` name, and the file name that ends a `file` path, may contain
only ASCII letters, digits, `.`, `_` and `-` and must not start with `.`;
the loaders refuse any other name, so validation refuses it before a volume is
created (a key's name is stored as the volume's immutable key identity).
A file credential path must end in the file name. If an older volume was
created with a key path such as `/etc/maki/key/` or `/etc/maki/key/.`, remove
the trailing directory suffix from the configuration before reattaching.
The old loader opened `/etc/maki/key` in both cases. Maki recognizes that
stored spelling for the corrected file path and verifies the key as usual.
An `env` name is upper-cased, with `-` and `.` replaced by `_`, to form the
variable name. It must not contain `=` or a NUL character, which no
environment variable name can hold (a lookup of `A=B` would even return part
of variable `A`); any other name is accepted, since the source is meant for
development only.
A local provider key may be stored raw or as a hex string (decoded on load).
Every other credential (a header or metadata value, a `client_key` PEM) is
text and is used exactly as stored, surrounding whitespace aside for header
and metadata values, so a token generated with `openssl rand -hex 32` is sent
as that hex text.
A credential that is empty or holds only whitespace is refused like a missing
one, whatever its source and use, so a token file truncated by a failed
rotation stops attach instead of sending a header or metadata value without
its token.
A header or metadata reference may add `format`, a template with exactly one
`{}` placeholder that the credential replaces (`format = "Bearer {}"`). The
rest of the template is sent literally, so never put a secret there.
Validation refuses a template with no placeholder or with several, and refuses
`format` on `crypto.key` and `tls.client_key`, which are loaded as stored.
Within one volume configuration, references may reuse a name only when they
declare the same source. For example, `name = "token"` in both the encrypt and
decrypt mappings is valid with `source = "credential"` on both. Combining that
name with `source = "env"` is rejected during validation and provider
construction; use distinct names for distinct sources.
Do not place plaintext keys or bearer tokens in TOML, command lines, logs, or
operation plans.

## Remote HTTP mapping

HTTP, WebSocket and gRPC endpoint lists must fit the control plane's aggregate
output budget. The endpoint allowance is 48 KiB; each entry costs a conservative
384 bytes plus four times its JSON-encoded name length. The remaining 16 KiB
is reserved for fixed fields and the response envelope. Validation accounts for
all endpoint names, their JSON escaping and their repeated appearances in
status and metrics. Excessive lists or long
names are rejected before the volume opens; reducing only one name may not
make a large list fit. Accepted lists retain complete endpoint reports within
the existing 64 KiB control line limit. The server returns an explicit error
if a backend's runtime data produces a larger response.

The HTTP provider maps logical fields into a vendor request without interpreting
the vendor cipher. Supported mappings include raw single-item payloads and JSON
objects whose fields (JSON pointer = `{ source, encoding }`) carry one of these
sources:

| `source` | Sent as |
|---|---|
| `payload` | the item's plaintext or ciphertext, as a string in its `encoding`: `base64` (default, padded), `base64url` (unpadded), `hex-lower` (alias `hex`) or `hex-upper` |
| `unit_index` | the item's unit index, an unsigned JSON integer |
| `volume_id` | the volume UUID, a lowercase hyphenated string |
| `compatibility_id` | the crypto compatibility ID, a string |
| `format_version` | the on-disk format version, an unsigned JSON integer |
| `batch_index` | the item's position in its request, an unsigned JSON integer |

Every JSON request maps a per-item `payload`. Batch requests also map the volume
`unit_index` so the server can echo it, including when context binding is disabled.
Only `payload` takes an `encoding`. A per-item body sends `fields` once per
item and takes no `item_fields`. A batch body sends `fields` once per request,
so they may carry only `volume_id`, `compatibility_id` and `format_version`
(validation refuses a `payload`, `unit_index` or `batch_index` there, which
would describe no item), and the array of `item_fields` objects at
`items_path`.

JSON requests default to `Content-Type: application/json`. An explicitly
configured `Content-Type` overrides that default, including vendor media types;
header-name matching is case-insensitive. This applies to single-item and batch
operations. Raw requests retain their configured headers without a JSON default.

The endpoint URL's path is a prefix for each operation path. For example,
`https://crypto.example/gateway?tenant=demo` with `/encrypt` requests
`/gateway/encrypt?tenant=demo`. Endpoint and operation-path queries are preserved,
then `[crypto.http.*.query]` is appended. Trailing slash removal applies only to
the endpoint path, and URL fragments are not sent. Configuration accepts `POST`
and `PUT` in any ASCII case and sends their uppercase spelling; programmatic
`OpSpec` methods retain their explicit spelling.

Responses can be single-item or batched. For JSON responses, a configured
`item_index_path` requires an unsigned integer echo matching the requested unit
index, relative to the whole single-item response or each batch element. Missing,
wrong, or non-integer echoes are provider contract errors. Single-item mappings
may omit this setting; batch mappings require it. Raw responses remain unchanged.
The response-size limit includes the configured echo and JSON wrappers. Missing,
duplicate, reordered, oversized, or partial batch responses are provider contract
errors. Response bodies are read under a hard size limit.
A successful response must frame its body with `Content-Length` or chunked
transfer coding. A body that only the connection close ends is a provider
contract error, because it cannot be told apart from an endpoint that died
mid-response. A raw encrypt response shorter than its plaintext is a contract
error too: the whole body becomes the unit's ciphertext, and nothing else in it
distinguishes ciphertext from, for example, a proxy's error page. Contract
errors charge the endpoint that answered, and a retry-safe request fails over.
JSON responses are parsed against the response mapping: values that no
configured pointer reaches are validated but not kept, so the size limit also
bounds the memory a response takes, not only its wire bytes.
Transport error messages omit the request URL, including its query values,
for connection failures, timeouts, and response-body failures.
How each response status is classified, and the `maki-crypto-error` header
that reports an integrity failure or a context refusal, is listed under
[provider error signals](#provider-error-signals).

An HTTP request's `timeout` covers the connection it opens. Its connector
(hyper-util's, as for gRPC) resolves the endpoint's host; the family of the
first address goes first, and the other family starts 300 ms later, or at once
when the first family has failed. Within a family the addresses are tried one
at a time, in the resolver's order, and each of the family's `n` addresses may
take `timeout / n` to connect, so an address that does not answer leaves the
next one time: half the `timeout` for two. These shares are fixed: one refused
at once does not leave its time to those after it, and a live address slower to
accept the connection than its share is given up. When every address has
failed within its share, the request fails then, before its `timeout`, as a
connection failure that was not sent. hyper-util reports the family's first
failure, so the error reads "connect timeout" when the first address's share
ran out and "transport error" when the first address refused the connection,
whatever the later ones did. When an address is still connecting at the
`timeout`, the request fails as a request timeout. Keep `timeout` well above `n` times the time a
connect is expected to take: with a short `timeout`, a host with many
addresses can have every live one given up, and on Linux one lost SYN already
delays a connect by 1 s. reqwest does not expose the 300 ms, so with a
`timeout` of 300 ms or less the other family is never tried when the first one
does not answer.

A per-item mapping without `body.items_path` sends one unit per HTTP call.
Units within a parent request run concurrently only within the existing
`limits.max_active_callbacks` budget. Declaring a larger batch size does not
turn a single-item vendor API into a batched one. Prefer a real batch mapping
when available, and establish throughput and tail latency with the
[performance profile](performance.md#compare-remote-mappings).

## WebSocket and gRPC contracts

WebSocket uses one JSON request per text frame with a correlation ID. Unknown or
stale response IDs are discarded; a binary frame, a text frame that is not JSON,
or a response without a numeric ID breaks the contract and fails every request
on that connection at once as a contract error. An `integrity` or
`unsupported-context` error frame whose envelope is not exact (see
[provider error signals](#provider-error-signals)) fails only the request it
answers, as a contract error, and that request is not sent again; the
connection then takes no new request and is released once the requests already
on it finish, as after a cancelled request (below). Any other malformed answer
to one request, such as an unknown error class or reason or a missing item, is
a contract error for that request and leaves the connection in use. Ping and
pong frames are ignored, and a close frame ends the connection. Pending requests are scoped to a connection
generation, and both inbound and outbound frame sizes are bounded. Each
response item must carry the `unit` of the request item it answers, in request
order; a missing, reordered, or mislabelled item is a contract error.
A response frame is parsed against this protocol: only its `id`, the error's
`class` and `reason`, and the `unit` and `data` of at most as many items as the
largest request awaiting a response on that connection are kept. Other values
are validated but not kept, so the frame-size limit also bounds the memory a
response takes, not only its wire bytes.
Once a request has registered on an established connection, cancelling it or
expiring its overall attempt deadline or response-wait timeout removes that
request and stops new requests from joining its connection generation.
Other in-flight requests
keep their socket and reader/writer task until they finish; the final request
then releases the draining generation. New requests use a replacement
generation, whose socket and requests are unaffected by cleanup of the old
one. Dropping the provider also closes an otherwise idle connection.

Connection loss, a send failure reported by the transport, or a fatal frame
error still fails the requests on that generation whose responses have not
already arrived. A timeout reported by the transport send queue can retire the
generation; expiration of the request's overall attempt deadline while waiting
to send follows the drain behavior above. Connection loss is retryable, while
malformed frames are contract errors as described above. A provider with
`retry_safe = false` returns errors without resending those requests. An
individual request cancellation does not make its live siblings fail or
require them to be resent.

The HTTP upgrade that opens a connection is the same request every time and
carries no crypto request, so its refusal is never blamed on a request: HTTP
408 and 5xx are retryable, 429 is throttling, and every other status (a
redirect, an authentication refusal, or a generic 4xx such as 400 or 426 from
a proxy that cannot upgrade) is an endpoint failure. The dispatcher opens that
endpoint's circuit, so later requests go to a peer, and attach quarantines it
like an unreachable endpoint. The refused request itself fails over at once,
even with `retry_safe = false`: no byte of it was sent (see below).

A gRPC request gives up after `timeout`, but the connection attempt behind it
(TCP connect and TLS handshake together) may continue for up to four times
`timeout`, so a slow handshake still serves the next request; a peer that never
completes the handshake is abandoned then and the next request reconnects.

A WebSocket request's `timeout` covers the connection it opens, including the
time the request waited for the connection. The endpoint's host is resolved;
the family of the first address goes first, and the other family starts 300 ms
later, as in the gRPC transport's connector, or at once when the first family
has failed. With less than 600 ms of the request left when the addresses are
dialed, it starts once half of what is left has passed instead, so it always
has at least half of that time, also with a `timeout` of 300 ms or less. Within
a family the addresses are tried one at a time, in the
resolver's order: each but the last may take an equal share of what is left of
the request's `timeout`, and the last has the rest, so an address that does not
answer leaves the next one time and one refused at once leaves its share to
those after it. (The gRPC connector gives every address of a family, the last
one too, a fixed share of its timeout, and keeps a family's first failure.)
The first connection made wins and the other attempt
is dropped; when none connects, the last failure is reported. The TLS handshake
and the upgrade then run on that connection, with the certificate verified for
the URL's host, never for the address it resolved to; their failure is not
retried at another address. No proxy is used.

Providers that do not declare `retry_safe` are sent every request at most
once: the dispatcher performs no retry or failover after a request may have
been sent, and the WebSocket transport does not resend over a fresh connection.
A request that provably never left Maki has not been sent, so it fails over to
another endpoint and is retried under the availability policy like any request
not yet sent. The transports claim this only where they can prove it: HTTP
when reqwest reports a connect error (the TCP connection or the TLS handshake
failed), gRPC when the connection, TLS handshake or channel readiness fails,
or the request timeout expires, before the request is handed to the
established connection, and WebSocket when the TCP connection, TLS, the
upgrade or the send queue fails, or the request timeout expires, before the
request frame reaches the connection. A timeout, reset or error status after
that point counts as sent, as does a later unit of an HTTP per-item mapping
once an earlier unit was sent. With
`availability_policy = "bounded-error"`, `max_operation_time` is an absolute
wall-clock deadline: backoff never sleeps past it and an expired caller receives
the last error an endpoint returned before the deadline for the RPC batch in
progress (one batch of items with its retries and failovers; a call sent as
several RPC batches reports only the current one), with that error's class, or
`operation deadline exceeded` when no endpoint failed that batch; either way
it counts once in `maki_crypto_deadline_exceeded_total`. A shared RPC
remains active while it still has a live caller.
Endpoints that could not be cross-validated at attach
(unreachable at the time) are quarantined and start serving only after the
cross-endpoint check succeeds against a validated endpoint. Each endpoint, a
lone one included, is probed on its own at attach (three attempts, spaced by
`retry.initial_delay`, for a `retry_safe` provider; one otherwise). When none
is reachable the attach is refused with "no remote endpoint is reachable;
attach refused" followed by each endpoint's name and failure (the first
endpoint failure among its attempts, otherwise the last failure). A lone
endpoint is the exception when none of its attempts gave an endpoint
failure and its probe request may be sent again: the provider is
`retry_safe`, or every attempt failed before the request left Maki (a
refused connection, a refused WebSocket upgrade). The attach then logs a
warning, "endpoint "<name>" unreachable at attach (<error>); it is the only
endpoint, so the attach keeps retrying it under the <policy> availability
policy", and retries it like any request, so `stall` waits for it and
`bounded-error` gives up at `max_operation_time`. Otherwise the probe's
failure refuses the attach under either policy: an endpoint failure (a TLS
authentication failure, a 401, 403 or 404) in any attempt, or, when the
provider is not `retry_safe`, a failure after the request may have reached
the endpoint (a 5xx, a timeout, a lost response), which is never sent
again. The policy also governs the engine's own self-test that follows the
probe, so under `stall` an endpoint that fails after passing its probe is
waited for as well.
Each background validation RPC shares the serving RPC count and resident-byte
budgets, and its probe batches are narrowed to fit those budgets. The dispatcher
owns these validation tasks and cancels them when its final owner is dropped.
Only proof that the candidate serves another contract excludes it until the
daemon restarts (`rejected: true` in its status): another key (either endpoint
refuses the other's ciphertext with an integrity failure or decrypts it to the
wrong plaintext, or the candidate does so with the volume canary), another
compatibility id, a claimed capability it does not honour, or an explicit
refusal of the volume's context. Anything else shows only that an exchange
failed and is inconclusive: a transport error or timeout, a reply that does
not parse or is truncated (a proxy error page, an endpoint restarting
mid-response) or a request refused without an integrity failure (a generic 4xx
such as 400 or 421, a WebSocket `bad-request`, a gRPC `InvalidArgument`) from
either endpoint, whatever the request, or any other failure of the validated
reference. The
candidate then stays quarantined and is validated again after
`circuit_breaker.open_initial`, the spacing doubling after each further
inconclusive attempt up to `circuit_breaker.open_max`; it serves only once a
later validation succeeds in full. Attach itself is stricter: a generic
refusal of a tamper or context probe, or of the other endpoint's ciphertext,
refuses the attach.
HalfOpen breaker probes return their admission slots on every exit, including
operation deadlines, cancellation, request/provider errors, and refusal by the
retry budget. These neutral outcomes leave the endpoint's failure count
unchanged, so later requests can still probe for recovery.

For a batched crypto call, the operation budget begins before scheduler
admission and includes coalescing, waiting for an RPC slot, and the RPC itself.
Dispatch does not reset the caller's budget. Cancellation removes that caller's
queued payload and admission charge; an in-flight coalesced RPC is abandoned
when its final caller leaves. Other callers in that batch can still complete.

The gRPC transport uses the message shape in
[`packaging/examples/maki-crypto.proto`](../packaging/examples/maki-crypto.proto).
A gateway endpoint path prefixes the method path. Endpoint query parameters precede
method query parameters on the request. ASCII metadata names are case-insensitive
and unique. Binary keys ending in `-bin` and the protocol fields `te`,
`content-type`, `user-agent`, `grpc-message`, `grpc-message-type`, and
`grpc-status` are rejected in configured metadata.

Service method paths are configurable (`encrypt_path` and `decrypt_path`,
default `/maki.CryptoService/EncryptBatch` and `/maki.CryptoService/DecryptBatch`;
a gateway prefix or a query is sent unchanged), but request and response
messages must match that contract and responses must preserve unit identity
and order.
The message-size limit bounds each received gRPC frame before decoding, and
decoding refuses the first item beyond the number the request carried, so the
limit also bounds the memory a response's items take. Locally rejected
oversized frames, extra items and invalid protobuf results are endpoint
contract failures: their breaker is charged, and only retry-safe requests may
move to another peer. An actual remote `OutOfRange` status remains a request
error, regardless of its message text. Remote status text (`grpc-message`) and
details (`grpc-status-details-bin`) are discarded before the status is read:
an error's class follows only its `grpc-status` code and `maki-crypto-error`
metadata, and text or details that do not decode neither change that class nor
turn an OK status into an error.

## Provider error signals

A remote provider reports a failure through its transport's status, never
through text: an HTTP error body, a gRPC status message or its details, and a
WebSocket `error.message` are ignored. This section lists every signal the
transports recognise and the error each becomes
([SPEC §18](../SPEC.md#18-remote-crypto) is normative).

Two failures carry an explicit token:

| Failure | Token | Meaning |
|---|---|---|
| Integrity | `auth-tag-mismatch` | The ciphertext failed authentication |
| Integrity | `context-mismatch` | The ciphertext is not bound to the context it was presented under |
| Context refusal | `unsupported-format-version` | The provider does not accept the request's format version |
| Context refusal | `unsupported-compatibility-id` | The provider does not accept the request's compatibility ID |

| Transport | Where the token goes |
|---|---|
| HTTP | Status 422 with exactly one `maki-crypto-error` response header whose value is the token |
| gRPC | Status `FailedPrecondition` with exactly one `maki-crypto-error` metadata value |
| WebSocket | `{"id": n, "error": {"class": "integrity", "reason": "<token>"}}`, or `"class": "unsupported-context"` for a context refusal |

A token is compared exactly. A missing, unknown, repeated or comma-joined
value, or a token on any other HTTP or gRPC status, is not one of these
signals: the response is classified by its status alone. A WebSocket frame
that repeats a member is read from its last occurrence, so its class is the
last `class` of its last `error`. An `integrity` or `unsupported-context`
class selected this way is a contract error when its `reason` is absent, is
not a string or is not one of that class's two tokens, or when the frame
repeats `id`, `error`, `class` or `reason`.

In each table below a row applies only when no row above it does.

| HTTP response | Error |
|---|---|
| 2xx | None; the body must satisfy the response mapping, or it is a contract error |
| 422 with exactly one `maki-crypto-error` header, holding a token | Integrity failure or unsupported context, by the token |
| 429 | Throttled |
| 408 | Retryable |
| 3xx, 401, 403, 404, 405, 407, 410 | Endpoint failure; a redirect is never followed |
| Any other 4xx, such as 400, 409, 413 or a 422 without one token | Request error |
| Any other status, such as 500, 502, 503 or 504 | Retryable |

| gRPC status | Error |
|---|---|
| `OK` | None; the reply must be one message that answers the request's items, or it is a contract error |
| `FailedPrecondition` with exactly one `maki-crypto-error` metadata value, holding a token | Integrity failure or unsupported context, by the token |
| `ResourceExhausted` | Throttled |
| `Unauthenticated`, `PermissionDenied`, `Unimplemented` | Endpoint failure |
| `InvalidArgument`, `NotFound`, `OutOfRange`, any other `FailedPrecondition` | Request error |
| Any other status: `Unavailable`, `DeadlineExceeded`, `Aborted`, `Internal`, `Cancelled`, `Unknown`, `AlreadyExists`, `DataLoss` | Retryable |

A gRPC response with an HTTP status other than 200 and no `grpc-status`, such
as a proxy's error page, is classified by that HTTP status: 401, 403 and 404
are endpoint failures and every other status is retryable.

| WebSocket `error.class` | Error |
|---|---|
| `integrity` with one of its two `reason` tokens | Integrity failure |
| `unsupported-context` with one of its two `reason` tokens | Unsupported context |
| `throttled` | Throttled |
| `retryable` | Retryable |
| `bad-request` | Request error |
| Anything else, a missing class included | Contract error |

A WebSocket error frame cannot report an endpoint failure. The upgrade that
opens a connection can, as described [above](#websocket-and-grpc-contracts).

A failure without such an answer is classified the same way on all three
transports: a timeout or a lost connection, also one that cuts a reply short,
is retryable, and a TLS authentication or protocol failure is an endpoint
failure. On an established connection, a reply that breaks the framing of the
transport's messages or its size limit (`max_response_bytes`,
`max_message_bytes`, `max_frame_bytes`) is a contract error: an HTTP/1.1
response head or chunked body that does not parse, or a body that only the
connection's close ends; a gRPC message whose length prefix, count or final
status breaks the gRPC protocol, or a stream that ends inside a message; a
WebSocket frame that breaks the WebSocket protocol or is not a JSON text frame
with a numeric ID. A TLS failure is recognised wherever the TLS error reaches
the transport: in the connection attempt, and for gRPC also when the library
reconnects inside an established channel (a server restarted with a
certificate Maki does not trust); the next call then opens a new connection.
Three failures are classified otherwise:

- A WebSocket upgrade reply that is not a valid upgrade (a 101 without the
  upgrade headers or with the wrong accept key, a status below 300 or above
  599, a head that is not HTTP) is an endpoint failure, like a refused upgrade.
  An upgrade reply cut short by a lost connection is retryable.
- An HTTP/2 error under a gRPC call, a reset stream or a GOAWAY, becomes the
  gRPC status that the gRPC library derives from it and is classified by the
  gRPC table above. A reset, and a GOAWAY that refuses the call (its last
  stream ID is below the call's stream, so the server did not process it), is
  classified by its error code: `ENHANCE_YOUR_CALM` is throttled
  (`ResourceExhausted`; a gRPC server's keepalive policy sends it to a client
  that pings too often), `INADEQUATE_SECURITY` is an endpoint failure
  (`PermissionDenied`), and every other code is retryable. A GOAWAY that
  accepted the call and then closes the connection under it is retryable
  whatever its code. Either way the request was handed to the connection and
  counts as sent, so a call that a GOAWAY refused is sent to another endpoint
  only when the provider is `retry_safe`. The next call opens a new
  connection.
- A gRPC server that refuses the client certificate under TLS 1.3 does so
  after the client has finished its side of the handshake, so the refusal
  reaches the first call, not the connection attempt. The HTTP/2 library
  keeps only the kind and text of that connection error, or cancels the call
  with "connection closed", and Maki never classifies by text: the call is
  classified by the status the library derives, usually `Unknown`,
  `Cancelled` or `Unavailable`, which is retryable and counts as sent. The
  server's log names the refusal. Under TLS 1.2 the refusal happens inside
  the handshake and is an endpoint failure, and HTTP and WebSocket report it
  as one when the server's alert is read before the connection is lost. On
  any transport, a server that resets the connection before the client has
  read its alert leaves only a lost connection, which is retryable.

Each error's message carries a fixed prefix, and the dispatcher handles each
kind differently:

| Error | Message prefix | What the dispatcher does |
|---|---|---|
| Retryable | `retryable:` | Counts a failure on the endpoint's circuit breaker, fails over to another endpoint, then retries with backoff under the availability policy |
| Throttled | `throttled:` | The same as retryable, with no extra backoff |
| Endpoint failure | `endpoint fatal:` | Opens the endpoint's circuit at once; the request fails over like a retryable one |
| Request error | `non-retryable request:` | Fails the operation at once: no retry, no failover, no breaker charge |
| Integrity failure | `integrity failure:` | The same as a request error |
| Unsupported context | `unsupported crypto context:` | Fails the operation at once: no retry, no failover, no breaker charge |
| Contract error | `provider contract violation:` | Counts a failure on the breaker and never sends this operation to that endpoint again; it moves to another validated endpoint only when the provider is `retry_safe` |

With `retry_safe = false`, a retryable, throttled or endpoint-failure error on
a request that may have been sent is returned without another attempt (see
[above](#websocket-and-grpc-contracts)).

At attach, a provider that declares `integrity` or `context_binding` is
given negative probes: a tampered ciphertext to decrypt, and an intact one to
decrypt under a changed unit index, volume UUID, format version or
compatibility ID. Only these answers pass:

| Probe | Passes with |
|---|---|
| Tampered ciphertext (`integrity`) | An integrity failure. Any successful reply fails the probe, whatever plaintext it carries |
| Changed unit index or volume UUID (`context_binding`) | An integrity failure, or a well-formed reply whose plaintext differs from the original |
| Changed format version or compatibility ID (`context_binding`) | The same, or a context refusal that names the changed field |

A retryable, throttled or endpoint-failure answer to a probe is inconclusive:
the endpoint is quarantined, or the attach fails when no other endpoint is
reachable (a lone endpoint that answered only retryable or throttled errors
and whose probe request may be sent again is retried under the availability
policy instead, as described [above](#websocket-and-grpc-contracts)). A contract error fails the
self-test and the attach. Any other answer, such as a 400, a 422 without a
token, a gRPC `InvalidArgument` or a WebSocket `bad-request`, refuses the
attach, because the declared capability was not proven. The cross-endpoint
check reads a refusal the other way: an endpoint that answers another
endpoint's ciphertext with an integrity failure or a request error is not
interchangeable with it, and the attach is refused.

## Backing directory identity

On Linux, `backing.root` and its ancestors must be real directories; symlink
aliases are refused. The backing pins the selected directory with an open
descriptor. Subsequent file, lock, rename, removal, listing, directory sync,
and free-space operations resolve through directory descriptors without
following symlinks. Renaming the root and replacing its old pathname cannot
redirect an existing backing instance to another volume.

When the backing creates missing root directories, it synchronizes their
directory entries before returning. Creation therefore requires read access
to each parent that will receive a new directory, as well as write and search
access. Existing ancestors still need only search access. Opening a root also
retries directory synchronization on writable, readable ancestors on its own
filesystem, so a previously failed creation cannot bypass the durability
barrier merely because its directories now exist.

Keep the backing tree writable only by its owner. Descriptor confinement does
not authenticate file contents or prevent a process with direct write access
from altering the volume. Other development platforms retain pathname-based
checks; this Linux confinement guarantee does not apply to them.

## NBD request limits

`nbd.socket`, when set, is a startup contract with the native nbdkit
listener. The plugin verifies the actual listening descriptor's pathname
before recovery, control binding and READY; a mismatching `nbdkit -U` path
fails startup. Merely creating another socket at the configured path does not
satisfy that check. The packaged unit uses `/run/maki/<volume>/nbd.sock`;
custom paths require a matching service launch and directory/sandbox policy.
When unset, the manual launch chooses its listener. Native control `status`
reports the observed pathname as `nbd_socket` (or null if there is no unique
pathname listener). Non-native adapter contexts have no observed listener.

`nbd.connections` must be `1`; multi-connection operation is disabled.

`nbd.threads` sets the number of Tokio runtime worker threads used by the
plugin. The default is 64, and the supported range is `1..=256`. This is
not the process's total thread count: nbdkit owns its native callback
thread pool, and Tokio may also create blocking-operation threads. The
plugin allows parallel nbdkit callbacks; changing `nbd.threads` does not
configure nbdkit's callback pool.

Request admission is controlled separately by `limits.max_active_callbacks`
and `limits.max_plaintext_bytes`. Increasing the runtime worker count does
not increase those limits or establish a tested throughput guarantee.

The plugin advertises `minimum_io`, `preferred_io`, and `maximum_io` through
nbdkit's block-size callback. The configured and stored export size must be a
multiple of `minimum_io`, so every exported byte is accessible. A larger
minimum can therefore require a different setting for an existing small volume.
The adapter rejects read/write requests with zero
length, invalid minimum-size alignment or an out-of-range end with EINVAL,
before copying write plaintext or entering the engine. Negotiation is advisory
and the Linux NBD driver does not honour the maximum (Debian 13's 6.12 kernel
sends writes up to `max_sectors_kb`, 1280 KiB by default), so a read or write
longer than `maximum_io` is served in chunks of at most `maximum_io`, each
copied and admitted on its own; FUA applies to the last chunk, whose journal
sync covers the others (R5-038). The engine itself still refuses anything
larger, so the value keeps bounding the plaintext and journal headroom of one
engine request. A trim or zero request is chunked the same way (the Linux nbd
driver sends much larger discards). `preferred_io` remains a performance
hint.

This negotiation path was verified with the installed nbdkit header and a real
rootless nbdkit/libnbd connection. Older clients can still connect, but requests
outside the configured constraints fail cleanly.

## Read cache

`cache.mode = "read"` keeps decrypted units in a versioned LRU keyed by
`(unit, write_sequence)`, bounded by `cache.max_bytes` and `cache.ttl`, with
entries in zeroizing buffers that are page-locked as
`security.memory_lock_mode` selects. `cache.lock_memory` and
`cache.zeroize_on_evict` are accepted but select neither: an entry is zeroized
when its last owner drops it whatever `zeroize_on_evict` says, and
`lock_memory = false` does not unlock entries (validation only refuses
`lock_memory = true` with `memory_lock_mode = "off"`). A read
first establishes each unit's current version — the overlay entry, or the
64-byte slot header — and serves a hit without reading the ciphertext
payload or calling the provider; a miss reads, verifies and decrypts the
payload and caches the result. A newer write changes the sequence, so a
stale entry can never be served.

Two consequences to know:

- The cache saves the payload read and the crypto call, not the header
  read: a hit still costs one small read (usually from the page cache).
- A hit does not re-verify the on-disk payload CRC of a version that was
  verified when it was cached. Payload-only damage that appears afterwards
  is therefore served from the cache until the entry is evicted by TTL,
  LRU pressure, a resize, or a newer write; header-level damage (an
  undecodable header, a foreign unit) still refuses the read, and
  `maki check --deep` reports the payload damage. Set `cache.ttl` with that
  window in mind, set `cache.verify_on_hit = true`, or keep `mode = "off"`
  for a workload with its own cache.

`cache.verify_on_hit = true` (default `false`) closes that window: every read
reads and CRC-checks the ciphertext payload exactly as a miss does, so payload
damage is EIO at once, and a hit saves only the provider call. Use it when the
decryption, not the storage read, is the cost you want the cache to remove
(a remote provider, for example). It is read at attach; changing it needs a
restart.

The size and TTL are runtime settings:

```sh
maki reload <config> cache --max-bytes 1048576 --ttl 1s
```

Omitting `--ttl` preserves the current TTL. The control payload requires
`max_bytes` and accepts an optional `ttl` string using the same duration syntax
as this configuration. Both settings are validated before either changes;
unknown fields, zero or invalid TTL, invalid size, and a disabled cache are
refused. A new TTL applies to existing entries using their original insertion
times; it does not refresh them.

## Journal bounds

| Setting | Enforced as |
|---|---|
| `backing.journal_segment_size` | Size at which the journal writer starts a new segment (4096 bytes to 1 GiB). It may be changed between attaches, lowered included: recovery accepts segments of any size up to that maximum |
| `backing.journal_max_bytes` | Hard limit on journal bytes on disk (at least twice the segment size). The worker checkpoints at half of it; a write that would exceed it checkpoints inline and fails with ENOSPC only if that cannot make room (see the inline reclaim paragraph below) |
| `backing.journal_emergency_reserve_bytes` | Enables write-admission free-space checks; writes fail with ENOSPC unless a fresh sample covers this reserve, checkpoint headroom, and the projected record/segment-header footprint |
| `backing.checkpoint_reserve_bytes` | Headroom preserved by write admission while the emergency reserve is enabled; the worker also checkpoints eagerly below this value |
| `limits.max_journal_pending_bytes` | Appended-but-unsynced journal bytes; checked before every record, including inside one request. Must hold a maximum ciphertext plus its 32-byte record header |
| `limits.max_overlay_bytes` (default 256 MiB) | Ciphertext held in memory by the overlay (journaled, not yet checkpointed records; each unit's latest and durable copy). A write whose projected charge would exceed it syncs and checkpoints inline first, and fails with ENOSPC only when that reclaim cannot make room; the worker checkpoints at half of it. Must hold twice the ciphertext for the greatest number of crypto units a legal request can touch, respecting export size and minimum I/O alignment, or be `0` to disable |
| `limits.max_overlay_entries` (default 262144) | Units the overlay may hold, whatever their payload (a v3 discard tombstone has none but still costs an entry). Same inline-checkpoint and ENOSPC behaviour; must hold the largest request in crypto units, or be `0` to disable |

An inline reclaim keeps what it frees for the write that ran it. From the
moment a write is refused for the journal or overlay bound until it has
appended, it holds a reclaim gate, and every other write or discard queues
behind it in arrival order instead of appending; reads, FLUSH and the
background worker do not wait. Only admitted requests queue, so
`limits.max_active_callbacks` bounds the queue. Nothing is appended between
the reclaiming write's journal sync and its retry, so its checkpoint covers
every appended record, and ENOSPC means that the request does not fit even
then. The validated minimums of both bounds are therefore sized for one
maximal request, not one per concurrent callback.

The hard journal limit also has a configuration-dependent minimum for forward
progress after reclaim. It includes the largest request, the retained active
segment and every segment header that appending the request can create.
Small segment sizes can require many headers for one large request; twice the
segment size plus record bytes alone is not a sufficient minimum.

A request may contain more record bytes than the pending budget: the engine
syncs between records to keep the tail bounded. Configuration validation and
direct core attach both reject a budget smaller than one maximum framed record.
An intermediate sync failure stops further appends and is returned to the caller.

The default checkpoint worker interval is 30 seconds. An administrative
checkpoint applies durable records; a successful call that advances no sequence
does not postpone the worker's periodic sync of pending writes. After a failed
pass the worker waits one interval before it tries again, however many writes
cross the watermark meanwhile; a write that reaches `journal_max_bytes` still
checkpoints inline, and a success clears the wait. Each pass syncs unsynced
records before it checkpoints; a failed sync counts as a failed pass, but the
pass still checkpoints the records that were durable before it, whatever started
it (applying them, deleting the sealed segments they cover and shrinking the
overlay), and then waits, so a journal whose syncs keep failing still gives that
space and memory back. With nothing durable left to apply or reclaim, a pass
whose sync fails runs no checkpoint. The watermark counts only journal a
checkpoint can delete: the active segment is never deleted, so the worker
checkpoints for size only once a sealed segment exists. Half of
`journal_max_bytes` is always above one segment, so this only matters to an
engine embedded with a lower watermark, which then checkpoints once per sealed
segment instead of on every write.

The overlay bounds exist because `journal_max_bytes` is a *disk* budget: with
a slow or failing checkpoint the overlay would otherwise grow toward the whole
journal, and `limits.max_ciphertext_bytes` only governs the remote scheduler's
queue, not this structure. `maki metrics` reports `maki_overlay_bytes` and
`maki_overlay_units` (`maki status` does not); the byte figure is the logical
charge (a shared version is counted twice), not process RSS, and the bound
applies to that projection.

Free space is read with `statvfs` on Unix hosts. When the emergency reserve is
enabled, an unavailable or failed query fails write admission with ENOSPC;
`maki_backing_free_bytes` is null until a usable observation is available.

When the emergency reserve is enabled, every write admission refreshes free
space while holding the volume write lock. It requires enough space for the
configured emergency reserve and checkpoint headroom after all record bytes and
segment headers created by that request. A discard (v3) needs only the
emergency reserve: its tombstones carry no payload and their checkpoint writes
no slot data, so a raw discard of the exported device is still admitted when
free space is inside the checkpoint headroom. A filesystem on the volume
cannot use that: deleting a file is itself a write, and XFS `fstrim` forces a
log write before it discards, so both are refused there and the filesystem
sees I/O errors ([known limitations](status.md#known-limitations)). Keep
backing free space above the reserve plus the headroom, and recover from that
state by freeing space on the backing
filesystem, not inside the volume. Checked arithmetic fails closed on an
overflow. It does not reuse the statistics cache, so space lost or restored
between consecutive writes is observed even within the same second. Setting
the emergency reserve to zero retains the explicit admission opt-out; the
checkpoint threshold still controls the worker. Status and metrics read cached
observations and never initiate this filesystem query.

The thresholds do not reserve the volume's entire maximum layout. On Linux,
each write additionally uses `posix_fallocate` for its exact journal range and
the complete destination slot before the journal accepts the record. A new
shard also has both allocation-map copies and its catalog entry created and
synced first. An unrelated filesystem consumer therefore cannot take the
already allocated journal or slot blocks before checkpoint completes. That
holds only where the backing filesystem overwrites allocated blocks in place:
not for extents shared with a reflink copy, and not on a copy-on-write
filesystem ([backing store](deployment/support-matrix.md#backing-store-below-maki)).
One metadata store is an exception there too: an A/B copy that a power loss
left undecodable is emptied before it is written again, which releases its
blocks, so on a filesystem with no free block that store can fail with ENOSPC,
and with it the checkpoint, barrier or attach that needed it. The other copy
is untouched, acknowledged writes stay in the journal, and the operation
succeeds once space is available.
A reservation failure returns ENOSPC without consuming a journal sequence and
is retryable.

Untouched slots remain sparse and unreserved. Filesystem directory metadata,
copy-on-write amplification, snapshots, journal/checkpoint headroom beyond the
exact admitted ranges, and application or database temporary space still need
deployment capacity. Non-Linux development backings extend the file but do not
claim the Linux physical-allocation guarantee. Include the remaining costs in
capacity qualification instead of equating exported virtual size with backing
space.

## Batching and pending bounds

The serving endpoint set is bound to the selected provider plaintext unit:
`volume.crypto_unit_size + crypto.random_prefix_bytes`. Encrypt inputs and
decrypt results must match that size even when the provider profile advertises
other supported sizes, and the set reports that size alone to the layers above
it. Decrypt batching uses the selected logical plaintext
size; actual ciphertext bytes still count toward memory and dispatch admission
limits. A larger unused supported size does not prevent a smaller volume from
using its valid batch limit.

Remote providers are called through a batch scheduler (SPEC §30). Concurrent
requests are coalesced into one provider call when their items fit
`crypto.batch.max_items` / `max_bytes`; a batch is dispatched as soon as
`target_items` or `target_bytes` is reached, subject to dispatch capacity.
Otherwise, coalescing stops `max_wait` after the oldest live request entered
the admitted queue. Time spent queued behind other batches counts toward this
window, while time waiting for queue admission does not. A full lane can delay
dispatch beyond that deadline; available capacity does not start a new window.
A request's items are never split and keep
their order. Requests that touch the same unit are never coalesced: one
provider call never carries a unit twice. A single request with a repeated unit
number is rejected before queue admission. So is a request with a unit that the
dispatcher or the random-prefix wrapper refuses before sending anything: an
empty ciphertext (a damaged slot can record one), a ciphertext above the
provider's maximum, or plaintext of a size the provider does not accept or
that is not the selected unit. Such a request fails alone.
A rejection the provider itself returns for a coalesced
call reaches each request separately only when the provider is `retry_safe`
(each request is then re-sent alone); otherwise it reaches every request in
the call. Each lane keeps up to `limits.max_crypto_inflight_batches`
batches in flight at once (the dispatcher's own limits bound what reaches the
endpoints), so one slow batch does not serialize the requests behind it.
`limits.max_pending_crypto_items` bounds queued items per lane (one permit per
item, so a request of eight items counts as eight),
`limits.max_pending_crypto_bytes` bounds queued plaintext (encrypt lane) and
`limits.max_ciphertext_bytes` bounds queued ciphertext (decrypt lane); a full
queue applies backpressure. Local providers are called directly, since
coalescing an in-process cipher only adds latency. `maki status` reports the
scheduler under `crypto`, and metrics expose `maki_crypto_pending_items`,
`maki_crypto_pending_bytes`, and batch counters.

The engine splits a request into batches of at most the provider's
`max_items` and runs them concurrently: the request's own admission covers
the first, and each further batch runs only under an idle
`limits.max_active_callbacks` slot taken without waiting, so that limit still
bounds provider calls and a waiting request is never starved (R5-039). A
`remote-http` mapping without `items_path` sends one HTTP request per unit,
so it counts as `max_items = 1` whatever `[crypto.batch]` says, and the
scheduler dispatches each unit at once instead of coalescing it; the
per-endpoint and in-flight limits bound how many reach the vendor. With
10 ms of provider latency this took sequential 128 KiB reads and writes from
about 330 KiB/s to 2.8 MiB/s. A batched mapping (`items_path`) is still
cheaper per unit.

## Security settings

The default administrative socket is
`/run/maki-control/<volume>/control.sock`. The shipped runtime directories allow
`maki-admin` to traverse this tree while the NBD socket remains under the
daemon group's `/run/maki` tree. `control.socket` can override the path; its
parent directories must permit traversal by the configured control group.

The `[security]` section is applied by the daemon before the volume is
attached, fails closed on Linux, and is reported under `security` in
`maki status` so nothing in it is a placebo.

| Setting | Effect on Linux |
|---|---|
| `disable_core_dump` (default true) | `prctl(PR_SET_DUMPABLE, 0)` and `RLIMIT_CORE = 0`, verified after the call |
| `madv_dontdump` (default true) | Honoured through `disable_core_dump`; validation refuses it when core dumps stay enabled |
| `memory_lock_mode = "secure-buffers"` (default) | Attempts to `mlock` registered `SecretBuffer` allocations (including plaintext, keys and cache entries); shared pages stay locked until their last buffer owner releases them, and failures are counted and reported. Local providers produce plaintext in place inside such buffers; their expanded AES key schedules are page-locked in a `SecretBox` and zeroized on drop (see [local providers and key material](transport-memory.md#local-providers-and-key-material)). Separate transport allocations are described in [buffer lifetime limits](transport-memory.md) |
| `memory_lock_mode = "all"` | `mlockall(MCL_CURRENT \| MCL_FUTURE)`; a failure refuses attach (raise `LimitMEMLOCK`) |
| `memory_lock_mode = "off"` | No locking. `cache.lock_memory` defaults to `true` (also with the cache off), which validation refuses with this mode, so set `cache.lock_memory = false` too |
| `require_secure_swap_policy` (default false) | Requires readable, parseable `/proc/swaps` and accepts only RAM-only zram or dm-crypt with proven independent physical backing, including zram writeback. NBD ancestors, cycles, and unknown backing are refused. Device identity determines classification; keep the topology fixed while attached. See [swap dependency checks](operations.md#swap-dependency-checks). The shipped production example enables this policy |

Buffers are zeroized before their page-lock ownership is released. Exporting a
buffer as a plain vector releases that buffer's ownership and transfers the
zeroization obligation to the caller; other buffers sharing its pages retain
their locks.

Without an explicit memory budget, non-Linux hosts report
`platform = "unsupported-platform"` and a warning; hardening is not enforced.
An explicit memory budget requires Linux and refuses attach elsewhere.

### Measured memory budget

An optional `[security.memory_budget]` makes attach conditional on the actual
Linux cgroup-v2 and memlock policy. All three fields are required. Values below
illustrate the syntax; select them from measurements of the deployment's
recovery, I/O, checkpoint and provider-stall peaks:

```toml
[security.memory_budget]
max_bytes = "256MiB"
startup_headroom_bytes = "16MiB"
required_memlock_bytes = "32MiB"
```

`max_bytes` must be positive and exactly match the service cgroup's finite
`memory.max`. Headroom must be positive and less than that ceiling. The daemon
requires at least that much remaining charged memory in the leaf and every
visible finite ancestor, before hardening/recovery and again before returning
the recovered engine. A smaller ancestor ceiling is rejected because it changes
the configured envelope. Missing, malformed, unreadable or unlimited leaf
limits fail attach. Ancestors may be unlimited; the real hierarchy root has no
`memory.max`. Paths come from `/proc/self/cgroup` and `/proc/self/mountinfo`,
including mountinfo escaping. Other mounts are compared with the cgroup-v2 mount
by their exact path bytes, so one elsewhere whose path is not UTF-8, contains a
newline or is deeply nested does not affect admission. Records are split by the
kernel's field layout, so a mount whose source is empty (printed as an empty
field) is read like any other. The table is read as a stream, so the number of
mounts does not limit admission; one record longer than 1 MiB is refused.
Admission reads the table again after the controller files and refuses when its
SHA-256 digest changed. Ambiguous mounts, subtree
mounts hiding ancestors, root membership, nested mounts shadowing controller
files and escaping paths are refused. Run under the host cgroup
namespace with the complete hierarchy visible; a container can hide further
ancestors, and visibility is not a proof of their headroom.

The actual soft `RLIMIT_MEMLOCK` must cover `required_memlock_bytes`. Use a
positive requirement for `secure-buffers`; `all` requires at least `max_bytes`,
and `off` requires zero. This admission check does not turn best-effort per-buffer
locking into guaranteed success: mapping/page overhead, privileges and subsequent
allocations can still cause failures. `mlockall` still must succeed in `all` mode,
and its virtual-address-space accounting can require more than the cgroup cap.

Set matching systemd limits with the
[opt-in drop-in template](../packaging/examples/maki@.service.d/20-memory-budget.conf).
Replace its placeholders before installation. The application reads kernel
state; it never changes cgroups or resource limits for this policy. Existing
configurations omit the section and retain their current behavior. On unsupported
platforms an explicit budget refuses attach. `maki status` reports the observed
limits and admission snapshot under `security.memory_budget`.

`MemoryMax` bounds cgroup-charged memory (including charged file cache and
descendants), not literal process RSS. Headroom is a startup snapshot, not a
reservation or a promise against OOM. Keep service membership and limits fixed
while attached; kernel enforcement continues after admission. Choose swap policy
separately. See the [measurement procedure](performance.md#establish-a-memory-and-capacity-envelope).

## Capacity and limits

`volume.max_virtual_size`, `crypto_unit_size`, provider ciphertext bounds, slot
alignment, and NBD block sizes jointly define immutable volume geometry. Treat
geometry or on-disk format changes as migrations, not hot reloads. Attach
compares configured device block size, crypto unit size, shard logical size,
slot alignment, maximum ciphertext size and virtual size with the recovered
superblock before provider initialization. A mismatch refuses readiness with
the field and both values, and `maki check` reports every such mismatch.
Advertised NBD minimum I/O must also be a multiple
of, and at least as large as, the stored device block size. Mutable request and
resource limits remain independently validated operational settings.

`maki volume inspect` reports maximum units and shards, the full slot-file span,
and the A/B allocation-map and catalog bytes calculated from that geometry. For
the 16 TiB example with 4 KiB units, 4384-byte maximum ciphertext, 4608-byte
slots and 64 GiB shards, the full slot span is 18 TiB. Its allocation maps use
1,073,758,208 bytes across both copies at full allocation; the two full catalog
copies use 4,152 bytes. The last partial logical shard still contributes a full
shard file because shard files are created at their complete fixed length.

Every shard in the catalog keeps one open file descriptor while the volume is
attached. The daemon, `maki` and `maki-check` raise their soft
`RLIMIT_NOFILE` to the hard limit (at most 2^20) before opening a volume;
systemd's default hard limit of 524288 is far above any practical shard count.
A lower hard limit (`LimitNOFILE=`) must leave room for the shards plus the
journal and connections, or attach fails with `Too many open files`. That error
names no damage: raise the limit and attach again.

These values describe format files at maximum allocation. Add journal and
checkpoint headroom, filesystem allocation and metadata overhead,
copy-on-write behavior, and database temporary space when sizing the backing
filesystem. Sparse file lengths do not reserve those blocks. Geometry
validation rejects a possible shard count above the catalog limit and any
maximum-layout byte calculation that overflows `u64`.

Set request-count and byte limits together. In particular, size global and
per-endpoint concurrency below the memory and provider capacity available to a
single volume. The cache can be resized at runtime; provider identity, backing
root, geometry, and journal layout cannot.

## Validate before use

Use a disposable backing root while reviewing a new configuration:

```bash
cargo run --locked -p maki -- volume create path/to/config.toml
cargo run --locked -p maki -- volume inspect path/to/config.toml
cargo run --locked -p maki -- check path/to/config.toml
```

Creating a volume writes metadata to the configured backing root. Do not point
an unreviewed configuration at an existing volume. Each command reads the file
under the [configuration file](#configuration-file) rules.

## Privileged attachment identity

The root-owned `/etc/maki/attach/<volume>.toml` is separate from the data-plane
volume configuration. Its template is
[`packaging/examples/attach.toml`](../packaging/examples/attach.toml). A
production attachment must pin the filesystem UUID and the LVM identity:

```toml
fs_uuid = "11111111-2222-3333-4444-555555555555"

[lvm_identity]
pv_uuids = ["111111-2222-3333-4444-5555-6666-777777"]
vg_uuid = "aaaaaa-bbbb-cccc-dddd-eeee-ffff-gggggg"
lv_uuid = "hhhhhh-iiii-jjjj-kkkk-llll-mmmm-nnnnnn"
```

When `[lvm_identity]` is present, all three fields are required. `pv_uuids`
must list the complete PV set without duplicates; its order is normalized.
Attach refuses a missing, additional, malformed or changed PV, VG or configured
target-LV UUID before activation. The pins are stored in the trusted attachment
record. Recovery does not read LVM metadata again: it checks the identity
attach persisted before activation against them, and the live mappings against
that identity or the post-activation mapping proof. Grow and detach also
require the current configuration, including the pins, to match that record
before any mutation.

Omitting the table remains accepted for old configurations and records, but
does not authenticate the discovered LVM metadata against an administrator's
expected identity. Do not use that compatibility mode for the production
profile. Obtain the identifiers from a separately verified host inventory; the
helper never learns or rewrites them.
