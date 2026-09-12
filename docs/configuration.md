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
| `crypto.websocket` | WebSocket endpoints, timeout, and frame-size limit |
| `crypto.grpc` | gRPC endpoints, method paths, metadata, and message-size limit |
| `limits` | Request, byte, queue, batch, and endpoint concurrency bounds |
| `backing` | Backing root, slot alignment, journal sizing, and reserves |
| `cache` | Read-cache mode, size, TTL, locking, and zeroization |
| `nbd` | Socket, negotiated I/O geometry, and Tokio runtime worker count |
| `control` | Administrative socket and group |
| `security` | Core-dump, memory-lock, and secure-swap policy |

Byte sizes use values such as `4096`, `256KiB`, `64MiB`, or `16TiB`.
Durations use values such as `150us`, `50ms`, `5s`, or `30s`.

## Providers

| `crypto.provider` | Transport | Integrity | TLS status |
|---|---|---|---|
| `local-aes-gcm-siv` | Local | Authenticated and context-bound | Not applicable |
| `local-aes-xts` | Local | No authenticated integrity | Not applicable |
| `remote-http` | HTTP | Declared by provider contract | HTTPS, custom CA, and mTLS supported |
| `remote-websocket` | WebSocket | Declared by provider contract | `wss://` currently rejected |
| `remote-grpc` | gRPC | Declared by provider contract | TLS endpoints currently rejected |
| `fake` | In-process test provider | Test-only | Refused unless built with `--features fake-provider` |

The `fake` provider is not compiled into a default build; `maki volume create`
and attach reject it at validation time. Enable the `fake-provider` feature of
`maki-nbdkit` only for development and benchmark builds.

WebSocket and gRPC fail closed when TLS is configured. Use `remote-http` when a
remote production deployment requires TLS until those transports gain rustls
support.

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

`validate()` runs before a volume is created and before every attach. Beyond
schema, geometry, and secret-literal checks it rejects:

- any zero count or byte limit under `[limits]`, `[crypto.batch]`,
  `[crypto.circuit_breaker]`, and `[crypto.retry_budget]`, a non-finite or
  negative `retry_ratio`, a `minimum_probe_rate` outside `(0, 1000]/s`, an
  `initial_delay` above `max_delay`, an `open_initial` above `open_max`, batch
  targets above their maxima, or a batch byte limit smaller than one crypto
  unit;
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
  above 64 KiB, a `maximum_io` that does not fit in the NBD 32-bit wire
  field, or a `limits.max_plaintext_bytes` smaller than `nbd.maximum_io`
  plus one crypto unit (the admission budget must hold one maximal request;
  a request is charged every unit it touches, in full);
- a `cache.mode = "read"` with a zero size or TTL, and empty `control` values;
- missing or foreign provider sections: local providers need `[crypto].key` and
  must not carry transport sections; `remote-http` needs `[crypto.http]` with at
  least one endpoint and both `encrypt` and `decrypt` mappings; `remote-websocket`
  and `remote-grpc` need their section with at least one endpoint;
- endpoint URLs without a scheme or host, with userinfo, with duplicate or empty
  names, or with a scheme the transport does not speak;
- **plaintext transports to non-loopback hosts**: `http://`, `ws://`, and gRPC
  `http://` endpoints are accepted only for `localhost`, `127.0.0.0/8`, and
  `::1`. Block data must not cross the network unencrypted; use `https://` or a
  local tunnel. `wss://`, gRPC `https://`, and `[crypto.websocket.tls]` /
  `[crypto.grpc.tls]` are refused because those transports have no TLS support
  in this build;
- HTTP batch layouts (`body.items_path`) whose response mapping lacks
  `items_path` or `item_index_path`: every batch element must echo its unit
  index so reordered, dropped, or duplicated results are detected;
- TLS material that does not exist or cannot be read, `client_key` without
  `client_cert_file`, and `server_name` (unsupported: put the certificate's name
  in the endpoint URL);
- the `keyring` credential source, which this build does not implement, and
  the same credential name declared with different sources.

The HTTP provider additionally refuses to start when a CA or client certificate
file cannot be read or parsed, and reads `client_key` from its credential source
to complete the client identity.

## Compatibility identity

`crypto_compatibility_id` identifies the cryptographic profile rather than a
network endpoint. Every endpoint in a failover set must decrypt ciphertext from
every other endpoint. Changing keys, algorithms, nonce layout, context binding,
or payload encoding without a compatible migration requires a new identity and
must not attach to an existing volume.

Maki stores the provider type, compatibility identity, and key name in the
superblock and refuses attach when the configuration disagrees. The provider
self-test verifies supported unit sizes, ciphertext bounds, response ordering,
round trips, and integrity claims; the key canary (see
[Operations](operations.md#key-binding-at-first-attach)) then proves that the
key material itself matches, which the self-test alone cannot.

## Credentials and secrets

Sensitive values must be credential references. Literal authorization headers,
API keys, tokens, and similar fields are rejected during validation. Production
deployments should use systemd credentials; environment-backed credentials are
intended for development.

The data-plane service receives credentials through `LoadCredential`. The
privileged attach helper has no crypto dependency and no credential directive.

Every credential reference is loaded from exactly the `source` it declares:
`credential` reads `$CREDENTIALS_DIRECTORY/<name>` and fails closed when the
directory is unset, `file` reads the named file, `env` reads
`MAKI_CREDENTIAL_<NAME>`. There is no fallback between sources, so a production
daemon cannot attach on a stray environment variable.
Within one volume configuration, references may reuse a name only when they
declare the same source. For example, `name = "token"` in both the encrypt and
decrypt mappings is valid with `source = "credential"` on both. Combining that
name with `source = "env"` is rejected during validation and provider
construction; use distinct names for distinct sources.
Do not place plaintext keys or bearer tokens in TOML, command lines, logs, or
operation plans.

## Remote HTTP mapping

The HTTP provider maps logical fields into a vendor request without interpreting
the vendor cipher. Supported mappings include raw single-item payloads and JSON
objects containing payload, unit index, volume ID, compatibility ID, or batch
index. Binary data may use base64, base64url, or hexadecimal encoding.

Responses can be single-item or batched. If an item index is returned, Maki
validates it; missing, duplicate, reordered, oversized, or partial responses are
provider contract errors. Response bodies are read under a hard size limit.
Transport error messages omit the request URL, including its query values,
for connection failures, timeouts, and response-body failures.

## WebSocket and gRPC contracts

WebSocket uses one JSON request per text frame with a correlation ID. Unknown or
stale response IDs are discarded, pending requests are scoped to a connection
generation, and both inbound and outbound frame sizes are bounded. Each
response item must carry the `unit` of the request item it answers, in request
order; a missing, reordered, or mislabelled item is a contract error.
Timeout or cancellation retires the connection generation and releases its
socket and reader/writer task. Reconnection uses a new generation; cleanup of
the retired one cannot close it or fail its requests. Dropping the provider
also closes an otherwise idle connection.

Providers that do not declare `retry_safe` are sent every request at most
once: the dispatcher performs no retry or failover after a request has been
sent, and the WebSocket transport does not resend over a fresh connection. With
`availability_policy = "bounded-error"`, `max_operation_time` is an absolute
wall-clock deadline: backoff never sleeps past it and an expired caller receives
an error. A shared RPC remains active while it still has a live caller.
Endpoints that could not be cross-validated at attach
(unreachable at the time) are quarantined and start serving only after the
cross-endpoint check succeeds against a validated endpoint.
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
Service method paths are configurable, but request and response messages must
match that contract and responses must preserve unit identity and order.

## Backing directory identity

On Linux, `backing.root` and its ancestors must be real directories; symlink
aliases are refused. The backing pins the selected directory with an open
descriptor. Subsequent file, lock, rename, removal, listing, directory sync,
and free-space operations resolve through directory descriptors without
following symlinks. Renaming the root and replacing its old pathname cannot
redirect an existing backing instance to another volume.

Keep the backing tree writable only by its owner. Descriptor confinement does
not authenticate file contents or prevent a process with direct write access
from altering the volume. Other development platforms retain pathname-based
checks; this Linux confinement guarantee does not apply to them.

## NBD request limits

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
nbdkit's block-size callback. The adapter also rejects read/write requests with
zero length, invalid minimum-size alignment, an out-of-range end, or a length
above `maximum_io` with EINVAL, before copying write plaintext or entering the
engine. Clients that ignore negotiation therefore cannot bypass the bound used
to validate journal headroom. `preferred_io` remains a performance hint.

This negotiation path was verified with the installed nbdkit header and a real
rootless nbdkit/libnbd connection. Older clients can still connect, but requests
outside the configured constraints fail cleanly.

## Journal bounds

| Setting | Enforced as |
|---|---|
| `backing.journal_segment_size` | Size at which the journal writer starts a new segment (at least 4096 bytes) |
| `backing.journal_max_bytes` | Hard limit on journal bytes on disk (at least twice the segment size). The worker checkpoints at half of it; a write that would exceed it checkpoints inline and fails with ENOSPC if space cannot be reclaimed |
| `backing.journal_emergency_reserve_bytes` | Writes fail with ENOSPC unless fresh free space covers this reserve plus the projected record and segment-header footprint of the write |
| `backing.checkpoint_reserve_bytes` | The worker checkpoints eagerly while backing free space is below it |
| `limits.max_journal_pending_bytes` | Appended-but-unsynced journal bytes; the write path forces a journal sync before exceeding it |

Free space is read with `statvfs` on Unix hosts. When the emergency reserve is
enabled, an unavailable or failed query fails write admission with ENOSPC;
`maki_backing_free_bytes` is null until a usable observation is available.

When the emergency reserve is enabled, every write admission refreshes free
space while holding the volume write lock. It requires enough space for the
configured reserve after all record bytes and segment headers created by that
request. It does not reuse the statistics cache, so space lost or restored
between consecutive writes is observed even within the same second. Status and
metrics still read cached observations; they never initiate this filesystem
query.

These thresholds are not physical reservations. The journal limit counts
record bytes and segment headers, while checkpointing must also write slots,
allocation maps and metadata before reclaiming the old journal. Sparse shard
file lengths do not reserve disk blocks. Filesystem allocation units, metadata,
copy-on-write and other filesystem users can consume space after the query;
a successful admission does not guarantee that the write or checkpoint will
complete without ENOSPC. Include those costs and DB temporary storage in
capacity qualification instead of equating exported virtual size with backing
space.

## Batching and pending bounds

Remote providers are called through a batch scheduler (SPEC §30). Concurrent
requests are coalesced into one provider call when their items fit
`crypto.batch.max_items` / `max_bytes`; a batch is dispatched as soon as
`target_items` or `target_bytes` is reached, and at the latest `max_wait`
after its first item arrived. A request's items are never split and keep
their order. Each lane keeps up to `limits.max_crypto_inflight_batches`
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
| `memory_lock_mode = "secure-buffers"` (default) | Attempts to `mlock` registered `SecretBuffer` allocations (including plaintext, keys and cache entries); shared pages stay locked until their last buffer owner releases them, and failures are counted and reported. Separate transport allocations are described in [buffer lifetime limits](transport-memory.md) |
| `memory_lock_mode = "all"` | `mlockall(MCL_CURRENT \| MCL_FUTURE)`; a failure refuses attach (raise `LimitMEMLOCK`) |
| `memory_lock_mode = "off"` | No locking; validation then refuses `cache.lock_memory = true` |
| `require_secure_swap_policy` (default false) | Requires readable, parseable `/proc/swaps` and accepts only RAM-only zram or dm-crypt with proven independent physical backing, including zram writeback. NBD ancestors, cycles, and unknown backing are refused. Device identity determines classification; keep the topology fixed while attached. See [swap dependency checks](operations.md#swap-dependency-checks). The shipped production example enables this policy |

Buffers are zeroized before their page-lock ownership is released. Exporting a
buffer as a plain vector releases that buffer's ownership and transfers the
zeroization obligation to the caller; other buffers sharing its pages retain
their locks.

On non-Linux hosts nothing is enforced; the status document reports
`platform = "unsupported-platform"` and a warning is logged.

## Capacity and limits

`volume.max_virtual_size`, `crypto_unit_size`, provider ciphertext bounds, slot
alignment, and NBD block sizes jointly define immutable volume geometry. Treat
geometry or on-disk format changes as migrations, not hot reloads.

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
an unreviewed configuration at an existing volume.
