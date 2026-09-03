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
| `nbd` | Socket and negotiated I/O geometry |
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

## WebSocket and gRPC contracts

WebSocket uses one JSON request per text frame with a correlation ID. Unknown or
stale response IDs are discarded, pending requests are scoped to a connection
generation, and both inbound and outbound frame sizes are bounded.

The gRPC transport uses the message shape in
[`packaging/examples/maki-crypto.proto`](../packaging/examples/maki-crypto.proto).
Service method paths are configurable, but request and response messages must
match that contract and responses must preserve unit identity and order.

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
