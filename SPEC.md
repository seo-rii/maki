# Maki Technical Specification

**Document Version:** 0.4 Draft
**Project Name:** `maki`
**Primary Implementation Language:** Rust
**Block Server:** nbdkit
**Recommended Filesystem:** XFS
**Volume Management:** LVM
**Development Methodology:** Test-Driven Development (TDD)
**Target Workloads:** SQLite, PostgreSQL, ClickHouse, MinIO, and Docker bind mounts

---

# 1. Overview

Maki is a general-purpose encrypted storage layer that exposes a standard Linux block device while ensuring that data stored in the backing storage remains encrypted.

The encryption algorithm is not fixed.

Supported provider classes include:

```text
Local Crypto
├── AES-256-GCM-SIV
└── AES-256-XTS

Remote Crypto
├── HTTP/HTTPS
├── WebSocket/WSS
└── gRPC
```

For remote cryptographic providers, Maki does not need to understand the underlying encryption algorithm.

However, Maki MUST know the storage-related contract of the provider, including:

```text
crypto unit size
maximum ciphertext size
statelessness
retry safety
batch capability
integrity capability
context-binding capability
crypto compatibility identity
```

---

# 2. High-Level Architecture

```text
Application / Database / Docker
                 │
                 ▼
                XFS
                 │
                LVM
                 │
             /dev/nbdN
                 │
          Linux NBD Client
                 │
        Unix Domain Socket
                 │
               nbdkit
                 │
           maki-nbdkit.so
                 │
┌────────────────▼─────────────────┐
│             maki-core            │
│                                  │
│  block mapping                   │
│  per-unit synchronization        │
│  allocation metadata             │
│  ciphertext journal              │
│  checkpoint / recovery           │
│  versioned plaintext LRU         │
│  FLUSH / FUA barriers            │
│  bounded queues                  │
│  byte/count semaphores           │
│  crypto batching                 │
│  retry / backoff                 │
│  retry budget                    │
│  circuit breaker                 │
│  endpoint failover               │
└────────────────┬─────────────────┘
                 │
          CryptoProvider
                 │
       Local or Remote Crypto
```

---

# 3. Daemon Architecture

Maki uses **one long-running daemon per volume** as the default deployment model.

Examples:

```text
maki@postgres.service
maki@clickhouse.service
maki@minio.service
```

Each daemon owns independent state for its volume, including:

```text
journal
checkpoint state
LRU cache
retry state
circuit breaker state
connection pool
metrics
crypto credentials
backing files
```

A failure in one volume MUST NOT directly propagate into another volume daemon.

---

# 4. Privilege Model

Long-running Maki data-plane processes MUST NOT run as root.

The recommended architecture is:

```text
systemd
│
├── maki@postgres.service
│      │
│      └── nbdkit --foreground
│             │
│             └── maki-nbdkit.so
│
│         UID=maki
│         GID=maki
│         no Linux capabilities
│
└── maki-attach@postgres.service
       │
       ├── NBD attach/detach
       ├── LVM activation
       ├── mount/umount
       └── XFS/LVM growth

          privileged one-shot helper
```

---

# 5. Data-Plane Daemon Privileges

The target privilege set for the `maki` daemon is:

```text
UID = maki
GID = maki

CAP_SYS_ADMIN      none
CAP_SYS_RAWIO      none
CAP_NET_ADMIN      none
CAP_DAC_OVERRIDE   none
CAP_SYS_PTRACE     none
```

Whenever possible, the systemd unit SHOULD use:

```text
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=yes
```

The daemon MUST be able to:

```text
read and write its own volume backing files
read and write its own journal
use its own runtime directory
connect to the crypto service
read its assigned credentials
expose metrics/control sockets
lock designated memory
```

The daemon MUST NOT be able to:

```text
mount filesystems
unmount filesystems
modify LVM
manage /dev/nbd* directly
access another volume's backing files
modify arbitrary host filesystem locations
load kernel modules
```

---

# 6. Privileged Helper

Privileged operations are delegated to a small separate helper.

Binary:

```text
maki-attach
```

Responsibilities:

```text
allocate an NBD device
connect the NBD device to the Unix socket
configure device block size
verify NBD candidates and complete LVM membership
activate the discovered VG UUID within the verified NBD device list
mount XFS
verify mount identity
grow LVM
run xfs_growfs
detach the NBD device
```

The helper MUST NOT handle:

```text
plaintext blocks
ciphertext payloads
crypto authentication tokens
TLS private keys
local encryption keys
LRU contents
crypto request bodies
```

The privileged helper is therefore strictly a **storage connection and control-plane component**.

`maki-attach verify` supplies a repeatable read-only workload-start check using
existing trusted state and root-controlled configuration. Both volume and XFS
UUIDs must be pinned. It checks the connected backend, complete persisted
mapping proof, whole read/write XFS mount without nested mounts, and volume
sentinel; potentially blocking reads are followed by fresh identity checks.
It does not create state or write-probe files, repair storage, start a DB, or certify
another mount namespace. A successful `--plan` is only a preview. See
[the verification contract](docs/storage-recovery.md#checking-storage-before-each-workload-start)
for privilege, deadline and lifecycle limits.

---

# 7. Control Plane

Administrative CLI:

```text
maki volume create
maki volume inspect

maki attach
maki detach

maki status
maki metrics

maki checkpoint
maki drain

maki reload
maki check

maki grow
```

`maki checkpoint` and `maki drain` are control-socket commands: `checkpoint`
requests a graceful checkpoint, and `drain` closes I/O admission, waits for
the requests in progress, then flushes and checkpoints. `maki attach`,
`maki detach` and `maki grow` do not perform the operation: `maki` prints the
`maki-attach` command to run (the same verb and arguments) on standard error
and exits with status 3. The operation runs only when the operator runs that
privileged helper (§6).

Normal status and runtime configuration operations are performed over the daemon control socket:

```text
/run/maki-control/<volume>/control.sock
```

Recommended ownership:

```text
owner = maki
group = maki-admin
mode = 0660
```

The control socket MAY allow:

```text
status
metrics snapshot
endpoint reload
credential reload
cache resize
retry/backpressure configuration reload
graceful checkpoint
drain (close I/O admission, then flush and checkpoint)
```

The following operations MUST require the privileged helper:

```text
attach
detach
mount
umount
LVM grow
XFS grow
NBD device management
```

---

# 8. Filesystem and Directory Permissions

Recommended layout:

```text
/etc/maki/
├── volumes/
│   ├── postgres.toml
│   └── minio.toml
└── policy/

/var/lib/maki/
├── postgres/
└── minio/

/run/maki/
├── postgres/
└── minio/

/run/maki-control/
├── postgres/
└── minio/

/run/maki-attach/
├── attach.lock
├── postgres.nbd
└── minio.nbd
```

Recommended ownership and permissions (the volume configuration rule below
is enforced):

```text
/etc/maki
root:maki                 0750

/etc/maki/volumes/*.toml
root:maki                 0640

/var/lib/maki
root:maki                 0750

/var/lib/maki/<volume>
maki:maki                 0700

data/journal/metadata files
maki:maki                 0600

/run/maki
root:maki                 0750

/run/maki-control
root:maki-admin           0750

/run/maki/<volume> and /run/maki-control/<volume>
maki:maki                 0711

/run/maki-attach
root:root                 0700

/run/maki-attach/*
root:root                 0600
```

A volume configuration decides where plaintext goes: the provider and its
endpoints, TLS trust, credential references, the backing root and the rollback
witness. Every loader (the data-plane daemon, `maki` and `maki-benchmark`)
MUST open it without following a final symlink and MUST refuse, before parsing
it, anything but a regular file of at most 1 MiB with exactly one link, owned
by root or by the user the loading process runs as, with no group or other
write permission. The checks MUST describe the opened descriptor that is then
read. Group and other read MAY be granted: a configuration holds credential
references, never secrets (§9). The recommended `root:maki 0640` is accepted
by root and by the daemon user, which reads it through its group; a file owned
by the daemon user is refused by commands run as root. The directory holding
it SHOULD be root-owned and not writable by others. This is the witness
configuration's owner and mode rule plus the single link; secret files (§9)
have the same owner rule and a stricter mode rule. Non-Unix hosts check only
that it is a regular file of at most 1 MiB.

The NBD Unix Domain Socket:

```text
/run/maki/<volume>/nbd.sock
```

MUST be created behind a restrictive runtime ancestor.
Administrative control access MUST NOT grant access to the NBD socket.

An administrative command run as root on a volume the daemon user owns (an
offline check or inspect, a creation into existing directories, a remote
takeover, restore or enrollment recovery) MUST create each file and
directory it adds below the backing root or in a local witness directory for
the owner of the directory it is created in, when that owner is not root, so
that it never leaves an entry the daemon cannot open. It MUST open an entry
that already exists as it is, MUST NOT give away an entry another user owns,
MUST give a new file its owner before writing to it, and MUST refuse rather
than keep an entry it cannot give away. A directory cannot be created
unnamed, so once the command has created one it MUST give away only an empty
root-owned directory under that name; whichever root process made that
directory, it holds nothing. A local witness publication MUST instead remove
a temporary record left from before, and MUST NOT publish a file under that
name that a user other than root or the record's owner owns, as that user
may still hold it open for writing. The backing root itself, when such a
command creates it, belongs to the user that runs the command. A crash
between creating an entry and giving it away (a directory, or a file on a
filesystem without unnamed files) leaves it root's, and later runs open it
as it is; like a backing root the command created, it needs a hand-back.

Privileged attachment state MUST be opened through root-controlled directory
descriptors without following symlinks. Detach MUST verify its requested
volume UUID, socket, mountpoint, VG, LV, and device against a trusted record
before executing any step. The record's unique connection identifier MUST
match the live NBD backend before detach and immediately before disconnect,
including rollback. A missing or invalid record MUST fail closed, even when
the caller supplies an explicit NBD device.

A trusted record reserves the NBD device it names for its volume, connected
or not, until one of that volume's own operations replaces or retires the
record. Under the attach lock, attach MUST read every record before it
chooses or connects a device, MUST NOT allocate or connect a device that
another volume's record names, and MUST refuse while a record cannot be read.

A record whose device is connected under an identity other than the recorded
one MUST be kept, and every verb of its volume MUST refuse without a command,
unless observation under the attach lock proves that nothing of the recorded
attachment remains: the record names its VG UUID (mapping proof, activation
intent or administrator pins); no device-mapper device on the host belongs to
that VG; every holder of the device and of its partitions is an LVM mapping
of another VG (a device-mapper uuid of `LVM-` and another VG UUID), not any
other device-mapper or block device; nothing is mounted at the recorded
mountpoint and no mount is of a mapping of that VG; no other volume's record
names the device with the same VG UUID or with none; and the device's backend
stays the same across the observation. Every such observation MUST be
readable. Attach, cleanup, recover and detach MAY then retire the record
without any command and without touching the device or its connection; grow
MUST refuse.

A detach retry MAY skip a step whose completion is verified from current mount
and block-device observations. Destructive steps still require matching live
identity. If every detach step has already completed, the helper MAY retire
the trusted record without device commands only after verifying mount absence,
inactive VG mappings, and no remaining NBD or partition use.

---

# 9. Credential Management

Secrets MUST NOT be stored directly in ordinary TOML configuration.

Forbidden:

```toml
token = "actual-secret"
key = "012345..."
```

Recommended:

```toml
Authorization = {
    source = "credential",
    name = "crypto-token"
}
```

Example systemd configuration:

```ini
LoadCredential=crypto-token:/secure/path/token
```

Supported credential sources, named by a reference's `source`:

```text
credential   systemd credentials ($CREDENTIALS_DIRECTORY/<name>)
file         secret file at an absolute path
env          environment variable MAKI_CREDENTIAL_<NAME> (development)
```

Each reference is loaded from exactly the source it declares, through one
key-source abstraction, with no fallback between sources. A secret file MUST
be a regular file, opened without following a symlink, owned by root or by
the user the loading process runs as, with no group or other access (for
example `0600` or `0400`): its owner can read or replace it whatever its
mode. A systemd credential follows the same rule, except that it MAY also
grant read, and only read, to its group when that group is the process's own
or root, as systemd 257 writes `LoadCredential=` files (`0440`). The kernel
keyring is not implemented; configuration validation rejects a `keyring`
source.

Environment variables MAY be used in development environments but SHOULD NOT be the primary production secret source.

---

# 10. systemd Data-Plane Unit

Conceptual example:

```ini
[Unit]
Description=Maki encrypted volume %i
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
NotifyAccess=main
TimeoutStartSec=180

User=maki
Group=maki

ExecStart=/usr/bin/nbdkit \
    --foreground \
    -U /run/maki/%i/nbd.sock \
    /usr/lib/maki/maki-nbdkit.so \
    config=/etc/maki/volumes/%i.toml

Restart=on-failure
RestartSec=2

NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=

LimitCORE=0
LimitMEMLOCK=512M

ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

RuntimeDirectory=maki/%i maki-control/%i
RuntimeDirectoryMode=0711
ReadWritePaths=/var/lib/maki/%i
ReadWritePaths=/run/maki/%i
ReadWritePaths=/run/maki-control/%i
```

The exact sandbox options MUST be finalized after compatibility testing with nbdkit and all required shared libraries.

The native plugin initializes its adapter in `after_fork`, so recovery,
configured provider validation, and control socket binding precede the first
NBD client. It sends `READY=1` from nbdkit's main process only after those
steps succeed. Initialization or configured notification failure fails startup.
Manual runs without `NOTIFY_SOCKET` perform the same initialization without
notifying a service manager. The startup timeout needs qualification for the
deployment's recovery size and provider latency.

Initial data-plane readiness is separate from the helper's verified XFS mount,
the fresh `maki-attach verify` workload gate, and database recovery. It does not
provide continuous health monitoring or container reattachment.

---

# 11. Project Layout

```text
maki/
├── crates/
│   ├── maki-core/
│   │   ├── engine
│   │   ├── volume
│   │   ├── journal
│   │   ├── overlay
│   │   ├── store
│   │   ├── recovery
│   │   └── check
│   │
│   ├── maki-format/
│   │   ├── superblock
│   │   ├── slot
│   │   ├── journal
│   │   ├── allocation
│   │   ├── catalog
│   │   ├── checkpoint
│   │   ├── durable_proof
│   │   ├── canary
│   │   ├── ab
│   │   ├── codec
│   │   ├── geometry
│   │   └── config
│   │
│   ├── maki-crypto/
│   │   ├── provider
│   │   ├── checked
│   │   ├── selftest
│   │   ├── scheduler
│   │   ├── endpoint
│   │   ├── retry
│   │   ├── breaker
│   │   ├── flow
│   │   └── secret
│   │
│   ├── maki-crypto-local/
│   ├── maki-crypto-http/
│   ├── maki-crypto-websocket/
│   ├── maki-crypto-grpc/
│   ├── maki-backing/
│   ├── maki-cache/
│   ├── maki-nbdkit/
│   ├── maki-control/
│   ├── maki-privileged/
│   ├── maki-witness/
│   └── maki-test-support/
│
├── bins/
│   ├── maki
│   ├── maki-attach
│   ├── maki-check
│   ├── maki-benchmark
│   └── maki-witness
│
└── packaging/
    ├── systemd/
    ├── tmpfiles.d/
    ├── sysusers.d/
    ├── debian/
    └── examples/
```

The entries under `maki-core`, `maki-format` and `maki-crypto` are those
crates' principal source modules (`src/<name>.rs`), not directories.

---

# 12. Core MUST Requirements

Maki MUST satisfy the following:

```text
plaintext is never persisted in backing storage

plaintext is never persisted in the journal

all internal queues are bounded

all major queues also have byte limits

writes acknowledged before FLUSH success are durable

FUA-successful writes are durable

checkpointing only consumes durable journal records

crypto profile mismatch prevents attach

the same volume cannot be attached twice simultaneously

remote provider failure never triggers fallback to another algorithm

corrupted encrypted data is never returned as plaintext

database containers cannot start without the expected secure mount
```

---

# 13. Device Geometry

Block-related concepts are separated.

| Setting               | Meaning                       |           Default |
| --------------------- | ----------------------------- | ----------------: |
| `device_block_size`   | Linux NBD device block size   |              4096 |
| `nbd_minimum_io`      | minimum request alignment     |              4096 |
| `nbd_preferred_io`    | preferred I/O size            |       crypto unit |
| `nbd_maximum_io`      | maximum callback request size |             1 MiB |
| `crypto_unit_size`    | independent encryption unit   |              4096 |
| `max_ciphertext_size` | maximum ciphertext per unit   | provider contract |
| `slot_alignment`      | backing slot alignment        |               512 |
| `slot_size`           | physical slot size            |        calculated |

The plugin MUST advertise the configured minimum, preferred, and maximum NBD
I/O sizes. The minimum MUST be at most 64 KiB, the preferred size at most
32 MiB (the largest nbdkit accepts), and the maximum MUST fit in the 32-bit NBD
field. Both configured and stored export sizes MUST be multiples
of the effective minimum I/O size; validation MUST refuse an inaccessible
tail before creation or export. Read and write callbacks MUST reject zero-length,
out-of-range, or minimum-misaligned requests before copying write plaintext or
submitting engine work. Clients may ignore the advertised maximum (the Linux
NBD driver does), so a longer read or write MUST be served in chunks of at
most the maximum, each copied and submitted separately, with FUA on the last.
The preferred size is a performance hint.

Recommended:

```text
device_block_size = 4096
crypto_unit_size = 4096
```

---

# 14. Ciphertext Slot

Variable-length ciphertext is stored in fixed-size physical slots.

```text
slot_size =
align_up(
    slot_header_size + max_ciphertext_size,
    slot_alignment
)
```

Example:

```text
Slot header           64
Max ciphertext      4384
------------------------
                     4448

Alignment             512

Slot size            4608
```

A slot holds a 64-byte header followed by the unit's ciphertext; the rest of
the slot is not read. Slot `i` of a shard holds unit
`shard_index * units_per_shard + i` of the volume and starts at byte
`i * slot_size` of `data/shard-<index>.dat`, where `<index>` is the shard
index as eight lowercase hexadecimal digits. The header (record notation in
§21):

```text
magic[8] = MAKISLT1
unit_index u64          the unit's index in the volume, not in the shard
write_sequence u64      journal sequence of the write the slot holds; never 0
ciphertext_len u32      at most max_ciphertext_size
flags u32 = 0
ciphertext_crc u32      CRC-32 of the ciphertext
reserved[24] = 0
crc32
```

The header has no version field: its magic, which ends in the format version
`1`, is its only format identifier, and a header with another magic does not
decode. Writers set `flags` and the reserved bytes to zero, and readers do not
interpret them.

Maximum fully allocated layout sizes are calculated from the immutable
geometry with checked arithmetic:

```text
num_units              = max_virtual_size / crypto_unit_size
units_per_shard         = shard_logical_size / crypto_unit_size
num_shards              = ceil(num_units / units_per_shard)
full_slot_span_bytes    = num_shards * units_per_shard * slot_size
allocation_map_ab_bytes = num_shards * 2 * (32 + ceil(units_per_shard / 8))
catalog_ab_bytes        = 2 * (28 + 8 * num_shards)
```

Geometry creation MUST reject more than 2^24 possible shards, matching the
supported shard-catalog limit, any capacity calculation that overflows an
unsigned 64-bit byte count, and a unit count that reaches the reserved
key-canary unit index (§27), which attach refuses. `maki volume inspect`
reports the five maximum-layout values above (all but `units_per_shard`) and
a sixth, the discard-map A/B bytes, which equal `allocation_map_ab_bytes` for
a v3 volume and are zero for v2. They exclude journal and checkpoint
headroom, filesystem metadata and copy-on-write overhead, and application
temporary space; they are not a full-volume physical reservation. Before
accepting a journal record, a Linux backing MUST physically allocate the exact
journal range and the record's complete checkpoint slot. Both allocation-map
copies and the catalog entry of a newly touched shard MUST already be durable.
A failed reservation MUST NOT consume a sequence or append the record.
Untouched slots MAY remain sparse.

---

# 15. CryptoProvider Interface

```rust
trait CryptoProvider: Send + Sync {
    async fn capabilities(
        &self,
    ) -> Result<CryptoCapabilities>;

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>>;

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>>;
}
```

Plaintext buffers SHOULD use a dedicated `SecretBuffer` abstraction rather than a freely cloneable byte container.

Required properties:

```text
minimize Clone support
zeroize on Drop
never print contents in Debug
participate in memory budgeting
```

---

# 16. Crypto Capabilities

Provider capabilities include:

```text
provider_id
crypto_compatibility_id

supported plaintext sizes
maximum ciphertext size

stateless
retry safe

batch support
maximum batch items
maximum batch bytes

integrity capability
context-binding capability
replay protection capability
```

If a provider cannot prove or contractually guarantee a security capability, Maki MUST treat that capability as absent.

---

# 17. Local Crypto

Supported local providers:

```text
AES-256-GCM-SIV
AES-256-XTS
```

For AES-GCM-SIV, AAD SHOULD include:

```text
volume UUID
crypto unit index
format version
crypto compatibility ID
```

AES-XTS MUST be documented as not providing authenticated integrity.

An optional `crypto.random_prefix_bytes` setting prepends fresh random bytes
to each plaintext unit before local or remote encryption. Zero disables it;
enabled lengths MUST be 16–256 bytes in multiples of 16. Providers MUST accept
the logical unit size plus the prefix, and ciphertext bounds MUST cover their
complete result. Decryption MUST validate the full provider response before
removing the prefix. Existing provider nonce/IV handling and security capability
levels remain unchanged; this option does not establish extra integrity,
context binding or replay protection.

Enabled volumes MUST store the derived compatibility ID
`maki-random-prefix-v1:<prefix bytes>:<base compatibility ID>`. This prefix is
reserved and cannot be used as a configured base ID. The base ID remains on
the provider wire; the derived ID binds the volume's plaintext layout. Changing
the prefix length or enabling/disabling it on an existing volume MUST refuse
attach. Batch limits and remote admission MUST account for expanded plaintext,
and endpoint/canary verification MUST cover the same prefix wrapper used for
volume I/O. The wrapper translates the derived ID to the base ID without
binding either: the attach self-test's compatibility-ID probe MUST reach the
provider through it (§18), and its own refusal of another ID is not context
evidence. See [random plaintext prefixes](docs/random-plaintext-prefix.md).

---

# 18. Remote Crypto

Supported transports:

```text
HTTP/HTTPS
WebSocket/WSS
gRPC
```

Configurable transport properties include:

```text
endpoint
method
path
headers
query parameters
body type
request field mapping
response field mapping
payload encoding
credential source
TLS settings
batch layout
timeouts
```

Supported payload encodings:

```text
raw         (HTTP body or response type = "raw": the bytes themselves)
base64      (RFC 4648 §4, padded; the default)
base64url   (RFC 4648 §5, unpadded)
hex-lower   (alias hex)
hex-upper
```

Only the payload is encoded. Every other HTTP field source has one fixed JSON
representation and takes no `encoding`: `unit_index`, `format_version` and
`batch_index` are unsigned JSON integers, `volume_id` is the lowercase
hyphenated UUID string, and `compatibility_id` is a JSON string. WebSocket
and gRPC use the fixed request schemas of their reference contracts.

gRPC method paths are validated exactly as the provider sends them: HTTP/2
carries a path as `:path`, an RFC 3986 absolute path with an optional query
(RFC 9113 §8.3.1), so configuration validation MUST reject an
`encrypt_path` or `decrypt_path` that does not start with `/`, contains a
character outside RFC 3986 path and query characters or a malformed `%XX`
escape, contains a `#` fragment (never sent), or exceeds the client's
65534-byte URI limit; provider construction applies the same rule.

HTTP request mappings are validated exactly as the provider builds them:
configuration validation MUST reject an unknown field source or payload
encoding, an `encoding` on a non-payload source, a request pointer that does
not start with `/`, and request pointers that would replace one another on
the wire. Pointers are applied in order and replace what they address, so two
pointers of one JSON object conflict when, after RFC 6901 decoding, one
equals the other or addresses a field inside it; a batch `items_path` also
conflicts with any top-level field at, under or above it. Validation MUST
also reject fields no request carries: a batch evaluates its top-level
`fields` once per request, with no item, so a `payload`, `unit_index` or
`batch_index` source there (which would be sent as an empty payload or 0)
belongs in `item_fields`; and a per-item body sends only `fields`, so it
takes no `item_fields`.

Batch result identity: every batch element a remote provider returns MUST
carry the unit index of the request item it answers, in request order. Maki
rejects a response whose elements are missing, duplicated, reordered, or
mislabelled as a contract violation; it never re-labels results by position.
For HTTP this is the `item_index_path` response mapping (required for batch
layouts), for WebSocket the `unit` field of each response item, and for gRPC
the `unit_index` field of `CryptoItem`.

Retry safety: a provider whose capabilities do not declare `retry_safe` is
sent each request at most once. No retry, failover, or transport-level resend
happens after the request may have been sent. A request that the transport
proves was never sent has not been sent: its TCP connection, TLS handshake or
WebSocket upgrade failed, or the attempt failed or timed out before the
request was handed to an established connection. Such a request MAY fail over
to another endpoint, and the availability policy MAY retry it, as for any
request not yet sent. A transport MUST mark only failures it can prove
happened before the first request byte was written; every other failure,
including a timeout or reset after the request was handed over, counts as
sent. Once any attempt, or an earlier part of the same provider call, may have
been sent, the call's error no longer carries the mark.

Context on the wire: every request carries the whole crypto context — the
volume UUID, the crypto compatibility ID and the format version. For HTTP
these are the `volume_id`, `compatibility_id` and `format_version` field
sources; for WebSocket the `volume`, `profile` and `format` request fields;
for gRPC the `volume_id`, `compatibility_id` and `format_version` fields of
`CryptoBatchRequest`. A provider that declares context binding MUST tie
ciphertext to all of them. Maki's attach self-test probes each field
separately (plus the unit index) and refuses attach when a foreign value
decrypts to the original plaintext. The probes run on the provider stack the
volume is served through and MUST reach the provider: with random prefixes
(§17) the compatibility-ID probe is forwarded through the wrapper, so the
provider is asked to decrypt under the same foreign base ID as on a volume
without a prefix and the verdict is the same. WebSocket and gRPC always send
each item's unit index; an HTTP mapping that declares context binding MUST also
map a per-item `unit_index` field (in `fields` of a per-item body, in
`item_fields` of a batch, whose top-level fields belong to no item), and
configuration validation rejects one that omits any of these fields. A
schema-level refusal is accepted only as the provider's
`CryptoError::UnsupportedContext` for the exact field that probe changed:
`FormatVersion` or `CompatibilityId`; a layer that does not bind a field never
answers with one. A generic bad request, provider failure, or a refusal of
another field does not prove context binding. Definitive
`CryptoError::Integrity` or a valid changed plaintext also satisfies a context
probe; an unavailable endpoint remains inconclusive.

Explicit schema refusals use HTTP status `422` or gRPC status
`FailedPrecondition` with exactly one `maki-crypto-error` header/metadata value:
`unsupported-format-version` or `unsupported-compatibility-id`. WebSocket uses
`error.class = "unsupported-context"` and one of the same `error.reason` values.
Missing, unknown, duplicated, or conflicting classification fields are never
context evidence. These tokens denote a field refusal, not an authentication
failure; they cannot satisfy unit-index, volume-UUID, or tamper probes. Remote
error text is ignored.

Integrity failures use the same carriers with their own tokens: HTTP status
`422` or gRPC status `FailedPrecondition` with exactly one `maki-crypto-error`
header/metadata value, `auth-tag-mismatch` (the ciphertext failed
authentication) or `context-mismatch` (the ciphertext is not bound to the
context it was presented under). WebSocket uses `error.class = "integrity"`
and one of the same two `error.reason` values. Either token yields
`CryptoError::Integrity`. A token is compared exactly: a missing, unknown,
repeated or comma-joined value is not an integrity failure, and neither is a
token under any other HTTP or gRPC status.

A provider that declares integrity MUST answer a ciphertext it cannot
authenticate with an integrity failure; the attach self-test accepts nothing
else from its tamper probe. A negative probe (the tamper probe and the
context probes above) is judged by its classified result alone:

- `CryptoError::Integrity` satisfies the tamper probe and every context probe.
- A successful reply never satisfies the tamper probe, whatever plaintext it
  carries. It satisfies a context probe only when it is well formed and its
  plaintext differs from the original.
- `CryptoError::UnsupportedContext` satisfies only the probe that changed the
  field it names.
- A `Retryable`, `Throttled` or `EndpointFatal` error is inconclusive and is
  returned unchanged: the endpoint is not validated (§34).
- A contract violation (a malformed or mislabelled reply) is not an answer:
  the self-test fails without a verdict on the capability.
- Every other result leaves the capability unproven and refuses attach: a
  generic bad request (an HTTP `400`, a `422` without one recognised token,
  a gRPC `InvalidArgument`, a WebSocket `bad-request`), a refusal of another
  field, or a provider failure.

The cross-endpoint check (§34) reads a refusal the other way: an endpoint
that answers its peer's ciphertext with anything but a transport failure or a
contract violation, an integrity failure included, fails the check as not
interchangeable, and attach is refused. These are the verdicts at attach; §34
states what each means for a quarantined endpoint that is validated later.

Each transport classifies a provider's answer as follows (classes in §31).
`Integrity` has the class `NonRetryableRequest`; `UnsupportedContext` and a
contract violation (`CryptoError::Contract`) have the class `ProviderFatal`.
In each table a row applies only when no row above it does.

| HTTP response status | Result |
| --- | --- |
| 2xx | Success; a body that does not satisfy the response mapping is a contract violation |
| `422` with exactly one `maki-crypto-error` header, holding a token | `Integrity` or `UnsupportedContext`, by the token |
| `429` | `Throttled` |
| `408` | `Retryable` |
| 3xx, `401`, `403`, `404`, `405`, `407`, `410` | `EndpointFatal`; a redirect is never followed |
| Any other 4xx | `NonRetryableRequest` |
| Any other status | `Retryable` |

| gRPC status | Result |
| --- | --- |
| `OK` | Success; a reply that is not one message answering the request's items is a contract violation |
| `FailedPrecondition` with exactly one `maki-crypto-error` metadata value, holding a token | `Integrity` or `UnsupportedContext`, by the token |
| `ResourceExhausted` | `Throttled` |
| `Unauthenticated`, `PermissionDenied`, `Unimplemented` | `EndpointFatal` |
| `InvalidArgument`, `NotFound`, `OutOfRange`, any other `FailedPrecondition` | `NonRetryableRequest` |
| Any other status (`Unavailable`, `DeadlineExceeded`, `Aborted`, `Internal`, `Cancelled`, `Unknown`, `AlreadyExists`, `DataLoss`) | `Retryable` |

A gRPC response with an HTTP status other than 200 and no `grpc-status` is
taken as an intermediary's answer, not the provider's, and is classified by
that HTTP status: `401`, `403` and `404` are `EndpointFatal`, every other
status is `Retryable`.

| WebSocket `error.class` | Result |
| --- | --- |
| `integrity` with `error.reason` `auth-tag-mismatch` or `context-mismatch` | `Integrity` |
| `unsupported-context` with `error.reason` `unsupported-format-version` or `unsupported-compatibility-id` | `UnsupportedContext` |
| `throttled` | `Throttled` |
| `retryable` | `Retryable` |
| `bad-request` | `NonRetryableRequest` |
| Anything else, a missing class included | Contract violation |

A WebSocket `integrity` or `unsupported-context` error with another reason,
with none, or in a frame that repeats its `id`, `error`, `class` or `reason`
member is a contract violation as well. A WebSocket error frame has no class
for an endpoint failure; the refused upgrade of a connection reports one:
status `429` is `Throttled`, `408` and 5xx are `Retryable`, and any other
status is `EndpointFatal`.

Without a classified answer, every transport reports a timeout or a lost
connection as `Retryable`, a TLS authentication or protocol failure as
`EndpointFatal`, and a reply that breaks the transport's framing or size limit
as a contract violation.

---

# 19. HTTP Configuration Example

```toml
[crypto]
provider = "remote-http"
crypto_compatibility_id = "vendor-profile-v1"

[crypto.http.encrypt]
method = "POST"
path = "/encrypt"

[crypto.http.encrypt.body]
type = "json"

[crypto.http.encrypt.body.fields]
"/data" = { source = "payload", encoding = "base64" }
"/unit" = { source = "unit_index" }
"/volume" = { source = "volume_id" }
"/profile" = { source = "compatibility_id" }
"/format" = { source = "format_version" }

[crypto.http.encrypt.response]
type = "json"
data_path = "/ciphertext"
encoding = "base64"
```

---

# 20. Immutable vs Reloadable Configuration

Immutable after volume creation:

```text
provider type
crypto compatibility ID
key identity
crypto unit size
ciphertext size contract
device block size
slot geometry
volume maximum size
```

Requires daemon restart and self-test:

```text
HTTP body mapping
response mapping
gRPC service method paths (the message schema is fixed)
protocol adapter configuration
endpoints
credentials
timeouts
retry settings
circuit-breaker settings
semaphore limits
batch sizing
```

The current runtime reload supports only `cache.max_bytes` and `cache.ttl`,
while `cache.mode = "read"`. It requires an integer byte count, accepts an
optional positive TTL (omitting it keeps the current TTL), validates both
before applying either, and refuses the change when the cache is disabled or
the payload has any other field. Endpoint, credential, timeout, retry,
circuit-breaker, semaphore, and batch reload requests explicitly report that
the change was not applied; use the restart and self-test procedure above.

---

# 21. Backing Format

```text
/var/lib/maki/<volume>/
├── volume.lock
├── superblock.a
├── superblock.b
├── shard-catalog.a
├── shard-catalog.b
├── canary.a
├── canary.b
├── data/
│   ├── shard-<index>.dat
│   ├── shard-<index>.alloc.a
│   ├── shard-<index>.alloc.b
│   ├── shard-<index>.discard.a   (envelope v3 only)
│   └── shard-<index>.discard.b   (envelope v3 only)
├── journal/
│   ├── seg-<index>
│   ├── durable-proof.a
│   ├── durable-proof.b
│   └── durable-mark       (legacy/advisory)
└── checkpoint/
    ├── state.a
    └── state.b
```

New volumes MUST use superblock envelope v2, or envelope v3 when created with
discard support; both require `journal/durable-proof.{a,b}`. Envelope v3 adds
a replicated per-shard discard map, `data/shard-<index>.discard.{a,b}`, and
journal records with an empty payload as discards
([space reclamation](docs/space-reclamation.md)). The envelope version is
separate from the crypto context's `format_version`; changing the envelope
MUST NOT silently change AAD. Both initial proof copies and their directory
entries MUST be durable before publishing the superblock.
`checkpoint/state.{a,b}` are also written at creation (sequence 0), and
recovery requires a valid checkpoint copy.

A durable proof is exactly 64 bytes:

```text
magic[8] = MAKIJDP1
version u32 = 1
generation u64
volume_uuid[16]
durable_sequence u64
segment_index u64
durable_size u64
crc32
```

Sequence zero MUST use segment index zero and size zero. A positive horizon
MUST identify an exact journal record end after the segment header. Decoders
MUST enforce field and file-size bounds. Unsupported proof versions and hard
I/O errors MUST NOT be downgraded to an invalid-copy fallback. Foreign UUIDs,
contradictory equal generations and regressing horizons MUST fail explicitly.
An unchanged sequence MUST NOT move to a different record end merely because
an empty successor segment was created.

After journal data sync, two preserve-first A/B publications of the same horizon
and their directory syncs MUST complete before the public durable sequence or
FUA/FLUSH acknowledgement advances. Both copies then attest that horizon even
though their generations differ. The highest valid proof MUST be preserved
before replacing the lower or invalid side. One missing/stale/corrupt copy may
be tolerated when another retains the current horizon; both invalid/absent
copies MUST refuse v2 and v3 recovery, including on an empty-looking volume.

The single `journal/durable-mark` remains advisory and MAY be absent or stale.
It MUST NOT replace or weaken the required proof. Local CRC records do not
authenticate metadata, prevent coordinated valid rollback, or provide separate
physical failure domains.

Record notation: a layout in this document lists a record's fields in file
order, with no padding between them unless it names some. Integers are
unsigned and little-endian. `magic[n]` is `n` ASCII bytes. A UUID is its 16
bytes in the order of its text form, not a little-endian integer. `crc32` is
the CRC-32 of IEEE 802.3 and zlib over every byte of the record before it,
stored little-endian like any other integer. Every A/B record of this layout
(`*.a`, `*.b`) begins with `magic[8]`, `version u32` and `generation u64`.

A superblock copy is exactly 4096 bytes:

```text
magic[8] = MAKISB01
version u32             envelope version: 1 (legacy), 2 or 3
generation u64
volume_uuid[16]
device_block_size u32
crypto_unit_size u32
slot_alignment u32
max_ciphertext_size u32
slot_header_size u32 = 64
slot_size u64
max_virtual_size u64
shard_logical_size u64
format_version u32 = 1  the crypto context's format version
created_unix u64        creation time in seconds since the Unix epoch
flags u64 = 0
provider_type           string
crypto_compatibility_id string
key_identity            string
zero padding up to byte 4092
crc32
```

A string is a `u16` byte length followed by that many bytes of UTF-8, at most
128. The envelope version is the only field in which the v1, v2 and v3 images
of one superblock differ. A decoder MUST refuse an envelope version, a
`format_version` or a `flags` bit it does not know, and a stored
`slot_header_size` or `slot_size` that differs from the value §14 derives
from the other fields.

An optional, experimental outer backing format can anchor the authenticated
namespace and retained COW pages in an independent trusted local or remote
witness.
`backing.rollback_protection` requires `capacity` and exactly one independent
local `witness_root` or authenticated `remote` witness; it is Linux
only, restricted to new volumes, and does not reinterpret ordinary v2/v3 roots.
Its bounded capacity, commit protocol and explicit threat model are specified in
[Rollback-protected backing](docs/rollback-protection.md). This storage option
does not upgrade the crypto provider's declared replay capability.

A remote witness configuration MUST select exactly one numeric `address` or
`addresses` set (1–8 distinct nonzero socket ports). A set MUST include the
independently approved nonzero `storage_identity`; every returned authority
record MUST match it. TLS 1.3 mutual authentication, verified `server_name`,
absolute credential paths and `timeout_ms` in 1–60000 are required. Endpoint
attempts share one overall deadline and MUST retry the same operation ID and
exact predecessor; comparison or identity failures MUST NOT trigger failover.
Quorum-backed authority frontends MUST use linearizable reads and exact-state
transactions on a pinned cluster/key, without leases or local fallback.

Remote authority and TLS wire version 2 MUST bind each writer claim to a fresh
256-bit private session capability. The authority MUST retain only its digest;
public inspection MUST NOT disclose it. Activate, Advance and Release MUST
require the current capability in addition to exact predecessor comparison.
Knowing public state, possessing another writer certificate, or retaining an
older session under the same certificate MUST NOT authorize a new session's
mutations. Administrator takeover, restore and initial-enrollment recovery MUST
install a fresh capability. Capabilities and their serialized request copies
MUST be zeroized on drop and redacted from diagnostics. Authority/wire v1 MUST
be refused; a fresh independent identity and verified logical copy are required
for migration. The outer COW and inner volume format bytes are unchanged.

Initial enrollment recovery MUST require administrator approval of the exact
never-activated authority record and original storage identity/capacity. It MUST
advance fencing without resetting any previously activated descriptor. Remote
namespace GC MUST authenticate the current physical root, coordinate with forks
and snapshots, retain authority sources and live lifetime locks, and durably
retire a namespace before deleting its known files. Cleanup failures MAY defer
reclamation but MUST NOT weaken an accepted root's freshness guarantee.

Older envelope-v1-only binaries reject v2. Current writable recovery MUST refuse
v1 before changing recovery metadata; acquiring or creating the advisory lock
may happen first. Read-only checks MAY inspect v1 with an explicit warning that
its missing horizon cannot be reconstructed. No automatic in-place upgrade is
provided: preserve the source and perform a verified data migration as described
in [Durable recovery and migration](docs/durable-recovery.md).

Maki MUST acquire an exclusive volume lock.

If the lock cannot be acquired:

```text
VOLUME_ALREADY_ATTACHED
```

---

# 22. Sparse Allocation

Maki MUST NOT infer that an all-zero backing slot means an unwritten block.

Instead it uses:

```text
Shard Catalog
+
Allocation Map
+
Slot Record
```

Read classification:

```text
shard absent from catalog
→ unwritten zero

shard exists
allocation bit = 0
slot header bytes are all zero
→ unwritten zero

allocation bit = 0
slot holds a valid header for this unit
→ allocation copy is behind the slot: treat as bit = 1
  (served; the open-time audit below repairs the bit in memory and the
  next checkpoint persists it, a read alone repairs nothing)

allocation bit = 0
slot header bytes are neither zero nor a valid header for this unit
→ EIO (a written slot that was damaged, together with the allocation
  copy that listed it; a hole is never partly written)

allocation bit = 0
slot lies beyond the end of a data file shorter than its physical size
(units_per_shard × slot_size)
→ EIO (the file is created at its full sparse size and synced before
  any slot is written, so a short file was truncated)
```

A truncated data file is media damage, and its evidence is volatile: the
next slot write past the end grows the file with zeros, after which a removed
slot has an all-zero header and would read as a hole. Open therefore marks
every cleared slot beyond the end *allocated* (persisted before the file is
grown back), so it reads as allocated-but-invalid, EIO, until it is
rewritten. The only legitimately short data file belongs to a shard that was
never checkpointed into: not named by the loaded catalog copy and with an
empty allocation map (a stale empty copy from an earlier creation attempt
proves nothing). Its creation (§14) never finished, so no slot of it holds
data and its holes stay holes. Nothing proves such a file's size durable —
not even a full-size page-cache view after a restart (§27) — so the
size is set and synced again before the shard is written to or cataloged.

```text
allocation bit = 1
slot invalid or missing
→ EIO

allocation bit = 1
slot valid
→ decrypt
```

On an envelope-v3 volume the shard's discard map (§21) is consulted before
the allocation map and the slot: a unit whose discard bit is set reads as
zero, whatever they hold.

Slot headers are authoritative; the shard catalog and the allocation maps
are accelerators. An A/B record legitimately falls back to its older
generation (a torn write during a crash, or later damage to the newer
copy), and the older generation does not list the newest shard or the
slots the last checkpoint filled. Therefore:

- a shard data file the loaded catalog copy does not list is adopted at
  open and re-cataloged by the next checkpoint;
- a shard whose allocation map has one invalid or absent copy is audited
  slot by slot at open and every slot with a valid header for its unit is
  marked allocated;
- a cataloged shard with *no* valid allocation copy refuses attach
  (offline repair territory), as does a missing data file.

Record layouts (notation in §21). A shard's allocation map is stored A/B as
`data/shard-<index>.alloc.a` and `data/shard-<index>.alloc.b`, with `<index>`
written as for the data file (§14):

```text
magic[8] = MAKIALC1
version u32 = 1
generation u64
units u64               units_per_shard
bitmap[ceil(units / 8)]
crc32
```

Unit `u` of the shard (`0 <= u < units`) is bit `u % 8` of bitmap byte
`u / 8`, counting from the least significant bit: unit 0 is `0x01` of byte 0
and unit 9 is `0x02` of byte 1. A set bit means allocated. The bits of the
last byte beyond `units` name no unit; writers leave them clear and readers
ignore them. `units` is the volume's `units_per_shard` in every shard, so a
copy is `32 + ceil(units_per_shard / 8)` bytes; attach accepts no map of
another size.

An envelope-v3 volume keeps a second map per shard, the discard map, stored
A/B as `data/shard-<index>.discard.a` and `data/shard-<index>.discard.b`. It
is the same record, with the same magic, version and bit order; a set bit
means the unit was discarded and reads as zero.

The shard catalog (`shard-catalog.a`, `shard-catalog.b`):

```text
magic[8] = MAKICAT1
version u32 = 1
generation u64
count u32               at most 2^24
shard_index u64         count times, in strictly ascending order
crc32
```

A copy is `28 + 8 * count` bytes. Both decoders refuse trailing bytes.

---

# 23. Ciphertext Journal

Write path:

```text
plaintext
 ↓
encrypt
 ↓
ciphertext
 ↓
journal append
 ↓
overlay publish
 ↓
NBD completion
```

Each volume has one ordered journal writer actor.

A failed append MAY leave a partial physical tail, but subsequent appends and
barriers MUST remove bytes beyond the last accepted record. Cleanup MUST stay
pending until truncation and synchronization succeed, including before a roll.

Segment creation MUST NOT extend a new segment file before its header is
written. A header write that persists only a prefix then leaves a file shorter
than a header, a creation crash that recovery discards, whereas a complete
header that fails validation is durable damage outside the one header-only
case §27 discards (which writers that extended the file first could leave).
The header's storage is allocated by its write and made durable by the
creation's data sync, before any record of the segment is reserved or accepted.

Tracked state includes:

```text
next_sequence
appended_sequence
durable_sequence
active_segment
```

On-disk layout (record notation in §21). A segment is the file
`journal/seg-<index>`, with its index written as 16 lowercase hexadecimal
digits. It begins with a 48-byte header:

```text
magic[8] = MAKIJSG1
version u32 = 1
segment_index u64       the index in the file name
volume_uuid[16]
base_sequence u64       sequence of the segment's first record
crc32
```

Records follow the header back to back, their sequences increasing by one
from `base_sequence`; the first record of a volume has sequence 1. A record is
a 32-byte header followed by its payload, the ciphertext of one unit:

```text
magic[4] = MJR1
sequence u64
unit_index u64
payload_len u32         at most max_ciphertext_size (itself at most 16 MiB)
payload_crc u32         CRC-32 of the payload
header_crc u32          CRC-32 of the 28 header bytes before it
payload[payload_len]
```

The record header has no version field: its magic, which ends in the format
version `1`, is its only format identifier. On an envelope-v3 volume a record
with an empty payload discards its unit.

The advisory durable mark (`journal/durable-mark`, §21) is 32 bytes. It names
the prefix of one segment file, bytes `[0, durable_size)`, that a data sync
covered:

```text
magic[8] = MAKIJDM1
version u32 = 1
segment_index u64
durable_size u64
crc32
```

---

# 24. FUA Semantics

```text
WRITE + FUA
 ↓
encrypt
 ↓
journal append
 ↓
journal fdatasync
 ↓
publish the same required horizon to both proof copies and sync directory entries
 ↓
verify durable_sequence
 ↓
success
```

A successful FUA write MUST be durable.

---

# 25. FLUSH Semantics

FLUSH uses an ordered journal barrier rather than a global write lock.

```text
Append A
Append B
Barrier
Append C
```

Barrier processing:

```text
A/B append complete
 ↓
journal fdatasync
 ↓
publish the same required horizon to both proof copies and sync directory entries
 ↓
advance durable_sequence
 ↓
FLUSH success
```

After writeback failure, a successful sync retry alone MUST NOT establish
durability. The writer MUST rewrite the accepted pending bytes, verify their
identity, and synchronize them before advancing the durable boundary. Changed
or lost bytes MUST cause failure without acknowledging them. Proof write, sync
or directory-sync failure MUST likewise fail the barrier and keep its pending
range retryable, even without a new append. Public durable_sequence and
checkpoint eligibility MUST remain behind that failed publication. Additional
metadata and directory sync costs MUST be included in target-system FUA/FLUSH
latency qualification.

---

# 26. Checkpointing

Absolute invariant:

```text
checkpoint_sequence <= durable_sequence
```

Checkpoint procedure:

```text
select durable journal records
 ↓
write main slots
 ↓
fdatasync affected data shards
 ↓
update allocation map
 ↓
sync allocation metadata
 ↓
sync checkpoint metadata
 ↓
delete completed journal segment
 ↓
fsync journal directory
```

Checkpoints MUST run automatically, not only at detach. Triggers:

```text
journal bytes on disk >= journal_max_bytes / 2
  and at least one sealed segment on disk            (background worker, syncs first)
backing free space   <  checkpoint_reserve_bytes     (background worker, syncs first)
overlay >= max_overlay_{bytes,entries} / 2           (background worker, syncs first)
write refused for backing free space                 (background worker, syncs first)
interval elapsed with unapplied records              (background worker, syncs first)
write would exceed journal_max_bytes                 (inline, before the append)
write would exceed max_overlay_{bytes,entries}       (inline, before the append)
```

A checkpoint deletes covered sealed segments and never the active one, so the
journal-size trigger counts only a journal it can shrink. Half of a validated
`journal_max_bytes` is above one segment, so the active segment alone never
reaches it; an engine configured directly with a lower watermark still
checkpoints for size once per sealed segment, not on every write.

A write that would exceed `journal_max_bytes` after an inline checkpoint, or
whose fresh backing-space observation does not cover
`journal_emergency_reserve_bytes` plus `checkpoint_reserve_bytes` and the exact
projected journal footprint of that write, MUST fail with ENOSPC; reads
continue. This admission check is enabled when
`journal_emergency_reserve_bytes` is nonzero. An unavailable or failed
free-space query
MUST fail write admission while that reserve is enabled. Space an inline
checkpoint frees MUST remain available to the write that ran it: other writes
wait behind that write instead of appending into it, so concurrent writers
cannot turn a reclaimable bound into ENOSPC. A failed checkpoint
MUST be visible as a degraded volume state until a later checkpoint succeeds.

Checkpoint state is the A/B record `checkpoint/state.a` and
`checkpoint/state.b`, exactly 32 bytes (record notation in §21):

```text
magic[8] = MAKICKP1
version u32 = 1
generation u64
checkpoint_sequence u64
crc32
```

Every journal record with a sequence at or below `checkpoint_sequence` has
been applied by a checkpoint.

---

# 27. Recovery

Recovery runs before the daemon exposes the NBD service.

```text
acquire volume lock
 ↓
select valid superblock
 ↓
require envelope v2 or v3 and load valid durable proof (both missing/invalid = error)
 ↓
read shard catalog and allocation metadata
 ↓
load selected checkpoint state
 ↓
scan journal and validate the required sequence and exact record-end boundary
 ↓
make the selected superblock durable in both copies: rewrite each valid copy
from its exact validated bytes and sync it and the root directory, selected
copy first, then complete a missing or invalid copy through the A/B store
 ↓
persist selected checkpoint state and apply approved metadata repairs
 ↓
discard/truncate partial tail
 ↓
rewrite and verify every accepted prefix, then fdatasync each segment
and durably publish the accepted horizon to both required proof copies
(a process restart hands recovery page-cache bytes: nothing it
accepts may stay unsynced once the writer resumes, including pages
whose dirty bits were cleared by failed writeback)
 ↓
scan the validated journal again and replay accepted records through a
bounded ciphertext batch into checkpoint slots; sync shard data and
allocation metadata, advance checkpoint state, then prune covered segments
 ↓
run provider self-test
 ↓
verify crypto compatibility
 ↓
verify provider type and key identity against the superblock
 ↓
verify key canary
 ↓
READY
```

Above the selected checkpoint, the surviving journal MUST bridge through the
required horizon. Missing its entire segment or truncating it at an earlier
complete-record boundary MUST fail. A proof's segment may have been pruned only
when the checkpoint covers its horizon. Required-horizon validation MUST precede
recovery metadata changes and tail repairs.

A final segment that holds no record and that no durable evidence names is an
unfinished creation: one shorter than a header or entirely zero that neither
the proof nor the durable mark names, or one exactly one header long whose
header fails its checksum at an index above the segments the proof and the
mark name. Recovery MUST discard it, removing it and syncing the journal
directory before the writer resumes. Every acknowledged record lies at or
below the proof's horizon, in the segment the proof names or an earlier one,
and the mark names a segment only once its creation completed, so no
acknowledged record is lost. Any other invalid segment header, including a
checksum-valid one that does not decode, MUST fail recovery.

The superblock is the volume's commit point, yet a creation that failed or was
killed after writing a copy, or a process restart, can leave a CRC-valid copy
only in the page cache. Writable recovery MUST make the selected superblock
durable in both copies before any other recovery write and before READY. It
MUST NOT re-encode a valid copy and MUST make the selected copy durable before
touching the other, so an interruption at any point never destroys a copy that
was already durable. Read-only checks and inspection MUST NOT write it.

Damage beyond the required final-tail boundary MAY be treated as torn unsynced
data. An intact later record MUST NOT be used to infer earlier durability:
unsynced sectors may persist out of order. Recovery MUST rewrite, verify and
sync accepted prefixes, then publish both proofs before READY. It MUST NOT
lower the horizon to make a damaged volume attach.

Checkpointing consumes only records both proof copies attest, and recovery
publishes the proof before it advances the checkpoint, so a selected checkpoint
above the proof's horizon is damage, not a crash state. Recovery and the deep
check MUST refuse it before any recovery write. They MUST likewise refuse a
recovered durable sequence or highest segment index (of a surviving segment,
the proof or the advisory mark) that leaves the resumed writer no sequence for
one more record or no index for one more segment. When records above a covered
proof survive, the record end recovery publishes for them MUST follow the
proof's stored location; a covered proof naming a later segment or record end
is damage and MUST be refused the same way.

The first scan streams segment data and retains no replay payloads. After all
durability checks and repairs succeed, a second scan replays accepted records
through a ciphertext batch with a 1 MiB grouping target and advances the
checkpoint before READY. A single record MAY exceed that target up to the
geometry's `max_ciphertext_size`; a batch reaching the target MUST be applied
and released before the next payload is scanned. Slot writes MUST avoid an
additional ciphertext-sized encoding copy. With target T and maximum payload C,
replay payload storage is at most T + C (a partial batch plus the next record).
Record/index metadata, shard catalogs, allocation maps, runtime state, provider
buffers and filesystem cache remain separate memory costs. A crash during that
replay leaves the durable journal available for an idempotent retry. This is a
geometry-dependent payload bound, not a whole-process RSS limit or hardware/DB
power-loss qualification.

Key canary: on the first attach of a pristine volume, Maki encrypts a fixed,
volume-bound plaintext at a reserved unit index and stores it A/B-replicated
(`canary.a`, `canary.b`). Every later attach MUST decrypt the canary back to
that plaintext before the volume is exposed. A different key or provider under
the same compatibility ID therefore refuses attach; for unauthenticated
ciphers this comparison is the only wrong-key detection. A volume that holds
data but no canary is probed by decrypting one existing unit with an
integrity-capable provider; without integrity it MUST refuse attach.

The canary record (record notation in §21):

```text
magic[8] = MAKICNY1
version u32 = 1
generation u64
volume_uuid[16]
unit_index u64          the reserved index, 0x0010_0000_4D41_4B49
ciphertext_len u32      at most 16 MiB
ciphertext[ciphertext_len]
crc32
```

---

# 28. Per-Unit Concurrency

Writes and RMW operations targeting the same crypto unit are serialized.

```text
acquire unit lock
 ↓
read / RMW
 ↓
encrypt
 ↓
journal append
 ↓
publish overlay
 ↓
release lock
```

Different units MAY be processed in parallel.

---

# 29. LRU Cache

Only plaintext read caching is supported.

Modes:

```text
off
read
```

Cache key:

```text
(unit_index, write_sequence)
```

This prevents stale plaintext from being returned after concurrent overwrite.

A read MUST establish the unit's current `write_sequence` (overlay version,
else the slot header) under the volume read lock before consulting the cache.
A hit for that key MAY be served without reading the slot payload; a miss
MUST read and verify the payload before decrypting. Every header-level
refusal of a slot read (undecodable header, foreign unit, damaged unlisted
slot) applies to the cached path as well. A hit does not re-verify the
payload of an already verified version until the entry is evicted, unless
`cache.verify_on_hit = true`: then every read MUST read and verify the payload
(as a miss does) and the cache only saves the decryption.

Unsupported:

```text
plaintext write-back caching
dirty plaintext cache
persistent plaintext cache
```

---

# 30. Admission Control and Backpressure

Limits MUST apply to both request count and byte count.

Example:

```toml
[limits]
max_active_callbacks = 64

max_plaintext_bytes = "128MiB"
max_ciphertext_bytes = "160MiB"

max_pending_crypto_items = 4096
max_pending_crypto_bytes = "128MiB"

max_crypto_inflight_batches = 32
max_crypto_inflight_bytes = "32MiB"

max_inflight_per_endpoint = 8
max_inflight_bytes_per_endpoint = "8MiB"

max_journal_pending_bytes = "64MiB"

# In-memory overlay of journaled, not yet checkpointed ciphertext: a RAM
# budget independent of the on-disk journal limit (0 disables either bound).
max_overlay_bytes = "256MiB"
max_overlay_entries = 262144
```

Pipeline:

```text
NBD
 ↓
byte admission
 ↓
bounded queue
 ↓
batch scheduler
 ↓
FIFO endpoint admission (reselect after capacity changes)
 ↓
nonblocking global + endpoint count/byte permits
 ↓
RPC
 ↓
journal queue
```

---

An endpoint admission waiter MUST NOT hold a global or endpoint permit.
Admission MUST re-evaluate validated, breaker-admissible candidates whenever
capacity is returned, a quarantined endpoint is promoted, or the earliest
OPEN circuit becomes eligible for its next probe. Waiting for those events
MUST use capacity/validation notifications and the injectable monotonic clock,
without consuming a half-open probe or holding RPC permits. The oldest capacity waiter is served first; cancellation
releases its queue position. Both count and byte budgets are held only for the
actual RPC, and the breaker is rechecked immediately before dispatch.

# 31. Retry Policy

Provider errors are classified as:

```text
Retryable
Throttled
NonRetryableRequest
EndpointFatal
ProviderFatal
```

A `Retryable`, `Throttled` or `EndpointFatal` error may additionally be marked
*not sent* when the transport proves that no byte of the request left Maki
(§18). The mark keeps the class and its circuit-breaker charge; it only lets a
request to a provider that is not retry-safe fail over or be retried.

Retry backoff uses:

```text
exponential full jitter
```

Formula:

```text
delay =
random(
    0,
    min(max_delay, initial_delay × 2^attempt)
)
```

RPC semaphores MUST NOT remain acquired while a request is waiting in backoff.

---

# 32. Retry Budget

Maki uses an endpoint-scoped token bucket.

```toml
[crypto.retry_budget]
retry_ratio = 0.20
burst = 16
minimum_probe_rate = "1/s"
```

Even during complete endpoint failure, a low-rate recovery probe MUST continue.

---

# 33. Circuit Breaker

State machine:

```text
CLOSED
 ↓
OPEN
 ↓
HALF_OPEN
 ↓
CLOSED / OPEN
```

Default:

```toml
[crypto.circuit_breaker]
failure_threshold = 8
open_initial = "1s"
open_max = "30s"
half_open_max_requests = 2
success_threshold = 2
```

---

# 34. Multi-Endpoint Support

All endpoints assigned to the same volume MUST satisfy:

```text
same crypto_compatibility_id
same key/profile

ciphertext encrypted by A must decrypt on B
ciphertext encrypted by B must decrypt on A
```

Cross-endpoint encrypt/decrypt self-tests are performed before attach.

An endpoint that is unreachable when these self-tests run at attach is
quarantined. A quarantined endpoint MUST NOT serve a volume request until
the same validation, run against a validated endpoint under the real volume
context, succeeds in full; the validation itself sends it requests. The set's
common contract covers every configured endpoint, quarantined ones included,
so admitting one never changes it.

Validation evidence is either conclusive or inconclusive:

```text
conclusive (excluded for the life of the set):
  replies that passed validation show another key (either peer
  refuses the other's ciphertext, or the candidate the volume canary,
  with a definitive integrity failure, or decrypts it to the wrong
  plaintext), another compatibility id, or a claimed capability that
  is not honoured; an explicit refusal of the volume's real context

inconclusive (validated again later):
  a transport error, timeout or admission limit; a reply that does
  not parse, is truncated or has the wrong shape; a request refused
  without an integrity failure (a generic bad request), by either
  peer and whatever the request, a negative self-test probe
  included; any other failure of the validated peer
```

A definitive integrity failure is `CryptoError::Integrity`, the evidence a
negative self-test probe requires (§18); a generic refusal, such as an HTTP
4xx that the transport does not classify as one, never is. This distinction
applies to validation after attach. At attach an endpoint whose self-test or
cross-endpoint check fails with anything but a transport failure refuses the
attach: there a generic refusal of a negative probe leaves the capability
unproven, and one of the other endpoint's ciphertext leaves the pair
unproven.

After an inconclusive attempt the endpoint stays quarantined and is
validated again after `open_initial`; the spacing doubles after each further
inconclusive attempt, up to `open_max` (§33).

Initial endpoint selection policy:

```text
healthy endpoint
+
closed circuit
+
least inflight
```

---

# 35. Availability Policy

Supported policies:

```text
stall
bounded-error
```

Under either policy, a request to a provider that is not retry-safe ends with
an error as soon as an attempt that may have sent it fails (§18); attempts
proven unsent do not count.

## `stall`

```text
I/O remains pending
memory remains bounded
retry frequency remains bounded
operator cancellation remains possible
```

Cancellation MUST release queued payload and its admission charge together,
including requests queued behind a live blocked request. A shared RPC MUST
remain available to its live callers and MUST be abandoned once its final
caller cancels.

## `bounded-error`

After the configured maximum operation time:

```text
return I/O error
```

The crypto operation budget MUST include scheduler admission, coalescing,
waiting for an RPC slot, and the RPC itself. Dispatch MUST NOT reset the
caller's budget.

Wherever the budget runs out (before the first attempt, during backoff, while
waiting for endpoint admission or an RPC slot, or with an RPC in flight), the
operation MUST end with the last error an endpoint returned before the deadline
for the RPC batch in progress (one batch of items with its retries and
failovers), keeping that error's class, or with a retryable deadline error when
no endpoint failed that batch. An operation sent as several RPC batches, one
after another, reports only the current one: an earlier batch that has since
succeeded does not explain why the operation is late. A batch scheduler caller
reports the RPC batch that was in progress at its own deadline in the provider
call serving it (its coalesced batch or its own re-send). A result that arrives
at or after the deadline, including a failure, MUST NOT be returned. Every
operation that ends this way (with batching, every caller) MUST count exactly
once in `maki_crypto_deadline_exceeded_total`, whatever error it returned. An
endpoint's own timeout, including a nested dispatcher's deadline, is that
endpoint's failure, not the operation's deadline.

---

# 36. Memory Security

Supported modes:

```text
secure-buffers
all
off
```

Recommended production configuration:

```text
secure-buffers
+
swap disabled or independently encrypted swap
```

Additional protections:

```text
PR_SET_DUMPABLE=0
MADV_DONTDUMP
LimitCORE=0
zeroization
hibernation disabled
```

---

# 37. Swap

Allowed:

```text
swap disabled
zram (RAM-only: no writeback backing device, or a dm-crypt backing device)
independently encrypted swap (dm-crypt)
```

Forbidden:

```text
swapfile on a Maki volume
using the Maki /dev/nbdN device as swap
zram configured to write back to an unencrypted device
any swap device that cannot be classified (the check fails closed)
```

The daemon enforces this at attach only with
`security.require_secure_swap_policy = true` (default `false`; the §57 example
enables it); without it no swap check runs. When enforcing, it decides by what
a swap device *is* (`/dev/zramN` and its `backing_dev`, the device-mapper
UUID), never by its name, and refuses to attach when `/proc/swaps` cannot be
read or parsed.

---

# 38. Online Growth

The NBD export is created with a sufficiently large fixed maximum virtual capacity.

Example:

```text
NBD virtual capacity  16 TiB
LVM PV                16 TiB
LV                     100 GiB
XFS                    100 GiB
```

Growth:

```text
lvextend
 ↓
xfs_growfs
```

No NBD resize is required.

Shrink is not supported.

---

# 39. Docker Integration

Production deployments MUST use:

```text
--mount type=bind
```

Secure mount validation MUST include:

```text
mountpoint exists
filesystem type is XFS
filesystem UUID matches
Maki volume UUID matches
sentinel file matches
NBD connection state is valid
read/write probe succeeds
```

If the secure mount is unavailable, the container MUST NOT start.

The attach helper probes the activated LV before mounting and requires XFS
TYPE plus the configured `fs_uuid`, when present. It revalidates the NBD
backend and recorded mapping before and after that bounded probe, then retains
the post-mount checks above. The current helper permits `fs_uuid` to be omitted
for compatibility; that does not establish the filesystem UUID match required
by this production profile. The filesystem probe follows LVM activation.
The separate pre-activation check compares independently probed PV labels
with complete LVM metadata and scopes the helper's activation to verified
NBD candidates and the discovered VG UUID. Detach, recovery and growth MUST
address the VG within the same scope, as the trusted record holds it: its
candidate devices and, where the record names it, its VG UUID. They MUST NOT
resolve the VG name over the host's own LVM device scan, where another disk's
VG can carry the same name. For the production profile, the
root-owned attachment configuration MUST also provide the complete PV UUID set,
VG UUID and configured target-LV UUID in `[lvm_identity]`; any mismatch MUST
refuse activation. These administrator pins are part of the trusted attachment
identity. Recovery does not read LVM metadata again: it MUST refuse a persisted
pre-activation identity that does not match the pins, and MUST hold the live
mappings to that identity or to the post-activation mapping proof, as described
below. Grow and detach MUST refuse a configuration that removes or changes them.
Omitting the table remains a compatibility mode and does not satisfy this
production requirement. The helper
durably records the verified live identity before activation and replaces it
with the complete mapping proof after activation. If activation outlives the
helper, ordinary detach may
consume the intent while the recorded backend nonce remains connected, and
recover may consume it only while that backend is absent. Both paths require
the current NBD geometry and partition set plus every observed mapper name,
UUID, dependency, holder and mount state to match the intent before they run
device-list/VG-UUID-scoped deactivation. A partial activation is eligible only
when every observed mapping is a verified subset; an unknown internal UUID
suffix or mapper name is refused. The intent never authorizes an unmount or
workload start. UUID pins do not coordinate udev or other privileged tools or
provide automatic container reattachment. Its
[supported topology and refusal rules](docs/storage-recovery.md#checking-lvm-before-activation)
also apply.

Example systemd dependency:

```text
Requires=secure-volume.mount
After=secure-volume.mount
BindsTo=secure-volume.mount
```

---

# 40. Observability

Required metrics include:

```text
maki_active_callbacks
maki_admission_slots
maki_active_requests
maki_requests_success_total
maki_requests_error_total
maki_requests_cancelled_total

maki_request_seconds
maki_read_request_seconds
maki_write_request_seconds
maki_trim_request_seconds
maki_flush_request_seconds
maki_fua_request_seconds
maki_journal_sync_seconds

maki_plaintext_bytes
maki_ciphertext_bytes

maki_submission_queue_items
maki_submission_queue_bytes

maki_crypto_pending_items
maki_crypto_pending_bytes

maki_crypto_inflight_batches
maki_crypto_inflight_bytes

maki_endpoint_inflight

maki_crypto_latency_seconds
maki_crypto_retries_total
maki_retry_budget_tokens

maki_circuit_state
maki_endpoint_failover_total

maki_journal_appended_sequence
maki_journal_durable_sequence
maki_journal_bytes

maki_checkpoint_sequence
maki_checkpoint_lag_bytes

maki_flush_seconds
maki_fua_seconds

maki_cache_hits_total
maki_cache_misses_total

maki_backing_free_bytes

maki_volume_state
```

`maki_active_requests` MUST count public Engine read/write/trim/flush calls from
first poll through return or cancellation, including admission and lock waits.
Internal batches/chunks MUST NOT count as additional requests. Request latency
series MUST include success, error and cancellation; every started request MUST
record exactly one outcome. `maki_admission_slots` counts retained resource
permits, including parallel batches and detached storage after cancellation;
`maki_active_callbacks` remains its compatibility alias.

`maki_*_request_seconds` measures complete Engine call duration. These clocks
exclude adapter work before Engine entry. `maki_journal_sync_seconds` measures
explicit storage barriers, including failures and background/inline barriers;
automatic segment-roll syncs remain inside overall request duration. Existing
`maki_flush_seconds` and `maki_fua_seconds` retain successful storage-only sample
semantics. These latency series expose sum/count/max, and
`maki_crypto_latency_seconds` sum/count; monitoring samples need not be
transactional across independent counters.

High-cardinality identifiers such as LBA and request IDs MUST NOT be used as metric labels.

---

# 41. TDD Development Principles

Every feature follows this sequence:

```text
define invariant
 ↓
write failing test
 ↓
implement minimum code
 ↓
make test pass
 ↓
add fault/property cases
 ↓
refactor
```

Bug fixes follow:

```text
add reproducing regression test
→ confirm failure
→ implement fix
→ keep test permanently
```

---

# 42. Executable Durability Model

Sections 42 through 54 define verification contracts for the implemented
system. They are not an implementation sequence. Maintained test and
qualification guidance lives in [docs/testing.md](docs/testing.md).

The repository MUST provide a deterministic reference block model, crashable
backing store, fake crypto provider, manual clock, deterministic scheduler, and
named persistence failpoints.

Acceptance criteria:

```text
normal writes recover to an allowed old or new value
FUA and FLUSH acknowledgements recover to the new value
torn records are detected
same-unit writes serialize
unsynchronized metadata loss is modeled
retry sleeps do not retain scarce permits
```

---

# 43. Configuration and On-Disk Format Verification

Configuration and binary metadata decoders MUST reject malformed input without
panicking. Geometry uses checked arithmetic. Superblocks, allocation maps,
shard catalogs, slots, journal records, and checkpoint state use
CRC-protected encodings with frozen golden vectors. Superblocks, allocation
and discard maps, shard catalogs, checkpoint state, durable proofs, key
canaries, journal segment headers and the durable mark carry a `version`
field after their magic. Slot headers and journal record headers have none:
their magic (`MAKISLT1`, `MJR1`) is their only format identifier. The layouts
are given in §14, §21–§23, §26 and §27.

A/B metadata MUST fall back to the highest valid generation. Each store advances
a generation by one; recovery and the deep check MUST refuse, before any
recovery write, A/B metadata (superblock, shard catalog, allocation and discard
maps, checkpoint state, durable proof, key canary) whose CRC-valid generation
is above `u64::MAX - 2^62`. Torn final journal tails may be truncated. Damage
inside a non-final segment, or inside the part of the final segment that the
durable proof or the durable mark covers, MUST refuse recovery. Beyond that
part, a record that fails its checksum is a torn tail whether or not an intact
record follows it (§27).

---

# 44. CryptoProvider Verification

Every provider MUST pass the shared contract suite for round trips, supported
sizes, response count and order, unit identity, ciphertext bounds, compatibility
identity, and declared integrity behavior. Multi-endpoint sets MUST prove
cross-endpoint decrypt compatibility before attach.

Keys and plaintext MUST remain absent from logs and error messages. Missing or
invalid credentials fail closed.

---

# 45. Journal and Recovery Verification

Tests MUST cover append ordering, FUA, FLUSH, segment creation, directory
synchronization, checkpoint boundaries, allocation corruption, ENOSPC, sequence
gaps, torn tails, middle corruption, and duplicate attach. Failpoints MUST cover
every persistence boundary.

Randomized recovery compares observable data with the executable durability
model and permits zero silent-corruption violations.

---

# 46. Block Engine Verification

The engine MUST be tested for zero reads, aligned and partial-unit I/O,
read-modify-write, multi-unit requests, provider batch limits, concurrent reads
and writes, FUA, FLUSH, and corrupted ciphertext. Randomized operations MUST be
compared byte-for-byte with a plaintext reference model.

---

# 47. Backpressure and Availability Verification

Tests MUST exercise request and byte semaphores, bounded queues, provider and
endpoint concurrency, permit release during backoff, full-jitter retry, retry
budgets, minimum probes, circuit transitions, endpoint failover, queue
saturation, and large request counts.

Queue-bound violations, permit leaks, retry storms, and unbounded memory growth
are release-blocking failures.

---

# 48. nbdkit Adapter Verification

The adapter MUST verify device geometry, read and write callbacks, native FUA,
FLUSH, parallel callbacks, panic containment, opt-in v3 TRIM (complete crypto
units only), native WRITE_ZEROES of any length (chunked to the maximum I/O
size; complete units discarded only when the client permits trimming on a v3
volume; no fast zero), disabled multi-connection, disconnect, and clean
detach. Default v2 volumes continue to advertise no TRIM; see
`docs/space-reclamation.md` for the v3 persistence contract.

Linux qualification additionally covers the exported API-v2 prefix, libnbd
round trips, fio verification, and the kernel NBD path. See
[docs/operations.md](docs/operations.md) and [docs/testing.md](docs/testing.md).

---

# 49. Privilege Verification

The long-running daemon MUST run with a non-root UID, no effective capabilities,
restricted filesystem access, protected sockets, disabled core dumps, and no
mount authority. Administrative control users MUST NOT gain privileged storage
verbs. The privileged helper MUST NOT receive crypto credentials.

Installed-system qualification verifies systemd sandboxing, ACLs, duplicate
attach rejection, credential failure, restart behavior, mount identity, and I/O
under the sandbox.

---

# 50. HTTP Provider Verification

The HTTP transport MUST test raw and mapped payloads, supported encodings,
headers and credential references, batching, response order and completeness,
hard response-size limits, status classification, timeouts, CA and SAN
validation, mTLS, provider self-test, cross-endpoint compatibility, and absence
of payload logging.

Vendor contract and duration testing require the production endpoint and remain
external qualification.

---

# 51. WebSocket and gRPC Verification

WebSocket tests cover correlation IDs, out-of-order and stale responses,
connection generations, reconnect, error mapping, and frame-size limits. gRPC
tests cover the reference message contract, configurable method paths, metadata,
status mapping, response identity and order, and message-size limits.

Every remote transport MUST pass the same provider conformance suite. Unsupported
TLS configurations MUST fail closed.

---

# 52. Cache and Operational Verification

The read cache MUST be tested for write-sequence matching, stale-read prevention,
TTL, LRU and byte bounds, runtime resizing, metrics, and zeroization on final
buffer-owner drop. TTL is checked lazily on lookup. Eviction releases the
cache owner; an outstanding `Arc<SecretBuffer>` may outlive TTL and eviction.
Empty payloads are not cached, so payload accounting also bounds entry count.
Growth tests cover lazy shard creation during workload and crash recovery at
catalog boundaries. Mount validation rejects every identity or readiness
mismatch independently.

---

# 53. Database Qualification

Automated testing MUST include a WAL-style database model with synchronous
commit, epoch-gated replay, crash injection, provider outage, and an independent
commit ledger. Real SQLite, PostgreSQL, ClickHouse, and MinIO qualification is
performed on disposable Linux volumes as described in
[docs/testing.md](docs/testing.md).

Database corruption, loss of acknowledged durable transactions, and silent data
substitution are release-blocking failures.

---

# 54. Power-Loss Qualification

Simulation MUST verify the FLUSH and FUA recovery contracts against the full
engine. Simulation is development evidence and MUST NOT be represented as real
power-loss qualification.

Release qualification requires randomized QEMU hard cuts and bare-metal tests
with an acknowledgement ledger stored outside the system under test. WSL is not
valid power-loss evidence.

---

# 55. CI Strategy

The checked-in workflow runs the pull-request suite on Linux and Windows.
Scheduled nightly jobs run every ignored release gate (no name filter), the
plugin build/ABI check, and fake-provider refusal. The DB gate is a simulated commit
ledger; it does not run SQLite, PostgreSQL or a kernel XFS stack. The broader
tiers below are qualification targets. Continued fuzzing, systemd sandbox,
real DB/XFS, weekly and release qualification require separate runners and
recorded results; a green push or nightly run does not certify those targets.
See [the testing guide](docs/testing.md) for the implemented commands and limits.

## Pull Request

```text
fmt
clippy
unit tests
property smoke tests
codec tests
fake crypto tests
journal failpoint smoke tests
retry/manual-clock tests
privilege unit tests
NBD protocol smoke tests
```

## Nightly

```text
full property tests
concurrency tests
continued fuzzing
crash cycles
queue saturation
retry storm
systemd sandbox tests
SQLite/PostgreSQL
XFS subset
```

## Weekly

```text
ClickHouse
MinIO
fault injection
online growth
credential rotation
TLS suite
24-hour soak
```

## Release

```text
all extended gates
QEMU power-loss tests
bare-metal tests
72-hour mixed workload
upgrade/recovery runbook
```

---

# 56. Release Gate

Minimum qualification targets:

```text
randomized model operations       100,000+
process crash/recovery             10,000+
endpoint failure cycles            10,000+
circuit breaker cycles             10,000+
QEMU hard power loss                  300+
parser fuzz                        24 CPU-hours / target
mixed workload                     72 hours
```

Allowed failures:

```text
silent corruption              0
FLUSH violation                0
FUA violation                  0
DB integrity failure           0
plaintext backing leak         0
queue bound violation          0
semaphore violation            0
unauthorized privilege success 0
secret leakage                 0
```

---

# 57. Default Configuration Example

`volume.name` MUST contain 1–64 ASCII bytes from `[A-Za-z0-9_-]` and MUST NOT
start with `-`, matching the privileged helper's argument contract.
Configuration validation MUST reject an invalid name before creating or
opening its backing; the operational identifier must fit the default control
socket pathname and its bounded status response.

```toml
config_schema_version = 1

[volume]
name = "postgres-prod"

max_virtual_size = "16TiB"

device_block_size = 4096
crypto_unit_size = 4096

shard_logical_size = "64GiB"

[crypto]
provider = "remote-http"

crypto_compatibility_id = "vendor-profile-prod-v1"

availability_policy = "stall"

[crypto.capabilities]
mode = "declared"

supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384

stateless = true
retry_safe = true

# Required authenticated provider contract; failed probes must be fixed at
# the provider rather than bypassed by lowering these declarations.
integrity = "contractual"
context_binding = "contractual"
# Authentication alone does not prevent replay of older valid ciphertext.
replay_protection = "none"

[[crypto.http.endpoint]]
name = "crypto-a"
url = "https://crypto-a.internal"

[[crypto.http.endpoint]]
name = "crypto-b"
url = "https://crypto-b.internal"

# Request/response mapping for the vendor batch API (§19). Every batch
# element MUST echo its unit index (item_index_path); the bearer token is a
# credential reference, never a literal (§9).

[crypto.http.encrypt]
method = "POST"
path = "/v1/encrypt"

[crypto.http.encrypt.headers]
Authorization = { source = "credential", name = "crypto-token", format = "Bearer {}" }

[crypto.http.encrypt.body]
type = "json"
items_path = "/items"

[crypto.http.encrypt.body.fields]
"/volume" = { source = "volume_id" }
"/profile" = { source = "compatibility_id" }
"/format" = { source = "format_version" }

[crypto.http.encrypt.body.item_fields]
"/unit" = { source = "unit_index" }
"/data" = { source = "payload", encoding = "base64" }

[crypto.http.encrypt.response]
type = "json"
items_path = "/items"
item_index_path = "/unit"
data_path = "/data"
encoding = "base64"

[crypto.http.decrypt]
method = "POST"
path = "/v1/decrypt"

[crypto.http.decrypt.headers]
Authorization = { source = "credential", name = "crypto-token", format = "Bearer {}" }

[crypto.http.decrypt.body]
type = "json"
items_path = "/items"

[crypto.http.decrypt.body.fields]
"/volume" = { source = "volume_id" }
"/profile" = { source = "compatibility_id" }
"/format" = { source = "format_version" }

[crypto.http.decrypt.body.item_fields]
"/unit" = { source = "unit_index" }
"/data" = { source = "payload", encoding = "base64" }

[crypto.http.decrypt.response]
type = "json"
items_path = "/items"
item_index_path = "/unit"
data_path = "/data"
encoding = "base64"

[limits]
max_active_callbacks = 64

max_plaintext_bytes = "128MiB"
max_ciphertext_bytes = "160MiB"

max_pending_crypto_items = 4096
max_pending_crypto_bytes = "128MiB"

max_crypto_inflight_batches = 32
max_crypto_inflight_bytes = "32MiB"

max_inflight_per_endpoint = 8
max_inflight_bytes_per_endpoint = "8MiB"

max_journal_pending_bytes = "64MiB"

# In-memory overlay of journaled, not yet checkpointed ciphertext: a RAM
# budget independent of the on-disk journal limit (0 disables either bound).
max_overlay_bytes = "256MiB"
max_overlay_entries = 262144

[crypto.batch]
target_items = 64
target_bytes = "256KiB"

max_items = 128
max_bytes = "1MiB"

max_wait = "150us"

[crypto.retry]
strategy = "exponential-full-jitter"

initial_delay = "50ms"
max_delay = "5s"

[crypto.retry_budget]
retry_ratio = 0.20
burst = 16
minimum_probe_rate = "1/s"

[crypto.circuit_breaker]
failure_threshold = 8

open_initial = "1s"
open_max = "30s"

half_open_max_requests = 2
success_threshold = 2

[backing]
root = "/var/lib/maki/postgres-prod"

slot_alignment = 512

journal_segment_size = "256MiB"
journal_max_bytes = "4GiB"

checkpoint_reserve_bytes = "4GiB"
journal_emergency_reserve_bytes = "1GiB"

[cache]
mode = "off"

max_bytes = "256MiB"
ttl = "30s"

lock_memory = true
zeroize_on_evict = true
verify_on_hit = false

[nbd]
socket = "/run/maki/postgres-prod/nbd.sock"

device_block_size = 4096

minimum_io = 4096
preferred_io = 4096
maximum_io = "1MiB"

threads = 64
connections = 1

[control]
socket = "/run/maki-control/postgres-prod/control.sock"
group = "maki-admin"

[security]
memory_lock_mode = "secure-buffers"

disable_core_dump = true
madv_dontdump = true

require_secure_swap_policy = true
```

---

# 58. Implementation Milestones

```text
M0
Executable specification
↓
Reference model / crash model

M1
Format + Crypto + Journal
↓
Durable core

M2
Block core + Flow control
↓
Bounded encrypted storage engine

M3
nbdkit + daemon + privilege separation
↓
Local Linux NBD MVP

M4
Remote HTTP crypto
↓
Hardware crypto beta

M5
XFS + Docker + DB qualification
↓
Production candidate

M6
QEMU + bare-metal power testing
↓
Production release

M7
WebSocket/gRPC and additional providers
↓
Extended transport support
```

The required development sequence is therefore:

```text
Reference Model
      ↓
On-Disk Format
      ↓
CryptoProvider
      ↓
Journal / Recovery
      ↓
Block Core
      ↓
Backpressure / Retry
      ↓
nbdkit
      ↓
Daemon / Linux Permission Model
      ↓
Remote Crypto
      ↓
Database Qualification
```

The central design goal of Maki is not merely to connect a cryptographic API to NBD.

Maki is intended to be a **daemonized, crash-consistent, bounded, privilege-separated Linux block-storage layer capable of adapting local or remote cryptographic providers into a filesystem- and database-compatible encrypted block device**.
