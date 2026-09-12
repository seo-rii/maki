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

maki reload
maki check

maki grow
```

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

Recommended permissions:

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

The NBD Unix Domain Socket:

```text
/run/maki/<volume>/nbd.sock
```

MUST be created behind a restrictive runtime ancestor.
Administrative control access MUST NOT grant access to the NBD socket.

Privileged attachment state MUST be opened through root-controlled directory
descriptors without following symlinks. Detach MUST verify its requested
volume UUID, socket, mountpoint, VG, LV, and device against a trusted record
before executing any step. The record's unique connection identifier MUST
match the live NBD backend before detach and immediately before disconnect,
including rollback. A missing or invalid record MUST fail closed, even when
the caller supplies an explicit NBD device.

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

Supported credential sources:

```text
systemd credentials
root-only secret file
kernel keyring
explicit secret-provider abstraction
```

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
│   │   ├── io/
│   │   ├── scheduler/
│   │   ├── barrier/
│   │   ├── admission/
│   │   ├── recovery/
│   │   ├── state/
│   │   └── volume/
│   │
│   ├── maki-format/
│   │   ├── superblock/
│   │   ├── slot/
│   │   ├── journal/
│   │   ├── allocation/
│   │   └── checksum/
│   │
│   ├── maki-crypto/
│   │   ├── provider/
│   │   ├── batching/
│   │   ├── retry/
│   │   ├── circuit_breaker/
│   │   └── endpoint/
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
│   └── maki-test-support/
│
├── bins/
│   ├── maki
│   ├── maki-attach
│   ├── maki-check
│   └── maki-benchmark
│
└── packaging/
    ├── systemd/
    ├── tmpfiles.d/
    ├── sysusers.d/
    └── examples/
```

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
I/O sizes. The minimum MUST be at most 64 KiB and the maximum MUST fit in the
32-bit NBD field. Read and write callbacks MUST reject zero-length, oversized,
out-of-range, or minimum-misaligned requests before copying write plaintext or
submitting engine work. The preferred size is a performance hint.

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

Supported encodings:

```text
raw
base64
base64url
hex-lower
hex-upper
utf8
integer
uuid
```

Batch result identity: every batch element a remote provider returns MUST
carry the unit index of the request item it answers, in request order. Maki
rejects a response whose elements are missing, duplicated, reordered, or
mislabelled as a contract violation; it never re-labels results by position.
For HTTP this is the `item_index_path` response mapping (required for batch
layouts), for WebSocket the `unit` field of each response item, and for gRPC
the `unit_index` field of `CryptoItem`.

Retry safety: a provider whose capabilities do not declare `retry_safe` is
sent each request at most once. No retry, failover, or transport-level resend
happens after the request has been sent.

Context on the wire: every request carries the whole crypto context — the
volume UUID, the crypto compatibility ID and the format version. For HTTP
these are the `volume_id`, `compatibility_id` and `format_version` field
sources; for WebSocket the `volume`, `profile` and `format` request fields;
for gRPC the `volume_id`, `compatibility_id` and `format_version` fields of
`CryptoBatchRequest`. A provider that declares context binding MUST tie
ciphertext to all of them. Maki's attach self-test probes each field
separately (plus the unit index) and refuses attach when a foreign value
decrypts to the original plaintext. A schema-level refusal is accepted only as
`CryptoError::UnsupportedContext` for the exact field that probe changed:
`FormatVersion` or `CompatibilityId`. A generic bad request, provider failure,
or a refusal of another field does not prove context binding. Definitive
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
"/data" = {
    source = "payload",
    encoding = "base64"
}

"/volume" = {
    source = "volume_id"
}

"/profile" = {
    source = "compatibility_id"
}

"/format" = {
    source = "format_version"
}

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

The current runtime reload supports only `cache.max_bytes`, while
`cache.mode = "read"`. It requires an integer byte count and refuses the change
when the cache is disabled. Endpoint, credential, timeout, retry,
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
├── journal/
│   ├── seg-<index>
│   ├── durable-proof.a
│   ├── durable-proof.b
│   └── durable-mark       (legacy/advisory)
└── checkpoint/
    ├── state.a
    └── state.b
```

New volumes MUST use superblock envelope v2 and require
`journal/durable-proof.{a,b}`. The envelope version is separate from the crypto
context's `format_version`; changing the envelope MUST NOT silently change AAD.
Both initial proof copies and their directory entries MUST be durable before
publishing the v2 superblock. `checkpoint/state.{a,b}` are also written at
creation (sequence 0), and recovery requires a valid checkpoint copy.

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
copies MUST refuse v2 recovery, including on an empty-looking volume.

The single `journal/durable-mark` remains advisory and MAY be absent or stale.
It MUST NOT replace or weaken required v2 evidence. Local CRC records do not
authenticate metadata, prevent coordinated valid rollback, or provide separate
physical failure domains.

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
slot holds no valid header for this unit
→ unwritten zero

allocation bit = 0
slot holds a valid header for this unit
→ allocation copy is behind the slot: treat as bit = 1
  (served; bit repaired in memory, persisted by the next checkpoint)

allocation bit = 1
slot invalid or missing
→ EIO

allocation bit = 1
slot valid
→ decrypt
```

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

Tracked state includes:

```text
next_sequence
appended_sequence
durable_sequence
active_segment
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
journal bytes on disk >= journal_max_bytes / 2       (background worker)
backing free space   <  checkpoint_reserve_bytes     (background worker)
interval elapsed with unapplied records              (background worker, syncs first)
write would exceed journal_max_bytes                 (inline, before the append)
```

A write that would exceed `journal_max_bytes` after an inline checkpoint, or
whose fresh backing-space observation does not cover
`journal_emergency_reserve_bytes` plus the exact projected journal footprint of
that write, MUST fail with ENOSPC; reads continue. An unavailable or failed
free-space query
MUST fail write admission while that reserve is enabled. A failed checkpoint
MUST be visible as a degraded volume state until a later checkpoint succeeds.

---

# 27. Recovery

Recovery runs before the daemon exposes the NBD service.

```text
acquire volume lock
 ↓
select valid superblock
 ↓
require envelope v2 and load valid durable proof (both missing/invalid = error)
 ↓
read shard catalog and allocation metadata
 ↓
load selected checkpoint state
 ↓
scan journal and validate the required sequence and exact record-end boundary
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
rebuild overlay
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

Damage beyond the required final-tail boundary MAY be treated as torn unsynced
data. An intact later record MUST NOT be used to infer earlier durability:
unsynced sectors may persist out of order. Recovery MUST rewrite, verify and
sync accepted prefixes, then publish both proofs before READY. It MUST NOT
lower the horizon to make a damaged volume attach.

The scanner streams segment data and discards covered payloads, but replay and
overlay memory remain separate costs. No whole-recovery RSS bound or current
hardware/DB power-loss qualification is implied by that implementation.

Key canary: on the first attach of a pristine volume, Maki encrypts a fixed,
volume-bound plaintext at a reserved unit index and stores it A/B-replicated
(`canary.a`, `canary.b`). Every later attach MUST decrypt the canary back to
that plaintext before the volume is exposed. A different key or provider under
the same compatibility ID therefore refuses attach; for unauthenticated
ciphers this comparison is the only wrong-key detection. A volume that holds
data but no canary is probed by decrypting one existing unit with an
integrity-capable provider; without integrity it MUST refuse attach.

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
global semaphore
 ↓
endpoint semaphore
 ↓
RPC
 ↓
journal queue
```

---

# 31. Retry Policy

Provider errors are classified as:

```text
Retryable
Throttled
NonRetryableRequest
EndpointFatal
ProviderFatal
```

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

The daemon decides by what a swap device *is* (`/dev/zramN` and its
`backing_dev`, the device-mapper UUID), never by its name, and refuses to
attach when `/proc/swaps` cannot be read or parsed.

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
NBD candidates and the discovered VG UUID. For the production profile, the
root-owned attachment configuration MUST also provide the complete PV UUID set,
VG UUID and configured target-LV UUID in `[lvm_identity]`; any mismatch MUST
refuse activation. These administrator pins are part of the trusted attachment
identity and MUST be rechecked during recovery. Grow and detach MUST refuse a
configuration that removes or changes them. Omitting the table remains a
compatibility mode and does not satisfy this production requirement. The helper
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
shard catalogs, slots, journal records, and checkpoint state use versioned,
CRC-protected encodings with frozen golden vectors.

A/B metadata MUST fall back to the highest valid generation. Torn final journal
tails may be truncated; corruption before a valid successor record MUST refuse
recovery.

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

The adapter MUST verify device geometry, read and write callbacks, emulated FUA,
FLUSH, parallel callbacks, panic containment, disabled native TRIM and
write-zeroes, disabled multi-connection, disconnect, and clean detach.

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
TTL, LRU and byte bounds, runtime resizing, metrics, and zeroization on eviction.
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
Scheduled nightly jobs run the seven named release phase gates, the plugin
build/ABI check, and fake-provider refusal. The DB gate is a simulated commit
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
