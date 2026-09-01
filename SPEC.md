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
activate LVM PV/VG/LV
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
/run/maki/<volume>/control.sock
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

/run/maki/<volume>
maki:maki                 0700
```

The NBD Unix Domain Socket:

```text
/run/maki/<volume>/nbd.sock
```

MUST be created inside a restrictive runtime directory.

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
Type=simple

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

ReadWritePaths=/var/lib/maki/%i
ReadWritePaths=/run/maki/%i
```

The exact sandbox options MUST be finalized after compatibility testing with nbdkit and all required shared libraries.

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
gRPC descriptor
protocol adapter configuration
```

Hot-reloadable:

```text
endpoints
credentials
timeouts
retry settings
circuit-breaker settings
semaphore limits
batch sizing
LRU cache size
```

---

# 21. Backing Format

```text
/var/lib/maki/<volume>/
├── volume.lock
├── superblock.a
├── superblock.b
├── shard-catalog.a
├── shard-catalog.b
├── data/
├── journal/
└── checkpoint/
```

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
→ unwritten zero

allocation bit = 1
slot invalid or missing
→ EIO

allocation bit = 1
slot valid
→ decrypt
```

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
advance durable_sequence
 ↓
FLUSH success
```

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

---

# 27. Recovery

Recovery runs before the daemon exposes the NBD service.

```text
acquire volume lock
 ↓
select valid superblock
 ↓
validate shard catalog
 ↓
validate allocation metadata
 ↓
scan journal
 ↓
discard/truncate partial tail
 ↓
rebuild overlay
 ↓
run provider self-test
 ↓
verify crypto compatibility
 ↓
READY
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

## `bounded-error`

After the configured maximum operation time:

```text
return I/O error
```

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
zram
independently encrypted swap
```

Forbidden:

```text
swapfile on a Maki volume
using the Maki /dev/nbdN device as swap
```

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

# 42. Phase 0 — Executable Specification

Build first:

```text
ReferenceBlockModel
CrashableBacking
FakeCryptoProvider
ManualClock
DeterministicScheduler
Failpoint framework
```

Test-first cases:

```text
normal write followed by crash
FUA followed by crash
FLUSH followed by crash
partial record
same-unit concurrent write
allocation mismatch
retry semaphore release
```

Phase gate:

```text
10,000+ randomized model sequences
durability oracle violations = 0
```

---

# 43. Phase 1 — Configuration and On-Disk Format

Test-first:

```text
geometry validation
slot-size calculation
integer overflow
superblock A/B
allocation metadata A/B
catalog A/B
malformed parser input
```

Implementation:

```text
config schema
codec
superblock
slot format
allocation metadata
shard catalog
format checker
```

Phase gate:

```text
parser panic = 0
golden vectors frozen
property/fuzz smoke tests pass
```

---

# 44. Phase 2 — CryptoProvider

Test-first:

```text
round trip
randomized ciphertext
maximum-size violation
batch reorder
missing item
duplicate item
compatibility mismatch
cross-endpoint decrypt
local AEAD context binding
secret logging leakage
```

Implementation:

```text
CryptoProvider
Fake Provider
AES-GCM-SIV
AES-XTS
key-source abstraction
provider self-test
```

---

# 45. Phase 3 — Journal and Recovery

Test-first:

```text
append
barrier
FUA
segment creation
directory fsync
partial journal tail
middle-record corruption
checkpointing
ENOSPC
allocation corruption
```

Failpoints are inserted at every persistence boundary.

Phase gate:

```text
10,000+ crash/recovery cycles
silent corruption = 0
```

---

# 46. Phase 4 — Block Core

Test-first:

```text
zero read
read/write
multi-unit request
partial-unit RMW
concurrent writes
concurrent read/write
FUA
FLUSH
cache-disabled differential model test
```

The implementation is continuously compared against `ReferenceBlockModel`.

Phase gate:

```text
100,000+ randomized I/O operations
model mismatch = 0
```

---

# 47. Phase 5 — Backpressure, Retry, and HA

Test-first:

```text
global semaphore
endpoint semaphore
byte semaphore

bounded queues

release permit during backoff

full jitter
retry budget
minimum probe rate

circuit transitions
endpoint failover
endpoint warm-up after recovery

queue saturation + FLUSH
queue saturation + FUA

100,000 pending requests
```

Phase gate:

```text
queue bound violation = 0
permit leak = 0
retry storm = 0
unbounded RSS growth = 0
```

---

# 48. Phase 6 — nbdkit Adapter

Test-first:

```text
get_size
block_size

read/write
FUA
FLUSH

parallel callbacks
panic boundary

zero fallback
trim disabled
multi-connection disabled

disconnect
clean detach
```

Implementation:

```text
maki-nbdkit cdylib
after_fork runtime
Unix Domain Socket
NBD attach helper
```

Phase gate:

```text
libnbd tests pass
/dev/nbd fio verify passes
FLUSH/FUA behavior matches model
```

This phase produces the local-crypto Linux NBD MVP.

---

# 49. Phase 7 — Daemon and Privilege Model

This phase is mandatory before production qualification.

## Test-first

```text
PRIV-001
Maki daemon UID != 0

PRIV-002
effective capability set == 0

PRIV-003
daemon cannot write another volume's backing

PRIV-004
daemon cannot modify arbitrary /etc files

PRIV-005
daemon cannot perform mount syscall

PRIV-006
unauthorized user cannot access NBD UDS

PRIV-007
unauthorized user cannot access control socket

PRIV-008
maki-admin group can perform status/reload

PRIV-009
maki-admin cannot perform attach/mount

PRIV-010
privileged helper cannot access crypto credentials

PRIV-011
duplicate attach rejected by volume lock

PRIV-012
systemd restarts daemon after failure

PRIV-013
daemon cannot enter READY without backing

PRIV-014
missing credential fails closed

PRIV-015
core dump generation is blocked

PRIV-016
normal I/O works under systemd sandbox
```

## Implementation

```text
maki system user/group
maki-admin group

systemd units
tmpfiles.d
sysusers.d

control socket ACL
NBD socket ACL

maki-attach helper

credential loading

volume locking

systemd sandboxing
```

## Phase gate

```text
daemon running as root = 0
unexpected capabilities = 0
unauthorized access success = 0
secret exposure = 0
```

---

# 50. Phase 8 — HTTP Remote Provider

Test-first:

```text
raw payload
JSON mapping
base64
hex

headers
query parameters
credentials

batch reorder
partial response

response-size limit

TLS CA
SAN
mTLS

HTTP 429
HTTP 503
timeout

body mapping self-test

absence of payload logging
```

Phase gate:

```text
fake HTTP chaos suite passes
vendor contract suite passes
cross-endpoint test passes
24-hour hardware-provider soak passes
```

---

# 51. Phase 9 — WebSocket and gRPC

WebSocket tests:

```text
correlation IDs
out-of-order responses
reconnection
stale responses
frame-size limits
```

gRPC tests:

```text
native protocol
dynamic descriptor
metadata
status mapping
message-size limits
```

Every transport MUST pass the same provider conformance suite.

---

# 52. Phase 10 — Cache and Operations

Test-first:

```text
versioned cache behavior
stale-read prevention
TTL
runtime resize
zeroization

metrics

online growth
growth during workload
crash during growth

mount guard

wrong volume UUID
missing mount
```

Phase gate:

```text
stale read = 0
plaintext leak = 0
growth corruption = 0
```

---

# 53. Phase 11 — Database Qualification

## SQLite

```text
WAL
DELETE journal
synchronous=FULL
process crash
provider outage
PRAGMA integrity_check
commit ledger
```

## PostgreSQL

```text
pgbench
fsync=on
synchronous_commit=on
full_page_writes=on
data_checksums=on

checkpoint
VACUUM
CREATE INDEX

WAL recovery
pg_amcheck
transaction ledger
```

## ClickHouse

```text
INSERT
merge
mutation
partition operations
CHECK TABLE
hash oracle
```

## MinIO

A dedicated Maki volume is recommended.

```text
multipart upload
large object
overwrite
range GET
restart
provider outage
SHA-256 oracle
```

Phase gate:

```text
DB corruption = 0
durable transaction loss = 0
silent corruption = 0
```

---

# 54. Phase 12 — Power-Loss Qualification

Test hierarchy:

```text
WSL
→ development and integration

QEMU/KVM
→ hard VM power cut

Bare-metal Linux
→ final durability qualification
```

Critical test:

```text
WRITE A
WRITE B
FLUSH success
WRITE C
power cut
```

Recovery requirement:

```text
A = new
B = new
C = old or new
```

FUA test:

```text
WRITE A + FUA success
power cut

A = new
```

---

# 55. CI Strategy

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
all phase gates
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
mode = "hybrid"

supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384

stateless = true
retry_safe = true

integrity = "none"
context_binding = "none"
replay_protection = "none"

[[crypto.http.endpoint]]
name = "crypto-a"
url = "https://crypto-a.internal"

[[crypto.http.endpoint]]
name = "crypto-b"
url = "https://crypto-b.internal"

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
socket = "/run/maki/postgres-prod/control.sock"
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
