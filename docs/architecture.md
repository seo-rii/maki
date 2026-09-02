# Architecture

Maki turns encrypted backing files into a byte-addressed Linux block device.
The storage engine does not require a specific cipher: cryptography is supplied
through a checked provider contract and may run locally or over the network.

## Data path

```text
Application or database
        |
       XFS
        |
       LVM
        |
   /dev/nbdN
        |
Linux NBD client
        |
     nbdkit
        |
  maki-nbdkit
        |
    maki-core -------- CryptoProvider
        |               |-- local AES-GCM-SIV / AES-XTS
encrypted backing       `-- HTTP / WebSocket / gRPC
```

The long-running data plane owns one volume. The separate `maki-attach` helper
performs privileged NBD, LVM, mount, and growth operations and never receives
crypto credentials.

## Components

| Crate | Responsibility |
|---|---|
| `maki-core` | Reads, writes, journaling, checkpointing, recovery, admission control, and metrics |
| `maki-format` | Configuration schema and versioned on-disk metadata |
| `maki-backing` | Escape-safe backing namespace and positional file I/O |
| `maki-crypto` | Provider contract, validation, flow control, retry, circuit breaker, and failover |
| `maki-crypto-*` | Local, HTTP, WebSocket, and gRPC provider implementations |
| `maki-cache` | Versioned plaintext read cache |
| `maki-nbdkit` | Blocking adapter, daemon assembly, and Linux C ABI shim |
| `maki-control` | Unprivileged control socket protocol |
| `maki-privileged` | Auditable attach, detach, mount, and growth plans |
| `maki-test-support` | Durability oracle, crash backing, fake provider, manual clock, and failpoints |

## Read and write semantics

The engine divides the device into fixed crypto units. Reads take a consistent
ciphertext snapshot per unit, decrypt in provider-sized batches, and return
zeros for unallocated units. A racing read observes either the old or new unit,
never a torn mixture.

Writes lock touched units in ascending order. Partial-unit writes perform a
read-modify-write, encryption happens outside the volume lock, and ciphertext
records are appended to the journal before becoming visible. FUA synchronizes
the complete request; FLUSH is an ordered durability barrier for all preceding
writes.

## On-disk state

| Structure | Protection | Role |
|---|---|---|
| Superblock | Two generations plus CRC | Volume identity, geometry, provider type, and compatibility ID |
| Shard catalog | Two generations plus CRC | Durable set of allocated shard files |
| Allocation map | Per-shard A/B copies | Distinguishes unwritten units from allocated slots |
| Slot | Header CRC and ciphertext CRC | Stores one encrypted unit and write sequence |
| Journal segment | Header and record CRCs | Ordered ciphertext writes pending checkpoint |
| Checkpoint state | Two generations plus CRC | Highest durably applied journal sequence |

Metadata updates overwrite the stale A/B side and then advance generation. A
torn new copy therefore falls back to the older valid generation. Journal tails
may be truncated after a crash; corruption before a valid successor record is a
hard error and attachment fails.

## Recovery and checkpointing

Recovery acquires the volume lock, validates superblock and allocation state,
scans journal segments, rejects sequence gaps or foreign records, and rebuilds
the in-memory overlay from records newer than the checkpoint.

The overlay keeps both the latest version and the latest durable version for
each unit. This distinction is required when a newer unflushed write exists at
checkpoint time. Checkpointing writes slots, synchronizes data and metadata,
commits checkpoint state, and only then deletes covered journal segments.

## Provider boundary

Every provider declares plaintext sizes, maximum ciphertext size, batching,
retry safety, integrity, context binding, and a compatibility identity. Maki
validates response count, order, unit index, and size on every call. A provider
self-test runs before attach, and multi-endpoint configurations verify
cross-endpoint ciphertext compatibility.

Provider errors are classified as throttled, retryable, endpoint-fatal,
request-fatal, or provider-fatal. Only eligible failures enter bounded full-
jitter retry. Retry budgets, circuit breakers, endpoint limits, and global byte
and request semaphores prevent a failing provider from causing unbounded work.

## Cache and growth

The optional cache stores plaintext under `(unit_index, write_sequence)`. A
version mismatch is always a miss, so correctness does not depend on invalidation
timing. Entries use zeroizing buffers and are never written back.

The virtual device capacity is fixed by the volume geometry. Maki creates
backing shards lazily as writes reach new regions. Filesystem-level growth is a
separate privileged `lvextend` and `xfs_growfs` operation.

## Security boundaries

- The nbdkit data plane runs as the `maki` user with no Linux capabilities.
- The control socket exposes status, metrics, checkpoint, and reload only.
- Privileged storage operations are isolated in `maki-attach`.
- Keys and plaintext use redacted, zeroizing buffers and must not be logged.
- Configuration rejects literal values for sensitive headers.
- A malformed provider response is treated as a contract failure, never trusted.

See [Configuration](configuration.md), [Operations](operations.md), and the
[technical specification](../SPEC.md) for detailed contracts.
