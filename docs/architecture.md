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
| Superblock | Two generations plus CRC | Volume identity, geometry, provider type, key name, and compatibility ID |
| Key canary | Two generations plus CRC, written at first attach | Provider/key-bound ciphertext of a fixed plaintext; must decrypt on every attach |
| Shard catalog | Two generations plus CRC | Durable set of allocated shard files |
| Allocation map | Per-shard A/B copies | Distinguishes unwritten units from allocated slots |
| Slot | Header CRC and ciphertext CRC | Stores one encrypted unit and write sequence |
| Journal segment | Header and record CRCs | Ordered ciphertext writes pending checkpoint |
| Journal durable mark | CRC, single copy, never fsync'd | Lower bound on the fdatasync'd prefix of the active segment |
| Checkpoint state | Two generations plus CRC, written at creation | Highest durably applied journal sequence |

Metadata updates overwrite the stale A/B side and then advance generation. A
torn new copy therefore falls back to the older valid generation. A side that
is absent, empty, short, or fails its CRC is an invalid copy; any other read
error is an I/O error and refuses attach rather than silently selecting the
other side.

## Recovery and checkpointing

Recovery acquires the volume lock, validates superblock and allocation state,
loads the checkpoint state (required on every volume), scans journal segments,
and rebuilds the in-memory overlay from records newer than the checkpoint. It
fails closed: the oldest surviving segment must bridge from the checkpoint
boundary, segments must be contiguous and carry the volume's UUID, a segment
larger than the writer can produce is rejected before it is read, and a
complete-but-invalid final segment header is treated as damage rather than as
a creation crash.

Journal tails may be truncated after a crash, but only after the point the
durable mark proves was fdatasync'd. Damage inside that prefix is corruption
even at the very end of the segment; damage after it is a torn tail even when
an intact record follows, because unsynced records may persist in any order.
The [review remediation log](review-remediation.md) describes these rules in
detail.

The overlay keeps both the latest version and the latest durable version for
each unit. This distinction is required when a newer unflushed write exists at
checkpoint time. The durable boundary can move inside `append` itself (an
automatic segment roll fdatasyncs the sealed segment), so the volume promotes
the overlay after every journal operation and *before* publishing a newer
version of the same unit; checkpointing re-derives the checkpointable set from
the journal's own boundary rather than trusting earlier promotions.

Checkpointing writes slots, synchronizes data, writes allocation metadata and
fsyncs the data directory before clearing any dirty flag, commits checkpoint
state, and only then deletes covered journal segments. A checkpoint that fails
part-way leaves every incomplete step marked for the retry.

Checkpoints are not only a shutdown step. A background worker checkpoints when
the journal crosses a size watermark, when backing free space drops below the
checkpoint reserve, and on a time interval (syncing unsynced records first). The
write path forces a journal sync once unsynced bytes reach their limit, reclaims
inline at the hard journal limit, and refuses writes with ENOSPC when the
backing is below its emergency reserve or the journal cannot be reclaimed. A
failed reclaim marks the engine degraded until a later checkpoint succeeds; the
[remediation log](review-remediation.md#bounded-journal) lists the exact rules.

## Provider boundary

Every provider declares plaintext sizes, maximum ciphertext size, batching,
retry safety, integrity, context binding, and a compatibility identity. Maki
validates response count, order, unit index, and size on every call. A provider
self-test runs before attach, and multi-endpoint configurations verify
cross-endpoint ciphertext compatibility.

The self-test proves only that the provider is coherent with itself. The key
canary proves that it is the provider and key the volume was written with: a
fixed, volume-bound plaintext encrypted at a reserved unit index on the first
attach and decrypted back on every later one. The configured provider type and
key name are also compared with the superblock. The non-cryptographic `fake`
provider is compiled in only with the `fake-provider` feature and refused at
configuration validation otherwise.

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
