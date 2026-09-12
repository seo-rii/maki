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
| Superblock | Two generations plus CRC; new volumes use envelope v2 | Volume identity, geometry, provider type, key name, compatibility ID, and required recovery policy |
| Key canary | Two generations plus CRC, written at first attach | Provider/key-bound ciphertext of a fixed plaintext; must decrypt on every attach |
| Shard catalog | Two generations plus CRC | Durable set of allocated shard files |
| Allocation map | Per-shard A/B copies | Distinguishes unwritten units from allocated slots |
| Slot | Header CRC and ciphertext CRC | Stores one encrypted unit and write sequence |
| Journal segment | Header and record CRCs | Ordered ciphertext writes pending checkpoint |
| Journal durable proof | Two 64-byte CRC records, both published before a barrier succeeds | Required sequence and exact segment/record-end boundary for v2 recovery |
| Legacy journal durable mark | CRC, single advisory copy | Retained advisory metadata; does not replace or weaken the v2 proof requirement |
| Checkpoint state | Two generations plus CRC, written at creation | Highest durably applied journal sequence |

Metadata updates select an absent, invalid, or older A/B side for replacement.
Before touching it, the store rewrites the preserved, typed-valid copy's exact
bytes without truncation, synchronizes that file, and synchronizes its parent
directory. Only then does it advance the generation, write the replacement,
and synchronize the new contents. The caller must synchronize the replacement's
directory entry when it creates a file.

This preservation step also runs after a failed store or a process restart:
readable, CRC-valid bytes may still be volatile, and writeback errors can clear
dirty page-cache bits without persisting them. If preservation fails, the
replacement side is untouched. A torn replacement can therefore fall back to
the preserved generation. A side that is absent, empty, short, or fails its
CRC or typed decode is an invalid copy; any other read error is an I/O error
and refuses attach rather than silently selecting the other side.

The required durable-proof store prevalidates future versions and semantic
consistency before using A/B storage. It performs two publications of the same
horizon, including directory syncs, so both copies attest every successfully
acknowledged boundary. One ordinary A/B update would leave the fallback horizon
behind an ACK. Unsupported proof versions, contradictory generations and
regressing horizons therefore fail explicitly rather than selecting or
overwriting a convenient older side.

Envelope v2 is distinct from the crypto AAD's `format_version`. Old binaries
reject v2; the current writable recovery path refuses legacy v1. Read-only
legacy inspection remains available with a warning. The
[compatibility and migration procedure](durable-recovery.md) requires a separate
verified data migration; there is no automatic in-place upgrade.

## Recovery and checkpointing

Recovery acquires the volume lock, checks the superblock envelope and required
proof, validates allocation state, loads checkpoint state, scans journal segments,
and rebuilds the in-memory overlay from records newer than the checkpoint. It
fails closed: the oldest surviving segment must bridge from the checkpoint
boundary, segments must be contiguous and carry the volume's UUID, a segment
larger than the writer can produce is rejected before it is read, and a
complete-but-invalid final segment header is treated as damage rather than as
a creation crash.

The journal above the selected checkpoint must bridge through the proof's
required sequence and exact record-end offset before recovery changes metadata.
A missing final segment, a shortened complete-record prefix, or corruption
inside that required prefix fails explicitly. A proof may name a pruned segment
only when the checkpoint already covers its horizon. Both proof copies absent
or invalid is an error even for an empty-looking v2 volume.

Unproven final-tail bytes may be truncated after a crash. Intact later records
do not prove the durability of earlier damaged bytes, because unsynced sectors
may persist out of order. A missing/stale advisory mark cannot weaken the v2
proof requirement. Recovered sequence/index bookkeeping also accounts for proof
metadata that can outlive the segment it names.

A failed append can leave bytes beyond the last accepted record. The writer
retains a cleanup flag until truncation and synchronization succeed, including
when the next operation is a shorter write, FLUSH, or segment roll.

After a journal writeback error, a plain fsync retry may leave clean but
unpersisted page-cache bytes behind. The writer re-reads and rewrites its
accepted pending range in 64 KiB chunks, compares an ephemeral streaming
fingerprint, and only then synchronizes it. Recovery similarly binds each
prefix to the bytes accepted by its scan, rewrites and verifies that prefix,
then synchronizes before publishing both required proofs. Changed bytes refuse
recovery or the durability acknowledgement. Normal successful live flushes
avoid this extra rewrite; recovery pays an additional pass over valid data.
While a rewrite is still owed, the engine reports the volume `degraded` and
`journal_writeback_uncertain`, and counts `journal_sync_failures_total`; a
successful barrier clears the flag, a successful checkpoint does not. Proof
publication failure also keeps the barrier pending, including when its retry
has no new append. Data sync alone does not advance the public durable boundary
or make those records checkpoint-eligible. Recovery publishes every accepted
horizon to both proof copies before READY.

Segment scanning uses fixed 64 KiB scratch and discards checkpoint-covered
payloads as they are validated. Volume attach retains only the latest record
per unit, and the deep checker discards each validated payload after counting
it. With shared overlay storage, the four-unit overwrite regression measures
21,280 bytes of extra heap
for recovery and 9,176 bytes for deep checking at both 1 MiB and 64 MiB history.
Distinct units, different latest/durable versions and segment/allocation metadata
still consume memory; public all-record APIs retain their return contract. See the
[measurements and limits](durable-recovery.md#cost-and-verification-limits).

The overlay keeps both the latest version and the latest durable version for
each unit. This distinction is required when a newer unflushed write exists at
checkpoint time. The durable boundary can move inside `append` itself: an
automatic segment roll synchronizes the sealed segment and publishes its proof.
The volume promotes the overlay after every journal operation and *before* publishing a newer
version of the same unit; checkpointing re-derives the checkpointable set from
the journal's own boundary rather than trusting earlier promotions.

Checkpointing writes slots, synchronizes data, writes allocation metadata and
fsyncs the data directory before clearing any dirty flag, commits checkpoint
state, and only then deletes covered journal segments. A checkpoint that fails
part-way leaves every incomplete step marked for the retry.

Proof replicas share the backing filesystem. Their CRCs do not provide
authenticity or an external freshness anchor against coordinated valid rollback.
Additional proof-file and directory syncs need target-system latency measurement;
the current protocol prioritizes durable evidence over reducing barrier calls.

Slot headers are authoritative; the shard catalog and the allocation maps are
accelerators that an A/B fallback can leave one generation behind. Opening the
store adopts data files the catalog copy does not list and, for a shard with an
invalid or absent allocation copy, audits its slot headers and repairs the map
in memory (the next checkpoint persists it; the deep check reports it). Reading
a cleared slot probes its header before answering zeros. A cataloged shard with
no valid allocation copy at all refuses attach.

In debug builds the overlay, journal, and volume verify their invariants after
every mutation (`check_invariants`), so the randomized suites described in
[testing](testing.md) fail at the first accounting slip rather than at a later
symptom.

Checkpoints are not only a shutdown step. A background worker checkpoints when
the journal crosses a size watermark, when backing free space drops below the
checkpoint reserve, and on a time interval (syncing unsynced records first). The
write path forces a journal sync once unsynced bytes reach their limit, reclaims
inline at the hard journal limit, and refuses writes with ENOSPC unless fresh
backing space covers the emergency reserve, configured checkpoint headroom,
projected record bytes, and all segment headers created by that write, or when
the journal cannot be
reclaimed. A
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

Remote providers sit behind a batch scheduler: concurrent requests are
coalesced into bounded provider calls (targets, maxima, and a maximum wait from
configuration), whole requests are never split, and each lane's pending work is
bounded by count and bytes so a slow provider applies backpressure instead of
growing memory. Each lane keeps several batches in flight (bounded by
`limits.max_crypto_inflight_batches`), so one slow batch does not serialize the
requests behind it. Local providers are called directly.

Queued groups own their payload and admission charge together. Cancellation
removes the complete group even if it is behind another group waiting for an
RPC slot. An active coalesced RPC remains necessary until its last caller
leaves. For bounded-error calls, one caller budget covers admission, coalescing,
the slot wait, and the provider response; dispatch does not restart it.

The dispatcher validates quarantined endpoints in background tasks, never on
the request path. Each admitted call owns a circuit-breaker permit for its
generation. Completion, operation deadline, cancellation, request/provider
errors, and retry-budget refusal all release a HalfOpen probe slot; outcomes
that are not endpoint failures do not advance the failure count. A stale
permit cannot affect a later breaker generation. Abandoning an RPC also
releases its transport inflight slot.

The HTTP transport never follows a redirect (a 3xx fails the endpoint over
rather than re-sending plaintext to a server-chosen URL). It removes request
URLs from transport errors before classification and formatting, keeping query
credentials out of those error messages. Each WebSocket connection generation
owns both reader and writer futures in one task. Timeout, request cancellation,
connection replacement, and provider drop retire that generation, cancel its
task, release its socket, and fail its pending requests without disturbing a
successor connection.

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
- The plugin advertises configured NBD block sizes and validates request
  length, range, and alignment before copying write plaintext into Maki or
  submitting work to the engine.
- The control socket exposes status, metrics, checkpoint, and reload only.
- Socket creation keeps the process umask unchanged. A private staging
  directory hides the socket until its group and mode are set; rename then
  publishes the ready socket at its configured path.
- Its default path is `/run/maki-control/<volume>/control.sock`; the packaged
  runtime layout lets `maki-admin` reach it through a separate directory tree
  while keeping the NBD runtime tree restricted to the daemon's group.
- Privileged storage operations are isolated in `maki-attach`.
- Keys and plaintext must not be logged. `SecretBuffer` owners are redacted
  and zeroized; remote serialization also creates allocations with separate
  lifetimes. See [transport memory protection](transport-memory.md) for the
  verified ownership boundaries and remaining copies.
- Optional buffer page locks have shared ownership: buffers on the same page
  keep it locked until the final owner releases it. Drop zeroizes before
  releasing ownership; `into_vec` transfers zeroization to the caller and
  releases only that buffer's lock ownership.
- Configuration rejects literal values for sensitive headers.
- Repeated credential names must declare the same source throughout a volume
  configuration; conflicting sources are rejected before credentials load.
- A malformed provider response is treated as a contract failure, never trusted.

See [Configuration](configuration.md), [Operations](operations.md), and the
[technical specification](../SPEC.md) for detailed contracts.
