# Durable recovery and volume compatibility

## Before replacing an existing installation

New volumes use **superblock envelope v2** and require
`journal/durable-proof.a` and `journal/durable-proof.b`. Binaries that only
understand envelope v1 reject these volumes. This envelope version is separate
from the crypto context's `format_version`; the latter is unchanged, including
its use in authenticated associated data.

The current writable recovery path refuses envelope-v1 volumes before changing
recovery metadata. It may acquire or create the advisory volume lock first.
Read-only checks still inspect v1 and report a legacy warning: those checks
cannot reconstruct a missing acknowledgement horizon or certify ambiguous
history. There is **no automatic in-place upgrade** or downgrade procedure.
Never delete proof files, alter version bytes, or reinitialize an existing
volume to silence a refusal.

For existing data, prepare an explicit migration:

1. Stop writers and automatic restarts. Preserve an untouched backing copy,
   the old executable, configuration, provider identity, and required keys or
   credential material. Protect secrets separately from general logs/backups.
2. Use an isolated recovery copy with the matching old software and provider
   if legacy recovery is needed. Keep the original untouched. A legacy tail
   may be indistinguishable from damaged acknowledged data when its advisory
   mark is missing or stale; successful old-version recovery does not certify
   that history. Resolve ambiguity using independent backups and external
   transaction/hash records before treating the source as complete.
3. Create a separate, empty v2 volume and restore a DB-native backup or perform
   a verified logical data copy. This is a data migration, not a metadata edit.
4. Verify the destination's logical contents and database consistency against
   the source and independent records, exercise backup restoration, and qualify
   its storage/provider configuration before switching the workload. Retain the
   preserved source until that verification and retention policy permit removal.

No command in this build performs those migration steps automatically.

## Required horizon and acknowledgement ordering

Each proof is a fixed 64-byte CRC-protected record containing its generation,
volume UUID, durable sequence, segment index, and exact durable record-end
offset. Sequence zero uses index zero and size zero. Creation durably
initializes both copies and their directory entries before publishing the v2
superblock. Missing or invalid copies on both sides refuse recovery, even when
the volume otherwise appears empty.

A barrier first synchronizes its journal data. The proof store then performs
two A/B publications of the same horizon. Each publication rewrites and syncs
the highest valid preserved copy before replacing the lower/invalid side;
directory entries are synchronized as part of publication. Only after both
copies are durable may the writer advance its public `durable_sequence` and
complete FLUSH/FUA. That public boundary also gates checkpoint eligibility.
The copies may have different generations but attest the same horizon after
a successful advance.

One missing, stale, or corrupt copy cannot lower the acknowledged horizon when
the other retains the current proof. Hard I/O errors, unsupported proof
versions, foreign volume identity, contradictory generations, and regressing
horizons refuse the operation. A new empty segment does not move the prior
sequence's proof to a different record end.

Failure of data sync or proof publication leaves the barrier pending. A retry,
including a FLUSH with no new append, rewrites and verifies the accepted data
range before syncing and completing proof publication. A plain retry of sync
is insufficient after writeback EIO may have cleared dirty page-cache bits.
Failed proof publication does not make new records checkpoint-eligible.

## Recovery, corruption and checkpoint pruning

Recovery loads the required proof before applying repairs. Above the selected
checkpoint, the journal must bridge through the required sequence and match
its exact segment/record-end boundary. A missing final segment or a file
truncated exactly at an earlier complete record therefore fails explicitly.
If the checkpoint already covers the horizon, its old segment may legitimately
have been pruned; checkpointing does not lower the horizon.

Unproven final-tail bytes may be discarded after a crash. Intact later records
do not prove that earlier damaged bytes were durable: unsynced sectors may
persist out of order. Recovery rewrites, verifies, and synchronizes every
accepted prefix, then durably publishes the accepted horizon to both proof
copies before READY. The old single-file `durable-mark` remains advisory; it
cannot replace or weaken the v2 proof requirement.

These local CRC records do not authenticate metadata or prevent coordinated
valid rollback of both copies and the backing contents. They also cannot
establish previously lost legacy history. The two files share the backing
filesystem and are logical replicas, not independent physical failure domains.
The corruption policy is preservation of acknowledged data or explicit
refusal, not guaranteed availability after arbitrary damage.

## Cost and verification limits

Proof publication adds preserved/replacement metadata-file syncs and directory
syncs to journal barriers. The current store uses two complete A/B stores;
measure FUA/FLUSH tail latency and recovery time on the intended backing before
choosing a production configuration.

Journal scanning streams segment contents. Volume attach additionally retains
only the latest validated record per unit, so repeated overwrites do not retain
all historical payloads or fill the overlay's pending-promotion index. Every
record still undergoes sequence, CRC, geometry and required-boundary checks;
a damaged superseded record cannot be skipped.

The controlled real-file tests compare 1 MiB and 64 MiB journal histories:

| Measured heap peak | 1 MiB history | 64 MiB history |
|---|---:|---:|
| Volume recovery before latest-record retention, four overwritten units | 1,060,000 bytes | 67,765,408 bytes |
| Volume recovery with latest-record retention, the same four units | 33,988 bytes | 33,988 bytes |
| Checkpoint-covered public scan, including v2 metadata loading | 8,260 bytes | 8,260 bytes |

These are allocations made by the measured recovery thread, not process RSS or
filesystem cache. Fixed stack scratch is separate. The earlier 488-byte
covered-scan result in `133d36d` predates v2 envelope/proof loading and is a
historical intermediate result.

MAKI-025 remains partial. Distinct units, the overlay's latest/durable copies,
segment metadata, shard catalogs and allocation maps still consume memory.
The public `scan_journal` and `recovery::recover` APIs retain their all-record
return contract; the deep checker still uses that public scan. No new arbitrary
RAM refusal limit has been applied to existing readable volumes.

The MAKI-020 integration in `1bc0ab5` passed 768 workspace tests (10 ignored),
all nine selected release gates, and Linux/Windows CI. The subsequent latest-
record retention change is tracked separately. These results do not establish
actual DB or hardware power-loss qualification. See the
[readiness record](production-readiness-review-2026-09-08.md) for exact revisions
and completed versus pending validation, and
[storage recovery](storage-recovery.md) for the separate NBD/LVM/mount cleanup
limitations.
