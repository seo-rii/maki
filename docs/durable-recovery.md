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

The [2026-09-19 package and migration qualification](qualification/package-topology-migration-validation-2026-09-19.md)
exercised this procedure for one cleanly drained envelope-v1 SQLite source. The
matching old reader produced a native backup, the current writable path refused
the unchanged v1 superblocks, and restoring into a fresh v2 volume matched the
source logical hash. That result does not certify an ambiguous v1 tail, a live
snapshot, another database engine or production cutover.

## Protected outer backing formats

The optional local-witness outer format remains unchanged. Remote witnesses
select a distinct outer marker, `MAKI-REMOTE-WITNESS-COW-V2\n`, with a new
physical namespace for each writer fence/session. Its inner flat manifest
remains version 1; the independent witness state uses the version 2
`MAKIRW02` canonical envelope and checksum, with a private session-authorization
digest. The TLS request protocol is version 2. These versions are separate from the volume's
superblock envelope and crypto context. Older binaries and mismatched local
or remote configurations refuse the remote marker.

There is no in-place conversion between plain, local-witness and remote-witness
backings. Create a separate empty destination with a fresh witness identity,
then perform and verify a logical migration. Moving an existing file-backed
remote authority to quorum-backed service also requires a separate destination
with a fresh storage identity and verified logical copy; duplicating its
authority value while the old service can still run would fork trusted history.
Never change marker bytes or copy an old witness record over the current
authority.

Remote authority/wire v1 is refused before a server binds or serves requests.
There is no automatic or in-place v1-to-v2 authority upgrade: v1 never stored
private session ownership. Preserve the old authority and backing as evidence;
use the matching old software with isolated access to read the exact trusted
source. Create a separate v2 authority with a fresh identity and destination,
then perform and verify a logical copy before cutover. Do not replace magic
bytes, reset a fence, or copy the old authority into the destination. The local
witness, remote COW marker, manifest and supplementary enrollment v1 bytes,
inner superblock envelopes and crypto AAD are unchanged. See the
[service upgrade procedure](remote-witness-service.md#authority-protocol-compatibility).

Remote same-identity restoration is an explicit administrator operation: approve
the current fence/root and the independently recorded snapshot root, verify and
synchronize the copy, then advance the authority's generation and restore epoch.
It deliberately replaces application history with the approved older snapshot;
normal FLUSH/FUA crash guarantees do not mean that later acknowledged writes
survive this operator-directed restore. Ordinary attach never accepts old roots.
See [remote witness operations](remote-witness-service.md) for commands,
retention costs and interrupted enrollment/recovery behavior.

New remote creation also writes `remote.enrollment` before its first claim.
This supplementary immutable envelope is exactly 64 bytes: eight-byte
`MAKIRE01` marker, 16-byte storage identity, little-endian 64-bit approved
capacity, and a domain-separated SHA-256 checksum of the preceding 32 bytes.
It has its own version 1 encoding. It does not change the remote COW marker,
flat manifest encoding, witness state envelope, inner superblock or crypto
context. Already activated remote volumes without this supplementary file
remain readable; there is no in-place conversion or authority recreation.

Interrupted initial enrollment can be explicitly resumed under the same
storage identity only when the independent authority has never selected any
current descriptor. An administrator approves the exact observed fence,
storage identity and configuration capacity. Recovery uses full-record CAS
and a higher fence/session, verifies or explicitly creates the missing
identity/capacity binding, and synchronizes a fresh namespace before activation.
This covers a valid marker-only legacy attempt, an uncertain initial claim and
partially reserved unactivated namespaces. Subsequent GC may retire recognized
quiescent lower-fence candidates, while
live handles and unknown artifacts remain protected. Recovery does not accept
corrupt or differently bound enrollment metadata. A successful
activation, even when its reply was lost, permanently rules out enrollment
reset. Ordinary takeover retains that selected manifest; incomplete inner
volume initialization after activation still requires explicit inspection and
recovery. See [initial enrollment recovery](rollback-protection.md#resume-interrupted-initial-enrollment).

Remote namespace retirement preserves the same outer format. GC first takes
the exclusive lifetime lock of an old lower-fence namespace, retaining the
current, pending and restore-source namespaces. It renames a retired namespace
without replacement to `.remote-gc-{namespace}` and synchronizes the root
directory before removing its contents. These supplementary tombstones let a
later GC pass resume interrupted removal. A root operation lock serializes
retirement with copying a selected source; a namespace still held by an old
writer is skipped. GC does not remove external backups or recreate any witness
history.

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

Recovery rejects a checkpoint, accepted record range, segment index or
advisory index whose successor cannot be represented, before rewriting
checkpoint/proof metadata or applying journal repairs. The last usable
sequence/index (`u64::MAX - 1`) remains readable; exhaustion does not permit
wraparound or index reuse. A writer refuses an exhausted append or segment
roll before changing storage, including before sealing the previous segment.
This is an error-handling bound, not a change to the on-disk encoding.

Proof publication adds preserved/replacement metadata-file syncs and directory
syncs to journal barriers. The current store uses two complete A/B stores;
measure FUA/FLUSH tail latency and recovery time on the intended backing before
choosing a production configuration.

Journal scanning streams segment contents. Volume attach first validates the
complete accepted journal while discarding replay payloads. After durable
prefix rewrite, proof publication and metadata repair, it scans the journal a
second time and applies accepted records to checkpoint slots through a
ciphertext batch with a 1 MiB grouping target. A geometry-valid record may
exceed the target; full or oversized batches are applied immediately, before
the scanner allocates another payload. Slot headers and ciphertext are written
separately, avoiding an additional payload-sized encoding copy. Within each
batch, only the final sequence
for each unit writes slot data; a final discard skips earlier writes. All
records still contribute allocation/discard evidence in sequence order, and
batch boundaries are unchanged. Shard data and allocation metadata are
synchronized before checkpoint state advances, and covered segments are
removed only afterward. A crash anywhere in that replay can retry from the
still-durable journal. Every record still undergoes sequence, CRC, geometry and
required-boundary checks; a damaged superseded record cannot be skipped.

For a target T = 1 MiB and maximum ciphertext payload C, the replay's live
payload storage is bounded by T + C: a partial batch plus the next scanned
record. Batch record/index metadata, shard maps/catalogs, allocator overhead,
provider/cache state and filesystem cache are additional costs. For example,
C = 4 KiB gives a payload allowance of 1 MiB + 4 KiB; C = 16 MiB gives 17 MiB.
These are payload allowances, not RSS limits or minimum RAM recommendations.
The `review_f06_large_ciphertexts_do_not_overlap_in_replay_or_slot_encoding`
allocator regression covers records just below, at and above the batching
boundary and two consecutive 16 MiB records, including recovered data checks.

The controlled real-file tests compare 1 MiB and 64 MiB journal histories:

| Measured heap peak | 1 MiB history | 64 MiB history |
|---|---:|---:|
| Volume recovery before latest-record retention, four overwritten units | 1,060,000 bytes | 67,765,408 bytes |
| Volume recovery with latest-record retention, before overlay sharing, the same four units | 33,988 bytes | 33,988 bytes |
| Volume recovery with latest-record retention and shared overlay, the same four units | 21,280 bytes | 21,280 bytes |
| Checkpoint-covered public scan, including v2 metadata loading | 8,260 bytes | 8,260 bytes |
| Deep checker before discarding validated replay payloads | 1,060,242 bytes | 67,765,650 bytes |
| Deep checker with report-only retention, the same four units | 9,176 bytes | 9,176 bytes |

These are allocations made by the measured recovery thread, not process RSS or
filesystem cache. Fixed stack scratch is separate. The earlier 488-byte
covered-scan result in `133d36d` predates v2 envelope/proof loading and is a
historical intermediate result.

An unchanged latest/durable overlay version now shares its immutable
ciphertext, including the internal checkpoint snapshot. A newer volatile
overwrite and its older durable predecessor still have separate storage.
Public `OverlayVersion` and `collect_durable` keep their independently owned
vector contract. `overlay.bytes()` also retains the conservative logical charge
for both latest and durable versions, even when they share one allocation.

With 64 units of 64 KiB ciphertext, the measured additional allocation peak
for promotion fell from 4,192,480 to 0 bytes. The real-file checkpoint peak
fell from 4,262,528 to 66,688 bytes; its per-slot encoding allocation remains.
These are controlled thread-local heap measurements, not total resident memory
or a new maximum supported overlay size.

Revision `733833c` removes the attach-time replay payload set: controlled
real-file recovery peaked at 1,079,060 bytes for 4,096 distinct 4 KiB records,
and at 1,068,272 bytes for 16,384 overwrites, while advancing the checkpoint
and pruning every covered segment. A crash injected while syncing replayed
slot data refused attach; the next recovery reproduced the exact state from
the journal. These measurements bound the replay payload batch, not the total
process. Segment metadata, shard catalogs, allocation maps, runtime/provider
state and filesystem cache still consume memory. The public `scan_journal` and
`recovery::recover` APIs retain their all-record return contract. The deep
checker continues to discard payloads immediately and does not apply repairs.
No arbitrary RAM refusal limit has been applied to existing readable volumes.

The MAKI-020 integration in `1bc0ab5` passed 768 workspace tests (10 ignored),
all nine selected release gates, and Linux/Windows CI. The subsequent latest-
record retention change is tracked separately. These results do not establish
actual DB or hardware power-loss qualification. See the
[readiness record](qualification/historical-reviews/production-readiness-review-2026-09-08.md) for exact revisions
and completed versus pending validation, and
[storage recovery](storage-recovery.md) for the separate NBD/LVM/mount cleanup
limitations.
