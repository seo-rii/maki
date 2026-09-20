# Discard and space reclamation

Status: implemented with local regression qualification on 2026-09-20. The
default v2 format is unchanged. The new v3 mode has not yet repeated the external
VM power-off and database campaigns previously run for v2.

## Selecting the volume format

`maki volume create <config.toml> --discard` selects metadata envelope v3 for a
new volume. Ordinary creation keeps envelope v2 and does not advertise TRIM.
The envelope is independent of the provider's cryptographic `format_version`;
enabling discard does not change the provider context or ciphertext format.
Older Maki binaries refuse v3. Existing volumes are never converted by attach,
configuration reload, or a trim request. To use discard for existing data,
create a separate v3 volume and copy/restore the data using the application's
normal migration procedure.

## Logical discard and physical release

NBD TRIM discards the complete crypto units contained in its range. Partial
units at either edge remain unchanged. Trim is a hint, so an edge-only request
can complete without changing data. Discarding an already-zero unit does not
create a shard, reserve a slot, or append another journal record.

After a complete unit is discarded, reads return zero. A normal discard may
remain volatile; FLUSH and FUA use the same durable journal proof as writes.
Physical release happens during checkpointing. Thus completion of `fstrim`
does not imply that the backing filesystem has already reclaimed the space;
`maki checkpoint <config.toml>` applies durable discards.

Linux backing files use `FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE`: complete
filesystem blocks in the range can be released, partial blocks are zeroed, and
file length remains unchanged. Checkpointing combines adjacent eligible slots
within each shard so their shared filesystem blocks can also be released.
Filesystems may reject hole punching. Such a
backing can still retain the logical zero state without physical release.
Reclamation is measured using the backing file's allocated blocks, rather than
its apparent length. See the [Linux API contract](https://man7.org/linux/man-pages/man2/fallocate.2.html).

## Persistence ordering

V3 journal records with empty payloads represent discard. V2 retains its
existing interpretation. Every v3 shard has a separate replicated discard
bitmap. Reads consult it before allocation-map and slot-header fallback, so a
punched header cannot resurrect old data or appear to be a damaged live slot.
Both empty discard maps and their directory are durable before a new shard's
data file is created. A crash during map creation can therefore leave only
unused maps, not a data shard with unknown discard history. An existing data
shard with neither valid discard-map copy is refused during recovery.

Checkpoint data writes finish and sync before publication changes the logical
bitmap. Both complete discard-map copies and their directory are synced before
any slot is punched or the checkpoint sequence advances. The current store is
updated, preserving concurrently created shards. Clearing a discard bit for a
later write follows the same two-copy rule after the new slot data is synced.
An interrupted publication keeps the covering journal for retry or recovery.
Recovery rewrites the selected discard state into both copies even when both
loaded copies decode successfully: a failed earlier sync can leave a newer
copy readable only in the page cache.

A checkpoint never punches a unit if the live overlay has any newer version
than its captured tombstone. Even a newer discard can hide an intermediate
durable write whose reserved space must remain available after a crash. Recovery
replays ordered bitmap transitions with bounded batches and never punches slots;
this also preserves reservations for newer writes later in the replay stream.
If recovery consumes a discard whose physical release was interrupted, its
logical zero remains durable while the old physical allocation can remain.
After the entire replay finishes, the volume schedules a scan of persisted
discard maps. Each subsequent checkpoint retries at most 4,096 slot positions
from one shard, coalescing adjacent eligible slots. This uses one cursor and a
bounded candidate batch, without another volume-sized bitmap or payload list.
The background checkpoint worker runs these batches even with an empty journal;
after a successful batch it schedules the next without waiting another full
checkpoint interval. The volume lock is released between batches. A manual
`maki checkpoint` also advances one batch, so one command need not finish all
post-recovery reclamation.

The scan skips every unit with a remaining overlay version, including a newer
tombstone hiding an intermediate write reservation. Normal checkpointing handles
that newer version later. A failed punch or data sync leaves the cursor unchanged
for retry; the worker waits until its next wakeup after a failure. Unsupported
punching completes the hint without releasing physical blocks. Each attach starts
a new scan, so previously punched holes can be visited again. Recovery itself
still performs no physical release while replaying journal records.

These rules preserve the write-admission reservation contract. A later write to
a reclaimed slot must reserve its full destination again before being accepted.
The punch phase holds the volume publication lock, so a new write cannot reserve
the same slot between eligibility checking and physical release. Coalescing
reduces the number of punch calls, but a slow backing filesystem can still delay
foreground requests during this phase.

## Verification

`review_punch_hole.rs` checks actual Linux allocated-block reduction, stable file
length and neighboring bytes, unaligned ranges, overflow rejection, reopening
after sync, and reservation followed by rewriting. `review_discard_format.rs`
checks opt-in v3 creation, unchanged v2 defaults, unknown/mixed envelope rejection,
required proof and discard-map validation. Engine tests cover partial edges,
already-zero requests, cached reads, concurrent writes, FUA and crash recovery.
`review_discard_crash.rs` covers 112 sync/retry/restart/fallback combinations,
32 immediate simulated-crash cases, unsupported and partially failed punches,
repeated FUA discard, and transitions across replay batches. The separate model
suite runs eight fixed seeds with four mixed-write/discard crash epochs each
across four shards. The ext4 physical test discards 126 of 128 adjacent slots,
requires over 75% allocated-block reduction, and verifies retained neighbors,
reopening, and rewriting.
`review_discard_reclaim_retry.rs` covers idle checkpoint and worker progress after
replay, failed-release retry, preservation of newer write reservations, and the
per-checkpoint scan bound. The real-file suite also checks that an idle checkpoint
after recovery releases over 75% of blocks for the 126-of-128-slot discard case.

The complete workspace tests, formatting check, and strict all-target Clippy
passed against the isolated storage feature snapshot. The native userspace NBD
test executed through nbdkit and `libnbd.so.0` without skipping: it negotiated
TRIM, issued FUA write and trim, read zeroes, rewrote the range, and shut down.
Evidence: `~/logs/maki-discard-workspace-20260920T083655Z/` (`exit.status` 0);
the separately captured native run is `~/logs/maki-discard-native.ELD0mC.log`.

The post-recovery retry follow-up first reproduced four failing regressions
and a real-file run that retained all 1,160 allocated blocks. The implementation
passed all five retry tests, the complete core suite (251 passing, six ignored),
and strict core Clippy. Both real-file reclamation tests and formatting passed
in a separate frozen snapshot. Evidence:
`~/logs/maki-reclaim-green-20260920T093754Z/` and
`~/logs/maki-reclaim-physical-green-20260920T094025Z/` (both `exit.status` 0).
