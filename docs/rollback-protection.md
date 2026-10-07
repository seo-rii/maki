# Rollback-protected backing

Status: experimental implementation, updated 2026-10-07. This is an explicitly selected
Linux storage format for new volumes. Default v2/v3 directory backings retain
their existing rollback limitation. Production qualification of this new format
is still pending; earlier v2/v3 GCE reset and RSS results do not qualify it.

## Trust boundary

The protected backing keeps its current authenticated manifest root in a
separate **trusted witness directory**. A lifetime exclusive witness lock allows
one writer. The witness contains a storage identity, monotonically increasing
generation and SHA-256 manifest root. It must survive independently of backing
snapshots and must not be restored, replaced or deleted with them.

The implementation rejects nested directories and a witness on the same
filesystem (`st_dev`) as the backing. Different filesystems alone do not prove
independent administration or snapshot policies. Use a separately managed,
durable local filesystem with working file locks, atomic rename and directory
fsync. A RAM filesystem, network filesystem, coordinated whole-host snapshot,
or an operator able to replace the witness is outside this protection claim.
Tests use a RAM filesystem solely to exercise the separate-device boundary.

Replacing an old valid ciphertext page fails authentication against the current
manifest. Restoring an older complete backing fails comparison with the current
witness. Missing or corrupt committed evidence refuses attachment; an observed
witness mismatch or uncertain storage commit stops every handle in that session.
Cached plaintext and journal-overlay reads also check the freshness authority.
The provider's advertised replay-protection capability is not changed by this
storage option.

## Configuration and creation

Merge these sections into a valid small-volume configuration, retaining the
provider, credentials and other required sections:

```toml
[volume]
name = "protected"
max_virtual_size = "16MiB"
shard_logical_size = "8MiB"
device_block_size = 4096
crypto_unit_size = 4096

[backing]
root = "/var/lib/maki/protected"
journal_segment_size = "1MiB"
journal_max_bytes = "8MiB"
checkpoint_reserve_bytes = "2MiB"
journal_emergency_reserve_bytes = "2MiB"

[backing.rollback_protection]
witness_root = "/mnt/maki-witness/protected"
capacity = "128MiB"
```

Both directories must be empty for creation. Provision the independent witness
mount first and give the daemon user exclusive access to its per-volume
directory. Run `maki volume create <config.toml>` or add `--discard` for a v3
volume. An existing raw or protected backing is refused; there is no implicit
enrollment, in-place conversion or automatic witness recreation.

The packaged daemon uses `ProtectSystem=strict`. For this example, add a
per-instance systemd drop-in to `maki@protected.service`:

```ini
[Unit]
RequiresMountsFor=/mnt/maki-witness/protected

[Service]
ReadWritePaths=/mnt/maki-witness/protected
```

The existing backing access rule remains necessary. Give other custom backing
paths their own explicit access rule. The witness directory is sensitive state,
not a cache. Do not include it in the backing's restore operation.

Use `maki check <config.toml> --deep` or `maki volume inspect <config.toml>` while
the volume is detached. These acquire the exclusive witness session and
reestablish the selected witness record's durability without advancing it. The
root-only `maki-check` utility cannot open this outer format. Removing the
rollback configuration stanza does not enable raw fallback.

## Capacity and durability

`capacity` means reserved logical **backing pages**, including journal, slots
and metadata, not exported virtual bytes. It is a positive multiple of 4096 and
at most 1 GiB. Sparse virtual file lengths can exceed it. The sum of checkpoint
and journal emergency reserves must be smaller than capacity; choose journal,
shard, request and volume sizes that leave room for their actual metadata and
checkpoint workload. The normal multi-GiB default reserves are inappropriate
for this bounded mode and are rejected.

Creation physically allocates a `2 * capacity` arena and two manifest slots,
each `8 MiB + (capacity / 4096) * 256` bytes. Thus the example reserves 288 MiB
on the backing filesystem, plus small files/filesystem metadata and witness
storage. A slot reservation records its logical page coordinates durably before
the journal can acknowledge a dependent write. Arena capacity therefore remains
available for checkpoint after restart and external filesystem consumption.
The witness filesystem must independently retain space for its atomic updates.

Pages in the committed manifest are immutable until the witness has durably
selected their successor. Writes use free arena pages, or their own uncommitted
pages. Every disk page read checks its SHA-256 hash; the canonical manifest binds
storage identity, generation, file identity, path, length, reservations, page
coordinates and hashes. The authenticated superblock binds volume identity and
geometry. Absent page mappings represent authenticated sparse zeroes; a missing
or corrupt **referenced** page is an error.

File sync publishes only that file's working version. Directory sync publishes
only the selected directory's bindings and necessary ancestors. Reservation can
persist extended EOF as zeroes without promoting unsynced bytes. Namespace
changes retain stable identities for already open files. These boundaries keep
concurrent checkpoint and journal work separate.

Each commit syncs the arena, writes and syncs the inactive preallocated manifest
slot, then atomically replaces and directory-syncs the witness record. Only
success makes the predecessor's pages reusable. A failed or lost commit result
does not acknowledge durability; close the failed session and reopen to select
the exact witnessed old or new state. Open rewrites and syncs that exact witness
record before exposing a session: a record visible after an unsuccessful
directory sync must become durable before older pages can be reused. The
generation/root pair identifies the outcome. Neither retries nor recovery ever
lower the witness generation.

V3 discard remains available. Fully punched pages and deleted files reclaim
internal arena capacity after the corresponding commit and open-handle lifetime.
After the last handle closes, the next space query or reservation commits a
manifest without the deleted identity before reporting or reusing its capacity.
Closing a handle performs no I/O. A pending namespace deletion still retains the
durable name and its pages; an unsuccessful reclamation commit stops the session.
Partial-page holes may retain their page reservation. The arena's physical
allocation is retained, so this mode does not return its fixed footprint to the
host filesystem. Cross-directory rename and directory removal/rename are not
implemented; current Maki volume operations do not require them.

## Backup and recovery procedure

A protected backing snapshot is usable with its original identity only while
it matches the authoritative witness generation. Subsequent commits can make a
previously valid backup too old. Keep DB-native or logical backups for recovery
to older application states; a collection of backing snapshots alone is not a
complete recovery plan.

1. Record the volume UUID, provider/key version reference, protected format,
   backing and witness locations, and package/configuration versions. Confirm
   that the witness is on an independently managed persistent filesystem and
   excluded from backing snapshots and whole-host rollback automation. Preserve
   secret material through its separate recovery process.
2. Stop application writers and their supervisors. Follow the stopped sequence
   in [key rotation](key-rotation.md#rotate-a-credential-while-retaining-the-encryption-key):
   detach while the daemon is available, obtain the explicit drain
   acknowledgement, then stop the daemon. Keep automatic restart disabled for
   the maintenance window and confirm that no process holds the volume. A
   live copy of the arena and manifest slots is not an atomic backup.
3. Copy the complete protected backing tree while it is stopped and record
   hashes. Keep the existing authoritative witness in place; do not copy it
   into a bundle that will be rolled back with the backing. Document that the
   copy will cease to be a usable same-identity restore point once commits
   advance the witness. Retain a separately verified application backup.
4. For same-identity recovery, keep writers and restart automation stopped.
   Preserve the failed backing as evidence, recover the complete matching
   backing under its trusted configuration, and run `maki check <config.toml>
   --deep` offline. This acquires the witness lock and verifies structural
   consistency; normal attach additionally verifies the crypto key and
   provider. Require application-level readback before permitting writes.
   Never run two writable copies against one witness.
5. A witness mismatch, missing witness or authentication failure leaves the
   volume offline. Do not edit generations, delete the witness, copy an older
   witness over it, or remove the configuration stanza. No administrative
   command reconstructs lost authoritative history. If only older data is
   available, restore an application backup into a newly created volume with
   a new witness identity, and validate cutover as a migration.

For witness ENOSPC, retain all Maki files, restore space on that independent
filesystem by removing unrelated data or through its established expansion
procedure, and reopen the failed session. Reopen selects the exact witnessed
old or new state; an unsuccessful commit was not an acknowledgement. Repeat
the offline/attach/application checks before resuming. A witness that resides
on unavailable storage is not repaired by moving a backing snapshot.

The [deployment profile](deployment/qualification-profile.md) must name the
backup owner, witness storage owner and tested restore path. These procedures
describe the current fail-closed behavior; independent persistent-disk reset,
capacity and latency qualification is still required.

## Recovery and validation limits

Open authenticates the entire selected manifest and streams all referenced pages
before exposing readiness. Metadata memory and commit cost grow with the number
of allocated pages; each commit currently serializes the complete manifest.
Page writes keep the committed and working slot sets incrementally, so a
write into an already reserved range no longer scales with committed data (a
release-build 64 KiB write at 128 MiB committed takes well under a
millisecond, gated by `phase_r5_rollback_write_cost_gate_full`). A write that
extends a reservation still commits, and each commit serializes the complete
manifest.
There are at most 4096 namespace entries, 4096 live file identities and 1024 bytes
per path. This first implementation targets bounded experiments, not high-volume
production I/O. Whole-process RSS, latency and hard-power-loss qualification on
independent persistent disks remain outstanding.

If backing data is behind the witness, restore the exact current generation or
keep the volume offline. To intentionally use older data, restore a DB-native or
logical backup into a newly created volume and witness identity. An offline
reader for an older
protected backing without its current witness is not provided. There is no
same-identity rollback override or restore-epoch reset. A remote transactional
witness, multi-host fencing and controlled epoch restore are future work
described in the [design](rollback-protection-design.md).

The automated suites cover whole-backing replay, changed arena pages, missing
witnesses, conflicting writers, file/directory durability separation, stale open
handles, full-capacity recovery, FUA, concurrent checkpoint/write, v3 discard and
rewrite, cached/overlay read checks, and failed arena/manifest/witness commits.
Witness fault injection covers temporary write, sync, rename and directory sync.
These are local functional and injected-failure results, not physical power-cut
or production deployment evidence.

Initial implementation validation used a frozen source tree based on `f8e6c3d`, with the
complete owned change set recorded by SHA-256 in `source.json`. The run at
`/home/seorii/logs/maki-rollback-final-20260921T114714Z/` (PID 92491, completed,
`exit.status = 0`) passed formatting, workspace strict Clippy, **1092 workspace
tests with 0 failures and 10 ignored**, and `cargo audit --deny warnings`
(258 dependencies). Its `step-0.log` through `step-3.log` and `status.json`
preserve the results. This includes the final witness-open durability repair;
the earlier 1090-test snapshot predates that repair.

Additional validation on 2026-09-22 found a capacity-progress defect: a deleted
file's reservation could remain counted after its namespace deletion was durable
and its final handle closed. The replacement-write regression failed with ENOSPC
before the fix. Reclamation now commits the pruned manifest before a space query
or reservation succeeds. Six injected cases (space query/reservation ×
arena/manifest/witness failure) preserve the prior root, stop the session and
successfully reopen and retry. The file model checks 1,600 operations across 16
fixed seeds, and eight child-process SIGKILL cycles check acknowledged FUA/FLUSH
writes and discards with and without checkpoints. These process tests retain the
host page cache.

The frozen reinforcement run at
`/home/seorii/logs/maki-rollback-reinforcement-20260922T053032Z/` (PID 99019,
completed, `exit.status = 0`) passed formatting, workspace strict Clippy,
**1100 Rust tests with 0 failures and 10 ignored**, and **71 Python tests**.
`source.json` records base `91df88f` and hashes of all eight overlaid task files;
the files matched the working tree after validation. The separate
[CI run for `91df88f`](https://github.com/seo-rii/maki/actions/runs/35690664557)
passed on both Ubuntu and Windows after fixing the WSS daemon fixture's bound
address. That CI run predates the new reclamation/model/process changes.

For repeat runs that can be left unattended, use the
[background runner's rollback profile](background-storage-validation.md).
Repetition exercises the same fixed seeds with potentially different scheduling;
it does not extend the persistent-disk qualification claim.
