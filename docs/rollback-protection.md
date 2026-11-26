# Rollback-protected backing

Status: experimental implementation, updated 2026-10-11. This is an explicitly selected
Linux storage format for new volumes. Default v2/v3 directory backings retain
their existing rollback limitation. Production qualification of this new format
is still pending; earlier v2/v3 GCE reset and RSS results do not qualify it.

There are two explicitly selected modes. The local mode uses a separate trusted
filesystem and retains its existing on-disk layout. The remote mode uses a
separate mTLS service and the new outer V2 format. Both are experimental.

## Trust boundary

The **local mode** keeps its current authenticated manifest root in a
separate **trusted witness directory**. A lifetime exclusive witness lock allows
one writer. The witness contains a storage identity, monotonically increasing
generation and SHA-256 manifest root. It must survive independently of backing
snapshots and must not be restored, replaced or deleted with them.

Local mode rejects nested directories and a witness on the same
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
From then on `maki status` reports `state: degraded` with a reason starting
`rollback session stopped:` and the daemon logs one `WARN` line with the cause.
A transient arena read error refuses only that operation and preserves its I/O
error. The next operation checks the witness and authenticates the page again;
missing, short or invalid referenced pages and hash mismatches still stop the
session, even if their original bytes are later restored. A read failure during
a multi-page write may leave an already completed prefix in the working view;
retrying the write can complete it. A failed arena write or commit still requires
reopening against the witness.
A remote witness that cannot be reached (a timeout, a refused or reset
connection, a local socket error such as the EPERM Linux returns from
`connect()` when a firewall or a full conntrack table drops the connection, an
unavailable quorum) refuses each operation with no fallback, but does not stop
the session: the next check either matches the claimed record again or
observes the change and stops it. Besides an observed change, only the
witness's own denial, a predecessor conflict, an invalid answer or a TLS failure
stops the session. A frontend whose allow-list no longer names the writer
certificate, or whose CA bundle no longer trusts it, denies it, which stops the
session too; correcting the allow-list or the bundle does not resume it.
Cached plaintext and journal-overlay reads also check the freshness authority.
The provider's advertised replay-protection capability is not changed by this
storage option.

## Remote witness mode

Replace `witness_root` with a remote section; configuring both is refused:

```toml
[backing.rollback_protection]
capacity = "128MiB"

[backing.rollback_protection.remote]
address = "192.0.2.10:9443"
server_name = "witness.example.net"
timeout_ms = 5000
ca_file = "/etc/maki/witness/ca.pem"
client_cert_file = "/etc/maki/witness/writer.pem"
client_key_file = "/etc/maki/witness/writer.key"
```

Provision the independently managed authority and its writer/admin certificate
allowlist as described in [remote witness operations](remote-witness-service.md).
Private key files must be owner-only regular files owned by root or by the user
the loading process runs as (the daemon user for the writer key); a key owned
by anyone else is refused whatever its mode. Requests use TLS 1.3 mutual
authentication, bounded frames and deadlines. There is no offline fallback.
The metadata service can use a local state directory with an exclusive lock or
a replicated etcd quorum shared by stateless frontends. Identity-pinned endpoint
sets provide frontend failover; independent copied local directories cannot.
Its storage and restore authority must remain independent of the backing's
administration.

Every attach first authenticates the authority's current manifest in its own
backing root, so a configuration that names another volume's witness fails
without changing that authority; it then claims a higher fence and copies the
committed pages into a fresh, fully reserved namespace before activation.
Takeover applies the same check before it revokes the current writer. The old
session cannot publish, and any in-flight physical write stays within its old
namespace. Normal attach requires a released session;
crashes, ambiguous responses and failed copies require explicit administrator
intervention. Cached and overlay reads also consult the remote authority.

Remote authority and transport v2 bind each claim to a random private session
capability. Activation, advance and release require both that capability and the
exact public predecessor; another process cannot gain ownership by inspecting
the current record, even with the same writer certificate. Capabilities stay in
zeroizing memory and are absent from inspection output and backing snapshots.
Authority v1 is rejected by new binaries; migrating it requires an independent
destination identity and verified logical data copy with matching old binaries.
See [authority compatibility](remote-witness-service.md#authority-protocol-compatibility)
before updating an existing deployment. Outer COW and inner volume bytes are
unchanged.

Each retained namespace reserves the same arena and manifest footprint described
below. At 128 MiB capacity this is approximately 288 MiB **per session**, including
normal offline checks and reattachments. After activation, automatic GC reclaims
lower-fence namespaces whose lifetime
locks are free. Current roots, pending forks and restore sources remain
protected; live handles retain their old namespace until a later cleanup.
Budget copy headroom and retained live data. No latency claim from the local
mode applies to this per-operation remote protocol.

The remote CLI can create an offline committed snapshot, take over a writer,
and intentionally restore an approved older snapshot under the same identity.
Restore requires administrator credentials, an exact current fence/root and a
separately approved snapshot hash. It increases generation and epoch; it never
lowers the authority. See the service guide for copy-pasteable commands.
The automatic GC pass after a restore deletes the replaced newer state from
the backing root; snapshot it first if it may be needed again
([restore procedure](remote-witness-service.md#snapshot-takeover-and-restore)).
An administrator can resume initial enrollment while the authority has never
activated a descriptor, using the procedure below. An initialized descriptor
cannot be reset through enrollment recovery, including when its activation
reply was lost. Never delete or reinitialize an existing authority to make an
old backing attach.

### Resume interrupted initial enrollment

Which command continues an interrupted `maki volume create` depends on how far
it got. Creation writes the format marker as `rollback.format.next`, syncs it,
renames it to `rollback.format` and syncs the directory, and it asks the
authority for a claim only after the marker and the binding are durable. A
backing root without `rollback.format` (it holds `remote.enroll.lock`,
`remote.operation.lock` and possibly `rollback.format.next`) is a creation
that published nothing and claimed nothing, whether it was killed, lost power
or failed on a full disk: run `maki volume create` again as before. An older
binary wrote the marker in place; a root in which it left `rollback.format`
empty or partly written beside nothing but those lock files is completed by
`volume create` the same way. Nothing has to be removed by hand, and
`resume-enrollment` refuses such a root with a message that says to create
the volume again. Once `rollback.format` holds the marker, `volume create`
no longer continues the root: it answers
`remote enrollment requires an empty backing` while the authority is still
unclaimed (the creation stopped before its claim, while it wrote the
binding), and `remote witness already enrolled or occupied` once the
creation had claimed the authority (it stopped while reserving the
namespace, on a full disk for example, or before activation). The
procedure below continues both. The binding, the next file, is written the
same way, as `remote.enrollment.next` renamed to `remote.enrollment` once it
is synced: a creation that stopped while it wrote the binding leaves at most
the staged file, which nothing reads, and `resume-enrollment` continues it
and writes the binding for the approved identity and capacity.
`resume-enrollment` makes the marker's name durable before it stages the
binding. An older binary did not: after a creation that failed in the
directory sync that publishes the marker, or was killed between the marker's
rename and that sync, a power loss during `resume-enrollment` could leave the
binding, staged or published, in a root without `rollback.format`.
`volume create` continues that root as well when it is run with the same
authority and capacity: it never reads the staged file, and it accepts a
published `remote.enrollment` only if it is the binding it would write
itself. A `remote.enrollment` for another authority or capacity is refused by
both commands and left as it is, with a message that says to create the
volume with that creation's authority and capacity or to use an empty backing
root. A staged file that the command cannot write again from the start (a
link, a directory, a FIFO, a file with a second name, or a file that another
user owns and this one cannot open, under `rollback.format.next` or
`remote.enrollment.next`) is refused by both commands before they change
anything, with a message that names it and gives the system's answer: remove
it and run the command again. A command run as root leaves a file of the
last kind when it is killed between creating the staged file under its name
and giving it to the directory's owner, on a filesystem without unnamed
temporary files; the daemon user's `volume create` used to fail on it once,
remove it and continue on the next run, and now names it until it is
removed. An older
binary wrote the binding in place, and a `remote.enrollment` it left empty or
incomplete cannot be told apart from a damaged binding. In a root whose
`rollback.format` holds the marker, `resume-enrollment` refuses it as invalid
enrollment metadata: move that file out of the backing root, keep it, and
resume. In a root without `rollback.format`, `volume create` answers
`remote enrollment requires an empty backing` and `resume-enrollment` says to
move the file out and create the volume again: move it out, keep it, and run
`volume create`. An interrupted
`maki-witness init` is a separate case, described with
[the authority's initialization](remote-witness-service.md#initialize-a-local-authority).

Keep the volume detached and automatic restarts disabled. Preserve the failed
backing and inspect the independently managed authority:

```sh
maki volume witness /etc/maki/protected-admin.toml
maki volume resume-enrollment /etc/maki/protected-admin.toml 1 11111111-1111-1111-1111-111111111111
```

Replace `1` with the exact inspected fence and the example UUID with the
approved **storage identity** from the authority, not the inner volume UUID.
The administrator configuration uses an administrator certificate and the
original backing root, provider, geometry and approved capacity. Add `--discard`
to create an inner v3 volume; the default initializes an inner v2 volume.
This command completes normal initial volume creation after recovering the
outer backing's enrollment.

Run both commands as root: the administrator key must stay unreadable to the
daemon user. `resume-enrollment` creates the new writer namespace owner-only
(`0700` directories, `0600` files) for the owner of the backing root, as
takeover and restore do
([remote witness operations](remote-witness-service.md#snapshot-takeover-and-restore)),
so a backing root that belongs to the daemon user needs no hand-back unless a
crash interrupted the command
([volume lifecycle](operations.md#volume-lifecycle)).

The authority must have `current = null`; successful first activation makes
that condition permanently unavailable. Recovery compares the full inspected
record, requires administrator credentials and selects a higher fence with a
fresh physical namespace. Old claim candidates and late replies cannot publish
over that namespace. The original storage identity is retained. A stale fence,
different approved identity, writer credential or initialized descriptor
refuses the command.

New creation synchronizes `remote.enrollment`, a versioned identity/capacity
binding, before claiming the authority. Resume validates an existing binding
against the approved configuration. A valid marker-only backing created by an
older binary can acquire the missing binding through this explicit operation
only while its authority has never activated. A missing binding does not show
that the root is unused: activated roots written by older binaries have none.
Before binding the root or claiming the authority, resume therefore refuses a
root that holds anything a never-activated authority cannot have written: a
GC tombstone, or a namespace other than the one its current claim names whose
manifest slots hold anything but this identity's empty initial candidate (or a
torn part of it). Another volume's data under a mistaken `backing.root` is
refused this way, and neither authority nor root changes. The subsequent GC
pass may retire only the quiescent lower-fence candidates that check examined;
live handles and unknown artifacts are preserved. An existing corrupt or truncated binding is
refused; preserve or quarantine it for explicit operator investigation rather
than automatically overwriting it or changing capacity to force progress.

If inspection shows a current descriptor after an uncertain activation, use
the ordinary exact-current takeover/recovery procedure and preserve its
manifest. Enrollment recovery never clears it. If inner volume initialization
itself stopped after outer activation, this command does not automatically
complete or reset that initialized backing; inspect its existing volume
evidence before choosing an explicit recovery procedure.

## Local configuration and creation

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

Start from two empty directories. Provision the independent witness
mount first, create both per-volume directories for the daemon user, and run
the creation as that user, as for any volume
([volume lifecycle](operations.md#volume-lifecycle)). Add `--discard` for a v3
volume:

```sh
install -d -o maki -g maki -m 0700 /var/lib/maki/protected /mnt/maki-witness/protected
runuser -u maki -- maki volume create /etc/maki/volumes/protected.toml
```

Creation writes the backing files and the witness files (`anchor`,
`witness.lock`) owner-only (`0600`) as the user that runs it. Run as root, it
creates each of them for the owner of its directory, so with both directories
created as above the result is the same. A directory the command has to
create itself is root's, and so is everything in it, so the daemon cannot open
it; the command then warns with the `chown -R maki:maki` of each such path to
run before the first start. An existing raw or protected backing is refused;
there is no implicit enrollment, in-place conversion or automatic witness
recreation.

The outer creation publishes the witness anchor last, and until then
nothing can open the volume, so nothing was acknowledged. A `maki volume
create` that is killed, loses power or fails before it publishes the anchor
(a full disk while it reserves the arena, for example) is completed by
running it again, with nothing to remove by hand. Once the anchor is
published, the command initializes the volume inside the backing, in
several commits that end with the volume's superblock. One that stops
there is completed by running it again as well, with the capacity it was
started with: `create` opens the pair against its witness, which
authenticates the manifest and every committed page, and continues only
if what it then finds is nothing but an unfinished creation, that is, no
superblock copy and no entry other than what a creation writes before its
superblock (the volume lock, the first shard-catalog copy, a staged
`superblock.next`, the empty `data`, `journal` and `checkpoint`
directories with the durable proof, the initial checkpoint state and a
durable mark that is still empty). It
removes those files and initializes the volume anew, with a new volume
UUID. A volume that was ever attached holds a superblock copy, so it is
never continued this way, and damage cannot make one look unfinished: a
pair whose superblock pages, manifest slots or anchor are damaged or
missing, or whose witness is not mounted, does not open, and `create`
refuses it as before and leaves it as it is. Until the command is run
again, the daemon, `maki check` and `maki volume inspect` refuse the pair
and say why: before the anchor that the backing holds no format marker or
the witness no anchor, after it `no valid superblock: this volume's
creation did not complete`, each naming `maki volume create` as what
continues it. A backing without its format marker that holds anything an
interrupted creation does not leave (the `lost+found` of a filesystem
mounted at the backing root, for example, or a manifest slot that holds
data), or whose witness directory does, is no such creation: `create`
refuses it every time
(`rollback enrollment requires empty backing and witness directories`),
and the refusal and the commands that open the pair name those entries
instead of offering `create`. It is not the volume's backing root, or
`create` needs directories that hold nothing else. Once a superblock copy
is committed the volume exists and `create` refuses it. The format marker and the anchor are each written under
a temporary name (`rollback.format.next`, `anchor.next`), synced and renamed
into place, so neither name ever holds an empty or torn file. `create` then
accepts a backing directory that holds only what a creation writes (the
lock, the marker, the arena and the two manifest slots) as long as the
second slot holds only zeros and the first only zeros or the initial empty
manifest, and a witness directory that holds only `witness.lock` and
`anchor.next`. The staged marker, the arena and the slots must each be a
regular file with one name, which the creation writes again: a directory,
a symbolic link, a FIFO or a file with a second name under one of those
names is refused before anything changes, and named. The one exception is
an entry under the staged marker's name that the user running `volume
create` may not open: anything there but a directory or a symbolic link
is removed (only that name is unlinked; a second name keeps its file). A
creation run as root that is killed between creating one of these files
and giving it to the directory's owner leaves a file the daemon user may
not open. Under the staged marker's name, which nothing reads, such a
file is removed and the marker staged anew, so the daemon user's `volume
create` continues in one run. An arena or a slot that the user running
`volume create` may not open is refused before anything changes, with a
message that says to give the file to that user (`chown`), let that user
read and write it (`chmod`) and run the command again. Every volume that
committed anything wrote its second slot, so `create` never creates over
one, whatever the witness directory holds
and short of both slots lost or zeroed entirely (an all-zero slot is an
unwritten one): a witness mount that is missing (an empty directory in its
place) cannot get a used volume recreated, and neither can slots that
damage left holding anything else. It never enrolls over an `anchor` either: a pair that
has one is only ever opened against it. Earlier releases created
the anchor empty before writing it: an empty `anchor` that such a release
left is refused by `create`
(`rollback enrollment requires empty backing and witness directories`) and
by the daemon and the offline commands, which say that the creation
did not complete or the witness lost its state. If the volume was never
attached, remove that empty file and run `maki volume create` again;
otherwise restore the witness directory.

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
the volume is detached, as the daemon user or as root:

```sh
runuser -u maki -- maki check /etc/maki/volumes/protected.toml --deep
```

These commands and the daemon never create the backing root or the witness
directory, as `volume create` does. They refuse a backing root or witness
directory that does not exist, is not a directory or that the user running
them may not open, with its path and the setting that names it
(`backing.root`, `backing.rollback_protection.witness_root`); a witness
directory that is missing after a reboot usually means that its filesystem
is not mounted. `maki-benchmark` refuses a backing root that is not a
directory or that it may not open the same way, and a volume it reuses as
the daemon does; where the backing root holds no volume, or does not exist,
it creates one as `volume create` does, witness directory included.

Where the user running them may write both directories, these acquire the
exclusive witness session and reestablish the selected witness record's
durability without advancing it, by writing the record to a new file renamed
over the old one, and rewrite and sync the backing's authenticated pages,
manifest and format marker, as attach does. Where the user may not write the
backing root or the witness directory, either of them (a read-only mount, for
example), `check` and `volume inspect` open the pair read-only instead
([checking a backing that cannot be written](operations.md#checking-a-backing-that-cannot-be-written)):
the same authentication against the witness, nothing created, written,
synced or removed in either directory, `rollback.lock` and `witness.lock`
taken shared, and the deep verdict `unproven`. That open refuses a pair
whose lock file is missing, which it cannot create, and one that a daemon
holds. The writable open also recreates a lock file
(`rollback.lock`, `witness.lock`) or inactive manifest slot that is missing
(after a partial restore, for example). Run as root, they create every such
file for the owner of its directory, so the daemon can still open both paths
and nothing has to be handed back. The new witness record keeps the replaced
record's owner, except that a root-owned record in a directory the daemon user
owns goes back to that user, and a record of a third user is refused with an
error naming both owners. Root never changes the owner of a file that was
there before it ran: a restored copy whose files lost their owners must still
be returned with `chown -R maki:maki` (see the recovery procedure below), and
so must both paths after a root run that a crash interrupted while it was
creating an entry, which can leave it root's
([volume lifecycle](operations.md#volume-lifecycle)). A
leftover `anchor.next` is removed rather than reused, so the published record
is never a file someone else may still hold open for writing; one that a third
user puts under that name meanwhile is refused. `maki-check`,
which takes only a backing root path and no configuration, cannot open this
outer format. Removing the rollback configuration stanza does not enable raw
fallback.

## Capacity and durability

`capacity` means reserved logical **backing pages**, including journal, slots
and metadata, not exported virtual bytes. It is a positive multiple of 4096 and
at most 1 GiB. Sparse virtual file lengths can exceed it. The sum of checkpoint
and journal emergency reserves must be smaller than capacity; choose journal,
shard, request and volume sizes that leave room for their actual metadata and
checkpoint workload. The normal multi-GiB default reserves are inappropriate
for this bounded mode and are rejected.

On attach, the configured capacity must equal the authenticated manifest's
stored capacity, in both local and remote modes. Changing the configuration
does not resize an existing backing; a different capacity requires migration.

Creation physically allocates a `2 * capacity` arena and two manifest slots,
each `8 MiB + (capacity / 4096) * 256` bytes. Thus the example reserves 288 MiB
on the backing filesystem, plus small files/filesystem metadata and witness
storage. A slot reservation records its logical page coordinates durably before
the journal can acknowledge a dependent write. Arena capacity therefore remains
available for checkpoint after restart and external filesystem consumption.
Reopening authenticates the selected manifest and referenced pages, then
reestablishes the arena and both manifest reservations before serving I/O. This
also covers sparse backup/restore tools that preserve bytes and lengths but not
physical allocation. A missing or incorrectly sized inactive manifest slot is
recreated or resized; missing or corrupt selected evidence is still refused.
Allocation, file-sync or directory-sync failure refuses attachment without
advancing the witness. The witness filesystem must independently retain space
for its atomic updates.

Local mode also reestablishes the durability of the authenticated restore
before exposing readiness. Reopen rereads and rewrites every referenced arena
page, republishes the selected manifest and format marker, and reasserts file
lengths before synchronizing the files and directory. This covers a failed
writeback followed by a process restart, where valid restored bytes can still
be readable in the page cache although they are no longer dirty. It adds one
read and one write per referenced page on each local reopen, using a 4 KiB page
buffer; it does not change the on-disk format or advance the witness. Remote
mode establishes durability by copying the selected generation into its new
namespace.

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
After the last handle closes, the next space query, reservation or file creation
at the identity limit commits a manifest without the deleted identity before
reporting or reusing its capacity. Repeated create/unlink/close operations do not
exhaust the identity limit; live handles and pending durable unlinks still count.
Closing a handle performs no I/O. A pending namespace deletion still retains the
durable name and its pages; an unsuccessful reclamation commit stops the session.
Partial-page holes may retain their page reservation. The arena's physical
allocation is retained, so this mode does not return its fixed footprint to the
host filesystem. Cross-directory rename and directory removal/rename are not
implemented; current Maki volume operations do not require them.

## Backup and recovery procedure

This section describes **local-witness** recovery. Remote snapshots and explicit
restore epochs use the [remote service procedure](remote-witness-service.md).

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
   unmount while the daemon is running, obtain the explicit drain
   acknowledgement, then stop the lifecycle target and wait for every unit to
   become inactive. Keep automatic restart disabled for
   the maintenance window and confirm that no process holds the volume. A
   live copy of the arena and manifest slots is not an atomic backup.
3. Copy the complete protected backing tree while it is stopped and record
   hashes. Keep the existing authoritative witness in place; do not copy it
   into a bundle that will be rolled back with the backing. Document that the
   copy will cease to be a usable same-identity restore point once commits
   advance the witness. Retain a separately verified application backup.
4. For same-identity recovery, keep writers and restart automation stopped.
   Preserve the failed backing as evidence, recover the complete matching
   backing under its trusted configuration, owned by the daemon user like the
   original (`chown -R maki:maki` it if the copy did not keep its owners), and
   run `maki check <config.toml> --deep` offline, as the daemon user or root
   ([which user](#local-configuration-and-creation)), where it may write both
   directories. This acquires the witness lock and verifies structural
   consistency and restores physical reservations; where it may not write
   one of them, the check is read-only and restores nothing. Provide the
   complete fixed footprint even when the restored copy is sparse;
   reservation failure keeps it offline. Normal attach
   additionally verifies the crypto key and provider.
   Require application-level readback before permitting writes.
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

If backing data is behind the witness, normal attach refuses it. Local mode
requires the exact current generation or a logical migration to a new identity.
Remote mode additionally provides explicit administrator-approved restoration
with increasing generation and epoch. Neither mode offers an offline reader
that claims freshness without its authority. The [extended design](rollback-protection-design.md)
still describes future Merkle-tree and replicated-service work.

Remote automated tests cover exact CAS contention, state persistence faults,
real TLS role and certificate enforcement, lost commit/claim/activation/release
replies, writer takeover at in-flight write and commit boundaries, authenticated
snapshot restoration, and revocation of actual Engine cache and overlay reads.
These are local fault tests, not multi-host or physical power-loss campaigns.

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

## Remote namespace reclamation

After successful creation, attach, takeover, enrollment recovery or restore,
Maki attempts cleanup while holding the root operation lock used by every
physical fork and snapshot. Cleanup authenticates the authority's exact current
manifest in the pinned backing before using its fence. Each candidate must be
canonical, have a lower fence and pass a fresh unchanged-authority check.
Current, pending and restore-source namespaces are always retained.

A namespace's existing `rollback.lock` must be available. Open file handles keep
the session and this lock alive even after their volume object drops. Cleanup
skips unknown files, symlinks, hardlinks, mount boundaries and original
namespaces missing their lock file. A namespace it cannot open or examine
(one the daemon user does not own, for example), or one whose retirement
stops at a step that changes it alone (a directory the daemon user may not
write, so that its tombstone cannot be emptied), is kept and reported with
the error, and cleanup goes on to the next one. A Linux kernel supporting statx mount IDs
(5.8+) and consistent advisory locks for every writer are required; unsupported
or failed automatic cleanup postpones reclamation without revoking the accepted
new root, and says so in a `WARN` log event. There is no fallback that deletes
based only on a fence or filename.

Quiescent namespaces are exclusively renamed into a durable `.remote-gc-`
tombstone before unlinking known files. Interrupted retirement resumes on a
later cleanup; the lock is removed last. The current directory and independent
external snapshot directories are never cleanup targets. See
[durable recovery](durable-recovery.md) for the persistence boundary.

To retry cleanup after old handles close, without claiming a writer, run GC
with the writer configuration as the daemon user (a process run as root
refuses the daemon-owned writer key):

```sh
runuser -u maki -- maki volume gc /etc/maki/protected-writer.toml
```

The command prints `removed`, `skipped_live`, `skipped_unrecognized` and
`retained` namespace arrays as JSON, `skipped_unreadable`, which gives
each namespace it could not open or examine with the error, and
`unfinished`, which gives each namespace or tombstone whose retirement it
could not finish with the step and the error. Each array holds
at most 4,096 entries;
use the corresponding `counts` fields for totals and `details_truncated` to
detect omitted details. See [GC reports](remote-witness-service.md#retire-old-writer-namespaces).
Authority outages or changes fail closed;
inspect the cause and retry after recovery. Do not manually delete a live
writer's namespace to recover space.
