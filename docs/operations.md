# Operations

This guide covers volume lifecycle, nbdkit integration, privilege separation,
control commands, and recovery. Commands that attach block devices, modify LVM,
mount filesystems, or grow filesystems require an isolated Linux target and
appropriate privileges.

The repository includes a guarded, destructive-target-restricted procedure in
[Privileged Linux validation](qualification/privileged-linux-validation.md).

## Volume compatibility before upgrade

New volumes use superblock envelope v2 with two required durable-proof files.
Older binaries reject v2. This build refuses writable recovery of legacy v1
before changing recovery metadata, although it may acquire/create the advisory
lock first. Read-only checks support v1 with a warning; they cannot certify
history whose durable horizon is missing.

Read [durable recovery and migration](durable-recovery.md) before replacing an
existing installation. There is no automatic in-place format upgrade. Preserve
an untouched source, old software and provider/key material, then use an
isolated recovery copy and verified logical/DB-native transfer to a fresh v2
volume. Copy backing files with `cp --reflink=never`: a reflink copy shares
extents with the source, which voids Maki's space reservation for both
([backing store](deployment/support-matrix.md#backing-store-below-maki)). Do
not remove proofs or change format bytes to bypass a refusal. The crypto
context's `format_version` is unchanged by the envelope version.

## Prerequisites

Building the Rust workspace requires a Rust toolchain. The Linux data path also
uses nbdkit. Rootless userspace validation requires `nbdkit`, `nbdinfo`,
`nbdcopy`, and fio with its NBD engine. Kernel attachment additionally requires
the Linux NBD module and a disposable `/dev/nbdN`.

On Debian-family systems the relevant packages are `nbdkit`,
`nbdkit-plugin-dev`, `libnbd-bin`, and `fio`. Package and service installation
remain distribution-specific.

Privileged attachment needs no NBD client package. The helper validates
`/dev/nbdN` as the configured block path, negotiates with the volume daemon's
socket itself (fixed-newstyle `NBD_OPT_GO` for the default export) and connects
and disconnects the kernel device with generic-netlink requests to the `nbd`
family, which needs a kernel whose `nbd` module has the netlink interface and
the backend identifier (SPEC §6). It refuses an export that does not advertise
FLUSH and FUA, before the kernel sees the socket. Two answers to a connect
mean "busy" and are retried every 100 ms, for up to 5 s from the first of them
and only while the device still shows no connection:

- the kernel's, while something has the unconnected device open (udev probes a
  device right after a disconnect). The helper sends its next request on the
  connection it has already negotiated, and negotiates a fresh one only when
  that connection has been closed or shut down;
- the daemon's, while its export is not available. The daemon serves one
  connection at a time and closes one a moment after its peer did, so a
  handshake right after a disconnect can be refused (`NBD_REP_ERR_UNKNOWN`).
  A server without a default export answers the same: when the 5 s are over,
  the refusal names both, and the daemon's own log says whether it refused a
  second connection ("the volume serves one connection at a time, and one is
  open").

A device that stays busy to the end shows nothing in sysfs. When the attach
allocated it (no pinned `nbd_device`), the helper gives it up, logs a warning
and tries the next free device within the same step's time; a pinned device
fails the attach. After a disconnect, `maki-attach nbd-disconnect`, detach and
cleanup wait up to 15 s, looking every 100 ms, until the device no longer shows
the connection: the kernel keeps showing it until whatever held the device open
at the disconnect (a probe of an earlier event, a monitoring tool, multipathd,
an operator's `blkid`) has closed it. The disconnect's own change event comes
only when the connection goes; the udev probe it starts is what can make a
connect right after it busy. If the device still shows the connection at the
end, `nbd-disconnect` fails, and detach and cleanup keep the attachment record
and fail; run them again once nothing holds the device open. The
[Debian installation guide](getting-started/installation-debian.md) shows how to
build and install the Maki package.

A new volume exports an empty device. Before its first `maki-attach attach`,
create the PV, VG, XFS data LV and record their identities as described in
[provisioning the first volume](getting-started/first-volume.md); the
[quick start](getting-started/quickstart.md) runs the whole sequence once.
Which hosts, backing stores and storage topologies are covered is listed in
the [support matrix](deployment/support-matrix.md).

## Build the plugin

```bash
cargo build --release --locked -p maki-nbdkit
nm -D --defined-only target/release/libmaki_nbdkit.so |
  grep -Eq '[[:space:]]T[[:space:]]plugin_init$'
```

The exported structure uses the validated nbdkit API-v2 prefix. FLUSH and
native FUA reach the engine, and the block-size callback advertises the
configured I/O limits. TRIM is available for new volumes explicitly created with
`--discard`; ordinary v2 volumes retain their existing behavior. Multi-connection
is disabled. See [space reclamation](space-reclamation.md) for format selection,
partial-unit behavior and checkpoint ordering. WRITE_ZEROES is native and
chunked to `nbd.maximum_io`, so a zero request of any length succeeds; on a
`--discard` volume whole units may be discarded when the client allows it.
Fast zero is advertised, and every fast zero request is refused with `ENOTSUP`
([why](space-reclamation.md)).

## Volume lifecycle

Initialize, inspect, and check a volume with the administrative CLI:

```bash
maki volume create /etc/maki/volumes/example.toml
maki volume inspect /etc/maki/volumes/example.toml
maki check /etc/maki/volumes/example.toml
```

`volume create` needs an empty backing root: it refuses a root whose `data/`,
`journal/` or `checkpoint/` directory still holds a file, because an earlier
volume's shards would otherwise be adopted and served by the new one, and a
root that still holds an earlier volume's `superblock.*`, `shard-catalog.*` or
`canary.*` (a stale key canary would otherwise fail the first attach as a key
mismatch). A leftover `volume.lock` is accepted.
The superblock copies are written last, once everything else is durable, and
the first one is written and synced under a temporary name (`superblock.next`)
and renamed into place, so a superblock file never holds anything but a
superblock. A creation interrupted before a superblock copy exists leaves a
root that is not a volume, and `volume create` refuses the files the
interrupted run left (in the layout directories, `shard-catalog.a`,
`superblock.next`) until the root is emptied. Once a copy exists, a
retried `volume create` reports `volume superblock already present`: the root
is a complete volume, except that a failed or killed creation may have left
that copy only in the page cache. The first attach makes both superblock copies
durable before it accepts writes; empty the root instead to start over.
A superblock file that holds no valid superblock is a third state. This
release does not produce it; an earlier one created the first copy before
writing it, so a creation it stopped there left an empty or partly written
`superblock.a`, and damage to both copies of a used volume looks the same.
`volume create` refuses such a root with both causes and never initializes it
again, and the daemon, `check` and `volume inspect` report `no valid
superblock`. Only if the volume was never attached, empty the root and create
it again; otherwise restore the root from a backup.
A backing with a remote rollback witness is continued differently, without
emptying its root: see
[interrupted initial enrollment](rollback-protection.md#resume-interrupted-initial-enrollment).
A backing with a local witness is continued by running `volume create`
again, without emptying anything, wherever its creation stopped before the
volume's superblock was committed: before the witness anchor, or after it
while the volume inside the backing was being initialized. Until then the
daemon, `check` and `volume inspect` refuse it and name that command
([local rollback creation](rollback-protection.md#local-configuration-and-creation)).

`volume inspect` and `check`, including `check --deep`, require an existing
backing-root directory. A missing root or parent is rejected before constructing
the backing and is not created by these commands. New paths remain supported by
`volume create`. On Linux, a root the user running them may not write, such
as one on a read-only mount, is opened read-only, and what the check then
reports means less ([checking a backing that cannot be written](#checking-a-backing-that-cannot-be-written)).

The inspect output includes `maximum units`, `maximum shards`, `full slot span
bytes`, `allocation map A/B bytes`, `discard map A/B bytes`, and `catalog A/B bytes`.
The discard-map estimate is zero for v2 and equals the allocation-map estimate
for v3. Use them as the
format-file baseline for a fully allocated volume. They do not include journal
or checkpoint headroom, filesystem metadata, copy-on-write overhead, or
database temporary files, and the command does not reserve disk space. Keep
the configured reserves and independently qualified operational margin beyond
the reported values.

`volume create` writes the initial superblock, catalog, and backing directories,
all owner-only (`0700` directories, `0600` files). The command must target an
empty, reviewed backing location, and the tree must end up owned by the daemon
user: `/var/lib/maki` is `root:maki 0750`, so create the volume directory for
the daemon and run the command as that user:

```bash
install -d -o maki -g maki -m 0700 /var/lib/maki/example
runuser -u maki -- maki volume create /etc/maki/volumes/example.toml
```

The backing filesystem must overwrite allocated blocks in place, or the
space reservation does not hold. A copy-on-write backing (btrfs with its
default copy-on-write data, ZFS) is unsupported. On btrfs, running
`chattr +C /var/lib/maki/example` between the two commands makes every backing
file created afterwards NOCOW; that configuration is not qualified
([copy-on-write filesystems](deployment/support-matrix.md#copy-on-write-filesystems)).

A `maki` command run as root creates every file and directory below an
existing backing root for the owner of the directory it creates it in, so a
root `volume create` into a volume directory created as above leaves the same
daemon-owned tree. A volume directory the command has to create itself is
root's, and so is everything in it: a root-owned `0700` tree is unreadable to
the daemon, which then fails to attach. `volume create` then warns with the
`chown -R maki:maki` to run before the first start. The offline commands below
follow the same rule. A root run that a crash interrupts can leave an empty
root-owned directory behind (or, on a filesystem without `O_TMPFILE`, an empty
root-owned file), which later runs open as it is; hand the tree back with
`chown -R maki:maki` after such a crash. In a remote rollback backing the
leftover of an interrupted takeover, restore or enrollment recovery is a
writer namespace directory: the daemon keeps attaching, and its namespace
cleanup reports that directory as one it may not open
([GC reports](remote-witness-service.md#retire-old-writer-namespaces)).

The packaged units derive every path from the systemd instance name, so with
them the instance, the file names and two configuration values must agree. For
instance `example`:

| Item | Required value |
|---|---|
| Volume configuration | `/etc/maki/volumes/example.toml` (`maki@example` reads it) |
| `volume.name` | `example`: the default control socket is `/run/maki-control/<volume.name>/control.sock`, and the unit only creates and permits `/run/maki-control/example` and `/run/maki/example` |
| `backing.root` | `/var/lib/maki/example`: `ProtectSystem=strict` leaves only that tree writable |
| Attach configuration | `/etc/maki/attach/example.toml` (`maki-attach@example` reads it and connects to `/run/maki/example/nbd.sock`) |
| Credential | `/etc/maki/secrets/example.token`, loaded as `crypto-token` |

A mismatch shows up as a daemon that cannot bind its control socket or open
its backing. Override paths only together with a matching service drop-in.

`maki-check` can also inspect a backing root directly:

```bash
maki-check /var/lib/maki/example
maki-check /var/lib/maki/example --deep
maki check /etc/maki/volumes/example.toml --deep
```

Without `--deep` the check covers the superblock, required v2 proof records,
shard catalog, allocation-map sizes, and file presence, including at least one
checkpoint state file. `--deep` additionally
verifies both checkpoint state copies, the key canary, and every journal
segment as recovery would scan it, including the required horizon and its
exact record end (or the legacy advisory-mark policy). It reports the repairs
recovery would make and checks every allocated slot's stored structure and
checksums. A successful deep check
does not decrypt data, authenticate its ciphertext, establish freshness, or
prove filesystem or database consistency. Canary checking here validates its
stored structure and volume identity; actual key verification happens at
attach. Combine these checks with provider authentication and application
recovery/backup verification before accepting recovered data.

`maki check` and `maki check --deep` also compare the configuration with the
volume, with the comparison attach makes before it loads any provider
credential or builds a provider transport: the geometry
(`volume.device_block_size`, `volume.crypto_unit_size`,
`volume.shard_logical_size`, `volume.max_virtual_size`,
`backing.slot_alignment`, `crypto.capabilities.max_ciphertext_size`),
`crypto.provider`, the key's name (`crypto.key.name`, stored as the volume's
key identity), `crypto.crypto_compatibility_id` and
`crypto.random_prefix_bytes`. Each setting that differs is an
`ERROR: configuration mismatch:` line with the configured value and the
volume's, and the check fails. These settings are fixed at creation: correct
the configuration to the volume's values. The values printed are sizes,
provider and credential names and compatibility ids, never key material. A
protected backing's `backing.rollback_protection.capacity` is compared when
the backing is opened: a mismatch stops the command before the check, with
both values. The check loads no provider credential and contacts no provider
(with a remote witness it loads the witness client's TLS identity, to ask the
authority), so attach alone finds a different key under the same name (the key
canary), a credential that is unavailable or does not fit the provider, a
provider that fails its self-test, endpoints that are unreachable or not
interchangeable, and the memory and swap checks. `maki-check <root>` reads no
configuration and compares none. `maki volume inspect` reports what the volume
stores and does not compare the geometry or crypto identity with the
configuration; like the check, it stops on a protected backing whose
`backing.rollback_protection.capacity` differs.

`--deep` takes the volume lock and refuses to run while a daemon is attached.
On a backing root it can write it recreates a missing `volume.lock` (a restore
or copy can drop the empty file); run as root, it creates the file for the
owner of the backing root, so the daemon can still take the lock and nothing
has to be handed back unless a crash interrupted the run (above). On one it
cannot write it creates nothing ([below](#checking-a-backing-that-cannot-be-written)).
When checking a backing root directly, `maki-check` needs no segment size:
like recovery, it bounds each journal segment file by the largest file a
writer can produce under any valid `journal_segment_size` (at most 1 GiB), so
segments written before the setting was lowered stay readable. Its
`--journal-segment-size` flag is still accepted, but no value within that
limit changes the verdict.

The deep report states one of three verdicts as an `info: deep check verdict:`
line, printed before any `warning:` and `ERROR:` lines; the report ends with
`check passed` or `check FAILED`. The verdict describes the volume: a
configuration mismatch (above) fails the check whatever the verdict says. A
check of a backing root it may not write states a fourth, `unproven`, in place
of `clean` and `recoverable` ([below](#checking-a-backing-that-cannot-be-written)).

| `deep check verdict:` | Meaning | Operator action |
|---|---|---|
| `clean` | Every allocated slot reads back and no unlisted slot holds a damaged header; ordinary replay of the journal is all the next attach does | None |
| `recoverable` | Some slot payloads are damaged, but each such unit has a validated journal record newer than the checkpoint, so recovery rewrites (or discards) the slot before the volume is exposed. The report lists them as `warning: slot: recoverable: …` and `check passed` | Attach normally; re-run the deep check afterwards and expect `clean` |
| `unrecoverable` | A slot is damaged and no journal record can repair it (the unit reads EIO at runtime), or checkpoint, canary or journal metadata failed validation in a way attach refuses. These are `ERROR:` lines and `check FAILED` | Restore from backup or migrate the database; do not edit format bytes |

A key canary with no valid copy is reported as `key canary: absent` or, when
canary files exist but none validates, `key canary: copies exist but no copy
validates`. Attach binds a new canary on a volume that holds no data, and on a
volume with data only after an integrity-capable provider decrypts existing
ciphertext; without such a provider, or with no ciphertext left (every unit
trimmed), it refuses. The offline check does not know the provider, so it
reports a lost canary as an `ERROR:` only when the volume has history but no
ciphertext to probe, which every attach refuses; otherwise it is a `warning:`
that says what attach needs.

The check reads every slot the map lists and probes the header of every
slot it does not list in an existing shard, exactly like the read path: a
non-zero header that does not decode on a cleared slot is damage (EIO at
runtime), not a hole.

The raw slot reader and recovery see different states of the same volume:
the checker reports what is on disk, the verdict says what the next attach
will make of it.

Run offline checks only after the daemon or nbdkit process has released the
volume lock.

### Checking a backing that cannot be written

On Linux, `volume inspect`, `check`, `check --deep` and `maki-check` ask the
kernel first whether the user running them may write the backing root
directory: the answer is no on a read-only mount (a read-only bind mount
too), for a directory without write permission for that user, and for an
immutable directory. Where it may, they open the backing as they always did.
Where it may not, a plain backing is opened read-only, and nothing below the
root is created, written, synced or removed. Other platforms, which serve
development only, do not ask and open every root as before. `maki` asks
about `backing.root`, and `maki-check` about the root it is given.

For a plain backing only the root decides, in both directions (a local
rollback-protected backing, below, also asks about its witness directory, and
a remote one is read read-only on every root). A writable root whose files the
user may not write still fails ("Permission denied", or "Operation not
permitted" for an immutable file), so make the root unwritable too (or mount
the backing read-only) to check such a copy. Conversely, a root the user may
not write is checked read-only even when its files are writable (a `0500`
volume directory holding `0600` files, which was checked as a writable backing
before): its deep verdict is now `unproven` where it was `clean`, and a
missing `volume.lock` is not recreated there. The deep check stops with
`volume lock: volume.lock is missing` (before, creating the file in such a
directory failed with "Permission denied").

A read-only check reads exactly what a writable one reads and finds the same
damage, but it proves less, and its report says so in a `warning: read-only
check:` line. Recovery rewrites and syncs everything it accepts, and repairs
what it must, before a writer resumes; through a read-only backing none of
that can happen, and what was read may exist only in the page cache (a failed
writeback, or a process that stopped before its sync, leaves bytes there that
the disk does not hold). Therefore:

- the deep verdict is `unproven` where a writable check would say `clean` or
  `recoverable`; an `ERROR:` still makes it `unrecoverable`;
- records newer than the checkpoint, which recovery would replay, and the
  journal repairs it would make (a torn tail to truncate, an unfinished
  segment to discard) are `warning:` lines, not `info:` lines;
- the deep check takes the volume lock shared, through a read-only
  descriptor. A writer is excluded as before (a daemon that starts during the
  check fails to take the lock, and the check refuses a volume a daemon
  holds), and other read-only checks are admitted. It cannot create a missing
  `volume.lock`, so without one it does not run and fails with `volume lock:
  volume.lock is missing`;
- the report still ends with `check passed` when nothing is wrong with what
  was read, and the exit status is the same as for a writable check: zero
  with `unproven`, so a script that gates on the exit status alone does not
  learn that the volume is `clean` (nor does it from a writable
  `recoverable`); read the verdict line.

| `deep check verdict:` | Meaning | Operator action |
|---|---|---|
| `unproven` | Read-only check only: nothing that attach refuses was found in what was read, but none of it is shown to be on disk, and nothing recovery would replay or repair (the `warning:` lines) was done | Attach where the backing can be written, which recovers it, or check it there for a `clean` verdict |

`volume inspect` prints the same fields read-only, and the fast check reports
the same lines plus the warning.

A rollback-protected backing is read read-only too: with a local witness where
the user may not write its backing root or its witness directory, either of
them, and with a remote witness always. Opening one to write, as attach does,
rewrites and syncs its authenticated pages, manifest and format marker and
publishes the witness anchor again by creating a new record in the witness
directory and renaming it over the old one; with a remote witness it claims a
writer at the authority and copies the current state into a namespace of its
own, which a command that only reads must never do. A local backing whose two
directories can both be written is opened to write, as before. Where the
witness directory cannot be written, that open would fail when it publishes
the anchor, before it writes anything in the backing. Where the backing root
cannot be written, the root decides as it does for a plain backing: the pair
is read read-only even when the files in the root could be written. (A
writable open would succeed there, for a `0500` root holding `0600` files, and
rewrite them, but could not recreate a missing lock file or manifest slot.)
The read-only open makes the authentication attach makes before the command
reads the volume: the format marker, the manifest the witness selects (exact,
canonical, of the witness's generation), the sizes of its slot and of the
arena, and every committed page against its digest. A damaged page, a manifest
the witness does not select, a configured capacity that differs from the
stored one and an unfinished creation are refused, as attach refuses them. It
creates, writes, syncs and removes nothing below the backing root or in the
witness directory, and asks a remote authority only to inspect: no claim, no
namespace, no operation guard. It takes the locks that keep a writer out
shared, and never creates them: `rollback.lock` and the witness directory's
`witness.lock`, which a writer holds while the volume is attached, or with a
remote witness the root's `remote.operation.lock`, which attach (while it
opens the backing), takeover, restore, snapshot and GC hold, and the current
namespace's `rollback.lock`, which its writer holds. It holds them before it
reads anything in either directory, apart from a remote root's format marker.
So, unlike on a plain backing, the fast check and `volume inspect` take a lock
too:

- `volume inspect`, `check` and `check --deep` all refuse a backing that a
  daemon or another writer holds (`… is held by another process`), and a
  missing lock file (`… is missing, and a read-only open cannot create it`);
- a daemon that starts while one of them runs fails to take its lock, and
  other read-only checks are admitted;
- with a remote witness the authority's record is read again once both locks
  are held, and one that changed in between refuses the command.

Every read is authenticated again, and every operation first asks the
witness whether it still selects what was read, as a writer's operations do:
a witness that stops selecting it stops the command with an error. The deep
verdict is `unproven`, as for a plain backing read read-only.

## Swap dependency checks

With `security.require_secure_swap_policy`, Linux attach accepts no swap,
RAM-only zram, or dm-crypt whose complete kernel dependency graph terminates
at independent physical devices. The same check applies to zram writeback.
Encrypted swap above NBD, including through partitions, LVM, or MD, is refused:
paging out Maki must not require Maki to serve that paging I/O. Missing or
inconsistent sysfs metadata, cycles, and unproven virtual backing are refused.
"dm-crypt" means a cryptsetup mapping of an encrypting type (LUKS1, LUKS2,
plain, loop-AES, TrueCrypt/VeraCrypt, BitLocker, FileVault2): cryptsetup also
names integrity-only (`integritysetup`), dm-verity and helper devices
`CRYPT-…`, and those are refused. A mapping set up with `cipher_null` cannot
be distinguished in sysfs; do not use one for swap.
Keep swap and its dependency topology fixed while the attachment is running;
this is an attach-time check, not a watcher of privileged device changes.

## Key binding at first attach

The first attach of a freshly created volume binds the configured provider and
key to it: Maki encrypts a fixed canary and stores it as `canary.a`/`canary.b`
in the backing root. Every later attach decrypts the canary before the volume
is exposed, so a rotated key file, a different key name, or a different
provider type under the same compatibility identity refuses attach with
`key canary verification failed` or `crypto identity mismatch`. This is the
only wrong-key detection for `local-aes-xts`, which otherwise decrypts to
garbage without an error.

After verifying an existing canary, attach rewrites and syncs both copies and
the backing directory before accepting I/O. A readable copy may have survived
only in the page cache after an earlier sync failure. This adds metadata I/O
on attach; a failed sync refuses attach and can be retried after correcting
the backing error. A wrong key is rejected before either copy is rewritten.

Consequences for operations:

- Attach a new volume once with the intended production key before handing it
  to a workload. If the wrong key was used on an empty volume, delete and
  recreate the volume rather than trying to re-bind it.
- Key rotation is a migration (new volume, copy data), not a config change.
- A volume written before canaries existed is bound on its next attach after
  one existing unit is decrypted with an integrity-capable provider
  (`local-aes-gcm-siv`, or a remote provider declaring integrity). Such a
  volume cannot be attached with `local-aes-xts` until it has a canary.

## Run nbdkit

Use a dedicated socket and one daemon per volume:

```bash
nbdkit --foreground \
  -U /run/maki/example/nbd.sock \
  /usr/lib/maki/maki-nbdkit.so \
  config=/etc/maki/volumes/example.toml
```

The plugin creates its Tokio runtime after nbdkit forks. Run it in the foreground,
including under systemd, and retain stderr in the service journal: attach and
unload failures are reported there. Background daemonization is not a qualified
logging mode. Clean shutdown closes I/O admission, waits for admitted callbacks,
flushes the engine, checkpoints durable state, and releases the volume lock.

After stopping workloads and unmounting their filesystems, use `maki drain` to
obtain an explicit durability acknowledgement before stopping nbdkit. The
plugin's unload callback cannot return an error to nbdkit; a zero process exit
status alone does not acknowledge a successful drain. The packaged service's
stop path is not a substitute for this administrative check. A drained daemon
refuses reads as well, which limits how a kernel attachment that is still
connected can be detached; see the [privileged helper](#privileged-helper).

### Logging

The plugin installs a `tracing` subscriber that writes to stderr as soon as
nbdkit has parsed its configuration, so every runtime event the engine,
store, control server and providers emit reaches nbdkit's log and, under the
packaged unit, the service journal. Without it these events would be
silently dropped; startup and unload failures were already printed directly.
The `maki` and `maki-check` binaries install the same subscriber, so an
offline check shows the repairs the store made at open. The privileged
helper `maki-attach` installs an equivalent one (from `maki-privileged`, which
links no crypto crate): every executed step is logged at `INFO` and every
halted rollback at `ERROR`/`WARN` ("rollback halted…", "keeping the attach
record"), and it reaches `journalctl -u maki-attach@<volume>.service`. Before
this, the helper dropped those reasons and showed only its exit status.

Events that matter operationally:

| Level | Event |
|---|---|
| `ERROR` | control socket server stopped; shutdown during unload failed; panic caught at the NBD boundary; `maki-attach` rollback halted (attach record kept) |
| `WARN` | checkpoint worker: journal sync failed / checkpoint failed; requested checkpoint failed; drain failed (I/O admission stays closed); rollback session stopped; endpoint quarantined at attach; allocation map repaired from slot headers; adopted or truncated shard data file; swap policy findings; automatic remote namespace GC did not complete, or kept namespaces it could not examine or could not finish retiring |
| `INFO` | default threshold; lifecycle milestones |
| `DEBUG` | free-space query failures, control session lifecycle |

`MAKI_LOG` selects the threshold with comma-separated
`tracing_subscriber::EnvFilter` directives, for example `MAKI_LOG=warn` or
`MAKI_LOG=info,maki_core=debug`. Each directive names its level: either a
level alone (`off`, `error`, `warn`, `info`, `debug` or `trace`, in any case)
or a target or span selector followed by `=<level>` (`maki_core::engine=debug`,
`[name]=trace`). EnvFilter itself would read a word without a level, such as
the misspelt `warning` or `err` or a bare `maki_core`, as a target enabled at
`trace` and turn every other target off, ERROR included, so Maki refuses it.
Unset or empty values mean `info`; so do invalid ones, and the process then
logs one `WARN` line, `MAKI_LOG is not a valid filter`, with a fixed reason
and the 1-based directive index when available. Selector values and detailed
parser errors are omitted because they can contain user data. A list without
a level alone logs only the targets it names:
`MAKI_LOG=maki_core=debug` hides the plugin's own `maki_nbdkit` errors, so
give the rest a threshold too, as in `info,maki_core=debug`. Set it through a
drop-in on the packaged unit:

```ini
[Service]
Environment=MAKI_LOG=info,maki_core::engine=debug
```

Lines carry the level, the target module and structured fields such as the
volume, operation and error class. Keys, plaintext, credentials and request
payloads are never passed to a log macro; `SecretBuffer` redacts itself.
Dependencies that would print payloads or credentials at trace level
(`tungstenite`, `tokio_tungstenite`, `reqwest`) are capped at `debug`, even
under `MAKI_LOG=trace` or a directive that names them
([observability](observability.md#logs)). The `tungstenite::protocol` subtree
is capped at `info` because its debug output also includes the peer's close
reason and reply frame. WebSocket handshake debug diagnostics remain available.
Read the journal with `journalctl -u maki@<volume>.service`.

## Rootless userspace smoke test

Use a disposable export at least 8 MiB in size. This test overwrites its first
8 MiB. The readback uses the nbdkit offset filter to copy exactly that range:

```bash
(
set -euo pipefail
uri='nbd+unix:///?socket=/run/maki/example/nbd.sock'
test_dir="$(mktemp -d)"

nbdinfo "$uri"
dd if=/dev/urandom of="$test_dir/source.bin" bs=1M count=8 status=none
nbdcopy --flush --synchronous "$test_dir/source.bin" "$uri"
export test_dir
nbdkit -r -U - --filter=offset nbd "$uri" range=8M \
  --run 'nbdcopy --synchronous "$uri" "$test_dir/roundtrip.bin"'
cmp "$test_dir/source.bin" "$test_dir/roundtrip.bin"

fio --name=maki-nbd-verify \
  --ioengine=nbd --uri="$uri" \
  --rw=write --bs=4k --size=8M --iodepth=1 --fsync=32 \
  --verify=crc32c --do_verify=1 --verify_fatal=1 \
  --verify_state_save=0
)
```

This covers Maki through nbdkit and libnbd without a kernel device. It does not
qualify `/dev/nbd`, LVM, XFS, or raw-device durability.

## Control plane

The data plane binds the per-volume control socket while attaching, at
`control.socket` or by default `/run/maki-control/<volume>/control.sock`, with mode
0660 and the group named by `control.group` (`maki-admin` in the packaged
example configuration; `sysusers.d` makes `maki` a member so the unprivileged daemon can apply
it). A socket that cannot be bound fails attach: a daemon without its control
socket is not operable. Rootless runs must therefore set `control.socket` to a
writable path. An address with a live listener, including a full connection
backlog, is refused instead of replaced. Stale sockets can be reclaimed; any
other file at the address (a regular file, a symlink, a directory) is refused
and left untouched, so a mistyped `control.socket` cannot overwrite volume
data. Concurrent publishers serialize the address check and publication. Clean
detach removes only the socket inode owned by that listener, so an older
daemon cannot remove a successor that reused its pathname.

The packaged `/run/maki-control` directory is `root:maki-admin` 0750; its
per-volume children are `maki:maki` 0711. This lets administrators traverse
the control path while `/run/maki` (`root:maki` 0750) restricts access to NBD.
The daemon keeps `Group=maki`. Set `control.group = "maki-admin"` to apply the
administrative socket group; omitting it retains the daemon's socket group.
NBD isolation relies on the restricted ancestor: nbdkit resets its own umask,
so a service `UMask` is not a socket-mode guarantee.
[nbdkit plugin manual](https://libguestfs.org/nbdkit-plugin.3.html#UMASK)

The unprivileged control socket uses one JSON object per line for requests and
responses. Each payload can be up to 64 KiB, excluding its terminating newline.
Writers send a newline after each object. A reader also accepts a complete
final object when the peer closes its write side immediately after the JSON.
An empty end of stream closes the session. Incomplete JSON at end of stream
produces a parse error.

The `maki` CLI exposes the supported operations:

```bash
maki status /etc/maki/volumes/example.toml
maki metrics /etc/maki/volumes/example.toml
maki checkpoint /etc/maki/volumes/example.toml
maki drain /etc/maki/volumes/example.toml
maki reload /etc/maki/volumes/example.toml cache --max-bytes 268435456
maki reload /etc/maki/volumes/example.toml cache --max-bytes 268435456 --ttl 1s
```

The control commands read the configured socket path and skip attach-time
validation. The full file must still parse as a Maki configuration. If an edit
prevents parsing, use `--socket` to reach the running daemon directly. The
packaged configuration is readable only by root and group `maki`, so members
of `maki-admin` also use this form.

```bash
maki status --socket /run/maki-control/example/control.sock
maki drain --socket /run/maki-control/example/control.sock
maki reload --socket /run/maki-control/example/control.sock cache --max-bytes 268435456
```

`drain` permanently closes admission to reads, writes, flushes, checkpoints,
and reloads for that attachment. It waits for already admitted callbacks,
including writes still waiting for encryption, then flushes and checkpoints.
Success returns `checkpoint_sequence`; repeated drains return the same
acknowledgement. `status` and `metrics` remain available, and the daemon retains
the volume lock until shutdown. Reattach to resume I/O.

The reads it refuses include the ones LVM makes on the exported PV, so after a
drain `vgchange -an` can no longer read the VG's metadata from the device. The
[privileged helper](#privileged-helper) section says what that leaves of
detach and cleanup.

`status` includes `io_state` (`running`, `draining`, `failed`, or `drained`) and
`drain_error`. A failed drain returns an error to the CLI, preserves the engine
and volume lock, and keeps admission closed. Correct the storage failure and
retry `maki drain` while the process is still alive. A timeout is not an
acknowledgement: inspect status and retry. If the process exits after a failed
drain, its unload error is logged; the next attach performs recovery. Do not
treat process cleanup or socket removal as proof that the failed barrier
succeeded.

`reload cache` needs the new size, between 1 byte and the device size; it is
refused (not silently accepted) outside that range and on a daemon running
with `cache.mode = "off"`. Optional `--ttl` uses the configuration duration
syntax and must be positive; omitting it keeps the current TTL. The daemon
validates the complete payload before applying size and TTL together. Invalid
TTL and unknown fields leave both settings unchanged.

Attach, detach, mount, unmount, NBD, and growth verbs are deliberately absent
from the control socket.

## Data-plane readiness

The packaged data-plane service uses `Type=notify`. The native plugin opens
the configured volume in nbdkit's `after_fork` callback, before the first NBD
client, and sends `READY=1` after recovery, the configured provider checks, and
control socket binding succeed. `maki-attach@` therefore waits for this initial
data-plane readiness through its existing `BindsTo=` and `After=` ordering.
An initialization or notification failure fails startup. The initial deadline
is 180 seconds. During journal recovery, completed scan, repair and replay work
can send `EXTEND_TIMEOUT_USEC=180000000`, at most once every 30 seconds. There
is no timer sending extensions while an operation is blocked; without further
progress the last granted deadline expires. Provider verification receives no
unconditional heartbeat. Qualify startup and recovery time for the selected
journal size, storage and provider, including a single slow operation that
cannot report progress within the deadline.

The packaged foreground process is the notification sender. A failed progress
notification prevents `READY=1`, even if subsequent recovery completes. These
messages do not persist a replay checkpoint across process termination or OOM;
repeated interrupted recovery still needs the target-profile campaign. Manual
runs without `NOTIFY_SOCKET` initialize before accepting clients without sending
service notifications.

This notification does not certify XFS attachment, database recovery, or
continued health. Mount readiness still requires successful attach, and every
workload start needs the fresh [storage identity gate](storage-recovery.md#checking-storage-before-each-workload-start).
The lifecycle follows nbdkit's [after-fork callback contract](https://libguestfs.org/nbdkit-plugin.3.html#Callback-lifecycle)
and systemd's [notification protocol](https://github.com/systemd/systemd/blob/v252/man/sd_notify.xml#L370).

## Privileged helper

`maki-attach` reads its parameters from the root-owned
`/etc/maki/attach/<volume>.toml` (template:
[`packaging/examples/attach.toml`](../packaging/examples/attach.toml)): the Maki
volume UUID, the mountpoint, VG and LV names, an optional pinned NBD device and
an optional expected XFS UUID. The production profile also provides the complete
PV UUID set, VG UUID and configured target-LV UUID in `[lvm_identity]`.
Every executing verb (attach, detach, cleanup, recover, grow, verify, and
the `recover-failed-start` hook) reads this file only when it is a root-owned regular file with one link, not
writable by group or others, below root-owned directories with the same
restriction: the helper runs as root on what it says. `--plan` reads any file.
Without `--config`, only a default path that does not exist selects the
built-in defaults. A path the caller cannot examine, for example because
`/etc/maki/attach` is closed to that user, is an error that names the path,
for `--plan` too: a plan from the defaults would show another attachment than
the configured one.
For attach, detach, recover, cleanup and grow, command-line flags override the
NBD device, NBD socket, VG, LV, mountpoint, volume UUID and XFS UUID, and
`--init-sentinel` (attach only) turns the sentinel option on, never off.
`device_block_size` and the LVM pins come from the file only. `verify` and
`recover-failed-start` accept no override, and `recover-failed-start` reads
only the default path (it refuses `--config`).
Every value is checked before it reaches a system utility: option-like values,
relative or non-canonical paths, non-canonical pinned devices (`/dev/nbd01`)
and malformed UUIDs are rejected with exit code 2 and no plan is printed.

Right before the XFS mount the helper checks the mountpoint path itself:
every ancestor directory must be a real directory (no symlink), owned by
root and not writable by group or others, and the mountpoint must be a real
directory. `mount(8)` runs as root and resolves the path, so a workload able
to replace a component could otherwise have its filesystem mounted over, say,
`/etc`, where neither rollback nor detach would find it. Use a mountpoint
such as `/srv/<volume>` created by root (`install -d -m 0755 /srv/<volume>`):
the mountpoint directory itself must also be root-owned and not writable by
group or others, or a workload could stack a FUSE mount over it before the
volume is mounted. It is hidden once the volume is mounted; the volume's own
root directory carries the workload's ownership. If the workload unit's
`CapabilityBoundingSet=` drops both CAP_DAC_READ_SEARCH and CAP_DAC_OVERRIDE,
that root must stay readable and searchable by root, or the workload's verify
gate fails (see the gate requirements below). `/` is refused as a mountpoint.

Before its LVM activation, attach inventories the recorded NBD and its kernel
partitions, compares independently probed PV identifiers with the complete VG
report, and limits activation to those devices and the discovered VG UUID.
It refuses incomplete or foreign membership, duplicate PV labels, existing
holders, overlapping PV regions, blank or unclassified candidates, shared VGs,
nonempty VG system IDs, and cachevol layouts. This requires compatible LVM2
report and scoped activation options.
When `[lvm_identity]` is present, attach additionally requires the observed PV
set and VG/target-LV UUIDs to equal the administrator pins before activation.
Those pins become part of the trusted record. Recovery does not read LVM
metadata again: it checks the identity persisted from attach's report against
the pins, and the live device-mapper mappings against that identity or the
post-activation mapping proof. A grow or detach whose current configuration
omits or changes them is refused before mutation. Omitting the table is
supported only for compatibility and is outside the production profile. The
checks do not coordinate host udev or other
privileged processes. See [the support limits](storage-recovery.md#checking-lvm-before-activation)
before using an existing partition layout or host activation policy.

The helper prints an auditable operation plan before execution. Always review
plan mode first:

```bash
maki-attach attach --volume example --plan
maki-attach detach --volume example --plan
maki-attach grow --volume example --size-bytes 2147483648 --plan
```

`grow --size-bytes` is an absolute minimum LV size in bytes, given as plain
decimal digits and a multiple of 512. LVM may round
up to its extent size; an LV already at or above the target is left unchanged,
and XFS growth is retried. Reuse the same target after a timeout or failure,
including a failure after `lvextend` already changed the LV. The former
`--add-bytes` option is rejected because a relative increase cannot identify
a retry. Growth revalidates the live attachment before each mutation and
never shrinks the LV or filesystem.

For attachments with a stored mapping proof, packaged growth requires direct
mappings to the qualified whole-device single-PV layout. Partition-PV and
layered mapper layouts are refused before either `lvextend` or `xfs_growfs`:
extending into another partition can change the mapper's slave list and
invalidate the recorded attachment proof. Attach's partition inventory does
not establish support for growing that layout.
New attachments capture this proof; legacy records without one retain their
existing checks and do not establish qualification for other layouts.

Execution (Linux, root) then:

1. opens `/run/maki-attach` through verified root-owned directory descriptors,
   takes its private `attach.lock`, and, unless a device is pinned, allocates
   the lowest unused `/dev/nbdN` from sysfs. Automatic selection skips connected
   devices, devices whose root or partitions have holders or direct mounts
   in the helper's mount namespace, and devices that another volume's
   attachment record names. Unreadable or inconsistent observations
   refuse allocation; the helper checks the selected device again before
   connecting it;
2. records the requested attachment and a random connection identifier before
   connecting NBD, then connects with the configured block size, waits until
   the device reports a size, and verifies its kernel backend identifier. An
   allocated device that the kernel keeps refusing as busy is given up for
   the next free one: the record is replaced by one that names that device,
   under a new identifier, before it is connected;
3. activates the VG and records its mapping identity, then verifies XFS TYPE
   and the optional configured `fs_uuid` with a bounded block probe before
   mounting with `noatime,nosuid,nodev`: the filesystem's bytes come from the
   unprivileged daemon and the provider, so a setuid binary or a device node
   in it never takes effect on the host. Workloads that need setuid programs
   or device nodes on the volume are not supported. It rechecks backend/mapping identity around that probe. After
   mounting, `--init-sentinel` (or `init_sentinel = true`, first boot only)
   creates `<mountpoint>/.maki-sentinel` holding the volume UUID, never
   overwriting a different value; see [attachment limits](storage-recovery.md);
4. verifies the mount identity (including `nosuid` and `nodev`) from `/proc/self/mountinfo`, `blkid`, sysfs NBD
   state, the sentinel, and a read/write probe (the mount root belongs to the
   workload: the sentinel is opened without following symlinks and read to a
   4 KiB bound, the probe file is created exclusively under an unpredictable
   name, so nothing planted there can make root overwrite or block);
5. on any failure rolls back the executed steps in reverse (umount, VG
   deactivate, NBD disconnect — a device that connected but never became
   ready is disconnected too, only if its recorded backend identity still
   matches) and exits non-zero, reporting rollback steps that themselves failed.

Attachment records live in `/run/maki-attach/<volume>.nbd`, under a
`root:root` 0700 directory. Records are bounded, private, single-link regular
files containing versioned JSON. The helper refuses symlinks, writable
ancestors, unexpected ownership, and malformed or legacy device-only records.
An atomic replacement binds the volume UUID, socket, mountpoint, VG, LV,
optional administrator LVM pins, device, random connection identifier, and
either the pre-activation recovery intent or the complete post-activation
mapping proof.

A record can outlive its kernel connection: a helper killed between publishing
the record and connecting, or between disconnecting and retiring it, leaves a
record whose device has no backend, holder or mount. The device stays that
volume's until its next attach replaces the record, or its next cleanup,
detach or recover retires it. Every attach therefore reads all records under
the lock before choosing a device: automatic selection skips a device that
another volume's record names, a pinned `nbd_device` that another volume's
record names is refused, and a `<volume>.nbd` entry that cannot be read refuses
the attach and names the file, because it could name any device.

A recorded device can still be found connected under another identity: an
NBD client started outside the helper, or two volumes left sharing a device by
a helper from before this rule. The device is no longer the record's, but the
record is still the only authority over what its attachment may have left: a
mount at its mountpoint, or a mapping of its VG, which on the device's number
would now read the other connection's data. Attach, cleanup, recover and
detach of the recorded volume therefore retire such a record, under the lock,
only when every observation shows that nothing of the attachment remains:

- the record names its VG UUID, in its mapping proof, its pre-activation
  intent or the administrator LVM pins;
- no device-mapper device on the host belongs to that VG (its uuid starts with
  `LVM-` and the VG UUID without dashes), and every holder of the device and of
  its partitions is an LVM mapping of another VG, whose uuid is `LVM-` and
  that VG's UUID. A crypt, multipath or partition mapping, a mapping without a
  uuid, or any other kind of holder keeps the record;
- nothing is mounted at the recorded mountpoint, and no mount is of a mapping
  of that VG;
- no other volume's record names the device with the same VG UUID (a cloned
  image) or with none;
- the device keeps the same backend across two such observations of the host.

Retiring runs no command and touches neither the device nor its connection.
Cleanup, recover and detach then succeed; detach logs that nothing was
attached. Attach goes on to choose a device without the recorded one, which is
connected and may also be reserved by the other volume's record. Grow refuses
and points to cleanup.

Otherwise every verb refuses without changing anything, keeps the record and
names what keeps it, including an observation that cannot be read. A mapping
of the recorded VG that still sits on the device's number reads the other
connection's data: stop whatever uses it first. Then detach the volume or
disconnect the client that uses the device and run
`maki-attach cleanup --volume <volume>`, which finds the device without a
backend and continues as for any disconnected attachment. A record that names
no VG UUID (an attach without `[lvm_identity]` pins that stopped before LVM
activation, or a record from before activation intents) is never retired this
way. If the device's present user has to stay up, confirm independently that
nothing is mounted at the recorded mountpoint and that no device-mapper mapping
of the recorded VG exists, and only then remove `/run/maki-attach/<volume>.nbd`
by hand.

`maki-attach detach` takes the same lock and compares the requested attachment
with that record and the live `/sys/block/nbdN/backend` before unmounting or
deactivating a VG. It verifies the backend again immediately before disconnect,
including rollback. Missing records or mismatched identities refuse execution;
an explicit `--nbd-device` cannot bypass this check. After the disconnect,
detach and cleanup wait, still under the lock, until the device shows no
connection (up to 15 s, as described under [prerequisites](#prerequisites)),
and retire the record only then. A device that still shows the connection, or
shows one under another identity, keeps the record and fails the command; one
whose backend cannot be read fails it too. Once nothing holds the device open,
a later run finishes the first case; in the second a later cleanup retires the
record only by the rules above for a device connected under another identity.

Detach, cleanup, recover and grow address the VG only where attach found it.
Their `vgchange --activate n` and `lvextend` run with the record's candidate
PVs as `--devices`: the NBD device and its partitions as the mapping proof or
the pre-activation intent recorded them, or the NBD device alone for a record
from before both. The deactivation also selects the recorded VG UUID, which
the proof's mapping uuids or the intent name; for a record with neither it
comes from the administrator pins, and pins must always agree with the record.
`lvextend` has no selection: with `--devices` it looks for the VG name only on
those devices, and grow runs it only after checking that the live mapping is
the recorded one. A VG of the same name on another disk (a second disk, a
cloned image) is therefore never extended or deactivated, and because
`--devices` replaces the host's own LVM device scan, a devices file or filter
that leaves `/dev/nbd*` out does not stop detach or grow either.

For a record with a mapping proof, or one from before proofs and intents, the
deactivation also names the VG: when LVM cannot read it, as after the daemon
stopped serving, the command fails instead of succeeding without effect, and
cleanup can continue with the fallback below. The deactivation of a
pre-activation intent selects the VG by UUID without naming it, as before; the
helper observes the mappings again afterwards instead of trusting its status.

`maki-attach cleanup --volume <volume>` is the idempotent selector used by the
packaged service lifecycle. Under the same single attach lock, no trusted
record is already clean and succeeds without probing the backend. A matching
connected backend follows the detach path; a known absent backend follows the
recovery path. An unreadable backend fails before mutation and keeps the
record; a backend under another identity is never touched, and its record is
retired only as described above. Re-run cleanup after a partial successful effect; each selected
path re-observes storage identity before its next change.

If the daemon stops serving reads while its recorded kernel connection is
present (a dead nbdkit server, or a daemon after `maki drain`, which refuses
every read), only
`cleanup` has a narrow fallback for the resulting LVM read failure. It first
runs the normal `vgchange -an`; only an exited command with a nonzero status may
continue. The completed post-activation proof must contain one recorded target
mapping and no other DM layer. The current mapping must still match its name,
UUID, major/minor, slave edge and backend nonce, have no mount or foreign holder,
and report open count zero through `dmsetup info`. Cleanup then issues one plain
`dmsetup remove` for that exact name, rechecks that the mapping and holder are
gone, and only then disconnects NBD. It never uses force, deferred removal, or
retry flags.

Explicit `detach` and `recover`, a pre-activation intent, multi-LV/internal
thin/cache/RAID mappings, open or changed targets, backend changes, and command
timeouts do not enter this fallback. They retain the trusted record and require
operator diagnosis. This limit keeps direct device-mapper mutation within the
single-LV topology qualified on the disposable GCE host.

After `maki drain` these limits decide how the attachment comes down. The
cleanup that the target stop runs finishes a single-LV attachment through the
fallback. An explicit `maki-attach detach` stops at the failed `vgchange -an`
and keeps the record; run `maki-attach cleanup` instead. On a VG with an
additional LV or an internal mapping the fallback is refused as it is after a
server death (the proof lists every mapping attach activated), and the VG
stays active on a daemon that will not serve LVM's reads again. Detach such a
volume before draining it (see the planned stop below).

Detach retries observe current mountinfo and sysfs state before each step.
An already completed unmount or VG deactivation is skipped. A remaining mount
must identify the expected LV device and XFS root, and active VG mappings must
use the recorded NBD device. Detach, cleanup and attach rollback identify the
mount from kernel metadata only: the sentinel lives in the workload-owned mount
root, so deleting or rewriting it must not be able to block cleanup (attach and
`verify` still require it). A different mount or backend,
unreadable observations, remaining device holders (including partition
holders), and direct mounts of the NBD device or its partitions block unsafe
deactivation or disconnect.

If attach stopped after verified activation but before publishing the complete
mapping proof, normal detach may use the saved recovery intent only while its
backend nonce remains connected. It refuses any mount and any changed device,
partition, mapper name, UUID, dependency or holder. A verified partial mapping
subset can be deactivated with the recorded device list and VG UUID; an unknown
internal LVM UUID suffix is not treated as owned. The intent never authorizes an
unmount or workload access. LVM reads the volume group from the NBD device for
this deactivation, so it works only while the daemon serves that device; the
packaged failed-start hook runs it before the recovery coordinator stops the
daemon, and [one state is left to the operator](#interrupted-activation-after-the-daemon-stopped).

If disconnect succeeded but the process stopped before retiring its record,
a retry may remove that record without running device commands only after
confirming the mount is absent, the VG is inactive, and the disconnected NBD
has no observed remaining use. This uses the helper's current mount namespace;
cross-namespace operational qualification remains a target-host check. The
trusted record format and the legacy migration requirements remain the same.

This requires a kernel whose `nbd` netlink family takes the backend identifier;
the helper refuses to connect on one that does not, and an unverifiable
connection fails closed. The helper sets the identifier itself; until the
change that made it do so, it ran `nbd-client` 3.27 or later, which set the
same kernel attribute, so attachments connected that way stay detachable.
Qualify the updated helper on the intended Linux target before deployment:
every external campaign that attached a kernel NBD device did so through
`nbd-client` (3.27.1 where the report names the version; 3.24 in the
2026-09-02 privileged run), and none covers the helper's own connect.

`maki-attach@<volume>.service` becomes active after the identity check passes.
Its `RemainAfterExit=yes` retains that past result even if the mount later
disappears; the service state is not a live readiness check. The packaged
`maki-workload@<volume>.target` requires the attach unit, while the attach unit
binds to the daemon. `AssertPathExists` makes a missing attach configuration
fail startup. Every registered workload start also needs a fresh mount/backend
identity check, including container recreation. Execution without a volume
UUID is refused.

Use `maki-attach verify --volume <volume>` as the repeatable, read-only storage
gate. It requires root privileges, an existing trusted attachment record and
both UUIDs pinned in the root-controlled attach configuration. Do not pass
`--plan` to a workload gate: that option only prints a preview. For a host
systemd service whose namespace exposes the configured mount, install the
example `packaging/examples/maki-workload.service.d/10-maki.conf`, replace `pg`
with the volume name, and adapt it below the real workload unit. Its essential
contract is:

The gate proves current kernel identity, mapping and mount topology, including
a read-write mount with `nosuid` and `nodev`; a volume mounted before that rule
(or remounted without it) fails the gate until it is reattached. It does not
perform data I/O or test nbdkit process liveness. In the qualified crash run it
still returned success immediately after nbdkit was killed because the kernel
NBD connection and mapping remained. The lifecycle must react to daemon failure
and complete cleanup/restart rather than treating `verify` alone as a health
probe.

```ini
[Unit]
BindsTo=maki-attach@pg.service
After=maki-attach@pg.service
PartOf=maki-workload@pg.target
Conflicts=maki-recover@pg.service

[Service]
ExecStartPre=!/usr/bin/maki-attach verify --volume pg

[Install]
RequiredBy=maki-workload@pg.target
```

The `!` keeps the helper's root user/group credentials while retaining the
service's other restrictions, including its filesystem view. The gate must
still be able to read the trusted configuration/state and probe the verified LV
under those restrictions: it opens `/dev/<vg>/<lv>`, so the unit must not use
`PrivateDevices=yes`, and any `DevicePolicy=` must allow reading that node.
It also opens the mounted volume's root directory and reads `.maki-sentinel`
in it. The gate runs as root, but only with the capabilities the unit's
`CapabilityBoundingSet=` keeps. If that drops both CAP_DAC_READ_SEARCH and
CAP_DAC_OVERRIDE, the kernel checks the gate's opens against the mode bits as
for any process with user and group root: it needs read and search
permission on the volume root and read permission on the sentinel. A volume
root owned by the workload user with mode `0700` (or `0750` with the
workload's group) then fails the gate with EACCES (`Permission denied`), and
so does a sentinel the workload replaced with one root cannot read (attach
creates it root-owned, mode `0600`). For such a unit, keep CAP_DAC_READ_SEARCH
(sufficient on its own) or CAP_DAC_OVERRIDE in the bounding set, or leave the
volume root readable and searchable by others (for example `0755`) with the
workload's private directory below it, as the
[PostgreSQL guide](deployment/postgres.md) does. The gate retries an open only
without `O_NOATIME`, when the kernel refuses that flag (it needs CAP_FOWNER
for an inode root does not own), never after EACCES.
Keep the configuration root-controlled; this is not a generic sudo grant. A
failed check prevents that start. Qualify the service's actual mount namespace
and sandbox on the target host. A host check cannot establish which
filesystem an existing container's bind mount exposes; stop and recreate those
bindings through the workload recovery procedure. See the
[gate's checks and limits](storage-recovery.md#checking-storage-before-each-workload-start).

Enable the workload so its `RequiredBy=` link is installed, then enable and
start the lifecycle target:

```bash
systemctl enable your-workload.service
systemctl enable --now maki-workload@pg.target
```

Do not enable `maki@pg.service` or `maki-attach@pg.service` directly. A daemon
failure triggers `maki-recover@pg.service`, which stops the target's registered
workloads, attachment, and daemon. Only a successful cleanup activates the
target again; the workload's privileged `ExecStartPre` gate then rechecks the
new attachment. Configure the workload so its start succeeds only after its
own database recovery and health gate is complete.

For Docker, put container creation and removal in the registered workload unit
and disable an independent `restart: always` path that could bypass the target.
Docker bind mounts are `rprivate` by default, so a host remount does not make an
old container safe; the lifecycle must stop and create the container again.
For a normal packaged shutdown, stop `maki-workload@pg.target` while engine
admission is still open. Filesystem unmount may need to write dirty data or
metadata; running `maki drain` before unmount prevents those writes. The
target stop unmounts through attach cleanup. Only successful cleanup queues
daemon shutdown and its final drain. A cleanup failure, timeout or killed
helper leaves the daemon running so a remaining mount keeps its backend.
Do not stop only the workload or attach unit: the
`Requires=` and `PartOf=` relationships can deactivate the rest of the graph.
For an explicit durability acknowledgement, first quiesce and close the
application through its own shutdown interface, unmount its verified filesystem
while the daemon is running, then run `maki drain` and require success before
stopping the target. If unmount fails, keep admission open and resolve that
failure; a successful drain cannot substitute for a successful unmount.
The target stop after a drain has to deactivate the VG while the daemon
refuses LVM's reads: it depends on the cleanup fallback above, which covers
only the qualified one-LV topology. With an additional LV in the VG, close
whatever uses it and run `maki-attach detach --volume pg` (the command, not a
stop of the attach unit) before `maki drain`, in place of the manual unmount:
the helper unmounts, deactivates the whole VG and disconnects NBD while the
daemon still serves reads, and leaves the daemon running. `maki drain` then
returns its acknowledgement as before, and the target stop finds no
attachment record left to clean up.

The target stop orders the workload before attach cleanup; successful cleanup
requests daemon shutdown without waiting inside the attach stop job. The
request uses `--job-mode=fail`, so it cannot replace an already queued
start/restart. Such a conflict preserves the daemon instead of failing the
completed detach. Any other stop-request error also leaves the daemon running
and must be diagnosed if the full-stop wait below does not finish.
The target's own stop job may finish while those
dependent stop jobs are still deactivating. Wait for every lifecycle unit to
become inactive before running an offline check, taking a snapshot, or removing
backing storage:

```bash
# Succeeds once every named unit is inactive; fails at once if one failed
# (inspect it before continuing) or after WAIT_SECONDS (default 600).
wait_stopped() {
    local unit state pending deadline=$((SECONDS + ${WAIT_SECONDS:-600}))
    while :; do
        pending=
        for unit in "$@"; do
            state=$(systemctl show -P ActiveState "$unit") || return 1
            if [ "$state" = failed ]; then
                echo "$unit failed: preserve the host state and inspect it" >&2
                return 1
            fi
            if [ "$state" != inactive ]; then pending="$unit ($state)"; fi
        done
        [ -n "$pending" ] || return 0
        if [ "$SECONDS" -ge "$deadline" ]; then
            echo "Still waiting for $pending" >&2
            return 1
        fi
        sleep 1
    done
}
systemctl stop maki-workload@pg.target
wait_stopped your-workload.service maki-attach@pg.service maki@pg.service &&
    maki check /etc/maki/volumes/pg.toml
```

Do not wait with `systemctl is-active`: it fails, and so ends a wait loop, as
soon as a unit is `deactivating` (the daemon is still flushing, checkpointing
and holding the volume lock) or `failed` (attach cleanup left a mount or
mapping behind). Wait for `ActiveState` to read `inactive`. If a unit fails or
the bounded wait expires, preserve the host state for diagnosis rather than
forcing NBD, LVM, or device-mapper cleanup.
The 2026-09-17 combined qualification observed this asynchronous tail directly;
after all named units became inactive, no mount, mapping, NBD connection,
trusted volume record, or workload container remained.

`systemctl restart maki-workload@pg.target` restarts the attachment and registered
workloads while retaining the daemon when their restart job prevents its stop.
For a new daemon process, configuration or credential reload, use the full
stop, wait for every unit to become inactive, then start the target.

> [!CAUTION]
> For attach, detach, recover and grow, removing `--plan` executes the planned
> storage changes on Linux. The separate `verify` command performs observations.

The helper has no crypto dependencies and must not receive provider credentials.

## systemd deployment

The repository provides templates under `packaging/systemd/`, users and groups
under `packaging/sysusers.d/`, and runtime directory rules under
`packaging/tmpfiles.d/`.

The data-plane unit runs as `maki`, has an empty capability set, disables core
dumps, uses `NoNewPrivileges`, and receives crypto credentials. The attach unit
is a separate privileged oneshot service without credentials.

The recovery template uses `OnSuccess=`, which requires systemd 249 or later.
This version boundary is recorded in the
[upstream v249 unit documentation](https://github.com/systemd/systemd/blob/v249/man/systemd.unit.xml).

The attach oneshot's `ExecStopPost` invokes `maki-attach recover-failed-start`.
It schedules the recovery coordinator only when systemd reports both a failed
service result and a failed main (`ExecStart`) process, and the exact attach
unit still has a running start job. A stop, restart, missing or unrecognized
job does not authorize recovery. The coordinator stops
registered workloads before identity-checked cleanup and starts the lifecycle
again only after cleanup succeeds.

The hook itself performs one cleanup, on the same evidence, after it has asked
systemd to queue the coordinator. It also runs when systemd refuses that
request, for example while the coordinator is masked as in the maintenance
procedure below: it is the rollback the dead helper would have run, checked
against the recorded identity. If the trusted record holds only a
pre-activation intent and its device still carries the recorded backend
identifier (the helper died between LVM activation and the mapping proof), the
hook runs that attach's rollback: the scoped VG deactivation of the
[privileged helper](#privileged-helper), then the NBD disconnect, and it
retires the record. The coordinator cannot do this later, because it stops the
daemon before its cleanup and LVM can then no longer read the volume group.
The coordinator's stop of the daemon is ordered after the attach unit's stop
job, which does not finish before the hook does, so the daemon is still
serving while the hook runs. The hook never unmounts and leaves every other
record to the coordinator. It first reads the record, without the attach lock.
Only when the record holds an intent does it read the same
`/etc/maki/attach/<volume>.toml` as `cleanup`, so an invalid or untrusted
attach configuration is reported by the hook only when there is an activation
to roll back.

Three bounds keep the hook inside the unit's `TimeoutStopSec=120` and inside
what the coordinator's `JobTimeoutSec=360` leaves after the daemon's stop
(systemd's default of 90 seconds) and its own cleanup (`TimeoutStartSec=180`).
The hook first waits up to 15 seconds until it is the only process in the
attach unit's control group: a command of the failed start, such as a
`vgchange` that defers signals until it has finished, can outlive the helper
there. This check needs the unified cgroup hierarchy. It then waits up to 40
seconds for the global attach lock, in turn behind the helpers already waiting
for it (other volumes' attach, detach and cleanup), and its commands, with the
wait for the device after its disconnect, have 30 seconds once it holds the
lock. If the record or the control group cannot be read, the group does not
settle, a bound expires, or the rollback is refused, the hook logs the reason
and the coordinator proceeds as it would have without it. An attach of another
volume can hold the attach lock for up to its 180-second start timeout, longer
than any lock wait these timeouts leave room for: contention of that length is
one way into
[the state below](#interrupted-activation-after-the-daemon-stopped).

The planned stop's `cleanup` (`ExecStop`) runs under the same
`TimeoutStopSec=120`, and its wait for the device after the disconnect holds
the attach lock for up to 15 seconds. When the devices of many volumes are all
held open at their disconnects (a monitoring tool that keeps every
`/dev/nbdN` open) and the volumes stop together, their cleanups queue on the
lock and each keeps it for the whole 15 seconds. From about the eighth in the
queue on, cleanups reach their stop timeout, the later ones while they still
wait for the lock. systemd ends such a cleanup before it has changed anything:
the attachment and its record stay as they were. In a planned stop of the
attach units the daemon keeps serving, and the stop is retried as for any
[failed planned stop](#retry-a-failed-planned-stop). At a host shutdown
nothing retries it: `maki@` is stopped next all the same (`maki-attach@` is
ordered after it), so a filesystem that such a cleanup did not unmount stays
mounted, for the rest of the shutdown, on a device whose daemon is gone.
Either way the record is kept and the stop fails, as it does for a cleanup
whose own wait ran out; the failure only comes by timeout, and in a planned
stop a cleanup ended during its own steps is resumed by the next one, which
observes again before each step.
Behind three such cleanups the failed-start hook's 40-second lock wait expires
as well, and the coordinator proceeds without it, as above.

Attach starts are limited to three in 300 seconds; inspect the failure before
resetting a start-limit failure.

A successful `ExecStart` followed by failed `ExecStop` cleanup does not request
an automatic restart. A stop already replacing the attach start job also
prevents the hook from scheduling recovery. The manager query and recovery
request are separate operations: a concurrent operator stop can race that
request, and stopping only the workload target does not cancel an already
running coordinator's `OnSuccess` restart.

For maintenance during a failed or recovering start, first block new recovery
requests, then stop the coordinator before stopping the workload lifecycle:

```bash
systemctl mask --runtime maki-recover@pg.service &&
    systemctl stop maki-recover@pg.service &&
    systemctl stop maki-workload@pg.target
```

Wait for the workload and attach stop jobs to finish and inspect any failed
unit. A cancelled attach start skips `ExecStop` and preserves the daemon and
any partial attachment for explicit cleanup. A failed cleanup also keeps the
daemon running. Keep the runtime mask until recovery is deliberately re-enabled
with `systemctl unmask --runtime maki-recover@pg.service`; a reboot removes a
runtime mask. This procedure must be qualified on the installed stack.

### Interrupted activation after the daemon stopped

One state has no helper path. The attach helper died between LVM activation
and its mapping proof, so the record holds only the pre-activation intent and
the VG's mappings are active but unmounted; and the daemon behind the
recorded kernel connection stopped serving reads before that activation was
rolled back. That takes a second fault: the daemon failed or was stopped
within the same window, or the hook's rollback above did not complete before
the coordinator stopped the daemon, for example because other helpers held
the attach lock for longer than the hook waits for it. LVM cannot read the
volume group through that connection again (a restarted daemon serves new
connections only), and the `dmsetup` fallback requires the completed mapping
proof. `maki-attach cleanup`, and with it `maki-recover@pg.service`, then
fails with an error that ends in one of

```text
scoped LVM deactivation of the interrupted activation on /dev/nbd3 failed (...). LVM reads the volume group from that device and can deactivate the mapping only while the volume's daemon serves it; keeping the attach record
scoped LVM deactivation of the interrupted activation on /dev/nbd3 left its mapping active. LVM reads the volume group from that device and can deactivate the mapping only while the volume's daemon serves it; keeping the attach record
```

and the next attach reports `recorded device is still connected`. The record,
the kernel NBD connection and the mappings stay as they are. Nothing was
mounted from this activation, and the intent never allowed a workload to use
it.

Mask the recovery coordinator as above and keep the workloads stopped. For
each device-mapper name of the volume group (`vg_maki_pg-data` for the default
names; LVM doubles a hyphen that is part of a VG or LV name, and `dmsetup ls`
lists them), confirm that it is an unused LVM mapping on the NBD device the
message names, remove it without force, and let cleanup finish:

```bash
dmsetup info -c -o name,uuid,open vg_maki_pg-data  # UUID starts with LVM-, Open is 0
dmsetup deps -o devname vg_maki_pg-data            # only that nbdN or its partitions
dmsetup remove vg_maki_pg-data                     # never --force or --deferred
maki-attach cleanup --volume pg
```

A plain `dmsetup remove` refuses a mapping that is open, including one that
another mapping is stacked on; remove the upper one first, by the same checks. Cleanup then
verifies the recorded device identity again, disconnects NBD and retires the
record. Stop the daemon if it is running and reset the failed units before
re-enabling recovery, as after [a failed planned stop](#retry-a-failed-planned-stop).
If a mapping is open, does not carry an LVM UUID, or depends on any other
device, stop and preserve the host state for diagnosis. A reboot also ends
this state: the mappings, the kernel connection and the record under `/run`
do not survive it.

### Retry a failed planned stop

Keep the recovery coordinator masked as above and every registered workload
stopped. Resolve the reported holder, open file or working directory without
forcing NBD or device-mapper removal. Retry identity-checked cleanup; stop the
daemon only after that succeeds:

```bash
maki-attach cleanup --volume pg &&
    systemctl stop maki@pg.service &&
    systemctl reset-failed maki-attach@pg.service
```

Then use the bounded `wait_stopped` above for the workload, attach and daemon
before an offline check or backup. If cleanup fails again, preserve the backend
and state for diagnosis. Re-enable recovery only when ready to start the target.
The success gate applies to planned target stops: an explicit daemon stop,
host shutdown, crash or recovery coordinator can independently stop the daemon.
The [installed-stack campaign](deployment/first-production-candidate.md) remains
separate from service-manager tests using simulated storage resources.

Before production use, verify the installed units on the target distribution:

```bash
systemd-analyze security maki@example.service
systemd-analyze verify \
  maki@example.service \
  maki-attach@example.service \
  maki-recover@example.service \
  maki-workload@example.target \
  your-workload.service
```

Also verify socket ACLs, effective capabilities, core-dump policy, duplicate
attach rejection, mount identity, and normal I/O under the service sandbox.

### Upgrading the runtime layout

The September 2026 fixes change helper records and the default control socket
path. Apply the package changes during a planned maintenance window:

1. Stop dependent workloads and detach existing volumes **using the old
   helper before replacing it**. Do not copy legacy
   `/run/maki/attach/<volume>.nbd` files into the new helper directory.
2. Disable old direct enablement of `maki@<volume>` and
   `maki-attach@<volume>`. Install the updated helper, daemon, attach, recover,
   and workload-target units plus tmpfiles rules, and ensure the systemd and
   kernel requirements above are satisfied.
3. Update explicit `control.socket` values to
   `/run/maki-control/<volume>/control.sock`, or provision an equivalent custom
   path whose ancestors permit the configured control group to traverse it.
4. Install the workload drop-in, enable the workload to create its
   `RequiredBy=maki-workload@<volume>.target` link, and enable the lifecycle
   target. Reattach through that target and verify the trusted record, mount
   identity, administrator control access, NBD socket isolation, and workload
   start gate.

If the helper has already been upgraded while a legacy attachment is live,
missing trusted state requires independently verified manual cleanup. Pinning
the NBD device is not a migration shortcut.

The November 2026 configuration-file check refuses a volume configuration that
another user could change or substitute
([configuration file](configuration.md#configuration-file)): a daemon started
on one fails attach, and every `maki` command refuses it. Before upgrading,
list the files it would refuse, then replace each listed file with a
`root:maki 0640` copy of its contents (`install` replaces the name, so a
symlink or second link is gone afterwards):

```bash
find /etc/maki/volumes -name '*.toml' \
    \( -type l -o -links +1 -o -perm /022 -o ! -user root \) -print
cp --dereference /etc/maki/volumes/<volume>.toml /root/<volume>.toml.copy
install -m 0640 -o root -g maki /root/<volume>.toml.copy /etc/maki/volumes/<volume>.toml
```

Review the copied contents before installing them. A listed file owned by the
daemon user is still accepted by the daemon, but not by `maki` commands run as
root.

Removing the package (`apt remove maki`) is refused by its `prerm` while any
trusted attachment record exists or a `maki@`, `maki-attach@`,
`maki-recover@` or `maki-workload@` unit is active: the helper being removed is what the
lifecycle needs to detach. A failed `systemctl` query refuses the removal too. Drain and deactivate every volume first. Upgrades
are not blocked and no maintainer script starts, stops or restarts a service
([package behaviour](../packaging/debian/README.md#removal-and-upgrade-behaviour)).
On RHEL 9 the RPM is removed with `rpm -e maki`, which its `%preun` refuses
in the same cases. `dnf remove maki` is always refused: rpm cannot stop a
transaction from `%preun`, so the package is protected from dnf, which would
otherwise keep Maki and erase its dependencies
([RHEL 9 removal](getting-started/installation-rhel.md#upgrading-and-removal)).

The [2026-09-19 package qualification](qualification/package-topology-migration-validation-2026-09-19.md)
installed a generated pre-upgrade Debian package on a clean Debian 12 VM,
detached two live volumes using that helper, upgraded to the current generated
package without auto-start, and reattached both with unchanged configuration,
credential and logical SQLite hashes. This covers one direct `dpkg -i` path;
signed repositories, downgrade and maintainer-script rollback remain separate
release checks.

### Fresh-host restore of an unchanged v2 backing

Use this procedure only when restoring the same v2 volume UUID, backing data,
crypto compatibility identity and key. A DB-native or legacy-v1 migration uses
the separate process in [durable recovery](durable-recovery.md).

1. Stop database writers and close database connections through the application
   shutdown interface. Unmount the verified filesystem while engine admission
   is open, then require a successful `maki drain` acknowledgement (a VG with
   an additional LV is detached before the drain instead; see the
   [planned stop](#privileged-helper)). Stop
   `maki-workload@<volume>.target` and wait until the workload, attach and daemon
   units are inactive. Run `maki check` before capture.
2. Capture the complete volume backing, volume TOML and root-owned attach TOML.
   A same-host capture must copy data, not clone extents (`cp --reflink=never`;
   see [backing store](deployment/support-matrix.md#backing-store-below-maki)).
   Capture the credential through the deployment's secret-backup mechanism,
   separately from ordinary logs and backups. Record hashes, Maki revision,
   volume UUID, provider identity, filesystem and LVM identities, tool versions,
   and an independent database transaction or content ledger.
3. On the fresh host, install the same qualified runtime and packaged systemd,
   sysusers and tmpfiles artifacts. Recreate package directory modes explicitly;
   in particular `/usr/lib/maki` must be traversable by the `maki` service.
   Run sysusers before restoring ownership because a dynamic service UID may
   differ from the source host.
4. Restore the backing as `maki:maki`, the volume config as `root:maki 0640`,
   the attach config as `root:root 0600`, and the credential as
   `root:root 0400`. Recreate the configured mountpoint, then run `maki volume
   inspect` and the offline check before starting the target.
5. Start the workload target, run `maki-attach verify`, and compare logical DB
   contents and database integrity with the independent ledger. Perform a
   planned drain and restart, then repeat the comparison before accepting the
   restored host.

The [2026-09-17 qualification](qualification/fresh-host-restore-validation-2026-09-17.md)
passed this flow for one graceful local-provider, single-PV/LV, SQLite backing.
It was an ad hoc artifact install. A later
[package and migration campaign](qualification/package-topology-migration-validation-2026-09-19.md)
qualified one generated Debian package upgrade plus stopped-source SQLite
DB-native and legacy-v1 backup/restore. Other distributions, databases,
live/crash-time backup and production cutover remain separate qualifications.

## Growth and cache reload

Maki allocates backing shards lazily within the configured virtual capacity.
Growing the mounted filesystem is a privileged LVM and XFS operation exposed by
`maki-attach grow`. The configured maximum virtual size does not change.

The read-cache size and TTL are runtime settings. Send the desired values
through the control socket with `maki reload <config> cache --max-bytes N
[--ttl DURATION]`; editing the configuration file alone does not apply them.
Reducing the byte limit evicts entries immediately. The control command
requires a positive limit; `cache.mode = "off"` remains an attach-time setting.
Changing TTL retains insertion times, so a shorter TTL can expire entries on
their next lookup.

## Metrics and health

Status and metrics use in-memory observations and remain callable while a
volume operation or free-space query is blocked. Busy, cached, and unavailable
fields must not be interpreted as current readiness or zero counters; see
[observation freshness and failure limits](observability.md).

`maki metrics` carries every metric SPEC §40 names: request and byte admission
(`maki_active_callbacks`, `maki_plaintext_bytes`), ciphertext held in memory,
the crypto submission queue and inflight batches and bytes, per-endpoint
inflight work, crypto latency (`_sum`/`_count`), retries, retry-budget tokens,
circuit state (0 closed, 1 open, 2 half-open), failover count, journal size and
sequences, journal sync failures (`maki_journal_sync_failures_total`,
`maki_journal_writeback_uncertain`), checkpoint lag, FLUSH and FUA latency
(`_sum`/`_count`/`_max`), cache hits and misses, backing free space, and volume
state. Per-endpoint values are objects keyed by endpoint name (empty for local
providers). Actual Engine requests and retained admission slots are separate:
`maki_active_requests` counts public calls, while `maki_admission_slots` and its
legacy alias `maki_active_callbacks` count resource permits. Complete request
latencies and success/error/cancellation totals include resource waits and
unsuccessful outcomes; explicit journal-sync time is separate. See
[metric boundaries](observability.md#request-counts-and-latency-boundaries).
Do not add unit indexes, LBAs, request IDs, or other high-cardinality values as
metric labels.

`maki_checkpoint_lag_bytes` counts durable journal records newer than the
published checkpoint, in bytes including record headers. Repeated writes to
one unit count once per journal record. A TRIM tombstone counts its header.
Unsynced records enter this gauge when they become durable.

`maki_crypto_deadline_exceeded_total` counts crypto encrypt/decrypt calls that
ended because their `bounded-error` deadline expired, whatever error they
returned. Such a call returns the last error an endpoint gave before the
deadline for the RPC batch in progress (one batch of items with its retries and
failovers; a call sent as several RPC batches reports only the current one),
with that error's own class, or `operation deadline exceeded` when no endpoint
failed that batch, so alert on this counter rather than on the error text.
With batching enabled it counts scheduler callers: queue admission,
coalescing, batch-slot waits and RPC time share each caller's budget. Two
expired callers in one coalesced RPC contribute two; a caller contributes only
once even if the dispatcher also observes the deadline. Success, errors that
end a call before its deadline and caller cancellation do not increment it.
Without a scheduler, the metric uses the dispatcher's deadline counter. These
are crypto calls, not Engine or NBD requests, which may issue several crypto
calls.

## Failure handling

- Provider contract or compatibility failures refuse attach.
- A wrong key, key name, or provider type refuses attach (key canary).
- Corrupt metadata, sequence gaps, and failure to reach the required v2 horizon
  at its exact record end fail loudly. Its segment may be absent only when the
  selected checkpoint already covers it. Losing both valid proof copies also
  refuses recovery of an otherwise empty-looking volume.
- A torn final journal tail beyond the proven boundary may be truncated during
  recovery. A missing/stale advisory mark does not weaken the v2 proof rule.
- A failed journal `fdatasync` or required proof publication fails the FLUSH or
  FUA that needed it, and every later barrier keeps failing until the journal has *rewritten* the
  unsynced records, verified them against what it accepted, and synced them
  (a bare retry of `fdatasync` succeeds on Linux without writing anything).
  `maki status` shows `journal_writeback_uncertain: true` and counts
  `journal_sync_failures_total` while this lasts; reads keep working. If the
  cached bytes no longer match what was accepted, no barrier can succeed:
  restart the daemon so recovery re-scans the journal and discards what was
  never acknowledged. After a restart, recovery rewrites and verifies every
  segment prefix it accepted before it syncs, then publishes both required
  proofs before READY. New records become checkpoint-eligible only after
  their proof publication succeeds. See [durability ordering and limits](durable-recovery.md).
- A journal write that fails part-way leaves no torn bytes behind: the
  segment is truncated back to its last record before anything is appended
  or the segment is sealed, and the cleanup stays pending until that
  truncation is synced; while the truncation itself fails, writes and
  barriers fail.
- The NBD plugin advertises `nbd.minimum_io`, `preferred_io` and
  `maximum_io` through nbdkit's block-size negotiation. It refuses a
  misaligned or out-of-range request (EINVAL) before any plaintext is copied,
  and serves a longer one (the Linux NBD driver ignores the maximum) in
  chunks of at most `maximum_io`; the engine refuses a larger request
  outright, so the value bounds the memory one engine request pins (R5-038).
- The control socket serves at most 64 sessions at once (further clients wait
  in the listen backlog), closes a session idle for 60 s or a client that does
  not drain a response within 10 s, and runs one `checkpoint`, `reload`, or
  `drain` at a time: a concurrent one is answered `busy` and must be retried.
- `maki-attach detach` compares the request with the trusted attach record
  under the attach lock and refuses one the record does not back (a different
  device, mountpoint, VG or LV, a re-attached volume, a live backend with
  another identity while anything of the recorded attachment remains); see the
  helper section above.
- `maki-attach attach` verifies, before the sentinel is written or the probe
  runs, that the mounted filesystem is stored only on the NBD device it
  connected (device-mapper stacks are walked through sysfs); a filesystem on
  any other device, or a volume group spanning other devices, is refused.
- An attach helper that dies between LVM activation and its mapping record is
  rolled back by the packaged failed-start hook while the daemon still serves
  the device. If the daemon stopped serving first, `cleanup` refuses and
  keeps the record and the mapping; see
  [the manual step](#interrupted-activation-after-the-daemon-stopped).
- An allocated slot that cannot be validated returns EIO, never fabricated zeros.
- A second process cannot attach while the volume lock is held.
- Clean detach requires FLUSH, checkpoint, engine drop, and lock release.
- A write that would push the in-memory overlay past
  `limits.max_overlay_bytes` or `limits.max_overlay_entries` first syncs and
  checkpoints inline; if the checkpoint fails it returns ENOSPC and the
  engine reports `state: degraded` until a later checkpoint succeeds. The
  worker also checkpoints when the overlay reaches half of either bound, so
  the inline path is the exception, not the norm. Reads are unaffected.
- Writes fail with ENOSPC unless fresh backing free space covers
  `backing.journal_emergency_reserve_bytes`,
  `backing.checkpoint_reserve_bytes`, and the projected record and
  segment-header footprint of the write, or when that write would exceed
  `backing.journal_max_bytes` even after an inline checkpoint. An unavailable
  or failed free-space query also fails closed while the emergency reserve is
  enabled. A zero emergency reserve disables this admission check while the
  checkpoint reserve still controls the worker. Admission
  refreshes the observation; that threshold check alone does not reserve
  storage. After admission, the Linux file backing uses `posix_fallocate` for
  the exact journal range and physical checkpoint-completion space before it
  publishes the record. A scoped ext4/GCE Persistent Disk campaign verified
  allocation before FUA acknowledgement and an ENOSPC refusal with no sequence
  or journal change; see the
  [physical reservation report](qualification/physical-reservation-validation-2026-09-18.md).
  This does not preallocate untouched slots or cover non-Linux backing behavior.
  It does not cover one metadata store either: an A/B copy that a power loss
  left undecodable is emptied before it is written again, so that store needs
  free blocks and can fail with ENOSPC on a filesystem that has none. The
  checkpoint, barrier or attach that needed it then fails; the other copy and
  the journal are untouched, and it succeeds once space is available.
  A reserve-only refusal leaves existing data readable and does not
  by itself set a checkpoint error or change the engine state. It wakes the
  checkpoint worker for an immediate pass, which deletes covered journal
  segments and punches pending trims, so space a checkpoint can give back
  returns without waiting for the worker's interval. A failed
  checkpoint reports `state: degraded` with its error, cleared by a successful
  checkpoint; the worker retries on its interval and writes retry necessary
  reclaim. Other outstanding failure states can still prevent `ready`.
- `maki reload` returns an error naming the section for any change the running
  daemon cannot apply; only `cache` is applied at runtime today. An error means
  the change was not applied: restart the daemon.
- `maki status`, `metrics`, `checkpoint`, `drain` and `reload` give up when the
  daemon does not answer within 60 s (600 s for `checkpoint` and `drain`); pass
  `--timeout <seconds>` to wait longer. A timeout means the daemon is stalled
  or busy, not that the command was rejected. Commands without a control
  round trip (`volume`, `check`) refuse `--timeout` with the usage and exit
  status 2.
- While the journal cannot be synced (see the writeback item above) `maki
  status` reports `state: degraded` with the reason, and `maki_volume_state`
  is 2, until a barrier succeeds; a successful checkpoint alone does not clear
  it.
- If a storage task panics while it holds the volume write lock (a bug, not
  an I/O error), the engine stops: the in-memory volume may be half updated,
  so every later read, write, trim, FLUSH and checkpoint fails with EIO,
  `maki status` reports `state: degraded` with a reason starting `engine
  stopped:`, and the log has an `ERROR` line. Nothing clears it. Restart the
  daemon; recovery rebuilds the state from disk and keeps every write a FLUSH
  or FUA acknowledged. `maki drain` fails meanwhile, which is correct: it
  cannot prove durability through that state.
- When the session of a rollback-protected volume stops
  ([rollback protection](rollback-protection.md)), every later request fails
  with EIO. From the first request that finds the stop, `maki status`
  reports `state: degraded` with a reason starting `rollback session
  stopped:` and the cause, `maki_volume_state` is 2, and the log has one
  `WARN` line with the cause. Nothing clears it. What to do depends on the
  cause:
  - The witness no longer names this writer's state (`remote writer revoked
    or witness changed`, `witness anchor changed while locked`, a missing or
    invalid anchor, or a remote witness's denial or invalid answer). After a
    `maki volume takeover` or `restore`, another writer owns the volume:
    leave this daemon stopped. Otherwise find out what changed the witness
    (a witness directory that is not mounted or was replaced, an older
    anchor put back, a changed allow-list) before you restart it.
  - A commit or a page write whose outcome is uncertain (`manifest commit
    failed: <error>`, `arena page write failed: <error>`). The error says
    what failed. Correct a storage error (a failed sync or write, a full
    filesystem) before the volume is opened again; the reopened volume keeps
    every acknowledged write. A commit the witness refused (a predecessor
    conflict, a denial) is treated as in the item above.
  - A page the committed state references is missing, short or does not
    authenticate (`arena page read failed: <error>`, `rollback arena page
    authentication failed`): media damage looks like this, and so does an
    older copy of a page put back, which is the rollback this protection
    detects. Inspect the backing before you restart: attach refuses the
    volume until every committed page authenticates again.

  With a local witness, restarting the daemon opens the volume again. With a
  remote witness, a restart alone is refused: the stopped daemon's shutdown
  drain fails, so it never releases its session, and the authority refuses
  the next daemon's claim (a predecessor conflict) until an administrator
  replaces the session with `maki volume takeover`, as for a
  [stale or failed writer](remote-witness-service.md#snapshot-takeover-and-restore);
  the takeover keeps every acknowledged write.
- A volume configuration that is a symlink, has a second hard link, is owned
  by a user other than root and the loading process's user, or is writable by
  its group or others is refused before it is parsed, by the daemon (attach
  fails), by every `maki` command that reads it and by `maki-benchmark`; the
  error names the file and the problem. Install it `root:maki 0640`
  ([configuration file](configuration.md#configuration-file)); a file owned
  by the daemon user is accepted only by processes running as that user.
- Volume directories are created `0700` and their files `0600`; a `file`
  credential must be a regular file with no group or other permission bits
  (for example `0600` or `0400`), owned by root
  or by the user the daemon runs as, or attach is refused. A `credential`
  (systemd `LoadCredential=`) has the same owner rule and may also be `0440`
  when its group is the daemon's own or root, as systemd 257 (Debian 13)
  writes them; group write and any access by others are refused (R5-037).
  An empty or whitespace-only credential is refused like a missing one.
- The control socket is `0660` with `control.group`; administrators reach it
  through the `root:maki-admin` `/run/maki-control` tree, while the NBD
  socket stays behind `/run/maki` (`root:maki` 0750), which only the daemon
  user and root (the attach helper) can enter.

Use [Testing and qualification](testing.md) before interpreting a successful
userspace smoke test as production readiness.
