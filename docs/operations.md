# Operations

This guide covers volume lifecycle, nbdkit integration, privilege separation,
control commands, and recovery. Commands that attach block devices, modify LVM,
mount filesystems, or grow filesystems require an isolated Linux target and
appropriate privileges.

The repository includes a guarded, destructive-target-restricted procedure in
[Privileged Linux validation](privileged-linux-validation.md).

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
volume. Do not remove proofs or change format bytes to bypass a refusal. The
crypto context's `format_version` is unchanged by the envelope version.

## Prerequisites

Building the Rust workspace requires a Rust toolchain. The Linux data path also
uses nbdkit. Rootless userspace validation requires `nbdkit`, `nbdinfo`,
`nbdcopy`, and fio with its NBD engine. Kernel attachment additionally requires
the Linux NBD module and a disposable `/dev/nbdN`.

On Debian-family systems the relevant packages are `nbdkit`,
`nbdkit-plugin-dev`, `libnbd-bin`, and `fio`. Package and service installation
remain distribution-specific.

## Build the plugin

```bash
cargo build --release --locked -p maki-nbdkit
nm -D --defined-only target/release/libmaki_nbdkit.so |
  grep -Eq '[[:space:]]T[[:space:]]plugin_init$'
```

The exported structure uses the validated nbdkit API-v2 prefix. FLUSH is
available, FUA is emulated by nbdkit, and native TRIM, write-zeroes, block-size
negotiation, and multi-connection callbacks are not exported.

## Volume lifecycle

Initialize, inspect, and check a volume with the administrative CLI:

```bash
maki volume create /etc/maki/volumes/example.toml
maki volume inspect /etc/maki/volumes/example.toml
maki check /etc/maki/volumes/example.toml
```

`volume create` writes the initial superblock, catalog, and backing directories,
all owner-only (`0700` directories, `0600` files). The command must target an
empty, reviewed backing location, and the tree must end up owned by the daemon
user: `/var/lib/maki` is `root:maki 0750`, so create the volume directory for
the daemon and run the command as that user rather than as root (a root-owned
`0700` tree is unreadable to the daemon, which then fails to attach):

```bash
install -d -o maki -g maki -m 0700 /var/lib/maki/example
sudo -u maki maki volume create /etc/maki/volumes/example.toml
```

`maki-check` can also inspect a backing root directly:

```bash
maki-check /var/lib/maki/example
maki-check /var/lib/maki/example --deep
maki check /etc/maki/volumes/example.toml --deep
```

Without `--deep` the check covers the superblock, required v2 proof records,
shard catalog, allocation-map sizes, and file presence. `--deep` additionally
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

`--deep` takes the volume lock and refuses to run while a daemon is attached;
when checking a backing
root directly, pass `--journal-segment-size` if the volume uses a non-default
size.

Run offline checks only after the daemon or nbdkit process has released the
volume lock.

## Swap dependency checks

With `security.require_secure_swap_policy`, Linux attach accepts no swap,
RAM-only zram, or dm-crypt whose complete kernel dependency graph terminates
at independent physical devices. The same check applies to zram writeback.
Encrypted swap above NBD, including through partitions, LVM, or MD, is refused:
paging out Maki must not require Maki to serve that paging I/O. Missing or
inconsistent sysfs metadata, cycles, and unproven virtual backing are refused.
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
  /usr/lib/maki/libmaki_nbdkit.so \
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
stop path is not a substitute for this administrative check.

## Rootless userspace smoke test

The following test overwrites the complete disposable export:

```bash
uri='nbd+unix:///?socket=/run/maki/example/nbd.sock'
test_dir="$(mktemp -d)"

nbdinfo "$uri"
dd if=/dev/urandom of="$test_dir/source.bin" bs=1M count=8 status=none
nbdcopy --flush --synchronous "$test_dir/source.bin" "$uri"
nbdcopy --synchronous "$uri" "$test_dir/roundtrip.bin"
cmp "$test_dir/source.bin" "$test_dir/roundtrip.bin"

fio --name=maki-nbd-verify \
  --ioengine=nbd --uri="$uri" \
  --rw=write --bs=4k --size=8M --iodepth=1 --fsync=32 \
  --verify=crc32c --do_verify=1 --verify_fatal=1 \
  --verify_state_save=0
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
writable path. The socket is removed on clean detach.

The packaged `/run/maki-control` directory is `root:maki-admin` 0750; its
per-volume children are `maki:maki` 0711. This lets administrators traverse
the control path while `/run/maki` (`root:maki` 0750) restricts access to NBD.
The daemon keeps `Group=maki`. Set `control.group = "maki-admin"` to apply the
administrative socket group; omitting it retains the daemon's socket group.
NBD isolation relies on the restricted ancestor: nbdkit resets its own umask,
so a service `UMask` is not a socket-mode guarantee.
[nbdkit plugin manual](https://libguestfs.org/nbdkit-plugin.3.html#UMASK)

The unprivileged control socket accepts newline-delimited JSON with a 64 KiB
line limit. The `maki` CLI exposes the supported operations:

```bash
maki status /etc/maki/volumes/example.toml
maki metrics /etc/maki/volumes/example.toml
maki checkpoint /etc/maki/volumes/example.toml
maki drain /etc/maki/volumes/example.toml
maki reload /etc/maki/volumes/example.toml cache --max-bytes 268435456
```

`drain` permanently closes admission to reads, writes, flushes, checkpoints,
and reloads for that attachment. It waits for already admitted callbacks,
including writes still waiting for encryption, then flushes and checkpoints.
Success returns `checkpoint_sequence`; repeated drains return the same
acknowledgement. `status` and `metrics` remain available, and the daemon retains
the volume lock until shutdown. Reattach to resume I/O.

`status` includes `io_state` (`running`, `draining`, `failed`, or `drained`) and
`drain_error`. A failed drain returns an error to the CLI, preserves the engine
and volume lock, and keeps admission closed. Correct the storage failure and
retry `maki drain` while the process is still alive. A timeout is not an
acknowledgement: inspect status and retry. If the process exits after a failed
drain, its unload error is logged; the next attach performs recovery. Do not
treat process cleanup or socket removal as proof that the failed barrier
succeeded.

`reload cache` needs the new size; it is refused (not silently accepted) on a
daemon running with `cache.mode = "off"`.

Attach, detach, mount, unmount, NBD, and growth verbs are deliberately absent
from the control socket.

## Privileged helper

`maki-attach` reads its parameters from the root-owned
`/etc/maki/attach/<volume>.toml` (template:
[`packaging/examples/attach.toml`](../packaging/examples/attach.toml)): the Maki
volume UUID, the mountpoint, VG and LV names, an optional pinned NBD device and
an optional expected XFS UUID. Command-line flags override individual values.
Every value is checked before it reaches a system utility: option-like values,
relative or non-canonical paths, and malformed UUIDs are rejected with exit
code 2 and no plan is printed.

The helper prints an auditable operation plan before execution. Always review
plan mode first:

```bash
maki-attach attach --volume example --plan
maki-attach detach --volume example --plan
maki-attach grow --volume example --size-bytes 2147483648 --plan
```

`grow --size-bytes` is an absolute minimum LV size in bytes. LVM may round
up to its extent size; an LV already at or above the target is left unchanged,
and XFS growth is retried. Reuse the same target after a timeout or failure,
including a failure after `lvextend` already changed the LV. The former
`--add-bytes` option is rejected because a relative increase cannot identify
a retry. Growth revalidates the live attachment before each mutation and
never shrinks the LV or filesystem.

Execution (Linux, root) then:

1. opens `/run/maki-attach` through verified root-owned directory descriptors,
   takes its private `attach.lock`, and, unless a device is pinned, allocates
   the lowest free `/dev/nbdN` from sysfs;
2. records the requested attachment and a random connection identifier before
   connecting NBD, then connects with the configured block size, waits until
   the device reports a size, and verifies its kernel backend identifier;
3. activates the VG and records its mapping identity, then verifies XFS TYPE
   and the optional configured `fs_uuid` with a bounded block probe before
   mounting. It rechecks backend/mapping identity around that probe. After
   mounting, `--init-sentinel` (or `init_sentinel = true`, first boot only)
   creates `<mountpoint>/.maki-sentinel` holding the volume UUID, never
   overwriting a different value; see [attachment limits](storage-recovery.md);
4. verifies the mount identity from `/proc/self/mountinfo`, `blkid`, sysfs NBD
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
An atomic replacement binds the volume UUID, socket, mountpoint, VG, LV, device,
and random connection identifier.

`maki-attach detach` takes the same lock and compares the requested attachment
with that record and the live `/sys/block/nbdN/backend` before unmounting or
deactivating a VG. It verifies the backend again immediately before disconnect,
including rollback. Missing records or mismatched identities refuse execution;
an explicit `--nbd-device` cannot bypass this check.

Detach retries observe current mountinfo and sysfs state before each step.
An already completed unmount or VG deactivation is skipped. A remaining mount
must identify the expected LV device, XFS root, and volume sentinel, and active
VG mappings must use the recorded NBD device. A different mount or backend,
unreadable observations, remaining device holders (including partition
holders), and direct mounts of the NBD device or its partitions block unsafe
deactivation or disconnect.

If disconnect succeeded but the process stopped before retiring its record,
a retry may remove that record without running device commands only after
confirming the mount is absent, the VG is inactive, and the disconnected NBD
has no observed remaining use. This uses the helper's current mount namespace;
cross-namespace operational qualification remains a target-host check. The
trusted record format and the legacy migration requirements remain the same.

This requires **nbd-client 3.27.0 or later built with netlink support**, and a
kernel exposing the NBD backend identifier. The identifier option was added
in [NBD 3.27.0](https://github.com/NetworkBlockDevice/nbd/releases/tag/nbd-3.27.0).
An unsupported client or unverifiable connection fails closed. Qualify the
updated helper on the intended Linux target before deployment; older privileged
validation reports do not cover this connection-identity protocol.

`maki-attach@<volume>.service` becomes active after the identity check passes.
Its `RemainAfterExit=yes` retains that past result even if the mount later
disappears; the service state is not a live readiness check. Services that
need the secure mount must declare
`Requires=maki-attach@<volume>.service` and `After=` it. `AssertPathExists`
makes a missing attach configuration fail startup, so the dependent service's
start job also fails. Every workload start also needs a fresh mount/backend
identity check, including container restarts that bypass that dependency start
job. Execution without a volume UUID is refused.

Use `maki-attach verify --volume <volume>` as the repeatable, read-only storage
gate. It requires root privileges, an existing trusted attachment record and
both UUIDs pinned in the root-controlled attach configuration. Do not pass
`--plan` to a workload gate: that option only prints a preview. For a host
systemd service whose namespace exposes the configured mount, the relevant
drop-in can include:

```ini
[Unit]
Requires=maki-attach@pg.service
After=maki-attach@pg.service

[Service]
ExecStartPre=!/usr/bin/maki-attach verify --volume pg
```

The `!` keeps the helper's root user/group credentials while retaining the
service's other restrictions, including its filesystem view. The gate must
still be able to read the trusted configuration/state and probe the verified LV
under those restrictions. Keep the configuration root-controlled; this is not
a generic sudo grant. A failed check prevents that start. Qualify the service's
actual mount namespace and sandbox on the target host. A host check cannot establish which
filesystem an existing container's bind mount exposes; stop and recreate those
bindings through the workload recovery procedure. See the
[gate's checks and limits](storage-recovery.md#checking-storage-before-each-workload-start).

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

Before production use, verify the installed units on the target distribution:

```bash
systemd-analyze security maki@example.service
systemd-analyze verify maki@example.service maki-attach@example.service
```

Also verify socket ACLs, effective capabilities, core-dump policy, duplicate
attach rejection, mount identity, and normal I/O under the service sandbox.

### Upgrading the runtime layout

The September 2026 fixes change helper records and the default control socket
path. Apply the package changes during a planned maintenance window:

1. Stop dependent workloads and detach existing volumes **using the old
   helper before replacing it**. Do not copy legacy
   `/run/maki/attach/<volume>.nbd` files into the new helper directory.
2. Install the updated helper, units, and tmpfiles rules, and ensure the
   nbd-client and kernel requirements above are satisfied.
3. Update explicit `control.socket` values to
   `/run/maki-control/<volume>/control.sock`, or provision an equivalent custom
   path whose ancestors permit the configured control group to traverse it.
4. Reattach and verify the trusted record, mount identity, administrator control
   access, and NBD socket isolation before starting workloads.

If the helper has already been upgraded while a legacy attachment is live,
missing trusted state requires independently verified manual cleanup. Pinning
the NBD device is not a migration shortcut.

## Growth and cache reload

Maki allocates backing shards lazily within the configured virtual capacity.
Growing the mounted filesystem is a privileged LVM and XFS operation exposed by
`maki-attach grow`. The configured maximum virtual size does not change.

The read-cache size and TTL are runtime settings. Reload the `cache` section
through the control socket after changing them. Reducing the byte limit evicts
entries immediately; setting it to zero disables caching.

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
providers). Do not add unit indexes, LBAs, request IDs, or other
high-cardinality values as metric labels.

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
  `maximum_io` through nbdkit's block-size negotiation and refuses a request
  outside them (EINVAL) before any plaintext is copied; the engine refuses a
  larger request outright, so the value bounds the memory one request pins.
- The control socket serves at most 64 sessions at once (further clients wait
  in the listen backlog), closes a session idle for 60 s or a client that does
  not drain a response within 10 s, and runs one `checkpoint`, `reload`, or
  `drain` at a time: a concurrent one is answered `busy` and must be retried.
- `maki-attach detach` compares the request with the trusted attach record
  under the attach lock and refuses one the record does not back (a different
  device, mountpoint, VG or LV, a re-attached volume, a live backend with
  another identity); see the helper section above.
- `maki-attach attach` verifies, before the sentinel is written or the probe
  runs, that the mounted filesystem is stored only on the NBD device it
  connected (device-mapper stacks are walked through sysfs); a filesystem on
  any other device, or a volume group spanning other devices, is refused.
- An allocated slot that cannot be validated returns EIO, never fabricated zeros.
- A second process cannot attach while the volume lock is held.
- Clean detach requires FLUSH, checkpoint, engine drop, and lock release.
- Writes fail with ENOSPC when backing free space is below
  `backing.journal_emergency_reserve_bytes`, or when the journal has reached
  `backing.journal_max_bytes` and an inline checkpoint could not reclaim it.
  Admission refreshes the free-space observation; it does not reserve physical
  storage. A reserve-only refusal leaves existing data readable and does not
  by itself set a checkpoint error or change the engine state. A failed
  checkpoint reports `state: degraded` with its error, cleared by a successful
  checkpoint; the worker retries on its interval and writes retry necessary
  reclaim. Other outstanding failure states can still prevent `ready`.
- `maki reload` returns an error naming the section for any change the running
  daemon cannot apply; only `cache` is applied at runtime today. An error means
  the change was not applied: restart the daemon.
- `maki status`, `metrics`, `checkpoint` and `reload` give up when the daemon
  does not answer within 60 s (600 s for `checkpoint`); pass
  `--timeout <seconds>` to wait longer. A timeout means the daemon is stalled
  or busy, not that the command was rejected.
- While the journal cannot be synced (see the writeback item above) `maki
  status` reports `state: degraded` with the reason, and `maki_volume_state`
  is 2, until a barrier succeeds; a successful checkpoint alone does not clear
  it.
- Volume directories are created `0700` and their files `0600`; a `file`
  credential must be a regular file with mode `0600` or `0400`, or attach is
  refused.
- The control socket is `0660` with `control.group`; administrators reach it
  through the `root:maki-admin` `/run/maki-control` tree, while the NBD
  socket stays behind `/run/maki` (`root:maki` 0750), which only the daemon
  user and root (the attach helper) can enter.

Use [Testing and qualification](testing.md) before interpreting a successful
userspace smoke test as production readiness.
