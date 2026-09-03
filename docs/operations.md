# Operations

This guide covers volume lifecycle, nbdkit integration, privilege separation,
control commands, and recovery. Commands that attach block devices, modify LVM,
mount filesystems, or grow filesystems require an isolated Linux target and
appropriate privileges.

The repository includes a guarded, destructive-target-restricted procedure in
[Privileged Linux validation](privileged-linux-validation.md).

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

`volume create` writes the initial superblock, catalog, and backing directories.
The command must target an empty, reviewed backing location. `maki-check` can
also inspect a backing root directly:

```bash
maki-check /var/lib/maki/example
maki-check /var/lib/maki/example --deep
maki check /etc/maki/volumes/example.toml --deep
```

Without `--deep` the check covers the superblock, shard catalog, allocation-map
sizes, and file presence only. `--deep` additionally verifies both checkpoint
state copies, the key canary, the durable mark, every journal segment exactly
as recovery would scan it (reporting the repairs recovery would make), and
every allocated slot exactly as the engine would read it. A volume that holds
data is only known good after a deep check passes. `--deep` takes the volume
lock and refuses to run while a daemon is attached; when checking a backing
root directly, pass `--journal-segment-size` if the volume uses a non-default
size.

Run offline checks only after the daemon or nbdkit process has released the
volume lock.

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

The plugin creates its Tokio runtime after nbdkit forks. Clean shutdown flushes
the engine, checkpoints durable state, and releases the volume lock.

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
`control.socket` or by default `/run/maki/<volume>/control.sock`, with mode
0660 and the group named by `control.group` (`maki-admin` in the packaged
units; `sysusers.d` makes `maki` a member so the unprivileged daemon can apply
it). A socket that cannot be bound fails attach: a daemon without its control
socket is not operable. Rootless runs must therefore set `control.socket` to a
writable path. The socket is removed on clean detach.

The unprivileged control socket accepts newline-delimited JSON with a 64 KiB
line limit. The `maki` CLI exposes the supported operations:

```bash
maki status /etc/maki/volumes/example.toml
maki metrics /etc/maki/volumes/example.toml
maki checkpoint /etc/maki/volumes/example.toml
maki reload /etc/maki/volumes/example.toml cache
```

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
maki-attach grow --volume example --add-bytes 1073741824 --plan
```

Execution (Linux, root) then:

1. takes `/run/maki/attach.lock` and, unless a device is pinned, allocates the
   lowest free `/dev/nbdN` from sysfs;
2. connects NBD with the configured block size and waits until the device
   reports a size;
3. activates the VG, mounts XFS, and on `--init-sentinel` (or
   `init_sentinel = true`, first boot only) creates `<mountpoint>/.maki-sentinel`
   holding the volume UUID, never overwriting a different value;
4. verifies the mount identity from `/proc/self/mountinfo`, `blkid`, sysfs NBD
   state, the sentinel, and a read/write probe;
5. on any failure rolls back the executed steps in reverse (umount, VG
   deactivate, NBD disconnect) and exits non-zero, reporting rollback steps
   that themselves failed.

`maki-attach@<volume>.service` therefore stays active only after the identity
check passed. Services that need the secure mount must declare
`Requires=maki-attach@<volume>.service` and `After=` it; the unit is skipped
when no attach configuration exists. Execution without a volume UUID is
refused.

> [!CAUTION]
> Removing `--plan` executes NBD, LVM, mount, or filesystem-growth commands on
> Linux.

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

## Growth and cache reload

Maki allocates backing shards lazily within the configured virtual capacity.
Growing the mounted filesystem is a privileged LVM and XFS operation exposed by
`maki-attach grow`. The configured maximum virtual size does not change.

The read-cache size and TTL are runtime settings. Reload the `cache` section
through the control socket after changing them. Reducing the byte limit evicts
entries immediately; setting it to zero disables caching.

## Metrics and health

Monitor request and byte admission, endpoint inflight work, crypto latency and
retries, retry-budget tokens, circuit state, failover count, journal size and
durable sequence, checkpoint lag, FLUSH/FUA latency, cache hits and misses,
backing free space, and volume state. Do not add unit indexes, LBAs, request IDs,
or other high-cardinality values as metric labels.

## Failure handling

- Provider contract or compatibility failures refuse attach.
- A wrong key, key name, or provider type refuses attach (key canary).
- Corrupt metadata, sequence gaps, missing journal segments, and journal
  corruption before the durable mark fail loudly.
- A torn final journal tail after the durable mark is truncated during recovery.
- An allocated slot that cannot be validated returns EIO, never fabricated zeros.
- A second process cannot attach while the volume lock is held.
- Clean detach requires FLUSH, checkpoint, engine drop, and lock release.
- Writes fail with ENOSPC when backing free space is below
  `backing.journal_emergency_reserve_bytes`, or when the journal has reached
  `backing.journal_max_bytes` and an inline checkpoint could not reclaim it.
  Reads keep working. `maki status` then shows `state: degraded` with the
  checkpoint error; the state returns to `ready` once a checkpoint succeeds
  (the worker retries on its interval, and every write retries the reclaim).
- `maki reload` returns an error naming the section for any change the running
  daemon cannot apply; only `cache` is applied at runtime today. An error means
  the change was not applied: restart the daemon.

Use [Testing and qualification](testing.md) before interpreting a successful
userspace smoke test as production readiness.
