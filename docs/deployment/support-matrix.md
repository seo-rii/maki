# Support matrix

This page answers "does Maki work on my setup?" in one place. It separates the
three layers that are easy to confuse:

```text
        workload (database, files)
                 │
   exported stack: XFS ─ LV ─ VG ─ PV ─ /dev/nbdN     ← "above Maki"
                 │
              Maki nbdkit plugin (ciphertext journal, slots)
                 │
   backing store: directory on a local filesystem       ← "below Maki"
                 │
              host: kernel, distribution, VM or metal
```

Status words have fixed meanings:

| Word | Meaning |
|---|---|
| **Campaign passed** | An external, disposable-host campaign recorded under [`qualification/`](../qualification/README.md) exercised it. Scoped, not production approval |
| **Expected** | The code path is exercised by automated tests or has no environment-specific behavior, but no external campaign covered it |
| **Not qualified** | Nothing prevents it, but Maki makes no claim; qualify it yourself before relying on it |
| **Refused** | The helper or daemon detects it and fails closed |
| **Unsupported** | Outside the design; do not use |

Current overall state is in [status](../status.md).

## Host platform

| Platform | Status | Notes |
|---|---|---|
| Debian 12 (bookworm) on Google Compute Engine, Linux `6.1.0-*-cloud-amd64` | **Campaign passed** | Every kernel NBD/LVM/XFS, systemd lifecycle, package, database and reset campaign ran here with `nbd-client` 3.27.1 |
| Debian 12 on KVM (other hypervisor) | **Campaign passed** (rootless data path only) | nbdkit/libnbd/fio path; kernel attachment not run there |
| Firecracker microVM guest | **Campaign passed** (guest crash only) | 20 abrupt VMM kills; the L1 host and its caches stayed alive |
| Debian 13 and later | Not qualified | Check that `nbd-client` ≥ 3.27.0 and systemd ≥ 249 are available |
| Ubuntu 22.04 / 24.04 | Not qualified | Same requirements; the Debian packaging is not built for Ubuntu |
| RHEL 9 and derivatives, Fedora | Not qualified | No packaging; LVM2 must support `fullreport`, `--devices` and UUID-scoped activation |
| Bare metal (any distribution) | Not qualified | Physical power-loss durability is an **open** gate; see [failure evidence](../status.md#failure-injection-evidence) |
| AWS EC2, Azure, other clouds | Not qualified | Reset semantics of the block service differ from GCE Persistent Disk |
| Windows, macOS | Unsupported for the data plane | The workspace builds and its portable tests run; nbdkit plugin and privileged helper are Linux-only |

Host requirements common to every Linux target: kernel NBD with the backend
identifier in sysfs, `nbd-client` ≥ 3.27.0 built with netlink support, LVM2
with `fullreport`/`--devices` (2.03.16 tested), xfsprogs, systemd ≥ 249 for
the recovery unit's `OnSuccess=`. Details are in the
[installation guide](../getting-started/installation-debian.md).

## Backing store (below Maki)

The backing is an ordinary directory (`backing.root`). Maki relies on the
filesystem honouring `fdatasync`, directory `fsync`, `posix_fallocate`, file
locks and atomic rename.

| Backing | Status | Notes |
|---|---|---|
| GCE balanced/standard Persistent Disk, ext4 | **Campaign passed** | Physical reservation, whole-instance reset, database and package campaigns |
| Single local NVMe/SATA SSD or HDD, ext4 | Expected | Same code path; write-cache and power-loss behaviour of the device are not qualified |
| Single local disk, XFS as the *backing* filesystem | Expected | Not exercised externally |
| Software RAID (`mdadm`) below the backing filesystem | Not qualified | Correctness depends on the array honouring FLUSH/FUA to all members; see [RAID](raid.md) |
| Hardware RAID controller below the backing filesystem | Not qualified | Depends on controller cache policy (battery-backed write cache or write-through) |
| LVM (plain, thin, cache) below the backing filesystem | Not qualified | The daemon does not inspect what is under its filesystem |
| dm-crypt below the backing filesystem | Not qualified | Redundant with Maki's own encryption; permitted |
| Network filesystems (NFS, SMB/CIFS) | Unsupported | Locking, `fsync` and directory-sync semantics are not honest enough for the durability model |
| FUSE filesystems, 9p/WSL mounts | Unsupported for durability claims | Development only |
| tmpfs, RAM disks | Unsupported for production | Tests use RAM filesystems deliberately; data does not survive a reboot |
| Snapshot- or restore-managed filesystems | See limitation | Restoring an older backing image is not detected by default formats ([rollback protection](../rollback-protection.md)) |

The backing directory and its ancestors must be real directories (no
symlinks) on Linux, owned by the daemon user, mode `0700`.

## Exported stack (above Maki)

`maki-attach` owns this layer. It attaches `/dev/nbdN`, activates exactly one
volume group on it, mounts exactly one XFS logical volume and verifies the
identity of each layer before and after every change.

| Topology on `/dev/nbdN` | Status | Notes |
|---|---|---|
| Whole device as one PV → one VG → one XFS data LV | **Campaign passed** | The qualified topology; pin `fs_uuid` and `[lvm_identity]` |
| Same VG with an additional LV (for example a sidecar LV) | **Campaign passed** (attach and fail-closed cleanup) | Attach and detach work. The narrow dead-`nbdkit` cleanup fallback applies only to a single mapping, so recovery of a multi-LV VG needs operator diagnosis |
| PV on a partition of the NBD device | Not qualified | Partitions are inventoried and mixed whole-device/partition PVs are refused; read [LVM activation checks](../storage-recovery.md#checking-lvm-before-activation) first |
| VG that also spans other block devices | **Refused** | The filesystem must be stored only on the NBD device Maki connected |
| LVM cache (`cachevol`) layouts | **Refused** at activation | |
| LVM thin pools, LVM RAID LVs, other internal device-mapper layers | Not qualified; fail closed in cleanup | Activation may succeed, but recovery paths refuse anything except the single-target mapping |
| ext4, btrfs or another filesystem on the LV | Unsupported by the helper | The helper verifies XFS `TYPE` before mounting |
| Filesystem directly on `/dev/nbdN` without LVM | Unsupported by the helper | Usable only by hand; no trusted record, no verify gate, no packaged recovery |
| `mdadm`/LVM RAID across several Maki devices | Unsupported | Each `maki-attach` instance owns one device; see [RAID](raid.md) |
| Swap on the exported device (directly or via LVM/MD/dm-crypt) | **Refused** when `require_secure_swap_policy` is on | Paging Maki out must never require Maki |
| Multiple NBD connections to one export | **Refused** | `nbd.connections` must be `1` |

Growth: `maki-attach grow --size-bytes` extends the data LV within the VG's
free space and grows XFS; the NBD device size (`volume.max_virtual_size`) is
fixed at creation.

## Workloads

| Workload | Status | Notes |
|---|---|---|
| SQLite WAL, `synchronous=FULL` | **Campaign passed** | Several campaigns with an external fsynced ACK ledger |
| PostgreSQL 15 with checksums, `fsync`, `synchronous_commit`, `full_page_writes` | **Campaign passed** (one crash campaign) | [PostgreSQL deployment guide](postgres.md) |
| PostgreSQL other versions and settings, MySQL/MariaDB, ClickHouse, MinIO | Not qualified | |
| Docker containers with bind mounts of the mountpoint | **Campaign passed** | Containers must be recreated by the lifecycle, not restarted independently |
| Plain file storage | Expected | |

## Crypto providers and formats

See [status](../status.md#crypto-providers) and
[status: volume formats](../status.md#volume-formats).

## How to read a report

Each campaign report names its revision, image, machine type, kernel, tool
versions and exactly what it did not do. A "Campaign passed" entry above
inherits every one of those limits. The
[external qualification checklist](../testing.md#external-qualification-checklist)
lists what remains before any production approval.
