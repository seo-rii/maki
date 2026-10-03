# PostgreSQL on discard, space pressure and syscall filter — 2026-10-03

A dated record of three runs on disposable GCE VMs (times are UTC); it does
not claim current state. They follow the
[R5 hardware validation](r5-hardware-validation-2026-10-03.md) and cover items
that report listed as not covered.

## Environment

| Item | Value |
|---|---|
| Project and zone | `hancomac`, `asia-northeast3-a` |
| VM | `e2-standard-4`, 50 GB balanced boot disk, no service account or scopes, fixed termination time with `DELETE` |
| Image and kernel | Debian 12.15, `6.1.0-53-cloud-amd64` |
| Software | nbdkit 1.32.5, nbd-client 3.27.1 (source build), PostgreSQL 15.19, systemd 252.39, Rust 1.99.0 |
| Revisions | run 1 `ff79721`; runs 2 and 3 `551db73` (documentation-only change) |

## PostgreSQL 15 on a v3 discard volume

Adapted from the [2026-09-18 PostgreSQL crash campaign](postgresql-crash-validation-2026-09-18.md):
the volume is created with `--discard`, and `maki@pgqual` runs with a drop-in
`SystemCallFilter=@system-service` and `SystemCallErrorNumber=EPERM`.
PostgreSQL runs with checksums, `fsync`, `synchronous_commit` and
`full_page_writes` on, below the packaged `maki-workload@` lifecycle on
kernel NBD, LVM and XFS. An external, fsync'd ledger records every committed
row before it counts as acknowledged.

Added to the earlier scenario: a 200,000-row table is created, checkpointed
and dropped, then `fstrim` runs on the volume while pgbench drives four
clients, immediately before the postmaster `SIGKILL`.

**Result: 15 of 15 checks passed in all three runs.** In run 3:

- `fstrim` trimmed 1.1 GiB (1,193,451,520 bytes) under load; in run 1 the
  journal took about 65,000 tombstones durable for it.
- The `SIGKILL` interrupted pgbench; automatic WAL recovery preserved all 16
  acknowledged rows and `pg_amcheck` passed.
- Rows 16–31 were committed after recovery; the packaged lifecycle was
  stopped (drain, `maki check --deep` verdict `clean`) and restarted, and all
  32 rows read back with `pg_amcheck` clean.
- 48 rows at the end, final `pg_amcheck` clean, final drain and deep check
  `clean`, no NBD or device-mapper residue.
- The Maki journals showed no `EPERM`, `SIGSYS` or seccomp denial.

## Space pressure (R5-011)

A separate 768 MiB v3 volume, run as `maki`, on a 1.2 GiB loop ext4 backing
with `journal_emergency_reserve_bytes = 64MiB` and
`checkpoint_reserve_bytes = 128MiB`. After writing and checkpointing 384 MiB,
`fallocate` ballast left backing free space at about 128 MiB: above the
emergency reserve, below reserve plus checkpoint headroom (192 MiB).

| Run | Scenario | Outcome |
|---|---|---|
| 1 | XFS on the volume; delete the file *at* the pressure point, then `fstrim` | `sync` after `rm` returned EIO: deleting a file is a write, refused inside the headroom |
| 2 | XFS; delete the file *before* the pressure point, `fstrim` at it | `FITRIM` returned EIO: XFS's trim forces its log, a write |
| 3 | Raw device, no filesystem; 384 MiB written and checkpointed | **7 of 7 passed** (below) |

Run 3:

- free space at the pressure point: 133,480,448 bytes;
- a 4 KiB write was refused (EIO);
- `blkdiscard` of the 384 MiB range was admitted: 98,304 tombstones, made
  durable;
- the following checkpoint freed 451,764,224 bytes of backing;
- writes were admitted again and the discarded range read back as zeros;
- offline deep check: 4,096 allocated slots, 0 invalid, verdict `clean`.

So R5-011 holds at the block level, but an XFS filesystem on the volume cannot
use the window: freeing space inside it needs writes. The documentation
([configuration](../configuration.md), [space reclamation](../space-reclamation.md))
now says to recover by freeing space on the backing filesystem.

## Syscall filter

The three PostgreSQL lifecycles above ran `maki@` with
`SystemCallFilter=@system-service` (which includes `@memlock`) and
`SystemCallErrorNumber=EPERM` without a denial. The packaged unit adopted
both directives after these runs.

## Cleanup

Each run's instance and boot disk were deleted, and exact-name listings were
empty. The run 1 pressure evidence was not collected (written with
umask 077 by root); runs 2 and 3 handed their evidence back to the invoking
user.

## Not covered

- Remote providers (HTTP, WebSocket, gRPC) and TLS under the syscall filter.
- A database under space pressure, and filesystems other than XFS on the
  volume.
- Physical power loss, hypervisor power cuts and long soak runs.
