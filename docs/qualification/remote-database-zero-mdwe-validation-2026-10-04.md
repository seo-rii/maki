# PostgreSQL over gRPC, NBD zeroing and MemoryDenyWriteExecute — 2026-10-04

A dated record of one campaign on disposable GCE VMs (times are UTC); it does
not claim current state. It follows the
[remote-transport syscall-filter campaign](remote-transport-syscall-filter-validation-2026-10-04.md)
and covers a database over a remote transport, R5-036 (WRITE_ZEROES) and the
packaged unit with `MemoryDenyWriteExecute=yes`.

## Environment

| Item | Value |
|---|---|
| Project and zone | `hancomac`, `asia-northeast3-a` |
| VM | `e2-standard-4`, 50 GB balanced boot disk, no service account or scopes, fixed termination time with `DELETE` |
| Image and kernel | Debian 12.15, `6.1.0-53-cloud-amd64` |
| Software | nbdkit 1.32.5, `nbdcopy` (Debian `libnbd-bin`), nbd-client 3.27.1 (source build), nginx 1.22.1, PostgreSQL 15.19, systemd 252.39, Rust 1.99.0 |
| Revision | `c37e7e0` |
| Daemon unit | packaged `maki@.service`: `SystemCallFilter=@system-service`, `SystemCallErrorNumber=EPERM`, `MemoryDenyWriteExecute=yes` (checked with `systemctl show`; `Seccomp: 2` and `NoNewPrivs: 1` in the daemon's `/proc` status) |

The provider side is the same as in the previous campaign: a qualification
service (`maki-crypto-local` AES-256-GCM-SIV) behind nginx with a private CA
and required client certificates, endpoint A on TLS 1.2 and B on TLS 1.3.

## Before the campaign: local runs

On the controller host (same Debian 12 kernel), the release plugin ran under
`systemd-run` with `MemoryDenyWriteExecute=yes` and the syscall filter for a
local AES-GCM-SIV volume and HTTP, WebSocket and gRPC volumes against loopback
providers. `nbdcopy` wrote a 1 GiB image (64 MiB of data) and read it back
identical for each, and each stopped cleanly with no error in its journal.

The first local attempt found R5-036: `nbdcopy` sends the holes of a sparse
image as WRITE_ZEROES of 64 and 128 MiB, nbdkit's emulation turned each into
one `pwrite` of that size, and the adapter refused it with EINVAL. The fix
(`bf85d01`) zeroes natively in `nbd.maximum_io` chunks; see the
[remediation log](../review-remediation.md#fifth-review-2026-10-01-r5-001r5-034).

## NBD zeroing (R5-036)

A legacy and a v3 discard volume (local provider, 1 GiB, packaged unit), each:

1. `nbdcopy` of a sparse 1 GiB image into the daemon's socket: 8 MiB of data,
   a 192 MiB hole, 8 MiB of data, an 816 MiB hole. The holes are WRITE_ZEROES
   requests of 192 and 816 MiB against a 1 MiB maximum block size. The
   image read back identical through `nbdcopy`.
2. Kernel NBD: the whole device read back with `O_DIRECT` and matched;
   `blkdiscard --zeroout` of the first 8 MiB read back as zeros.
3. Drain, stop, start, the whole device matched again; offline deep check
   `clean`.

**7 of 7 checks passed** (attempt 3). The kernel reported
`write_zeroes_max_bytes` 0 for `/dev/nbd15`: Debian 12's 6.1 NBD driver does
not send WRITE_ZEROES and zeroes with ordinary writes, so the kernel path was
never affected by R5-036. Userspace NBD clients are.

## PostgreSQL 15 over remote gRPC

The [PostgreSQL discard campaign](database-discard-pressure-validation-2026-10-03.md)
scenario on a 2 GiB v3 volume with `provider = "remote-grpc"` (two endpoints,
mTLS, bearer metadata, `availability_policy = "stall"`), under the packaged
`maki-workload@` lifecycle on kernel NBD, LVM and XFS. Added: endpoint A's
provider was stopped for 4 s during pgbench.

**15 of 15 checks passed.**

- Rows 0–15 committed and recorded in an external fsync'd ledger.
- pgbench ran with four clients; provider A was stopped and restarted;
  `fstrim` trimmed 1.1 GiB (1,193,480,192 bytes) under load. The status
  snapshot taken right after showed A's circuit `open` and B carrying the
  in-flight batch; nginx logged 10 HTTP 502s on A in that window.
- Postmaster `SIGKILL`: pgbench aborted (224 transactions processed), WAL
  recovery preserved all 16 rows, `pg_amcheck` clean.
- Rows 16–31 committed; drain, packaged stop, offline deep check `clean`,
  restart: all 32 rows read back, `pg_amcheck` clean.
- 48 rows at the end, `pg_amcheck` clean; final drain and deep check:
  durable sequence 298,820, 101,595 allocated slots, 0 invalid, verdict
  `clean`; no NBD or device-mapper residue.
- No `EPERM`, `SIGSYS` or seccomp message in the Maki journals.

The final metrics snapshot was taken after the lifecycle restart, so its
failover and retry counters (0) cover only the restarted daemon.

## Attempts

Each ran on its own VM, which was deleted with empty exact-name listings.

| Attempt | Revision | Stopped at | Cause |
|---|---|---|---|
| 1 | `e37ec18` | zeroing | Harness assumption: the script required `write_zeroes_max_bytes` above 1 MiB; this kernel reports 0. The R5-036 documentation made the same wrong kernel claim and was corrected in `c37e7e0` |
| 2 | `c37e7e0` | zeroing | Harness: `nbdcopy --progress=no` is not valid |
| 3 | `c37e7e0` | PostgreSQL setup | Harness: an edit left the old configuration heredoc body in the script. The zeroing phase had passed 7/7 and is reported above |
| 4 | `c37e7e0` | — | PostgreSQL passed 15/15 (zeroing skipped, already passed at this revision) |

## Not covered

- Provider and client on separate hosts under the filter.
- A kernel that sends NBD WRITE_ZEROES (newer than 6.1).
- Packet loss, latency and a commercial provider.
- Physical power loss and long soak runs.
