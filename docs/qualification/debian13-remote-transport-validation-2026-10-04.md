# Debian 13: remote transports, sandbox, latency and NBD zeroing — 2026-10-04

A dated record of one campaign on disposable GCE VMs (times are UTC); it does
not claim current state. It repeated the
[remote-transport campaign](remote-transport-syscall-filter-validation-2026-10-04.md)
and the NBD zeroing checks of the
[PostgreSQL over gRPC campaign](remote-database-zero-mdwe-validation-2026-10-04.md)
on Debian 13, with packet loss and latency added. Earlier attempts found
three platform problems, two of them product bugs (below).

## Environment

| Item | Value |
|---|---|
| Project and zone | `hancomac`, `asia-northeast3-a` |
| VM | `e2-standard-4`, 50 GB balanced boot disk, no service account or scopes, fixed termination time with `DELETE` |
| Image and kernel | Debian 13.7 (`debian-13-trixie-v20260921`), `6.12.107+deb13-cloud-amd64` |
| Packages | systemd 257.13, glibc 2.41, nbdkit 1.42.3, libnbd 1.22.2, nginx 1.26.3; Rust 1.99.0 |
| nbd-client | 3.27.1 built from source. Debian 13's package is `1:3.26.1-6.1`, below Maki's `>= 3.27.0` requirement (below) |
| Revision | `fc8d697` |
| Daemon unit | packaged `maki@.service`: `SystemCallFilter=@system-service`, `SystemCallErrorNumber=EPERM`, `MemoryDenyWriteExecute=yes` |

The provider side is the same as before: a qualification service
(`maki-crypto-local` AES-256-GCM-SIV) behind nginx with a private CA and
required client certificates; endpoint A accepts only TLS 1.2, B only TLS 1.3.

## Method

For each of `remote-http`, `remote-websocket` and `remote-grpc`, a 1 GiB v3
discard volume under the packaged unit with XFS on `/dev/nbd15`:

1. A log-only pass (`SystemCallLog=~@system-service`, filter removed) over
   format, writes, an endpoint outage, `fstrim` and a restart; a positive
   control showed the kernel reports a deliberate `swapoff(2)`.
2. Under the shipped unit: 128 MiB written and read back; writes with each
   endpoint stopped in turn; **`tc netem` delay 10 ms ± 5 ms and 1 % loss on
   loopback** (all client → nginx → provider traffic), 32 MiB written and
   everything read back; both endpoints stopped with an `O_DIRECT` writer
   that must stall, then complete when B returns; `fstrim` and checkpoint;
   stop/start and readback; offline deep check.

Then the zeroing checks on a legacy and a v3 volume (local provider):
`nbdcopy` of a sparse 1 GiB image (WRITE_ZEROES of 192 and 816 MiB), kernel
readback, `blkdiscard --zeroout`, restart and deep check.

## Results

**43 of 43 checks passed** (12 per transport, 7 for zeroing).

- **Sandbox:** the log-only passes recorded no syscall outside
  `@system-service` from rustls, reqwest, tokio-tungstenite, tonic, glibc
  2.41 or nbdkit 1.42; no `EPERM`, `SIGSYS` or seccomp message under the
  filter with `MemoryDenyWriteExecute=yes`.
- **Latency and loss:** every transport stayed correct under netem.
  Throughput differed sharply: the 32 MiB write plus full readback (about
  370 MiB) took 63 s over WebSocket, 179 s over gRPC and **4,123 s over
  HTTP**. This campaign's HTTP mapping is per item (no `items_path`): the
  provider sends one request per 4 KiB unit, and the engine awaits a
  request's provider calls one after another, so each unit costs a full
  round trip (about 100 KiB/s measured). See *Follow-up* below.
- **Failover and outage:** 21–28 endpoint failovers and 47–53 retries per
  transport, no deadline expiry, no unsafe-retry refusal, no checkpoint or
  journal-sync failure; the writer stalled with both endpoints down and
  completed when B returned.
- **Discard:** `fstrim` trimmed 1 GiB on each volume.
- **Deep checks:** all `clean`, 0 invalid slots.
- **Kernel zeroing:** Linux 6.12 sends NBD WRITE_ZEROES
  (`write_zeroes_max_bytes` 4,294,966,784; 6.1 reported 0). `BLKZEROOUT` of
  8 MiB read back as zeros on both formats, and nbdcopy's 192 and 816 MiB
  zero requests succeeded, which needed R5-036.

## Problems found on the way

| Attempt | Revision | Stopped at | Finding |
|---|---|---|---|
| 1 | `d93de49` | first daemon start | **R5-037 (product).** systemd 257 writes `LoadCredential=` files with mode `0440`; Maki required `0600`/`0400`, so `maki@.service` could not start with any provider. Fixed in `efdb704` |
| 2 | `efdb704` | first `nbd-client` | **Platform.** The campaign used Debian 13's packaged nbd-client 1:3.26.1, which rejects the kernel name `nbd15` that 3.27 requires (3.27 rejects `/dev/nbd15`). Maki's package already depends on `nbd-client (>= 1:3.27.0)`; Debian 13 still needs a 3.27 build |
| 3 | `f440bcb` | first mount | **R5-038 (product).** Linux 6.12 sends writes up to `max_sectors_kb` (1,280 KiB) to a 1 MiB export; the adapter refused them and buffered writeback lost them silently, so `mkfs.xfs` exited 0 and left a zeroed superblock. A diagnostic run with nbdkit's verbose log showed two refused `pwrite` requests above 1 MiB. Fixed in `fc8d697`; Debian 12's 6.1 kernel defaults to 128 KiB, so the earlier 6.1 campaigns were not exposed |
| 4 | `fc8d697` | — | Passed |

The owner and group of the `0440` credential files were not captured (the
evidence command expanded its glob without root); that the daemon started
shows only that the group was `maki` or root.

## Follow-up

The engine calls the provider for one request's batches sequentially, and
the HTTP provider's per-item mode sends its items sequentially, so a per-item
HTTP mapping pays one full round trip per unit. Running a request's provider
calls concurrently must keep `limits.max_active_callbacks` bounding provider
concurrency (SPEC §30, `phase5_admission.rs`); it was not changed here. A
batched HTTP mapping (`items_path`) avoids the cost today.

## Not covered

- Provider and client on separate hosts; a commercial provider.
- PostgreSQL and the `maki-attach` LVM lifecycle on Debian 13 (this campaign
  used XFS directly on the NBD device).
- Physical power loss and long soak runs.
