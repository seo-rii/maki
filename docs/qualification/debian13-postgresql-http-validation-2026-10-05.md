# Debian 13: PostgreSQL 17 over per-item HTTP and R5-039 throughput — 2026-10-05

A dated record of two runs on disposable GCE VMs (times are UTC); it does not
claim current state. It covers what the
[Debian 13 transport campaign](debian13-remote-transport-validation-2026-10-04.md)
left open: a database and the packaged `maki-attach` LVM lifecycle on
Debian 13, and the effect of R5-039 (concurrent provider batches) on a real
kernel under latency.

## Environment

| Item | Value |
|---|---|
| Project and zone | `hancomac`, `asia-northeast3-a` |
| VM | `e2-standard-4`, 50 GB balanced boot disk, no service account or scopes, fixed termination time with `DELETE` |
| Image and kernel | Debian 13 (`debian-13-trixie-v20260921`), `6.12.107+deb13-cloud-amd64` |
| Software | PostgreSQL 17.11, systemd 257.13, glibc 2.41, nbdkit 1.42.3, nginx 1.26.3, nbd-client 3.27.1 (source build), Rust 1.99.0 |
| Revision | `bd64553` |
| Daemon unit | packaged `maki@.service` with `SystemCallFilter=@system-service`, `SystemCallErrorNumber=EPERM`, `MemoryDenyWriteExecute=yes` (checked; `Seccomp: 2`, `NoNewPrivs: 1`) |

The provider side is the qualification service used since 2026-10-04
(`maki-crypto-local` AES-256-GCM-SIV behind nginx with a private CA and
required client certificates; endpoint A TLS 1.2 only, B TLS 1.3 only). The
volumes use a **per-item HTTP mapping** (no `items_path`): one HTTP request
per 4 KiB unit, the case R5-039 targets.

## PostgreSQL 17 over remote HTTP

The [PostgreSQL scenario](database-discard-pressure-validation-2026-10-03.md)
on a 2 GiB v3 volume under the packaged `maki-workload@` lifecycle
(`maki-attach`, pinned single-PV LVM, XFS), with an external fsync'd ledger
and endpoint A's provider stopped for 4 s during pgbench.

**15 of 15 checks passed.**

- The packaged graph attached the volume through `maki-attach` on Debian 13
  for the first time.
- Rows 0–15 committed and recorded. Under pgbench (four clients, 109 TPS,
  793 transactions before the kill) provider A was stopped; the status
  snapshot after it showed A's circuit `open`; `fstrim` trimmed 1.5 GiB.
- Postmaster `SIGKILL`: WAL recovery kept all 16 rows, `pg_amcheck` clean.
- Rows 16–31, drain, packaged stop, offline deep check `clean`, restart: all
  32 rows, `pg_amcheck` clean; 48 rows at the end; final deep check `clean`
  (101,519 allocated slots, 0 invalid); no NBD or device-mapper residue; no
  `EPERM`, `SIGSYS` or seccomp message.

## Throughput of a per-item HTTP volume (R5-039)

Sequential `O_DIRECT` 128 KiB requests (`dd`), 32 MiB written then read back
and hashed, through kernel NBD, on a 1 GiB volume with the same mTLS edge.
`tc netem` applies to loopback, which carries client → nginx → provider.

Two runs at the same revision (the PostgreSQL run measured the first and
last rows only):

| netem on loopback | Write | Read |
|---|---|---|
| none | 6.7–8.1 MiB/s | 8.5–9.9 MiB/s |
| delay 10 ms ± 5 ms | 0.61 MiB/s | 0.61 MiB/s |
| delay 10 ms ± 5 ms, 1 % loss | 0.16–0.17 MiB/s | 0.16–0.17 MiB/s |

Every readback matched, both volumes' deep checks were `clean`, and the
dispatcher recorded no deadline expiry.

How to read these numbers:

- One unit request crosses loopback several times (client → nginx, nginx →
  provider, and back, with nginx opening a new backend connection per
  request), so it costs several netem delays, not one.
- Loss cost 3.6× against delay alone. The likely mechanism (inferred, not
  measured): R5-039 sends a 128 KiB request's 32 units as up to 16
  concurrent HTTP requests and the request finishes with its slowest one,
  and with 1 % loss on every loopback segment most rounds include a TCP
  retransmission timeout (at least 200 ms).
- The 2026-10-04 Debian 13 campaign, before R5-039, read about 0.10 MiB/s
  with the same netem (delay and loss), but through a buffered `sha256sum`
  rather than `O_DIRECT` `dd`, so the gain there is roughly 1.6× and not a
  strict comparison. Delay alone was not measured before R5-039. The local
  benchmark recorded in the remediation log (a fixed 10 ms per provider
  request, no loss) showed 25 s → 2.8 s for 8 MiB.
- A batched HTTP mapping (`items_path`) sends one request per batch and
  avoids most of this; the per-item numbers are a floor for vendors without
  a batch API.

## Not covered

- Provider and client on separate hosts; a commercial provider.
- Physical power loss and long soak runs.
