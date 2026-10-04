# Remote transports under the syscall filter — 2026-10-04

A dated record of one campaign on disposable GCE VMs (times are UTC); it does
not claim current state. It follows the
[PostgreSQL, space-pressure and syscall-filter campaign](database-discard-pressure-validation-2026-10-03.md),
which ran the newly adopted `SystemCallFilter=@system-service` only with the
local provider. This campaign ran all three remote transports under it, and
was the first external campaign for `remote-websocket` and `remote-grpc`.

## Environment

| Item | Value |
|---|---|
| Project and zone | `hancomac`, `asia-northeast3-a` |
| VM | `e2-standard-4`, 50 GB balanced boot disk, no service account or scopes, fixed termination time with `DELETE` |
| Image and kernel | Debian 12.15, `6.1.0-53-cloud-amd64` |
| Software | nbdkit 1.32.5, nbd-client 3.27.1 (source build), nginx 1.22.1, systemd 252.39, Rust 1.99.0 |
| Revision | `f1d75f7` (attempt 4; earlier attempts below) |
| Daemon unit | packaged `maki@.service` from that revision, plus a drop-in adding `LoadCredential=crypto-client-key:…` |

## Topology

One VM held both sides. A qualification provider (`maki-crypto-local`
AES-256-GCM-SIV behind a small axum/tonic service, context-bound, bearer
token checked on HTTP and gRPC) ran as six systemd services: endpoints A and B
for each transport on loopback. nginx terminated TLS in front of each with a
private qualification CA and required a client certificate; endpoint A
accepted only TLS 1.2 and endpoint B only TLS 1.3. Maki resolved
`provider-a.maki.test` and `provider-b.maki.test` through `/etc/hosts` to the
VM's VPC address, so connections left the loopback interface and went through
glibc name resolution.

| Transport | Endpoints | Authentication |
|---|---|---|
| `remote-http` | `https://provider-{a,b}.maki.test:8443/8444` | mTLS and a bearer header credential |
| `remote-websocket` | `wss://provider-{a,b}.maki.test:8445/8446/crypto` | mTLS |
| `remote-grpc` | `https://provider-{a,b}.maki.test:8447/8448` (HTTP/2) | mTLS and a bearer metadata credential |

Each volume was a 1 GiB v3 discard volume with 4 KiB units,
`availability_policy = "stall"` and a 5 s transport timeout, with XFS directly
on `/dev/nbd15`. Before the transports ran, `curl` confirmed that a client
without a certificate got HTTP 400 from the edge.

## Method

For each transport, in order:

1. **Audit pass.** A temporary drop-in removed the filter and set
   `SystemCallLog=~@system-service`, so the kernel reports every syscall
   outside the set as an audit `SECCOMP` record. Under it: `mkfs.xfs`,
   96 MiB written, endpoint A stopped and 16 MiB written, `fstrim`, a
   stop/start, and a full readback. A positive control earlier in the run
   showed that the same setting reports a deliberate `swapoff(2)` on this
   kernel.
2. **Enforce pass** with the shipped unit (`Seccomp: 2` checked in
   `/proc/<pid>/status`):
   - 128 MiB written and read back after dropping caches;
   - 32 MiB written with B stopped, then 32 MiB with A stopped;
   - both stopped: an 8 MiB `O_DIRECT` writer had to remain blocked after
     10 s, then complete once B returned;
   - one file deleted, `fstrim`, a device flush and a checkpoint;
   - drain, stop, start, full readback; drain, stop, offline deep check.
   Every file's SHA-256 was computed from a source copy on the boot disk
   before it was written.

## Results

**33 of 33 checks passed (11 per transport).**

- **Syscalls:** no audit `SECCOMP` record from the daemon in any audit pass,
  and no `EPERM`, `SIGSYS` or seccomp message in its journal under the filter.
  This covers rustls, reqwest, tokio-tungstenite, tonic/HTTP/2, glibc
  `getaddrinfo`, `mlock` and nbdkit on this kernel.
- **TLS edge:** every request carried a verified client certificate
  (`SUCCESS`); endpoint A served only TLS 1.2 and B only TLS 1.3.

  | Edge | 2xx/101 | 422 | 502 |
  |---|---|---|---|
  | HTTP A / B | 269,767 / 229,078 | 40 / 20 | 31 / 19 |
  | WebSocket A / B (upgrades) | 7 / 6 | — | 72 / 42 |
  | gRPC A / B | 7,200 / 4,826 | — | 35 / 20 |

  The 422s are the attach self-test's tamper and context probes, which
  WebSocket and gRPC answer in-band; the 502s fall in the stopped-provider
  windows.
- **Failover and outage:** per transport, 24–27 endpoint failovers and 41–47
  retries, no deadline expiry, no unsafe-retry refusal, no checkpoint or
  journal-sync failure. The writer stayed blocked with both endpoints down
  and completed once B returned; restarting B, the write completing and
  the full readback took 28–38 s together.
- **Discard:** `fstrim` trimmed 775.8 MiB through each transport (tombstones
  need no provider call).
- **Deep check:** for each volume, durable sequence 131,323–131,324, 63,536
  allocated slots, 0 invalid, verdict `clean`.

## Product bug found: R5-035

Attempt 3 stopped at the first `maki@qhttp` start:
`provider fatal: credential is not valid UTF-8`. The bearer token, generated
with `openssl rand -hex 32`, was read through the key loader, which hex-decodes
any even-length hex string because local keys may be stored as hex; the
header builder received 32 random bytes. `maki volume create` never loads it,
so only the daemon failed. Reproduced locally, fixed test-first in `f1d75f7`
(`KeySource::load_text`), and listed as R5-035 in the
[remediation log](../review-remediation.md#fifth-review-2026-10-01-r5-001r5-034).
The September remote campaigns had used non-hex tokens.

## Attempts

Each ran on its own VM, which was deleted with empty exact-name listings.

| Attempt | Revision | Stopped at | Cause |
|---|---|---|---|
| 1 | `b41580e` | provider install | Harness: `/usr/local/libexec` does not exist on Debian 12 (`install -D`) |
| 2 | `b41580e` | environment record | Harness: `nginx` is in `/usr/sbin`, not on the user's `PATH` |
| 3 | `b41580e` | first daemon start | **Product bug R5-035** (above) |
| 4 | `f1d75f7` | — | Passed |

## Not covered

- Provider and client on separate hosts. The
  [2026-09-19 campaign](cross-host-tls-provider-validation-2026-09-19.md)
  covered that for HTTP only, without the syscall filter.
- A commercial provider, a database workload over a remote transport, packet
  loss and latency.
- `MemoryDenyWriteExecute`, which the unit does not set.
- Physical power loss and long soak runs.
