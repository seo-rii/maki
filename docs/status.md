# Project status

This page is the single authoritative statement of what Maki supports today.
Other documents describe procedures or record evidence; when they disagree
with this page about the *current* state, this page wins and the other
document needs a fix. Dated reports under [`qualification/`](qualification/README.md)
describe what was true when they were written and never claim current state.

Last updated: 2026-10-01 (after the R5-001…R5-034 fixes; see the
[remediation log](review-remediation.md#fifth-review-2026-10-01-r5-001r5-034)).

## Release state

| Item | Value |
|---|---|
| Version | `0.1.0` (workspace `Cargo.toml`); no tagged release yet |
| Production approval | **Pending.** No configuration of Maki is production-qualified |
| Recommended use | Evaluation and development on disposable Linux hosts |
| Primary platform | Debian 12 (bookworm), Linux 6.1, systemd 252, on Google Compute Engine VMs |
| Prebuilt packages | None published; build the Debian package from source ([installation guide](getting-started/installation-debian.md)) |

## Volume formats

| Format | Selection | Status |
|---|---|---|
| Superblock envelope v2, mirrored durable proofs | Default for `maki volume create` | Current default; all scoped campaigns below used it unless noted |
| Envelope v3 with durable TRIM and space reclamation | `maki volume create <config> --discard` | Implemented; scoped GCE whole-instance-reset campaigns passed (2026-09-20, and 2026-10-03 after the R5 fixes), kernel `fstrim` reclaimed backing space through XFS/LVM/NBD, and one scoped PostgreSQL 15 crash and lifecycle campaign passed ([details](space-reclamation.md)) |
| Rollback-protected backing (local witness) | `[backing.rollback_protection]` on a new volume | **Experimental.** Focused test suites only; not campaign-qualified ([details](rollback-protection.md)) |
| Legacy envelope v1 | Existing volumes only | Read-only checks with a warning; writable recovery is refused; migrate through [durable recovery](durable-recovery.md) |

There is no in-place format upgrade between envelopes.

## Crypto providers

| Provider | Status |
|---|---|
| `local-aes-gcm-siv` | Supported and used by every kernel NBD/LVM/XFS campaign; authenticated and context-bound |
| `local-aes-xts` | Supported; no authenticated integrity, wrong-key detection only through the key canary; not used in external campaigns |
| `remote-http` | Supported; scoped campaigns against a reference provider (loopback, then cross-host TLS 1.2/1.3, mTLS, bearer, failover, credential and CA rotation). No commercial vendor endpoint qualified |
| `remote-websocket`, `remote-grpc` | Supported; scoped campaigns against a reference provider, single-host and cross-host (TLS 1.2/1.3, mTLS, failover, total-outage stall and resume, restart, deep check; PostgreSQL over gRPC). No commercial vendor endpoint qualified |

## Deployment topology

The qualified attachment topology is one whole NBD device as a single LVM PV,
one VG, one XFS data LV, attached through `maki-attach` with `fs_uuid` and
`[lvm_identity]` pins, under the packaged systemd lifecycle. Everything else is
enumerated, with its status, in the [support matrix](deployment/support-matrix.md).

## Databases and workloads

| Workload | Status |
|---|---|
| SQLite WAL (`synchronous=FULL`) | Scoped campaigns: installed lifecycle with nbdkit crashes, fresh-host restore, package upgrade, migration, provider outage |
| PostgreSQL 15 (checksums, `fsync`, `synchronous_commit`, `full_page_writes` on) | One scoped postmaster-`SIGKILL` crash campaign with `pg_amcheck`; production profiles and long runs open |
| Other databases and object stores | Not tested |

## Failure-injection evidence

| Tier | Status |
|---|---|
| Deterministic simulation (model, crash, fault, chaos, fuzz) | Passing in CI and release gates |
| Native nbdkit process kill, cgroup CPU/freeze/OOM | Scoped campaigns passed; constrained-recovery RSS measured for one profile |
| Firecracker guest loss, GCE whole-instance hard reset | Scoped campaigns passed (v2 and v3) |
| Physical power loss, QEMU power cuts, 72-hour mixed soak | **Open** |

## Known limitations

- Default v2/v3 backings cannot detect restoration of an older, internally
  valid volume image (historical rollback). Only the experimental
  rollback-protected backing addresses this, and it is not qualified.
- `local-aes-xts` returns garbage rather than an error for a wrong key once
  the canary check is bypassed by an empty volume; use `local-aes-gcm-siv`.
- Remote transport libraries may keep plaintext copies outside `SecretBuffer`,
  and stack temporaries of the local cipher implementations are outside the
  `secure-buffers` page lock ([transport memory](transport-memory.md)).
- Recovery memory is bounded by a 1 MiB replay batch and the journaled overlay
  by `limits.max_overlay_bytes`/`max_overlay_entries`, but a total-RSS bound for
  arbitrary geometry, provider and cache settings has not been established.
- The volume's XFS filesystem is mounted `nosuid,nodev`; workloads that need
  setuid programs or device nodes on it are not supported.
- The R5 changes passed one scoped GCE campaign on 2026-10-03
  ([record](qualification/r5-hardware-validation-2026-10-03.md)): ten v3
  discard resets, kernel `fstrim` reclamation through XFS/LVM/NBD, the
  `nosuid,nodev` mount, attach-config ownership, and the packaged quick start
  under the `maki@.service` sandbox. A further campaign that day ran
  PostgreSQL 15 crash and lifecycle tests on a v3 volume with `fstrim` under
  load, and three lifecycles under the adopted syscall filter
  ([record](qualification/database-discard-pressure-validation-2026-10-03.md)).
- All three remote transports ran under that filter on 2026-10-04, each
  with mTLS, endpoint failover, a total-outage stall and resume, `fstrim`
  and a restart, with no syscall outside `@system-service`
  ([record](qualification/remote-transport-syscall-filter-validation-2026-10-04.md)).
  PostgreSQL 15 then passed its crash and lifecycle scenario over remote gRPC,
  with an endpoint outage under load, under the packaged unit including
  `MemoryDenyWriteExecute=yes`
  ([record](qualification/remote-database-zero-mdwe-validation-2026-10-04.md)).
- Debian 13 (systemd 257, glibc 2.41, Linux 6.12) passed a scoped campaign
  with all three remote transports under the shipped sandbox, with latency
  and packet loss, and NBD zeroing
  ([record](qualification/debian13-remote-transport-validation-2026-10-04.md)).
  It needs `fc8d697` or later and nbd-client 3.27 built from source. That
  campaign's per-item HTTP mapping was slow under latency (one round trip
  per 4 KiB unit, in sequence); a request's units now go out concurrently
  (R5-039). On Debian 13 a per-item HTTP volume then did 0.61 MiB/s of
  sequential direct I/O with 10 ms ± 5 ms of loopback latency and
  0.16–0.17 MiB/s with 1 % loss added; prefer a batched mapping. PostgreSQL
  17 passed its crash and lifecycle scenario over that mapping with the
  packaged `maki-attach` LVM lifecycle
  ([record](qualification/debian13-postgresql-http-validation-2026-10-05.md)).
- With client and provider on separate VMs and the provider reached by its
  internal DNS name, all three remote transports passed under the shipped
  sandbox on Debian 12
  ([record](qualification/cross-host-sandbox-validation-2026-10-05.md)).
  Hard resets of that provider host during fsync'd writes stalled the
  writer for 12–20 s per transport, with no failed write and no lost
  acknowledged data
  ([record](qualification/provider-host-reset-validation-2026-10-05.md)).
- Below the backing's emergency reserve plus checkpoint headroom, writes are
  refused. A filesystem on the volume can then neither delete files nor run
  `fstrim` (XFS returned EIO for both); recover by freeing space on the
  backing filesystem. Raw discards are still admitted there.
- Privileged attach supports the single-PV/single-data-LV XFS topology; other
  device-mapper layouts fail closed and need operator diagnosis
  ([storage recovery limits](storage-recovery.md#remaining-recovery-limits)).
- Debian 12's stock `nbd-client` 3.24 is too old; 3.27.0 or later is required
  ([installation guide](getting-started/installation-debian.md#nbd-client-327-or-later)).

## Where the evidence lives

- Automated coverage and release gates: [testing](testing.md).
- Dated external campaigns and reviews: [qualification index](qualification/README.md).
- Review findings and fixes: [remediation log](review-remediation.md).
- Remaining external checks before any production approval:
  [external qualification checklist](testing.md#external-qualification-checklist).
