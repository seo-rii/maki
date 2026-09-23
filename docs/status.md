# Project status

This page is the single authoritative statement of what Maki supports today.
Other documents describe procedures or record evidence; when they disagree
with this page about the *current* state, this page wins and the other
document needs a fix. Dated reports under [`qualification/`](qualification/README.md)
describe what was true when they were written and never claim current state.

Last updated: 2026-09-23.

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
| Envelope v3 with durable TRIM and space reclamation | `maki volume create <config> --discard` | Implemented; one scoped GCE whole-instance-reset campaign passed; no database campaign yet ([details](space-reclamation.md)) |
| Rollback-protected backing (local witness) | `[backing.rollback_protection]` on a new volume | **Experimental.** Focused test suites only; not campaign-qualified ([details](rollback-protection.md)) |
| Legacy envelope v1 | Existing volumes only | Read-only checks with a warning; writable recovery is refused; migrate through [durable recovery](durable-recovery.md) |

There is no in-place format upgrade between envelopes.

## Crypto providers

| Provider | Status |
|---|---|
| `local-aes-gcm-siv` | Supported and used by every kernel NBD/LVM/XFS campaign; authenticated and context-bound |
| `local-aes-xts` | Supported; no authenticated integrity, wrong-key detection only through the key canary; not used in external campaigns |
| `remote-http` | Supported; scoped campaigns against a reference provider (loopback, then cross-host TLS 1.2/1.3, mTLS, bearer, failover, credential and CA rotation). No commercial vendor endpoint qualified |
| `remote-websocket`, `remote-grpc` | Supported with verified TLS/mTLS and daemon I/O tests; no external campaign |

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
  and the local providers' expanded AES key schedules are zeroized on drop but
  not page-locked under `secure-buffers` ([transport memory](transport-memory.md)).
- Recovery memory is bounded by a 1 MiB replay batch, but a total-RSS bound for
  arbitrary geometry, provider and cache settings has not been established.
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
