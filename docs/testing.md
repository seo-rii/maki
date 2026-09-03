# Testing and qualification

Maki combines ordinary unit and integration tests with deterministic fault
injection, model comparison, transport chaos, database simulation, and external
Linux or hardware qualification. Passing an automated tier does not imply that
the higher deployment tiers are complete.

Historical `phase*` test filenames and `phase*_gate_full` function names remain
stable internal identifiers. They do not represent the public documentation or
an active implementation plan.

## Run checks locally

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --release --locked -- --ignored
```

The ignored release-mode suite is substantially more expensive than the default
workspace suite. It uses simulated backing stores and does not perform real
power cuts or privileged device operations.

## Automated CI

The executable workflow is [`.github/workflows/ci.yml`](../.github/workflows/ci.yml).

| Tier | Trigger | Platform | Enforcement |
|---|---|---|---|
| Baseline | Pull requests and pushes | Ubuntu and Windows | Formatting, strict Clippy, and workspace tests block |
| Extended | Scheduled run | Ubuntu | Ignored model, crash, HA, database, and power-loss gates block |

The baseline workspace suite includes unit tests, parser mutation smokes,
golden format vectors, provider conformance, transport chaos, failpoints,
manual-clock retry tests, privilege-plan tests, NBD adapter tests, database and
power-loss simulations, and real-process tests for all four binaries.

The scheduled job runs:

| Test identifier | Workload |
|---|---|
| `phase0_gate_full` | 10,000 seeded durability-model sequences |
| `phase3_gate_full` | 10,000 seeded crash/recovery sequences |
| `phase4_gate_full` | 110,000 randomized block operations |
| `phase5_gate_endpoint_cycles_full` | 10,000 endpoint-failure cycles |
| `phase5_gate_breaker_cycles_full` | 10,000 circuit-breaker lifecycles |
| `phase11_gate_dbsim_full` | 500 database-simulation runs |
| `phase12_gate_full` | 500 barrier and 500 FUA power-loss simulations |

It also builds the Linux cdylib and verifies the global `plugin_init` symbol.

## Test model

`maki-test-support` provides the reusable verification environment:

| Component | Purpose |
|---|---|
| `ReferenceBlockModel` | Oracle for acknowledged, durable, and crash-possible data |
| `CrashableBacking` | Independently keeps or loses unsynchronized operations and can model tearing |
| `FakeCryptoProvider` | Deterministic crypto, latency, errors, and malformed provider responses |
| `ManualClock` | Deterministic retry, timeout, cache TTL, and breaker timing |
| `DeterministicScheduler` | Reproducible seeded interleavings |
| Failpoints | Named failures at journal, shard, and checkpoint persistence boundaries |

Golden vectors freeze the on-disk format. Self-checksummed images are hashed
without their trailing CRC because the CRC of a correctly self-checksummed image
has a constant residue.

## Coverage by subsystem

| Subsystem | Evidence |
|---|---|
| Format and parsing | Overflow checks, malformed input, A/B fallback, CRC, torn-tail and middle-corruption classification |
| Provider contract | Round trips, size/order/index validation, tamper checks, compatibility, and cross-endpoint decrypt |
| Journal and recovery | Persistence-boundary failpoints, sequence continuity, checkpoint ordering, ENOSPC, and double attach |
| Block engine | RMW, concurrent access, FUA, FLUSH, provider batching, and differential model tests |
| Availability | Request and byte bounds, retry budget, jitter, breaker transitions, failover, and permit-leak checks |
| Transports | HTTP mapping/TLS/chaos, WebSocket reconnect/order/size, and gRPC status/metadata/size |
| Cache and growth | Version matching, stale-read prevention, eviction, zeroization, shard creation, and crash recovery |
| NBD adapter | Geometry, capability advertisement, read/write, panic boundary, parallel callbacks, and clean detach |
| Review regressions | `review_storage.rs`, `review_attach.rs`, `review_bounded.rs`, `review_check.rs` (maki-core), `review_deep.rs` (maki-check binary), `review_format.rs` and `review_config.rs` (maki-format), `review_daemon.rs`, `review_control.rs` and `review_sample.rs` (maki-nbdkit), `review_uds.rs` (maki-control), `review_dispatch.rs` (maki-crypto), `review_ws.rs` (maki-crypto-websocket), `review_priv.rs` (maki-privileged), `review_attach.rs` (maki-attach binary): roll-vs-promotion ordering, allocation dirty-flag ordering, fail-closed recovery, durable mark, A/B error classification, key canary and identity checks, bounded journal and degraded state, control-socket lifecycle and ownership (Unix-only suites run under Linux CI and WSL), configuration validation matrix, plaintext-transport policy, TLS fail-closed, the production sample building its provider, retry-safety and absolute deadlines in the dispatcher, endpoint quarantine, and WebSocket unit echo; see the [remediation log](review-remediation.md) |

## Current qualification status

| Requirement | Target | Status | Evidence |
|---|---:|---|---|
| Randomized model operations | 100,000+ | Pass | 110,000-operation block-model gate |
| Crash/recovery cycles | 10,000+ | Partial | 10,000 in-process seeded runs; not 10,000 OS process crashes |
| Endpoint failure cycles | 10,000+ | Pass in simulation | Deterministic dispatcher cycles with no failed requests or permit leaks |
| Circuit-breaker cycles | 10,000+ | Pass in simulation | Complete open, half-open, close, and failed-probe reopen cycles |
| Parser fuzzing | 24 CPU-hours per target | Partial | 5,500 mutation inputs; maintained cargo-fuzz corpus not wired |
| Userspace nbdkit/libnbd/fio | Functional smoke | Pass on Debian 12/KVM | ABI probe, byte-identical copy, and CRC32C fio verification |
| Kernel NBD, LVM, XFS, and fio | Functional smoke | Pass on Debian 12/KVM | Guarded privileged run completed on a disposable NBD target |
| Real databases | Required | Partial | SQLite WAL smoke passed; crash campaigns and other engines remain open |
| QEMU hard power loss | 300+ cuts | Open | Simulation is not hardware evidence |
| Mixed workload | 72 hours | Open | Dedicated hardware run not recorded |

The detailed Debian run is preserved in the
[rootless Linux validation report](native-linux-validation-2026-09-02.md). The
later [privileged Linux validation report](privileged-linux-validation.md)
records the kernel NBD, LVM, XFS, raw and filesystem fio, privilege, helper, and
SQLite smoke results.

## Database qualification

The automated database simulation models a WAL database with synchronous commit,
a durable epoch header, commit records, replay, and an external ledger oracle.
Crashes are injected before commit, after durable commit but before apply, and
after apply. Provider outages must abort uncommitted transactions without
damaging previously committed data.

Real-database qualification requires an attached disposable XFS volume:

- SQLite: WAL and DELETE journal modes, `synchronous=FULL`, process crashes,
  provider outages, `PRAGMA integrity_check`, and an external commit ledger.
- PostgreSQL: `fsync=on`, `synchronous_commit=on`, full-page writes, checksums,
  `pgbench`, forced process crashes, WAL recovery, and `pg_amcheck`.
- ClickHouse: inserts, merges, mutations, partition operations, crash cycles,
  `CHECK TABLE`, and an external hash oracle.
- MinIO: multipart upload, overwrite, range reads, restart and provider outage,
  with SHA-256 verification for every completed object.

The acceptance criterion is zero corruption, zero loss of acknowledged durable
transactions, and zero silent data substitution.

## Power-loss qualification

The automated simulator checks two durability contracts:

```text
WRITE A; WRITE B; FLUSH succeeds; WRITE C; crash
=> A and B are new; C may be old or new

WRITE A with FUA succeeds; crash
=> A is new
```

`CrashableBacking` models independent survival of pending operations. Tearing is
available but is not enabled in the main power-loss gate. Simulation is useful
development evidence, not proof that a real filesystem and device stack obeys
the same model.

QEMU qualification uses a guest on a dedicated virtual disk, an external
host-side acknowledgement ledger, randomized `virsh destroy` cuts, offline
checking after reboot, and at least 300 successful recovery cycles. Bare-metal
qualification uses a second machine for the ledger and a managed power cut; disk
write-cache behavior must be characterized first.

WSL is suitable for Linux syscall integration but not for power-loss claims.

## External qualification checklist

- Repeat kernel `/dev/nbd`, LVM, XFS, and raw-device fio qualification on each
  supported target distribution.
- Effective capability, ACL, core-dump, mount, and service-restart checks under
  installed systemd units.
- Vendor endpoint conformance with production mapping and credentials.
- Credential rotation and TLS certificate rotation.
- Real SQLite and PostgreSQL workloads before broader database qualification.
- QEMU and bare-metal power cuts with an independent acknowledgement ledger.
- Maintained cargo-fuzz targets and long-duration provider and mixed-I/O soaks.

These checks are privileged, destructive, externally credentialed, or
long-running. Run them only in explicitly authorized environments.
