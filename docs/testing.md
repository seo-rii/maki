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

The default (debug) suite also runs the core sanitizers: `Overlay`,
`JournalWriter`, and `Volume` check their invariants after every mutation and
panic on the first violation. Release builds compile the checks out, so run the
default suite, not only the release gates, after touching those structures.

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
The Linux baseline installs `nbdkit`, `nbdkit-plugin-dev`, and `libnbd-bin`
before the workspace tests and checks their executables. This runs the native
startup, negotiation, drain, process-crash, and ABI regressions instead of relying on optional
tool availability. Native startup uses disposable files and Unix sockets; it
does not attach a kernel NBD device or mount a filesystem. On developer hosts
without nbdkit, native cases explicitly report that they were skipped; such a
run is not native execution evidence.
The Linux baseline also runs the Python cgroup and Firecracker fault-oracle
regressions. Actual Docker cgroup and KVM/Firecracker campaigns remain opt-in
host qualification steps.

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

It also builds the Linux cdylib, verifies the global `plugin_init` symbol,
installs `nbdkit-plugin-dev` and runs `review_abi.rs`, which compiles a C probe
against the distribution's `nbdkit-plugin.h` and compares every field offset
and `NBDKIT_*` constant the shim depends on. The same test runs under WSL
when the header is installed there, and skips with a message otherwise.

## Test model

`maki-test-support` provides the reusable verification environment:

| Component | Purpose |
|---|---|
| `ReferenceBlockModel` | Oracle for acknowledged, durable, and crash-possible data |
| `CrashableBacking` | Independently keeps or loses unsynchronized operations and can model tearing. Failure semantics are Linux-faithful: a failed `sync_data` marks its dirty writes clean and *lost* (a retried sync writes nothing; only a rewrite persists them), and the partial-write hook makes a `write_at` persist a prefix before failing |
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
| Review regressions | `review_storage.rs`, `review_attach.rs`, `review_bounded.rs`, `review_check.rs` (maki-core), `review_deep.rs` (maki-check binary), `review_format.rs` and `review_config.rs` (maki-format), `review_daemon.rs`, `review_control.rs`, `review_sample.rs` and `review_security.rs` (maki-nbdkit), `review_uds.rs` (maki-control), `review_dispatch.rs` and `review_scheduler.rs` (maki-crypto), `review_ws.rs` (maki-crypto-websocket), `review_priv.rs` (maki-privileged), `review_attach.rs` (maki-attach binary): roll-vs-promotion ordering, allocation dirty-flag ordering, fail-closed recovery, durable mark, A/B error classification, key canary and identity checks, bounded journal and degraded state, control-socket lifecycle and ownership (Unix-only suites run under Linux CI and WSL), configuration validation matrix, plaintext-transport policy, TLS fail-closed, the production sample building its provider, retry-safety and absolute deadlines in the dispatcher, endpoint quarantine, and WebSocket unit echo; see the [remediation log](review-remediation.md) |
| Sanitizers and randomized suites | Debug-build `check_invariants` on `Overlay`, `JournalWriter`, and `Volume` after every mutation; `review_fuzz.rs` (maki-format: single-bit-flip and random-mutation fuzz of every decoder, the journal scanner, URL parsing, and `validate()` on a mutated production sample), `review_stress.rs` and `review_corruption.rs` (maki-core: concurrent engine stress with a per-unit oracle, provider chaos, background checkpoints and a crash; engine-level sweep of all persistence failpoints; random single-file corruption with deep check and re-attach), `review_stress_crypto.rs` (maki-crypto: scheduler and dispatcher under random faults), `review_cache_model.rs` (maki-cache: model-based LRU check); findings S-01 to S-05 in the [remediation log](review-remediation.md#sanitizers-and-randomized-suites-2026-09-03) |
| Second audit regressions | `review_audit.rs` (maki-core: process-restart durability, covered-segment reclaim, adoption ordering, scanner bounds, covered-prefix resurrection, decrypt length), `review_audit2.rs`, `review_secret.rs` (maki-crypto: breaker probes, deadline accounting, background validation, lane concurrency, self-test strictness, pending items, page unlocking), `review_redirect.rs` (maki-crypto-http), `review_hang.rs` (maki-crypto-websocket), and the O-series additions to `review_priv.rs`, `review_uds.rs`, `review_control.rs`, `review_sample.rs`, `review_config.rs`, `review_format.rs`; findings K/C/O in the [remediation log](review-remediation.md#second-audit-2026-09-03-core-crypto-layer-operational-layers) |
| Third review regressions | `review_writeback.rs` and `review_limits.rs` (maki-core: sync-retry rewrite, recovery rewrite of page-cache bytes, torn-tail normalization, request-size cap and per-unit admission cost), `review_abi.rs` (maki-nbdkit: the nbdkit struct layout and constants, `block_size` callback included, checked against the installed header by a compiled C probe, Linux), F05 additions to `review_security.rs` (swap classification by device identity, unreadable `/proc/swaps` refused), `review_secret.rs` page-lifetime test (maki-crypto, Linux, reads `/proc/self/smaps`), `review_limits.rs` (maki-control: idle and write timeouts, busy refusal, session backlog), F02 additions to `review_priv.rs` (mount topology through device-mapper `slaves`), the symlink test in `maki-backing`; findings F01 to F10 in the [remediation log](review-remediation.md#third-review-2026-09-05-os-partial-failure-device-identity-memory-ownership) |
| Fourth pass (specification) | `review_state.rs` (maki-core: degraded state on journal sync failure, admission and barrier-latency counters), `review_metrics.rs` (maki-nbdkit: every SPEC §40 metric present with and without a dispatcher), `dispatcher_reports_latency_budget_and_inflight` (maki-crypto), `preferred_io_defaults_to_the_crypto_unit` and the absolute-root cases (maki-format), `created_directories_and_files_are_owner_only` (maki-backing, Unix), `review_keysource.rs` (maki-crypto-local, Unix), `control_commands_time_out_against_a_silent_daemon` (maki binary, Unix); findings N-01 to N-08 in the [remediation log](review-remediation.md#fourth-pass-2026-09-05-specification-contradictions-and-boundaries) |
| Fifth pass | socket-path cases (maki-format); findings N-09 to N-13 in the [remediation log](review-remediation.md#fifth-pass-2026-09-05-ab-retry-breaker-probes-packaging). N-09's A/B retry durability is covered by the preserve-first `review_ab_retry.rs` (maki-format, maki-core) after the merge; N-10 and N-11 by `review_probe_lifetime.rs` and `regression_control_packaging.rs` below |
| Additional review (BUG-015…BUG-024) | `review_next_storage.rs` (maki-core: journal reclaim never outruns checkpoint-state durability, BUG-022), `review_next_grow_*` in `exec_tests.rs` (maki-privileged: grow needs the trusted record and lock, BUG-018), `review_next_transport.rs` (maki-crypto-grpc: a stalled response is bounded by the transport timeout, BUG-017), `review_next_control.rs` (maki-nbdkit: shutdown drains live sessions and frees the volume lock, BUG-015), `pointer_tests` in `maki-crypto-http` (RFC 6901 request-pointer escaping, BUG-024); BUG-016/019/023 were already closed by the merged F05/F02/backing-symlink work. See the [remediation log](review-remediation.md#additional-review-2026-09-05-eight-further-findings-bug-015--bug-024) |

## September 2026 review regressions

These suites cover the repaired storage, resource-lifetime, and configuration
boundaries. They are part of the default workspace suite; Linux-specific checks
exercise kernel page-lock state, and the runtime permission check models the
packaged configuration without installing services or creating users.

| Boundary | Regression coverage |
|---|---|
| A/B retry durability (BUG-001) | `review_ab_retry.rs` in `maki-format` and `maki-core`: failed data/directory sync, repeated retries and restart, sector tearing, writeback that loses dirty bits, preservation across metadata types, and recovery of durable volume data |
| Required attach configuration (BUG-002) | `maki-privileged/tests/regression_missing_attach_config.rs`: required assertion in the unit and actual offline systemd assertion evaluation for missing/present temporary configuration |
| Trusted helper state (BUG-003) | `maki-privileged/src/state_tests.rs`, `exec_tests.rs`, and `tests/regression_attach_state.rs`: protected state ancestors/files, configuration and live backend identity, stale records, fail-before-side-effects ordering, rollback, and cleanup failure; device operations are simulated |
| HalfOpen probe lifetime (BUG-004) | `maki-crypto/tests/review_probe_lifetime.rs`: request/provider errors, operation deadline, future cancellation, and exhausted retry budget all leave a slot for a healthy recovery request |
| WebSocket connection lifetime (BUG-005) | `maki-crypto-websocket/tests/review_connection_lifetime.rs`: server-observed socket closure after timeout, outer cancellation, and idle provider drop; a healthy successor remains reusable |
| Secret-buffer page ownership (BUG-006) | `maki-crypto/tests/review_secret_page_lifetime.rs`: shared-page drop, `into_vec`, and duplicate lifetimes; last-owner unlock, lock failures, and full-capacity zeroization before deallocation, with process-wide settings isolated in child processes |
| Credential source identity (BUG-007) | `maki-nbdkit/tests/review_credential_sources.rs`: conflicting sources for one name rejected before loading credentials; repeated same-source references and distinct names remain valid |
| HTTP error redaction (BUG-008) | `maki-crypto-http/tests/review_redirect.rs`: connection failure, timeout, and truncated response errors omit request URLs and synthetic query secrets from both Display and Debug |
| Administrative socket access (BUG-009) | `maki-nbdkit/tests/regression_control_packaging.rs`: default/example/custom paths, admin traversal, daemon access, and isolation from NBD and helper state under the packaged directory modes |
| Interrupted detach (BUG-010) | `maki-privileged/src/detach_tests.rs`, `exec_tests.rs`, and `probe.rs`: retry after each completed step, safe record-only cleanup, wrong mount/backend refusal, escaped VG names, partition holders, and direct mounts; all device operations use fixtures |
| NBD request limits (BUG-011, supersedes O-03) | `maki-nbdkit/tests/review_nbd_limits.rs`: oversized reads leave caller buffers untouched, oversized writes leave volume data unchanged, minimum alignment applies to offsets and lengths, valid maximum writes survive reopen, invalid wire sizes fail configuration validation, and real nbdkit/libnbd negotiation reports the configured tuple |
| Scheduler cancellation (BUG-012) | `maki-crypto/tests/review_scheduler_cancellation.rs`: queued payload and admission release, cancellation behind a live blocked group, active-RPC cancellation, cancellation of one group in a coalesced batch, and continued service for live callers |
| Queue deadlines (BUG-013) | `maki-crypto/tests/review_queued_deadline.rs`: ManualClock deadlines cover admission, coalescing, slot wait, and RPC under one caller budget; a live peer retains its own budget and stall mode remains unbounded |
| Concurrent socket permissions (BUG-014) | `maki-control/tests/review_uds_umask.rs`: bind concurrently with private directory creation and verify mode 0700 is preserved; `review_uds.rs` also checks prepared socket mode/group, preservation on failed group lookup, cleanup on failed publication, and actual Linux connection at the maximum public path length |
| Partial journal writes (BUG-020) | `maki-core/tests/review_journal_retry.rs`: a BackingFile that writes a prefix then returns EIO, shorter retries, roll/FLUSH without retry, cleanup failure, and recovery after sealing the segment |
| Journal writeback errors (BUG-021) | `maki-core/tests/review_journal_writeback.rs`: clean-but-unpersisted cache after EIO, retry and process recovery followed by power loss, changes after the scan, valid-header mutation despite unchanged CRC residue, and pending ranges larger than the 64 KiB rewrite buffer |
| gRPC authentication evidence (TEST-002) | `maki-nbdkit/tests/phase9_daemon.rs`: attach without metadata must fail after the server actually rejects it with Unauthenticated; valid metadata roundtrips with no authentication rejection, independently of which deadline's error text wins |

The native NBD negotiation case requires Linux, `nbdkit`, and `nbdinfo` from
libnbd. It uses Cargo's cdylib and an isolated child process with a private Unix
socket; absent optional programs skip that case. It passed
on this review host. An independent C probe against the installed
`nbdkit-plugin.h` also confirmed the 384-byte published prefix and the
`block_size` callback at offset 376 on this host. These checks qualify the
userspace ABI and negotiation, without operating a kernel NBD device.

## Current qualification status

The September helper changes require new target-host qualification with
nbd-client netlink/backend identity support. The historical privileged Linux
reports below cover earlier code. The current regression suite does not start
systemd workloads or attach real devices; follow the
[runtime-layout upgrade procedure](operations.md#upgrading-the-runtime-layout).

| Requirement | Target | Status | Evidence |
|---|---:|---|---|
| Randomized model operations | 100,000+ | Pass | 110,000-operation block-model gate |
| Crash/recovery cycles | 10,000+ | Partial | 10,000 in-process seeded runs plus native FLUSH/FUA SIGKILL regressions; not 10,000 OS process crashes |
| Endpoint failure cycles | 10,000+ | Pass in simulation | Deterministic dispatcher cycles with no failed requests or permit leaks |
| Circuit-breaker cycles | 10,000+ | Pass in simulation | Complete open, half-open, close, and failed-probe reopen cycles |
| Parser fuzzing | 24 CPU-hours per target | Partial | `review_fuzz.rs` (exhaustive single-bit-flip sweep of every on-disk decoder, ~30,000 seeded mutations, config and URL fuzz) and `review_fuzz_transport.rs` (random provider responses through the HTTP parse path); coverage-guided `cargo-fuzz` targets in `fuzz/` (`format_decoders`, `journal_scan`, `config_parse`, `endpoint_url`, `probe_parsers`) — a 60 s-per-target smoke run did ~62M iterations with no crash; a 24 CPU-hour-per-target corpus run remains outstanding |
| Userspace nbdkit/libnbd/fio | Functional smoke | Pass on Debian 12/KVM | ABI probe, byte-identical copy, and CRC32C fio verification |
| Kernel NBD, LVM, XFS, and fio | Functional smoke | Pass on Debian 12/KVM | Guarded privileged run completed on a disposable NBD target |
| Real databases | Required | Partial | SQLite WAL smoke passed; crash campaigns and other engines remain open |
| cgroup resource faults | Target-specific | Partial | Real AES userspace NBD passed CPU throttling, freeze/resume, SIGKILL and workload OOM readback. Recovery at 32 MiB varied by trial; 192 MiB succeeded |
| Firecracker guest abrupt loss | Target-specific | Partial | 20 alternating FLUSH/FUA ACKs survived VMM SIGKILL and cold-boot authenticated readback on GCP nested KVM; L1 kernel and storage caches remained live |
| QEMU hard power loss | 300+ cuts | Open | Simulation is not hardware evidence |
| Mixed workload | 72 hours | Open | Dedicated hardware run not recorded |

The detailed Debian run is preserved in the
[rootless Linux validation report](native-linux-validation-2026-09-02.md). The
later [privileged Linux validation report](privileged-linux-validation.md)
records the kernel NBD, LVM, XFS, raw and filesystem fio, privilege, helper, and
SQLite smoke results.
The [September 12 fault report](cgroup-fault-validation-2026-09-12.md) records
the new native process and cgroup executions, external ACK evidence, reproduction
commands and the unresolved restart limit. The host was Debian, so no WSL
shutdown was executed.
The [Firecracker report](firecracker-validation-2026-09-12.md) records the
separate guest-kernel/page-cache loss campaign, its host-fsynced ACK ledger,
image hashes, cold-boot readbacks, and the boundary at the surviving L1 host.

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

The opt-in Firecracker runner boots the same writable data image after each
VMM `SIGKILL`. Its virtio data drive explicitly uses Firecracker `Writeback`
cache semantics and synchronous host I/O, while the root filesystem remains
read-only. A guest running the release Maki nbdkit plugin alternates FLUSH and
FUA. Only complete guest ACK frames are fsynced into the L1 ledger, and the
next boot reads and hashes the acknowledged units without receiving their
expected hashes. This removes the guest kernel and guest page cache from the
next recovery attempt. It does not cut power to the L1 kernel or persistent
disk and therefore is not physical power-loss evidence.

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
- Long-duration (24 CPU-hour-per-target) `cargo-fuzz` corpus runs (the
  targets exist in `fuzz/`; only short smoke runs have been done) and
  long-duration provider and mixed-I/O soaks.

These checks are privileged, destructive, externally credentialed, or
long-running. Run them only in explicitly authorized environments.
