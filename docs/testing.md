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
The Linux baseline also runs the Python cgroup, Firecracker, and GCE reset
fault-oracle regressions. Actual Docker cgroup, KVM/Firecracker, and GCE reset
campaigns remain opt-in host qualification steps.

The 2026-09-18 bounded-replay follow-up at revision `733833c` reran the Docker
cgroup campaign. A 21.5 MiB distinct pressure tail recovered at 32 MiB with all
136 external ACK units intact, then passed the 192 MiB recovery and offline
deep check. Because `memory.peak` reached the exact 32 MiB cap, this is a
scenario result rather than a minimum-memory recommendation. See the
[cgroup evidence](cgroup-fault-validation-2026-09-12.md#bounded-replay-follow-up--2026-09-18).

The 2026-09-19 [constrained recovery RSS campaign](recovery-rss-validation-2026-09-19.md)
then ran two independent 48 MiB and two independent 64 MiB post-OOM recoveries.
All four matched 136 ACK units and passed deep checking. The largest observed
nbdkit `VmHWM` was 11,415,552 bytes. Both 48 MiB cgroups touched their cap; both
64 MiB runs stayed below it without max events. This qualifies that fixed
profile and does not define a universal deployment minimum.

The scheduled job runs:

Linux PR, push, and scheduled CI installs the pinned `cargo-audit 0.22.1` and
runs `cargo audit --deny warnings`. A known vulnerability, unmaintained or
unsound advisory, or yanked crate therefore fails the job against the fetched
RustSec database. Revision `8ed9c03` raised the direct rustls minimum and lockfile
from affected 0.23.43 to 0.23.45 after `RUSTSEC-2026-0285`; the focused HTTP/TLS
package suite and a fresh warning-denying audit passed locally.

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
| Convergent privileged cleanup (R3-007) | `maki-privileged/src/exec_tests.rs`, `recover.rs`, and `maki-attach/tests/e2e.rs`: no record succeeds without probing, an owned connected backend selects detach, an absent backend selects recovery, and a foreign or unreadable backend preserves the record. The proof-scoped fallback runs only after an exited `vgchange` returns nonzero, accepts one exact closed target mapping, rechecks the backend, and rejects changed identity, multi-mapping topology, open count, or force/deferred/retry removal |
| Packaged workload lifecycle (R3-007) | `maki-privileged/tests/regression_workload_lifecycle.rs`: daemon failure enters bounded recovery, registered workloads stop before attachment cleanup, cleanup success alone restarts the target, every workload start verifies identity, and target stop cleans attachment before daemon exit |
| Current privileged runner contract | `regression_nbd_client_version_probe.rs` and `phase7_priv.rs`: a 3.27.1 help banner with nonzero exit is accepted, netlink receives `nbdN`, root plans mode-0600 configuration, the control runtime is provisioned, and real cleanup is invoked twice |

The native NBD negotiation case requires Linux, `nbdkit`, and `nbdinfo` from
libnbd. It uses Cargo's cdylib and an isolated child process with a private Unix
socket; absent optional programs skip that case. It passed
on this review host. An independent C probe against the installed
`nbdkit-plugin.h` also confirmed the 384-byte published prefix and the
`block_size` callback at offset 376 on this host. These checks qualify the
userspace ABI and negotiation, without operating a kernel NBD device.

## Current qualification status

The current revision `448c0b2` passed a disposable Debian 12 GCE campaign with
nbd-client 3.27.1, actual Maki nbdkit, kernel NBD, pinned single-PV LVM/XFS,
trusted attach/verify/cleanup, and a Docker SQLite external ACK oracle under the
Installed shipped systemd graph. Two automatic nbdkit `SIGKILL` recoveries
advanced the fsynced ledger from 16 to 32 and 48 rows. A third crash while a
root process held the LV open failed cleanup closed without restarting the
workload; closing the descriptor and explicitly retrying recovery reached 64
acknowledged rows in a fourth distinct container. An independent container
matched all 64 rows and reported `integrity_check=ok`.
Follow the [runtime-layout upgrade procedure](operations.md#upgrading-the-runtime-layout).

Revision `ece7e39` then passed a separate two-host restore campaign. A source
VM wrote 32 SQLite WAL rows and a fsynced external ledger, drained and exported
the unchanged v2 backing, configuration, attach identity and credential, and
was deleted with its boot disk. A newly created VM restored the artifacts,
matched all 32 rows, added 16 rows, and matched all 48 after a full lifecycle
restart. Both final offline checks passed and both VMs and disks were deleted.
See the [fresh-host restore validation](fresh-host-restore-validation-2026-09-17.md).

Revision `c385c99` then passed a separate remote-provider database campaign on
one disposable GCE VM. Two authenticated loopback HTTP providers served the
actual Maki kernel NBD/LVM/XFS path. SQLite committed eight rows with both
providers, eight with only B, eight with only A, stalled one transaction while
both were down, resumed that exact transaction after B returned, and finished
at 32 rows. All IDs and body hashes matched an external fsynced ledger before
and after a packaged lifecycle restart. See the
[remote HTTP provider database validation](remote-provider-db-validation-2026-09-18.md).

Revision `47058d2` then passed a separate three-host HTTPS campaign. A client
used private VPC addresses to reach two nginx-terminated reference providers,
explicitly proved TLS 1.2 and TLS 1.3 with the expected mTLS identity, and
required a bearer credential. Wrong-CA, missing-client-certificate and
wrong-bearer attachments failed before daemon readiness. Provider A and B
were stopped separately while writes continued; with both down, the ledger
stayed at 24 until B returned. The run reached 32 exact ACK rows, retained them
through a Maki restart, passed deep checking with zero invalid slots, and
deleted all three VMs. See the
[cross-host TLS reference-provider validation](cross-host-tls-provider-validation-2026-09-19.md).

Revision `5f50354` then passed a checksummed PostgreSQL 15 campaign on another
disposable GCE VM. After 16 exact ACK rows, a cgroup-wide postmaster `SIGKILL`
interrupted four pgbench clients. Automatic WAL recovery produced a distinct
postmaster, preserved the whole ACK prefix, and passed `pg_amcheck`. The cluster
advanced to 32 rows, retained them through a packaged Maki lifecycle restart,
then reached 48 rows. Four `pg_amcheck` runs were clean. See the
[PostgreSQL process-crash validation](postgresql-crash-validation-2026-09-18.md).

Revision `3cac300` then passed a generated Debian package, topology, and
migration campaign. A clean pre-upgrade package install ran two simultaneous
kernel NBD/LVM/XFS volumes, including a second LV mapping, before the current
package upgrade preserved configuration, credentials and both SQLite hashes.
A corrupt DB-native restore was rejected before retry, a clean legacy-v1
old-reader backup restored exactly into v2 while the current writer refused the
unchanged v1 metadata, and multi-mapping plus foreign-backend cleanup both
failed closed before mutation. See the
[package, topology, and migration validation](package-topology-migration-validation-2026-09-19.md).

Revision `bdb9113` then passed a separate three-host credential-rotation and
new-key migration campaign. An existing K1 volume was stopped, detached and
drained before its bearer token and mTLS client identity/CA changed; the old
credentials were refused, both peers validated the new credentials, and the
superblock/canary hashes stayed unchanged. A DB-native SQLite backup then
restored into a distinct K2 volume, and an isolated K1 wrong-key canary was
refused with unchanged superblock/canary hashes. The 24 exact external ACK rows
survived a lifecycle restart.
Both volumes passed final deep checking with zero invalid slots, and all three
VMs and disks were deleted. See the
[credential rotation and key migration validation](credential-rotation-key-migration-validation-2026-09-19.md).

Revision `da89ae3` then passed a four-host stopped server-CA and endpoint
rotation campaign. Mixed old/new server leaves worked with overlapping private
roots; both peers then moved to the new CA before old trust was removed.
Correct-root HTTP 204 and wrong-root curl 60 controls accompanied failed actual
NBD negotiations in both trust directions. Replacing A's address with C's
distinct IP while A's nginx listener was stopped preserved the key/profile,
volume identity, superblock/canary hashes, and exact SQLite data. C/B reached
48 ACK rows through another restart. The negative oracle was corrected in TDD
to distinguish an early socket inode from readiness and an outer operation
deadline from an explicit TLS error. See the
[server CA and endpoint rotation validation](server-ca-endpoint-rotation-validation-2026-09-19.md).

| Requirement | Target | Status | Evidence |
|---|---:|---|---|
| Randomized model operations | 100,000+ | Pass | 110,000-operation block-model gate |
| Crash/recovery cycles | 10,000+ | Partial | 10,000 in-process seeded runs plus native FLUSH/FUA SIGKILL regressions; not 10,000 OS process crashes |
| Endpoint failure cycles | 10,000+ | Pass in simulation | Deterministic dispatcher cycles with no failed requests or permit leaks |
| Circuit-breaker cycles | 10,000+ | Pass in simulation | Complete open, half-open, close, and failed-probe reopen cycles |
| Parser fuzzing | 24 CPU-hours per target | Partial | `review_fuzz.rs` (exhaustive single-bit-flip sweep of every on-disk decoder, ~30,000 seeded mutations, config and URL fuzz) and `review_fuzz_transport.rs` (random provider responses through the HTTP parse path); coverage-guided `cargo-fuzz` targets in `fuzz/` (`format_decoders`, `journal_scan`, `config_parse`, `endpoint_url`, `probe_parsers`) — a 60 s-per-target smoke run did ~62M iterations with no crash; a 24 CPU-hour-per-target corpus run remains outstanding |
| Userspace nbdkit/libnbd/fio | Functional smoke | Pass on Debian 12/KVM | ABI probe, byte-identical copy, and CRC32C fio verification |
| Kernel NBD, LVM, XFS, and fio | Functional smoke and repeated server crash | Pass on Debian 12 GCE | `448c0b2` ran two automatic nbdkit SIGKILL recoveries and one open-target cleanup failure/retry through `/dev/nbd15` and pinned single-PV/LV storage |
| Packaged systemd lifecycle | Functional ordering and failure gates | Pass for one Debian 12 GCE topology | Installed shipped templates recreated the real daemon, attachment, workload, and Docker container twice, withheld restart on open-LV cleanup failure, then recovered on explicit retry |
| Debian package install and upgrade | Clean install, stopped-volume upgrade, and exact reattach | Pass for one generated-package Debian 12 profile | Pre-upgrade and current packages preserved volume/attach configs, all token hashes and two SQLite logical hashes, did not auto-start volumes, and reattached both after upgrade |
| Multi-mapping and foreign-backend refusal | Refuse ambiguous fallback and changed backend identity before mutation | Pass for one two-LV and one same-NBD foreign-backend topology | Packaged recovery preserved both mappings and proof after daemon death; cleanup preserved a foreign backend identifier and trusted record until explicit disconnect |
| DB-native and legacy-v1 migration | Reject corrupt restore; old-reader backup into a fresh v2 volume | Pass for stopped-source SQLite profiles | Corrupt native restore failed before clean retry; current writer refused byte-stable v1 superblocks and the old-reader backup restored with the exact logical hash |
| Docker bind lifecycle | Functional rebind and start gate | Pass for one Debian 12 GCE topology | Four distinct default-`rprivate` containers preserved the exact external ACK prefix; the failed cleanup created no replacement container |
| Fresh-host backing restore | Graceful backup, new host, continued writes and restart | Pass for one unchanged v2/local-provider/SQLite topology | Distinct source and target VMs recovered 32 exact ACK rows, advanced to 48, retained 48 after restart, and passed SQLite integrity and offline checks |
| Remote HTTP provider database faults | Single-endpoint failover plus total-provider outage | Pass for one loopback two-provider/SQLite topology | A and B separately served after peer loss; a 4,094 ms total outage held the ledger at 24, then resumed exactly one commit and reached 32 exact rows before and after restart |
| Cross-host HTTPS reference provider | TLS/mTLS/auth refusal, host failover, and total-provider outage | Pass for one three-host private-VPC/SQLite topology | TLS 1.2 and 1.3 health gates recorded the client subject; wrong CA, absent client identity and wrong bearer failed closed; 32 ACK rows survived provider-VM stop/start and Maki restart |
| Stopped credentials and new-key migration | Replace bearer and mTLS client identity without changing the existing key; restore into a distinct provider key/volume | Pass for one three-host private-VPC/reference-provider/SQLite topology | Old bearer and client identity were refused, both peers validated the replacements, existing superblock/canary hashes matched, K1/K2 fingerprints and volume UUIDs differed, a wrong-key canary kept those hashes unchanged, and 24 ACK rows survived DB-native restore and restart |
| Server CA and endpoint-address rotation | Overlap private roots, replace leaves, remove old trust, then replace an address with the same key/profile | Pass for one four-host private-VPC/reference-provider/SQLite topology | Both wrong-trust directions refused real NBD negotiation; A/B changed to C/B with A's listener stopped; both peers validated, superblock/canary hashes matched across each attach, and 48 ACK rows survived restart |
| PostgreSQL process crash | Checksums, WAL recovery, logical check, and storage restart | Pass for one PostgreSQL 15.19/scale-3 topology | Postmaster SIGKILL interrupted pgbench after 590 transactions; WAL recovery preserved 16 ACK rows, four `pg_amcheck` runs passed, and the cluster retained 32 rows through Maki restart before reaching 48 |
| Real databases | Required | Partial | SQLite WAL and one short checksummed PostgreSQL 15 profile passed scoped campaigns; production PostgreSQL profiles, ClickHouse, MinIO, and application recovery contracts remain open |
| cgroup resource faults | Target-specific | Partial | Real AES userspace NBD passed CPU throttling, freeze/resume, SIGKILL and workload OOM readback. Four later constrained recoveries passed at 48/64 MiB; process `VmHWM` stayed at or below 11,415,552 bytes, while only 64 MiB avoided cgroup max events |
| Physical checkpoint-space reservation | Linux filesystem ENOSPC before ACK | Pass on one Debian 12/ext4/GCE PD topology | A 4,608-byte slot owned 8,192 allocated bytes before FUA ACK; with zero free bytes, the next FUA returned ENOSPC without changing sequence, journal bytes, or slot allocation, then retried and survived restart |
| Firecracker guest abrupt loss | Target-specific | Partial | 20 alternating FLUSH/FUA ACKs survived VMM SIGKILL and cold-boot authenticated readback on GCP nested KVM; L1 kernel and storage caches remained live |
| GCE whole-instance reset | Target-specific | Pass on disposable Debian 12 GCE | 10 alternating FLUSH/FUA generations and 160 acknowledged write versions survived hard instance resets; 11 unique boots retained the same instance, data disk, filesystem UUID and authenticated readbacks |
| QEMU hard power loss | 300+ cuts | Open | Simulation is not hardware evidence |
| Mixed workload | 72 hours | Open | Dedicated hardware run not recorded |

The detailed Debian run is preserved in the
[rootless Linux validation report](native-linux-validation-2026-09-02.md). The
later [privileged Linux validation report](privileged-linux-validation.md)
records the kernel NBD, LVM, XFS, raw and filesystem fio, privilege, helper, and
SQLite results, including the installed-systemd combined campaign and its
limits. The disposable instances and disks were deleted afterward, and fresh
name-scoped queries found no remaining `maki-*` resources.
The [September 12 fault report](cgroup-fault-validation-2026-09-12.md) records
the new native process and cgroup executions, external ACK evidence, reproduction
commands and the unresolved restart limit. The host was Debian, so no WSL
shutdown was executed.
The [Firecracker report](firecracker-validation-2026-09-12.md) records the
separate guest-kernel/page-cache loss campaign, its host-fsynced ACK ledger,
image hashes, cold-boot readbacks, and the boundary at the surviving L1 host.
The [GCE reset report](gce-reset-validation-2026-09-13.md) records the later
whole-workload-VM hard reset campaign, stable resource identities, shutdown
witness, Cloud Audit Log entries, authenticated readbacks, and cloud cleanup.
The [fresh-host restore report](fresh-host-restore-validation-2026-09-17.md)
records the later graceful export, source deletion, new-host restore, continued
writes, restart readback, harness corrections and cloud cleanup.
The [remote-provider database report](remote-provider-db-validation-2026-09-18.md)
records the two authenticated HTTP endpoints, per-endpoint failure, total
provider outage, SQLite ACK/hash oracle, lifecycle restart, harness correction,
and deletion of both attempted VMs and disks.
The [cross-host TLS reference-provider report](cross-host-tls-provider-validation-2026-09-19.md)
records private-VPC TLS 1.2/1.3, mTLS and bearer controls, provider-host
stop/start, SQLite ACK/hash readback, final deep checking, immutable harness
inputs, and deletion of all three VMs and disks.
The [PostgreSQL crash report](postgresql-crash-validation-2026-09-18.md)
records active durability settings, pgbench interruption, WAL redo, postmaster
replacement, four logical checks, ACK/hash readback, Maki lifecycle restart,
and deletion of the disposable VM and disk.
The [physical reservation report](physical-reservation-validation-2026-09-18.md)
records real ext4 block allocation before FUA acknowledgement, a zero-free-space
ENOSPC refusal with unchanged journal state, retry, restart readback, offline
checking, and deletion of the disposable VM and separate data disk.
The [package, topology, and migration report](package-topology-migration-validation-2026-09-19.md)
records clean install and upgrade, simultaneous volumes with a sidecar LV,
fail-closed multi-mapping and foreign-backend cleanup, SQLite DB-native and
legacy-v1 migration, final deep checks, and deletion of the disposable VM and
disk.
The [credential rotation and key migration report](credential-rotation-key-migration-validation-2026-09-19.md)
records the stopped bearer/mTLS-client transition, old-credential refusal,
unchanged existing-volume superblock/canary hashes, distinct provider-key
fingerprints and volume UUIDs, wrong-key canary refusal, DB-native cutover and
restart readback, final deep checks, immutable harness inputs, and deletion of
all three VMs and disks.

The [server CA and endpoint rotation report](server-ca-endpoint-rotation-validation-2026-09-19.md)
records private-CA overlap/removal, fresh server-leaf fingerprints, paired trust
controls and actual NBD refusal, same-key replacement on a distinct provider IP,
unchanged volume identity, and 48-row restart readback. It also preserves the
two invalid harness attempts and their corrections. It does not qualify hot
reload, public-CA revocation, or C-only availability while B remains configured.

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

The opt-in GCE reset controller runs outside the disposable workload VM. It
fsyncs each validated ACK to its own ledger, then invokes only
`gcloud compute instances reset`. It requires the old SSH session to die and a
globally new boot ID to appear. The guest systemd `ExecStop` witness must
remain absent.
This removes the workload VM's RAM, kernel, and page cache, while the Persistent
Disk service and physical storage path stay operational. It is whole-VM reset
evidence rather than physical power-loss evidence.

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
- Run the actual Maki daemon, kernel NBD/LVM/XFS, packaged systemd recovery, and
  DB/container ACK oracle together in one crash/recovery campaign.
- Vendor endpoint conformance with production mapping and credentials.
- Repeat the scoped bearer/mTLS-client, server-certificate/private-CA, and
  same-key/profile endpoint-address rotation procedures against the selected
  commercial vendor and target network, including shared-client coordination,
  rollback, and failures at each transition.
- Real SQLite and PostgreSQL workloads before broader database qualification.
- Repeat the unchanged-backing fresh-host restore on each supported package and
  distribution, and separately exercise DB-native backup or logical migration
  with credentials protected outside the general backup.
- Repeat GCE reset qualification on the selected deployment image and storage
  class; run QEMU and bare-metal power cuts with an independent acknowledgement
  ledger for the stronger storage-failure tiers.
- Long-duration (24 CPU-hour-per-target) `cargo-fuzz` corpus runs (the
  targets exist in `fuzz/`; only short smoke runs have been done) and
  long-duration provider and mixed-I/O soaks.

These checks are privileged, destructive, externally credentialed, or
long-running. Run them only in explicitly authorized environments.
