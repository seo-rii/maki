# Independent Code and Architecture Review of Maki

- Review date: 2026-09-02
- Target: user-provided `maki-main.zip`
- Review scope: architecture, storage consistency, cryptographic provider boundaries, crash recovery, remote transports, privilege separation, operational control plane, configuration and packaging, and testing strategy
- Conclusion: **Maki is technically ambitious and has strong design assets, but deploying it in production with real data is currently a No-Go.**

---

## 1. Executive Summary

Maki aims to provide a crash-consistent, bounded, privilege-separated storage layer that turns local or remote cryptographic providers into an nbdkit/NBD-backed block device. Compared with a typical early-stage project, three aspects stand out in particular:

1. `SPEC.md` defines the product in terms of **invariants and failure semantics**, rather than merely listing features.
2. The codebase is designed for verification, with crashable backing storage, a deterministic clock, failpoints, a reference model, and database simulators.
3. Cryptography, storage, NBD integration, and privileged helper logic are separated into crates, so the intended architecture is visible in the code structure.

However, cross-checking the actual state transitions and runtime paths uncovered several issues that currently block a production release:

- **A wrong key or cryptographic provider is not reliably rejected at attach time.** With AES-XTS in particular, this can result in silently returning incorrect plaintext.
- **The ordering between automatic journal rollover and overlay promotion can cause a previously durable version of the same unit to be omitted from a checkpoint.** This can lead to acknowledged-write loss.
- **On allocation-map A/B update retries, a directory fsync failure can occur after the dirty flag has already been cleared.** A retry may then skip the required metadata synchronization and later delete the journal.
- Automatic checkpointing, hard journal limits, and emergency free-space controls are not actually wired into the runtime, so the core “bounded” guarantee does not hold during long-running sustained writes.
- The control socket and mount-identity verification exist as implementation fragments, but are not connected to the real daemon/helper execution paths.

Accordingly, I would rate Maki highly as a **design- and verification-oriented advanced alpha prototype**, but it is **not yet suitable as production block storage for important data**.

---

## 2. Scope of Verification and Limitations

### What was inspected directly

Static inspection produced the following counts:

| Item | Value |
|---|---:|
| Cargo workspace packages | 17 |
| Rust files | 99 |
| Total Rust lines | 19,081 |
| `src` lines | 11,606 |
| `tests` lines | 7,475 |
| `#[test]` / `#[tokio::test]` attributes | 227 |
| Separate test files | 26 |
| `todo!` / `unimplemented!` / TODO / FIXME | 0 found by static search |

The archive contains `Cargo.lock`, but does not contain `.git`, `LICENSE`, or a `rust-toolchain.toml` / `rust-version`. Therefore, the exact Git revision referenced in the documentation cannot be independently matched to the supplied archive.

### What could not be executed independently

The review environment did not have `cargo` or `rustc` installed, so **I did not independently compile the project or execute its Rust test suite**. The defects below are based on static analysis of code paths and state transitions. Where test behavior is projected rather than executed, it is explicitly labeled as an **Expected result**.

The project’s own `docs/native-linux-validation-2026-09-02.md` records the following for revision `8f8b13d...`:

- Default workspace: 200 passed, 0 failed, 5 ignored
- Extended phase gates: 5/5 passed
- `fmt` and strict Clippy passed
- Debian 12 nbdkit ABI probe passed
- Rootless libnbd/fio path passed

The same report also states that the following were still incomplete: kernel `/dev/nbd` + filesystem validation, installed systemd service and real privilege enforcement, vendor endpoints, real databases, QEMU/bare-metal power-cut tests, and 24/72-hour soak and fuzz testing. That limitation is stated clearly and appropriately, but these successful test records are still **secondary evidence supplied by the repository**, not results reproduced in this review environment.

---

## 3. Ratings

| Area | Score | Assessment |
|---|---:|---|
| Problem definition and architecture | 8.5/10 | Goals, boundaries, and invariants are unusually clear. |
| Testability and verification design | 8.5/10 | Crash models, failpoints, and reference models are strong. |
| Core storage correctness | 4.0/10 | P0 defects remain that can lead to acknowledged-data loss. |
| Cryptography and security | 4.0/10 | Primitive implementations are generally sound, but attach-time key/provider validation and release defaults are unsafe. |
| Operability and observability | 3.5/10 | Automatic checkpointing and the control plane are not connected to the real daemon path. |
| Release and packaging hygiene | 5.0/10 | CI and documentation are good, but the default fake provider, missing license file, and incomplete live gates remain concerns. |
| Production readiness | 2.5/10 | **No-Go** in the current state. |

Overall, I would place the project at roughly **6/10 as a strong research/alpha implementation**. The relatively low production score is not a judgment that the code quality is poor. It reflects the much higher standard required for a block-storage system where acknowledged data must not be lost.

---

## 4. What Is Done Well

### 4.1 The specification is written as an engineering contract

`SPEC.md` defines requirements such as no plaintext at rest, bounded queues, checkpointing only durable journal data, rejecting crypto-profile mismatches on attach, never returning corrupted ciphertext as plaintext, and refusing to start the database when the expected secure mount is not present. Defining failure semantics first is a major strength for a storage-system project.

### 4.2 Crate boundaries are clear

- `maki-format`: on-disk format and configuration
- `maki-backing`: storage backend abstractions
- `maki-core`: journal, overlay, checkpointing, and block engine
- `maki-crypto*`: cryptographic contracts and transport-specific implementations
- `maki-nbdkit`: nbdkit ABI and daemon assembly
- `maki-control`: control protocol
- `maki-privileged`: planning and verification in the root helper

In particular, the fact that the root helper does not depend on the cryptography crates is directionally correct for privilege separation.

### 4.3 The cryptographic provider boundary is defensive

`CheckedProvider` validates result count, ordering, unit index, and plaintext/ciphertext sizes on every call (`crates/maki-crypto/src/checked.rs:37-129`). The design does not blindly trust provider implementations, which is a good boundary discipline.

The local AES-256-GCM-SIV implementation includes the volume UUID, unit index, format version, and compatibility ID in AAD (`crates/maki-crypto-local/src/gcm_siv.rs:66-72`). This correctly causes authentication failure if ciphertext is moved across units, volumes, or incompatible profiles.

`SecretBuffer` also avoids implementing `Clone`, requires explicit duplication, zeroizes on drop, and hides contents from `Debug` output (`crates/maki-crypto/src/secret.rs`). This is not complete memory protection, but it is a good API baseline for handling sensitive material.

### 4.4 Concurrency and cache invariants are comparatively well designed

Writes and RMW operations to the same unit are serialized with per-unit locks, while encryption occurs outside the global volume write lock (`crates/maki-core/src/engine.rs:329-411`). The read cache is tied to `(unit, write_sequence)`, reducing the risk of returning stale plaintext after a concurrent overwrite.

### 4.5 The test infrastructure is significantly stronger than in a typical prototype

Crashable backing storage, failpoints, randomized state models, database simulators, and power-loss simulation are all strong positives. The important point is not merely that the repository contains many tests; it is that the architecture is **designed to be testable under failure**. The defects identified in this review should be reproducible with relatively small regression tests on top of the existing infrastructure.

### 4.6 The FFI boundary and configuration parser have good baseline defenses

NBD callbacks prevent Rust panics from crossing the FFI boundary and convert them to EIO (`crates/maki-nbdkit/src/adapter.rs:109-126`). Configuration structs make broad use of `deny_unknown_fields`, and literal secrets in sensitive headers are rejected. Fixed-size format handling, CRC checks, and checked arithmetic are also generally well implemented.

### 4.7 The validation report does not overclaim

The project’s own Linux validation report distinguishes between what was and was not tested, and explicitly warns against treating rootless NBD/fio success as equivalent to kernel NBD, filesystem, or power-cut qualification. That is the right attitude for release documentation.

---

## 5. P0 Defects Requiring Immediate Fixes

## M-001. A wrong key or provider is not rejected at attach time

**Severity: Critical**  
**Confidence: High**

The superblock stores `provider_type`, `crypto_compatibility_id`, and `key_identity` (`crates/maki-format/src/superblock.rs:23-31`). The creation path also records the configured provider and key name (`crates/maki-nbdkit/src/daemon.rs:440-462`).

However, the attach path initializes `CryptoContext` with only the volume UUID, format version, and compatibility ID (`crates/maki-core/src/engine.rs:134-162`), and then performs a self-test that encrypts a fresh test pattern with the current provider and decrypts it with the same provider (`crates/maki-crypto/src/selftest.rs:38-87`). There is no comparison against the persisted `provider_type` or `key_identity`.

As a result, loading a different key while keeping the same compatibility ID can still pass the fresh-data round-trip self-test.

- With GCM-SIV, attach can succeed and the first read of existing data may later fail authentication with EIO.
- With XTS, there is no integrity authentication, so existing ciphertext can be decrypted under the wrong key and **garbage plaintext may be returned without an error**. The XTS implementation itself documents this limitation (`crates/maki-crypto-local/src/xts.rs:1-9, 84-102`).

This violates the specification’s requirement that a crypto-profile mismatch prevent attach.

### Recommended fix

1. Compare a normalized provider identifier and key identity against the values persisted in the superblock.
2. Do not rely on key-name equality alone; aliases can refer to the same key or the same name can refer to changed material.
3. Store a **provider/key-bound encrypted canary** when the volume is created.
4. During attach, decrypt the canary with the current provider and verify a fixed domain-separated plaintext value.
5. Require this canary validation for XTS; preferably isolate XTS behind an explicit legacy or low-assurance mode.

### Required regression test

`attach_rejects_wrong_key_same_compatibility_id`

- Create the volume with key A, write data, then flush/checkpoint.
- Attach with the same provider and compatibility ID, but key B.
- Expected behavior: attach fails immediately.
- **Expected result with the current implementation:** attach itself succeeds. GCM-SIV should fail only when pre-existing data is read, while XTS may return incorrect plaintext.

---

## M-002. Automatic segment rollover can drop a durable overwrite from the overlay

**Severity: Critical**  
**Confidence: High**

`JournalWriter::append` calls `roll()` before appending when the new record would exceed the segment size (`crates/maki-core/src/journal.rs:171-181`). `roll()` synchronizes the current active segment with `sync_data` and advances `durable_sequence` (`journal.rs:112-125`).

The problem is the ordering in `Volume::write_ct`:

1. `journal.append`
2. `overlay.publish` the new version
3. `overlay.promote` up to the current durable boundary

(`crates/maki-core/src/volume.rs:133-145`)

The overlay retains only one `latest` value per unit. Publishing a new value for the same unit removes the previous `latest` value (`crates/maki-core/src/overlay.rs:50-64`). Promotion only creates a durable copy when the target sequence is still the `entry.latest` sequence (`overlay.rs:73-98`).

### Loss scenario

1. Unit U at sequence N exists in the active segment and has not yet been synchronized.
2. Another write to U, sequence N+1, causes automatic rollover because the segment is full.
3. The rollover makes N durable and advances `durable_sequence` to N.
4. N+1 is then published, removing N from `latest`.
5. `promote(N)` can no longer find N because `latest.sequence == N+1`.
6. A checkpoint can advance to boundary N and delete the sealed segment containing N.
7. If the process crashes while N+1 is still volatile, N+1 disappears and N was never copied into the base slot.

The result is loss of N even though N had already become durable.

The existing `segments_roll_and_survive_crash` test does not catch this exact state transition because it performs a final flush before validating recovery.

### Recommended fix

The safest design is for the overlay to retain pre-promotion versions by sequence. A smaller patch could promote any sequence newly made durable by rollover **before publishing the next version**. The state machine should be modeled explicitly across append failure and FUA sync failure as well.

### Required regression test

`auto_roll_preserves_previous_durable_overwrite`

- Use a very small segment that holds only one or two records.
- Repeatedly overwrite the same unit.
- Cause the next overwrite to trigger automatic rollover.
- Run checkpoint without an explicit flush.
- Simulate a crash that loses the active segment.
- The most recent durable version must be recovered.

**Expected result:** before the fix, the previous durable version can be lost; after the fix, it must survive.

---

## M-003. Allocation-map retry can skip the required directory fsync

**Severity: Critical**  
**Confidence: High**

`persist_allocations` writes a dirty allocation map to the A/B store, immediately clears `dirty_alloc=false`, and only fsyncs the data directory after the loop completes (`crates/maki-core/src/store.rs:201-218`).

### Loss scenario

1. A new shard already has a durable, empty allocation map A.
2. The first checkpoint writes and synchronizes slot data.
3. The allocation bit is set and a new A/B side B is written and fdatasynced.
4. The final `sync_dir(data)` fails.
5. The checkpoint returns an error, but `dirty_alloc` has already been cleared.
6. On retry, the allocation bit is already 1 in memory, so `mark_allocated` does not mark the shard dirty again (`store.rs:183-190`).
7. The second checkpoint can skip allocation metadata and data-directory fsync, advance checkpoint state, and later delete the journal.
8. After a crash, the newly created B dirent can disappear, leaving durable A with bit 0 and causing the slot to be classified as unwritten zero.

Thus, a normal “failure followed by retry” sequence can lead to acknowledged-data loss.

### Recommended fix

- Collect the dirty shard set separately.
- Complete all A/B writes and fdatasync calls.
- Fsync the containing directory.
- Clear dirty flags **only after** that directory fsync succeeds.
- Preserve dirty state if the directory fsync fails.

### Required regression test

`checkpoint_retry_keeps_allocation_dirent_durable`

- Allow the allocation-side write to succeed but inject failure in the final data-directory fsync.
- Retry checkpoint in the same process.
- Simulate a namespace crash and recover.
- The data must not become zero.

**Expected result:** with the current implementation, data can be lost if the B-side dirent disappears in the crash.

---

## 6. Production-Blocking Operational and Security Issues

## M-004. There is no automatic checkpointing, and journal/memory bound settings are not enforced

Production call sites for `checkpoint()` appear to be limited to explicit API calls, adapter shutdown, and the currently disconnected control backend. There is no background checkpoint worker driven by write volume or elapsed time.

The following settings also appear unused in the runtime:

- `backing.journal_max_bytes`
- `backing.checkpoint_reserve_bytes`
- `backing.journal_emergency_reserve_bytes`
- `limits.max_journal_pending_bytes`

Under sustained normal writes, sealed journal segments can continue accumulating and the overlay can grow without an effective bound. A clean-shutdown checkpoint does not protect long-running operation from ENOSPC or OOM. This directly undermines the project’s “bounded” guarantee.

### Recommended fix

- Add a high/low-watermark checkpoint worker.
- Check actual free space and emergency reserve before journal append.
- Apply a hard admission failure when the journal reaches its limit.
- If checkpoint failures persist, transition the volume into a defined degraded, read-only, or failed state.
- Run 24/72-hour sustained-write soak tests with injected checkpoint faults.

---

## M-005. The control plane exists in code but is not started by the actual daemon

`maki-control::serve_uds` and `EngineControlBackend` are defined, but no production construction or invocation site was found. The nbdkit plugin only lazy-opens an `NbdAdapter` (`crates/maki-nbdkit/src/plugin.rs:28-45`), while the CLI attempts to connect to `/run/maki/<volume>/control.sock` (`bins/maki/src/main.rs:122-160`).

Therefore, the packaged runtime currently has no control socket through which `status`, `metrics`, `checkpoint`, or `reload` can operate.

Worse, `reload("retry" | "circuit-breaker" | "batch" | "limits")` returns `Ok(())` without applying any changes (`crates/maki-nbdkit/src/control.rs:60-70`). Silent success is more dangerous than an explicit unsupported error.

### Recommended fix

- Spawn the UDS server as part of adapter/runtime initialization and bind its lifetime to daemon shutdown.
- Return explicit `unsupported` / `not applied` errors for reload sections that are not actually implemented.
- Expose effective-configuration generation or revision in `status` before and after reload.

---

## M-006. Secure mount-identity verification is a no-op in the real execution path

The planner creates a `VerifyMountIdentity` step (`crates/maki-privileged/src/plan.rs:136-160`), but the corresponding executor match arm performs no work (`crates/maki-privileged/src/exec.rs:53-56`). A comment says the wiring lives in the `maki-attach` binary, yet the binary simply builds a plan and calls `exec::execute` (`bins/maki-attach/src/main.rs:68-75`). The pure verification function appears to be used only in tests.

In addition, the default value for `--uuid` is an empty string. The systemd unit runs only `maki-attach attach --volume %i`, so it does not pass an expected UUID into the verification path.

Consequently, the helper can report attach success even when the wrong XFS/LV/NBD device is mounted or the sentinel is absent. The specification’s requirement that the database not start without the expected secure mount is therefore not enforced.

### Recommended fix

- Read expected NBD device, filesystem UUID, Maki UUID, and mountpoint from a root-owned volume configuration.
- Collect and verify `/proc/self/mountinfo`, `blkid`, sysfs NBD state, the sentinel, and a read/write probe.
- Roll back mount, LVM, and NBD operations in reverse order if verification fails.
- Make the dependent database service strongly depend on a verification-success unit.

---

## M-007. Recovery can misclassify some durable corruption as a torn tail

### 7.1 A full-sized corrupt final segment header is deleted unconditionally

If the final journal segment header fails to decode, the code treats it as a crash during segment creation and deletes it even when the file length is at least a complete header (`crates/maki-core/src/recovery.rs:108-120`). A file shorter than the header can reasonably be treated as incomplete creation, but a full header with bad magic or CRC can also indicate durable corruption. The safer behavior is fail-closed.

### 7.2 The gap between checkpoint boundary and the first surviving segment is not verified

Continuity is checked only between surviving segments (`recovery.rs:161-169`). If the earliest uncheckpointed segment disappears, the first remaining segment becomes the new baseline and the loss may not be detected. Recovery should verify that journal history connects correctly to `checkpoint_sequence + 1`.

### 7.3 A corrupt record header in the final segment is treated as a torn tail

If record-header parsing fails, the scanner returns `TornTail` without attempting to determine whether valid durable records exist later in the segment (`crates/maki-format/src/journal.rs:100-108`). If a header in the middle of the final segment is corrupted, later durable records may be truncated from replay. The current “middle corruption” test covers payload-CRC corruption, not this header path.

### 7.4 Recovery allocates the entire journal body based on file length

Recovery allocates the entire segment body into a `Vec` without a runtime segment-size cap (`recovery.rs:138-140`). A corrupt or intentionally huge sparse segment can trigger OOM during attach.

### Recommended fix

- Treat a full-sized corrupt final header as fatal corruption.
- Verify that the first replay sequence bridges exactly from the checkpoint boundary.
- Use a footer/commit marker or bounded resynchronization to distinguish middle corruption from a true torn tail.
- Use a streaming scanner and enforce a hard segment-size cap.

---

## M-008. The default release feature includes a non-cryptographic fake provider

The default feature of `maki-nbdkit` is `fake-provider` (`crates/maki-nbdkit/Cargo.toml:11-14`). As a result, a normal `cargo build --release` produces a cdylib that accepts `provider="fake"`.

The fake provider uses a test-only XOR keystream and CRC (`crates/maki-test-support/src/fake_provider.rs:262-329`). The provider is clearly named “fake,” so accidental selection is not invisible, but a production storage product should not ship a non-cryptographic provider in the default release artifact.

### Recommended fix

- Set `default = []`.
- Enable the fake provider explicitly only in test/benchmark packages.
- Add release CI that verifies the fake provider cannot be selected.
- Separate development plugin artifacts from deployable artifacts at the packaging level.

---

## 7. Other High-Risk Issues

## M-009. The A/B metadata reader collapses all I/O errors into “invalid copy”

`AbStore::read_side` converts open/length/read/decode errors into `None` via `.ok()?` (`crates/maki-format/src/ab.rs:32-40`). This means transient I/O failures and permission errors are indistinguishable from a missing or CRC-invalid copy. If one side temporarily fails to read, an older copy can be selected; if both fail, checkpoint state defaults to zero (`crates/maki-core/src/recovery.rs:82-85`).

**Fix:** distinguish NotFound, torn/CRC-invalid, and hard I/O errors. Hard I/O should fail attach. On an initialized volume, require at least one valid checkpoint-state copy.

## M-010. Remote retry logic does not enforce `retry_safe` or an absolute deadline

Capabilities include `retry_safe`, but the dispatcher does not check it before retrying or failing over on Retryable, Throttled, or EndpointFatal errors (`crates/maki-crypto/src/endpoint.rs:188-267`). The WebSocket transport also performs one internal retry outside the dispatcher (`crates/maki-crypto-websocket/src/lib.rs:251-279`).

`bounded-error.max_operation_time` is converted into an approximate number of passes based on the initial delay rather than enforced as an absolute deadline (`crates/maki-nbdkit/src/daemon.rs:365-380`). Combined RPC timeouts and capped backoff can therefore exceed the configured wall-clock limit substantially. The retry budget also appears to be global to an EndpointSet, despite names/comments implying endpoint-local semantics.

**Fix:** use a monotonic absolute deadline, cancel RPCs based on remaining time, centralize retries, prohibit retry/failover for non-retry-safe providers unless an idempotency key exists, and maintain endpoint-local retry budgets.

## M-011. Endpoints that were not validated at startup can enter the normal serving pool

Cross-endpoint self-test is skipped when an endpoint is temporarily unavailable (`crates/maki-nbdkit/src/daemon.rs:319-359`). That endpoint is still inserted into the EndpointSet with a fresh closed circuit breaker (`crates/maki-crypto/src/endpoint.rs:95-128`). If it later recovers, traffic can reach it before interchangeability has ever been verified.

**Fix:** quarantine endpoints whose cross-decrypt validation has not completed, and promote them into the serving pool only after validation succeeds using the actual volume context.

## M-012. Reordered batch results are not reliably detected in WebSocket and some HTTP paths

The WebSocket response item contains only data, not the unit index (`crates/maki-crypto-websocket/src/lib.rs:4-8`). The parser validates only the item count and then zips returned data with the caller’s unit labels (`lib.rs:281-369`). If the provider reorders results, the outer `CheckedProvider` sees the already reattached labels and therefore cannot detect the mismatch.

HTTP batch mode similarly validates a unit echo only when `item_index_path` is configured; otherwise it relies on positional zip semantics (`crates/maki-crypto-http/src/lib.rs:418-427, 619-651`).

**Fix:** require every batch result to echo both a request ID and unit index, and reject duplicates, omissions, and reordering mismatches.

## M-013. Configuration validation is incomplete, and several settings are effectively placebo

Current validation checks schema/version/name/provider/geometry, some capabilities, and literal-secret handling, but does not fully validate conditions such as:

- count/byte limits > 0
- finite and nonnegative retry ratios and probe rates
- `initial_delay <= max_delay`
- internally consistent circuit-breaker thresholds
- batch targets/maxima relative to unit size
- provider-specific required sections
- TLS certificate/key pairing and file readability
- URL scheme and host restrictions

For example, a max item count of zero can cause `DualSemaphore::acquire` to wait forever for a permit (`crates/maki-crypto/src/flow.rs:25-60`). A value such as `minimum_probe_rate=nan` can reach `Duration::from_secs_f64(NaN)` and panic (`crates/maki-crypto/src/retry.rs:72-87`). The validator accepts `keyring`, while the daemon resolver implements only env/file/credential sources.

The following settings also appear to be parsed without being connected to their advertised runtime guarantees:

- `limits.max_ciphertext_bytes`
- `limits.max_pending_crypto_items/bytes`
- `limits.max_journal_pending_bytes`
- `security.memory_lock_mode`, `disable_core_dump`, `madv_dontdump`, `require_secure_swap_policy`
- `cache.lock_memory`
- `control.group`
- `crypto.batch.target_items/target_bytes/max_wait`
- TLS `client_key`, `server_name`

Unsupported settings should be rejected at validation time rather than silently accepted.

## M-014. The supplied production sample is insufficient for remote HTTP attach

`packaging/examples/postgres-prod.toml` specifies the endpoint but does not include `[crypto.http.encrypt]` or `[crypto.http.decrypt]` mappings. The HTTP provider constructor requires both sections (`crates/maki-crypto-http/src/lib.rs:547-556`). Configuration validation does not detect the omission, so volume creation can succeed while attach later fails.

A production sample is effectively executable documentation and should be validated in CI through parse, create, and provider construction.

## M-015. Production WebSocket/gRPC transports do not use TLS

WebSocket accepts only `ws://`, and gRPC only `http://`; TLS configuration is rejected for those transports (`crates/maki-nbdkit/src/daemon.rs:152-259`). There is also no enforced loopback- or Unix-only restriction. A user can therefore configure a remote host and send plaintext block data over the network.

For HTTP TLS, failures to read CA/certificate files are converted through `.ok()` and execution continues with default trust/no client identity; separate `client_key` and `server_name` settings are not applied (`crates/maki-crypto-http/src/lib.rs:581-590`).

**Fix:** restrict non-TLS transports explicitly to loopback/Unix development mode, and treat certificate/key file errors as attach failures.

## M-016. Privileged attach does not support robust multi-volume allocation, rollback, or config-driven execution

The systemd unit passes only the volume name. CLI defaults use `/dev/nbd0`, LV `data`, `/srv/<volume>`, and an empty UUID for every volume (`bins/maki-attach/src/main.rs:34-43`). There is no free-NBD-device allocation/locking and no reverse rollback of prior NBD/LVM/mount steps if a later stage fails. The executor also hardcodes `nbd-client -b 4096` independently of the block size in the plan (`crates/maki-privileged/src/exec.rs:37-45`).

**Fix:** drive attach from root-owned configuration, allocate free devices atomically, canonicalize inputs and reject leading-dash arguments, implement transactional rollback, and wait for explicit readiness.

## M-017. Control-socket ACL expectations do not match systemd ownership

The UDS code applies chmod 0660 but does not chgrp the socket (`crates/maki-control/src/uds.rs:12-23`). The systemd service runs as `User=maki`, `Group=maki`, and the runtime directory is also owned by `maki`. `control.group=maki-admin` is not used. The resulting socket is therefore likely to be `maki:maki`, rather than the documented `maki:maki-admin`.

**Fix:** use systemd socket activation with `SocketGroup=maki-admin`, or perform safe `fchown` and configure supplementary groups explicitly.

## M-018. The offline checker is too shallow to justify “check passed”

`maki-check` validates the superblock, catalog, allocation-map size, data-file existence, and some orphan conditions (`crates/maki-format/src/checker.rs:27-113`). It does not verify:

- checkpoint-state A/B copies
- journal headers, record CRCs, or sequence continuity
- slot header/payload CRC for allocated slots
- slot unit index and sequence
- A/B generation divergence

Important corruption can therefore remain while the tool prints `check passed`.

A better design would separate fast and deep modes, with deep checking reusing the real recovery scanner and slot validator.

---

## 8. Recommended Remediation Order

### P0 — Before storing any real data

1. Introduce a provider/key-bound canary and reject wrong-key attach.
2. Fix journal-roll-to-overlay-promotion ordering and add a same-unit automatic-roll regression test.
3. Clear allocation-map dirty state only after successful directory fsync.
4. Make recovery fail-closed for first-sequence bridging, full corrupt headers, corrupt record headers, and oversized segments.
5. Remove the fake provider from default release features.

### P1 — Before a limited beta

6. Implement automatic checkpointing and real journal/free-space hard limits.
7. Connect the control UDS to the actual daemon lifecycle and remove no-op reload behavior.
8. Perform real mount-identity verification and rollback all prior steps on failure.
9. Strengthen configuration using typed enums and cross-field validation, and reject unsupported settings.
10. Add item identity, `retry_safe` enforcement, absolute deadlines, and endpoint quarantine to remote protocols.
11. Add TLS for WebSocket/gRPC or enforce a loopback-only policy.

### P2 — Before a release candidate

12. Complete a deep offline checker and the necessary metrics.
13. Validate systemd socket ACLs, sandboxing, and multi-volume NBD allocation on real systems.
14. Add CI coverage for `--locked`, `--all-features`, distro ABI probes, dependency audit/deny, fuzzing, and sanitizers.
15. Complete kernel NBD + XFS, real SQLite/PostgreSQL, QEMU hard-power-cut, 24/72-hour soak, and vendor endpoint qualification.

---

## 9. Regression Tests to Add First

1. `attach_rejects_wrong_key_same_compatibility_id`
2. `attach_rejects_provider_type_change_with_same_compatibility_id`
3. `auto_roll_preserves_previous_durable_overwrite`
4. `checkpoint_retry_keeps_allocation_dirent_durable`
5. `recovery_rejects_missing_first_uncheckpointed_segment`
6. `recovery_rejects_full_final_segment_bad_header`
7. `recovery_rejects_corrupt_middle_record_header_in_final_segment`
8. `recovery_rejects_oversized_segment_before_allocation`
9. `ws_rejects_reordered_batch_items`
10. `http_batch_requires_unit_echo`
11. `bounded_error_obeys_wall_clock_deadline`
12. `non_retry_safe_provider_is_never_retried`
13. `unverified_endpoint_never_enters_serving_pool`
14. `control_socket_is_created_and_grouped`
15. `reload_reports_not_applied_for_unsupported_section`
16. `attach_fails_and_rolls_back_on_mount_identity_mismatch`
17. `production_sample_builds_provider_successfully`
18. `sustained_writes_keep_journal_and_overlay_within_hard_limits`

---

## 10. Final Assessment

Maki’s greatest strength is not its code volume or feature count. It is the project’s **commitment to modeling failure and building a system that can be verified under failure**. That is a substantial advantage for a difficult block-storage project.

Its biggest weakness is the remaining gap between the invariants described in the documentation and the guarantees actually enforced on every runtime path. The three P0 defects are not merely unfinished features; they directly affect data safety. Likewise, automatic checkpointing, the control plane, and the privileged helper illustrate a recurring pattern where “the implementation exists” and “the product path actually enforces the guarantee” are not yet the same thing.

My current assessment is therefore:

- Research and architecture project: **Excellent**
- Test-oriented alpha implementation: **Strong**
- Limited experimental userspace NBD use: **Conditionally acceptable**
- Production block storage for important data: **No-Go at present**

Once the P0 issues are fixed and their regression tests are integrated into the existing crash/failpoint infrastructure, confidence in the system can improve substantially. The project already has a good verification foundation; this is not a system that needs to be redesigned from scratch. It is a system that needs to **close the remaining state-transition and operational-wiring gaps all the way through the real product path**.
