# Review remediation log

The independent code and architecture review dated 2026-09-02
(`maki-review-report.md`) rated Maki a strong alpha but a production **No-Go**,
and listed 18 findings (M-001 … M-018). This page tracks what has been done
about each one, in the review's own order, and records subsequent reviews and
their regression evidence.

Status values: **Fixed** (regression test landed and passes), **Partial**
(behaviour improved, remaining gap described), **Open**.

## Further reliability review (2026-09-05)

The next pass started from `aae6ee9` and reproduced seven more defects in the
journal, crypto scheduler, NBD boundary, detach recovery, and control socket.
Every fix followed RED (behavioral regression failure), implementation, and
GREEN. The journal changes preserve the on-disk format and use bounded scratch
space.

| Finding | Status | Result and regression evidence |
|---|---|---|
| BUG-010: detach cannot resume after partial completion | Fixed | Observe current mountinfo and sysfs before each step; skip verified completed work while retaining mount, VG, and live backend checks. Already-disconnected records can be retired only with no remaining mount, VG, NBD, or partition use. Fixture tests cover interrupted steps, foreign mounts/backends, escaped VG names, partition holders, and direct mounts. |
| BUG-011 / O-03: NBD limits are neither advertised nor enforced | Fixed | Publish the nbdkit `block_size` callback and reject invalid read/write lengths, ranges, and alignment before copying write plaintext or entering the engine. Configuration rejects minimum sizes above 64 KiB and maxima outside the NBD wire field. `review_nbd_limits.rs` verifies unchanged data on rejection, valid maximum I/O across reopen, and actual rootless NBD negotiation. |
| BUG-012: cancelled scheduler work retains payload, admission, or RPC slots | Fixed | Pending groups own payload and admission together. Closed callers are removed even behind a live blocked group; shared RPCs are cancelled only when their final caller leaves. Seven `review_scheduler_cancellation.rs` cases cover coalescing, slot waits, queued tails, cancellation of one group in a coalesced batch, and live peers. |
| BUG-013: bounded-error excludes time spent in the scheduler | Fixed | Forward the provider operation budget through wrappers and apply it around the entire scheduler submission. ManualClock tests cover admission, coalescing, waiting for a slot, and RPC under one deadline, with independent peer budgets and an unbounded stall control. |
| BUG-014: control socket bind changes permissions in unrelated threads | Fixed | Remove the process-wide umask override. Prepare the socket inside a mode-0700 directory, apply group/mode, then rename it to the public path. Concurrent mode-0700 directory creation previously produced mode 0600. Tests now preserve that mode, the existing path on failed group lookup, cleanup on failed publication, and Linux's maximum usable public path length. |
| BUG-020: a failed append leaves a corrupt tail after a shorter retry or roll | Fixed | Retain a tail-cleanup flag until truncation and sync succeed; remove unaccepted bytes before retrying, flushing, or sealing. `review_journal_retry.rs` injects a real partial BackingFile write and checks recovery after a shorter retry, roll without retry, and failed cleanup. |
| BUG-021: sync retry or process recovery acknowledges lost journal writeback | Fixed | After actual sync failure, rewrite the accepted pending range, compare an ephemeral streaming fingerprint, and sync before acknowledging. Recovery rewrites each prefix accepted by its scan before sealing. `review_journal_writeback.rs` models lost dirty bits, subsequent power loss, cache changes, self-consistent header mutation, and ranges larger than the 64 KiB buffer. |
| TEST-002: gRPC authentication regression depends on the winning deadline's error string | Fixed | `phase9_daemon.rs` now observes actual server-side Unauthenticated rejections and failed attach, with no rejection for valid metadata. A generic scheduler deadline is valid under BUG-013. The real-socket fixture has a two-second budget; precise deadline behavior remains covered by ManualClock tests. |

Linux iomap can clear dirty bits even when page-cache writeback fails, so the
writeback fixture models a documented kernel behavior. Recovery now pays an
additional read/write pass over accepted journal data; ordinary successful live
flushes avoid it. See the [kernel writeback documentation](https://www.kernel.org/doc/html/v6.17/filesystems/iomap/operations.html#pagecache-writeback).

NBD clients can ignore negotiated sizes, which is why both advertisement and
adapter validation are required. The installed C header and loaded plugin
agreed on the 384-byte prefix, API version 2, and `block_size` offset 376; an
actual nbdkit/libnbd connection reported the configured 4096/4096/8192 tuple.
See the [nbdkit callback contract](https://libguestfs.org/nbdkit-plugin.3.html#block_size).

All RED logs below returned **101** with behavioral failures; all GREEN logs
returned **0**. Filenames are relative to `/home/seorii/logs/`, with private
`.exit.json` sidecars preserving commands and exit status.

| Issue | RED log | GREEN log |
|---|---|---|
| BUG-010 | `maki-fix-bug010-red-20260905T121013.730111Z.log`; partition use: `maki-fix-bug010-partition-red-20260905T122825.502887Z.log` | `maki-fix-bug010-partition-green-20260905T122953.767108Z.log` |
| BUG-011 | `maki-fix-bug011-isolated-red-20260905T122132.775100Z.log` | `maki-fix-bug011-green-20260905T122308.662263Z.log` |
| BUG-012 | `maki-fix-bug012-red-20260905T121106.912502Z.log`; queued tail: `maki-fix-bug012-tail-red-20260905T122059.475151Z.log` | `maki-fix-bug012-tail-green-20260905T122212.004436Z.log` |
| BUG-013 | `maki-fix-bug013-red-20260905T121828.291381Z.log` | `maki-fix-bug013-green-20260905T122641.978514Z.log` |
| BUG-014 | `maki-fix-bug014-red-20260905T124750.878309Z.log`; failed publication: `maki-fix-bug014-publication-red-20260905T125158.193474Z.log` | `maki-fix-bug014-green-20260905T125347.498590Z.log` |
| BUG-020 | `maki-fix-bug020-red-20260905T121354.899842Z.log` | `maki-fix-bug020-green-20260905T121627.739081Z.log` |
| BUG-021 | `maki-fix-bug021-red-20260905T122051.918638Z.log`; valid-header mutation: `maki-fix-bug021-header-red-20260905T122447.223461Z.log` | `maki-fix-bug021-green-20260905T122652.551362Z.log` |
| TEST-002 | `maki-fix-test002-observed-auth-red-20260905T130857.232492Z.log` | `maki-fix-test002-auth-green-20260905T131019.262153Z.log` |

Final Linux verification for this round:

| Check | Result | Exit |
|---|---|---:|
| `cargo fmt --all --check` | Pass | 0 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Pass, no diagnostics | 0 |
| `cargo test --workspace --locked` | 484 passed, 0 failed, 7 ignored | 0 |
| `cargo test --workspace --release --locked -- --ignored` | 7 passed, 0 failed | 0 |
| Independent C ABI probe and rootless NBD negotiation | Configured block-size callback layout and 4096/4096/8192 negotiation verified | 0 |

Final baseline process PID `2886645` returned **0**:
`/home/seorii/logs/maki-fix-followup-baseline-final-20260905T131121.236462Z.log`.
Its `.exit.json` and `.summary.json` sidecars record the command and totals.
The release-gates command returned **0** in process PID `2786564`:
`/home/seorii/logs/maki-fix-followup-final-gates-20260905T125637.142287Z.log`.
That earlier combined wrapper returned **1** because of the now-fixed TEST-002
assertion; no production code changed after its successful release-gates step.
The independent C probe was PID `2533875`, exit **0**:
`/home/seorii/logs/maki-fix-bug011-abi-review-20260905T122540.302503Z.log`.

The detach changes use the helper's current mount namespace and require target
qualification for the installed kernel, nbd-client, LVM, XFS, and service
layout. This pass used simulated device observations and private userspace
sockets; it did not perform privileged device operations or deployment. The
existing database, vendor-provider, TLS, and hardware power-loss qualification
limits remain.

## Follow-up review (2026-09-05)

The [project assessment](project-review-2026-09-05.md) of `8b06c53` found nine
additional defects and one formatting failure. All nine were reproduced by a
failing regression before implementation, then verified green. Each issue has
its own code commit. The changes preserve the on-disk format and golden vectors.

| Finding | Status | Result and regression evidence |
|---|---|---|
| BUG-001: A/B retries can overwrite the last durable copy | Fixed | Preserve the typed-valid copy by rewriting its exact bytes, syncing the file and its directory before replacing the other side. `review_ab_retry.rs` in `maki-format` and `maki-core` cover all A/B record types, failed sync/restart, sector tearing, lost dirty bits after writeback EIO, and actual volume recovery. The extra preservation write and syncs are a durability cost per update. |
| BUG-002: missing attach configuration skips the dependency | Fixed | `AssertPathExists` fails startup so an ordered `Requires` workload cannot start after that failure. `regression_missing_attach_config.rs` checks the template and evaluates assertions with `systemd-analyze`; dependency syntax was also verified offline. |
| BUG-003: privileged state is below a daemon-owned directory | Fixed | `/run/maki-attach` is root-controlled. Descriptor-relative state access rejects symlinks, unsafe ownership/modes, multiple links, oversized and malformed records. Records bind configuration identity and a unique live NBD backend identifier; pinned devices cannot bypass validation. `state_tests.rs`, `exec_tests.rs`, and `regression_attach_state.rs` cover refusal before side effects, attach/rollback ordering, stale devices, changed mountpoint/VG/LV, and cleanup errors. |
| BUG-004: HalfOpen probe permits leak on early exit | Fixed | A generation-bound guard returns admission on every exit, without charging neutral outcomes as endpoint failures. `review_probe_lifetime.rs` covers request/provider errors, deadline, cancellation, and retry-budget refusal followed by a healthy probe. |
| BUG-005: retired WebSocket connections leave tasks and sockets alive | Fixed | One task owns both socket halves; retirement aborts it and cleans only its generation. `review_connection_lifetime.rs` observes server-side closure after timeout, cancellation, and provider drop, and verifies successor reuse. |
| BUG-006: one SecretBuffer unlocks another buffer's shared page | Fixed | Page references are counted under the same lock as `mlock`/`munlock`; zeroization precedes the final owner's unlock. `review_secret_page_lifetime.rs` checks Linux page state for drop, duplicate, and `into_vec`, lock failures, and full-capacity zeroization in isolated child processes. |
| BUG-007: name-only credential routing overwrites a different source | Fixed | Validation and public provider construction reject one name used with conflicting sources before resolving credentials. `review_credential_sources.rs` also preserves repeated same-source references and distinct names. |
| BUG-008: HTTP error strings contain query credentials | Fixed | Strip the URL from reqwest errors before classification or formatting. `review_redirect.rs` asserts that connection, timeout, and response-body errors omit synthetic secrets and URLs in both Display and Debug. |
| BUG-009: administrators cannot traverse control socket directories | Fixed | Control sockets default to `/run/maki-control/<volume>/control.sock`; packaging gives the admin group traversal through that separate tree and keeps NBD private. `regression_control_packaging.rs` checks effective path access and default/example/custom paths, alongside the existing control integration suite. |
| TEST-001: control regression fixture fails rustfmt | Fixed | `review_control.rs` was formatted after reproducing the check's exit 1. The same check then returned exit 0. |

The RED runs below returned exit **101** with behavioral assertion failures;
TEST-001 returned **1**. Each corresponding focused GREEN run returned **0**.
Logs and per-process `.exit.json` files are local evidence under
`/home/seorii/logs/`; the committed regression suites are the portable evidence.

| Issue | RED log | GREEN log |
|---|---|---|
| BUG-001 | `maki-fix-bug001-format-red-20260905T103601.938579Z.log`; additional writeback case: `maki-fix-bug001-writeback-red-20260905T104307.770996Z.log` | `maki-fix-bug001-format-final-confirmed-20260905T104507.333205Z.log`; volume: `maki-fix-bug001-core-final-20260905T105157.024176Z.log` |
| BUG-002 | `maki-fix-bug002-red-20260905T103242.816339Z.log` | `maki-fix-bug002-green-20260905T103326.120353Z.log` |
| BUG-003 | `maki-fix-bug003-red-20260905T103535.254697Z.log`; target identity: `maki-fix-bug003-detach-target-red-20260905T105013.661352Z.log`; cleanup: `maki-fix-bug003-cleanup-red-20260905T105119.266743Z.log` | `maki-fix-bug003-final-green-20260905T105202.654573Z.log` |
| BUG-004 | `maki-fix-bug004-red-20260905T103222.480448Z.log` | `maki-fix-bug004-green-20260905T103408.635450Z.log` |
| BUG-005 | `maki-fix-bug005-red-20260905T103713.475681Z.log` | `maki-fix-bug005-green-20260905T103941.006699Z.log` |
| BUG-006 | `maki-fix-bug006-red-20260905T104229.660488Z.log` | `maki-fix-bug006-green-20260905T104425.713962Z.log` |
| BUG-007 | `maki-fix-bug-007-red-20260905T103256.830969Z.log` | `maki-fix-bug-007-green-20260905T103422.878678Z.log` |
| BUG-008 | `maki-fix-bug-008-red-20260905T103612.112163Z.log` | `maki-fix-bug-008-green-20260905T103658.813604Z.log` |
| BUG-009 | `maki-fix-bug009-red-20260905T104541.818204Z.log` | `maki-fix-bug009-green-20260905T104647.999531Z.log` |
| TEST-001 | `maki-fix-test-001-red-20260905T103628.521262Z.log` | `maki-fix-test-001-green-20260905T103730.833720Z.log` |

Final Linux verification:

| Check | Result | Exit |
|---|---|---:|
| `cargo fmt --all --check` | Pass | 0 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Pass, no diagnostics | 0 |
| `cargo test --workspace --locked` | 441 passed, 0 failed, 7 ignored | 0 |
| `cargo test --workspace --release --locked -- --ignored` | 7 passed, 0 failed | 0 |
| Final control packaging + control integration tests | 5 passed after removing reliance on the service umask; format check also passed | 0 |

The full verification process was PID `1512616`, aggregate exit **0**, with log
`/home/seorii/logs/maki-fix-final-gates-20260905T105411.243723Z.log`; its
`.exit.json` and `.summary.json` sidecars record the result and per-check totals.
The final packaging verification was PID `1698849`, exit **0**, with log
`/home/seorii/logs/maki-fix-packaging-final-20260905T110453.725787Z.log`.
The service umask is not an NBD socket-mode guarantee because nbdkit resets it;
the tested access boundary is the restricted runtime ancestor.

The helper now requires nbd-client 3.27.0 or later with netlink and kernel
backend-identifier support. Existing live attachments must be detached with the
old helper before upgrading; legacy device-only records are not imported.
Explicit old control socket paths also need migration. See the
[upgrade procedure](operations.md#upgrading-the-runtime-layout).

This round used Linux fixtures and local sockets without activating services,
creating users/groups, or operating real NBD devices. Offline systemd assertion
and dependency checks do not replace a real service-start campaign. The new
helper protocol still needs target-host qualification; the earlier kernel
NBD/LVM/XFS reports describe older revisions. O-03 and queue deadlines remained
outside those nine fixes and were subsequently resolved as BUG-011 and BUG-013
above. Transport TLS, database, and power-loss qualification limits remain.

## Overall status (2026-09-03)

All 18 findings have code changes with regression tests: the three P0 data
safety defects (M-001 key canary, M-002 roll-vs-promotion, M-003 dirty-flag
ordering) plus fail-closed recovery (M-007, M-009), the bounded journal
(M-004), the wired control plane (M-005, M-017), configuration and transport
hardening (M-008, M-013, M-014, M-015), remote-provider hardening (M-010,
M-011, M-012), the deep checker (M-018), and the privileged helper (M-006,
M-016). Every batch was verified with `cargo fmt`, strict Clippy, and the
full workspace suite on Windows, and the Linux-only paths (Unix sockets,
`statvfs`, the privileged executor, process hardening) under WSL Ubuntu.

A follow-up pass added debug-build sanitizers and randomized suites (see
[Sanitizers and randomized suites](#sanitizers-and-randomized-suites-2026-09-03))
and re-ran the extended release gates, which had not been exercised after the
review changes. That pass found and fixed three more defects: S-01
(checkpointed data read as zeros after an allocation-map or catalog A/B
fallback), S-02 (overlay byte accounting), and S-03 (a healthy volume refused
after segment numbering restarted under a stale durable mark). Widening the
crash model to out-of-order sector persistence then found S-04 and S-05 in
recovery's torn-tail classification.

A second audit of the core, the crypto layer and the operational layers
followed (see [Second audit](#second-audit-2026-09-03-core-crypto-layer-operational-layers)):
27 confirmed findings, each reproduced by a failing test before the fix, among
them recovery accepting never-fsync'd page-cache bytes after a process restart
(K-01), HTTP redirects re-sending plaintext (C-01), the root helper following
symlinks in the mount root (O-01), credentials falling back to environment
variables (O-06), and detach disconnecting the wrong NBD device (O-02). The
final state passes strict Clippy, the full debug workspace suite (every
Unix-only suite included), and all seven `phase*_gate_full` release gates
under WSL Ubuntu, and strict Clippy plus the per-crate suites on Windows.

A third external review (2026-09-05) examined the boundaries where the code's
guarantees meet the operating system's partial failures, real device identity,
and memory ownership (see
[Third review](#third-review-2026-09-05-os-partial-failure-device-identity-memory-ownership)):
ten findings F01 to F10 plus two smaller items, every one confirmed against
HEAD and reproduced by a failing test before its fix. The two durability
findings changed what the journal does after an I/O error: a failed
`fdatasync` is answered by rewriting and verifying the unsynced records
before the next sync, never by a bare retry (F01), and a partial `write_at`
is truncated back to the logical end before anything is appended or sealed
(F03). `CrashableBacking` now models both failure modes by default.

Several of these findings were fixed independently on two branches (the
third-to-fifth passes below and the
[follow-up](#follow-up-review-2026-09-05) and
[further reliability](#further-reliability-review-2026-09-05) reviews); the
merge kept one implementation per finding and both sides' regression tests
wherever they agree. Where a row below names the superseding BUG entry, that
entry's implementation is the one in the tree.

A fourth, self-directed pass then read the normative sections of `SPEC.md`
against the code (see
[Fourth pass](#fourth-pass-2026-09-05-specification-contradictions-and-boundaries)):
eight findings N-01 to N-08, among them backing files created world-readable
against SPEC §8, most of the SPEC §40 required metrics missing, the
`preferred_io` default, key files loaded regardless of their permissions, and
control commands that could hang forever.

What still needs an environment this repository cannot provide:

- Real NBD/LVM/XFS attach, mount-identity verification, rollback, and device
  allocation on a privileged Linux target (`docs/privileged-linux-validation.md`).
- Vendor endpoint qualification of the remote transports, including the new
  batch identity contract (unit echo) and non-retry-safe behaviour.
- Long soaks under sustained writes with injected checkpoint faults, QEMU or
  bare-metal power cuts, and real database campaigns (`docs/testing.md`).
- `memory_lock_mode = "all"` and `require_secure_swap_policy = true` on the
  target distribution's limits and swap layout.

Design limits that remain and are documented: WebSocket and gRPC still have no
TLS (refused explicitly, not downgraded); `tls.server_name` is refused rather
than supported; a missing *last* journal segment cannot be detected without
additional metadata; `madv_dontdump` is honoured through the non-dumpable
process flag rather than per buffer.

## P0 — before storing any real data

| Finding | Status | Change | Regression tests |
|---|---|---|---|
| M-001 wrong key / provider not rejected at attach | Fixed | See [Key canary](#key-canary). Attach also compares the configured provider type and key name with the superblock (`AttachIdentity`, always set by the daemon). The fake provider gained `with_integrity_check(false)` to model an unauthenticated cipher. | `review_attach.rs` (maki-core): `attach_rejects_wrong_key_same_compatibility_id`, `attach_rejects_wrong_key_without_provider_integrity`, `first_attach_binds_key_durably`, `attach_rejects_provider_type_change_with_same_compatibility_id`, `attach_rejects_key_identity_change`, `legacy_volume_is_probed_with_integrity_provider_then_canaried`, `legacy_volume_without_integrity_is_refused`, `canary_transport_failure_is_not_reported_as_key_mismatch`, `canary_from_another_volume_is_rejected`; `review_daemon.rs` (maki-nbdkit, real AES-XTS/GCM-SIV through `attach_from_config`): `xts_wrong_key_is_refused_at_attach`, `provider_type_change_is_refused_at_attach`, `key_identity_change_is_refused_at_attach`; canary golden vectors in `review_format.rs` |
| M-002 automatic roll can drop a durable overwrite from the overlay | Fixed | The volume promotes the overlay to the journal's durable boundary after *every* `append` (including a failed one) and before publishing the new version; `checkpoint` re-promotes from the journal boundary before collecting. A roll whose fdatasync fails now keeps the segment active instead of dropping it, so a later FLUSH still syncs it. | `auto_roll_preserves_previous_durable_overwrite`, `failed_append_after_roll_still_promotes_durable_versions`, `failed_seal_sync_does_not_lose_active_segment_durability` |
| M-003 allocation-map retry can skip the directory fsync | Fixed | `persist_allocations` writes every dirty A/B copy, fsyncs the data directory, and only then clears the dirty flags; a new `checkpoint.alloc_dirsync` failpoint covers the fsync. | `checkpoint_retry_keeps_allocation_dirent_durable`; the failpoint joined `crash_mid_checkpoint_at_every_boundary_recovers_consistently` |
| M-007 recovery misclassifies durable corruption as a torn tail | Fixed | See [Recovery fail-closed rules](#recovery-fail-closed-rules). | `recovery_rejects_missing_first_uncheckpointed_segment`, `recovery_rejects_gap_after_checkpoint_boundary`, `recovery_rejects_full_final_segment_bad_header`, `recovery_rejects_corrupt_middle_record_header_in_final_segment`, `recovery_rejects_oversized_segment_before_allocation`, `recovery_rejects_damage_inside_durable_mark_even_at_the_tail`, `recovery_truncates_volatile_damage_despite_valid_successor`, `recovery_rejects_segment_shorter_than_durable_mark`, plus the bounded-scanner tests in `review_format.rs` |
| M-008 fake provider in the default release feature | Fixed | `maki-nbdkit` has `default = []`; the crate's own tests enable `fake-provider` through a dev-dependency on itself. `parse_and_validate` refuses `provider = "fake"` when the feature is off, so `maki volume create` and attach both fail closed. CI's nightly job builds the release `maki` binary and asserts a fake-provider config is refused. | `fake_provider_is_refused_without_the_feature` (`check_provider_available` with the feature flag passed explicitly, since feature unification makes the runtime flag always true under `cargo test`) plus the CI step |

## P1 — before a limited beta

| Finding | Status | Change | Regression tests |
|---|---|---|---|
| M-004 no automatic checkpointing; journal / free-space bounds unenforced | Fixed | See [Bounded journal](#bounded-journal): a background checkpoint worker (watermark, low free space, interval), a forced journal sync at `limits.max_journal_pending_bytes`, inline reclaim and ENOSPC at `backing.journal_max_bytes`, ENOSPC below `backing.journal_emergency_reserve_bytes`, eager checkpoints below `backing.checkpoint_reserve_bytes`, a `Degraded` state, and the `maki_backing_free_bytes` / `maki_journal_bytes` / `maki_checkpoint_lag_bytes` metrics. `Backing::free_bytes` (statvfs on Unix) feeds the reserves. Config validation now requires `journal_max_bytes >= 2 * journal_segment_size`. | `review_bounded.rs` (maki-core): `sustained_writes_keep_journal_and_overlay_within_hard_limits`, `worker_checkpoints_when_watermark_is_crossed`, `worker_checkpoints_on_interval_and_syncs_pending_records`, `worker_stops_when_engine_is_dropped`, `pending_bytes_limit_forces_journal_sync`, `emergency_reserve_refuses_writes_until_space_returns`, `failed_reclaim_at_hard_limit_degrades_then_recovers` |
| M-005 control socket not started by the daemon; no-op reloads | Fixed | `NbdAdapter::open_config` binds the control socket (`control.socket`, default `/run/maki-control/<volume>/control.sock`) on the adapter's runtime before returning and serves `EngineControlBackend` on it; a bind failure fails attach; `shutdown` stops the server and removes the socket. `reload` returns an explicit "NOT applied" error for every section the engine cannot apply at runtime (`retry`, `circuit-breaker`, `batch`, `limits`, `timeouts`, `semaphores`, `endpoints`, `credentials`); only `cache` is applied, and it requires `max_bytes`. `status` reports the engine state, journal size, free space, and checkpoint counters. | `review_control.rs` (maki-nbdkit, Unix): `control_socket_is_created_served_and_removed`, `missing_control_socket_directory_fails_attach` |
| M-006 mount-identity verification is a no-op | Fixed | The Linux executor's `VerifyMountIdentity` step now gathers real observations (`/proc/self/mountinfo` fstype and source through the pure `parse_mountinfo`, `blkid` filesystem UUID, `<mountpoint>/.maki-sentinel`, sysfs NBD `pid` state, a write-fsync-read-remove probe) and runs the existing pure verifier; a failure rolls the attach back. The volume UUID comes from the root-owned attach config or `--uuid` and is required for execution (`--plan` still renders without it). `--init-sentinel` writes the sentinel on an empty filesystem, never overwriting a different value. The unit now carries `AssertPathExists` on the attach config (BUG-002) and documents that dependents must use both `Requires=` and `After=`. | `mountinfo_parsing_finds_the_visible_mount_and_decodes_escapes`, `verifier_rejects_wrong_device_and_missing_sentinel`, `execution_requires_a_volume_uuid_but_plan_rendering_does_not` (maki-privileged); `plan_mode_works_without_uuid_but_execution_requires_it` (maki-attach process). Real mount/rollback runs need the privileged Linux target (`docs/privileged-linux-validation.md`). |
| M-009 A/B reader collapses I/O errors into "invalid copy" | Fixed | `AbStore` reports any I/O failure other than not-found as an error; empty, short, and CRC-invalid copies remain "invalid". `create_volume` writes both checkpoint-state copies (sequence 0) and recovery requires a valid copy on every volume instead of defaulting to 0. | `recovery_requires_valid_checkpoint_state`, `recovery_surfaces_hard_io_error_on_checkpoint_state`, `ab_load_reports_hard_io_errors_instead_of_masking_them`, `ab_load_treats_missing_empty_and_corrupt_sides_as_invalid_copies`, `create_volume_writes_checkpoint_state_and_durable_mark` |
| M-010 retry ignores `retry_safe`; no absolute deadline | Fixed | `DispatchConfig` carries `retry_safe` and `max_operation_time`. A non-retry-safe provider is sent a request at most once (no retry, no failover; the WebSocket transport's transparent reconnect-and-resend is disabled too). `bounded-error` is an absolute deadline measured on the injectable clock: backoff sleeps are capped to the remaining time and an in-flight RPC is abandoned when it expires (`deadline_exceeded_total`). Retry budgets are now endpoint-local (SPEC §32) instead of one bucket for the set. | `review_dispatch.rs` (maki-crypto): `non_retry_safe_provider_is_never_retried`, `retry_safe_provider_fails_over_within_the_pass`, `bounded_error_obeys_wall_clock_deadline_during_an_rpc`, `retry_backoff_never_sleeps_past_the_deadline`; `non_retry_safe_websocket_never_resends_after_a_transport_failure` (maki-crypto-websocket) |
| M-011 unvalidated endpoints enter the serving pool | Fixed | `EndpointSet::with_quarantine` admits only validated endpoints. At attach the daemon first probes each endpoint on its own (three attempts, spaced by the retry delay) so an unreachable *reference* can no longer poison the check, cross-validates the reachable ones against the first reachable endpoint, quarantines the rest, and refuses attach when nothing is reachable or an endpoint is proven non-interchangeable. A validator reruns the cross-endpoint check for quarantined endpoints against a validated one under the real volume context, at most once per breaker interval; proven non-interchangeability excludes the endpoint permanently. `endpoint_status()` exposes the flags. Retry budgets are per endpoint, charged only to repeat attempts on that endpoint. | `unverified_endpoint_never_enters_serving_pool`, `proven_incompatible_endpoint_is_excluded_permanently`, `capabilities_come_from_a_validated_endpoint` (maki-crypto) |
| M-012 reordered batch results undetected (WebSocket, positional HTTP) | Fixed | WebSocket response items must echo `unit` in request order (missing, reordered, duplicated, or wrong echoes are `Contract` errors); HTTP batch layouts require `item_index_path` at validation; gRPC already echoed `unit_index`. SPEC §18 now states the identity contract. | `ws_rejects_reordered_batch_items`, `ws_rejects_missing_unit_echo`, `ws_rejects_wrong_unit_echo`, `ws_accepts_correct_unit_echo` (maki-crypto-websocket); `http_batch_layout_requires_unit_echo` (maki-format) |
| M-013 incomplete configuration validation; placebo settings | Fixed | `validate_settings` and `validate_provider_sections` (see [Configuration](configuration.md#validation-rules)): positive counts and byte limits, finite ratios and probe rates, ordered delay and breaker ranges, batch targets within maxima, capability mode, bounded-error timing, NBD size ordering, cache and control values, memory-lock mode, provider-specific required and forbidden sections, endpoint URL parsing, and the `keyring` source refused. The `[security]` section is now applied by `maki_nbdkit::security::apply` before attach (Linux, fail closed): `disable_core_dump` via `prctl` + `RLIMIT_CORE`, `memory_lock_mode = "all"` via `mlockall`, `"secure-buffers"` via per-`SecretBuffer` `mlock` (opt-in in `maki-crypto`, failures counted), `require_secure_swap_policy` via `/proc/swaps` plus dm-crypt detection; `madv_dontdump` is honoured through the non-dumpable flag and validation refuses it without `disable_core_dump`; `cache.lock_memory` follows the lock mode and validation refuses it with `off`. The posture is reported under `security` in `status`. Non-Linux hosts report `unsupported-platform`. The secure-swap policy defaults to off (explicit production opt-in; the shipped example enables it). | `review_config.rs` (maki-format): `zero_and_inverted_bounds_are_rejected` (28 cases), `capability_mode_and_availability_policy_are_checked`, `keyring_credential_source_is_refused`, `local_provider_requires_key_and_rejects_transport_sections`, `duplicate_or_empty_endpoint_names_are_rejected`, `defaults_still_validate`; `review_security.rs` (maki-nbdkit): `inconsistent_security_settings_are_rejected_at_validation`, `swap_parser_is_strict`, `posture_is_recorded_and_reported`, `linux_disables_core_dumps_for_real` (Linux); `page_locking_is_opt_in_and_accounted` (maki-crypto) |
| M-014 production sample cannot attach | Fixed | `packaging/examples/postgres-prod.toml`, the SPEC §57 example, and the `full_config.toml` fixture now carry complete `[crypto.http.encrypt]` / `[crypto.http.decrypt]` batch mappings with unit echo and a credential-referenced bearer token; validation requires both mappings for `remote-http`. | `production_sample_and_full_fixture_validate`, `remote_http_requires_endpoints_and_both_mappings` (maki-format); `production_sample_builds_provider_successfully`, `production_sample_fails_without_its_credential` (maki-nbdkit `review_sample.rs`) |
| M-015 WebSocket / gRPC without TLS | Fixed | Validation refuses plaintext `http://`, `ws://`, and gRPC `http://` endpoints unless the host is loopback, refuses `wss://` / gRPC `https://` / transport TLS sections as not compiled in, and rejects URL userinfo. The HTTP provider fails closed on unreadable or invalid CA and client-certificate files, applies `client_key` from its credential source, and refuses `server_name` instead of ignoring it. The daemon's credential router reads path-like names as files. | `plaintext_transports_are_loopback_only`, `websocket_and_grpc_require_their_sections_and_reject_tls`, `tls_files_must_exist_and_server_name_is_refused`, `endpoint_url_parsing_and_loopback_detection` (maki-format); `unreadable_tls_material_refuses_the_provider`, `client_key_credential_is_appended_to_the_identity` (maki-nbdkit) |
| M-016 privileged attach: allocation, rollback, config-driven execution | Fixed | `maki_privileged::config` loads `/etc/maki/attach/<volume>.toml` (`packaging/examples/attach.toml`) and applies argument hygiene to every value (no option-like values, canonical absolute paths, LVM name charset, UUID shape). The plan carries the block size into `nbd-client -b` and `blockdev --setbsz`, and can leave the NBD device as `/dev/nbd<auto>`: the executor allocates the lowest free device from sysfs under `/run/maki-attach/attach.lock`, binds it into every step, and waits for readiness after connect. `rollback_steps` derives the compensating steps for the executed prefix and the executor runs them in reverse on any failure, reporting rollback failures. | `config_resolves_defaults_and_auto_device`, `overrides_win_and_are_validated`, `argument_hygiene`, `attach_plan_binds_the_allocated_device_everywhere`, `nbd_connect_uses_the_configured_block_size`, `init_sentinel_adds_a_write_step_before_verification`, `rollback_reverses_the_executed_prefix`, `free_nbd_allocation_picks_the_lowest_unconnected_device` (maki-privileged); `option_like_values_are_rejected_before_planning`, `attach_config_drives_the_plan` (maki-attach process) |
| M-017 control-socket group ownership | Fixed | `bind_control_socket` resolves `control.group` with `getgrnam_r`, `chown`s the socket to it and only then applies mode 0660, before any client can connect; an unknown group fails the bind. `packaging/sysusers.d` adds `maki` to `maki-admin` so the unprivileged daemon may perform that `chgrp`. | `review_uds.rs` (maki-control, Unix): `bind_sets_mode_replaces_stale_socket_and_cleans_up`, `bind_refuses_missing_directory`, `unknown_group_is_an_error`, `root_group_resolves_to_gid_zero` |
| M-018 offline checker too shallow | Fixed | `maki_core::check::deep_check` (exposed as `maki-check --deep` and `maki check <config> --deep`) runs the fast checks, takes the volume lock, then inspects both checkpoint-state copies (requiring one), the key canary, the durable mark, the whole journal through the recovery scanner refactored into a read-only `scan_journal` that reports the repairs it would make, and every allocated slot through the real slot reader. The fast check remains for volumes without data. | `review_check.rs` (maki-core): `deep_check_passes_on_a_healthy_volume_with_data_and_journal`, `deep_check_finds_slot_damage_the_fast_check_misses`, `deep_check_requires_checkpoint_state`, `deep_check_reports_journal_corruption_and_missing_segments`, `deep_check_tolerates_a_torn_tail_and_reports_the_repair`, `deep_check_refuses_to_race_an_attached_volume`; `review_deep.rs` (maki-check binary, real filesystem) |

## Follow-up audit (2026-09-03)

Issues found while re-reading the code after the review, all fixed with tests:

| Issue | Change | Regression tests |
|---|---|---|
| `[crypto.batch] target_*` / `max_wait` and `[limits] max_pending_crypto_*` / `max_ciphertext_bytes` were parsed and validated but nothing consumed them (the `Batcher` and `BoundedQueue` helpers had no call sites) | `maki_crypto::scheduler::BatchScheduler` coalesces concurrent requests into bounded provider calls (targets, maxima, `max_wait`, whole requests only, separate encrypt/decrypt lanes bounded by the pending limits). The daemon wraps remote providers with it; local providers are called directly. Counters are reported in `status` and metrics. | `review_scheduler.rs` (maki-crypto): `concurrent_requests_are_coalesced_into_one_provider_call`, `lone_request_flushes_after_max_wait`, `requests_are_never_split_and_max_items_is_respected`, `provider_error_reaches_every_request_in_the_batch`, `decrypt_lane_is_independent_and_round_trips`, `pending_work_is_bounded`, `capabilities_pass_through` |
| A FUA write whose fdatasync failed was already appended to the journal but never published to the overlay: live reads showed the old version while a later barrier or a restart surfaced the new one | `Volume::write_ct` publishes as soon as the append succeeded and only then performs the FUA sync, so the live view can never lag the on-disk journal | `failed_fua_sync_still_publishes_the_journaled_record` (maki-core) |
| `backing.journal_max_bytes >= 2 * journal_segment_size` still allowed a limit too small for the largest request to fit after an inline reclaim, leaving writes refused with ENOSPC forever | Validation requires two segments plus the largest request (`nbd.maximum_io` in records of `32 + max_ciphertext_size`) | `journal_hard_limit_must_leave_room_for_a_reclaim_and_the_largest_request` (maki-format) |
| The dispatcher computed its deadline with unchecked `Duration` addition | `saturating_add` | covered by the existing deadline tests |
| The plaintext cache found its LRU victim with a linear scan over every entry; a full cache of tens of thousands of units evicts on every insert, making the hot read path quadratic | Recency is an ordered index keyed by the monotonic tick, so eviction and touch are O(log n) | `eviction_order_survives_many_entries_and_touches` plus the existing cache suite |
| The superseded `maki_crypto::batch::Batcher` had no call sites | Removed; `BatchScheduler` is the batching layer | build |
| The two security tests in one binary raced on the process-global posture | Serialized with a test-local lock | `review_security.rs` |

## Sanitizers and randomized suites (2026-09-03)

Debug-build invariant checkers ("sanitizers") now run after every mutation of
the core structures, and new randomized suites drive the system through fault,
concurrency, and corruption spaces the hand-written tests did not reach. No
nightly toolchain is available on the development machines, so Miri and the
LLVM sanitizers are not part of this pass; the checkers below are ordinary
debug assertions that release builds compile out.

| Sanitizer / suite | What it checks | Result |
|---|---|---|
| `Overlay::check_invariants` (debug, after every publish/promote/retire; sampled above 4096 units) | byte accounting equals the live versions; a durable version never leads the latest one and equal sequences carry equal bytes; every version at or below the promoted boundary is promoted; pending promotions are above the boundary and name live units | found S-02 |
| `JournalWriter::check_invariants` (debug, after every append/sync/roll/seal/delete) | `durable <= appended = next - 1`; sealed segments strictly ordered, contiguous, never larger than their header allows, and fully durable; the active segment ends at `next`; synced prefix consistent with the unsynced flag and with `durable` | clean |
| `Volume::check_invariants` (debug, after every write/flush/checkpoint and at recovery) | `checkpoint <= durable`; both sub-audits; no overlay version beyond the appended sequence | clean |
| `review_fuzz.rs` (maki-format) | every on-disk decoder (superblock, segment header, durable mark, canary, slot header, allocation map, catalog, checkpoint state) rejects every single-bit flip of its image and never panics on 3000 random mutations or on garbage; the journal scanner never panics and never reports a torn tail inside the durable prefix; endpoint URL parsing and `validate()` on a mutated production sample never panic | clean |
| `review_stress.rs` (maki-core) | 4 writers + 2 readers on a 128 KiB journal with a 15 ms checkpoint worker and provider chaos, per-unit oracle of issued/acknowledged/durable stamps: no torn reads, no stamp that was never issued, journal and overlay stay bounded, the engine returns to `Ready`, and after a crash every FUA/flush-acknowledged stamp (or a newer acknowledged one) survives; plus a sweep of all 15 persistence failpoints through the engine with recovery to `Ready` and a crash check | clean |
| `review_corruption.rs` (maki-core) | 80 rounds of random single-file damage (bit flips, truncation, zeroed ranges) to any volume file after a checkpointed workload: the deep checker never panics; attach either refuses (journal or checkpoint-state damage only) or serves every unit exactly; data-shard damage yields EIO, never zeros or another version | found S-01 |
| `review_stress_crypto.rs` (maki-crypto) | scheduler and dispatcher under 48 concurrent tasks with random request shapes and random retryable / throttled / endpoint-fatal faults: request order and unit identity kept, every failure classified transient, no hangs, pending counters and permits return to zero, service resumes once faults stop | clean |
| `review_cache_model.rs` (maki-cache) | 12 seeds x 4000 random put/get/invalidate/resize/TTL steps against an independent LRU model: exact hit/miss, eviction order, byte accounting, budget after every step | clean |
| Extended gates (`cargo test --workspace --release -- --ignored`, Linux) | the historical `phase*_gate_full` randomized crash/recovery, endpoint, breaker, database-simulation and integration gates, re-run against the review changes | found S-03; all seven pass after the fix |
| Wider crash model (`CrashableBacking::with_tearing`, now used by the phase 3, 11 and 12 crash cycles and the engine stress) | any unsynced write, not only the last one, may persist partially: a sector-aligned prefix, or every sector but one (out-of-order sector persistence) | found S-04 |

### Findings

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| S-01 | **Checkpointed data read as zeros after an A/B fallback.** The allocation map and the shard catalog are A/B records. When the newest copy is unreadable (a torn write during a crash, or later damage to that one file) recovery legitimately falls back to the previous generation, which does not list the slots filled by the last checkpoint, nor a shard that checkpoint created. `read_slot` treated "bit 0" as unwritten, so those units silently read as zeros, and the journal segments that could have re-supplied them had already been deleted. Found by `review_corruption.rs` on its first run (truncating `shard-0000000a.alloc.a`). | Slot headers are authoritative (SPEC §22 and §27 updated). At open the store adopts shard data files the catalog copy does not list, and for a shard with an invalid or absent allocation copy it probes every cleared slot's header and marks the ones that decode for their unit; `read_slot` also probes a cleared slot before answering zeros. Repairs are persisted by the next checkpoint even when nothing new is durable, and `deep_check` reports them as warnings. A cataloged shard with no valid allocation copy still refuses attach (offline repair territory). | `allocation_map_fallback_never_reads_checkpointed_data_as_zeros`, `catalog_fallback_never_hides_a_shard`, `deep_check_reports_allocation_repair_and_idle_checkpoint_persists_it`, `missing_allocation_maps_refuse_attach`, `recovery_under_random_single_file_corruption` (maki-core `review_corruption.rs`) |
| S-02 | Overlay byte accounting drifted when a durable version was replaced by one of a different length (`promote` added the new length only when no durable copy existed yet). Invisible in practice because a volume's ciphertext length is fixed, but the admission counters would be wrong for a provider with variable overhead. | `promote` subtracts the replaced durable copy; the overlay sanitizer enforces exact accounting. | overlay sanitizer under every maki-core suite |
| S-03 | **Healthy volume refused after segment numbering restarted under a stale durable mark.** The M-007 durable mark is a plain, never-fsync'd, never-cleaned file naming the newest segment the writer synced. After recovery every surviving segment is sealed and none is active, so a checkpoint with nothing to add deletes *all* of them; recovery then restarted segment numbering at 0. The next crash left a fresh `seg-0` (header only) next to the old mark ("seg-0 durable to 2336 bytes"), and recovery failed closed with "durable mark covers 2336 bytes but file has 48". Availability, not durability: no data was at risk, but the volume could not attach. Found by `phase3_gate_full` (seed 172) in the release gates, which had not been re-run after M-007. | Recovery continues segment numbering above both the surviving segments and the mark's segment index, so an index is never reused while a mark for it can exist; the writer also points the mark at each new segment when it rolls (header-only durable size). | `segment_indexes_never_fall_below_the_durable_mark` (maki-core `review_storage.rs`); `phase3_gate_full` |
| S-04 | **Healthy crash state refused when the durable mark was lost.** The mark is written without fsync, so the crash it is meant to describe frequently loses it (or leaves an older mark naming a deleted segment). Recovery then fell back to the pre-M-007 heuristic for the final segment, which classifies a damaged record *followed by an intact one* as corruption in the durable body. Unsynced records persist in any order, so a torn record 2 next to an intact record 3 is a normal crash state; the volume was refused with "payload CRC failure in durable body". Availability only. Found within seconds by the widened crash model in `phase3_gate_full` (seed 1) and `phase11_gate_dbsim_full`; the old model only ever tore the last write of a file, which can never produce that pattern. | With no mark naming the final segment, recovery treats only the segment header as proven durable: all damage beyond it is a torn tail (truncate), never corruption. The heuristic mode of the scanner is no longer reachable from recovery or the deep check. The cost is documented: bit rot inside the final segment's synced-but-unmarked records is truncated rather than reported when the mark was lost. | `lost_or_stale_mark_never_turns_a_torn_middle_record_into_corruption` (maki-core `review_storage.rs`); `phase3_gate_full`, `phase11_gate_dbsim_full` with the wider crash model |
| S-05 | **Zero-filled tail accepted, then refused one crash later.** A torn unsynced record can survive a crash as an all-zero tail of the final segment (the file grew, none of the record's sectors arrived). The scanner treated that as a clean preallocated end and recovery left it in place. The writer then sealed the segment as-is when it opened a successor, and the next recovery, for which the segment was non-final and therefore durable in full, refused the volume with "zeroed record inside durable prefix". Availability only; found by the widened crash model (`phase3_gate_crash_recovery_smoke` seed 78, `phase11_gate_dbsim_full`). | Recovery normalizes the final segment to exactly its records: a clean scan that ends before the file length now produces a `Truncate` repair (fdatasync'd like every repair), so no sealed segment ever carries a zero tail. | `zero_tail_of_final_segment_is_truncated_before_it_can_be_sealed` (maki-core `review_storage.rs`); the crash gates |

## Second audit (2026-09-03): core, crypto layer, operational layers

After the sanitizer pass, three independent adversarial code reviews (core
engine and recovery; crypto layer and transports; daemon, control, privileged
helper, format and backing) produced 32 candidates. Each was reproduced with a
failing test before being fixed; the ones below survived verification. IDs:
K (core), C (crypto), O (operations).

### Durability and data

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| K-01 | **Recovery declared page-cache bytes durable and never synced them.** A process crash (SIGKILL, OOM, panic) is not a power loss: records appended without FUA sit in the page cache and are read back by the next recovery, which accepted them, sealed their segment and resumed with no active segment. A later FLUSH acknowledged them with nothing to sync (SPEC §12 violated by the next power loss), and the first append after the restart opened a successor, after which the same power loss tore a *non-final* segment and the volume was refused. | Recovery fdatasyncs every surviving segment, fsyncs the journal directory and publishes a durable mark for the final segment before handing the journal to the writer. | `recovery_fsyncs_page_cache_records_before_a_flush_acknowledges_them`, `resumed_segment_is_durable_before_a_successor_is_opened` (maki-core `review_audit.rs`) |
| K-08 / C-08 | Decrypted plaintext was checked against *any* size the provider declares, not the volume's unit size; a short unit was sliced out of range (a panic caught only at the NBD boundary), a long one silently re-encrypted at the wrong length. Oversized or empty ciphertexts could reach the journal and turn the next recovery into "corruption". | `CheckedProvider::pinned` and the engine pin decrypt results to the unit size and refuse ciphertexts above the volume maximum, as `Contract` errors. | `short_plaintext_is_a_contract_error_not_a_panic` (maki-core), `checked_provider_pins_decrypt_length_to_the_unit_size` (maki-crypto `review_audit2.rs`) |
| K-06 | A CRC-valid journal record naming a unit beyond the device, or carrying a payload above the volume's ciphertext size, was replayed and then checkpointed into an out-of-range shard that the next open rejects. | The scanner classifies such records as corruption. | `record_with_out_of_range_unit_is_corruption_not_replay`, `record_with_oversized_payload_is_corruption_not_replay` |
| C-01 | **HTTP redirects were followed.** reqwest's default policy replays the POST body (plaintext on encrypt) to whatever `Location` the endpoint names, possibly another host over plaintext HTTP, and turns 301/302/303 into a body-less GET parsed as ciphertext; a redirect loop was even classified retryable. | Redirect policy `none`; any 3xx is an `EndpointFatal` (fail over, never re-send). | `redirects_are_never_followed` (maki-crypto-http `review_redirect.rs`) |
| C-09 | The self-test could not tell a pass-through provider (debug/no-op endpoint, a response mapping echoing the request) from a real one, and never exercised a claimed context binding; attaching such a provider persists plaintext. | The self-test refuses ciphertext equal to plaintext and, when context binding is claimed, a decrypt under another unit index that yields the same plaintext. | `self_test_rejects_a_pass_through_provider`, `self_test_checks_a_claimed_context_binding` |
| O-01 | **The root helper followed symlinks in the tenant-writable mount root.** The rw probe opened `<mountpoint>/.maki-rw-probe` with create+truncate and the sentinel with an unbounded read: a planted symlink let the workload make root truncate any file, a FIFO could block the attach unit forever, a huge sentinel could exhaust memory. | Probe files are `O_CREAT\|O_EXCL\|O_NOFOLLOW` under an unpredictable name and read back through the same descriptor; the sentinel is opened `O_NOFOLLOW\|O_NONBLOCK`, must be a regular file and is read to a 4 KiB bound. | `sentinel_symlink_and_oversized_file_are_ignored`, `rw_probe_never_overwrites_a_planted_target` (maki-privileged, Linux) |
| O-06 | Header, metadata and TLS-key credentials ignored their declared `source`: a path-like name always read a file, anything else tried the systemd directory and silently fell back to `MAKI_CREDENTIAL_*` environment variables, so a production daemon could attach on a stray variable. | The router dispatches on the declared source exactly like the volume key does; `credential` fails closed without `CREDENTIALS_DIRECTORY`, undeclared names are refused. | `credential_source_never_falls_back_to_the_environment` (maki-nbdkit `review_sample.rs`) |

### Availability

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| K-02 | A checkpoint that stored its state but failed to delete the covered segments (transient unlink error, or the deletions lost in a crash) left them on disk forever: every later checkpoint took the "nothing new" path, the journal stayed at its hard limit, and every write failed with ENOSPC while the engine reported Ready — across restarts. | The idle checkpoint path deletes covered segments and fsyncs the journal directory; the worker runs when covered segments exist even with nothing new to apply. | `idle_checkpoint_reclaims_covered_segments_left_by_a_failed_deletion` |
| K-03 | `persist_allocations` (S-01) stored the catalog before the adopted shard's allocation map; a failure in between produced a cataloged shard with no allocation copy, which every later attach refuses. | Allocation maps are stored and the data directory fsynced before the catalog commits, the same order as shard creation. | `adopted_shard_is_never_cataloged_without_an_allocation_copy` |
| K-04 | The per-unit lock table swept idle entries on *every* insertion once it held more than 8192 entries, under the global mutex: with many locks held (large requests on small units, parallel callbacks) each unit acquisition scanned the whole table. | Sweeps are amortized: the next one runs only once the table has doubled since the last. | `sweeps_are_amortized_while_many_locks_are_held` (engine unit test) |
| K-07 | Recovery required every surviving segment to be contiguous, including checkpoint-covered ones; a crash that lost one covered unlink but not its neighbour's produced a "gap" and refused the volume. | Only records above the checkpoint must be contiguous (the first uncovered segment still has to bridge it); the journal sanitizer knows about covered holes. | `partially_resurrected_covered_prefix_is_accepted`, `gap_after_the_checkpoint_boundary_is_still_refused` |
| C-03 | Validation of a quarantined endpoint ran inline in every request with no deadline: one black-holed endpoint stalled every request behind its transport timeout, about once per validation interval, forever. | Validation runs in a background task (one per endpoint at a time); requests never wait for it. | `quarantined_endpoint_validation_never_blocks_requests` |
| C-04 | The batch scheduler awaited each provider call inline: one batch per round trip per lane, so the configured inflight limits were unreachable, "least inflight" selection degenerated to config order, and one stalled batch blocked every request behind it. | Batches are dispatched on their own tasks under a per-lane inflight bound (`limits.max_crypto_inflight_batches`). | `lane_keeps_several_batches_in_flight`, `lane_honours_its_inflight_limit` |
| C-05 | WebSocket TCP connect, handshake and send had no timeout and ran under the connection mutex: a peer that accepts and never answers held every request on the provider forever; a request timeout did not retire the connection, so every later request burned the timeout on the same dead socket. | Connect and send are bounded by the transport timeout; a timed-out request retires its connection so the next one reconnects. | `connect_to_a_silent_peer_fails_within_the_timeout`, `request_timeout_retires_the_connection_so_the_next_request_reconnects` (maki-crypto-websocket `review_hang.rs`) |
| C-06 | An RPC abandoned at the operation deadline never returned its inflight slot (a permanent drift in `endpoint_inflight`, deprioritizing the endpoint forever) and the deadline was charged to whichever endpoint happened to be in flight, opening its circuit. | Inflight is released by a drop guard; a deadline error is not an endpoint failure and charges nothing. | `deadline_abandoned_rpc_releases_inflight_and_does_not_charge_the_breaker` |
| C-07 | With `success_threshold` above `half_open_max_requests` (an accepted configuration) the breaker admitted one probe, counted its success and then admitted nothing ever again: a permanent stall on a single-endpoint volume. | Probe slots are returned when a probe completes; the bound applies to probes in flight. | `half_open_admits_new_probes_as_earlier_ones_complete`, `failed_probe_reopens_and_the_next_window_admits_again` |
| O-02 | **`maki-attach detach` with the packaged default (device on auto) disconnected the wrong device.** The detach plan carried the placeholder, the executor allocated the lowest *free* device for it and disconnected that, leaving the real device connected — and possibly racing another volume's attach, which held the lock while detach did not. | The executor records the bound device at attach; BUG-003 extends this to a trusted identity record under `/run/maki-attach/<volume>.nbd`. Detach resolves and verifies it under the attach lock before any side effects. | `detach_with_an_unrecorded_auto_device_is_unresolved_and_never_allocates` (maki-privileged) |
| O-04 | One `accept` error (EMFILE/ENFILE during a client burst) ended the control-socket loop and unlinked the socket for the rest of the daemon's life. | Accept errors are logged and retried after a short pause. | `accept_errors_do_not_kill_the_control_server` (maki-control, Linux, best effort) |
| O-05 / K-05 | Configuration accepted geometries the format layer cannot serve: a unit whose ciphertext exceeds the journal scanner's 16 MiB record bound (writes succeed, the first re-attach is refused as corrupt with the data intact), and shards with more than 2^32 units (the allocation map asserts on the first write). | `Geometry::compute` and validation refuse both. | `geometry_rejects_units_the_journal_or_allocation_map_cannot_hold`, `units_whose_ciphertext_exceeds_a_journal_record_are_rejected`, `shards_with_more_units_than_the_allocation_map_indexes_are_rejected` (maki-format) |
| O-07 | If `nbd-client` connected but the device did not become ready within the wait, the connect step was not recorded as executed and the rollback left the device connected; a retry connected a second device to the same volume. | The connect counts as executed as soon as `nbd-client` succeeds, so a readiness timeout rolls it back. | executor restructuring (Linux, root-only path; covered by the attach validation run) |
| O-08 | `docs/configuration.md` promised an `nbd.device_block_size` cross-check that did not exist; a mismatch made every kernel request fail alignment. | `nbd.device_block_size` is optional and, when set, must equal the volume's. | `nbd_device_block_size_must_match_the_volume` (maki-format) |
| O-09 | `maki reload <cfg> cache` could never succeed (the CLI sent no size) and the verb answered `ok` on a daemon running without a cache. | `maki reload <cfg> cache --max-bytes N`; the verb refuses when there is no cache to resize. | `reload_cache_without_a_cache_is_refused_not_silently_accepted` (maki-nbdkit, Unix) |
| O-10 | `AbStore::store` chose the side to overwrite by raw generation while `load` used the typed decode: a side that passes CRC but does not decode as the record type counted as newest, so the next store overwrote the only loadable copy. | The target side is chosen from the typed view; the generation still moves past every raw generation. | `ab_store_overwrites_the_side_that_does_not_decode_as_the_record_type` (maki-format) |

### Hygiene

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| C-02 | `SecretBuffer::drop` zeroized before unlocking, and zeroizing empties the vector, so `munlock` saw an empty range: with `memory_lock_mode = "secure-buffers"` every dropped buffer stayed pinned until `RLIMIT_MEMLOCK` made all later locks fail silently. | Originally unlocked before zeroize; BUG-006 now retains the original address range in a shared page-lock guard, zeroizes first, then releases the lock ownership. | `dropping_locked_buffers_releases_their_pages` (maki-crypto, Linux) |
| C-10 | `max_pending_crypto_items` took one permit per *request*, not per item. | Per-item permits. | `pending_item_limit_counts_items_not_requests` |
| C-11 | Resolved credentials (headers, query values, gRPC metadata, the mTLS private key, URL userinfo) lived in `#[derive(Debug)]` specs. | Manual `Debug` implementations redact values. | `spec_debug_output_redacts_credentials` (http), `spec_debug_output_is_redacted` (websocket) |
| K-09 | Plaintext left `SecretBuffer` into plain `Vec<u8>` on the read and write paths of the adapter. | `Engine::read_secret` returns a zeroizing buffer; the adapter copies from it and wraps incoming writes. | build (the daemon path only) |
| O-11 | The control socket existed with `0777 & ~umask` between `bind` and `chmod`. | `bind` runs under umask `0117`. | existing mode assertions |

The temporary umask approach for O-11 was replaced by private preparation and
atomic publication in BUG-014 above because a umask override also affected
unrelated threads and child processes.

The NBD maximum-I/O gap (O-03) and deadline starting only at dispatch (C-04
note) were subsequently fixed as BUG-011 and BUG-013 in the
[further reliability review](#further-reliability-review-2026-09-05).

Still documented as limits:

- The checkpoint worker can hold the volume lock for the duration of one
  checkpoint after the last engine handle is dropped (K-10).
- The accept-error test creates descriptor pressure in-process and is
  therefore best effort.

## Third review (2026-09-05): OS partial failure, device identity, memory ownership

The third external review (Korean, 2026-09-05) examined the source archive
of HEAD and rated the structure and test base sound while identifying where
the guarantees break at the operating-system boundary: partial I/O failures,
real device identity, and memory ownership. It listed one P0 candidate,
six P1 and three P2 findings (F01 to F10), and two smaller hardening items.
Every finding was confirmed against the tree (the review's line numbers
matched), reproduced by a failing test, and fixed in the same change; the
review's own verification limits (no Rust build, no NBD mount, no memory
dump) were closed by running the new tests, including the Linux-only ones
under WSL.

### Durability (P0 candidate and P1)

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| F01 | **A failed `fdatasync` was retried by calling it again.** Linux marks the dirty pages clean when writeback fails, so the retry succeeded without writing anything: the second FLUSH (or a later FUA) acknowledged records that never reached the disk, and recovery after a restart did the same for page-cache bytes (K-01 only synced them). | Same finding as BUG-021, whose implementation is the one in the tree: the writer fingerprints every record accepted since the last successful sync and, once a sync has failed, re-reads and rewrites that range in 64 KiB chunks, verifies the fingerprint, and only then syncs again; changed or lost bytes refuse the barrier. Recovery rewrites and verifies every accepted segment prefix before it syncs. `status`/`metrics` expose `journal_sync_failures_total` and `journal_writeback_uncertain`. `CrashableBacking` models the Linux behaviour by default (a failed sync loses its dirty writes but keeps them readable; `set_lenient_sync_failures(true)` restores the old model). | `review_writeback.rs` (maki-core): `flush_after_a_failed_sync_rewrites_lost_records_before_acknowledging`, `fua_after_a_failed_sync_covers_every_pending_record`, `seal_after_a_failed_sync_rewrites_before_opening_a_successor`, `barriers_keep_failing_until_the_rewrite_persists`, `recovery_rewrites_page_cache_bytes_it_accepts_after_a_failed_writeback`; `failed_sync_marks_dirty_writes_clean_and_lost` (maki-test-support) |
| F03 | **A partial `write_at` left a torn tail the next seal carried as corruption.** `write_all_at` can persist a prefix and then fail; the logical offset did not move, a shorter retry record did not cover the torn bytes, and the roll sealed the file at its physical length. Recovery treats a non-final segment as durable in full and refused the volume. | Same finding as BUG-020, whose implementation is the one in the tree: the writer marks the tail on any append failure and truncates the file back to the logical end before the next append or seal, keeping the flag until the truncation has been synced; while that truncation fails, appends, rolls and barriers fail too. The debug sanitizer asserts the file length equals the logical end. `CrashableBacking` gained a partial-write hook. | `partial_append_failure_leaves_no_garbage_for_the_next_seal`, `crash_right_after_a_partial_append_is_a_torn_tail`, `appends_are_refused_while_the_torn_tail_cannot_be_normalized` (maki-core); `partial_write_hook_persists_a_prefix_and_fails` (maki-test-support) |

### Security and operations (P1)

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| F02 | **The mount was verified by filesystem type, UUID, sentinel and probe, never by which block device it was on.** With `init_sentinel` the helper wrote the expected sentinel onto whatever XFS it had mounted (a local LV of the right name) and then verified its own sentinel: application data could land outside Maki in plaintext. | A new `verify-mount-device` step runs right after `mount`, before the sentinel or the probe touch the filesystem: the mount's `major:minor` is walked through the sysfs `slaves` relation (device-mapper, MD) down to the leaf devices, and every leaf must be the NBD device this attach connected (partitions fold into their device). Mixed volume groups and unresolvable topologies are refused. `verify_mount_identity` repeats the check. | `a_filesystem_not_stored_only_on_the_bound_nbd_device_is_refused_before_it_is_touched`, `leaf_devices_are_resolved_through_the_device_mapper_stack`, `mountinfo_parsing_exposes_the_device_number`, updated `init_sentinel_adds_a_write_step_before_verification` and `verifier_rejects_wrong_device_and_missing_sentinel` (maki-privileged). A real LVM-over-NBD run still needs the privileged Linux target. |
| F04 | **Locked secret buffers shared heap pages.** `mlock`/`munlock` work on whole pages with no reference count: dropping one `SecretBuffer` unlocked the page of a live neighbour, which still reported itself locked. | Same finding as BUG-006, whose implementation is the one in the tree: page ownership is reference-counted under the same lock as `mlock`/`munlock`, so a page is unlocked only by its last owner, after zeroization. | `dropping_a_buffer_never_unlocks_a_live_neighbours_pages` (`review_secret.rs`, Linux: every survivor's address must still sit in a `VmFlags: lo` VMA in `/proc/self/smaps`), `review_secret_page_lifetime.rs`, existing `dropping_locked_buffers_releases_their_pages` |
| F05 | **The secure-swap check passed unsafe layouts.** Any path containing `zram` counted as safe (`/var/swap/zram-backup`), an unreadable `/proc/swaps` read as "no swap", and a real zram device with a writeback `backing_dev` was assumed RAM-only. | Classification is by device identity: `/dev/zramN` exactly, with `/sys/block/zramN/backing_dev` equal to `none` (or absent) for RAM-only, a dm-crypt backing for encrypted, anything else unsafe; dm-crypt by device-mapper UUID as before. `/proc/swaps` must be readable and start with its header line or attach is refused. SPEC §37 and the configuration reference say so. | `swap_classification_never_trusts_a_name`, `zram_writeback_target_is_read_from_sysfs_not_assumed`, `unparseable_proc_swaps_is_an_error_not_no_swap`, updated `swap_parser_is_strict` (maki-nbdkit) |
| F06 | **A detach decided its device outside the attach lock.** `plan_detach` read the bound-device record before `execute` locked; a detach, re-attach (to another device) and another volume's attach in between left a stale plan that unmounted the current mount and disconnected the other volume's device. The record was also written before `nbd-client` ran and was not removed when a failed attach rolled back. | Superseded by BUG-003 and BUG-010: the planner never reads runtime state; the executor resolves the trusted record (configuration identity plus a unique kernel connection identifier) under the root-controlled lock, refuses a detach whose request or live backend does not match it, and verifies the identity again immediately before every disconnect, rollback included. | `exec_tests.rs`, `state_tests.rs`, `regression_attach_state.rs` (maki-privileged); the process interleaving itself needs the privileged Linux target |
| F07 | **`nbd.maximum_io` and the plaintext budget were not hard limits.** The byte semaphore capped an oversized request to the whole budget instead of bounding it, admission charged the request length while a partial write holds whole units, and the adapter copied the entire NBD request before admission. | The engine refuses any request above `max_request_bytes` (= `nbd.maximum_io`); at the NBD boundary the limits are advertised through the `block_size` callback and a request outside them is refused with EINVAL before its plaintext is copied (BUG-011, which replaced this pass's request splitting); admission charges every touched crypto unit in full (`Engine::admission_cost`); validation requires `limits.max_plaintext_bytes >= nbd.maximum_io + crypto_unit_size`. | `requests_above_the_configured_maximum_are_refused`, `admission_charges_every_touched_unit_in_full` (maki-core `review_limits.rs`); `review_nbd_limits.rs` (maki-nbdkit); a new case in `zero_and_inverted_bounds_are_rejected` (maki-format) |

### Hygiene (P2 and additional items)

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| F08 | `can_fua` returned 1, which is `NBDKIT_FUA_EMULATE` (nbdkit-common.h: NONE 0, EMULATE 1, NATIVE 2), so nbdkit emulated FUA with a full flush after every FUA write and the engine's native FUA path was never exercised in production. | `can_fua` returns `NBDKIT_FUA_NATIVE`; every `NBDKIT_*` constant is named once. `review_abi.rs` compiles a C probe against the installed `nbdkit-plugin.h` (API version 2) and compares every field offset of the mirrored struct, up to the `block_size` callback the prefix now covers (BUG-011), and every constant; CI's nightly job installs `nbdkit-plugin-dev` and runs it; WSL has the header installed. | `fua_is_advertised_as_native_not_emulated`, `declared_prefix_ends_after_the_block_size_callback` (unit), `shim_constants_and_layout_match_the_installed_header` (Linux, header 1.46.2) |
| F09 | The HTTP provider copied plaintext into plain vectors, JSON documents and request bodies that were never wiped, and parsed decrypt responses through plain buffers. | Every copy this crate makes is `Zeroizing`: payload copies, the serialized body (handed to reqwest through `Bytes::from_owner`, wiped when the body is released), the response body, decoded payloads; JSON documents are wiped in place after serialization or extraction. Copies inside reqwest, hyper, rustls and the kernel remain outside the crate's reach and are covered by the no-swap and no-core-dump posture, as documented. The WebSocket provider already sends slices; the gRPC provider's prost message copy remains a documented residual. | build (type changes) plus the existing provider conformance and chaos suites |
| F10 | Control sessions were unbounded: one task per connection, no idle or write deadline, and administrative verbs queued behind each other. | At most 64 sessions are served at once (the slot is taken before `accept`, so excess clients wait in the backlog); a session idle for 60 s or a client that does not drain a response within 10 s is closed; `checkpoint` and `reload` run one at a time and a concurrent one is answered `busy`. | `review_limits.rs` (maki-control): `idle_session_is_closed_after_the_idle_timeout`, `an_active_session_outlives_the_idle_timeout`, `a_client_that_never_reads_is_disconnected_after_the_write_timeout`, `concurrent_mutating_verbs_are_refused_with_busy`, `extra_sessions_wait_in_the_backlog_until_a_slot_frees` (Unix) |
| Backing paths | Lexical validation stopped `..` and absolute paths, but a symlink planted under the backing root redirected opens outside it. | No component under the root may be a symlink; Unix opens pass `O_NOFOLLOW`. | `symlinks_inside_the_root_are_never_followed` (maki-backing, Unix) |
| CI | The CI workflow ran without `--locked`, unlike the documented commands. | `--locked` on every CI cargo invocation; the nbdkit ABI check joined the nightly job. | the workflow |

Observability added for the operator (review item 5): `journal_sync_failures_total`
and `journal_writeback_uncertain` in `status` and `metrics`. Still open from
the review's recommendations: memory accounting for callbacks waiting in
admission (the adapter refuses anything above `maximum_io`, which bounds it
to one request per callback), lock-wait latency measurement, and the narrow
production profile (one geometry, one provider) that needs the Linux
qualification environment. The attach state machine with connection identity
the review asked for is BUG-003.

## Fourth pass (2026-09-05): specification contradictions and boundaries

A self-directed pass after the third review read the normative sections of
`SPEC.md` against the code and re-read the modules no review had covered
(overlay, slot store, cache, initialization, binaries). Every finding has a
failing test before its fix. IDs: N (new).

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| N-01 | **SPEC §8 contradiction: backing files and directories were created with the process umask** (`0644` / `0755` under the usual `022`), while the specification places the volume tree at `maki:maki 0700` and its files at `0600`. Ciphertext, metadata, the journal and the key canary were readable by every local user. | `FileBacking` creates directories with mode `0700` and files with `0600` regardless of the umask (existing entries keep their mode). | `created_directories_and_files_are_owner_only` (maki-backing, Unix) |
| N-02 | **SPEC §40 contradiction: most of the "required metrics" were absent** — active callbacks, plaintext bytes in flight, submission queue, inflight batches and bytes, per-endpoint inflight, crypto latency, retries, retry-budget tokens, circuit state, failover count, FLUSH and FUA latency. | The engine accounts admission usage and FLUSH/FUA latency (sum, count, max); the dispatcher accounts RPC latency and exposes per-endpoint budget tokens and global inflight; the scheduler counts inflight batches; the daemon hands the endpoint dispatcher to the control backend, whose `metrics` document now carries every name the specification lists (per-endpoint gauges as objects keyed by endpoint name, empty for local providers) and whose `status` lists each endpoint's circuit, validation, inflight and budget. | `every_spec_required_metric_is_reported_with_a_dispatcher`, `every_spec_required_metric_is_reported_without_a_dispatcher` (maki-nbdkit `review_metrics.rs`); `dispatcher_reports_latency_budget_and_inflight` (maki-crypto); `admission_usage_and_barrier_latencies_are_reported` (maki-core `review_state.rs`) |
| N-03 | **SPEC §13 contradiction: `nbd.preferred_io` defaulted to a fixed 4096**, not to the crypto unit; a volume with 8 KiB units advertised a 4 KiB preferred size. | `nbd.preferred_io` is optional and defaults to the crypto unit (raised to `nbd.minimum_io` when the unit is smaller, so the size ordering holds). | `preferred_io_defaults_to_the_crypto_unit` (maki-format) |
| N-04 | A journal whose sync had failed reported the volume `ready`: `maki_volume_state` said 1 while every FLUSH and FUA failed (SPEC §26 wants a persistence failure visible until it is resolved; the third review asked for a sticky, observable state). | The engine mirrors the journal's writeback-uncertain flag after every journal operation and reports `degraded` (with the reason) while it is set; a successful checkpoint does not clear it, only the barrier that rewrites and syncs does. | `a_failed_journal_sync_degrades_the_volume_until_a_barrier_succeeds` (maki-core) |
| N-05 | An engine request bound that is not a multiple of the device block size would be advertised as an NBD maximum no aligned request can reach exactly, failing every maximal request as invalid. | `Engine::attach` refuses a zero or non-block-multiple `max_request_bytes`. | `attach_refuses_a_request_bound_that_is_not_a_block_multiple` (maki-core) |
| N-06 | `maki status`, `metrics`, `checkpoint` and `reload` waited forever on a daemon that accepts but never answers (a stalled provider, a long checkpoint holding the volume lock). | Every control round trip is bounded: 60 s by default, 600 s for `checkpoint`, `--timeout <seconds>` to override; the failure names the socket and the bound. | `control_commands_time_out_against_a_silent_daemon` (maki binary, Unix) |
| N-07 | **SPEC §9 contradiction: a `file` credential was loaded whatever its permissions** — a world-readable key file, or a symlink to any file, was accepted as the "root-only secret file". | `FileKeySource` refuses a credential that is not a regular file or whose mode grants group or other access (`0600`/`0400` only; systemd's `LoadCredential` files are `0400`). | `group_or_world_readable_key_files_are_refused`, `a_symlink_or_special_file_is_not_a_credential` (maki-crypto-local, Unix) |
| N-08 | `backing.root` accepted a relative path, which resolves against nbdkit's working directory rather than the SPEC §8 layout. | Validation requires an absolute path. | two cases in `zero_and_inverted_bounds_are_rejected` (maki-format) |

Read and found consistent with the specification in this pass: the overlay's
latest/durable bookkeeping and byte accounting, the slot store's shard
creation protocol and read classification, the cache's version key and
eviction, volume initialization, the checkpoint triggers and inline ENOSPC
rules (SPEC §26), the per-unit concurrency and FUA/FLUSH sequences (§24, §25,
§28), the control socket's verb split (§7), and the secure-mount checklist
(§39). Known and documented deviations that remain: only the cache section is
hot-reloadable (§20 lists more); `madv_dontdump` is honoured through the
non-dumpable flag; FLUSH takes the volume's exclusive lock rather than an
append-ordered barrier (§25 describes the ordering, which the lock also
provides, at a concurrency cost the benchmark must quantify).

## Fifth pass (2026-09-05): A/B retry, breaker probes, packaging

A further pass over the A/B metadata store, the circuit breaker, the
dispatcher, the journal scanner, the deep checker, and the packaging
(systemd units, tmpfiles, sysusers) against SPEC §5, §7, §8 and §10.

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| N-09 | **The A/B store retried a failed sync on the wrong side.** After a failed `fdatasync` the new record stays visible in the page cache (F01), so the retry read that side as the newer generation and overwrote the *other* side, the only copy proven durable; a crash tearing that retry left one torn side and one side two generations old, losing metadata acknowledged as durable (checkpoint state, allocation maps, catalog, canary). | Same finding as BUG-001, whose preserve-first implementation is the one in the tree and **subsumes** N-09: before the stale side is overwritten the preserved (typed-valid) side's exact bytes are rewritten and synced, file and directory, so the durable copy is safe before the target is touched. N-09's own fix (emptying the side whose sync failed) was **removed** in the merge — it discards a newer generation and contradicts BUG-001's tests, which keep the failed side readable for a later store to preserve. | `review_ab_retry.rs` (maki-format, maki-core: failed data/directory sync, repeated retries and restart, sector tearing, writeback that loses dirty bits, preservation across metadata types, and recovery of durable volume data). The N-09-specific `review_ab.rs` was deleted as redundant with, and contradictory to, these. |
| N-10 | A half-open probe abandoned at the operation deadline (its RPC future dropped, C-06) never reported back, so its slot was never returned: `half_open_max_requests` abandoned probes wedged the circuit half-open forever, and a single-endpoint `bounded-error` volume with a slow provider stopped probing for good. | Same finding as BUG-004, whose implementation is the one in the tree: the dispatcher holds a generation-bound `BreakerPermit` whose drop returns the slot on every exit, verdict or not. | `review_probe_lifetime.rs` (maki-crypto) |
| N-11 | **Administrators could not reach the control socket.** systemd creates `/run/maki/<volume>` as `maki:maki`, and `/run/maki` was `maki:maki`, so a `maki-admin` member could not traverse to the `0660` socket (SPEC §7 group access); SPEC §8 even asked for `0700`, contradicting §7. | Same finding as BUG-009, whose layout is the one in the tree: control sockets live under a separate `root:maki-admin` `/run/maki-control` tree, NBD sockets stay behind `root:maki` `/run/maki`, and SPEC §8 says so. (This pass's daemon-side `chgrp` of the socket directory and the unit-level `UMask` were dropped: nbdkit resets its own umask, so the unit setting never governed the NBD socket.) | `regression_control_packaging.rs` (maki-nbdkit) |
| N-12 | The documented `maki volume create` flow produced a tree the daemon cannot open: run as root it created `/var/lib/maki/<volume>` owned by root (now `0700` after N-01), while `/var/lib/maki` (`root:maki 0750`) does not let the daemon user create it either. | The operations guide creates the directory for the daemon user and runs the command as that user; `maki volume create` warns when run as root. `/etc/maki/attach` and `/etc/maki/secrets` joined the tmpfiles layout. | documentation; the warning has no root-only test |
| N-13 | `control.socket` and `nbd.socket` accepted relative paths, which nbdkit and the helper resolve against their own working directories. | Validation requires absolute paths. | two cases in `zero_and_inverted_bounds_are_rejected` (maki-format) |

Read and found consistent: the retry budget (token bucket with the minimum
probe rate), the dispatcher's retry-safety and failover accounting, the
journal scanner's durable-prefix classification, the deep checker's use of
the real scanner and slot reader, and the attach helper unit's ordering
(`Requires=`/`After=` the daemon, `ConditionPathExists` on the attach config).

## Additional review (2026-09-05): eight further findings (BUG-015 … BUG-024)

A later external review of `1411ed5` listed eight defects that did not
overlap the earlier passes. Three of them were already closed on this branch
by fixes the merge with the third-to-fifth passes brought in, and were only
re-verified here; the other five were fixed. IDs follow the review (BUG-nn).

Already closed by the merged work (verified against the merged tree, not the
review's `1411ed5` baseline):

| ID | Finding | Where it is already handled |
|---|---|---|
| BUG-016 | Swap security trusted a device *name* containing `zram`, and an unreadable `/proc/swaps` read as "no swap". | F05: `zram_index` matches `/dev/zramN` exactly, classification is by device identity, and `parse_proc_swaps` refuses a file without the `Filename` header. `review_security.rs`. |
| BUG-019 | Attach never checked that the mounted LV is backed by the bound NBD device before writing the sentinel. | F02: the `verify-mount-device` step runs right after `mount`, before the sentinel or the probe, walking the sysfs `slaves` topology to the leaf devices. `review_priv.rs`, `phase7_priv.rs`. |
| BUG-023 | A symlink planted under the backing root redirected an open outside it. | The backing hardening: `resolve` rejects a symlink at *every* component under the root and opens pass `O_NOFOLLOW`. `symlinks_inside_the_root_are_never_followed` (maki-backing). |

Fixed in this change:

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| BUG-022 | **Journal reclaim could outrun the durability of the checkpoint state that authorized it.** A checkpoint-2 state whose sync failed could be read from the page cache after a restart, used to reclaim journal, and then lost to a power loss — leaving an older checkpoint whose covering segment was gone, so recovery refused to bridge. | Recovery re-persists the checkpoint state it selects (rewrite + sync, preserving the other valid A/B side first) before the writer resumes, and a failed A/B store already empties the side it could not sync (N-09), so a volatile newer generation is never adopted; either way a reclaim rests only on a durable checkpoint. | `journal_reclaim_never_outruns_checkpoint_state_durability` (maki-core `review_next_storage.rs`) |
| BUG-018 | **Grow ran `lvextend`/`xfs_growfs` with no trusted record and no attach lock**, so it could extend an LVM/XFS unrelated to any current attachment and race a detach. | `plan_grow` carries the attachment identity; the executor takes the attach lock for a grow and refuses one whose targets, or whose live NBD backend identity, do not match the trusted record before any command runs. | `review_next_grow_requires_trusted_attachment_before_commands`, `review_next_grow_rejects_reused_backend_and_changed_targets` (maki-privileged `exec_tests.rs`) |
| BUG-017 | **A gRPC server that stalled after the response headers, or between the message and the trailers, held the RPC open indefinitely** (`Channel::timeout` bounds only the connection), pinning the inflight slot and blocking that request's retry and failover. | The provider wraps readiness plus the unary exchange in one `tokio::time::timeout(spec.timeout, …)`; a timeout is a retryable error. The `bounded-error` outer deadline (BUG-013) still applies separately. | `a_stalled_grpc_response_is_bounded_by_the_transport_timeout` (maki-crypto-grpc `review_next_transport.rs`) |
| BUG-015 | **A clean `shutdown` stopped accepting but left live control sessions running**, each holding an `Engine` reference and so the volume lock; a detach that reported success left the volume `VOLUME_ALREADY_ATTACHED`. | Sessions run in a `JoinSet`; `serve_with_shutdown` aborts *and awaits* them on a shutdown signal, and the adapter signals then joins the serve task before releasing the engine, so no session outlives `shutdown`. | `shutdown_terminates_live_sessions_and_releases_the_volume_lock` (maki-nbdkit `review_next_control.rs`) |
| BUG-024 | **HTTP request JSON pointers were not RFC 6901-unescaped**, so a vendor field named `key/slot` (`/key~1slot`) was sent as the wrong field `key~1slot`; the response side already decoded with `Value::pointer`. | `pointer_set` decodes each reference token (`~1`→`/`, `~0`→`~`, in order) to match the response side. | `pointer_set_decodes_rfc6901_escapes`, `decode_pointer_token_matches_rfc6901_order` (maki-crypto-http, in-crate) |

## Deeper review pass (2026-09-07): two further findings (BUG-025, BUG-026)

A whole-codebase re-read (crypto flow control, core durability, control,
privileged, backing, local providers) plus four targeted review agents over
the daemon/config wiring, the remote providers, the format decoders, and the
privileged probes. The format decoders and the remote providers came back
clean; the other two surfaces each yielded one concrete finding. Both are
fail-*open*/availability gaps that contradict the project's fail-closed
stance, not data-loss bugs.

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| BUG-025 | **`resolve_leaf_devices` dropped an over-deep subtree instead of failing closed.** The F02 topology walk (`probe.rs`) skipped any node past `MAX_DEPTH` with a bare `continue`, so a branching sysfs `slaves` stack with a *foreign* leaf hidden below depth 16 resolved to just the shallow NBD leaf; `verify_mount_device` then passed on an incomplete picture and the helper wrote plaintext onto a filesystem partly backed by a non-Maki device. (Low reachability — building an 18-deep dm/MD stack needs `CAP_SYS_ADMIN`, which the untrusted tenant lacks — but a genuine fail-open contradicting its sibling walker `detach.rs::depends_only_on`, which errors on the same condition.) | Exceeding the depth bound now returns *no leaves*, so the caller refuses (empty `backing_devices` ⇒ `verify_mount_device` fails). A diamond (a device reached by two paths) is still merely not re-walked. | `an_over_deep_topology_resolves_to_no_leaves_not_a_partial_set` (maki-privileged `review_priv.rs`) |
| BUG-026 | **`crypto.batch.max_bytes` was never validated against the transport frame/message limit.** A whole batch is sent as one gRPC message / one WebSocket frame; a `batch.max_bytes` above `grpc.max_message_bytes` (default 4 MiB) or the base64-inflated `ws.max_frame_bytes` (default 8 MiB) validated cleanly but then failed *every* large batch at runtime with a non-retryable transport error (EIO to the client) on a volume that attached fine. A zero `max_message_bytes`/`max_frame_bytes` also passed (unlike HTTP's `max_response_bytes`). | `validate_provider_sections` now checks the batch fits: gRPC `batch.max_bytes ≤ max_message_bytes`, WebSocket `base64(batch.max_bytes) ≤ max_frame_bytes` (necessary bounds; the error advises leaving headroom for framing/JSON structure), and both limits must be positive. The default is a shared constant (`DEFAULT_WS_MAX_FRAME_BYTES`, `DEFAULT_GRPC_MAX_MESSAGE_BYTES`) used by both validation and the daemon wiring so a config that validates also runs. | `remote_transport_batch_must_fit_the_frame_or_message_limit` (maki-format `review_config.rs`) |

## Fast-checker / recovery drift (2026-09-07): BUG-027

The offline `maki check` fast path (`maki-format::checker::check_volume`) and
recovery/attach (`maki-core::store::SlotStore::open`) disagreed on one state, so
`maki check` could report "passed" on a volume `maki attach` would refuse — the
opposite of the tool's purpose (a green pre-attach check that then fails to
attach). Not a durability bug; a fail-*open* diagnostic gap.

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| BUG-027 | **`maki check` passed a volume `maki attach` would reject: a cataloged shard with a missing data file was only a warning when its allocation map was empty.** The fast checker errored on a missing data file *only* inside the `map.set_count() > 0` arm, then pushed an unconditional "data file not yet created" warning otherwise — so a cataloged shard with a valid but empty allocation map and no data file left the report error-free (`ok() == true`). `SlotStore::open`, though, opens every cataloged shard's data file with `create=false` regardless of its allocation map and returns `CoreError::Corrupt` if it is absent, so recovery refuses to attach. The "not yet created" state the warning described cannot arise for a *cataloged* shard: `ensure_shard` creates and `sync_dir`s the data file's dirent *before* the catalog names the shard (the reverse ordering only ever yields an orphan data file, which is adopted, not a cataloged shard with no file). | The missing-data-file check is a single unconditional error per cataloged shard, matching recovery, and the misleading warning is removed. `maki check` now fails exactly when attach would. | `fast_check_flags_a_cataloged_shard_with_no_data_file` (maki-core `review_check.rs`) |

## Supplementary review (2026-09-07): R01–R08

A follow-up review (`maki-review-20260907`) of the privileged attach/detach/grow
lifecycle, the crypto scheduler's admission accounting, and the journal hard
bound, with six proposed RED regression tests it could not compile in its own
environment. Each finding below was reproduced (RED) against the actual source,
fixed, and reverified (GREEN); the proposed tests were adapted to the real
fixtures. R05 also has a landed service-boundary fix. Findings needing a
native-Linux VM, an allocation observer, or peak-RSS experiments are scoped
under "Tracked, not closed in this pass" below rather than closed here.

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| R01 | **Attach rollback continued compensating even after an earlier step failed, and a command that failed *after* its effect was skipped.** After an attach failure the rollback ran every compensating step regardless of whether the previous one succeeded, so a failed umount did not stop the disconnect beneath it — the backing could be torn out from under a still-mounted filesystem. Separately, a command that reports failure after taking effect (a mount that mounted, a VG activation that mapped) never entered the executed prefix, so its compensation was skipped while a lower-level one still ran. | Rollback re-observes live state first and folds any effect that actually happened (mount, VG activation) into the compensation set in dependency order, and it **stops** at the first compensating failure rather than proceeding to the destructive step beneath it. Attach only — a failed detach is resumed, not rolled back. | `audit_20260907_failed_unmount_must_not_disconnect_live_mount`, `audit_20260907_mount_failure_after_effect_requires_reobservation` (maki-privileged `exec_tests.rs`) |
| R03 | **Grow trusted the saved config plus the NBD identity, not the current topology.** A correct stored record and a matching live NBD connection can coexist with a replaced mountpoint or a changed active VG mapping; the grow branch checked only `verify_connection`, then ran `lvextend`/`xfs_growfs` on the configured names. | Grow re-observes the live attachment (`verify_live_attachment`, sharing `verify_detach_state`'s mount/VG/leaf observation) and refuses on a foreign mount, a foreign VG, or an unreadable observation before any mutation, while still requiring the connection present. | `audit_20260907_grow_rechecks_live_mount_and_vg_topology` (maki-privileged `exec_tests.rs`) |
| R04 | **A single request larger than a lane's pending budget was admitted anyway, and `run_lane` took its first group without checking the batch maxima.** `DualSemaphore::acquire_n` clamps an oversized group's item/byte charge to the whole budget and serializes it, but the pending *stats* and the real allocations still counted the full group, so a two-item request slipped past a one-item pending budget. Separately, `run_lane` applied `max_items`/`max_bytes` only to *additional* groups, so a lone request above the batch maxima reached the provider whole. Positive-value config validation did not require the pending/inflight capacities to cover the configured maximum batch, so a config that validated could reject full batches at runtime. | The scheduler validates every request against the lane's admittable maximum (batch maxima capped by pending capacity) **before** copying the payload, and *rejects* an oversized one (it never splits a request; the reject charges nothing and copies no secret). Config validation now requires `max_pending_crypto_items ≥ batch.max_items`, `max_pending_crypto_bytes ≥ batch.max_bytes` (encrypt lane) and `max_ciphertext_bytes ≥ batch.max_bytes` (decrypt lane), so a validated config never rejects an in-spec request. | `audit_20260907_one_group_cannot_exceed_pending_budgets`, `audit_20260907_first_group_obeys_batch_maxima` (maki-crypto `review_scheduler.rs`); `audit_20260907_pending_capacity_must_cover_a_full_batch` (maki-format `review_config.rs`) |
| R05 | **A hung external command could hold the global attach lock indefinitely.** `Command::output` has no deadline, and systemd disables the *start* timeout by default for `Type=oneshot`, so a stuck `nbd-client`/`mount`/`umount` in one volume's helper would block every other volume's attach/detach/grow. | The packaged unit now sets a finite `TimeoutStartSec`/`TimeoutStopSec`, above the internal 15s NBD readiness wait plus expected XFS mount recovery, so systemd terminates a stuck helper and releases the lock; the next attempt re-observes actual kernel state. The finer in-process per-command deadline is tracked below. | `audit_20260907_attach_unit_bounds_a_hung_helper` (maki-privileged `regression_missing_attach_config.rs`) |
| R08 | **The journal hard limit counted record headers and payloads but not the 48-byte segment header an automatic roll creates.** With the on-disk total exactly at `journal_max_bytes` and the active segment full, admission's record-only check saw equality (not `>`), admitted the write, and the roll then pushed the on-disk total 48 bytes past the documented hard bound. Multiple rolls in one request could add several headers. | `JournalWriter::append_footprint` computes the exact bytes an append adds — records **plus** any new segment headers — by projecting `append`/`roll` step by step. `admit_journal` checks `journal_total_bytes + append_footprint` against the limit, recomputing the footprint after inline reclaim (reclaim can change the active segment). Record-byte accounting and the footprint share one `record_len` helper so they cannot drift. The `sustained_writes…` assertion was tightened from `+ SEGMENT + RECORD` slack to the strict bound. | `audit_20260907_journal_hard_limit_counts_new_segment_headers` and the tightened `sustained_writes_keep_journal_and_overlay_within_hard_limits` (maki-core `review_bounded.rs`) |

### Tracked, not closed in this pass

These findings from the same review need a native-Linux VM, an allocation
observer, or peak-RSS measurement — infrastructure the review itself calls for
and that WSL/CI simulation cannot substitute for. Each is scoped here so it is
not silently dropped; none is a data-durability defect.

- **R02 (P1) — mount target verified only after a read-write mount.** The plan
  activates the VG and mounts the LV read-write before `VerifyMountDevice`
  runs, and a read-write XFS mount can itself modify a filesystem (log
  recovery) before the post-mount check rejects it. The fix — resolve the
  LV device's PV/VG/LV identity and *all* backing leaves and confirm they are
  exactly the bound NBD device *before* the read-write mount, retaining the
  post-mount check — requires a device-path leaf probe (not the current
  mountpoint-based one) and must be qualified against a real dirty XFS in a VM
  (a rejected attach must perform no writes). Administrative accident-safety,
  not a privilege-escalation or plaintext-persistence path.
- **R05 in-process command deadline (P1).** The service-boundary timeout above
  is landed; the finer per-command deadline with bounded captured output and
  process-group cleanup/reaping (tested against a child that never exits, a
  descendant holding output pipes open, and a verbose child) is a careful
  systems change to root-privileged code that the review says to qualify in a
  VM before shipping.
- **R06 (P2) — WebSocket/gRPC make plaintext copies outside `SecretBuffer`.**
  The transports build JSON/Base64 strings and prost `Vec`s without explicit
  zeroization, and error/cancellation paths can drop decoded plaintext before
  it is wrapped. Closing this needs owned wire types with RAII zeroization and
  an allocation/deallocation observer to prove the lifetime; the review notes
  reading freed memory directly in a test is itself invalid, so a meaningful
  regression needs that observer harness first.
- **R07 (P2) — recovery memory grows with all uncheckpointed records.**
  Recovery collects every newer journal record before reducing them into the
  overlay, so a GiB-sized journal needs comparable scratch memory even when the
  live overlay is small. A streaming/two-pass replay that reduces into the
  overlay as it scans would bound this, but it touches the recovery ordering
  the release gates guard (second-crash-during-recovery, superseded-record
  validation); it needs peak-RSS measurement and the full ignored release
  gates, done deliberately, not folded into this pass.
- **Additional improvements.** `plugin.rs` cold-open initialization is not
  serialized (concurrent first opens can both attempt the exclusive volume
  lock); synchronous storage calls remain on async engine paths; the CI comment
  references a `docs/ci.md` and weekly/release tiers the uploaded workflow does
  not implement. These are availability/accuracy items, not correctness bugs.

## Comprehensive review (2026-09-07): MAKI-001–050

A 50-item review (`maki-review-2026-09-07`) spanning the privileged lifecycle,
crypto verification, durability, memory/scalability, performance, Docker
deployment, capacity, and qualification. The review compiled no Rust and marks
every item `runtime_reproduced: false`; most items are design constraints,
performance limits, deployment/ops gaps, or qualification work that need a
native-Linux VM, real databases, or measurement infrastructure. This pass
fixed the self-contained code defects with RED→GREEN regression tests; several
findings restate defects the earlier 2026-09-07 supplementary review already
closed.

### New code defects fixed this pass

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| MAKI-008 | **The nbdkit `unload` callback discarded a shutdown error** (`let _ = a.shutdown()`), so a failed final flush/checkpoint looked like a clean stop. | The error is recorded via structured tracing before `unload` returns (a void C callback cannot propagate it). No unit test — the C shim is covered by the ABI probe, not unit tests; the fuller shutdown-report feature is tracked below. | — |
| MAKI-010 | **The provider self-test sent all patterns in one batch**, rejecting a valid single-item or small-batch provider at attach. | The self-test splits every batch into capability-respecting RPCs (`batch_ranges`) in `provider_self_test`, `provider_conformance`, and `cross_endpoint_self_test`. | `self_test_splits_patterns_for_a_small_batch_provider` (maki-crypto `review_audit2.rs`) |
| MAKI-011 | **The tamper and context-binding self-tests accepted *any* error** as proof, so a provider that returns a transport error only on the tampered/moved request passed. | Both require a definitive bad-ciphertext rejection (`NonRetryableRequest` class); a transport/retryable error leaves the claim unproven and refuses attach. Context binding also accepts Ok-with-different-plaintext. | `self_test_rejects_integrity_proven_only_by_a_transport_error` (maki-crypto `review_audit2.rs`) |
| MAKI-016 | **gRPC/WebSocket embedded the remote error message verbatim** in an error, allowing log injection (newlines) or log flooding — unlike HTTP. | `maki_crypto::sanitize_external_message` (strips control chars, caps length) wraps both remote messages; the mapped error class is preserved. | `sanitize_strips_control_chars_and_caps_length` (maki-crypto), `map_status_sanitizes_remote_message` (maki-crypto-grpc) |
| MAKI-017 | **An unreadable zram `backing_dev` (EACCES/EIO) was classified RAM-only**, so an unencrypted writeback target could be trusted as safe swap. | `classify_zram_backing` keeps a missing attribute (NotFound) as RAM-only but fails closed (Unsafe) on any other read failure. | `zram_backing_read_failure_is_unsafe_not_ram_only` (maki-nbdkit `security.rs`) |
| MAKI-026 | **A corrupt small metadata file was read up to the 1 GiB common cap**, and `Superblock::decode` accepts its valid prefix. | Per-type `AbRecord::MAX_ENCODED_LEN` rejects an over-long copy by size before allocating (Superblock = one block, KeyCanary = header + max canary ciphertext). | `oversized_superblock_copy_is_rejected_before_it_is_read` (maki-format `review_format.rs`) |
| MAKI-027 | **A/B `store` incremented the generation with an unchecked `+ 1`** (panics in debug, wraps in release at u64::MAX). | `checked_add` fails closed with `FormatError::Invalid` on exhaustion. | `storing_at_max_generation_fails_closed_instead_of_wrapping` (maki-format `review_format.rs`) |

### Already closed by the 2026-09-07 supplementary review (R01–R08)

- **MAKI-001** (attach rollback disconnecting beneath a failed step) = **R01** — fixed (observation-reconciled, stop-on-failure rollback).
- **MAKI-002** (grow re-verifying live mount/VG) = **R03** — fixed (`verify_live_attachment`). MAKI-002 additionally asks for per-step re-checks of PV/VG/LV/FS UUIDs and the sentinel immediately before *each* of lvextend and xfs_growfs; that finer per-step identity re-observation is tracked below.
- **MAKI-004 / MAKI-005** (hung-command global lock; pre-mount device topology) = **R05 / R02** — R05's service-boundary timeout is landed; the in-process command deadline and the pre-mount identity probe remain tracked (see the R01–R08 "Tracked" section above).

### Tracked, not closed in this pass

Each needs a native-Linux VM, real DB/transport servers, an allocation
observer, peak-RSS measurement, or a careful on-disk/attach-flow redesign that
the review itself says to qualify before shipping. None is a newly-introduced
regression.

- **MAKI-009 (P0) — multi-endpoint self-test uses `Uuid::nil`, not the real volume UUID.** `dispatch_endpoint_set` runs its per-endpoint and cross-endpoint checks under a synthetic nil-UUID context before `Engine::attach` reads the superblock, so two endpoints keyed identically for nil but differently for the real UUID pass interchangeability. The fix reads the superblock's real UUID/profile/version first and validates every endpoint (individually and cross) under that context and the real key canary. It restructures the attach flow, and its mismatch-rejection acceptance test needs UUID-divergent transport servers (integration/VM), so it is not landed as an untested change to the crypto-verification path.
- **MAKI-003 (P1) — relative-size grow is not idempotent.** `lvextend -L +bytes` then `xfs_growfs`: a retry after a mid-grow failure can extend the LV twice. Needs a persisted grow op (id, original size, absolute target), observed LV/FS sizes, and skip-completed-steps logic in the privileged executor — VM-qualified.
- **MAKI-023 / MAKI-025 / MAKI-028 / MAKI-035 (memory & scalability)** — deep-check builds the full allocated-unit list; recovery accumulates every replay record; the overlay holds latest+durable+checkpoint ciphertext copies; resident bitmaps and the fallback scan bound large-volume RTO. Each needs streaming/paged redesigns and peak-RSS measurement against real target sizes.
- **MAKI-029 / MAKI-030 / MAKI-031 / MAKI-032 / MAKI-033 / MAKI-034 / MAKI-036 (performance)** — checkpoint under the exclusive lock, synchronous backing I/O on async threads, serial per-chunk crypto, plaintext admission vs. real copies, per-unit syscalls, full-shard bitmap rewrites, per-FUA flush. Design/measurement work, not correctness bugs.
- **MAKI-006 / MAKI-007 / MAKI-040 / MAKI-042 / MAKI-043 / MAKI-044 / MAKI-045 / MAKI-046 / MAKI-047 (deployment & ops)** — readiness vs. process start, a whole-stack recovery controller, a container mount-identity gate, the DB write-path encryption boundary, boot-dependency cycles, failure-domain isolation, backup/restore/key/format procedures, installable packaging, and the systemd credential drop-ins. These are packaging and operational designs to build and qualify on the target host.
- **MAKI-012 / MAKI-013 / MAKI-014 / MAKI-015 / MAKI-018 / MAKI-019 (crypto policy & security)** — the postgres-prod example permitting unauthenticated crypto, replay/rollback outside the threat model, WSS/gRPC TLS unimplemented, transport plaintext copies outside `SecretBuffer` (MAKI-015 overlaps R06), Maki-backed encrypted swap recursion, and the credential/endpoint/key-rotation runbook. Policy decisions plus an allocation observer for MAKI-015.
- **MAKI-020 / MAKI-021 / MAKI-022 (durability & space)** — the durable-mark-plus-final-segment ambiguity threat model, physical-space reservation/admission, and TRIM/deallocation. Durability-model and on-disk-format work requiring the release gates and power-loss campaigns.
- **MAKI-024 / MAKI-037 / MAKI-038 / MAKI-039 / MAKI-041 / MAKI-048 / MAKI-049 / MAKI-050 (observability, capacity, docs, qualification)** — deep-check grading vs. authenticated/recovery-view checks, thread-count config surfacing, remote-crypto I/O contract, lock-independent health, capacity/slot-span accounting, doc/CI drift, and the outstanding real-DB/power-loss/soak qualification and DB support matrix.

## Recovery fail-closed rules

Recovery (`maki-core/src/recovery.rs`) now refuses to attach on anything that
is not provably a crash artifact:

- **Bridging.** The oldest surviving segment must start at or before
  `checkpoint_sequence + 1`. A later base sequence means an uncheckpointed
  segment disappeared; internal contiguity of the survivors is no longer
  enough. (A missing *last* segment remains undetectable without additional
  metadata; the writer never acknowledges a record before the segment's
  directory entry is durable, so this needs external damage.)
- **Final-segment header.** A final segment shorter than a header, or entirely
  zero-filled, is a creation crash and is discarded. A complete header that
  fails magic, version, or CRC is durable damage.
- **Size cap.** A segment longer than `max_segment_file_size(segment_size)`
  is rejected before it is read into memory.
- **Durable mark.** After every successful segment fdatasync the journal
  writer records `(segment index, synced byte count)` in
  `journal/durable-mark` with a plain, unsynced write. The mark is only ever
  a lower bound. Recovery classifies damage *before* the mark as corruption
  even when it sits at the very end of the segment, and damage *after* the
  mark as a torn tail even when an intact record follows it. The second half
  matters: records after the last fdatasync may persist in any order, so a
  later unsynced record surviving while an earlier one is lost is a legal
  crash outcome, not corruption. Without a mark the scanner falls back to the
  previous heuristic (payload-CRC failure immediately followed by a valid
  successor is corruption).

## Key canary

`maki-format/src/canary.rs`, verified in `Engine::attach` after the provider
self-test:

- **Plaintext.** `canary_plaintext(volume_uuid, unit_size)`: the ASCII tag
  `MAKI-KEY-CANARY-V1` followed by a deterministic pattern derived from the
  volume UUID. Not secret; frozen by a golden vector because an old canary
  must verify forever.
- **Index.** `CANARY_UNIT_INDEX = 0x0010_0000_4D41_4B49`: above any unit a
  volume can address (attach refuses geometries that reach it) and below
  2^53 so JSON-carrying remote providers represent it exactly. Context-bound
  providers therefore bind the canary to an index no data unit uses.
- **Record.** `MAKICNY1 | version | generation | volume_uuid | unit_index |
  ciphertext_len | ciphertext | crc32`, A/B-replicated as `canary.a` /
  `canary.b` in the volume root and made durable (both copies plus the root
  directory) before attach returns.
- **Verification.** Decrypt through `CheckedProvider` and compare with the
  expected plaintext. Integrity, request, provider-fatal and contract errors
  mean "wrong key or provider" (`AttachError::KeyMismatch`); retryable,
  throttled and endpoint-fatal errors are surfaced as the transport errors
  they are.
- **Establishment.** Only on a pristine volume (no checkpoint, no journal
  record, no shard). A volume with data but no canary is probed by decrypting
  one existing unit when the provider declares integrity, and the canary is
  written after a successful probe; without integrity attach is refused
  (`AttachError::MissingCanary`), because an unauthenticated cipher cannot
  prove anything about an old key.

Operational consequences are in [Operations](operations.md#key-binding-at-first-attach).

## Bounded journal

`Engine` (`maki-core/src/engine.rs`) enforces `CheckpointPolicy`, which the
daemon derives from configuration:

| Policy field | Source | Effect |
|---|---|---|
| `journal_high_watermark_bytes` | `backing.journal_max_bytes / 2` | Write path wakes the worker once journal bytes on disk reach it; the worker checkpoints. |
| `journal_max_bytes` | `backing.journal_max_bytes` | Hard limit. A write that would cross it first syncs the journal and checkpoints inline (under the volume lock); if the journal still cannot fit the write, it fails with ENOSPC. |
| `max_pending_bytes` | `limits.max_journal_pending_bytes` | Appended-but-unsynced bytes; the write path forces a journal sync before exceeding it. |
| `emergency_reserve_bytes` | `backing.journal_emergency_reserve_bytes` | Writes fail with ENOSPC while backing free space is below it. Reads continue. |
| `low_space_checkpoint_bytes` | `backing.checkpoint_reserve_bytes` | The worker checkpoints eagerly while free space is below it. |
| `interval` | 30 s (engine default) | The worker syncs pending records and checkpoints at least this often while anything is unapplied. |

The worker holds only a weak reference to the engine and exits when the
engine is dropped. Free space is queried through `Backing::free_bytes`
(`statvfs` on Unix; unknown elsewhere and in the in-memory backings unless a
test sets it) and cached for one second of the engine's clock.

A checkpoint failure on any path increments `checkpoint_failures_total` and
sets `EngineState::Degraded { reason }`; the next successful checkpoint
returns the engine to `Ready`. The control socket reports the state in
`status` and as `maki_volume_state` (1 ready, 2 degraded).

## On-disk additions

All additions are new files; no existing structure changed, so the format
version stays at 1. Volumes created before these changes lack these files:

- `canary.{a,b}`: established on the next attach as described above.

- `checkpoint/state.{a,b}` are now written at creation and **required** by
  recovery. A pre-existing volume that was never checkpointed will fail to
  attach with `no valid checkpoint state copy`.
- `journal/durable-mark` is created empty at creation and recreated lazily by
  the writer if absent. Its absence only weakens corruption detection.
