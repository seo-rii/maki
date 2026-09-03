# Review remediation log

The independent code and architecture review dated 2026-09-02
(`maki-review-report.md`) rated Maki a strong alpha but a production **No-Go**,
and listed 18 findings (M-001 … M-018). This page tracks what has been done
about each one, in the review's own order. It is updated in the same commit as
the fix it describes.

Status values: **Fixed** (regression test landed and passes), **Partial**
(behaviour improved, remaining gap described), **Open**.

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
after segment numbering restarted under a stale durable mark). The final state
passes strict Clippy, the full debug workspace suite, and all seven
`phase*_gate_full` release gates on both Windows and WSL Ubuntu.

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
| M-005 control socket not started by the daemon; no-op reloads | Fixed | `NbdAdapter::open_config` binds the control socket (`control.socket`, default `/run/maki/<volume>/control.sock`) on the adapter's runtime before returning and serves `EngineControlBackend` on it; a bind failure fails attach; `shutdown` stops the server and removes the socket. `reload` returns an explicit "NOT applied" error for every section the engine cannot apply at runtime (`retry`, `circuit-breaker`, `batch`, `limits`, `timeouts`, `semaphores`, `endpoints`, `credentials`); only `cache` is applied, and it requires `max_bytes`. `status` reports the engine state, journal size, free space, and checkpoint counters. | `review_control.rs` (maki-nbdkit, Unix): `control_socket_is_created_served_and_removed`, `missing_control_socket_directory_fails_attach` |
| M-006 mount-identity verification is a no-op | Fixed | The Linux executor's `VerifyMountIdentity` step now gathers real observations (`/proc/self/mountinfo` fstype and source through the pure `parse_mountinfo`, `blkid` filesystem UUID, `<mountpoint>/.maki-sentinel`, sysfs NBD `pid` state, a write-fsync-read-remove probe) and runs the existing pure verifier; a failure rolls the attach back. The volume UUID comes from the root-owned attach config or `--uuid` and is required for execution (`--plan` still renders without it). `--init-sentinel` writes the sentinel on an empty filesystem, never overwriting a different value. The unit carries `ConditionPathExists` on the attach config and documents that dependents must `Requires=` it. | `mountinfo_parsing_finds_the_visible_mount_and_decodes_escapes`, `verifier_rejects_wrong_device_and_missing_sentinel`, `execution_requires_a_volume_uuid_but_plan_rendering_does_not` (maki-privileged); `plan_mode_works_without_uuid_but_execution_requires_it` (maki-attach process). Real mount/rollback runs need the privileged Linux target (`docs/privileged-linux-validation.md`). |
| M-009 A/B reader collapses I/O errors into "invalid copy" | Fixed | `AbStore` reports any I/O failure other than not-found as an error; empty, short, and CRC-invalid copies remain "invalid". `create_volume` writes both checkpoint-state copies (sequence 0) and recovery requires a valid copy on every volume instead of defaulting to 0. | `recovery_requires_valid_checkpoint_state`, `recovery_surfaces_hard_io_error_on_checkpoint_state`, `ab_load_reports_hard_io_errors_instead_of_masking_them`, `ab_load_treats_missing_empty_and_corrupt_sides_as_invalid_copies`, `create_volume_writes_checkpoint_state_and_durable_mark` |
| M-010 retry ignores `retry_safe`; no absolute deadline | Fixed | `DispatchConfig` carries `retry_safe` and `max_operation_time`. A non-retry-safe provider is sent a request at most once (no retry, no failover; the WebSocket transport's transparent reconnect-and-resend is disabled too). `bounded-error` is an absolute deadline measured on the injectable clock: backoff sleeps are capped to the remaining time and an in-flight RPC is abandoned when it expires (`deadline_exceeded_total`). Retry budgets are now endpoint-local (SPEC §32) instead of one bucket for the set. | `review_dispatch.rs` (maki-crypto): `non_retry_safe_provider_is_never_retried`, `retry_safe_provider_fails_over_within_the_pass`, `bounded_error_obeys_wall_clock_deadline_during_an_rpc`, `retry_backoff_never_sleeps_past_the_deadline`; `non_retry_safe_websocket_never_resends_after_a_transport_failure` (maki-crypto-websocket) |
| M-011 unvalidated endpoints enter the serving pool | Fixed | `EndpointSet::with_quarantine` admits only validated endpoints. At attach the daemon first probes each endpoint on its own (three attempts, spaced by the retry delay) so an unreachable *reference* can no longer poison the check, cross-validates the reachable ones against the first reachable endpoint, quarantines the rest, and refuses attach when nothing is reachable or an endpoint is proven non-interchangeable. A validator reruns the cross-endpoint check for quarantined endpoints against a validated one under the real volume context, at most once per breaker interval; proven non-interchangeability excludes the endpoint permanently. `endpoint_status()` exposes the flags. Retry budgets are per endpoint, charged only to repeat attempts on that endpoint. | `unverified_endpoint_never_enters_serving_pool`, `proven_incompatible_endpoint_is_excluded_permanently`, `capabilities_come_from_a_validated_endpoint` (maki-crypto) |
| M-012 reordered batch results undetected (WebSocket, positional HTTP) | Fixed | WebSocket response items must echo `unit` in request order (missing, reordered, duplicated, or wrong echoes are `Contract` errors); HTTP batch layouts require `item_index_path` at validation; gRPC already echoed `unit_index`. SPEC §18 now states the identity contract. | `ws_rejects_reordered_batch_items`, `ws_rejects_missing_unit_echo`, `ws_rejects_wrong_unit_echo`, `ws_accepts_correct_unit_echo` (maki-crypto-websocket); `http_batch_layout_requires_unit_echo` (maki-format) |
| M-013 incomplete configuration validation; placebo settings | Fixed | `validate_settings` and `validate_provider_sections` (see [Configuration](configuration.md#validation-rules)): positive counts and byte limits, finite ratios and probe rates, ordered delay and breaker ranges, batch targets within maxima, capability mode, bounded-error timing, NBD size ordering, cache and control values, memory-lock mode, provider-specific required and forbidden sections, endpoint URL parsing, and the `keyring` source refused. The `[security]` section is now applied by `maki_nbdkit::security::apply` before attach (Linux, fail closed): `disable_core_dump` via `prctl` + `RLIMIT_CORE`, `memory_lock_mode = "all"` via `mlockall`, `"secure-buffers"` via per-`SecretBuffer` `mlock` (opt-in in `maki-crypto`, failures counted), `require_secure_swap_policy` via `/proc/swaps` plus dm-crypt detection; `madv_dontdump` is honoured through the non-dumpable flag and validation refuses it without `disable_core_dump`; `cache.lock_memory` follows the lock mode and validation refuses it with `off`. The posture is reported under `security` in `status`. Non-Linux hosts report `unsupported-platform`. The secure-swap policy defaults to off (explicit production opt-in; the shipped example enables it). | `review_config.rs` (maki-format): `zero_and_inverted_bounds_are_rejected` (28 cases), `capability_mode_and_availability_policy_are_checked`, `keyring_credential_source_is_refused`, `local_provider_requires_key_and_rejects_transport_sections`, `duplicate_or_empty_endpoint_names_are_rejected`, `defaults_still_validate`; `review_security.rs` (maki-nbdkit): `inconsistent_security_settings_are_rejected_at_validation`, `swap_parser_is_strict`, `posture_is_recorded_and_reported`, `linux_disables_core_dumps_for_real` (Linux); `page_locking_is_opt_in_and_accounted` (maki-crypto) |
| M-014 production sample cannot attach | Fixed | `packaging/examples/postgres-prod.toml`, the SPEC §57 example, and the `full_config.toml` fixture now carry complete `[crypto.http.encrypt]` / `[crypto.http.decrypt]` batch mappings with unit echo and a credential-referenced bearer token; validation requires both mappings for `remote-http`. | `production_sample_and_full_fixture_validate`, `remote_http_requires_endpoints_and_both_mappings` (maki-format); `production_sample_builds_provider_successfully`, `production_sample_fails_without_its_credential` (maki-nbdkit `review_sample.rs`) |
| M-015 WebSocket / gRPC without TLS | Fixed | Validation refuses plaintext `http://`, `ws://`, and gRPC `http://` endpoints unless the host is loopback, refuses `wss://` / gRPC `https://` / transport TLS sections as not compiled in, and rejects URL userinfo. The HTTP provider fails closed on unreadable or invalid CA and client-certificate files, applies `client_key` from its credential source, and refuses `server_name` instead of ignoring it. The daemon's credential router reads path-like names as files. | `plaintext_transports_are_loopback_only`, `websocket_and_grpc_require_their_sections_and_reject_tls`, `tls_files_must_exist_and_server_name_is_refused`, `endpoint_url_parsing_and_loopback_detection` (maki-format); `unreadable_tls_material_refuses_the_provider`, `client_key_credential_is_appended_to_the_identity` (maki-nbdkit) |
| M-016 privileged attach: allocation, rollback, config-driven execution | Fixed | `maki_privileged::config` loads `/etc/maki/attach/<volume>.toml` (`packaging/examples/attach.toml`) and applies argument hygiene to every value (no option-like values, canonical absolute paths, LVM name charset, UUID shape). The plan carries the block size into `nbd-client -b` and `blockdev --setbsz`, and can leave the NBD device as `/dev/nbd<auto>`: the executor allocates the lowest free device from sysfs under `/run/maki/attach.lock`, binds it into every step, and waits for readiness after connect. `rollback_steps` derives the compensating steps for the executed prefix and the executor runs them in reverse on any failure, reporting rollback failures. | `config_resolves_defaults_and_auto_device`, `overrides_win_and_are_validated`, `argument_hygiene`, `attach_plan_binds_the_allocated_device_everywhere`, `nbd_connect_uses_the_configured_block_size`, `init_sentinel_adds_a_write_step_before_verification`, `rollback_reverses_the_executed_prefix`, `free_nbd_allocation_picks_the_lowest_unconnected_device` (maki-privileged); `option_like_values_are_rejected_before_planning`, `attach_config_drives_the_plan` (maki-attach process) |
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
| O-02 | **`maki-attach detach` with the packaged default (device on auto) disconnected the wrong device.** The detach plan carried the placeholder, the executor allocated the lowest *free* device for it and disconnected that, leaving the real device connected — and possibly racing another volume's attach, which held the lock while detach did not. | The executor records the bound device at attach under `/run/maki/attach/<volume>.nbd`; a detach uses the record, refuses to run with an unresolved device, and takes the attach lock. | `detach_with_an_unrecorded_auto_device_is_unresolved_and_never_allocates` (maki-privileged) |
| O-04 | One `accept` error (EMFILE/ENFILE during a client burst) ended the control-socket loop and unlinked the socket for the rest of the daemon's life. | Accept errors are logged and retried after a short pause. | `accept_errors_do_not_kill_the_control_server` (maki-control, Linux, best effort) |
| O-05 / K-05 | Configuration accepted geometries the format layer cannot serve: a unit whose ciphertext exceeds the journal scanner's 16 MiB record bound (writes succeed, the first re-attach is refused as corrupt with the data intact), and shards with more than 2^32 units (the allocation map asserts on the first write). | `Geometry::compute` and validation refuse both. | `geometry_rejects_units_the_journal_or_allocation_map_cannot_hold`, `units_whose_ciphertext_exceeds_a_journal_record_are_rejected`, `shards_with_more_units_than_the_allocation_map_indexes_are_rejected` (maki-format) |
| O-07 | If `nbd-client` connected but the device did not become ready within the wait, the connect step was not recorded as executed and the rollback left the device connected; a retry connected a second device to the same volume. | The connect counts as executed as soon as `nbd-client` succeeds, so a readiness timeout rolls it back. | executor restructuring (Linux, root-only path; covered by the attach validation run) |
| O-08 | `docs/configuration.md` promised an `nbd.device_block_size` cross-check that did not exist; a mismatch made every kernel request fail alignment. | `nbd.device_block_size` is optional and, when set, must equal the volume's. | `nbd_device_block_size_must_match_the_volume` (maki-format) |
| O-09 | `maki reload <cfg> cache` could never succeed (the CLI sent no size) and the verb answered `ok` on a daemon running without a cache. | `maki reload <cfg> cache --max-bytes N`; the verb refuses when there is no cache to resize. | `reload_cache_without_a_cache_is_refused_not_silently_accepted` (maki-nbdkit, Unix) |
| O-10 | `AbStore::store` chose the side to overwrite by raw generation while `load` used the typed decode: a side that passes CRC but does not decode as the record type counted as newest, so the next store overwrote the only loadable copy. | The target side is chosen from the typed view; the generation still moves past every raw generation. | `ab_store_overwrites_the_side_that_does_not_decode_as_the_record_type` (maki-format) |

### Hygiene

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| C-02 | `SecretBuffer::drop` zeroized before unlocking, and zeroizing empties the vector, so `munlock` saw an empty range: with `memory_lock_mode = "secure-buffers"` every dropped buffer stayed pinned until `RLIMIT_MEMLOCK` made all later locks fail silently. | Unlock before zeroize. | `dropping_locked_buffers_releases_their_pages` (maki-crypto, Linux) |
| C-10 | `max_pending_crypto_items` took one permit per *request*, not per item. | Per-item permits. | `pending_item_limit_counts_items_not_requests` |
| C-11 | Resolved credentials (headers, query values, gRPC metadata, the mTLS private key, URL userinfo) lived in `#[derive(Debug)]` specs. | Manual `Debug` implementations redact values. | `spec_debug_output_redacts_credentials` (http), `spec_debug_output_is_redacted` (websocket) |
| K-09 | Plaintext left `SecretBuffer` into plain `Vec<u8>` on the read and write paths of the adapter. | `Engine::read_secret` returns a zeroizing buffer; the adapter copies from it and wraps incoming writes. | build (the daemon path only) |
| O-11 | The control socket existed with `0777 & ~umask` between `bind` and `chmod`. | `bind` runs under umask `0117`. | existing mode assertions |

Not fixed, documented as limits:

- **O-03: `nbd.maximum_io` is neither advertised nor enforced.** The plugin
  publishes only the nbdkit v2 callback prefix, so clients never learn the
  configured maximum and the kernel sends up to its own `max_sectors_kb`
  (32 MiB, 64 MiB for libnbd). `validate_journal_bounds` sizes the journal
  headroom from `maximum_io`, so a minimal configuration can leave a very
  large request unable to fit after an inline reclaim and it fails with
  ENOSPC (EIO to the filesystem). The fix is advertising `.block_size`
  through the nbdkit ≥ 1.30 plugin struct, which this environment cannot
  compile or test; until then size `backing.journal_max_bytes` for the
  largest request the client can issue, not for `nbd.maximum_io`.
- The scheduler's operation deadline starts when a batch is dispatched, not
  when the request is queued (C-04 note).
- The checkpoint worker can hold the volume lock for the duration of one
  checkpoint after the last engine handle is dropped (K-10).
- The accept-error test creates descriptor pressure in-process and is
  therefore best effort.

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
