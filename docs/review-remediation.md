# Review remediation log

The [independent code and architecture review dated 2026-09-02](qualification/historical-reviews/external-review-2026-09-02.md)
rated Maki a strong alpha but a production **No-Go**,
and listed 18 findings (M-001 … M-018). This page tracks what has been done
about each one, in the review's own order, and records subsequent reviews and
their regression evidence.

These dated sections preserve the findings and evidence from each review
pass. For current support and limits, use [Status](status.md). The
[R3 readiness record](qualification/historical-reviews/production-readiness-review-2026-09-08.md)
is the historical record of that review.
Later fixes can supersede an older section's remaining-work list. The
[2026-10-15 boundary follow-up](review-boundaries-2026-10-15.md) distinguishes
proposed PR fixes from remote-main changes and combined qualification.

Status values: **Fixed** (regression test landed and passes), **Partial**
(behaviour improved, remaining gap described), **Open**.

## Internal audit, third round (2026-11-17): AUD-091–AUD-097

A third internal audit, also of `main` at `5a65e96`, reviewed the second
round's pull requests from their branches and covered the NBD adapter and its
native shim, release-build arithmetic, engine concurrency (a linearizability
oracle, FLUSH/FUA crash sweeps and admission fairness), the operator CLI and
packaged units, and the witness service. The adapter, release-arithmetic and
concurrency reviews found no defect. Four pull requests,
[#186](https://github.com/seo-rii/maki/pull/186) to
[#189](https://github.com/seo-rii/maki/pull/189), fixed its findings and were
merged into `main` on 2026-11-17. #186 completes AUD-060. The verify gate's permission limit that
#187 adds to the privileged-helper section is recorded with AUD-086, and a
root run recreating a missing `volume.lock` is in the second round's open
list. One finding needed no change of its own: parsing the request of a
client the allow-list does not name (AUD-077) reached the patched serde_json's
error-position parsing, whose cost AUD-070 makes linear, and both are merged.
Every code fix landed test-first. AUD-096 and AUD-097 correct documentation;
all rows are **Fixed**. AUD-094 and AUD-095 refuse input that was accepted
before (a `MAKI_LOG` directive without a level, `--timeout` on a command
without a control round trip). No change alters the on-disk format.

#186, #188 and #189 report Linux debug runs, in isolated build directories, of
the changed crates' suites and the dependents that exercise the change,
strict Clippy and `cargo fmt --check`, with mutation checks; #186 also ran the
test targets it shares with #185 on a tree merged with that branch. #187
checked `systemd-analyze` (systemd 255) against the packaged units in an
offline root and ran the documentation tests. No systemd service, real
nbdkit, NFS export or WORM storage was exercised.

### Durability and recovery

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-091 | AUD-060's classification of an adopted shard still counted the positions of a partial last shard at or past the device's last unit, which name no unit: the store never sets them, and `allocated_units()`, `unlisted_units()` and the truncation marks already skip them (R5-027). A CRC-valid map whose only set bits lay there made a never-written short orphan truncated: with seven units, five per shard and a zero-length data file for shard 1, a map listing only its position 2 or 4 made the deep check report units 5 and 6 as damage and attach return EIO for them. | `SlotStore::open` decides whether an adopted shard's map lists a slot from its in-device positions only, the bound `allocated_units()` uses, and the truncation-marking loop shares that bound. Bits past the device's end stay in the map as found; nothing reads them. | `positions_past_the_device_end_do_not_make_a_never_finished_shard_truncated` (maki-core `review_adopted_shard_padding.rs`); the control `a_listed_unit_still_makes_a_short_orphan_truncated` now covers the partial last shard | [#186](https://github.com/seo-rii/maki/pull/186) |

### Witness and rollback protection

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-092 | A local remote-witness authority (`maki-witness serve` with `state_dir`) publishes each change by writing and syncing `remote.next`, renaming it over `remote.state` and syncing the directory, and any failure of those steps poisoned the open store. A failure before the rename (EMFILE from a flood of connections waiting for TLS, or a transient ENOSPC or EIO while opening, writing or syncing `remote.next`, during a FLUSH's Advance for example) leaves `remote.state` byte for byte as published, yet every later request, Inspect included, was answered "remote witness state uncertain; reopen required" (`Unavailable`) until the process was restarted. `serve` kept running and logged nothing, so every volume using the witness refused reads, writes and FLUSHes until an operator noticed. | Publication is split into a stage (write and sync `remote.next`) and a commit (rename and directory sync). A failed stage fails only its request: the published state and the in-memory copy still agree, nothing reads `remote.next` as state, and the next stage truncates and rewrites all of it through a new descriptor, so bytes a failed write or sync left are never synced as they are. A failed commit still poisons the store until a reopen re-publishes the state it reads, because a failed rename may have happened and a failed directory sync leaves the new name visible but not durable; opening a store still refuses any publication failure. **Not changed:** `serve` does not exit when its store is poisoned. No packaged unit runs it, and a poison also records a `remote.state` changed behind the server's back, where an automatic restart would serve whatever valid state the file then holds; the [witness service guide](remote-witness-service.md#initialize-a-local-authority) says which failures need a restart and that such a change must be investigated first. | `a_publication_failure_before_the_rename_refuses_only_that_request` (maki-backing `remote_witness.rs`: failures opening, writing a prefix of and syncing `remote.next`) and `a_reopen_after_a_failure_before_the_rename_serves_the_published_state`; the pinned test, now `an_uncertain_publication_poisons_and_reopen_resolves_exact_old_or_new`, is narrowed to failed renames and directory syncs and keeps its assertions | [#189](https://github.com/seo-rii/maki/pull/189) |
| AUD-093 | `maki volume restore` and `RollbackBacking::restore_remote` only read the snapshot, but they opened its marker, `snapshot.json`, manifests and arena read-write and took its operation lock read-write, creating the file if missing. A snapshot kept where nothing can change it (a read-only mount, immutable files, a read-only export, files the administrator may not write) therefore failed with EROFS, EPERM or EACCES before the authority was asked anything. | A new `FileBacking::read_only` view opens an existing root without creating, probing or syncing anything, opens files read-only with the same no-follow, regular-file and single-link checks, and fails every change with `ReadOnlyFilesystem`; restore and the command's `snapshot.json` read go through it. Restore takes the snapshot's `remote.operation.lock` shared through a read-only descriptor. Every operation that changes a root (create, open, takeover, snapshot, GC) still takes that lock exclusively, so they stay excluded while the snapshot is read, and concurrent restores may now share one snapshot. The restore target keeps every check and its exclusive lock, and everything read from the snapshot is still authenticated against the approved descriptor. | maki-backing `review_restore_read_only_source.rs`: `restore_reads_a_snapshot_it_may_not_write`, `restore_reads_a_snapshot_on_a_read_only_mount`, `restore_reads_an_immutable_snapshot` (the last two need root and skip with the reason otherwise), `restore_refuses_a_snapshot_another_operation_holds`; `restore_reads_a_snapshot_it_may_not_write` (`bins/maki` `remote_admin.rs`, the CLI) | [#189](https://github.com/seo-rii/maki/pull/189) |

### Logging and command line

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-094 | `MAKI_LOG` is documented to mean `info` when unset or invalid, but a word that is not a level (`warning`, `err`, `notice`, a typo such as `wran`) is a valid `EnvFilter` directive: that target at trace and every other target off. The fallback never ran, and the plugin, `maki`, `maki-check` and `maki-attach` dropped every event of their own, ERROR included: checkpoint and journal-sync failures, a stopped control server, a panic at the NBD boundary, a halted rollback. An empty value (`Environment=MAKI_LOG=`) built a filter that enables nothing. | Both log sinks check `MAKI_LOG` before handing it to `EnvFilter`: every comma-separated directive must be a level or end in `=<level>`, a value with no directive means `info` like an unset one, and any invalid value (no level, an unknown level, a syntax error, non-UTF-8) falls back to `info`. Installing the sink then logs one `WARN` line, "MAKI_LOG is not a valid filter", with a fixed reason and the 1-based index of the failed directive, never the value or the parser's error text, which can hold user data such as span-field selector values. `maki-privileged` carries its own copy of the check, so it still links no crypto crate. **Behaviour change:** a bare target such as `MAKI_LOG=maki_core`, which meant that target at trace and everything else off, now falls back to `info` with the warning; `maki_core=trace` selects one target. | `a_maki_log_value_without_a_level_falls_back_to_info_and_says_so`, `an_empty_maki_log_means_info_like_an_unset_one` and `invalid_filter_diagnostics_never_expose_selector_values` (unit tests in `crates/maki-core/src/logging.rs` and `crates/maki-privileged/src/logging.rs`); `a_maki_log_value_that_is_not_a_level_keeps_warnings_and_says_so` (`bins/maki` `review_log_filter.rs`) | [#188](https://github.com/seo-rii/maki/pull/188) |
| AUD-095 | `maki` removed `--timeout <seconds>` from every command line before choosing the command, so `maki volume create`, `inspect` and `witness` and `maki check` accepted the option and ignored it (`maki volume create <config> --timeout 5` created the volume and exited 0), while `maki check <config> --timeout 0` failed on the value of an option `check` never uses. | `maki` finds the command word before it parses `--timeout`: only `status`, `metrics`, `checkpoint`, `drain` and `reload` take it, and every other command refuses it with the usage and exit status 2, whatever its value. A leading `--timeout` before `attach`, `detach` or `grow` keeps the existing delegation route. The operations guide and the usage text name the commands that take it. | `commands_without_a_control_round_trip_refuse_timeout`, `control_commands_keep_applying_timeout` (`bins/maki` `review_control_timeout_scope.rs`) | [#188](https://github.com/seo-rii/maki/pull/188) |

### Documentation

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-096 | A remote restore runs automatic GC right after activation, and activation clears the record's restore source, so GC retires every lower-fence namespace whose lock is free. With the daemon stopped, as the procedure requires, that includes the namespace holding the newer state the restore replaces: the restore deletes that state from the backing root. Neither the restore procedure nor the rollback-protection summary said so. | Documentation only: the [remote witness guide](remote-witness-service.md#snapshot-takeover-and-restore) warns before the restore command that the deletion cannot be undone from the backing root, that a handle still open only postpones it and that the source snapshot stays in its backup directory. It says to snapshot the newer state first if it may be needed again (that snapshot raises the fence, so the restore must use the fence from a new inspection) and, if the current generation does not authenticate, to keep a copy of the stopped backing directory. Checked with a throwaway test on the `remote_rollback.rs` fixture, not committed. | — | [#187](https://github.com/seo-rii/maki/pull/187) |
| AUD-097 | The Debian installation guide said `systemd-analyze verify` reports the missing `/etc/maki/attach/demo.toml` assertion of `maki-attach@demo.service`, but `verify` does not evaluate `Assert*=` settings; the data-plane readiness section said `maki-attach@` waits for `READY=1` through `Requires=`, but the unit uses `BindsTo=`; and the quick start's cleanup left `/srv/demo`, so following it a second time on the same host stopped at the bootstrap's new-mountpoint guard. | Corrected: the guide says `verify` does not cover the assertion and names `systemd-analyze condition --unit=maki-attach@demo.service`; the readiness section names `BindsTo=`; the cleanup runs `rmdir /srv/demo` after every unit is inactive and before anything is deleted, so a mount left behind stops it. | — | [#187](https://github.com/seo-rii/maki/pull/187) |

### Not closed in this pass

- After a failed rename or directory sync of its state, a local witness
  authority answers every request as unavailable until it is restarted, and
  `serve` does not exit by itself; no packaged unit runs or restarts it
  (AUD-092).
- A restore from a snapshot that lacks its `remote.operation.lock` still
  creates that file, which needs write access to the snapshot directory
  (AUD-093).

## Internal audit, second round (2026-11-17): AUD-052–AUD-090

A second pass closed most of the gaps the
[first pass](#internal-audit-2026-11-16-aud-001aud-051) left open and fixed
the findings of a second internal audit of `main` at `5a65e96`, which contains
the first pass. That audit reviewed the merged durability, transport and
configuration fixes, fed CRC-valid but inconsistent metadata to recovery and
the deep check, ran randomized engine and rollback sweeps, and read the
operator documentation and the vendored parser. Sixteen pull requests,
[#170](https://github.com/seo-rii/maki/pull/170) to
[#185](https://github.com/seo-rii/maki/pull/185), were merged into `main` on
2026-11-17: #170 to #177 close items of the first pass's open list and gaps
found while fixing them, and #178 to #185 fix the audit's findings. Every code
fix landed test-first: its commit message and pull request name the
regression that failed before the change. AUD-064 and AUD-065 strengthen
tests that could not fail and add a missing one; AUD-081 and AUD-083 to
AUD-090 correct tooling and documentation. AUD-061 and AUD-062 record decoder behaviour a pull request
examined and deliberately kept; every other row is **Fixed**. Four rows
change documented behaviour: AUD-054 relaxes the
[fail-closed rule](#recovery-fail-closed-rules) for a final segment's header,
AUD-056 makes recovery refuse a volume whose counters leave no room for one
more record or segment, AUD-059 makes a lost key canary a deep-check error
only where attach must refuse, and AUD-068 lets a request that is not
retry-safe fail over, and under `stall` wait, while none of its attempts was
sent. The list after the tables records what remains open. No change alters
the on-disk format or the golden vectors. The operator-visible refusals are
listed in the [changelog](../CHANGELOG.md#breaking-changes).

The pull requests report Linux debug runs, in isolated build directories, of
the changed crates' suites, the dependents that exercise the change, strict
Clippy, `cargo fmt --check` and the documentation link checker. The
crash-model, worker, journal, codec and recovery changes (#175, #176, #177,
#184, #185) also ran maki-core's ignored release gates one at a time (#185
all eight), #174 the maki-crypto phase 5 gates, and #182 the rollback
write-cost gate in release. Most code fixes also report mutation checks: the
new tests fail when the fix is removed or weakened. #185 also ran a CRC-valid
metadata mutation sweep over 2,438 volumes: on `main` the deep check passed 41
that recovery refused, 16 attached and then failed a write, a checkpoint or a
second recovery, and 57 served zeros or older data; with the fix the counts
are 0, 0 and 7, the 7 being checkpoint raises at or below the durable proof's
horizon (see the open list). These are repository tests with simulated
devices, local sockets, private mount namespaces and test authorities; no
kernel NBD/LVM/XFS stack, systemd unit, vendor endpoint or physical power loss
was exercised.

### Durability and recovery

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-052 | Every worker pass syncs before it checkpoints, but after a failed sync only a pass started by the journal watermark or by low free space still checkpointed the records that were already durable (AUD-005). A pass started only by the interval, the overlay watermark or a write refused for backing space deferred by one interval and returned, so while every journal sync failed those passes never applied durable records, deleted the sealed segments they cover or shrank the overlay. | A failed sync does not advance the durable mark and a checkpoint applies only records at or below it, so every worker pass now checkpoints after a failed sync when there is something to do without it (durable records above the checkpoint, covered segments, pending cleanup or a due reclamation); otherwise it returns without an empty checkpoint. BUG-101's one-interval retry deferral is kept, and the inline reclaim still refuses its write when its sync fails. | maki-core `review_watermark_volatile_tail.rs`: `interval_pass_reclaims_durable_segments_while_journal_sync_fails`, `overlay_pass_reclaims_durable_records_while_journal_sync_fails`, `refusal_pass_reclaims_durable_segments_while_journal_sync_fails` | [#176](https://github.com/seo-rii/maki/pull/176) |
| AUD-053 | The journal-size trigger compared all journal bytes on disk with the watermark, but a checkpoint never deletes the active segment. With a watermark at or below the segment size the active segment alone kept the journal above it, so every write above the watermark woke the worker into a journal sync and a checkpoint that gave nothing back. Validation keeps the watermark (half of `journal_max_bytes`) above one segment, so only an engine configured directly reached this. | The trigger, and the write path's wake-up of the worker, also require a sealed segment on disk, so a low watermark costs one pass per sealed segment. Three tests that used such a watermark only to wake the worker on every write (`review_checkpoint_backoff.rs`, `review_blocking_io.rs`, the volatile-tail watermark case) now seal a segment per write. | `watermark_below_the_segment_size_checkpoints_once_per_sealed_segment` (maki-core `review_watermark_active_segment.rs`) | [#176](https://github.com/seo-rii/maki/pull/176) |
| AUD-054 | A final journal segment exactly one header long whose header fails its checksum still refused attach, after a plain restart too, and the deep check reported it as damage. Writers before AUD-003 extended a new segment to the header length before writing the header, and left such a file when that write tore (or the header was later damaged there) and the failed creation's cleanup never finished. The file holds no record and the durable proof and mark name earlier segments; 39 of 192 random power losses taken while the torn file was volatile were refused. | Recovery discards such a file as an unfinished creation (removed, journal directory synced before the writer resumes) when the segment is final, exactly header-sized, fails its checksum and lies above the segments the durable proof (unless empty) and the durable mark name; without a proof (legacy v1 inspection) never. Every acknowledged record lies in or below the segment the proof names, and a segment that held one is longer than a header. A header followed by record bytes, one the proof or the mark names or lies below, one that is not final and an intact header that does not decode still fail closed. The deep check reports the discarded file as an info line. **Behaviour change:** this relaxes the rule, kept by AUD-003 and BUG-060, that any complete header failing validation is durable damage; the writer and its cleanup obligation are unchanged. | maki-core `review_journal_legacy_torn_header.rs`: `legacy_torn_header_only_final_segment_is_discarded`, `legacy_torn_header_survives_random_power_loss` and seven fail-closed cases; `review_journal_creation_cleanup.rs`: `an_unremoved_invalid_header_still_fails_closed_after_power_loss` (now record-like bytes after the damaged header, or an index the mark names) and `an_unremoved_damaged_header_only_creation_is_discarded_after_power_loss` | [#177](https://github.com/seo-rii/maki/pull/177) |
| AUD-055 | A CRC-valid checkpoint state whose sequence lay above the required durable proof's horizon was accepted: recovery treated the FUA-acknowledged records between the two as applied, those units read zeros, the next checkpoint pruned their journal, and the deep check reported the volume clean. Reaching it needs write access to the backing or media damage. | Recovery refuses such a checkpoint right after loading it, before any write, and the deep check applies the same function. No crash or restart produces it: a record becomes checkpoint-eligible only once both proof copies attest it, and recovery publishes the proof before it advances the checkpoint. | maki-core `review_checkpoint_horizon.rs`: `checkpoint_above_the_durable_proof_is_refused_by_recovery_and_the_deep_check`, `refused_checkpoint_horizon_leaves_the_acknowledged_journal_intact` | [#185](https://github.com/seo-rii/maki/pull/185) |
| AUD-056 | A v2/v3 volume whose recovered durable sequence was `u64::MAX - 1`, or whose highest segment index (of a surviving segment, the durable proof or the advisory mark) was `u64::MAX - 1`, attached and passed the deep check; every later write then failed as exhausted, forever. | The shared journal scan refuses, on v2/v3 volumes, a durable sequence that leaves no sequence for one more record and a highest index that leaves no index for one more segment; the advisory mark is refused like a segment index instead of being ignored. **Behaviour change:** the [durable recovery guide](durable-recovery.md#cost-and-verification-limits) said the last representable sequence and index stay readable after recovery. A writer that reaches the limit still refuses the append or roll before changing storage and serves its data until detach, but the next recovery refuses the volume: read availability of a state only damage produces is traded for agreement between the deep check and attach. Legacy v1 read-only inspection keeps the old bound. | maki-core `review_r3_recovery_counters.rs`: `durable_horizon_leaving_no_sequence_for_a_record_is_refused`, `record_at_the_last_sequence_leaving_no_successor_is_refused`, `segment_index_leaving_no_index_for_a_roll_is_refused`, `advisory_mark_index_leaving_no_index_for_a_roll_is_refused`, `durable_proof_index_leaving_no_index_for_a_roll_is_refused`; `last_accepted_horizon_remains_readable_with_exact_record_count` and `empty_segment_at_the_last_accepted_base_preserves_the_horizon` pin the highest accepted horizon | [#185](https://github.com/seo-rii/maki/pull/185) |
| AUD-057 | A durable proof that the checkpoint covers, naming a later segment (or the same record end) than the newer surviving records end at, passed the deep check, while recovery refused it ("advancing durable sequence regressed its segment location") after it had already rewritten the superblock and checkpoint state. | The shared scan compares a covered proof's location with the record end recovery would publish for the newer records, so both refuse it, before any recovery write. | maki-core `review_durable_proof_location.rs`: `covered_proof_naming_a_later_segment_is_refused_by_check_and_recovery`, `covered_proof_ending_where_the_newer_record_ends_is_refused_by_check_and_recovery`; control `covered_proof_before_the_newer_record_still_recovers` | [#185](https://github.com/seo-rii/maki/pull/185) |
| AUD-058 | A generation near `u64::MAX` in the checkpoint state, the durable proof, an allocation or discard map or the key canary passed the deep check, while attach refused it as exhausted, or attached and a later checkpoint failed. | A read-only check that recovery and the deep check both run refuses A/B metadata (superblock, checkpoint state, durable proof, key canary, shard catalog, and each loaded shard's allocation and discard maps) whose raw generation, as the store ranks it, lies in the top quarter of the generation space (above `u64::MAX - 2^62`). No writer reaches it, and the `2^62` stores left are more than any attach, replay or checkpoint performs. `AbStore` gains a read-only `raw_generations` accessor. | maki-core `review_generation_headroom.rs`: `generations_without_store_headroom_are_refused_by_check_and_attach`, `generations_up_to_the_bound_are_accepted_by_check_and_attach` | [#185](https://github.com/seo-rii/maki/pull/185) |
| AUD-059 | With both key canary copies damaged or removed on a used volume that no longer held ciphertext (every unit trimmed), the deep check printed a `key canary: absent` warning and `check passed`, while every attach refused with "volume has history but no readable ciphertext to probe", whatever the provider. | The deep check tells damaged copies (`copies exist but no copy validates`) from missing ones and decides severity after reading the journal and slots, as attach does after recovery: an `ERROR` when the volume has history but no unit would hold ciphertext after replay, otherwise a warning saying what attach needs. It cannot know whether the provider offers integrity, so it never fails a volume some provider can attach. **Behaviour change:** the [operations guide](operations.md#volume-lifecycle) classified any canary metadata that failed validation as `unrecoverable`; a lost canary is now an error only where attach must refuse, and a damaged canary on a pristine volume, which attach re-binds, is a warning. Three journal tests that built canary-less volumes with history now bind a canary first. | maki-core `review_check_canary.rs`: `canary_loss_on_a_used_volume_without_ciphertext_fails_the_deep_check`, `canary_loss_on_a_volume_with_ciphertext_is_a_warning`, `canary_loss_on_a_pristine_volume_is_a_warning` | [#185](https://github.com/seo-rii/maki/pull/185) |
| AUD-060 | When a shard's unit count is not a multiple of eight, the last byte of its allocation bitmap (and of its v3 discard bitmap) holds padding bits. The decoder accepted a CRC-valid copy with padding bits set and `AllocationMap::set_count()` counted them. `SlotStore::open` uses that count to classify an adopted shard whose data file is short: with an empty map it was never checkpointed into and its holes stay holes, with a listed slot it was truncated and its cleared slots past the end read EIO (S-01). A map whose only set bits were padding therefore made a never-finished shard truncated: the deep check reported all its units as damage and attach returned EIO for units never written. No writer in this repository sets padding bits. | The decoder clears padding bits instead of carrying them into the map, so `set_count()`, `encode()` and equality see only real units. Every image accepted before is still accepted with the same unit bits; the decoder masks rather than refuses because the repository's history cannot show what earlier writers did. No encoder output, golden vector or format version changes. | `padding_bits_are_not_allocated_units` (maki-format `review_codec_canonical.rs`); `padding_bits_do_not_make_a_never_finished_shard_truncated` and the control `a_listed_unit_still_makes_a_short_orphan_truncated` (maki-core `review_adopted_shard_padding.rs`) | [#184](https://github.com/seo-rii/maki/pull/184) |
| AUD-061 | The decoders also ignore the slot header's flags word and 24 reserved bytes, the superblock's bytes between its last string and the CRC, and a key canary's bytes after its ciphertext, so non-canonical CRC-valid copies are accepted. | **Not changed**, deliberately: accepting them has no observable effect, and refusing them could break a volume an earlier writer produced. Every reader decodes a slot header identically, it is identified by its unit and write sequence, and its payload is verified by the ciphertext CRC; two superblock copies of one generation that differ in those bytes are already refused as conflicting, and copies are rewritten from their exact bytes; a successful attach rewrites both canary copies from the decoded record, whereas refusing their trailing bytes would make the canary absent, which attach refuses on a volume with data unless the provider offers integrity. A comment at each decoder says why. | `slot_header_flags_and_reserved_bytes_stay_accepted`, `key_canary_bytes_after_the_ciphertext_stay_accepted` (maki-format `review_codec_canonical.rs`); existing `same_generation_conflicts_include_ignored_padding` (`review_superblock_v2.rs`) | [#184](https://github.com/seo-rii/maki/pull/184) |
| AUD-062 | A v2 journal record of zero length is replayed as an empty slot write; on v3 the same record is a discard tombstone. | **Not changed**, deliberately: `Volume::write_ct(unit, &[], ..)` on a v2 volume produces such a record, and replay serves the same empty ciphertext the live view served. The engine never journals one, because `CheckedProvider` refuses an empty encrypt result. | — | [#185](https://github.com/seo-rii/maki/pull/185) |

### Crash model and test doubles

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-063 | Linux `FileBacking` refuses a directory name as a lock file and as a file to remove (EISDIR), but `CrashableBacking::try_lock` locked a directory name, and `remove` of a directory name returned `NotFound` in both `CrashableBacking` and `MemBacking` (AUD-010's open item), so a test could pass for code that confuses the two kinds of entry. | Both in-memory backings apply one rule, "the parent exists and the name is not a directory", to `remove` and `try_lock`, as they already did for `open` and rename targets. The namespace table moves to `crates/maki-backing/tests/common/namespace_parity.rs`, gains directory-removal cases and a file-removal control, and runs against both in-memory backings. | `mem_backing_namespace_follows_posix_path_rules` (maki-backing `review_mem_backing_parity.rs`) and `crashable_backing_namespace_follows_posix_path_rules` (maki-test-support `review_test_doubles.rs`); `file_backing_namespace_matches_the_expectations` checks the expected outcomes against Linux `FileBacking` | [#175](https://github.com/seo-rii/maki/pull/175) |
| AUD-064 | Three regressions in the first pass's open list did not fail when the code they are named after was removed. `recovery_rewrites_page_cache_bytes_it_accepts_after_a_failed_writeback` and `process_recovery_rewrites_clean_cache_bytes_before_sealing_the_journal` passed without recovery's prefix rewrite, because attach recovery replays the adopted records into synced slots before it returns, and the second test's wrapper failed a segment sync without the crash model seeing it, so recovery's own sync persisted the writes anyway. `a_failed_intermediate_sync_stops_append_and_can_resume` passed without the journal's rewrite after a failed sync, because its later FUA records re-dirtied the page holding the failed records (AUD-008). | Test only. The `review_writeback.rs` case stops recovery after a restart right after it syncs the durable mark, while the segment holds the only copy of the record, then loses power and requires the next attach to serve it. The `review_journal_writeback.rs` wrapper fails segment writeback inside `CrashableBacking`, and the test uses the full-replay `recovery::recover` before a power loss. The `review_journal_pending.rs` case uses a segment that holds exactly the two records pending at the failed sync, so later records go to a successor; its accounting assertions are unchanged. Each now fails when its rewrite is removed. | maki-core `review_writeback.rs`, `review_journal_writeback.rs`, `review_journal_pending.rs` | [#175](https://github.com/seo-rii/maki/pull/175) |
| AUD-065 | MAKI-011 (a transport error on the self-test's tamper probe must leave the integrity claim unproven) had no dedicated test. The only covering test answers every negative probe with a transport error, so the self-test stops at the first context-binding probe, and accepting any error at the tamper probe's call site passed every test. | Test only. A provider that fails only the decrypt of the flipped ciphertext, with a `Retryable`, `Throttled` or `EndpointFatal` error, must reach the tamper probe once and fail the self-test with that class (FUP-008); the same provider passes when the tamper probe gets `Integrity`. | `a_transport_error_on_the_tamper_probe_alone_leaves_integrity_unproven` (maki-crypto `review_audit2.rs`) | [#175](https://github.com/seo-rii/maki/pull/175) |

### Remote providers and transports

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-066 | The WebSocket reader parsed every text frame into a guarded tree of all its nodes before routing it, at 56 bytes per node, so a frame of small values within the default 8 MiB `max_frame_bytes` (extra empty items, padding inside an item or an error envelope) held about 43 times its size, 361 MB, at peak (AUD-024's open item). | The frame parser keeps only what response handling reads (the numeric `id`, the error's `class` and `reason`, each item's `unit` and `data`), and items only up to the largest item count among the requests registered on the frame's connection generation; later items are counted, so a longer array still fails the count check. Unread values go through a skipping visitor that keeps the syntax, UTF-8, number-range, trailing-input and recursion checks and never copies a string out of the guarded frame. | maki-crypto-websocket `review_response_memory.rs` (`json_frame_memory_is_bounded_by_its_size`: 43.0 times before, 1.0 after; bound three times); erasure unit tests moved to fields the parser reads | [#173](https://github.com/seo-rii/maki/pull/173) |
| AUD-067 | The gRPC provider decoded every repeated `CryptoItem` of a response before comparing the item count with the request. An empty item is two bytes on the wire but a 64-byte guarded item in memory, so a message of empty items within the default 4 MiB `max_message_bytes` held about 49 times its size, 206 MB, at peak. | The response codec carries the request's item count, and the decoder refuses the first item field beyond it before decoding that item, as a receive-contract error charged to the endpoint. Decoding is otherwise prost's own loop, so field replacement, unknown-field skipping and erasure of decoded items are unchanged. | maki-crypto-grpc `review_response_memory.rs` (`response_message_memory_is_bounded_by_its_size`: 49.0 and 25.0 times before, 1.1 to 1.3 after); a unit test of decoding at, below and above the count | [#173](https://github.com/seo-rii/maki/pull/173) |
| AUD-068 | `EndpointSet` sends a request of a provider that is not retry-safe at most once (M-010) and applied that to every failed attempt, including one that failed before any request byte left Maki. With `retry_safe = false` and a healthy peer, a request whose endpoint refused the TCP connection, failed or never finished the TLS handshake, or refused the WebSocket upgrade was returned as an I/O error, although sending it to the peer could not duplicate an operation. | Transports mark exactly the errors they can prove happened before the first request byte was written with `CryptoError::not_sent`, a `NotSent` wrapper whose class, message and `duplicate()` are the inner error's; only `Retryable`, `Throttled` and `EndpointFatal` errors can be marked. While every attempt so far was unsent, the request fails over and, under the availability policy, is retried like one not yet sent; once any attempt, or an earlier chunk of the same call, may have been sent, it is never sent again. WebSocket marks failures before the frame reaches the connection's writer, HTTP marks reqwest connect errors (and builds its client with `retry::never()`), and gRPC marks the connection attempt and channel readiness; errors the libraries cannot prove unsent stay unmarked. **Behaviour change:** M-010's "no retry, no failover" now applies only once an attempt may have been sent, so under `stall` a non-retry-safe request whose only endpoint refuses connections stays pending instead of failing at once. | maki-crypto `review_unsent_failover.rs`; `review_unsent_failover.rs` in maki-crypto-websocket, maki-crypto-http and maki-crypto-grpc (refused connections and TLS failures fail over; a request written before the connection died, a gRPC error status, a gRPC timeout after hand-over, a WebSocket reconnect after a written frame and an HTTP per-item call after an earlier unit are never sent again); `generic_4xx_upgrade_refusal_fails_over_and_opens_the_refusing_peer` (maki-crypto-websocket `review_error_class.rs`) now requires every non-retry-safe request to succeed | [#174](https://github.com/seo-rii/maki/pull/174) |
| AUD-069 | When the `bounded-error` deadline expired while an operation waited for endpoint admission (an endpoint had already failed it and the failover target's slots were taken by other operations), the dispatcher returned the generic `Retryable` "operation deadline exceeded" and dropped that endpoint's error. Its deadline exits at the top of a pass and after a failed RPC return the last endpoint error, so one outage was reported with a different message and class depending on where the deadline expired. | The admission exit returns the last endpoint error with its own class, like the other two exits; an operation that never reached an endpoint still gets the deadline error, and the deadline metric is unchanged. | maki-crypto `review_admission_deadline_error.rs`: `an_admission_deadline_reports_the_last_endpoint_error`, `an_admission_deadline_keeps_the_class_of_the_last_endpoint_error` | [#174](https://github.com/seo-rii/maki/pull/174) |
| AUD-070 | The patched serde_json keeps custom error messages in a `GuardedString` whose `Deref` validates the whole buffer as UTF-8, and `parse_line_col`, which recovers a trailing " at line L column C", indexed the guard once per digit. Serde puts untrusted text in these messages (wrong-type string values, unknown field names), so an authenticated witness client, a hostile witness response or a control-socket value with many digits after its last " at line " made one error cost O(length × digits): 160 to 179 ms for a 64 KiB witness request frame against about 2 ms for a same-size control. | `parse_line_col` derefs the guard once and runs upstream's unchanged index logic on the borrowed text, so building an error validates the message at most twice; `Deref` keeps its runtime UTF-8 check. `vendor/patches.json` records the new hashes. | vendored `error::tests::position_parse_validates_the_message_a_fixed_number_of_times` (`vendor/serde_json/src/error.rs`; 4,099 validations for 4,096 digits before) | [#183](https://github.com/seo-rii/maki/pull/183) |
| AUD-071 | The `&RawValue` seed implemented only `visit_borrowed_str`. On reader input, or when converting from a `Value` or `&Value`, the parser hands the seed owned raw text, and serde's default `visit_string` returned the invalid-type error and freed that String with the raw JSON still in it, although the vendor guide says the library's own visitors adopt such a String. Maki borrows `&RawValue` only through `from_slice`, so production did not reach this path. | A `visit_string` adopts the String into a `GuardedString` and returns the same error, so the text is erased when the guard drops, including on unwinding. | `borrowed_raw_rejection_of_owned_raw_text_erases_it` (`vendor/serde_json/tests/maki_raw.rs`) | [#183](https://github.com/seo-rii/maki/pull/183) |

### Configuration validation

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-072 | Validation never inspected gRPC `encrypt_path` and `decrypt_path`; the provider parsed them with the HTTP URI type only at construction, during attach. An empty path, one without the leading `/`, or one with a space, control character, `<`, `>` or backtick validated and then failed every attach, and some paths construction accepted were not sent as written: a `#v2` fragment was dropped, and `*` or a bare `?tenant=demo` named no method. | maki-format owns the method-path rule (`check_grpc_method_path`), which validation and provider construction both apply before the URI parse: an RFC 3986 absolute path with an optional query (the HTTP/2 `:path` of RFC 9113 §8.3.1), only path and query characters and well-formed `%XX` escapes, no `#`, within the client's 65534-byte URI limit. Every accepted path parses unchanged; characters RFC 3986 requires to be percent-encoded (quotes, braces, brackets, backslash, caret, vertical bar, non-ASCII) now must be. maki-crypto-grpc gains maki-format as a normal dependency. | `method_paths_the_provider_cannot_send_as_written_are_refused` (maki-format `review_grpc_method_paths.rs`); `validation_and_construction_accept_exactly_the_paths_sent_as_written` (maki-crypto-grpc `review_method_path_rule.rs`) | [#172](https://github.com/seo-rii/maki/pull/172) |
| AUD-073 | In a `remote-http` batch body the top-level `fields` are evaluated once per request with no item, so a `payload`, `unit_index` or `batch_index` source there validated and was sent as an empty payload or 0 in every request; a per-item body (no `items_path`) never sends `item_fields`, which validated and were dropped. | `BodyConfig::request_mapping`, which validation and `HttpCryptoProvider::from_config` share, refuses an item source among a batch's top-level fields (pointing at `item_fields`) and a non-empty `item_fields` table on a per-item body. Context sources at a batch's top level, raw bodies and programmatic `OpSpec` mappings are unchanged. Two assertions that now meet the earlier refusal were adapted (`review_http_field_mappings.rs`, `review_r3b_config.rs`). | maki-format `review_http_item_sources.rs`: `item_sources_in_top_level_batch_fields_are_refused`, `item_fields_of_a_per_item_body_are_refused`; `fields_no_request_carries_are_refused_by_validation_and_construction` (maki-crypto-http `review_unsent_item_sources.rs`) | [#172](https://github.com/seo-rii/maki/pull/172) |
| AUD-074 | `env` credential names only had to be non-empty, but the development source reads `MAKI_CREDENTIAL_<NAME>` and no environment variable name can contain `=` or NUL. Such a name was not a clean miss: with glibc, `std::env::var("MAKI_CREDENTIAL_A=B")` returns the rest of `MAKI_CREDENTIAL_A` after a leading `B=`, so a key or token was read from part of another variable. | Validation and the `validate_credential_sources` preflight refuse an `env` name containing `=` or NUL in every credential reference, without quoting it. The rule is deliberately minimal: `env` is development-only and POSIX allows every other byte in a variable name. | `env_names_no_environment_variable_can_have_are_refused` (maki-format `review_env_credential_names.rs`) | [#172](https://github.com/seo-rii/maki/pull/172) |

### Rollback protection and witness

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-075 | The `maki-witness` configuration loader refused a symlink, a non-regular or oversized file and group or other write, but not a foreign owner, who can rewrite the file whatever its mode (AUD-031's open item). A `0644` server configuration owned by an unprivileged user let that user add their own certificate as an administrator or point `key_file`, `state_dir` or `[etcd]` elsewhere; the same loader serves `init-etcd` and `inspect`, whose configurations name the backend and the server and CA the command trusts. | A configuration must be owned by root or by the process's effective user, checked on the descriptor opened with `O_NOFOLLOW` before the mode check; `serve`, `init-etcd` and `inspect` refuse anything else with `PermissionDenied` naming both uids and none of the content. Group and other read stays allowed: a configuration holds paths and fingerprints, not secrets. | `a_configuration_owned_by_another_user_is_refused_by_every_loader`, `root_owned_and_own_configurations_still_load` (`bins/maki-witness` `review_config_owner.rs`; root only) | [#170](https://github.com/seo-rii/maki/pull/170) |
| AUD-076 | `StateStore::open` and `StateStore::create`, which `maki-witness init` and `serve` use, pinned the authority's state directory without following a symlink but checked neither its owner and mode nor those of the `remote.state`, `remote.next` and `remote.lock` files in it (AUD-031's open item). Whoever could write the directory or one of those files could put an older record back and roll the freshness authority back across a restart; a planted `remote.next` was even renamed into place by the next publish. | The directory and every existing `remote.*` file must be owned by root or the effective user and have no group or other write bit (a sticky bit does not stop a stranger creating the next `remote.next`); a non-regular entry is refused. The directory is checked on the descriptor `FileBacking` pinned, a refused `create` writes nothing, and `serve` refuses before binding its listener. Group and other read stays allowed: the files hold the public record and domain-separated digests. Ancestors are not checked (documented). | maki-backing `review_witness_state_owner.rs`: `a_state_directory_another_user_owns_is_refused`, `a_state_directory_writable_by_group_or_others_is_refused`, `state_files_another_user_owns_or_can_write_are_refused`, `private_and_world_readable_state_still_opens`; `bins/maki-witness` `review_state_owner.rs` (`init` and `serve`); root only | [#170](https://github.com/seo-rii/maki/pull/170) |
| AUD-077 | A witness frontend checked the client certificate against its allow-list only after the TLS 1.3 handshake, and for a certificate its CA trusts but its allow-list does not name (a rotation that missed one frontend, a wrong role file) it closed the connection without an answer. The client saw `UnexpectedEof`, `BrokenPipe` or `ConnectionReset`: failover moved on and could be answered by another frontend, `transact` retried the mutation, and a remote rollback session refused each operation but kept running, so operators saw an unavailable witness instead of the documented terminal denial. | The server reads that connection's single request and answers it with the existing `permission_denied` wire error bound to the request's id, without calling the handler; clients already map it to `PermissionDenied`, which failover, `transact` and the remote session treat as final. The wire format is unchanged, and in the accept loop a denied connection never takes a worker slot. Rejecting the certificate inside the TLS verifier was not used: in TLS 1.3 the client has already written its request when the alert arrives. | maki-witness `review_witness_auth_denial.rs`: `an_unlisted_certificate_is_answered_with_a_denial_not_a_dropped_connection`, `failover_stops_at_a_frontend_that_denies_the_certificate`, `a_denied_freshness_check_stops_the_remote_session`, `a_denied_commit_is_not_retried` | [#179](https://github.com/seo-rii/maki/pull/179) |
| AUD-078 | One entry whose name is not UTF-8 in a remote rollback backing root (anyone who can write the root can create one) made the root listing fail with `InvalidData` before GC examined any candidate. `maki volume gc` always failed; the automatic pass after each activation, which ignores GC errors, left every predecessor namespace and its full arena on disk until the filesystem filled; and `resume-enrollment` of a never-activated authority refused the root. | The directory visitor passes each entry's exact name bytes, and the root listing sorts and pages by them. GC reports such a name under `skipped_unrecognized` (with U+FFFD in place of invalid sequences), never removes it and keeps scanning; enrollment recovery skips it like other unknown entries. The scan inside a namespace still fails closed, so a namespace holding such an entry is kept. | maki-backing `review_remote_gc_names.rs`: `non_utf8_root_entries_are_reported_and_kept_while_gc_reclaims`, `non_utf8_names_across_pages_are_each_counted_once`, `activation_retires_its_predecessor_past_a_non_utf8_root_entry`, `enrollment_recovery_keeps_a_non_utf8_root_entry`; control `control_a_non_utf8_entry_inside_a_retired_namespace_keeps_it` | [#181](https://github.com/seo-rii/maki/pull/181) |
| AUD-079 | Both rollback manifest loaders, local and remote, allocated a buffer of a slot's unauthenticated 8-byte length after checking it only against the slot size of a 1 GiB backing, so a damaged or planted length made each open, takeover and GC pass allocate about 72 MiB before the read failed on a slot file of about 8 MiB. | The loaders refuse a length the slot file cannot hold before they allocate. A canonical manifest always fits its slot, whose exact size is checked after decoding, so which manifest is selected does not change. | maki-backing `review_rollback_manifest_length.rs`: `local_manifest_length_beyond_its_slot_is_refused_before_allocating`, `remote_manifest_length_beyond_its_slot_is_refused_before_allocating` (peak under 9 KB after) | [#181](https://github.com/seo-rii/maki/pull/181) |
| AUD-080 | Every open of a local rollback witness republishes its anchor (written to `anchor.next`, synced, renamed over `anchor`, directory synced), and the new file belonged to the process that opened it. The rollback guide told operators to run `maki check --deep` and `maki volume inspect` on a detached volume without naming a user, so a root run replaced the anchor with a `root:root 0600` file and the daemon's next attach failed with EACCES. A root `maki volume create` also left the witness files root-owned, and its warning told the operator to chown only the volume tree. | The republish stays. When root publishes the anchor, the new file gets the replaced anchor's uid and gid with `fchown` on its own descriptor before any byte is written, and is synced with `fsync` (`fdatasync` need not persist an owner change) before the rename and directory sync; a refused owner change refuses the open. Other users still create it as themselves, and every publication stays owner-only (`0600`). `BackingFile` gains `owner`/`set_owner`, which `FileBacking` implements on Unix. A root create names both the backing root and the witness directory in its `chown -R maki:maki` warning, and the guide says to run create, `check --deep` and `inspect` as the daemon user. | maki-backing `review_local_witness_owner.rs`: `root_republish_keeps_the_anchor_owner_and_mode`, `root_reopen_of_a_daemon_owned_rollback_backing_creates_no_root_owned_file`, `republish_by_the_anchor_owner_changes_neither_owner_nor_mode`; `bins/maki` `review_local_witness_owner.rs`: `root_offline_check_and_inspect_leave_the_daemon_able_to_open_its_witness`, `root_create_names_the_rollback_witness_among_the_paths_to_hand_back`; unit test `only_root_gives_a_new_record_the_replaced_owner_and_syncs_it_first` (`crates/maki-backing/src/witness.rs`); the root cases skip unprivileged | [#182](https://github.com/seo-rii/maki/pull/182) |
| AUD-081 | Since the witness client refuses a TLS key owned by another user (AUD-031), `maki volume snapshot` and `maki volume gc` with the daemon-owned writer configuration refuse to run as root, as `maki volume witness` does, but the guides showed them with no user. The rollback guide's enrollment-recovery procedure also lacked the `chown -R maki:maki` hand-back the remote witness guide gives after `resume-enrollment`, which runs as root and creates the new writer namespace owner-only. | Documentation only: the remote witness guide runs `witness`, `snapshot` and `gc` with the writer configuration as the daemon user, with a backup directory that user can create, and takeover, restore and `resume-enrollment` as root with the administrator configuration, followed by the hand-back; the enrollment-recovery procedure includes it. The root refusal was checked with the built binary. | — | [#182](https://github.com/seo-rii/maki/pull/182) |

### Daemon admission

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-082 | The daemon's `[security.memory_budget]` admission, which runs before attach and again before readiness, read `/proc/self/mountinfo` as UTF-8 and checked every mount's path with the cgroup path rules. One mount anywhere in `maki@`'s namespace whose path is not UTF-8 (a user's FUSE mount, a USB stick under a Latin-1 label), whose directory name contains a newline, or whose path has more than 256 components failed admission, and every memory-budgeted volume then failed to start. AUD-040 fixed only the privileged helper's parsers. | The table is read, compared on recheck and split into records and fields as bytes. Only the cgroup-v2 records are decoded and checked as before; every other mountpoint is unescaped into its exact bytes and compared with the cgroup mount path component by path component. A mount at or below the cgroup mount still refuses as shadowing whatever its bytes, a sibling that only shares its text prefix does not, and a mountpoint the kernel never emits (relative, NUL, an empty, `.` or `..` component, an unknown or truncated escape) still refuses. | maki-nbdkit `review_memory_budget_mountinfo.rs` (private mount namespace; prints the reason and checks nothing where mounts are not permitted); unit tests in `crates/maki-nbdkit/src/security/memory.rs`: `unrelated_mount_path_bytes_do_not_refuse_admission` (12 cases), `mounts_at_or_below_the_cgroup_mount_shadow_policy_whatever_their_bytes`, `cgroup2_records_and_undecodable_mountpoints_still_refuse` | [#180](https://github.com/seo-rii/maki/pull/180) |

### Validation tooling and documentation

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-083 | `scripts/check_vendor_erasure.py` ran `cargo metadata` without feature flags, which resolves only the default features of workspace members, so a non-default member feature (such as `etcd-qualification` or `fake-provider`) could enable an unreviewed patched-crate feature, directly or through an optional dependency, and pass the contract while `cargo build --features …` compiled the unreviewed code. | The contract resolves with `--all-features`. Features are additive and the patched packages are excluded from the workspace, so this covers every feature selection a workspace build can make; the current tree resolves the same reviewed features with and without the flag. | `test_unreviewed_feature_behind_optional_workspace_feature_is_rejected`, `test_unreviewed_feature_behind_optional_dependency_is_rejected` (`scripts/test_vendor_erasure.py`) | [#183](https://github.com/seo-rii/maki/pull/183) |
| AUD-084 | The link checker read only inline links (AUD-047's open item): a reference definition with a missing file or anchor passed CI, a full or collapsed reference whose label matched no definition (which GitHub shows as literal brackets) was not reported, and a heading containing a full reference was slugged from its raw brackets, so a correct link to it failed. | The checker parses the definitions GitHub recognizes (CommonMark) and applies the inline target and anchor checks to each, reports full and collapsed references with no definition in the same document, and slugs headings from a reference's link text; CONTRIBUTING describes the rule. All 65 definitions in the repository, all in vendor documents, resolve. | `DocumentationReferenceLinks` in `scripts/test_docs_links.py` (9 of its 10 tests failed before) | [#171](https://github.com/seo-rii/maki/pull/171) |
| AUD-085 | The documentation covered only reflink-shared extents (AUD-049). On btrfs with its default copy-on-write data, `posix_fallocate` allocates a range, but every later overwrite of written data goes to new space, so a checkpoint's slot rewrite, the A/B metadata rewrites and recovery's journal rewrites can fail with ENOSPC on a full filesystem with no copy involved; ZFS always writes changed blocks to new space. The support matrix had no row for either. | Documentation only: the [support matrix](deployment/support-matrix.md#copy-on-write-filesystems) lists btrfs with copy-on-write data and ZFS as unsupported and btrfs with NOCOW backing files as not qualified, with the NOCOW conditions (`chattr +C` on the backing directory before `maki volume create`, no btrfs checksums or compression, snapshots and reflinks still share extents); the [status page](status.md#known-limitations), the configuration and operations guides and `BackingFile::allocate_range` say the same. Maki checks neither the filesystem nor the attribute. | — | [#171](https://github.com/seo-rii/maki/pull/171) |
| AUD-086 | The workload verify gate opens the mounted volume root and `.maki-sentinel` as root, but `ExecStartPre=!` keeps the unit's `CapabilityBoundingSet=`. In a unit that drops both CAP_DAC_READ_SEARCH and CAP_DAC_OVERRIDE, a workload-owned `0700`, `0750` or `0711` volume root, or a sentinel the workload replaced with its own `0600` file, makes the gate fail with EACCES and the workload never starts; the `O_NOATIME` retry (AUD-041) applies to EPERM only. Nothing documented this, and the privileged-helper section said the volume root carries the workload's ownership without the limit. | Documentation only: the example drop-in, the gate requirements in the operations guide and the storage-recovery sentinel description give the two remedies (keep CAP_DAC_READ_SEARCH or CAP_DAC_OVERRIDE in the bounding set, or keep the volume root readable and searchable by others with the workload's private directory below it); #187 adds the limit to the mountpoint paragraph. The gate still fails closed on EACCES. Checked as root on threads and under `setpriv` without those capabilities. | — | [#171](https://github.com/seo-rii/maki/pull/171), [#187](https://github.com/seo-rii/maki/pull/187) |
| AUD-087 | The configuration and space-reclamation guides said `fstrim` still returns space the filesystem had already freed while backing free space is inside the checkpoint headroom, as R5-011 below did. The status page and the 2026-10-03 pressure runs say otherwise: XFS `fstrim` forces a log write first and FITRIM failed with EIO there; only a raw discard of the exported device was admitted. | Documentation only: both guides say raw discards are admitted inside the headroom but a filesystem's deletes and XFS `fstrim` are refused, and link the [known limitations](status.md#known-limitations) instead of restating them. R5-011 now carries a note. | — | [#178](https://github.com/seo-rii/maki/pull/178) |
| AUD-088 | The credential-rotation guide starts `maki@` and `maki-attach@` by hand while the workloads are held stopped, but never masked `maki-recover@<volume>`. A failed daemon start reaches it through `OnFailure=` and a failed attach start requests it from `ExecStopPost`; with no attach record its cleanup succeeds and its `OnSuccess=` starts `maki-workload@<volume>.target`, registered workloads included, before the guide's peer, mount and database checks. | Documentation only: the procedure applies the operations guide's runtime mask before the target stop, keeps it through the rollback path and removes it only after the verification evidence is accepted. Checked against the packaged units and `cleanup_with`; systemd itself was not exercised. | — | [#178](https://github.com/seo-rii/maki/pull/178) |
| AUD-089 | SPEC §9 listed a "root-only secret file", the kernel keyring and a "secret-provider abstraction" as key sources. Validation accepts only `credential`, `file` and `env` and refuses `keyring`, and the loader accepts a file owned by root or by the loading user (AUD-029). | SPEC §9 lists the three implemented sources and the owner and mode rules the loader enforces, and says the keyring is not implemented; no requirement is added or relaxed. Two key-loader comments that quoted the old wording are updated. | — | [#178](https://github.com/seo-rii/maki/pull/178) |
| AUD-090 | Smaller statements were wrong or incomplete: the architecture page left `drain` out of the control verbs; SPEC §26 and the architecture page omitted the overlay checkpoint triggers and the immediate pass after a write refused for backing space; SPEC §14 counted five `maki volume inspect` layout values where inspect prints six; "mode `0600` or `0400`" read as the only accepted secret modes; the `memory_lock_mode = "off"` row did not say that `cache.lock_memory` defaults to true even with the cache off; the `~0`/`~1`-only escape rule applies to response pointers only; and the support matrix's daemon-user `0700` rule read as covering the backing directory's ancestors. | Corrected. A proposed exemption of HTTP/2 from the HTTP framing rule was dropped: the workspace builds `reqwest` without `http2`, so the provider speaks only HTTP/1.x. | The link checker and the documentation tests | [#178](https://github.com/seo-rii/maki/pull/178) |

### Not closed in this pass

- A CRC-valid checkpoint raise that stays at or below the durable proof's
  horizon is still accepted by recovery and the deep check; it drops the
  acknowledged records between the true and the forged checkpoint, and
  detecting it needs a comparison of slots with the covered journal (AUD-055).
- Allocation and discard map files of shards the store has not loaded are not
  generation-checked (AUD-058).
- `CrashableBacking` namespace operations (opening or creating a file,
  `remove`, `rename`, `sync_dir`) carry no crash epoch; only file handles and
  locks do (AUD-009). A volume, engine or worker that a test does not drop
  before `crash*()` can still create and sync files in the recovered state,
  so such a test can see a pre-crash volume acknowledge a FUA write that
  recovery then serves.
- Renaming a directory still differs from `FileBacking` (the in-memory
  backings return `NotFound`), and `CrashableBacking::try_lock` creates no
  lock file (AUD-063).
- A client certificate from a CA the witness does not trust is still refused
  inside the TLS handshake. In TLS 1.3 the client has already written its
  request by then, so it can see a broken pipe instead of the alert and treat
  the refusal as a transport failure (failover continues, a remote session
  keeps running) rather than a denial (AUD-077).
- A root run of an offline command that has to recreate a missing
  `volume.lock`, a rollback-protected volume's `rollback.lock` or
  `witness.lock`, or an inactive manifest slot creates it owned by root, and the daemon then cannot attach
  until the paths are handed back (AUD-080). The
  [rollback protection guide](rollback-protection.md) says to run those
  commands as the daemon user and to hand the paths back after a root run;
  the operations guide does not say so for a plain volume's `volume.lock`.
- The `maki` commands and the daemon read a volume's TOML configuration
  without an owner, mode or symlink check (SPEC §8 lists its permissions as
  recommended only), and the local rollback witness directory has no owner or
  mode check, unlike the witness service's files (AUD-075, AUD-076).
- CIFS escapes only spaces and tabs in its mount source, so a source that
  holds a newline would split its `/proc/self/mountinfo` record in both the
  privileged helper's and the daemon's parsers (AUD-040, AUD-082). This is
  theoretical and has not been reproduced.
- An operation whose deadline has already passed when the dispatcher asks
  for endpoint admission or starts an RPC within a pass ends with the deadline
  error without incrementing `deadline_exceeded_total`, so that metric can
  undercount (AUD-069).
- A `raw` HTTP body still accepts and ignores `fields` and `item_fields`;
  validation reads them only for JSON bodies (AUD-073).
- `FileBacking::list` still converts names lossily for its other callers; only
  the remote rollback root listing passes exact bytes (AUD-078).

## Internal audit (2026-11-16): AUD-001–AUD-051

An internal audit of `main` at `132cb6f` covered the journal, recovery and
engine, the crash model and test doubles, the remote transports, credential
loading and logging, configuration validation, rollback protection and the
witness, the privileged helper, and the validation tooling and documentation.
Nineteen pull requests, [#150](https://github.com/seo-rii/maki/pull/150) to
[#168](https://github.com/seo-rii/maki/pull/168), fixed its findings and were
merged into `main` on 2026-11-17. Every code fix landed test-first: its commit
message and pull request name the regression that failed before the change.
AUD-006, AUD-007 and AUD-016 to AUD-018 strengthen tests that could not fail
or that failed only because they ran as root; AUD-047 to AUD-051 correct
tooling and documentation. All rows are **Fixed**; the list after the tables
records the gaps their pull requests left open. No change alters the on-disk
format or the golden vectors. The operator-visible refusals are listed in the
[changelog](../CHANGELOG.md#breaking-changes).

The pull requests report Linux debug runs of the changed crates' suites, the
dependents that exercise the change, strict Clippy, `cargo fmt --check` and the
documentation link checker; the recovery, journal and engine changes (#164,
#166, #168) also ran the maki-core release gates one at a time. Four of them
(#155, #159, #160, #165) were also checked as an integrated tree: the workspace
suite (2,539 tests), strict Clippy, the Python contract tests, the vendor
integrity checks and the standalone vendor suites passed, and #159 and #165
report the integrated ignored release gates passing. These are repository tests
with simulated devices, local sockets and test authorities; no kernel
NBD/LVM/XFS stack, vendor endpoint or physical power loss was exercised.

### Durability and recovery

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-001 | Recovery selected a superblock copy and never wrote it back. A copy that existed only in the page cache (create's `fdatasync` of `superblock.a` failed, or the process died before it) was accepted: a retried create refused the root, attach acknowledged FLUSH and FUA, and the next power loss left no valid superblock. A create killed after A was durable but before B was written left one copy that nothing completed. | After the read-only journal scan and before any other repair, writable recovery rewrites each valid copy from its exact validated bytes and syncs it with the root directory, the selected copy first, then completes a missing or invalid copy through the preserve-first A/B store. Read-only paths still never write; legacy v1 is still refused first (SPEC §27). | maki-core `review_superblock_durability.rs`: failed sync at each publication step, a process-kill sweep over create, recovery stopped at every operation and followed by power loss or by a restart after writeback EIO, byte-identical repeated recoveries, read-only inspection writes nothing | [#164](https://github.com/seo-rii/maki/pull/164) |
| AUD-002 | Creation refused an existing superblock and any file in `data/`, `journal/` or `checkpoint/` (R5-018), but initialized a root that still held an earlier volume's `canary.a`/`canary.b` or `shard-catalog.a`/`shard-catalog.b`. A stale canary failed the new volume's first attach as a key mismatch; a stale catalog copy stayed the fallback side until the first catalog commit. | Creation refuses every root-level metadata name (`layout::ROOT_METADATA`) with `AlreadyExists` naming the file, before writing anything. A leftover `volume.lock` is still accepted. | maki-format `review_create_root_leftovers.rs`, both envelopes | [#164](https://github.com/seo-rii/maki/pull/164) |
| AUD-003 | A segment roll extended the new file to the 48-byte header length before writing the header, so a header write that persisted only a prefix left a complete-length header with a bad checksum. When the failed creation's cleanup (unlink, then directory sync) did not finish, recovery found that file as the final segment and refused attach as durable damage, after a plain restart too, although the segment never held a record. | The roll no longer preallocates the header: a torn header write leaves a file shorter than a header (or all zero), which recovery already discards as an unfinished creation. Recovery is unchanged; a complete header that fails validation is still durable damage (SPEC §23). *Relaxed by AUD-054 ([#177](https://github.com/seo-rii/maki/pull/177)):* a final segment exactly one header long whose header fails its checksum, above the segments the durable proof and mark name, is now discarded as an unfinished creation; every other invalid header still fails closed. | maki-core `review_journal_torn_header.rs`: restart with the deep check, power loss after writeback of the torn prefix, random torn power losses (22 of 256 crash states refused before). BUG-060's `an_unremoved_invalid_header_still_fails_closed_after_power_loss` now persists the whole header and damages one byte | [#166](https://github.com/seo-rii/maki/pull/166) |
| AUD-004 | A write over `backing.journal_max_bytes` or `limits.max_overlay_bytes` synced, released the volume lock, checkpointed and retried admission, up to four rounds, but nothing held the freed space for it: other writers appended into it and the write failed with ENOSPC although nothing had failed and the bound was reclaimable. Eight writers of maximal requests at the validated minimums lost 27 (journal) and 117 (overlay) of 1440 writes. | A write refused for either bound holds a FIFO reclaim gate until it has appended; every other write and discard queues behind it instead of appending, so its checkpoint covers every appended record and ENOSPC means the request does not fit even then. Reads, FLUSH and the worker never wait, and `limits.max_active_callbacks` bounds the queue. The round limit remains only as a termination bound (SPEC §26). | maki-core `review_reclaim_fairness.rs`; `review_r4_overlay_bound.rs` adapted | [#168](https://github.com/seo-rii/maki/pull/168) |
| AUD-005 | The worker's journal-watermark and low-free-space passes checkpointed without syncing first, and a checkpoint applies only durable records. With volatile records above the watermark every write woke a checkpoint that applied nothing (two exclusive volume-lock passes per write) while the journal grew toward its hard limit. | Both triggers sync first, like the interval trigger. When that sync fails, such a pass still checkpoints the records that were already durable and deletes the sealed segments they cover, keeping BUG-101's one-interval deferral of the failing sync. *Extended by AUD-052 ([#176](https://github.com/seo-rii/maki/pull/176)):* every worker pass does so, whatever started it. | maki-core `review_watermark_volatile_tail.rs`: volatile tail for both triggers; reclaim while every journal sync fails | [#168](https://github.com/seo-rii/maki/pull/168) |
| AUD-006 | Recovery rewrites every journal prefix its scan accepted before syncing it (SPEC §27, F01), but no test failed when that rewrite was removed: every case let recovery finish, and replay then made the records durable through the slots. | Test only. A sweep stops such a recovery after each backing operation, loses power and requires the next attach to match the durability oracle; without the rewrite it fails from the durable-mark sync to the directory sync that makes segment removal durable. A premise check refuses a crash model in which a plain sync persists lost writeback. | maki-core `review_recovery_prefix_rewrite.rs` | [#167](https://github.com/seo-rii/maki/pull/167) |
| AUD-007 | `recovery_refuses_bytes_that_changed_after_the_validated_scan` checked only that recovery fails. Replay fails on the changed record too, so the test passed when recovery skipped its fingerprint check, although the changed bytes were then synced and covered by the durable mark and both proof copies, and every later attach refused the volume. | Test only. The next attach must also succeed, with the acknowledged record and without the changed one. | maki-core `review_journal_writeback.rs` | [#167](https://github.com/seo-rii/maki/pull/167) |

### Crash model and test doubles

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-008 | `CrashableBacking` dropped a failed sync's dirty operations, turning "possibly written back" into "certainly lost": no later power loss could keep a page the flusher had already written, whole or torn, nor a truncation whose sync failed. Writeback was byte-range granular, so a later write that re-dirtied a page persisted only its own bytes, not the cached page. | A failed sync's operations become uncertain: a crash samples them like unsynced ones (torn when tearing is on), `crash_all_lost` and `crash_keep_torn_prefix` drop them, and no sync replays them, so a bare retry still writes nothing (F01). A successful sync writes back every re-dirtied 4 KiB page whole, zero past end-of-file. `fua_after_a_failed_sync_covers_every_pending_record` now keeps the failed records in a page the next FUA record does not touch. | maki-test-support `review_crash_writeback.rs`; maki-core `review_writeback.rs` | [#165](https://github.com/seo-rii/maki/pull/165) |
| AUD-009 | A file handle opened before `crash*()` could still read, write and sync into the recovered state, and the dead process's volume lock stayed held. | Each power loss starts a new epoch: every lock is released and every earlier handle fails with the model's EIO and changes nothing; dropping it releases nothing taken after the crash. A restart invalidates nothing. The Phase 0 oracle and `phase6.rs` `clean_detach_flushes_checkpoints_and_releases_lock` relied on the old behaviour and were adapted. | maki-test-support `review_crash_handles.rs` | [#165](https://github.com/seo-rii/maki/pull/165) |
| AUD-010 | `MemBacking` created files in directories that did not exist, renamed into them, listed or synced a missing directory as empty, looked up names below a regular file and opened or locked a directory name as a file, so a test could pass for code that fails on `FileBacking`. | The namespace applies the POSIX path rules `CrashableBacking` uses (`NotFound`, `NotADirectory`, `IsADirectory`). | maki-backing `review_mem_backing_parity.rs`: `mem_backing_namespace_follows_posix_path_rules` (14 of 21 cases failed before) | [#163](https://github.com/seo-rii/maki/pull/163) |
| AUD-011 | `allocate_range(offset, 0)` failed with EINVAL on Linux `FileBacking`, extended the file to the offset on `MemBacking` and `CrashableBacking`, and did nothing on `RollbackBacking`. | A zero-length range is a no-op on every backing, after the same overflow check. No production caller passes a zero length. | maki-backing `review_mem_backing_parity.rs`; maki-test-support `review_test_doubles.rs` | [#163](https://github.com/seo-rii/maki/pull/163) |
| AUD-012 | With integrity off, `FakeCryptoProvider` still checked its magic bytes, so a zeroed or overwritten unit failed with `Integrity` where `local-aes-xts` returns garbage, and a test of an unauthenticated profile could pass on the fake's own framing check. | The magic is checked only with integrity on; a wrong length is still refused, as XTS does. | `an_unauthenticated_fake_decrypts_any_well_sized_ciphertext` (maki-test-support `review_test_doubles.rs`) | [#163](https://github.com/seo-rii/maki/pull/163) |
| AUD-013 | `FakeCryptoProvider` declared `batch.max_bytes` but checked only the item count. | An over-limit batch is refused with `NonRetryableRequest`, measured as the crypto crate accounts batch bytes. | `the_fake_refuses_an_encrypt_batch_over_its_declared_byte_limit`, `the_fake_refuses_a_decrypt_batch_whose_plaintext_exceeds_the_byte_limit` (`review_test_doubles.rs`) | [#163](https://github.com/seo-rii/maki/pull/163) |
| AUD-014 | `ManualClock` woke sleepers that share a deadline in `HashMap` order, which changes from run to run. | Sleepers wake by deadline, then registration order. | `manual_clock_wakes_due_sleepers_in_deadline_then_registration_order` (`review_test_doubles.rs`) | [#163](https://github.com/seo-rii/maki/pull/163) |
| AUD-015 | `DeterministicScheduler` polled every unfinished task with a no-op waker, so a future that lost its wake-up completed in tests although tokio would never poll it again. | Each task has a waker that marks it runnable; with tasks left and none runnable, `run()` panics with a stall and `run_bounded()` returns false. | Three lost-wakeup cases in `review_test_doubles.rs` | [#163](https://github.com/seo-rii/maki/pull/163) |
| AUD-016 | `unlink_failure_keeps_durable_retirement_and_restarts_without_touching_current` relied on a mode-0500 directory, which `CAP_DAC_OVERRIDE` ignores, so it failed when run as root. | The test clears the capability on its own thread, checks that the directory refuses a new entry, and skips with a message only if it cannot clear it. | maki-backing `remote_gc.rs` | [#163](https://github.com/seo-rii/maki/pull/163) |
| AUD-017 | The `locking_failure` case of `secret_page_lifetimes` set `RLIMIT_MEMLOCK` to zero, which `CAP_IPC_LOCK` bypasses, so it failed when run as root. | The child process clears `CAP_IPC_LOCK` before lowering the limit. | maki-crypto `review_secret_page_lifetime.rs` | [#163](https://github.com/seo-rii/maki/pull/163) |
| AUD-018 | `payloads_never_appear_in_logs` captured tracing on its own thread only and did not bridge `log`, so a payload logged from a runtime worker or through `log` could not make it fail. | The round trip runs in a child process with the daemon's sink at `MAKI_LOG=trace`; both a worker-thread and a `log` sentinel must arrive, and plaintext and ciphertext are refused in base64, hex and decimal. | maki-crypto-http `phase8.rs` | [#163](https://github.com/seo-rii/maki/pull/163) |

### Remote providers and transports

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-019 | tonic decodes `grpc-status-details-bin` with `expect()`, so a peer could panic a provider call; through `EndpointSet` the panic skipped failover and the breaker. A `grpc-message` that does not percent-decode to UTF-8 replaced the code with `Unknown`, turning `Integrity`, `PermissionDenied` and `Unauthenticated` into retryable errors (a tampered unit stalled instead of returning EIO) and an OK reply into an error. | Both headers are removed from initial headers and trailers before tonic parses a status; the class follows only `grpc-status` and the allowlisted `maki-crypto-error` metadata (SPEC §18). | maki-crypto-grpc `review_status_headers.rs` | [#150](https://github.com/seo-rii/maki/pull/150) |
| AUD-020 | An IPv6-literal gRPC endpoint such as `https://[2001:db8::10]:7443` passed validation, but the provider could never be built: rustls received the bracketed host as the server name. | The server name is the host without brackets, verified as an IP-address name against the certificate's IP SANs, as IPv4 literals already were. | maki-crypto-grpc `review_ip_literal_tls.rs` (the IPv6 handshake case skips without an IPv6 loopback) | [#150](https://github.com/seo-rii/maki/pull/150) |
| AUD-021 | After a `Contract` error the dispatcher ended the operation unless some endpoint was both untried and admitting a call at that moment. A validated peer that had failed transiently, or whose circuit was cooling, did not count, so under `stall` the outcome depended on routing order. | The violation is final only once every validated endpoint (a single one included; quarantined ones not) has broken the contract for the operation; until then the operation stays in the normal backoff loop with the violators excluded. A violator is never sent the operation again, and a request that is not retry-safe is still never re-sent. | maki-crypto `review_contract_finality.rs` | [#154](https://github.com/seo-rii/maki/pull/154) |
| AUD-022 | A WebSocket upgrade refused with a generic 4xx (400, 422, 426 from a proxy that cannot upgrade) was `NonRetryableRequest`: the dispatcher returned it at once without charging the breaker or failing over, and attach refused as a failed self-test instead of quarantining the endpoint. | Every 3xx and 4xx upgrade status except 408 (retryable) and 429 (throttled) is `EndpointFatal`: the upgrade GET carries no crypto request, so its refusal is the endpoint's fault. | maki-crypto-websocket `review_error_class.rs`, `review_upgrade_errors.rs`; maki-nbdkit `review_ws_upgrade_quarantine.rs` | [#155](https://github.com/seo-rii/maki/pull/155) |
| AUD-023 | A 2xx HTTP/1.x response with neither `Content-Length` nor chunked coding ends at connection close, so the prefix an endpoint sent before dying was accepted as a complete body. With a raw mapping it became the unit's ciphertext; the write was acknowledged and the next read returned an integrity error. A well-framed short body, such as a proxy's HTML page, was accepted the same way. | A close-delimited success response is refused before its body is read, and a raw encrypt response shorter than its plaintext is refused, both as contract errors (breaker charged, retry-safe failover). The length rule is scoped to raw mappings, so BUG-049 and BUG-053's compact encodings are unaffected. | maki-crypto-http `review_short_raw_ciphertext.rs` | [#157](https://github.com/seo-rii/maki/pull/157) |
| AUD-024 | `max_response_bytes` capped wire bytes, but the JSON parser materialized every node of the body as a guarded tree: about 43 times the body size at peak, about 360 MB for a body within the default 8 MiB cap. | The parser keeps only what the response mapping reads (payload, echo and at most the requested batch elements); every other value is validated by a skipping visitor (syntax, UTF-8, number range, trailing input, recursion limit) and never copied out of the guarded body. | maki-crypto-http `review_response_memory.rs` (peak below three times the body; about 1.9 times measured); erasure tests in `sensitive_tests.rs` now place sensitive values on configured pointers | [#157](https://github.com/seo-rii/maki/pull/157) |
| AUD-025 | The pinned tungstenite `FrameCodec::read_in` zero-filled its whole spare capacity before every read and the patched `BytesMut::truncate` wiped it again, so after one large frame every read rewrote megabytes, and accumulating a frame in TLS-record-sized reads was quadratic in its size. | `read_in` hands the reader the spare capacity directly and zero-fills it once per allocation; erasure is unchanged for Maki's streams. The recorded vendor hash is updated. | maki-crypto-websocket `review_read_buffer_cost.rs` (page faults 15872 and 23344 before, 0 and 1265 after); vendored unit tests | [#160](https://github.com/seo-rii/maki/pull/160) |
| AUD-026 | Validation never inspected `remote-http` body mappings. Unknown sources or payload encodings failed only at attach, an encoding on a non-payload source was dropped silently, a pointer without a leading slash failed every request, overlapping pointers (or a field at, under or above `items_path`) dropped a context field the binding check had counted, and a declared context binding without a per-item `unit_index` validated although the self-test always refuses it. SPEC §18 listed `utf8`, `integer` and `uuid` encodings the provider never implemented. | maki-format owns the mapping parser that validation and the provider both use; it refuses each of these, and a declared context binding requires a per-item `unit_index`. SPEC §18 lists the payload encodings and the fixed representation of the other sources; the §19 example is valid TOML. | maki-format `review_http_field_mappings.rs`; maki-crypto-http `review_field_mapping_wire.rs` | [#161](https://github.com/seo-rii/maki/pull/161) |

### Credentials, secrets and logs

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-027 | Under `MAKI_LOG=trace`, or any directive enabling tungstenite, the vendored tungstenite logged every frame payload, received text message and the client upgrade request through the `log` bridge, so base64 unit plaintext and URL query credentials reached the journal. | The daemon's sink caps `tungstenite`, `tokio_tungstenite` and `reqwest` at `debug` under every directive, module and span directives included; Maki's own targets keep the operator's level. | maki-crypto-websocket `review_trace_logging.rs`; maki-core `logging.rs` `dependency_payload_targets_cannot_exceed_safe_levels_whatever_maki_log_says` | [#155](https://github.com/seo-rii/maki/pull/155) |
| AUD-028 | At `MAKI_LOG=debug`, `tungstenite::protocol` logged the peer's close reason and reply frames, which may carry request contents. | That subtree is capped at `info`; WebSocket handshake debug diagnostics remain. | `raised_maki_log_never_writes_websocket_close_reason` (`review_trace_logging.rs`) | [#155](https://github.com/seo-rii/maki/pull/155) |
| AUD-029 | The credential loader checked only the mode of an opened file. A `0600` key owned by an unprivileged user was loaded by any root process (`maki-benchmark`, a daemon started by hand), although its owner can read or replace it; the HTTP combined certificate and private-key PEM had the same gap. | A `file` credential, a file in the systemd credentials directory and a combined PEM holding a private key must be owned by root or by the process's effective user. A root process therefore refuses a key owned by the daemon user. | maki-crypto-local `review_secret_file_owner.rs`; maki-crypto-http `review_tls_files.rs` (root only) | [#158](https://github.com/seo-rii/maki/pull/158) |
| AUD-030 | An empty or whitespace-only credential file, environment variable or in-memory entry loaded as present, so the daemon built the HTTP provider with `Authorization: Bearer ` and the gRPC provider with the same empty metadata value. | Every key source refuses a value that is empty after trimming, with a `ProviderFatal` error naming the credential (SPEC §44); a padded token still loads verbatim (R5-035). | maki-crypto-local and maki-nbdkit `review_empty_credentials.rs` | [#158](https://github.com/seo-rii/maki/pull/158) |
| AUD-031 | The witness TLS key loader refused group or other access but not a foreign owner, so the witness server, the daemon's witness clients, the etcd backend client and the administrator commands loaded a `0600` key owned by an unrelated user. | A private key must be owned by root or by the process's effective user, checked on the opened descriptor while the TLS configuration is built, before any connection. Certificates and CA bundles keep their rules. | maki-witness `review_tls_key_owner.rs` (root only) | [#162](https://github.com/seo-rii/maki/pull/162) |
| AUD-032 | Validation never checked a credential `format` template. Without a `{}` the template text alone was sent, so a literal secret in `format` passed the SPEC §9 rule and a typo such as `Bearer {token}` dropped the credential; two placeholders sent it twice; `format` on `crypto.key` or a `tls.client_key` was ignored. | Validation and the provider's own credential preflight refuse a template without exactly one `{}` and `format` on keys; neither error quotes the template or the name. | maki-format `review_credential_template.rs`; adapted `review_header_template_erasure.rs` (maki-crypto-http) and `review_grpc_credential_erasure.rs` (maki-nbdkit) | [#159](https://github.com/seo-rii/maki/pull/159) |
| AUD-033 | The error for a `[crypto.http.<op>] path` without a leading slash quoted the path, which can carry path or query tokens, to stderr and the journal. | The message names the operation and the rule only. | `an_invalid_http_operation_path_is_not_echoed` (maki-format `review_config_secret_echo.rs`) | [#159](https://github.com/seo-rii/maki/pull/159) |

### Configuration validation

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-034 | nbdkit fails its `.block_size` callback, and with it every NBD handshake after READY, when the preferred block size exceeds 32 MiB; validation bounded only `nbd.minimum_io` and `nbd.maximum_io`. | An effective `nbd.preferred_io` above 32 MiB, configured or defaulted, is refused (SPEC §13). | maki-format `review_nbd_preferred_limit.rs` | [#159](https://github.com/seo-rii/maki/pull/159) |
| AUD-035 | Attach refuses a volume whose units reach the reserved key-canary unit index, but validation and `volume create` accepted such a geometry (512-byte units from just over 2 EiB), producing a volume no attach would open. | `Geometry::compute` refuses a unit count above the canary index, for validation, creation and superblock decode. A superblock with such a geometry from an older binary, which can hold no data, loads as an invalid copy (SPEC §14). | maki-format `review_canary_geometry.rs` | [#159](https://github.com/seo-rii/maki/pull/159) |
| AUD-036 | Validation required only a non-empty credential name, while the loaders accept only `[A-Za-z0-9._-]` names without a leading dot (a `credential` name, the file name of a `file` path). `volume create` stored such a key name as the immutable key identity; every attach then refused, and correcting the name was an identity mismatch. | Validation applies the loader rule to every credential reference (`env` names are unchanged) without quoting the name. | maki-format `review_credential_names.rs`; maki-nbdkit `review_credential_name_rule.rs` compares the two copies of the rule | [#159](https://github.com/seo-rii/maki/pull/159) |

### Rollback protection and witness

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-037 | Enrollment recovery proved only the authority side. A root activated before the `remote.enrollment` binding existed received a binding for the approved identity; recovery then claimed and activated an empty namespace, and its GC retired the other volume's quiescent namespaces. A failed claim after the binding write left a wrong binding. | Before rewriting the marker, binding or claiming, recovery refuses a different or corrupt binding, any GC tombstone, and any namespace other than its own whose manifest slots hold anything but this identity's empty generation-0 manifest or a torn part of it. The post-activation GC retires only the namespaces that check examined. | maki-backing `review_remote_enrollment_identity.rs`; existing `remote_extensions.rs` enrollment cases | [#156](https://github.com/seo-rii/maki/pull/156) |
| AUD-038 | `maki volume resume-enrollment` validated without the provider-availability check (M-008), so a build without the `fake-provider` feature advanced the witness fence and wrote a superblock naming provider `fake`, a volume no release daemon can attach. | The library entry point and the CLI refuse a provider this build cannot construct before the first authority read. | `resume_enrollment_refuses_a_provider_this_build_cannot_construct` (`bins/maki` `remote_admin.rs`, under `cargo test -p maki`) | [#156](https://github.com/seo-rii/maki/pull/156) |
| AUD-039 | Linux returns EPERM or EACCES from `connect()` and `send()` when netfilter drops a local packet; the witness client passed that through as `PermissionDenied`, the kind it uses for the server's own denial. Frontend failover stopped at the first endpoint, and the rollback backing stopped the session instead of refusing one operation (BUG-103). | Client and server transport errors of a kind callers treat as final report `ConnectionAborted` with their OS text; `PermissionDenied` remains only the server's denial, and TLS failures stay `InvalidData`. | maki-witness `review_local_socket_denial.rs` (seccomp-injected EPERM; skips without seccomp), plus a classification unit test | [#156](https://github.com/seo-rii/maki/pull/156) |

### Privileged helper

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-040 | Every privileged observer read `/proc/self/mountinfo` as UTF-8. One mount anywhere in the helper's namespace whose path or source is not UTF-8 (a user's FUSE mount, a Latin-1 CIFS or USB mount) made attach preflight, detach, cleanup, `maki-recover@`, recovery proofs, NBD allocation and the verify gate fail with `InvalidData` for every volume, and the post-mount observer reported nothing mounted. | One reader reads the table as bytes; paths are unescaped and compared as bytes, never decoded lossily. `observe()` and `observe_mount()` return the read error instead of an empty observation. | maki-privileged `review_mountinfo_bytes.rs` (root, private mount namespace), `allocation_tests.rs`, parser cases in `detach_tests.rs`, `recover_tests.rs` and `workload_verify_tests.rs` | [#153](https://github.com/seo-rii/maki/pull/153) |
| AUD-041 | The workload verify gate opened the mount root and `.maki-sentinel` with `O_NOATIME`, which the kernel refuses unless the caller owns the inode or has `CAP_FOWNER`. Both can belong to the workload user and `ExecStartPre=!` keeps the unit's bounding set, so a workload unit that drops `CAP_FOWNER` could never start. | Each open retries once without `O_NOATIME`, only after EPERM; the other flags and the device checks are kept. The example drop-in now says that `!` skips only the user and group switch. | `descriptor_sentinel_reader_does_not_need_cap_fowner_for_workload_owned_files`, `sentinel_opens_drop_only_o_noatime_and_only_when_it_is_refused` (maki-privileged `workload_verify_tests.rs`) | [#153](https://github.com/seo-rii/maki/pull/153) |

### Validation tooling, CI and documentation

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-042 | The unrelated-user socket probe and the unprivileged NBD disconnect probe of `scripts/privileged-linux-validation.sh` passed on any nonzero exit, so a sudo policy refusal, a missing command or an `nbd-client` usage error was logged as PASS. | Each probe requires the expected permission denial, with the run's own backend still connected; anything else stops the run and prints the output. The [runbook](qualification/privileged-linux-validation.md#denial-check-harness-correction--2026-11-16) names the earlier results those checks cover. | `scripts/test_privileged_denial_validation.py` | [#151](https://github.com/seo-rii/maki/pull/151) |
| AUD-043 | The nightly plugin gate's `nm -D \| grep -q plugin_init` also matched an undefined or prefixed symbol, and the fake-provider gate passed on any `maki volume create` failure, including a configuration that no longer validates. | The gates require a defined text symbol named exactly `plugin_init` and the daemon's `provider "fake" is not compiled into this build` refusal. | `scripts/test_ci_gate_validation.py` | [#151](https://github.com/seo-rii/maki/pull/151) |
| AUD-044 | On Linux `scripts/run_cargo_tests.py` added `--no-run` to every selection, including `--doc`, which Cargo refuses, so the wrapper could not run doc tests. | A `--doc` selection is forwarded verbatim. | `test_doc_test_selection_is_forwarded_without_a_compile_phase` (`scripts/test_cargo_tests_validation.py`) | [#151](https://github.com/seo-rii/maki/pull/151) |
| AUD-045 | The vendor erasure contract never compared resolved features, although the transport-memory guide said parser features were checked; the guides said no optional `serde_json` mode was enabled, yet `maki-witness` enables `raw_value`; and the inventory skipped every path with a `target` component. | `check()` compares each patched package's resolved features with a reviewed list and fails on a missing resolve section or node; only a package-root `target/` is skipped; the guides state what is enabled. | `scripts/test_vendor_erasure.py` | [#160](https://github.com/seo-rii/maki/pull/160) |
| AUD-046 | The standalone `hyper` and `tungstenite` vendor test graphs depended on unmaintained `humantime` (RUSTSEC-2026-0542) through their test loggers, which the per-lockfile `cargo audit --deny warnings` job refuses. | Both use `env_logger` 0.11.11; the manifest and lockfile hashes are recorded in `vendor/patches.json`. The workspace lockfile and production logging are unchanged. The same commit was merged into #159, #160 and #165. | The CI dependency audit and the standalone vendor suites | [#155](https://github.com/seo-rii/maki/pull/155) |
| AUD-047 | The link checker ignored fragments: an in-page `#anchor` was skipped and `other.md#anchor` checked only the file. The changelog linked to an anchor that GitHub's slug for "Correctness and recovery review — 2026-10-12" does not produce. | Fragments on Markdown targets must match a heading slug as GitHub computes it, or an explicit `<a id>`/`<a name>`; CONTRIBUTING describes the rule. 179 anchored links are checked; the changelog link was the only broken one. | `DocumentationAnchors` in `scripts/test_docs_links.py` | [#152](https://github.com/seo-rii/maki/pull/152) |
| AUD-048 | Without a durable mark the deep check reported "heuristic torn-tail classification", a rule recovery has not used since M-007 and S-04. | The report describes the actual rule: the final segment is proven only as far as the durable proof names it, otherwise only its header. Message text only. | `deep_check_reports_the_rule_recovery_uses_without_a_durable_mark` (maki-core `review_check.rs`) | [#152](https://github.com/seo-rii/maki/pull/152) |
| AUD-049 | `BackingFile::allocate_range` claimed that a successful `posix_fallocate` guarantees later writes cannot fail for space. On XFS with reflink (the `mkfs.xfs` default) a `cp --reflink` copy, which coreutils 9 makes by default, shares extents; `posix_fallocate` does not unshare them, so a later in-place slot write or recovery journal rewrite can fail with ENOSPC and the volume degrades. | Documentation only: the comment states the limit, and the support matrix, the [status page](status.md#known-limitations) and the operations guide require backing copies without shared extents (`cp --reflink=never`). Maki does not detect sharing. | — | [#152](https://github.com/seo-rii/maki/pull/152) |
| AUD-050 | Several statements no longer matched the code: CLAUDE.md said a failed A/B store empties its unsynced side (N-09's approach, which BUG-001 replaced); SPEC §20 omitted that reload applies `cache.ttl`; the operations guide implied `maki-check --journal-segment-size` can change a verdict; this log cited renamed tests for M-015, F09, MAKI-011 and the S-01 truncation entry; and two counts in the performance and testing guides were wrong. | Corrected. MAKI-011 is stated to be covered only indirectly. | The link checker | [#152](https://github.com/seo-rii/maki/pull/152) |
| AUD-051 | SPEC, the configuration and operations guides and the storage-recovery page said recovery rechecks the `[lvm_identity]` pins (against a fresh LVM report); only attach runs that report. | Documentation only: recovery, and a detach that consumes a pre-activation intent, check the identity attach persisted against the pins and the live NBD geometry and device-mapper mappings against that identity, or after activation against the mapping proof. | Existing `recovery_rechecks_persisted_lvm_identity_against_administrator_pins` (maki-privileged `lvm_preflight_tests.rs`) | [#153](https://github.com/seo-rii/maki/pull/153) |

### Not closed in this pass

- A final journal segment that an earlier binary left with a complete-length
  torn header (it extended the file before writing the header) is still
  refused as durable damage (AUD-003). *Closed by AUD-054
  ([#177](https://github.com/seo-rii/maki/pull/177)).*
- With a journal watermark at or below the segment size, reachable only at
  exact equality in a daemon-validated configuration, every write above it
  still triggers a worker pass, which now syncs and checkpoints (AUD-005).
  *Closed by AUD-053 ([#176](https://github.com/seo-rii/maki/pull/176)),
  which also found that validation keeps the watermark above one segment, so
  only an engine configured directly reached this.*
- The `maki-witness` server configuration file is checked for group and other
  write but not for its owner, and the witness state directory has no owner
  or mode check (AUD-031). *Closed by AUD-075 and AUD-076
  ([#170](https://github.com/seo-rii/maki/pull/170)).*
- AUD-024 bounds HTTP JSON responses only; the WebSocket and gRPC response
  parsers are unchanged. *Closed by AUD-066 and AUD-067
  ([#173](https://github.com/seo-rii/maki/pull/173)).*
- `recovery_rewrites_page_cache_bytes_it_accepts_after_a_failed_writeback`
  (`review_writeback.rs`) and
  `process_recovery_rewrites_clean_cache_bytes_before_sealing_the_journal`
  (`review_journal_writeback.rs`) let recovery finish and do not detect the
  removal of its prefix rewrite; AUD-006's sweep does. Under page-granular
  writeback (AUD-008), `a_failed_intermediate_sync_stops_append_and_can_resume`
  (`review_journal_pending.rs`) no longer detects the removal of the journal's
  F01 rewrite either; it tests pending-byte accounting and is unchanged.
  *Closed by AUD-064 ([#175](https://github.com/seo-rii/maki/pull/175)): all
  three now fail without their rewrite.*
- The denial texts AUD-042 accepts follow libnbd's and `nbd-client`'s formats
  but have not yet been observed in a privileged run; a mismatch fails closed
  and prints the captured output.
- `CrashableBacking::try_lock` still accepts a directory name (AUD-010 changes
  `MemBacking` only), and the link checker does not verify reference-style
  link definitions (AUD-047). *Closed by AUD-063
  ([#175](https://github.com/seo-rii/maki/pull/175)) and AUD-084
  ([#171](https://github.com/seo-rii/maki/pull/171)).*

## Comprehensive review follow-up (2026-11-14)

This revision addresses twelve actionable findings from the review of
`d2380cf`. The changes preserve the volume format and the existing provider
trust policy. They do not expand the project's qualified deployment scope.

| Finding | Change | Portable regression evidence |
|---|---|---|
| BUG-178: ambiguous or missing final gRPC status | Require one valid final status before accepting a unary result; preserve legitimate remote errors and HTTP proxy failure classification. | `maki-crypto-grpc/tests/review_final_status.rs`, existing initial-status and HTTP-status suites |
| BUG-181: unusable custom CA material | Reject empty, certificate-free, malformed, or invalid-DER bundles in HTTP, gRPC and WebSocket, including a bad certificate mixed with a valid root; accept multiple valid roots using the existing additive policy. | All three providers' `tests/review_ca_bundle.rs`, existing TLS and custom-CA suites |
| BUG-083: capability lookup retains abandoned scheduler work | Cancel the asynchronous retry-safety lookup when the last caller cancels or expires, releasing inputs and the lane slot while preserving live siblings. | `maki-crypto/tests/review_scheduler_capability_cancellation.rs` |
| BUG-183: idle worker misses late checkpoint cleanup failure | Track unfinished journal cleanup independently of the published checkpoint horizon and retry its directory barrier with backoff. | `maki-core/tests/review_checkpoint_cleanup_retry.rs` |
| BUG-184: failed TRIM release blocks healthy ranges | Continue a bounded reclamation sweep past failed windows, then retry from the earliest failure after an independent interval. | `maki-core/tests/review_reclamation_progress.rs`, existing discard/reclamation and power-loss suites |
| BUG-182: fast checker overlooks unusable v3 orphan metadata | Validate the required discard map before claiming an in-geometry orphan can be adopted; preserve fallback warnings and inconclusive I/O errors. | `maki-core/tests/review_orphan_discard_check.rs` |
| BUG-179: disconnect acknowledgement prematurely retires cleanup state | Keep the trusted record until the backend is absent and resource observations are empty; incomplete teardown returns an error and remains retryable. | `maki-privileged/src/exec_tests.rs` |
| BUG-080: supported LV inventory exceeds the record limit | Bound both encoded writes and reads at 256 KiB, reject oversize before creating a temporary file, and enforce the existing 64-LV recovery limit during preflight. | `maki-privileged/src/state_tests.rs`, `exec_tests.rs` |
| BUG-137: hidden LV display names cannot be persisted | Normalize LVM's `[name]` spelling before recording identity; continue rejecting invalid, ambiguous, and hidden configured targets. | `maki-privileged/src/lvm_preflight_tests.rs`, `exec_tests.rs` |
| BUG-168: semantic configuration errors echo input | Report the field and constraint without embedding arbitrary configuration values. | Both helper/API and CLI `review_attach_config_diagnostics.rs` suites |
| DOC-002: failed workload startup still creates data | Gate quickstart writes and PostgreSQL initialization on successful start, active services, and attachment verification inside fail-fast subshells. | `scripts/test_workload_start_validation.py`, using the actual documentation blocks and harmless mocks |
| BUG-180: shared libraries accepted as CLI package inputs | Require executable loader metadata and a nonzero entry point while retaining dynamic/static PIE and ET_EXEC support. | `scripts/test_debian_package.py`, including a native shared-library fixture |

The retained regressions use private files, local providers, fault injection,
virtual clocks, and simulated device observations. They do not demonstrate
physical power-loss safety or qualify a real NBD/LVM/XFS stack. In particular,
delayed kernel disconnect still needs target-stack verification; the helper
now preserves the authority needed to retry it safely.

Six findings remain outside these fixes: first-write synchronization of all
adopted shard maps after reopen (PERF-006); crypto scratch/CPU budgets
(ARCH-007); HTTP JSON node/allocation budgets (ARCH-008); physical memory
retained by checkpoint snapshots beyond logical overlay accounting
(ARCH-009); the fail-closed policy for optional durable-mark I/O errors
(ARCH-010); and the non-atomic stop/recovery scheduling boundary (BUG-177).
Those require separate durability, resource-budget, or lifecycle decisions.
Keep using the documented maintenance serialization procedure for recovery
and stop; these changes do not claim to resolve that race.

Later update (2026-11-17): AUD-024
([#157](https://github.com/seo-rii/maki/pull/157)) makes the HTTP response
parser keep only the values the response mapping reads, so parsing a JSON
response takes about twice its size in memory (the regression bounds it below
three times) instead of about 43 times. That bounds what ARCH-008 describes for
HTTP responses; unselected values are validated but never allocated, so no
separate node-count budget was added. The other five items remain open.

## Sentinel diagnostic contents (BUG-167, 2026-10-26)

Mount identity rejection and an initialization attempt over an existing
sentinel included the observed file contents in their errors. The workload
owns that file, so a malformed sentinel could send decrypted payload bytes
to helper stderr or a service log. Both paths now report a value-free mismatch;
the verifier identifies a missing or unreadable sentinel separately. UUID
case handling and the atomic, no-replacement write/retry protocol are unchanged.

`maki-privileged`'s `review_sentinel_diagnostics.rs` first reproduced both
leaks, then checks `Display`, `Debug`, and the error source chain for arbitrary
text and a different well-formed UUID. It also covers missing sentinels,
preservation of rejected files, creation, and identical case-insensitive
retries. The executor tests use only disposable regular files; no mount,
LVM, NBD, service, or physical qualification runs are implied.

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

The [project assessment](qualification/historical-reviews/project-review-2026-09-05.md) of `8b06c53` found nine
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
  allocation on a privileged Linux target
  (`docs/qualification/privileged-linux-validation.md`).
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
| M-004 no automatic checkpointing; journal / free-space bounds unenforced | Fixed | See [Bounded journal](#bounded-journal): a background checkpoint worker (watermark, low free space, interval), a forced journal sync at `limits.max_journal_pending_bytes`, inline reclaim and ENOSPC at `backing.journal_max_bytes`, and fresh fail-closed admission unless free space covers `backing.journal_emergency_reserve_bytes` plus the projected record/segment-header footprint of the request. It also exposes a `Degraded` state and the `maki_backing_free_bytes` / `maki_journal_bytes` / `maki_checkpoint_lag_bytes` metrics. `Backing::free_bytes` (statvfs on Unix) feeds the reserves. Config validation requires `journal_max_bytes >= 2 * journal_segment_size`. | `review_bounded.rs` and `review_r3_space_admission.rs` (maki-core): hard journal bounds, forced sync, fresh high/low observations, exact append boundary, overflow, unknown and query-error rejection |
| M-005 control socket not started by the daemon; no-op reloads | Fixed | `NbdAdapter::open_config` binds the control socket (`control.socket`, default `/run/maki-control/<volume>/control.sock`) on the adapter's runtime before returning and serves `EngineControlBackend` on it; a bind failure fails attach; `shutdown` stops the server and removes the socket. `reload` returns an explicit "NOT applied" error for every section the engine cannot apply at runtime (`retry`, `circuit-breaker`, `batch`, `limits`, `timeouts`, `semaphores`, `endpoints`, `credentials`); only `cache` is applied, and it requires `max_bytes`. `status` reports the engine state, journal size, free space, and checkpoint counters. | `review_control.rs` (maki-nbdkit, Unix): `control_socket_is_created_served_and_removed`, `missing_control_socket_directory_fails_attach` |
| M-006 mount-identity verification is a no-op | Fixed | The Linux executor's `VerifyMountIdentity` step now gathers real observations (`/proc/self/mountinfo` fstype and source through the pure `parse_mountinfo`, `blkid` filesystem UUID, `<mountpoint>/.maki-sentinel`, sysfs NBD `pid` state, a write-fsync-read-remove probe) and runs the existing pure verifier; a failure rolls the attach back. The volume UUID comes from the root-owned attach config or `--uuid` and is required for execution (`--plan` still renders without it). `--init-sentinel` writes the sentinel on an empty filesystem, never overwriting a different value. The unit now carries `AssertPathExists` on the attach config (BUG-002) and documents that dependents must use both `Requires=` and `After=`. | `mountinfo_parsing_finds_the_visible_mount_and_decodes_escapes`, `verifier_rejects_wrong_device_and_missing_sentinel`, `execution_requires_a_volume_uuid_but_plan_rendering_does_not` (maki-privileged); `plan_mode_works_without_uuid_but_execution_requires_it` (maki-attach process). Real mount/rollback runs need the privileged Linux target (`docs/qualification/privileged-linux-validation.md`). |
| M-009 A/B reader collapses I/O errors into "invalid copy" | Fixed | `AbStore` reports any I/O failure other than not-found as an error; empty, short, and CRC-invalid copies remain "invalid". `create_volume` writes both checkpoint-state copies (sequence 0) and recovery requires a valid copy on every volume instead of defaulting to 0. | `recovery_requires_valid_checkpoint_state`, `recovery_surfaces_hard_io_error_on_checkpoint_state`, `ab_load_reports_hard_io_errors_instead_of_masking_them`, `ab_load_treats_missing_empty_and_corrupt_sides_as_invalid_copies`, `create_volume_writes_checkpoint_state_and_durable_mark` |
| M-010 retry ignores `retry_safe`; no absolute deadline | Fixed | `DispatchConfig` carries `retry_safe` and `max_operation_time`. A non-retry-safe provider is sent a request at most once (no retry, no failover; the WebSocket transport's transparent reconnect-and-resend is disabled too). *Refined by AUD-068 ([#174](https://github.com/seo-rii/maki/pull/174)):* an attempt whose transport proves that no request byte was written does not count as a send, so until one may have been sent the request fails over and, under the availability policy, is retried. `bounded-error` is an absolute deadline measured on the injectable clock: backoff sleeps are capped to the remaining time and an in-flight RPC is abandoned when it expires (`deadline_exceeded_total`). Retry budgets are now endpoint-local (SPEC §32) instead of one bucket for the set. | `review_dispatch.rs` (maki-crypto): `non_retry_safe_provider_is_never_retried`, `retry_safe_provider_fails_over_within_the_pass`, `bounded_error_obeys_wall_clock_deadline_during_an_rpc`, `retry_backoff_never_sleeps_past_the_deadline`; `non_retry_safe_websocket_never_resends_after_a_transport_failure` (maki-crypto-websocket) |
| M-011 unvalidated endpoints enter the serving pool | Fixed | `EndpointSet::with_quarantine` admits only validated endpoints. At attach the daemon first probes each endpoint on its own (three attempts, spaced by the retry delay) so an unreachable *reference* can no longer poison the check, cross-validates the reachable ones against the first reachable endpoint, quarantines the rest, and refuses attach when nothing is reachable or an endpoint is proven non-interchangeable. A validator reruns the cross-endpoint check for quarantined endpoints against a validated one under the real volume context, at most once per breaker interval; proven non-interchangeability excludes the endpoint permanently. `endpoint_status()` exposes the flags. Retry budgets are per endpoint, charged only to repeat attempts on that endpoint. | `unverified_endpoint_never_enters_serving_pool`, `proven_incompatible_endpoint_is_excluded_permanently`, `capabilities_come_from_a_validated_endpoint` (maki-crypto) |
| M-012 reordered batch results undetected (WebSocket, positional HTTP) | Fixed | WebSocket response items must echo `unit` in request order (missing, reordered, duplicated, or wrong echoes are `Contract` errors); HTTP batch layouts require `item_index_path` at validation; gRPC already echoed `unit_index`. SPEC §18 now states the identity contract. | `ws_rejects_reordered_batch_items`, `ws_rejects_missing_unit_echo`, `ws_rejects_wrong_unit_echo`, `ws_accepts_correct_unit_echo` (maki-crypto-websocket); `http_batch_layout_requires_unit_echo` (maki-format) |
| M-013 incomplete configuration validation; placebo settings | Fixed | `validate_settings` and `validate_provider_sections` (see [Configuration](configuration.md#validation-rules)): positive counts and byte limits, finite ratios and probe rates, ordered delay and breaker ranges, batch targets within maxima, capability mode, bounded-error timing, NBD size ordering, cache and control values, memory-lock mode, provider-specific required and forbidden sections, endpoint URL parsing, and the `keyring` source refused. The `[security]` section is now applied by `maki_nbdkit::security::apply` before attach (Linux, fail closed): `disable_core_dump` via `prctl` + `RLIMIT_CORE`, `memory_lock_mode = "all"` via `mlockall`, `"secure-buffers"` via per-`SecretBuffer` `mlock` (opt-in in `maki-crypto`, failures counted), `require_secure_swap_policy` via `/proc/swaps` plus dm-crypt detection; `madv_dontdump` is honoured through the non-dumpable flag and validation refuses it without `disable_core_dump`; `cache.lock_memory` follows the lock mode and validation refuses it with `off`. The posture is reported under `security` in `status`. Non-Linux hosts report `unsupported-platform`. The secure-swap policy defaults to off (explicit production opt-in; the shipped example enables it). | `review_config.rs` (maki-format): `zero_and_inverted_bounds_are_rejected` (28 cases), `capability_mode_and_availability_policy_are_checked`, `keyring_credential_source_is_refused`, `local_provider_requires_key_and_rejects_transport_sections`, `duplicate_or_empty_endpoint_names_are_rejected`, `defaults_still_validate`; `review_security.rs` (maki-nbdkit): `inconsistent_security_settings_are_rejected_at_validation`, `swap_parser_is_strict`, `posture_is_recorded_and_reported`, `linux_disables_core_dumps_for_real` (Linux); `page_locking_is_opt_in_and_accounted` (maki-crypto) |
| M-014 production sample cannot attach | Fixed | `packaging/examples/postgres-prod.toml`, the SPEC §57 example, and the `full_config.toml` fixture now carry complete `[crypto.http.encrypt]` / `[crypto.http.decrypt]` batch mappings with unit echo and a credential-referenced bearer token; validation requires both mappings for `remote-http`. | `production_sample_and_full_fixture_validate`, `remote_http_requires_endpoints_and_both_mappings` (maki-format); `production_sample_builds_provider_successfully`, `production_sample_fails_without_its_credential` (maki-nbdkit `review_sample.rs`) |
| M-015 WebSocket / gRPC without TLS | Fixed | Validation refuses plaintext `http://`, `ws://`, and gRPC `http://` endpoints unless the host is loopback, refuses `wss://` / gRPC `https://` / transport TLS sections as not compiled in, and rejects URL userinfo. The HTTP provider fails closed on unreadable or invalid CA and client-certificate files, applies `client_key` from its credential source, and refuses `server_name` instead of ignoring it. The daemon's credential router reads path-like names as files. | `plaintext_transports_are_loopback_only`, `websocket_and_grpc_require_their_sections_and_accept_tls` (cited here originally as `..._and_reject_tls`; since WSS and gRPC TLS were implemented it accepts `wss://` and gRPC `https://` and refuses an unreadable transport `ca_file`), `tls_files_must_exist_and_server_name_is_refused`, `endpoint_url_parsing_and_loopback_detection` (maki-format); `unreadable_tls_material_refuses_the_provider`, `client_key_credential_is_appended_to_the_identity` (maki-nbdkit) |
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
| F01 | **A failed `fdatasync` was retried by calling it again.** Linux marks the dirty pages clean when writeback fails, so the retry succeeded without writing anything: the second FLUSH (or a later FUA) acknowledged records that never reached the disk, and recovery after a restart did the same for page-cache bytes (K-01 only synced them). | Same finding as BUG-021, whose implementation is the one in the tree: the writer fingerprints every record accepted since the last successful sync and, once a sync has failed, re-reads and rewrites that range in 64 KiB chunks, verifies the fingerprint, and only then syncs again; changed or lost bytes refuse the barrier. Recovery rewrites and verifies every accepted segment prefix before it syncs. `status`/`metrics` expose `journal_sync_failures_total` and `journal_writeback_uncertain`. `CrashableBacking` models the Linux behaviour by default (a failed sync loses its dirty writes but keeps them readable; `set_lenient_sync_failures(true)` restores the old model). *Superseded by AUD-008 ([#165](https://github.com/seo-rii/maki/pull/165)):* a failed sync's writes stay readable but uncertain (a later crash may keep them, whole or torn; `crash_all_lost` drops them), a bare retry still writes nothing, and a successful sync writes back every re-dirtied 4 KiB page whole. | `review_writeback.rs` (maki-core): `flush_after_a_failed_sync_rewrites_lost_records_before_acknowledging`, `fua_after_a_failed_sync_covers_every_pending_record`, `seal_after_a_failed_sync_rewrites_before_opening_a_successor`, `barriers_keep_failing_until_the_rewrite_persists`, `recovery_rewrites_page_cache_bytes_it_accepts_after_a_failed_writeback`; `failed_sync_marks_dirty_writes_clean_and_lost` (maki-test-support) |
| F03 | **A partial `write_at` left a torn tail the next seal carried as corruption.** `write_all_at` can persist a prefix and then fail; the logical offset did not move, a shorter retry record did not cover the torn bytes, and the roll sealed the file at its physical length. Recovery treats a non-final segment as durable in full and refused the volume. | Same finding as BUG-020, whose implementation is the one in the tree: the writer marks the tail on any append failure and truncates the file back to the logical end before the next append or seal, keeping the flag until the truncation has been synced; while that truncation fails, appends, rolls and barriers fail too. The debug sanitizer asserts the file length equals the logical end. `CrashableBacking` gained a partial-write hook. | `partial_append_failure_leaves_no_garbage_for_the_next_seal`, `crash_right_after_a_partial_append_is_a_torn_tail`, `appends_are_refused_while_the_torn_tail_cannot_be_normalized` (maki-core); `partial_write_hook_persists_a_prefix_and_fails` (maki-test-support) |

### Security and operations (P1)

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| F02 | **The mount was verified by filesystem type, UUID, sentinel and probe, never by which block device it was on.** With `init_sentinel` the helper wrote the expected sentinel onto whatever XFS it had mounted (a local LV of the right name) and then verified its own sentinel: application data could land outside Maki in plaintext. | A new `verify-mount-device` step runs right after `mount`, before the sentinel or the probe touch the filesystem: the mount's `major:minor` is walked through the sysfs `slaves` relation (device-mapper, MD) down to the leaf devices, and every leaf must be the NBD device this attach connected (partitions fold into their device). Mixed volume groups and unresolvable topologies are refused. `verify_mount_identity` repeats the check. | `a_filesystem_not_stored_only_on_the_bound_nbd_device_is_refused_before_it_is_touched`, `leaf_devices_are_resolved_through_the_device_mapper_stack`, `mountinfo_parsing_exposes_the_device_number`, updated `init_sentinel_adds_a_write_step_before_verification` and `verifier_rejects_wrong_device_and_missing_sentinel` (maki-privileged). A real LVM-over-NBD run still needs the privileged Linux target. |
| F04 | **Locked secret buffers shared heap pages.** `mlock`/`munlock` work on whole pages with no reference count: dropping one `SecretBuffer` unlocked the page of a live neighbour, which still reported itself locked. | Same finding as BUG-006, whose implementation is the one in the tree: page ownership is reference-counted under the same lock as `mlock`/`munlock`, so a page is unlocked only by its last owner, after zeroization. | `dropping_a_buffer_never_unlocks_a_live_neighbours_pages` (`review_secret.rs`, Linux: every survivor's address must still sit in a `VmFlags: lo` VMA in `/proc/self/smaps`), `review_secret_page_lifetime.rs`, existing `dropping_locked_buffers_releases_their_pages` |
| F05 | **The secure-swap check passed unsafe layouts.** Any path containing `zram` counted as safe (`/var/swap/zram-backup`), an unreadable `/proc/swaps` read as "no swap", and a real zram device with a writeback `backing_dev` was assumed RAM-only. | Classification is by device identity: `/dev/zramN` exactly, with `/sys/block/zramN/backing_dev` equal to `none` (or absent) for RAM-only, a dm-crypt backing for encrypted, anything else unsafe; dm-crypt by device-mapper UUID as before. `/proc/swaps` must be readable and start with its header line or attach is refused. SPEC §37 and the configuration reference say so. | `swap_classification_never_trusts_a_name`, `zram_writeback_target_is_read_from_sysfs_not_assumed`, `unparseable_proc_swaps_is_an_error_not_no_swap`, updated `swap_parser_is_strict` (maki-nbdkit) |
| F06 | **A detach decided its device outside the attach lock.** `plan_detach` read the bound-device record before `execute` locked; a detach, re-attach (to another device) and another volume's attach in between left a stale plan that unmounted the current mount and disconnected the other volume's device. The record was also written before `nbd-client` ran and was not removed when a failed attach rolled back. | Superseded by BUG-003 and BUG-010: the planner never reads runtime state; the executor resolves the trusted record (configuration identity plus a unique kernel connection identifier) under the root-controlled lock, refuses a detach whose request or live backend does not match it, and verifies the identity again immediately before every disconnect, rollback included. | `exec_tests.rs`, `state_tests.rs`, `regression_attach_state.rs` (maki-privileged); the process interleaving itself needs the privileged Linux target |
| F07 | **`nbd.maximum_io` and the plaintext budget were not hard limits.** The byte semaphore capped an oversized request to the whole budget instead of bounding it, admission charged the request length while a partial write holds whole units, and the adapter copied the entire NBD request before admission. | The engine refuses any request above `max_request_bytes` (= `nbd.maximum_io`); at the NBD boundary the limits are advertised through the `block_size` callback and a request outside them is refused with EINVAL before its plaintext is copied (BUG-011, which replaced this pass's request splitting; R5-038 restored splitting above the maximum, chunk by chunk, after the Linux 6.12 NBD driver was seen ignoring it); admission charges every touched crypto unit in full (`Engine::admission_cost`); validation requires `limits.max_plaintext_bytes >= nbd.maximum_io + crypto_unit_size`. | `requests_above_the_configured_maximum_are_refused`, `admission_charges_every_touched_unit_in_full` (maki-core `review_limits.rs`); `review_nbd_limits.rs` (maki-nbdkit); a new case in `zero_and_inverted_bounds_are_rejected` (maki-format) |

### Hygiene (P2 and additional items)

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| F08 | `can_fua` returned 1, which is `NBDKIT_FUA_EMULATE` (nbdkit-common.h: NONE 0, EMULATE 1, NATIVE 2), so nbdkit emulated FUA with a full flush after every FUA write and the engine's native FUA path was never exercised in production. | `can_fua` returns `NBDKIT_FUA_NATIVE`; every `NBDKIT_*` constant is named once. `review_abi.rs` compiles a C probe against the installed `nbdkit-plugin.h` (API version 2) and compares every field offset of the mirrored struct, up to the `block_size` callback the prefix now covers (BUG-011), and every constant; CI's nightly job installs `nbdkit-plugin-dev` and runs it; WSL has the header installed. | `fua_is_advertised_as_native_not_emulated`, `declared_prefix_ends_after_the_block_size_callback` (unit), `shim_constants_and_layout_match_the_installed_header` (Linux, header 1.46.2) |
| F09 | The HTTP provider copied plaintext into plain vectors, JSON documents and request bodies that were never wiped, and parsed decrypt responses through plain buffers. | Payload copies, the serialized body, response owner and decoded payloads use zeroizing owners. Fixed-size decoders erase malformed partial Base64/hex output; response growth wipes the replaced allocation; guarded JSON request trees drain and wipe keys, overwritten values and partial construction on every return. Resolved header/query values and the assembled mTLS identity PEM are erased on normal drop and construction errors, without an intermediate UTF-8 byte-vector copy. Source configuration strings, malformed-response allocations discarded inside serde_json, page locking, and copies inside reqwest, hyper, rustls and the kernel remain documented residuals. | provider conformance/chaos suites; `malformed_base64_erases_partial_decoded_output`, `malformed_hex_erases_partial_decoded_output`, `response_growth_erases_the_replaced_plaintext_allocation`, `zeroize_json_erases_object_key_allocations`, `pointer_error_erases_the_incoming_value`, `pointer_overwrite_erases_the_replaced_value`, `pointer_descent_erases_a_replaced_intermediate_value`, `per_item_build_error_does_not_copy_borrowed_request_metadata` and `batch_build_error_does_not_copy_borrowed_item_metadata` (requests are now serialized from borrowed input without a JSON tree, so these assert that a failed build makes no copy, not that a partial tree is wiped), `http_request_partial_fixed_serialization_erases_its_output`, `http_request_mapping_errors_and_duplicate_keys_erase_owned_key_storage`, `provider_drop_erases_owned_header_and_query_values`, `provider_construction_error_erases_owned_credentials`, `tls_spec_drop_erases_identity_pem`, `config_error_erases_a_resolved_credential_header` |
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
| BUG-022 | **Journal reclaim could outrun the durability of the checkpoint state that authorized it.** A checkpoint-2 state whose sync failed could be read from the page cache after a restart, used to reclaim journal, and then lost to a power loss — leaving an older checkpoint whose covering segment was gone, so recovery refused to bridge. | Recovery re-persists the checkpoint state it selects before the writer resumes. Every A/B store first rewrites and syncs the other valid copy and its directory before overwriting the selected target; a failed target sync may leave volatile bytes readable, but cannot destroy the preserved durable copy. Recovery persists whichever valid state it selects before journal mutation, so reclaim rests only on durable state. | `journal_reclaim_never_outruns_checkpoint_state_durability` (maki-core `review_next_storage.rs`) |
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
| BUG-026 | **Transport limits did not cover a reachable full crypto batch.** A whole batch is sent as one gRPC message / one WebSocket frame; an undersized limit validated but rejected large batches at runtime. Zero limits also passed. | `validate_provider_sections` checks the serialized maximum batch reachable under both the item and plaintext-byte limits, including maximum ciphertext and framing. Both transport limits must be positive and share defaults with the daemon. BUG-162 removes the old raw-byte floor, which incorrectly treated unused byte capacity as a message that could be sent. | `remote_transport_batch_must_fit_the_frame_or_message_limit` (maki-format `review_config.rs`), plus the singleton transport regressions described below |

## Fast-checker / recovery drift (2026-09-07): BUG-027

The offline `maki check` fast path (`maki-format::checker::check_volume`) and
recovery/attach (`maki-core::store::SlotStore::open`) disagreed on one state, so
`maki check` could report "passed" on a volume `maki attach` would refuse — the
opposite of the tool's purpose (a green pre-attach check that then fails to
attach). Not a durability bug; a fail-*open* diagnostic gap.

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| BUG-027 | **`maki check` passed a volume `maki attach` would reject: a cataloged shard with a missing data file was only a warning when its allocation map was empty.** The fast checker errored on a missing data file *only* inside the `map.set_count() > 0` arm, then pushed an unconditional "data file not yet created" warning otherwise — so a cataloged shard with a valid but empty allocation map and no data file left the report error-free (`ok() == true`). `SlotStore::open`, though, opens every cataloged shard's data file with `create=false` regardless of its allocation map and returns `CoreError::Corrupt` if it is absent, so recovery refuses to attach. The "not yet created" state the warning described cannot arise for a *cataloged* shard: `ensure_shard` creates and `sync_dir`s the data file's dirent *before* the catalog names the shard (the reverse ordering only ever yields an orphan data file, which is adopted, not a cataloged shard with no file). | The missing-data-file check is a single unconditional error per cataloged shard, matching recovery, and the misleading warning is removed. `maki check` now fails exactly when attach would. | `fast_check_flags_a_cataloged_shard_with_no_data_file` (maki-core `review_check.rs`) |

## Deep-check metadata I/O failures (BUG-133, 2026-10-26)

An I/O failure while inspecting checkpoint copies, loading checkpoint state or
reading the key canary now stops the deep check with the original error kind
and OS error number. The same rule covers wrapped metadata I/O errors from the
journal scanner and slot store after the fast check has succeeded. An unreadable
file no longer contributes to an `unrecoverable` verdict; invalid bytes and
foreign-volume metadata retain their existing corruption classification.

[`review_deep_metadata_io.rs`](../crates/maki-core/tests/review_deep_metadata_io.rs)
injects one-shot failures into those five boundaries, including a successful
earlier inspection or later read. It checks that removing the fault restores a
clean report and the original checkpointed and journaled ciphertext. Controls
cover fast-check I/O propagation, damaged checkpoint copies, a foreign canary,
and valid A/B fallback. This changes diagnostics only; disk formats, recovery
ordering and durability guarantees are unchanged.

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
  regression needs that observer harness first. Later transport-memory changes
  supersede these provider-owned WebSocket/gRPC gaps and add that observer;
  library copies, page locking and total resident accounting remain open.
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

Later update: [native startup readiness](operations.md#data-plane-readiness)
now initializes the adapter once in `after_fork`, before any client opens it.
This supersedes the cold-open initialization finding above. The other bullets
describe that review's snapshot; consult the [current remediation status](qualification/historical-reviews/production-readiness-review-2026-09-08.md)
for their subsequent fixes and remaining limits.

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
| MAKI-011 | **The tamper and context-binding self-tests accepted *any* error** as proof, so a provider that returns a transport error only on the tampered/moved request passed. | Both require a definitive bad-ciphertext rejection (`NonRetryableRequest` class); a transport/retryable error leaves the claim unproven and refuses attach. Context binding also accepts Ok-with-different-plaintext. | No dedicated test remains. `followup_inconclusive_negative_probe_preserves_retry_class` (maki-crypto `review_audit2.rs`, FUP-008) covers it indirectly: its provider answers every negative probe with a transport error and the self-test must fail; the first probe it reaches is context binding, so the tamper probe's transport-error case is exercised only through the shared `classify_probe_err`. *Since AUD-065 ([#175](https://github.com/seo-rii/maki/pull/175)):* `a_transport_error_on_the_tamper_probe_alone_leaves_integrity_unproven` (same file) fails only the tamper probe's decrypt with a transport error and requires the self-test to fail with that class |
| MAKI-016 | **gRPC/WebSocket embedded the remote error message verbatim** in an error, allowing log injection (newlines) or log flooding — unlike HTTP. | `maki_crypto::sanitize_external_message` (strips control chars, caps length) wraps both remote messages; the mapped error class is preserved. | `sanitize_strips_control_chars_and_caps_length` (maki-crypto), `map_status_sanitizes_remote_message` (maki-crypto-grpc) |
| MAKI-017 | **An unreadable zram `backing_dev` (EACCES/EIO) was classified RAM-only**, so an unencrypted writeback target could be trusted as safe swap. | `classify_zram_backing` keeps a missing attribute (NotFound) as RAM-only but fails closed (Unsafe) on any other read failure. | `zram_backing_read_failure_is_unsafe_not_ram_only` (maki-nbdkit `security.rs`) |
| MAKI-026 | **A corrupt small metadata file was read up to the 1 GiB common cap**, and `Superblock::decode` accepts its valid prefix. | Per-type `AbRecord::MAX_ENCODED_LEN` rejects an over-long copy by size before allocating (Superblock = one block, KeyCanary = header + max canary ciphertext). | `oversized_superblock_copy_is_rejected_before_it_is_read` (maki-format `review_format.rs`) |
| MAKI-027 | **A/B `store` incremented the generation with an unchecked `+ 1`** (panics in debug, wraps in release at u64::MAX). | `checked_add` fails closed with `FormatError::Invalid` on exhaustion. | `storing_at_max_generation_fails_closed_instead_of_wrapping` (maki-format `review_format.rs`) |

### Already closed by the 2026-09-07 supplementary review (R01–R08)

- **MAKI-001** (attach rollback disconnecting beneath a failed step) = **R01** — fixed (observation-reconciled, stop-on-failure rollback).
- **MAKI-002** (grow re-verifying live mount/VG) = **R03** — fixed (`verify_live_attachment`). MAKI-002 additionally asks for per-step re-checks of PV/VG/LV/FS UUIDs and the sentinel immediately before *each* of lvextend and xfs_growfs; that finer per-step identity re-observation is tracked below.
- **MAKI-004 / MAKI-005** (hung-command global lock; pre-mount device topology) = **R05 / R02** — the in-process command deadline, pre-mount topology probe, and optional administrator PV/VG/target-LV UUID pins are landed. Target-host udev/root coordination and qualification remain tracked.

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
- **MAKI-020 / MAKI-021 / MAKI-022 (durability & space)** — the durable-mark-plus-final-segment ambiguity threat model, physical-space reservation beyond the projected journal footprint of a write, and TRIM/deallocation. Durability-model and on-disk-format work requiring the release gates and power-loss campaigns.
- **MAKI-024 / MAKI-037 / MAKI-038 / MAKI-039 / MAKI-041 / MAKI-048 / MAKI-049 / MAKI-050 (observability, capacity, docs, qualification)** — deep-check grading vs. authenticated/recovery-view checks, thread-count config surfacing, remote-crypto I/O contract, lock-independent health, capacity/slot-span accounting, doc/CI drift, and the outstanding real-DB/power-loss/soak qualification and DB support matrix.

## Follow-up review (2026-09-08): FUP-001–015

A follow-up review (`maki-followup-review-2026-09-08`) of the updated tree
audited the fixes above, found several incomplete and one regression, and added
15 findings with twelve proposed RED tests. Each item below was reproduced,
fixed, and reverified (GREEN); the proposed tests were adapted to the real
fixtures.

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| FUP-001 (P0) | Attach rollback ignored a re-observation *failure* (`if let Ok(observed)`) and gated disconnect only on backend identity, so it could disconnect a device with unknown live mappings. | Rollback is now fully observation-based (`attach_rollback`): tears down the top present layer, disconnects only our own backend, and **fails closed** — halting and keeping the record — on any unreadable observation, remaining holder, foreign backend, or step failure. | `followup_observation_failure_after_activation_must_not_disconnect` (maki-privileged) |
| FUP-002 | A new attach replaced the trusted record when the NBD backend was merely absent, even with a live mount/VG/holder. | Re-observe before replacement; refuse unless every upper-layer resource is also gone (unreadable observation fails closed). | `followup_stale_backend_with_live_mapping_must_not_replace_record` (maki-privileged) |
| FUP-003 | Grow required only `connected`, not a live mount/active VG. | `verify_live_attachment` now requires `mounted` and `vg_active` before any lvextend/xfs_growfs. (Relative-size idempotency of MAKI-003 still tracked.) | `followup_grow_requires_a_live_mount_before_extending_lv` (maki-privileged) |
| FUP-006 | The remote gRPC/WS error *text* was sanitized but still embedded, leaking reflected secrets. | Drop the remote message entirely; only the allowlisted gRPC code / WS class token (mapped to a fixed description) reaches the error. Removed `sanitize_external_message`. | `followup_remote_status_does_not_expose_reflected_secrets` (maki-crypto-grpc) |
| FUP-007 | The decrypt lane charged ciphertext bytes against the plaintext `crypto.batch.max_bytes`, rejecting even a single unit. | The decrypt lane is bounded by its ciphertext pending budget, not the plaintext `max_bytes`; plaintext and wire budgets are kept distinct. | `followup_single_plaintext_unit_budget_works_through_scheduler` (maki-crypto) |
| FUP-008 (regression) | The self-test folded a *transport* error on a negative probe into `ProviderFatal`, aborting the whole attach instead of quarantining one flaky endpoint. | `classify_probe_err` returns a transport error unchanged (inconclusive) so the dispatcher quarantines; only `Integrity` proves the claim. | `followup_inconclusive_negative_probe_preserves_retry_class` (maki-crypto) |
| FUP-009 | `NonRetryableRequest` (incl. generic bad-request) counted as integrity proof, and an empty/malformed `Ok` to a probe passed unchecked. | Only `CryptoError::Integrity` proves it; `Ok` responses are shape-validated. | `followup_empty_moved_reply_does_not_prove_context_binding` (maki-crypto) |
| FUP-010 | The first attach persisted a new key canary without decrypt-verifying it at the reserved index. | Decrypt-probe the new canary at the reserved index and compare to the known plaintext before publishing. | `followup_first_attach_verifies_new_canary_before_publication` (maki-core) |
| FUP-011 | Context-binding was probed only on the unit index, not the volume UUID. | Probe both the unit index and a different volume UUID; XTS (context_binding Absent) is unaffected, AEAD binds the full context. | `followup_context_binding_selftest_exercises_volume_uuid` (maki-crypto) |
| FUP-012 | The per-type A/B read cap missed CheckpointState (kept 1 GiB, ignored trailing bytes) and the `store` generation probe (read via unbounded `RawGeneration`). | CheckpointState declares `MAX_ENCODED_LEN = 32` and rejects trailing bytes; `generations::<T>` bounds the probe by `T::MAX_ENCODED_LEN`. | `followup_checkpoint_v1_has_a_tight_read_bound`, `followup_checkpoint_rejects_crc_valid_trailing_payload`, `followup_superblock_store_raw_generation_probe_is_also_bounded` (maki-format) |
| FUP-013 | Config allowed the in-flight byte budgets to fall below a batch, so the `DualSemaphore` clamped an over-budget RPC through. | Config validation requires `max_crypto_inflight_bytes` and `max_inflight_bytes_per_endpoint` ≥ `crypto.batch.max_bytes`. (Unifying the DualSemaphore oversize semantics still tracked.) | `followup_inflight_byte_budgets_must_cover_a_full_batch` (maki-format) |
| FUP-005 | The unload shutdown error used `tracing::error!` with no production subscriber. | Also write it to stderr (nbdkit captures it, as with open-path failures). (A fuller subscriber/`nbdkit_error` lifecycle with a subprocess log test remains tracked.) | — (C unload shim; not unit-testable) |
| FUP-015 | The failpoint-isolation fix had reduced growth stress to a single thread. | Restored to a 4-worker runtime while holding the failpoint lock (the `!Send` guard lives only in the `block_on`'d test body, never in spawned tasks). | restored `growth_during_workload_creates_shards_consistently` (maki-core) |

### Tracked, not closed in this pass

- **FUP-004 (P1)** — the in-process per-command deadline (bounded output,
  process-group reaping) — same as R05/MAKI-004, still needs the native-VM
  qualification.
- **FUP-014 (P2, later closed on Linux)** — at this review point a TOCTOU
  remained between `FileBacking::resolve` and open (`O_NOFOLLOW` covered only
  the final component). `df886a3` superseded this item on Linux: the backing
  root and every parent are pinned by directory descriptors and all operations
  are descriptor-relative with `O_NOFOLLOW`. Symlink, root-replacement, and
  ancestor-permission regressions pass. The pathname implementation on
  non-Linux development hosts does not claim the same guarantee.
- **Residual sub-parts** — MAKI-003 relative-grow idempotency (persist the
  absolute target), the FUP-007 config alignment to guarantee one max ciphertext
  unit fits every layer, the FUP-013 blocking/non-blocking DualSemaphore oversize
  semantics, and the FUP-005 full logging lifecycle.

## Third-round follow-up (2026-09-10): R3-004, R3-006, K-03 residual

The R3 review (`maki-review-r3`, 2026-09-08) left R3-004 and R3-006 open
after the first batch of R3 fixes. Both were confirmed with RED tests and
fixed. A new randomized multi-cycle durability sweep (workload → power loss
*or* restart → recovery → oracle, with random `fdatasync` failures) then
found two residual conditions of K-03 in the slot store, each minimised to a
named regression test.

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| R3-004 | `EndpointSet::capabilities` returned the first validated endpoint's contract, so a batch built against it could be routed (load balancing, failover, a quarantined endpoint admitted later) to an endpoint with smaller `max_items`/`max_bytes` or without a claimed security capability. | The set reports the intersection over *all* endpoints: minimum batch limits, intersected plaintext sizes, the largest ciphertext bound, and the weakest security claim (`Capability::weakest`, `CryptoCapabilities::intersect`). | `aggregate_batch_limits_are_the_minimum_over_all_endpoints`, `aggregate_security_capabilities_are_the_weakest_claim`, `quarantined_endpoints_count_towards_the_aggregate`, `aggregate_plaintext_sizes_are_the_intersection`, `batch_within_the_aggregate_survives_failover_to_the_weakest_endpoint` (maki-crypto `review_r3b_endpoints.rs`) |
| R3-006 | The context-binding self-test probed the unit index and the volume UUID only; a provider that normalized `format_version` or the compatibility id passed as fully bound. No wire transport even carried `format_version`. | Two more negative probes (format version, compatibility id); a field-specific `UnsupportedContext` rejection of the foreign value is accepted, while generic request/provider errors and a decrypt to the original plaintext are refused. HTTP gained the `format_version` field source, WebSocket the `format` request field, gRPC `CryptoBatchRequest.format_version = 4`; the reference fixtures bind all three fields (SPEC §18 "Context on the wire"). | `context_binding_selftest_exercises_format_version`, `context_binding_selftest_exercises_compatibility_id`, `explicit_rejection_of_a_foreign_context_passes_the_selftest`, `integrity_for_every_decrypt_never_certifies_a_provider`, `retryable_for_every_decrypt_never_certifies_a_provider` (maki-crypto `review_r3b_selftest.rs`); the authenticated pipelines in each transport's `review_integrity.rs` now run all four probes over the wire |
| K-03 (residual, creation path) | `ensure_shard`'s catalog commit publishes the whole in-memory catalog, which after open names any *adopted* orphan shard — before that shard's allocation map has ever reached disk (only `persist_allocations` had the K-03 ordering). An interrupted checkpoint after such a commit plus a power loss left a cataloged shard with no allocation copy: every later attach refused. | Every shard tracks `map_stored`; `commit_adopted_maps` stores and dir-syncs the maps of adopted shards before *any* catalog commit, in `ensure_shard` as well as `persist_allocations`. | `adopted_shard_is_never_cataloged_by_another_shards_creation` (maki-core `review_r3b_durability.rs`) |
| K-03 (residual, restart path) | After a plain restart an orphan's allocation copy can still be *readable* from the page cache although its sync failed (K-01); `open` loaded it as a valid copy and nothing re-stored it, so the next catalog commit named the shard and the next power loss dropped its only copy. | An adopted shard's loaded map is never trusted as durable: it is re-stored (preserve-first, so the readable copy becomes durable) before the shard can be cataloged. | `adopted_shards_page_cache_map_is_re_stored_before_it_is_cataloged`, plus the sweeps `random_workloads_survive_power_loss_and_restart_cycles`, `random_workloads_with_sync_failures_never_show_foreign_data`, `restart_followed_by_power_loss_keeps_recovered_state` and the `phase_r3b_durability_gate_full` release gate (maki-core `review_r3b_durability.rs`) |
| test hygiene | Four maki-privileged fixtures named temp directories by pid + nanosecond clock; WSL's coarse clock let two tests collide (`File exists`). | A per-process sequence number is folded into the name. | (flake fix; `detach::tests::observation_distinguishes_complete_and_partial_detach` and siblings) |
| R3-004 (addendum) | An `EndpointSet` whose *serving* endpoints report different compatibility ids has no common contract, yet `capabilities()` quietly reported the first one's id. | A validated endpoint with a foreign id is a `Contract` error; a quarantined one is skipped (the validator will never admit it). | `mismatched_compatibility_ids_have_no_aggregate_contract` (maki-crypto `review_r3b_endpoints.rs`) |
| R3-006 (config) | A `remote-http` configuration could declare `context_binding` while its request bodies never carried `volume_id`, `compatibility_id` or `format_version`; every attach then failed late at the self-test with a "decrypts to the original plaintext" probe error. | Config validation requires all three field sources in both bodies whenever `context_binding != "none"`. | `declared_context_binding_requires_every_context_field_on_the_wire`, `without_context_binding_the_context_fields_are_optional` (maki-format `review_r3b_config.rs`) |
| R3-007 (activation intent) | A helper crash after LVM activation but before complete proof publication left exact Maki mappings active without a product cleanup path. | Attach persists verified NBD geometry, partition and LVM intent before activation, then atomically replaces it with the complete proof. Absent-backend `recover` and connected-backend normal detach accept only exact, mount-free verified mappings and run device-list/VG-UUID-scoped deactivation; legacy no-proof/no-intent records stay fail closed. | `recover_tests.rs`, `exec_tests.rs`, and `lvm_preflight_tests.rs`: activation crash, corrupted intent, connected/absent backend, partial verified activation, foreign name/UUID/slave/holder/mount and unknown internal UUID suffix |
| MAKI-005 (administrator pins) | The live LVM inventory was contained to the NBD candidates but was not authenticated against a root-configured expected identity. | Optional all-or-nothing `[lvm_identity]` pins the complete PV set, VG and configured target LV. Attach compares the independent inventory before activation; pins persist into the trusted record and recovery rechecks them (clarified by AUD-051, [#153](https://github.com/seo-rii/maki/pull/153): recovery reads no LVM metadata; it checks the identity attach persisted against the pins, and the live mappings against that identity or the mapping proof). Grow/detach reject changed or omitted pins before mutation. Compatibility mode may omit them, but the production profile may not. | `configured_lvm_identity_pins_are_normalized_and_carried_into_plans`, `configured_lvm_identity_rejects_missing_duplicate_and_malformed_pins`, `administrator_lvm_pins_require_an_exact_pv_set_vg_and_target_lv`, `recovery_rechecks_persisted_lvm_identity_against_administrator_pins`, `lvm_pin_mismatch_stops_before_activation_or_lvm_teardown`, `changed_or_missing_lvm_pins_cannot_authorize_detach_mutations` |
| MAKI-015 (HTTP credential ownership) | Provider-owned resolved header/query values and the combined mTLS identity PEM remained in ordinary allocations after drop or a later construction error. | Operation/TLS specifications and construction guards erase these owners; UTF-8 credential validation borrows the key-source bytes instead of making an intermediate vector. Transport-library copies remain outside the guarantee. | `provider_drop_erases_owned_header_and_query_values`, `provider_construction_error_erases_owned_credentials`, `tls_spec_drop_erases_identity_pem`, `config_error_erases_a_resolved_credential_header` |
| coverage | Configuration drift (a `crypto_unit_size` that no longer matches the volume) through the daemon path; concurrent block-aligned partial-unit (RMW) writers racing FLUSH/checkpoints into power loss or restart; the same sweeps with a tiny plaintext cache (constant eviction and version turnover). No defect found; kept as regression coverage. | — | `crypto_unit_size_drift_refuses_attach_and_leaves_the_volume_intact` (maki-nbdkit `review_r3b_daemon.rs`); `concurrent_partial_unit_workloads_*`, `random_workloads_with_a_plaintext_cache_*`, `phase_r3b_concurrent_gate_full` (maki-core `review_r3b_durability.rs`) |
| S-01 (residual) | A checkpointed unit whose newest allocation-map copy was lost *and* whose slot header was damaged (partly overwritten, not zeroed) read as **zeros**: the older map copy did not list it and the header probe treated every undecodable header as "unwritten". Found by the media-damage sweep (seed 16) within seconds. | A hole is never partly written: on a cleared slot only an all-zero header is unwritten; any other undecodable header is damage ⇒ EIO in `read_slot`. The open-time audit still leaves such slots unmarked (a torn first write of a still-journaled unit is the benign cause and is served from the overlay). SPEC §22 updated. | `damaged_header_on_a_cleared_slot_is_eio_not_zeros`, `media_damage_after_power_loss_never_yields_foreign_data`, `phase_r3b_media_damage_gate_full` (maki-core `review_r3b_durability.rs`) |
| S-01 (residual, truncation) | The same sweep (seed 170): a shard data file truncated below a checkpointed slot whose newest allocation copy was lost too read that unit as **zeros**, because a header beyond EOF counted as "unwritten". A shard data file is created at its full sparse size and synced before it is ever used, so it never legitimately ends before a slot. | A slot beyond the end of a file shorter than its physical size (`units_per_shard × slot_size`) is damage, not a hole. The one legitimate short file belongs to a shard that was never checkpointed into (not named by the loaded catalog copy, empty allocation map): its creation never finished, its holes stay holes and its size is restored before its first slot write. Without that exception, adopting a zero-length orphan turned every unit of the shard into EIO, and later writes never restored the size. An earlier version of the exception required *no* allocation copy on disk; the full durability gate (seed 95) showed an interrupted creation leaving a stale empty copy next to a re-created, zero-length data file, which the rule then took for truncation (every unit EIO after a plain restart). The gate then found the K-01 twin (seed 388, sync faults): the data file's first sync failed, the process restarted, the page cache showed the full size the disk never got, and the next checkpoint wrote into and cataloged the shard — the power loss after that left a cataloged shard with a file ending at its last written slot, "truncated" by the new rule. Nothing proves an uncataloged, never-checkpointed shard's size, so `prove_data_file` sets and syncs it again before the first slot write and before either catalog commit that can name it (`commit_adopted_maps` under `ensure_shard`, and the repair checkpoint's commit in `persist_allocations` — the sync-fault sweep, seed 29, found the latter cataloging a zero-length orphan once checkpoint destinations moved to write admission, after which the next power loss read the whole shard as EIO); `reserve_slot` and the checkpoint slot plan prove it as well, since they grow the file without `write_slot`. Residual: a data file truncated *and* the catalog *and* every allocation copy listing its slots lost is indistinguishable from that orphan and serves zeros beyond the truncation point. | `truncated_shard_file_reads_eio_for_units_beyond_its_end_not_zeros`, `zero_length_orphan_shard_without_a_map_is_unwritten_not_damaged`, `zero_length_orphan_shard_with_a_stale_empty_map_is_unwritten_not_damaged`, `adopted_shards_data_file_size_is_re_proven_after_a_failed_sync_and_restart`, `adopted_orphan_is_sized_before_a_repair_checkpoint_catalogs_it` (maki-core `review_r3b_durability.rs`); `check_all` now reports the seed, cycle and op history of a failed read |
| S-01 (residual, truncation evidence) | Seed 58 of the same sweep, once the sweep logged its history: the truncated volume kept running, a checkpoint wrote a *later* slot of the shard, and that write grew the file back with zeros. A checkpointed unit in the zero-filled range whose newest allocation copy had been lost then read as **zeros** (all-zero header on a cleared bit), although the attach right after the truncation had reported EIO. The read-time rule above cannot hold once the evidence (the short file) is gone. | Open records the damage in the one place that persists: every cleared slot beyond the end of a truncated file is marked allocated, so it reads as allocated-but-invalid (EIO) until rewritten. Before the shard's first slot write grows the file (`SlotStore::prove_data_file` in maki-core `store.rs`), the marks are stored and dir-synced, then the size is restored and synced; a restart before that re-derives the same marks from the still-short file. The deep checker counts the marked slots as invalid and explains them in a warning. Cost: a unit never written beyond the cut is EIO as well until rewritten, since nothing distinguishes it from a removed slot (SPEC §22). | `truncation_damage_survives_the_file_growing_back` (maki-core `review_r3b_durability.rs`); the sweep failure report now carries the full op history and an on-disk state dump |
| S-04 (confirmed limitation) | The same sweep reproduces the documented S-04 trade-off (seed 56): with the durable mark lost in the crash, bit rot inside the final journal segment's synced records is truncated as a torn tail, so a FLUSH-acknowledged write reverts to its previous durable value instead of refusing attach. Not changed: making the mark durable costs an extra fsync per FLUSH; the sweep tolerates journal damage explicitly. | — | (documented in the sweep's assertion) |
| gate hygiene | `cargo test --workspace --release -- --ignored` (the documented release gate) failed on `exec::command_tests::child_fixture`, an ignored subprocess fixture that panicked when run without its driving test. | The fixture returns early when its scenario environment is absent. | (gate fix; the full gate is otherwise green) |

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
  fails magic, version, or CRC is durable damage, with one exception since
  AUD-054 ([#177](https://github.com/seo-rii/maki/pull/177)): a final segment
  exactly one header long whose header fails its CRC, at an index above the
  segments the durable proof (unless it is empty) and the durable mark name,
  never held an acknowledged record and is discarded as an unfinished
  creation, which the deep check reports as such. Since AUD-003
  ([#166](https://github.com/seo-rii/maki/pull/166)) the writer never extends a
  new segment before writing its header, so a torn header write leaves a file
  shorter than a header; the exception covers the complete-length torn headers
  earlier binaries left, which extended the file first, and such a header
  damaged later. A header followed by record bytes, one the proof or the mark
  names or lies below, one that is not final, and an intact header that does
  not decode are still refused.
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
  successor is corruption). *Superseded by S-04:* without a mark the final
  segment is proven only as far as the durable proof names it, otherwise only
  its header, and damage beyond that is a torn tail. The deep check named the
  old heuristic until AUD-048
  ([#152](https://github.com/seo-rii/maki/pull/152)).

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
| `emergency_reserve_bytes` | `backing.journal_emergency_reserve_bytes` | Enables write-admission space checks; unknown/error fails closed and reads continue. |
| `low_space_checkpoint_bytes` | `backing.checkpoint_reserve_bytes` | While admission is enabled, its value is preserved as headroom after the exact next record/segment-header footprint; the worker also checkpoints eagerly below it. |
| `interval` | 30 s (engine default) | The worker syncs pending records and checkpoints at least this often while anything is unapplied. |

Since AUD-004 and AUD-005 ([#168](https://github.com/seo-rii/maki/pull/168))
the watermark and low-free-space passes sync the journal before they
checkpoint, as the interval pass does, and a write refused at the hard limit or
the overlay bound holds a reclaim gate until it has appended, so concurrent
writes cannot take the space its inline checkpoint frees. Since AUD-052 and
AUD-053 ([#176](https://github.com/seo-rii/maki/pull/176)) every worker pass,
whatever started it, still checkpoints the records that were already durable
when its journal sync fails, and the watermark trigger also requires a sealed
segment on disk, because a checkpoint never deletes the active segment.

The worker holds only a weak reference to the engine and exits when the
engine is dropped. Free space is queried through `Backing::free_bytes`
(`statvfs` on Unix; unknown elsewhere and in the in-memory backings unless a
test sets it) and cached for one second of the engine's clock.

A checkpoint failure on any path increments `checkpoint_failures_total` and
sets `EngineState::Degraded { reason }`; the next successful checkpoint
returns the engine to `Ready`. The control socket reports the state in
`status` and as `maki_volume_state` (1 ready, 2 degraded).

## On-disk additions

This section records the intermediate v1 state at the time of that remediation.
At that point the additions were new files and the format version remained 1.
The current release instead requires the v2 superblock envelope and dual
durable-proof records described in [Durable recovery](durable-recovery.md);
that later contract supersedes the current-tense v1 statements below. Volumes
created before the intermediate changes lacked these files:

- `canary.{a,b}`: established on the next attach as described above.

- `checkpoint/state.{a,b}` are now written at creation and **required** by
  recovery. A pre-existing volume that was never checkpointed will fail to
  attach with `no valid checkpoint state copy`.
- `journal/durable-mark` is created empty at creation and recreated lazily by
  the writer if absent. Its absence only weakens corruption detection.

### R3-006 context refusal classification after the remote follow-up

The full-context probes and all upstream transport fields remain in place.
Schema rejection now identifies the refused field with
`CryptoError::UnsupportedContext(ContextField)`. Only the probe changing that
same field accepts it; generic `ProviderFatal`/`NonRetryableRequest` errors,
wrong-field refusals, and schema errors during integrity tests never certify a
capability. Availability errors still propagate for endpoint retry/quarantine.
The local and reference providers identify compatibility-ID refusal explicitly.
HTTP/gRPC carry the allowlisted field token in one `maki-crypto-error` value;
WebSocket uses `unsupported-context` plus the same reason token. Duplicate or
ambiguous values are rejected and remote text is not reflected.

Validation: `review_r3_context` supplements the upstream `review_r3b_selftest`
with matching-field, wrong-field/generic-error, and inconclusive-probe tests.
Each transport's `review_integrity` covers exact field tokens and malformed
signals as well as the authenticated engine pipeline using the full context.

## R3 final status and lifecycle qualification (2026-09-13)

The direct R3-001–010 causes are closed in product paths and focused tests.
This table distinguishes that closure from broader production qualification
that the review bundle also tracks.

| R3 item | Final direct-finding status | Evidence |
|---|---|---|
| R3-001 wire integrity | Closed | `3703683`; authenticated ciphertext reaches the engine and wire mappings preserve integrity, schema, and timeout classes |
| R3-002 rollback ownership | Closed | `c834ff5`; foreign or unreadable backend identity stops teardown and preserves trusted state |
| R3-003 request budgets | Closed | `4449a74`; logical, ciphertext, and RPC boundaries reject oversized requests before mutation |
| R3-004 endpoint capabilities | Closed | Preserved per-endpoint intersection plus `27dce14`; heterogeneous endpoint regressions pass |
| R3-005 UUID/canary identity | Closed | `8e725fc`; locked actual UUID, per-endpoint canary, and quarantine recovery tests |
| R3-006 full context | Closed | `dd87466`; only exact context-field refusal is accepted as capability evidence |
| R3-007 recovery lifecycle | Product path closed; installed crash and scoped topology qualification passed | Intent/recover/verify plus `3fc0404` convergent cleanup and `98a5b0e`/`90843db` packaged lifecycle; `448c0b2` combined the installed graph, actual storage, and SQLite through two automatic nbdkit crashes plus an open-LV cleanup failure/retry. The `3cac300` package campaign additionally refused a dead-backend two-LV fallback and a same-NBD foreign backend before mutation. Nested/internal mappings, partitions, holders, hot replacement and production topology remain |
| R3-008 shutdown result/logging | Closed for supported foreground mode | `dc646ef`; explicit drain result, admission closure, retry, subprocess logging, and concurrent shutdown tests |
| R3-009 response shape | Closed | `57ca845`; empty, extra, wrong-index, and wrong-length responses fail without panic |
| R3-010 capability mode | Closed | `40502a7`; only declared mode is accepted and remote declarations are contractual |

The earlier safe privileged run at `5a3bef6` used nbd-client 3.27.1 and passed
22 checks on a disposable Debian 12 GCE host: real kernel NBD, single-PV
LVM/XFS with all UUID pins, attach, verify, two cleanup calls, fio, SQLite WAL,
and an offline check. The actual systemd transaction used fixture daemon,
attach, verify, and workload components but proved stop, cleanup-success
restart, cleanup-failure hold, and per-start gate ordering. A separate Docker
run observed default `rprivate` propagation, distinct container IDs and
creation times, SQLite rows 1→2 with `integrity_check=ok`, and zero container
starts on a plain directory. Those two runs did not combine the Maki storage
stack and installed controller.

Revision `8bf0e941bd3501b972850240fb1050fbc2a90c0b` then passed 29 checks in one
combined campaign. A default-`rprivate` Docker container committed 32 SQLite
WAL `synchronous=FULL` rows individually and recorded each ACK in an external
fsynced ledger. The actual nbdkit process exited 137 after `SIGKILL`; kernel NBD
remained connected, and `maki-attach verify` still succeeded because it checks
storage identity and topology rather than server liveness. Cleanup used the
completed proof to remove the one exact closed mapping after normal `vgchange`
failed, disconnected NBD, and reattached after nbdkit restart. A distinct
container recovered all 32 ACK rows exactly and returned
`integrity_check=ok`. Final cleanup, its idempotent replay, and the offline
check passed.

The proof fallback is limited to cleanup of one exact top-level target mapping;
it rejects explicit detach/recover, pre-activation intent, multi-LV/internal or
open/changed mappings, backend identity changes, and command timeouts. The
combined campaign did not execute the installed systemd controller or cover a
remote provider, whole-VM/physical power loss, another database, repeated
crashes, or soak load.

Revision `448c0b2a46bd748eb473e34405175db9b3cfa102` then installed the shipped
systemd, sysusers, and tmpfiles artifacts over the actual single-PV/LV stack on
a new Debian 12 GCE host. Two successive daemon `SIGKILL` events automatically
recreated the daemon, attachment, per-start verification, and default-`rprivate`
container while preserving external ACK prefixes of 32 and 48 rows. On a third
crash, a root-held LV descriptor made both attach stop and recovery cleanup fail
closed. The workload stayed stopped, the ledger stayed at 48, and NBD, the
mapping, backend identity, and trusted volume record remained. Closing the
descriptor and explicitly retrying recovery produced a fourth container and 64
external-ACK rows. An independent reader matched every SQLite row and payload
hash with `integrity_check=ok`.

The final drain, target stop, ordered workload/attach/daemon completion, plugin
unload and offline check passed with no remaining mount, mapping, NBD holder,
volume record, or container. The result closes the earlier installed-controller
combination gap for this one local-provider topology. It does not qualify a
distribution package install or upgrade, multi-LV/internal mapping, foreign
device replacement, remote providers, another database, DB-native migration,
whole-VM loss on this topology, or soak load.

At that point, revision `ece7e39` passed a separate
[fresh-host backing restore](qualification/fresh-host-restore-validation-2026-09-17.md).
A source GCE VM wrote and externally acknowledged 32 SQLite rows, drained,
passed the offline check and exported the unchanged v2 backing, configuration,
attach identity and credential. That VM and disk were deleted before a distinct
target VM restored the artifacts, matched all 32 rows, advanced to 48 and
matched all 48 again after a lifecycle restart. Both SQLite integrity checks,
final drain, offline check and cloud cleanup passed. Three retained harness
failures occurred before the product path: a `sudo` home-directory mismatch, a
missing parent-directory mode in the ad hoc runtime tar, and non-idempotent
`reset-failed` handling. Distribution package install/upgrade, DB-native or
legacy migration and crash-time capture remain open.

Revision `c385c99` then passed a separate
[remote HTTP provider database campaign](qualification/remote-provider-db-validation-2026-09-18.md)
on a disposable Debian 12 GCE VM. Two authenticated loopback providers served
the actual packaged systemd, kernel NBD/LVM/XFS, and SQLite WAL path. Rows 0–7
used both endpoints, 8–15 used only B after A stopped, and 16–23 used only A
after B stopped. With both providers down, the next DB writer stayed blocked
and the fsynced external ledger stayed at 24; restoring B advanced it to
exactly 25 after a 4,094 ms observed outage. Both providers then returned and
the database reached 32 exact ACK rows. All row IDs and body hashes plus
`integrity_check=ok` matched before and after a packaged lifecycle restart.
Metrics recorded six failovers and nine retries, and provider journals recorded
21,326 encrypt/decrypt requests across both endpoints. This closes the narrow
database-through-provider fault observation, while real network/TLS/vendor
behavior, another DB, concurrent host loss, latency targets and soak remain.

Revision `5f50354` then passed a separate
[PostgreSQL process-crash campaign](qualification/postgresql-crash-validation-2026-09-18.md)
on a disposable Debian 12 GCE VM. PostgreSQL 15.19 ran with data checksums,
`fsync`, synchronous commit and full-page writes on the actual packaged Maki,
kernel NBD/LVM/XFS path. After 16 external ACK rows, a cgroup-wide postmaster
`SIGKILL` interrupted four pgbench clients after 590 transactions. A distinct
postmaster performed WAL redo and an end-of-recovery checkpoint, preserved the
entire ACK/hash prefix, and passed `pg_amcheck`. The cluster advanced to 32
rows, retained all 32 through a packaged Maki lifecycle restart, then reached
48 rows. Four `pg_amcheck` runs were clean. This narrows the other-database gap
for one short PostgreSQL profile; production sizing, backup/restore,
replication, DB-native migration, concurrent VM/storage loss and soak remain.

Revision `3cac300` then passed a separate
[package, topology, and migration campaign](qualification/package-topology-migration-validation-2026-09-19.md)
on one disposable Debian 12 GCE VM. A generated pre-upgrade package cleanly
installed and ran two simultaneous pinned NBD/LVM/XFS volumes, including a
sidecar LV. The generated current package preserved every config and token hash,
did not auto-start a volume, and reattached both SQLite databases with unchanged
logical hashes. A corrupt native restore failed before clean retry. A matching
old reader backed up a clean legacy-v1 volume; the current writer refused the
unchanged v1 superblocks, and the backup restored exactly into fresh v2.

After a daemon `SIGKILL`, packaged recovery preserved both top-level mappings
and the trusted proof when proof-scoped fallback refused the ambiguous topology.
Cleanup also preserved a same-number foreign NBD backend and trusted record.
Explicit cleanup then converged, both offline deep checks reported zero invalid
slots, and exact instance/disk lookups plus prefix queries proved cloud cleanup.
This closes those scoped package, multi-mapping, foreign-backend and SQLite
migration observations. Signed repositories, rollback, nested device stacks,
live backup/cutover and other databases remain open.

The disposable instances and their auto-delete boot disks were deleted. The
last fresh project queries found zero name-matched `maki-*` instances and disks,
and the latest combined disk's exact lookup returned 404. The CI run for
`448c0b2` passed on Linux and Windows.

Capacity follow-up `5803be8` partially closes MAKI-041's accounting gap. The
geometry API and `maki volume inspect` now report maximum units and shards,
full-shard slot span, and both copies of allocation-map and catalog metadata.
They reject shard counts above the supported catalog limit and `u64` layout
overflow. The standard 16 TiB geometry has an 18 TiB slot span before journal,
checkpoint, filesystem, or database overhead. This planning output does not
reserve physical blocks and does not close MAKI-021's external-consumer race.

Physical reservation follow-up `ced2bda` closes that race for accepted Maki
writes on Linux. The write path uses `posix_fallocate` for the exact journal
range and full checkpoint slot before appending, and creates and syncs both
allocation-map copies plus the catalog entry before a new shard can receive a
journal record. Injected slot and journal ENOSPC leave the sequence unchanged
and retry successfully. A real-filesystem regression verifies allocated slot
blocks and both metadata copies before the first record is accepted. Core
all-targets passed 204 tests with 6 ignored, and strict Clippy passed. This is
not full-volume preallocation: untouched slots, filesystem/COW overhead, and
database temporary space remain deployment-capacity inputs. The reservation
also does not hold for extents a backing file shares with a reflink copy,
which `posix_fallocate` does not unshare (AUD-049,
[#152](https://github.com/seo-rii/maki/pull/152)).

The later [GCE physical reservation campaign](qualification/physical-reservation-validation-2026-09-18.md)
exercised that path on ext4 over a separate standard Persistent Disk. A
4,608-byte slot owned 8,192 allocated bytes before the first FUA ACK, and both
allocation-map copies owned blocks. After consuming all 9,910,247,424 initially
free bytes, the next FUA returned ENOSPC while sequence 1, the journal hashes,
and slot allocation stayed unchanged. Releasing the space allowed sequence 2;
restart readback, deep check, and unmounted `e2fsck` passed. This qualifies one
Linux filesystem and storage class, not full-volume capacity or physical power
loss.

Bounded recovery follow-up `733833c` removes the attach-time map of retained
latest ciphertext. Recovery validates and repairs the full journal first, then
replays it through a 1 MiB batch into durable checkpoint slots. Controlled
tests held the measured replay peak near 1.1 MiB for 4,096 distinct records and
16,384 overwrites, and a slot-sync crash retried from the preserved journal.
The actual Docker cgroup campaign then recovered a 21.5 MiB pressure tail at a
32 MiB cap and matched 136 external ACK units, but touched the cap exactly.
This closes payload retention proportional to distinct units; metadata,
runtime/provider allocations, filesystem cache and a production RSS minimum
remain target-specific qualification inputs.

A later [constrained recovery RSS campaign](qualification/recovery-rss-validation-2026-09-19.md)
ran two fresh 48 MiB and two fresh 64 MiB post-OOM recoveries. All four matched
136 ACK units and passed deep checking; the maximum observed nbdkit `VmHWM` was
11,415,552 bytes. Both 64 MiB runs stayed below the cgroup cap with zero max
events, while both 48 MiB runs touched the cap. This supplies a scoped process
RSS high-water observation and cgroup sizing result, not a universal bound.

Revision `47058d2` then passed a separate
[cross-host TLS reference-provider campaign](qualification/cross-host-tls-provider-validation-2026-09-19.md).
Two GCE provider hosts required mTLS and a bearer credential over private VPC
addresses. Explicit TLS 1.2 and TLS 1.3 health gates passed; wrong CA, absent
client identity and wrong bearer all refused startup before
daemon readiness. Provider-VM stop/start exercised each endpoint alone and
both absent, after which SQLite reached 32 exact external ACK rows and retained
them through a Maki restart. The final deep check had zero invalid slots and all
three VMs and disks were deleted. This closes the scoped cross-host HTTPS
reference-provider observation, while commercial vendor behavior and target
network faults remain open.

Revision `bdb9113` then passed a separate
[credential rotation and key migration campaign](qualification/credential-rotation-key-migration-validation-2026-09-19.md)
on the same three-host class of topology. A stopped K1 volume rejected its old
bearer and mTLS client identity after rotation, validated the replacement
identity on both peers, preserved its superblock/canary hashes, and reached 16
external ACK rows. A SQLite DB-native backup restored into a distinct K2 volume;
an isolated K1 wrong-key canary was refused with unchanged superblock/canary
hashes, and 24 ACK rows survived a full restart. Both retained volumes had zero
invalid slots and all resources were deleted. This closes the tested
reference-provider client-credential and stopped K1-to-K2 migration profile.
Commercial vendors, target networks, key retirement and production
cutover/rollback remain open.

Revision `da89ae3` then passed a four-host
[server CA and endpoint-address campaign](qualification/server-ca-endpoint-rotation-validation-2026-09-19.md).
Stopped transitions exercised mixed old/new server certificates with overlapping
private roots, new-only trust, and wrong-trust NBD refusal in both directions.
A/B changed to distinct-IP C/B with A's nginx listener stopped and the encryption
key/profile, client credentials and volume identity unchanged. Both configured
peers validated at each restart, superblock/canary hashes matched across each
attach, and all 48 exact ACK rows survived. This qualifies that stopped
reference-provider path, not C-only service, hot reload, CA revocation or a
commercial deployment. The harness corrected two false failures in TDD: socket
existence was mistaken for readiness, then an outer operation-deadline error
was mistaken for an unrelated failure. Prior reports now describe the verified
startup-refusal boundary accurately.

The supplied R3 directory is retained because it also contains the inherited
MAKI/FUP production checklist. Universal and target-profile RSS bounds,
remaining transport-library copies, checkpoint stalls, actual provider
faults over a commercial vendor and target network, replay policy, key migration,
broader and live database migration, production database profiles and remaining
engines, physical power loss, and long-duration load remain open.
Direct R3 closure must not be read as general production approval.

## Fourth review (2026-09-23): R4-001–R4-007

A code and packaging review of the 2026-09-22 tree looked at observability,
memory protection scope, resource bounds, diagnostics and package behaviour
rather than at durability under crash. It reproduced the packaging finding
(R4-007) directly and reported the Rust findings from code analysis. None of
them is an acknowledged-data-loss defect. Each fix below starts from a
regression test that failed before the change.

| Finding | Problem | Fix | Tests |
|---|---|---|---|
| R4-001 (logging) | The default plugin execution path never installed a `tracing` subscriber, so `checkpoint worker: … failed`, `control socket server stopped`, provider quarantine and store repair warnings were dropped; only startup and unload failures used `eprintln!`. | `maki_core::logging::install_default_logging` installs a stderr `fmt` subscriber (no ANSI, target and fields, `MAKI_LOG` filter, default `info`). The plugin calls it in `config_complete` and again in `after_fork` (idempotent); `maki` and `maki-check` call it at startup. Follow-up (2026-09-29): `maki-attach` dropped its executed steps and halted-rollback errors the same way; `maki_privileged::logging` installs the equivalent sink without linking crypto crates (PRIV-010). Documented in [operations](operations.md#logging). | `logging::tests::*` (maki-core; a child process installs the subscriber and the parent checks its stderr and the `MAKI_LOG` filter), `runtime_warnings_reach_stderr_in_the_default_plugin_path`, `maki_log_filters_the_default_plugin_output` (maki-nbdkit `review_r4_native_logging.rs`: real nbdkit, an adopted orphan shard's `WARN` must appear in the captured stderr), `maki_privileged::logging::tests::*` |
| R4-002 (guarded plaintext) | `local-aes-gcm-siv` decrypted with the allocating AEAD API into an ordinary `Vec` and wrapped it in `SecretBuffer` afterwards; XTS copied ciphertext through a plain `Vec`; encryption copied plaintext into an unlocked vector before encrypting; key files were read into a plain `Vec` and hex-decoded into another. `secure-buffers` therefore did not cover plaintext or keys during their first moments. | The guarded buffer is allocated first and the AEAD/XTS operation runs in place (`encrypt_in_place_detached` / `decrypt_in_place_detached`, `encrypt_area` / `decrypt_area` on `expose_mut()`); key files are read straight into a `SecretBuffer` and hex-decoded into one; `SecretBuffer::from_vec` now counts `unguarded_wraps()`; `SecretBuffer::truncate` added; the `aes` crate's `zeroize` feature erases key schedules on drop. Follow-up (2026-09-29): the cipher objects moved into `SecretBox<T>`, a page-locked heap box that drops (erases) the value before unlocking and erases the move's staging copy, so the expanded key schedules are covered by `secure-buffers` too. Residual: cipher-crate stack temporaries ([transport memory](transport-memory.md#local-providers-and-key-material)). | `review_r4_guarded_buffers.rs` (maki-crypto-local: encrypt, decrypt, tampered-ciphertext failure and file/env key loading must not move `unguarded_wraps()`; `key_schedules_are_page_locked_under_secure_buffers`, `locked_key_schedules_still_encrypt_and_decrypt`), `truncate_keeps_the_allocation_and_erases_the_tail`, `guarded_constructors_are_not_counted_as_unguarded_wraps`, `secret_box_drops_its_value_exactly_once`, `secret_box_is_page_locked_when_enabled_and_redacted` (maki-crypto) |
| R4-003 (package removal) | The package had `postinst` and `postrm` only. `apt remove maki` under a live attachment deleted `maki-attach`, the very program `ExecStop=` and `maki-recover@` need to detach, leaving no normal cleanup path. | A `prerm` refuses `remove`/`deconfigure` while a trusted attachment record exists under `/run/maki-attach/` or a `maki@`, `maki-attach@` or `maki-workload@` unit is active, and prints the drain-then-deactivate procedure. `upgrade` is exempt and no maintainer script starts, stops or restarts a service. Follow-up (2026-09-29): a failed `systemctl list-units` was read as "no active units" (the pipeline status was `awk`'s); it now refuses the removal. | `test_prerm_refuses_removal_while_a_volume_is_attached`, `test_prerm_refuses_removal_while_a_maki_unit_is_active`, `test_prerm_allows_idle_removal_and_never_blocks_an_upgrade`, `test_prerm_fails_closed_when_systemd_cannot_be_queried`, and the no-`systemctl start/stop/restart` scan over every maintainer script (`scripts/test_debian_package.py`) |
| R4-007 (package inputs) | `build-deb.py` checked only the *format* of `--architecture`; x86-64 artifacts requested as `arm64` produced a valid-looking arm64 package (reproduced by the reviewer), and `Depends` never reflected the binaries' native libraries. | Every release file's ELF header (machine, class, byte order, type) must match the requested architecture; the plugin must be `ET_DYN` and the binaries executables; unknown architectures are refused. `--shlibdeps` runs `dpkg-shlibdeps` and appends the result to `Depends`, failing closed when the scan cannot analyse an artifact. The package tests now use ELF stubs instead of text files. Follow-up (2026-09-29): the scan is the default, a missing `dpkg-shlibdeps` fails the build, and `--no-shlibdeps` (test fixtures only) warns. | `test_package_architecture_must_match_the_elf_binaries`, `test_release_files_must_be_elf_images_of_the_right_kind`, `test_unknown_debian_architecture_is_refused_before_building`, `test_shlibdeps_option_fails_closed_on_artifacts_it_cannot_analyse`, `test_native_dependency_scan_is_on_by_default`, `test_opting_out_of_the_scan_keeps_the_static_depends_and_warns` |
| R4-004 (deep-check verdict) | `maki check --deep` reported every slot CRC failure as an error, although recovery rewrites a checkpointed slot from a validated journal record newer than the checkpoint. An operator could read a routinely recoverable volume as a data-loss incident. | The journal summary now also returns the set of units with an uncovered validated record (`ReplayRecords::Units`, one `u64` per unit, no payloads). A failing slot whose unit is in that set is reported as `warning: slot: recoverable: …` and does not fail the check; other damage stays an error. The report ends with `deep check verdict: clean | recoverable | unrecoverable` and counts both classes ([operations](operations.md#volume-lifecycle)). Follow-up (2026-09-29): the check walked only allocated units and called a volume clean whose unlisted slot held a damaged header, which the read path refuses (S-01 residual); it now probes those slots too (`SlotStore::unlisted_units`). | `review_r4_check_verdict.rs` (maki-core): recoverable damage passes with a warning and is repaired by the next recovery, damage without a source fails, mixed damage reports both classes, a healthy volume is `clean`, `damage_in_an_unlisted_slot_is_reported_like_the_read_path_refuses_it` |
| R4-005 (overlay bound) | `limits.max_ciphertext_bytes` only bounds the remote scheduler's pending queue (local providers bypass it), while the overlay that holds journaled, uncheckpointed ciphertext had no bound of its own: with a slow or failing checkpoint it could grow toward the multi-GiB `journal_max_bytes`, a disk budget that is not an instance's RAM budget. | New `limits.max_overlay_bytes` (default 256 MiB) and `limits.max_overlay_entries` (default 262144) reach `EngineLimits`. Admission charges a request at its eventual size (`max(bytes, 2 × latest_bytes) + 2 × payload`, since every unit ends up with a durable copy); a write that would exceed a bound syncs and checkpoints inline like the journal hard limit and returns ENOSPC after a failed reclaim; the worker checkpoints at half of either bound. The overlay tracks `latest_bytes` (sanitizer-checked). Validation requires the byte bound to hold the largest request (`nbd.maximum_io` plus one unit, as ciphertext) twice and the entry bound to hold it in units; `0` disables. Library callers keep the unbounded default. Follow-up (2026-09-29): a write still over a bound after its reclaim was refused even when concurrent writers' volatile records were what kept it out (a checkpoint retires only up to the durable mark); it now syncs and takes another round while volatile records exist, up to `MAX_RECLAIM_ROUNDS` (4), for the journal hard limit too. *Superseded by AUD-004 ([#168](https://github.com/seo-rii/maki/pull/168)):* concurrent writers could still take the freed space in every round; a refused write now holds a reclaim gate that other writes queue behind until it has appended, and the round limit remains only as a termination bound. | `review_r4_overlay_bound.rs` (maki-core: bytes and entries stay under their limits through 96/40 writes without journal pressure, the worker checkpoints on the watermark with a manual clock, a failed reclaim refuses the write and degrades, zero keeps library callers unbounded, `a_concurrent_volatile_write_during_inline_reclaim_does_not_cause_enospc`), `review_r4_overlay_limits.rs` (maki-format defaults, zero, minimums), `review_r4_overlay_options.rs` (maki-nbdkit mapping) |
| R4-006 (cache-first reads) | `read_secret` called `read_ct` (slot header, full ciphertext, CRC) *before* consulting the plaintext cache, so a hit only saved the provider call: the cache was a decryption cache, not a read cache. | The read path first establishes the unit's current write sequence (`Volume::current_sequence`: overlay entry, else the 64-byte slot header through `SlotStore::slot_sequence`, which applies every header-level refusal of `read_slot`) and serves a `(unit, sequence)` hit without reading the payload; misses read and decrypt as before. Versioning is unchanged (a newer write changes the sequence). Documented trade-off: a hit does not re-verify the on-disk payload CRC of an already validated version until the entry is evicted; header damage still refuses the read and the deep check still finds payload damage. Follow-up (2026-09-29): `cache.verify_on_hit = true` re-reads and CRC-checks the payload on every hit and uses the cache only to skip decryption. `CrashableBacking::read_bytes()` counts served read bytes for tests. | `review_r4_cache_reads.rs` (maki-core: a hit reads ≤ 64 bytes and no provider call, an overlay hit reads nothing, newer versions miss, header damage is EIO despite a cached entry, payload damage is served until eviction then EIO, no-cache reads still verify, `verify_on_hit_rereads_the_payload_but_skips_decryption`; maki-nbdkit `review_r4_cache_verify_options.rs`: off by default, reaches the engine) |

## Fifth review (2026-10-01): R5-001–R5-034

A whole-tree review of `10b0b25` found CI red on `main` and a set of
privileged, transport and discard defects; none loses FLUSH-acknowledged data
or returns zeros for damaged data. Each code fix starts from a regression test
that failed before the change.

| Finding | Problem | Fix | Tests |
|---|---|---|---|
| R5-001 (CI) | Every `main` run since `9122777` failed at `cargo fmt --all --check`, so clippy, the workspace tests, `cargo audit` and the docs-link check never ran for the R4 work. The nightly gate filter named seven gates and silently skipped the three R3b sweeps. | `cargo fmt --all`; the nightly job runs `-- --ignored` without a name filter ([testing](testing.md)). Stale untracked `review_next_*` reproductions of already-fixed BUG-016/023/024 were removed. | CI itself |
| R5-002 (mount options) | `maki-attach` mounted XFS as root with `-o noatime` only. The filesystem's bytes come from the unprivileged daemon and an untrusted provider, so a crafted image with a setuid-root binary or a device node for a host disk was a local privilege escalation. | Mount with `noatime,nosuid,nodev` (`plan::MOUNT_OPTIONS`); `verify_mount_device` (and so attach, `verify` and the post-mount check) refuses a mount whose mountinfo options lack `nosuid` or `nodev`. `maki@.service` adds `DevicePolicy=closed` (not `PrivateDevices=`, which would hide the `/dev` nodes the swap-policy check stats). | `review_r5_mount_options.rs` (maki-privileged: planned options, mountinfo option parsing, refusal without either flag) |
| R5-003 (environment proxy) | `reqwest` honours `HTTP_PROXY`/`ALL_PROXY` by default and the HTTP provider never disabled it, so a daemon inheriting `http_proxy` sent every loopback `http://` encrypt request (plaintext and credential headers) to the proxy and accepted its reply as ciphertext. | `Client::builder().no_proxy()`; documented in [architecture](architecture.md). | `review_r5_proxy.rs` (maki-crypto-http: a recording proxy in the environment and a closed endpoint; the proxy must see nothing and the request must fail) |
| R5-004 (scheduler re-send) | `1678e3e` re-sent each request of a coalesced batch that failed with a request-class error without checking `retry_safe`, so a provider declaring itself not retry-safe received the same plaintext units twice, breaking the M-010 promise the `EndpointSet` keeps. The re-send loop also awaited outside any cancellation `select!` while holding the lane slot and after `inflight_batches` was decremented: with `max_inflight_batches = 1` a hung re-send blocked every new request after its callers had gone. | The per-request path runs only when the inner provider's capabilities report `retry_safe`; otherwise the error fans out as before. Each re-send is counted in `inflight_batches` and raced against its caller's `closed()`, so an abandoned one releases the slot. | `review_r5_scheduler_resend.rs` (maki-crypto: exactly one provider call for a non-retry-safe provider, per-request verdicts kept for a retry-safe one, abandoned re-send frees the only lane slot) |
| R5-005 (endpoint attribution) | A `Contract` error (malformed response, wrong item count, bad encoding; `ProviderFatal` class) and a generic HTTP 4xx (`NonRetryableRequest`) returned from `dispatch` at once and dropped the breaker probe without a verdict. A misrouted endpoint (404, an HTML page) therefore never opened its circuit, and stable least-inflight ordering kept picking it: 100 of 100 requests failed with a healthy peer idle. | In a set, `Contract` charges the endpoint's breaker and a retry-safe request fails over to an endpoint it has not tried; with none left (a single endpoint included) the error is returned immediately, so the stall policy never retries into it. HTTP 404/405/410 map to `EndpointFatal`. Integrity, `UnsupportedContext` and other 4xx are unchanged. *Superseded by the follow-up below and AUD-021 ([#154](https://github.com/seo-rii/maki/pull/154)):* the violation is returned at once only when every validated endpoint (a single one included) has broken the contract for the operation; while another validated endpoint remains, even one that failed transiently or whose circuit is cooling, the operation stays in the normal backoff loop with the violators excluded. | `review_r5_endpoint_attribution.rs` (maki-crypto: failover plus open circuit, no re-send when not retry-safe, single endpoint reports the violation), `missing_operation_statuses_are_endpoint_faults` (maki-crypto-http `phase8.rs`) |
| R5-007 (literal secrets) | The SPEC §9 literal check was an exact match against nine names, so `X-Vault-Token`, `X-Goog-Api-Key`, `Ocp-Apim-Subscription-Key`, `X-Amz-Security-Token`, `apikey` and `X-Auth-Key` validated as inline literals. A credential reference on a header outside the list also skipped `validate_credential`. | `is_sensitive_header`: the exact list plus credential-like name fragments; every credential reference is validated whatever header carries it. Query parameters remain literal-only and are documented as never holding secrets. | `review_r5_sensitive_headers.rs` (maki-format: eleven vendor names refused as literals and accepted as references for HTTP and gRPC, ordinary headers keep literals, references on ordinary headers validated) |
| R5-008 (punch ordering) | `finish_checkpoint` punched discarded slots before storing the new `checkpoint_sequence`. With an older durable write of the unit still in the journal (superseded by the tombstone), a failed state store or power loss in that window made recovery replay the write into the punched hole: new blocks, ENOSPC on a full backing, against the reservation promise in [space reclamation](space-reclamation.md). The existing guard covered only versions newer than the tombstone. | Collect the punchable units first, punch after the checkpoint state and its directory are synced. A punch failure there is logged and schedules the reclamation scan instead of failing a checkpoint that is already durable. `partial_punch_failure_keeps_both_discards_and_the_gap_across_crash` now expects the checkpoint to succeed; its durability assertions are unchanged. | `review_r5_reclamation.rs::a_slot_is_punched_only_after_the_checkpoint_that_retires_it_is_durable` (maki-core), `review_discard_crash.rs` |
| R5-009 (catalog commit) | `ensure_shard` inserted the shard into the in-memory catalog before `catalog_ab.store` and the root directory sync. When either failed, the catalog listed a shard that was not open, and the reclamation cursor's next-shard search indexed `self.shards[next]` and panicked every checkpoint that finished the cursor's shard. | Commit a cloned catalog and adopt it only after the store and sync succeed; the reclamation scans look shards up with `get`. | `review_r5_reclamation.rs::a_failed_shard_catalog_commit_does_not_break_reclamation` (maki-core) |
| R5-010 (long trim) | The adapter and `Engine::trim` refused a trim longer than `nbd.maximum_io` with EINVAL. The NBD maximum block size limits payloads and TRIM has none; the Linux nbd driver sends discards up to its own `max_discard_sectors`, so `fstrim` and `-o discard` were refused in practice. Reproduced end to end: libnbd's 64 KiB `nbd_trim` against an 8 KiB maximum reached the plugin through nbdkit 1.32 and failed with `Invalid argument`. | Trim validates alignment and bounds only (`validate_extent`, `check_extent`) and the engine journals it in unit-aligned chunks of at most `max_request_bytes`, each with its own admission and unit locks; FUA applies to the last chunk, whose sync makes the earlier ones durable. | `review_discard.rs` (maki-nbdkit: `a_trim_longer_than_maximum_io_discards_every_whole_unit` across reopen; the native libnbd case now also trims 64 KiB) |
| R5-011 (discard admission) | `admit_journal` charged tombstone-only requests the emergency reserve *plus* the checkpoint headroom, like writes. With the defaults (1 GiB + 4 GiB) every discard failed with ENOSPC below about 5 GiB free, so the tombstones whose checkpoint would punch reserved slots could never be journaled. | A request made only of tombstones is admitted against the emergency reserve alone; the reserve itself still holds. The 2026-10-03 hardware runs showed the limit of this: inside the headroom a filesystem cannot delete files (that is a write), so a trim there only returns space freed earlier; the documentation says so. *Corrected by AUD-087 ([#178](https://github.com/seo-rii/maki/pull/178)):* XFS `fstrim` forces a log write before it discards, and FITRIM failed with EIO in those runs, so a filesystem cannot trim there either; only a raw discard of the exported device is admitted inside the headroom ([known limitations](status.md#known-limitations)). | `review_r5_trim_admission.rs::a_trim_is_admitted_inside_the_checkpoint_headroom` (maki-core) |
| R5-012 (discard of damaged units) | The engine's already-zero filter (`read_ct`) and `Volume::discard_ct` (`read_slot`) read and CRC-checked the full payload: a unit with a damaged payload or header could not be discarded (EIO) while a full overwrite succeeded, and each discarded unit was read twice under the exclusive volume lock. | Both decide from the slot header (`current_sequence` / `slot_sequence`): only `Ok(None)` skips the tombstone; any other outcome, damage included, journals one. | `review_r5_trim_admission.rs` (maki-core: damaged payload and damaged header are discarded, read zero across a checkpoint, the neighbour unit is untouched) |
| R5-013 (breaker overflow) | `MakiDuration` has no upper bound and the breaker computed `now + open_duration` and `open_duration * 2` with panicking `Duration` operators: `open_initial = "9223372036854775808s"` validated and panicked the dispatcher on the first trip. | `saturating_add` / `saturating_mul`: a huge duration means open for a very long time. | `review_r5_breaker_overflow.rs` (maki-crypto: opening and doubling after a failed probe) |
| R5-014 (`reload cache` bounds) | The control verb passed `max_bytes` straight to the cache: any `maki-admin` member could set `0` (refused by config validation at startup) or `u64::MAX`. | The verb applies the startup rule plus a device-size ceiling (a cache larger than the device can never fill) and answers "NOT applied" otherwise. | `review_control.rs::control_socket_is_created_served_and_removed` (maki-nbdkit, Unix) |
| R5-015 (`prerm` and recovery) | The removal guard queried `maki@`, `maki-attach@` and `maki-workload@` units only. `maki-recover@` runs the packaged `maki-attach` after a daemon failure and can still be activating (or waiting on stop jobs) after the record is gone. | The query includes `maki-recover@*.service`. | `test_prerm_refuses_removal_while_a_recovery_unit_runs` (`scripts/test_debian_package.py`; the fake `systemctl` reports the unit only when its pattern is queried) |
| R5-017 (`maki-benchmark`) | The benchmark takes a production-format configuration, swallowed every volume-creation error (`let _ =`) and wrote `0xA5` over the first `ops × io_size` bytes (40 MiB by default) of whatever volume it named, with no confirmation. A device smaller than `io_size` panicked on `i % 0`. | An existing volume is refused (exit 2) unless `--destroy-data` is given; other creation errors fail; `io_size` larger than the device is refused. | `bins/maki-benchmark/tests/e2e.rs` (a second run without the flag exits 2 and leaves every shard file and the journal unchanged; with it, the run re-attaches) |
| R5-018 (creation over leftovers) | `create_volume` refused only an existing superblock. Leftover `data/shard-*.dat` of an earlier volume (superblocks removed, a partial restore) were adopted by `SlotStore::open`; slot headers carry no volume UUID, so the new volume served old ciphertext (EIO with AEAD, garbage with XTS) where it should read zeros. | Creation refuses any file in `data/`, `journal/` or `checkpoint/` with `AlreadyExists`, before writing anything; empty directories are accepted. Binding the volume UUID into slot or shard headers remains a candidate for the next format version. | `review_r5_create_empty_root.rs` (maki-format: v2 and v3, one leftover in each directory, nothing written; empty roots and empty directories still initialize) |
| R5-019 (root mountpoint) | `mountpoint = "/"` passed `check_abs_path` (which special-cases `/`) and the pre-mount ancestor check (no ancestors), so a configuration or override could mount the volume over the host root; detach would then unmount `/`. | `into_request` refuses `/` for configuration and override alike. | `review_r5_mountpoint_root.rs` (maki-privileged) |
| R5-020 (cache order) | `VersionedLruCache::put` removed the unit's entry unconditionally and a `get` for a mismatching sequence evicted it. A reader that snapshotted `(U, S1)` and finished decrypting after another reader cached `(U, S2)` replaced (or evicted) the newer entry: never stale data, but a lost hit and another payload read and decryption. | `put` keeps a newer entry; a live newer entry survives a lookup for an older sequence. Stale and expired entries are still evicted on lookup. | `review_r5_cache_order.rs` (maki-cache); the randomized `review_cache_model.rs` reference model follows the same rule |
| R5-021 (header name before credential) | `from_config` loaded and formatted a header's credential into a plain `String` before checking the header *name*; the invalid-name error path dropped it without wiping (only the invalid-value path zeroized). | The name is validated before any credential is loaded. | `an_invalid_header_name_is_refused_before_its_credential_is_loaded` (maki-crypto-http `review_header_values.rs`: a counting key source sees no load) |
| R5-022 (create output) | `maki volume create` printed `created volume <provider type>`, labelling the provider as the volume name. | The line names the volume and the provider separately. | `volume_lifecycle_create_inspect_check` (maki `e2e.rs`) |
| R5-023 (command environment) | The attach, detach and grow steps (`mount`, `umount`, `nbd-client`, `lvextend`, `xfs_growfs`, `vgchange`, `modprobe`) and their `blkid`/`blockdev` probes ran through a bare `Command::new`, inheriting the caller's environment and `PATH`; only `recover` and the LVM preflight cleared it. | One `command::controlled` builder (cleared environment, systemd's default service `PATH` `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`, `LC_ALL=C`) is used for every external command of the helper. | `step_commands_do_not_inherit_the_callers_environment` (maki-privileged `exec_tests.rs`) |

| R5-006 (detach sentinel) | Detach, cleanup and attach rollback of a live backend required `<mountpoint>/.maki-sentinel` to match. The mount root belongs to the workload, which could delete, rewrite or replace the file and make every `maki-attach@` stop fail with XFS still mounted. The same observation already bound the mount to the recorded LV (device number, root `/`, XFS, exclusive NBD dependency), so the sentinel added no proof. | `detach::observe` is kernel-only, like recovery; the `allow_missing_sentinel` rollback flag is gone. Attach and `verify` keep the sentinel as an identity input. This supersedes the earlier design whose tests asserted that ordinary detach stays strict (`initial_rollback_only_relaxes_a_missing_sentinel` and the sentinel half of the replacement-mount test are replaced). | `the_workload_cannot_block_detach_through_its_sentinel` (maki-privileged `detach_tests.rs`: deleted, rewritten, symlinked and directory sentinels; another device is still refused) |

| R5-024 (mountpoint ownership) | `check_mount_target` checked owner and mode of every ancestor but not of the mountpoint itself, which the documentation allowed to belong to the workload. A workload with FUSE access could `fusermount` over it between the check and `mount`: XFS stacked on the FUSE mount, `VerifyMountDevice` failed and `attach_rollback` halted with XFS mounted and the record kept. | The mountpoint directory must be owned by root and not group/other-writable, like its ancestors. It is hidden under the mounted volume, whose root carries the workload's ownership. | `a_mountpoint_owned_or_writable_by_others_is_refused` (maki-privileged `regression_mount_target.rs`) |

| R5-025 (bounded metadata reads) | Allocation maps, discard maps and the shard catalog used the generic 1 GiB `MAX_ENCODED_LEN`, so an over-long corrupt or tampered copy was read into memory in full, several times during recovery (29 MB for three 4 MiB copies), before decoding rejected it. | `AbStore::with_max_len`: the store and the offline checker open maps with their exact geometry size (`AllocationMap::encoded_len`) and the catalog with `ShardCatalog::max_encoded_len(num_shards)`; a longer copy is invalid by its length, as MAKI-026 already did for fixed-size records. No on-disk change. | `review_r5_bounded_metadata.rs` (maki-core: recovery reads less than one padding's worth and still opens from the intact copies) |

| R5-026 (`maki-check` mutated) | The checker opened its root with `FileBacking::new`, which creates missing directories, so `maki-check /typo/path` created `/typo/path`. | A root that is not an existing directory is refused before the backing is opened. | `check_of_a_missing_root_creates_nothing` (maki-check `e2e.rs`, fast and `--deep`) |
| R5-027 (truncated last shard) | Open marked every cleared slot beyond a truncated data file's end as allocated (EIO until rewritten), including positions of a partial last shard past the device's last unit, and `allocated_units()` did not filter them: the deep check reported nonexistent units as unrecoverable. | Marks and `allocated_units()` stop at `num_units`, as `unlisted_units()` already did. | `review_r5_truncated_last_shard.rs` (maki-core: units 9–11 reported, 12–15 not) |

| R5-028 (key in a certificate file) | `read_tls_file(.., may_hold_private_key = false)` (every `ca_file`, WebSocket and gRPC `client_cert_file`) skipped the credential checks and never wiped its buffer, so a combined certificate/key PEM there put the mTLS private key, unchecked, into ordinary memory. | Such a file is refused at attach and its bytes erased; the key belongs in `client_key`. | `a_private_key_in_a_certificate_only_file_is_refused` (maki-crypto-http `review_tls_files.rs`) |

| R5-029 (cache clock) | The engine built its plaintext cache with a fresh `SystemClock`, so cache TTLs ignored `EngineOptions::clock` and could not be tested with `ManualClock`, against the injectable-clock rule. | The cache uses the engine's clock. | `review_r5_cache_clock.rs` (maki-core: an entry past its TTL on the manual clock misses) |

| R5-030 (trusted attach config) | Only `verify` read the attach configuration through the root-owned, descriptor-anchored reader. Attach, detach, cleanup, recover and grow used `read_to_string` on any path, although they run as root on what the file says (mountpoint, VG, NBD socket): a config writable by a non-root user handed them those choices. | Executing verbs use `exec::load_trusted_config` (the `verify` reader: root-owned regular file with one link, no group/other write, root-owned ancestors, read through held descriptors); `--plan` still reads any file. | `executing_verbs_refuse_an_attach_config_a_non_root_user_controls` (maki-attach `e2e.rs`, Linux, skipped as root) |

| R5-031 (daemon sandbox) | `maki@.service`, which holds plaintext and keys, had no kernel-log, clock, hostname, realtime, namespace, syscall-ABI or address-family restriction. | `ProtectKernelLogs`, `ProtectClock`, `ProtectHostname`, `RestrictRealtime`, `RestrictNamespaces`, `SystemCallArchitectures=native`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK` (netlink for glibc `getaddrinfo`). `SystemCallFilter=@system-service` with `SystemCallErrorNumber=EPERM` was adopted after three packaged PostgreSQL lifecycles ran under it without a denial ([record](qualification/database-discard-pressure-validation-2026-10-03.md)); `MemoryDenyWriteExecute=yes` followed on 2026-10-04, after the local and all three remote providers round-tripped data under it with the filter. `systemd-analyze verify` accepts the unit. | `the_daemon_unit_is_sandboxed` (maki-nbdkit `regression_control_packaging.rs`) |

| R5-032 (RMW through the cache) | A partial-unit write always read and decrypted the unit, although reads serve a cached `(unit, sequence)` without the payload or the provider (R4-006): every small write over a cached unit cost a provider round trip. | The RMW path establishes the current sequence and uses a cache hit under the unit locks, honouring `verify_on_hit` like reads; misses read and decrypt as before. | `review_r5_rmw_cache.rs` (maki-core: no decryption for a cached unit with and without `verify_on_hit`; an uncached unit still decrypts once) |

Follow-ups from a review of the R5 commits themselves:

- **R5-008:** a punch that kept failing still failed the checkpoint, now
  *after* publication. The same call retried the just-failed units through
  the reclamation scan and returned its error once the state was stored,
  the journal deleted and the overlay retired, so the engine reported a
  durable checkpoint as failed (Degraded). After publication a reclamation
  failure is now logged and leaves its cursor; the next idle checkpoint
  retries it and still reports a persistent failure there, which keeps the
  worker from spinning. Two older tests that expected a failed punch to fail
  the checkpoint (`review_discard_model.rs`, and
  `failed_punch_is_retried_by_reclamation_even_when_bitmap_is_already_set`,
  formerly `failed_punch_keeps_journal_and_retries…`) now expect it to
  succeed, and still check that the failpoint fired and the data survives.
  Regression: `a_persistently_failing_punch_does_not_fail_a_published_checkpoint`.
- **R5-005:** an endpoint that broke the contract was skipped for the rest
  of the pass but sent the same request again on the next pass. It is now
  excluded for the whole operation, and the violation is reported once only
  such endpoints remain. Regression:
  `a_contract_violating_endpoint_is_not_retried_on_a_later_pass`. AUD-021
  ([#154](https://github.com/seo-rii/maki/pull/154)) makes that rule hold
  whatever order the endpoints were tried in.
- **R5-004 trade-off:** with a provider that is not retry-safe, one
  integrity failure in a coalesced decrypt batch fails every request in it
  (the error fans out, as before `1678e3e`). That is the cost of never
  sending a request twice.
- **R5-002 scope:** the post-mount checks of `maki-attach attach` required
  `nosuid,nodev` but the `maki-attach verify` workload gate did not, so a
  volume mounted before the change (or remounted `suid`) still opened to the
  workload. The gate now refuses such a mount and asks for a reattach
  (`missing_read_only_subtree_stacked_or_extra_mounts_refuse_the_gate`,
  cases `suid` and `dev`).

A second hunt over the journal, recovery scan, rollback backing, WebSocket
provider, control server and NBD adapter found two more:

| Finding | Problem | Fix | Tests |
|---|---|---|---|
| R5-033 (lowered segment size) | Recovery capped each segment file at four times the *configured* `journal_segment_size`. A checkpoint never deletes the active segment, so after a clean stop a segment of up to the old size stays on disk: lowering the setting by about 4x (256 MiB to 16 MiB) made attach and `maki check` report the clean volume as corrupt. | The setting is bounded by `MAX_JOURNAL_SEGMENT_SIZE` (1 GiB) and recovery caps segment files by the largest file any configuration's writer can produce; a larger file is still refused before it is read. The oversize regression moved to a sparse file on `FileBacking`. | `review_r5_segment_size.rs` (maki-core: 20 MiB segment written at 64 MiB, recovered at 1 MiB), `review_r5_segment_limit.rs` (maki-format), `recovery_rejects_oversized_segment_before_allocation` (maki-core `review_storage.rs`, Unix) |
| R5-034 (rollback write cost) | The rollback-protected backing rebuilt the committed and working slot sets and cloned the file's whole page map for every page write, and rebuilt every reservation coordinate for every write: a 64 KiB write into a reserved range took 152 ms with 128 MiB committed and filling 128 MiB took 263 s (release build). | A committed-slot set recomputed only after a successful commit; a cached used-slot set that allocation adds to and every slot-freeing path (commit, truncate, punch) invalidates, so it is never smaller than the slots in use; a rotating free-slot hint; page lookups instead of node clones; a reservation fast path when both views already reserve the range. 0.5 ms per write and 0.6 s to fill 128 MiB. | `phase_r5_rollback_write_cost_gate_full` (maki-backing `rollback_write_cost.rs`, release gate; fails on the previous implementation), all rollback suites unchanged |
| R5-035 (text credentials; found by the 2026-10-04 remote-provider campaign) | HTTP header and gRPC metadata credentials, and WebSocket/gRPC/HTTP `client_key` PEMs, were read through the key loader, which hex-decodes any even-length hex string because local provider keys may be stored as hex. A bearer token generated with `openssl rand -hex 32` became 32 random bytes: `maki@` refused to start (`credential is not valid UTF-8`), and a hex token whose decoded bytes happened to be printable would have been sent altered. `maki volume create` never loads it, so only the daemon failed. | `KeySource::load_text` returns a credential's exact bytes; headers, metadata and PEM keys use it. `load` still hex-decodes local provider keys. | `review_r5_text_credentials.rs` (maki-crypto-http: the recorded `Authorization` header equals the hex token; maki-nbdkit: the daemon builds HTTP and gRPC providers with one), keysource unit test |
| R5-036 (write zeroes; found preparing the 2026-10-04 follow-up campaign) | The plugin returned `can_zero = 0`, leaving WRITE_ZEROES to nbdkit, which emulates it with one `pwrite` of the whole range. The NBD maximum block size limits payloads only, so clients send longer zero requests (nbdcopy sent 64 and 128 MiB for the holes of a sparse image; the Debian 12 6.1 kernel's NBD driver sends no WRITE_ZEROES at all, `write_zeroes_max_bytes` 0, so the kernel path was not affected there), and the adapter refused every one above `nbd.maximum_io` with EINVAL. SPEC §48 required this "disabled native write-zeroes" design. | A native `zero` callback: `NbdAdapter::zero` writes zeros in requests of at most `maximum_io`; with `NBDKIT_FLAG_MAY_TRIM` on a v3 volume the complete units are discarded and only partial edges written; FUA on the last step. `can_fast_zero` is 0 and a FAST_ZERO request fails with ENOTSUP. SPEC §48 now requires native zeroing of any length. | `review_r5_write_zeroes.rs` (maki-nbdkit: legacy and discard volumes, with and without trim, unaligned edges, bounds; native libnbd `nbd_zero` of 128× the maximum block size on both formats), `phase6.rs` capability test updated, ABI probe checks the two new flags |
| R5-037 (systemd 257 credential mode; found by the 2026-10-04 Debian 13 campaign) | systemd 257 writes `LoadCredential=` files with mode `0440`. The key loader required `0600` or `0400` for every credential, so `maki@.service` refused to start on Debian 13 with any provider (`credential file "crypto-token" has mode 0440`). `maki volume create` does not load the credential, so only the daemon failed. | `FileKeySource::credentials_directory`, used for `$CREDENTIALS_DIRECTORY`, accepts group read when the file's group is the process's effective group or root; group write, other access, and every group bit on plain `file` credentials are still refused. | `review_r5_credentials_directory.rs` (maki-crypto-local: 0440/0640 accepted there, 0444/0460/0470/0644 refused, 0440 still refused for a plain file) |
| R5-038 (requests above `maximum_io`; found by the 2026-10-04 Debian 13 campaign) | The adapter refused any read or write longer than `nbd.maximum_io` with EINVAL (BUG-011). The NBD maximum block size is advisory, and the Linux NBD driver ignores it: Debian 13's 6.12 kernel reports `max_sectors_kb` 1280 and sent 1.25 MiB writes to a 1 MiB export. Buffered writeback lost those writes silently: `mkfs.xfs` exited 0 and the volume read back a zeroed XFS superblock (`can't read superblock` at mount, on the local provider too). ext4 happened to issue no such write. Debian 12's 6.1 kernel defaults NBD devices to `max_sectors_kb` 128 (read on a throwaway VM before connecting), so the earlier 6.1 campaigns were not exposed unless an administrator raised it. | Reads and writes above `maximum_io` are served in chunks of at most `maximum_io`, each copied into its own `SecretBuffer` and submitted as its own engine request (so the engine's per-request bound, the plaintext budget and journal headroom are unchanged, which was F07/BUG-011's concern); FUA on the last chunk. Zero-length, misaligned and out-of-range requests are still refused before any copy. SPEC §13 updated. | `review_nbd_limits.rs` (maki-nbdkit: chunked 20 KiB read/write against an 8 KiB maximum survives reopen; misaligned and out-of-range oversized requests still refused with buffer and volume untouched; real nbdkit with a libnbd client in non-strict mode, which failed with EINVAL before the change) |
| R5-039 (serialized provider calls; found by the 2026-10-04 Debian 13 campaign) | The engine awaited a request's provider batches one after another, and a `remote-http` mapping without `items_path` still declared `[crypto.batch] max_items` (64), so the scheduler grouped units that the HTTP provider then sent one request at a time. Every unit cost a full round trip: under 10 ms of netem latency the campaign read at about 100 KiB/s (4,123 s for one step that took 63 s over WebSocket). | `Engine::run_batches` runs a request's batches concurrently in order: the first under the request's own admission, each further one only under an idle `max_active_callbacks` slot taken with `try_acquire` (never waiting, so no deadlock and no starvation of queued requests, and provider concurrency stays within the limit, SPEC §30); the first error cancels the rest. `VolumeConfig::effective_batch_max_items` is 1 for a per-item HTTP mapping, used by the HTTP provider's own capabilities and the daemon's, and the scheduler's `target_items` follows it so units are not held back to coalesce; its `max_items` is unchanged, since the attach self-test sends multi-item requests (review R04 refuses a request above it). A first attempt set only the daemon's copy of the capability and changed nothing, which a benchmark showed. Local benchmark, 10 ms per provider request, two endpoints, sequential 128 KiB requests over 8 MiB: write 25.2 s → 2.8 s, read 25.0 s → 2.9 s. On Debian 13 with netem on loopback ([record](qualification/debian13-postgresql-http-validation-2026-10-05.md)): 0.61 MiB/s with 10 ms ± 5 ms delay and 0.16–0.17 MiB/s with 1 % loss added, where the slowest of the parallel unit requests (a TCP retransmission) dominates. | `review_r5_chunk_concurrency.rs` (maki-core: one request's eight single-unit batches run together, encrypt and decrypt; four concurrent requests never exceed `max_active_callbacks = 3`), `review_r5_per_item_http.rs` (maki-nbdkit: effective size, scheduler target, and the HTTP provider's own capability, which failed with 64 before the fix), `phase5_admission.rs` unchanged |

Also noted: cancelling or
timing out one WebSocket request retires its connection and fails the other
requests in flight on it as retryable, which a provider that is not
retry-safe turns into EIO.

The HTTP TLS `Debug`-text classification was initially left unchanged.
The later immediate circuit-open policy for `EndpointFatal` (BUG-094) made
misclassification observable: an EOF before any certificate arrived matched
"handshake" and immediately opened an otherwise healthy endpoint's circuit.
The 2026-11-14 follow-up (BUG-186) walks typed rustls errors through transport
and I/O wrappers instead. EOF/reset remains `Retryable`; certificate and TLS
protocol errors remain `EndpointFatal`, and HTTP framing violations remain
`Contract`. `maki-crypto-http/tests/review_tls_classification.rs` covers EOF,
reset, invalid records, a fatal alert, and the first error's actual
EndpointSet circuit state; the existing TLS suite retains CA/SAN/mTLS controls.

Considered and left as is: the gRPC provider's local size estimate omits
the context strings; an under-estimate is refused by tonic's encoder as
`OutOfRange`, which maps to the same `NonRetryableRequest`. Discard admission
charges plaintext bytes it never holds, but each chunk is bounded by
`nbd.maximum_io`, which `limits.max_plaintext_bytes` must already hold.

Considered and left as is: `lvextend` (grow) and the detach-time
`vgchange -an` address the VG by name rather than through `--devices` and
`--select vg_uuid=` as activation does. Before either runs, the kernel
observation proves every mapping of that VG depends only on the recorded NBD
device, and LVM refuses an ambiguous duplicate VG name; scoping them needs the
verified LVM identity at detach and grow time and a hardware campaign.

Considered and left as is: the checkpoint worker does not wake for store
repairs found at open (an adopted orphan shard, a rebuilt allocation map) when
nothing else is pending. An unpersisted repair is redone at the next open and
every write path persists it before any catalog commit (K-03), so this costs
latency, not durability.

The 2026-10-03 hardware campaign found that the first R5-023 `PATH`
(`/usr/sbin:/usr/bin:/sbin:/bin`) hid a source-built `nbd-client` 3.27 in
`/usr/local/sbin`, which the helper had found through the inherited
environment before: `maki-attach attach` failed with "No such file or
directory" at its first `nbd-client` step. The controlled environment now uses
systemd's default service `PATH`, root-controlled locations only, including
`/usr/local`.

`scripts/privileged-linux-validation.sh` created its mountpoint inside a
user-owned `mktemp` tree (or under `/var/tmp`, mode 1777), which the
mount-target rule of `69514ea` and R5-024 refuses. It now uses a root-created
`/run/maki-validation-mnt.*` directory and removes it during cleanup. The
script needs sudo and kernel NBD, so this change has been syntax-checked only;
the next campaign is its first run.

`NbdAdapter::shutdown` has no panic guard of its own (R5-016, not changed):
storage and provider panics already become errors before it, and no reachable
panic was found.


## Correctness and recovery review — 2026-10-12

The review used `1c1e64f`. Each functional fix starts with a failing permanent
regression and retains existing success, retry, cancellation and persistence
contracts. The two journal paths use `CrashableBacking` with sector tearing;
concurrent initialization uses actual `FileBacking`; transport failover uses
real local HTTP/gRPC/TLS servers; sentinel partial writes use an isolated child
with an OS file-size limit. These are automated regressions, not a new external
kernel-NBD or hardware-power-loss campaign.

| Finding | Result | Permanent regression |
|---|---|---|
| BUG-020, journal length retries | Reassert accepted length together with verified bytes before retry sync, including recovery restarts | maki-core `review_journal_length_retry.rs` |
| BUG-033, writer ownership bypass | Authority/wire v2 private capability gates current-session mutations, including older sessions using the same credential; v1 requires explicit migration | maki-backing `remote_session_authorization.rs`; maki-witness `transport.rs`, `session_erasure.rs`, `etcd_ha.rs` |
| BUG-034, gRPC credential copies | Guard original resolved metadata, endpoint clones and constructor/error/drop paths; format from guarded bytes without intermediate copies | maki-crypto-grpc `review_credentials_erasure.rs`; maki-nbdkit `review_grpc_credential_erasure.rs` |
| BUG-035, later batch error | Consume completions immediately, cancel remaining work on error and restore successful input order | maki-core `review_batch_liveness.rs` |
| BUG-036, HTTP oversized response | Classify response bounds and arithmetic overflow as peer contract violations; preserve unsafe no-resend | maki-crypto-http `review_response_contract.rs`, `phase8.rs` |
| BUG-037, persisted geometry | Compare immutable saved fields and advertised minimum I/O before provider construction/readiness | maki-nbdkit `review_persisted_geometry.rs` |
| BUG-038, tiny probe rate | Configuration rejects unrepresentable intervals; direct library invalid rates disable free probes without panicking | maki-crypto `review_probe_interval.rs`; maki-format `review_probe_interval_config.rs` |
| BUG-039, concurrent create | Lock before the first root check through the final directory sync; preserve explicit lock-file durability | maki-core `review_create_concurrency.rs`; maki-format `review_create_lock.rs` |
| BUG-040, sentinel retry | Atomically publish fully synced bytes without replacement; rewrite/resync identical existing content and synchronize the directory | maki-privileged `review_atomic_sentinel.rs`, `sentinel_tests.rs` |
| BUG-041, gRPC unsupported method | Treat `Unimplemented` as endpoint-scoped; record breaker failure and route safe requests to a healthy peer | maki-crypto-grpc `phase9_grpc.rs` |
| BUG-042, attach CLI options | Reject missing values, unknown/duplicate options and extra positionals before loading configuration | maki-attach `review_strict_arguments.rs` |
| PERF-001, endpoint admission | FIFO capacity admission reselects after capacity release, validation promotion and open-circuit probe readiness, holding no RPC permits while waiting | maki-crypto `review_endpoint_admission.rs`, existing flow/dispatch/probe-lifetime suites |
| PERF-002, repeated witness failover | Prefer the last validated successful address, retaining one deadline, identical requests and terminal identity/authorization/conflict failures | maki-witness `failover.rs` |
| TOOL-001, new compiler warnings | Compatible CAS and fixed-array chunk APIs; pinned 1.94 baseline and separate latest stable jobs, with matrix cancellation disabled | Strict Clippy on Rust 1.99; exact-revision Linux/Windows CI |

Recovery also reduces slot writes within each existing 1 MiB batch to the
latest sequence per unit. All historical validation and allocation/discard
publication order remain. `review_recovery_batch_latest.rs` covers overwrites,
discard ordering, batch boundaries, allocation evidence, superseded corruption
and 96 restart/power-loss fault cases. The controlled fixtures reduced 24/4/300
slot writes to 2/1/2; this is a write-count result, not a throughput claim.

Request observability now separates actual Engine calls from retained admission
slots, records success/error/cancellation and measures complete per-operation
latency alongside explicit storage-sync time. The legacy gauges and successful
storage-only series retain their meanings; `review_request_metrics.rs` verifies
provider and storage cancellation separately and failed full-FLUSH/FUA timing.
See [measurement boundaries](observability.md#request-counts-and-latency-boundaries).

The benchmark adds bounded parallel jobs, deterministic random access, mixed
read/write ratios, configurable working sets and periodic drained barriers.
Setup, real latency, exact pending work, sampled resource peaks and optional
process RSS are reported separately. `concurrent_report.rs` exercises actual
AES at 1/2/8/32 callers; `synthetic_recovery.rs` verifies 768 requests across
12 virtual-time healthy/outage/recovery phases. These simulations are not a
hardware throughput result. See [benchmark guide](benchmark.md).

The state boundaries are isolated where they carry testable invariants:
indexed batch completions, FIFO endpoint admission, current-session capabilities,
recovered geometry comparison and request-lifetime guards. No arbitrary file
split is needed to establish these contracts.

Default tests, strict Clippy and formatting must pass on the pinned baseline
and latest stable. Journal/recovery changes additionally require the complete
ignored release gates before release acceptance. Push success is separate from
the exact-SHA GitHub Actions result; local Rust 1.94 results do not establish
Rust 1.99 or Windows CI success.

## Additional functional findings — 2026-10-12

The six additional findings were reproduced against the current implementation
before their fixes. Permanent regressions run the real Engine, deterministic
restart/power-loss model, local HTTP server, or CLI process as appropriate.

| Finding | Implementation | Permanent regression |
|---|---|---|
| BUG-043, recovered shard readiness | Treat loaded allocation copies as unproven in each session. Establish both copies and directory durability before reserving a slot or publishing the whole adopted catalog; failed preparation remains retryable. Reads defer this metadata work. | maki-core `review_shard_readiness.rs`: initial ENOSPC, v2/v3 retry, empty checkpoint, cached B after failed sync, second-copy/directory failures, and multiple adopted shards |
| BUG-044, per-request pending overflow | Enforce the tail budget before every record, and share the maximum framed-record size between configuration validation and core attach. Intermediate sync failure stops append. | maki-core `review_journal_pending.rs`; maki-format `review_pending_record_limit.rs` |
| BUG-045, no-progress checkpoint starvation | Update the periodic checkpoint reference time only when the checkpoint sequence advances. Preserve explicit checkpoint's durable-only behavior. | maki-core `review_checkpoint_progress.rs`: six administrative calls and four completed worker passes through 120 seconds, plus controls |
| BUG-046, HTTP URL components | Compose the endpoint path prefix and operation path separately from their queries. Preserve escapes and query-value slashes, append configured query pairs, and omit fragments from the wire. | maki-crypto-http `review_url_composition.rs`: actual received request targets |
| BUG-047, HTTP method spelling | Normalize validated configuration methods to uppercase in `from_config`, retaining explicit programmatic `OpSpec` methods. | maki-crypto-http `review_method_normalization.rs`: encrypt/decrypt with POST/post/PUT/pUt |
| BUG-048, missing-root CLI mutation | Inspect/check reject a missing or non-directory backing root before invoking its constructor; volume creation still accepts a new path. | maki `review_existing_repository.rs`: real inspect/check/deep, regular-file rejection, creation and existing-volume controls |

The lazy shard proof adds metadata I/O once per store session when reservation
or checkpoint first needs it, proportional to the loaded shard count. In the
single-shard controlled fixture, recovery alone adds no allocation I/O; the first
subsequent FUA adds four allocation writes, four allocation syncs and three data
directory syncs. This is an operation-count observation, not a throughput claim.

The new suites contain 30 regression functions. Their test-first results and
focused success do not replace the full workspace, complete ignored release
gates, or exact-revision Linux/Windows CI required above. Hardware power loss and
external kernel-NBD qualification remain separate.

## Batch, runtime reload and benchmark findings — 2026-10-12

The follow-up report inspected `11c5a66` without a Rust toolchain. Its models
were treated as proposed reproductions, then checked with compiled Rust
regressions against the current code before implementation.

| Finding | Correction | Permanent regression |
|---|---|---|
| BUG-049, decrypt batch byte basis | Split Engine reads and RMW decrypts by the original volume unit size. Preserve the scheduler's separate resident-ciphertext admission. | maki-core `review_logical_read_batches.rs`: short reversible encodings, individual/combined/partial reads and RMW, expanded ciphertext resident limits |
| BUG-050, serialized split retries | Give each retry-safe caller an independent verdict under the same lane semaphore. Retain the failed batch's input reservation and reuse its first slot; extra retries acquire shared capacity. Observe cancellation of waiting and running callers. | maki-crypto `review_scheduler_split_retry.rs`: encrypt/decrypt progress, item order, width-one reuse, shared bounds, cancellation and retry-safety controls |
| BUG-051, ignored cache TTL | Validate the whole payload, including positive TTL and supported field names, before applying byte limit and TTL together. Size-only reloads preserve TTL; the CLI accepts `--ttl` in either option order. | maki-nbdkit `review_cache_ttl_reload.rs` with ManualClock; maki `review_cache_reload_cli.rs` with a real control request |
| BUG-052, false read-verification claim | Derive `read_verified` from actual compared read samples. Add `verified_read_operations` and `read_verification`, and print skipped when no reads ran. Read failures still exit without a success report. | maki-benchmark `review_read_verdict.rs`: zero-percent and short mixed workloads, actual reads, default phases and text output |

The shared stateless Engine/provider fixture encodes uniform plaintext as a
compact packet with the fake's integrity/context checks and retains full-size
ciphertext for other data.
Its zero and all-one attach probes are short too; scheduler admission stays
enabled throughout attach, reads and RMW. Independent fixture instances decode
one another's ciphertext without a shared dictionary.

**BUG-053, attach self-test byte basis.** The positive decrypt probes in
`provider_self_test`, wide/repeated `provider_conformance` probes, and both
directions of `cross_endpoint_self_test` now split by the caller's actual
plaintext unit size. Using encoded lengths previously sent two short units
against a one-unit byte limit, refusing an otherwise valid attach; ciphertext
overhead also caused unnecessarily small batches. Item limits, result-shape
validation, negative probes and independent resident-memory admission remain
enforced. `maki-crypto/tests/review_selftest_logical_batches.rs` covers those
paths and exact byte/item boundaries; `maki-core` exercises real scheduler
attach and subsequent reads/RMW with the same fixture.

Focused success remains separate from the complete workspace, ignored release
gates and exact-revision Linux/Windows CI.

The prior Windows CI reached workspace tests after all four Clippy matrix
steps passed. Its remote-witness configuration fixtures still used Unix TLS
paths, which Windows correctly rejects as nonabsolute. The fixtures now use
drive-qualified absolute paths there while keeping their invalid-path checks.
Linux tests are local evidence; Windows execution must be confirmed in CI.

## Additional functional corrections — 2026-10-12

The six findings were reproduced against `8d2b2fa` without changing product
code. Each correction has a permanent regression that failed before its fix;
the changes keep the existing on-disk formats and wire messages.

| Finding | Correction | Permanent regression |
|---|---|---|
| BUG-054, local restore after failed writeback | Authenticate all selected evidence before mutation, then rewrite referenced arena pages, the selected manifest and marker, and reassert reserved file lengths before local readiness. Do not advance the witness. | maki-backing `rollback/review_restore.rs`: failed sync, plain restart, later acknowledged write, torn power loss, manifest/marker/length failures, partial rewrite, repeated failures and authentication controls |
| BUG-055, live control address replacement | Serialize publication and cleanup with a short directory lock. Refuse live or backlogged addresses; preserve stale-address recovery. Remove only the listener's own inode and eliminate adapter's duplicate unlink. | maki-control `review_socket_ownership.rs` and maki-nbdkit `review_control_collision.rs`: concurrent binds, stale sockets, full backlog, two volumes, predecessor shutdown and successor ownership |
| BUG-056, result validation after a success verdict | Validate both the peer and common result contracts inside the RPC attempt, before breaker success. Attribute bad successful payloads to that peer and use failover only when retransmission is safe. | maki-crypto `review_endpoint_result_contract.rs` and maki-crypto-http `review_endpoint_payload_contract.rs`: actual HTTP 200 size violations, shape/order/index errors, peer-specific limits, breaker state, permits and unsafe/single-peer controls |
| BUG-057, local gRPC receive errors | Bound incoming frame headers and mark local response decoding errors with private typed provenance. Classify those as `Contract`; preserve actual remote `OutOfRange` request semantics and the original protected wire decoder. | maki-crypto-grpc `review_receive_contract.rs` plus framing unit tests: actual TCP/HTTP2 failover, malformed protobuf, exact bounds, unsafe retransmission, remote status text, split headers, trailers and cancellation |
| BUG-058, unrelated maximum supported unit | Bind daemon dispatch to `crypto_unit_size + random_prefix_bytes`. Split decrypt calls using that logical size and reject a result of another supported size inside the endpoint attempt. Preserve the advertised capability intersection and actual ciphertext admission. | maki-crypto `review_pinned_endpoint_unit.rs` and maki-nbdkit `review_endpoint_volume_unit.rs`: actual scheduler attach, FUA/read/checkpoint/reconnect, prefix settings, wrong-size failover, cached capabilities and input controls |
| BUG-059, oversized configured volume name | Require a 1–64 ASCII-byte operational name before opening backing storage; preserve `[A-Za-z0-9_-]`. Align the configuration guide and SPEC with the boundary. | maki-format `review_volume_name_bound.rs` and maki-nbdkit `review_volume_name_status.rs`: 64/65-byte boundary, 65536-byte rejection without backing side effects, maximum-name FUA and official status response |

There are 51 new regression cases across these fixes. Focused checks also ran
the complete backing and gRPC package suites, existing control/configuration
and daemon cases, and endpoint admission, capability, identity and batching
regressions. Rust 1.94 and 1.99 workspace strict Clippy and formatting passed.
Full workspace tests, the extended ignored release gates, and exact-revision
Linux/Windows CI are recorded separately; focused passes are not a substitute
for those results or for physical power-cut qualification.

Local reopen now adds a read and rewrite for every referenced arena page,
using a bounded 4 KiB page buffer. This cost is documented in
[rollback capacity and durability](rollback-protection.md#capacity-and-durability).
The remote restore path still copies a selected generation into a new
namespace. No hardware power-loss, kernel NBD or real mount campaign was
performed for these regressions.

## Additional functional corrections — 2026-10-13

The six findings were reproduced against the product implementation in
`0a9199a`. These fixes preserve the on-disk formats and wire messages.

| Finding | Correction | Permanent regression |
|---|---|---|
| BUG-060, failed journal creation cleanup | Retain the failed inactive segment index until unlink and journal directory sync both succeed. FLUSH/FUA, index reuse and covered-segment reclamation first complete this obligation. Preserve the original creation error and reject genuinely corrupt headers. *Adapted by AUD-003 ([#166](https://github.com/seo-rii/maki/pull/166)):* a roll no longer extends the file before writing the header, so a torn header prefix leaves a short file that recovery discards; `an_unremoved_invalid_header_still_fails_closed_after_power_loss` now persists the whole header and damages one byte, and recovery must still refuse it. *Relaxed by AUD-054 ([#177](https://github.com/seo-rii/maki/pull/177)):* recovery now discards a final segment that holds only such a header when it lies above the segments the durable proof and mark name, since it never held an acknowledged record. The test proves the refusal for what BUG-060 protects instead (the damaged header followed by record-like bytes, and at an index the mark names), and its former state is `an_unremoved_damaged_header_only_creation_is_discarded_after_power_loss`, which attaches with every acknowledged record. The writer's cleanup obligation is unchanged. | maki-core `review_journal_creation_cleanup.rs`: first/successor header partial writes, remove/directory failures, retry and sequence bounds, v2/v3, checkpoint, restart and torn power loss |
| BUG-061, configured outer capacity mismatch | Compare configuration to the authenticated COW manifest capacity before provider initialization and READY, for both local and remote protected backing. Refuse mismatch without resizing; direct low-level open still uses stored geometry. | maki-nbdkit `review_rollback_capacity.rs`: actual local AES and remote mTLS, smaller/larger/matching capacity, reserve policy, credential-loading order, session release and data preservation |
| BUG-062, inaccurate gRPC request estimate | Check the completed protobuf request's exact encoded length before readiness or transmission. A local size violation remains a request error and does not charge endpoint breakers. Preserve genuine remote status semantics. | maki-crypto-grpc `review_request_size.rs`: fitting and oversized requests, context/varint boundaries, two-peer breaker neutrality and remote Internal failover |
| BUG-063, unknown WebSocket error class | Treat missing, malformed or unsupported remote error classifications as endpoint contract violations. Preserve recognized error classes and refuse unsafe retransmission. | maki-crypto-websocket `review_error_class.rs`: conformance followed by peer failure, healthy failover, malformed classes, all-peer terminal failure and unsafe controls |
| BUG-064, lost WebSocket receive verdict | Carry receive size/encoding/framing violations through generation cleanup as Contract. Publish death and sweep the same generation under one pending lock, so retirement cannot replace the verdict. Ordinary abrupt transport loss still reconnects when safe. | maki-crypto-websocket `review_receive_contract.rs`: single/fragmented size limits, invalid UTF-8, multiple pending callers, healthy successor, breaker failover, terminal stall and unsafe controls; existing connection-lifetime suites |
| BUG-065, omitted split-retry totals | Increment provider call and item totals when each ordinary or split call actually starts. Exclude unstarted cancelled groups and preserve coalesced, pending and inflight semantics. | maki-crypto `review_retry_metrics.rs`: encrypt/decrypt retries, cancellation before/after dispatch, mixed group sizes, coalescing and inflight counts |

There are 50 new permanent regression functions. The original implementations
failed the corresponding test-first checks. Focused verification includes the
complete crypto/gRPC, backing and WebSocket package suites, daemon capacity
tests and related journal durability regressions. The final workspace, complete
ignored release gates and exact-revision Linux/Windows CI are recorded
separately; focused checks do not establish those outcomes or physical
power-loss qualification.

The preceding Linux CI was blocked by the RustSec audit of `quinn-proto`
0.11.17. The lockfile now selects its fixed 0.11.18 patch while retaining other
dependency choices. The local dependency audit and pinned erasure contract pass;
the audit remains enabled in CI.

## Functional follow-up: metadata retries and endpoint validation

The eight findings below were reproduced against `fbbdbb4`. The fixes preserve
the on-disk formats, wire messages and public endpoint validator API.

| Finding | Correction | Permanent regression |
|---|---|---|
| BUG-066, preserved metadata length | Reassert the exact validated preserved A/B file length before rewriting its bytes and syncing it, then update the other copy. A failed preservation step leaves the other copy untouched. | maki-format `review_ab_length_retry.rs`; maki-core `review_catalog_length_retry.rs`: shrinking/empty/same-size/growing metadata, failed length change, partial target write, restart, v2/v3 and preservation of earlier FUA data |
| BUG-067, uncharged validation RPCs | Wrap each validation capabilities/encrypt/decrypt call in the same global and endpoint admission as serving calls. Hold only one peer's permits per RPC and narrow probe batches to count and resident-byte capacity. | maki-crypto `review_endpoint_validation.rs`: independent global/local/count/byte limits, single-slot cross-test progress, large advertised batches and ordinary serving controls |
| BUG-068, reference failure attribution | Preserve the reference peer and operation stage before cross-test error conversion. Its contract/fatal/context errors defer candidate validation; candidate errors and actual cross-key failures remain conclusive. | Same validation suite: malformed reference encrypt/decrypt, later reference recovery, malformed candidate and different-key candidate |
| BUG-069, nested metadata ENOSPC | Map storage-full I/O nested in a format error to ENOSPC at the NBD boundary. Keep other I/O and semantic format errors as EIO. | maki-nbdkit `review_metadata_enospc.rs`: public pwrite forcing checkpoint, metadata write/resize/sync failures, slot control, successful retry and generation exhaustion |
| BUG-070, protected benchmark reuse | Detect and open an existing validated volume before creation. Require explicit destruction authorization, reuse its identity/witness and retain normal attach geometry, capacity and key checks. | maki-benchmark `review_rollback_reuse.rs`: actual CLI, UUID/witness preservation, refusal and invalid/partial layouts; maki-nbdkit `review_rollback_capacity.rs`: actual mTLS identity/data preservation and session release |
| BUG-071, UUID spelling | Validate both filesystem UUID shapes and compare hex case independently. | maki-privileged `review_filesystem_uuid.rs`: configuration/full mount identity, both case directions and malformed/different/missing controls |
| BUG-072, validation task lifetime | Retain validation task handles in the dispatcher and abort them on final owner drop; cancellation guards return validation state and RPC permits. | Validation suite: final dispatcher drop, cancelled waiting caller, live-set validation ownership and capacity return |
| BUG-073, cross-pass failover metric | Track the previous actually called endpoint across retry passes and count peer identity changes. | maki-crypto `review_failover_metrics.rs`: later-pass recovery, same-pass failover and same-peer retry |

There are 49 new permanent regression functions. The test-first runs produced
25 expected-behavior failures and 18 passing controls before implementation;
the final focused suites pass. These include 39 A/B/catalog durability tests,
the complete crypto suite (215 passing tests), the complete privileged suite
(195 passing tests), benchmark tests and real mTLS daemon controls. Final
workspace, complete ignored release gates and exact-revision Linux/Windows CI
are recorded separately.

Reference responses with valid shape but wrong plaintext contents remain an
ambiguous cross-endpoint round-trip mismatch; the reference-error correction
above covers the reproduced contract and explicit-error attribution paths.
The storage regressions use the executable crash model, rather than physical
power-loss qualification.

## Functional follow-up: journal progress and operational bounds

The six findings below were reproduced against local `main` at `7551a54`.
Their corrections retain the existing on-disk formats and 64 KiB control
framing. Each fix has permanent regressions that failed before implementation.

| Finding | Correction | Permanent regression |
|---|---|---|
| BUG-074, journal minimum progress budget | Include repeated segment headers and the retained active segment when validating room for the largest request after reclaim. Share checked append accounting with the writer. | maki-format and maki-core `review_journal_progress.rs`: exact boundary, many rolls, retained large records and maximum-request FUA/readback |
| BUG-075, aggregate endpoint output | Validate an aggregate endpoint report budget, including escaped names and repeated metrics. Refuse an oversized backend response explicitly before writing it. | maki-format `review_endpoint_control_budget.rs`; maki-control `review_response_bound.rs`: cardinality, escaped names, exact framing boundaries and subsequent commands on the same connection |
| BUG-076, stale mapping proof after growth | With a stored mapping proof, refuse unqualified partition-PV or layered growth layouts before either LV or filesystem mutation. Preserve exact mapping identity checks, legacy checks and qualified whole-device growth. | maki-privileged `review_growth_topology.rs`: partition refusal, unchanged whole-device mapping, already-extended retry and foreign-mapping controls |
| BUG-077, truncated exponential backoff | Grow the jitter cap with checked wide arithmetic until the actual maximum delay is reached. Sample over the complete capped duration. | maki-crypto `review_jitter_progress.rs`: attempts 31/32, extreme attempts, zero delays and the full Duration range |
| BUG-078, omitted unsafe contract refusal | Count the contract-error branch that refuses retransmission, without sending to another endpoint. | maki-crypto `review_contract_refusal_metrics.rs`: single/multiple peers, safe failover and request/provider-error controls |
| BUG-079, transient queue length underflow | Publish a pushed item's occupancy under the same queue lock that removes it. Keep notification and permit release outside that critical section. | maki-crypto `review_queue_accounting.rs`: concurrent FIFO transfers with occupancy observation, capacity reuse and serial controls |

The growth tests use the original executor with a simulated system and sysfs;
they do not establish new LVM/kernel or partition-PV qualification. The queue
finding concerns the public library's occupancy API; current volume paths do
not use that queue. Focused test results, full workspace and complete ignored
release gates, main push and exact-revision Linux/Windows CI are recorded
separately.

There are 42 new permanent regression functions. Test-first runs produced
18 expected-behavior failures and 15 passing controls before implementation.
Focused verification passes all new cases, 44 journal-related tests, the
complete crypto suite (229 passing tests), control suite (33 passing tests)
and privileged suite (201 passing tests), plus admitted endpoint snapshot
controls. Strict Clippy passes for the affected packages on Rust 1.94.0.

Repeated witness observations remain a measured optimization candidate
(PERF-003). These fixes preserve the existing authority freshness checks.

## Functional follow-up: attach retries and ready endpoint admission

The four findings below were reproduced against `0cc3539`. Each correction has
permanent test-first regressions and preserves the on-disk formats.

| Finding | Correction | Permanent regression |
|---|---|---|
| BUG-085, readable but unsynced key canary | Verify the existing key binding, then restore both canary copies and their directory entries before attach succeeds. Reject a wrong key before publication. | maki-core `review_canary_retry.rs`: first publication and retry sync failures, process restart followed by power loss, FUA readback, wrong-key refusal and authenticated fallback |
| BUG-086, unsent request waiting for endpoint readiness | Keep the caller's admission position while eligible peers are OPEN or probe-saturated. Wake on cooldown or capacity return without consuming a retry pass before the first RPC. Keep a peer eligible if a concurrent caller takes its probe slot before dispatch. | maki-crypto `review_endpoint_readiness.rs`: OPEN cooldown, successful/cancelled probe, waiting caller cancellation, deadline and actual failed-RPC retry control |
| BUG-087, duplicate HTTP media type | Add the JSON default only when no explicit Content-Type header is configured, ignoring header-name case. | maki-crypto-http `review_content_type.rs`: actual loopback HTTP, standard/vendor media types, single/batch encrypt/decrypt and raw/default controls |
| BUG-088, occupied automatic NBD choice | Choose the lowest unused device after checking connection state, root/partition holders and direct mounts. Keep the final executor recheck and refuse incomplete observations. | maki-privileged `allocation_tests.rs`: synthetic sysfs/mountinfo, occupied lower devices, numeric order, missing/malformed/bounded observations and existing explicit-device refusal controls |

There are 32 new permanent regression functions. Test-first runs produced 19
expected-behavior failures and 10 passing controls before implementation.
Focused suites pass for canary attach, crypto, HTTP and privileged operations,
including strict Clippy for the changed packages. Complete workspace checks,
ignored release gates and exact-revision Linux/Windows CI are recorded
separately. The canary tests use the executable crash model, and NBD allocation
tests use observation fixtures; neither constitutes physical power-loss or
kernel NBD/LVM campaign qualification.

## Project review (2026-10-14)

A static review of the whole tree at `b268798` covered the engine, journal and
recovery, formats and backing, rollback protection, the crypto layer and
remote transports, nbdkit and control, the privileged helper and packaging,
and the documentation and CI. Each correction below landed test-first in its
own pull request; the RED evidence is in each commit message. No on-disk
format changed. The findings that need a design decision, or were not yet
taken on, are listed after the table.

| Finding | Correction | Permanent regression | PR |
|---|---|---|---|
| TEST-003, nightly gates stopped at the first failing binary | The unfiltered `-- --ignored` run compiled the etcd quorum gate, which refuses to skip without `MAKI_ETCD_BIN`; without `--no-fail-fast` every gate after it silently did not run. The gate is behind the opt-in `etcd-qualification` feature and the nightly run uses `--no-fail-fast` | `scripts/test_ci_gate_validation.py` | #1 |
| BUG-089, spurious ENOSPC after an inline reclaim | `durable >= appended` did not prove nothing more could be reclaimed: a concurrent FUA is durable but newer than the checkpoint horizon. Refuse only when the checkpoint covers every appended record, or on the last round | maki-core `review_r4_overlay_bound.rs`: concurrent FUA during inline reclaim, volatile control | #2 |
| BUG-090, deep check passed without checking | A failed second superblock read returned an error-free report. I/O now fails the check; any other failure is reported | maki-core `review_check.rs`: the fast phase's reads succeed and the deep check's own read fails | #5 |
| BUG-091, non-canonical segment and shard names | `seg-000000000000000A` parsed as segment 10 and was scanned under one name but replayed and reclaimed under another. Names must round-trip through `layout`; the fast checker uses recovery's shard parser and reports adoption accurately | maki-format `review_format.rs`; maki-core `review_check.rs` | #5 |
| BUG-092, transport limits sized for plaintext | gRPC messages, WebSocket frames and batched HTTP responses carry ciphertext. Each limit must hold the larger of the plaintext and the ciphertext batch (base64 where encoded); zero WebSocket and gRPC timeouts are refused | maki-format `review_config.rs`: gRPC, WebSocket, batched HTTP and timeouts | #4 |
| BUG-093, HTTP mappings counted fields never sent | Context binding counted `fields` of a raw body and `item_fields` of a per-item body, and a raw body with `items_path` counted as a batch. Both use `BodyConfig::is_batch` | maki-format `review_r3b_config.rs` | #4 |
| BUG-094, endpoint-fatal answers charged like transient ones | A revoked credential or missing route kept its circuit closed for `failure_threshold` answers. `EndpointFatal` opens it at once; no-resend for non-retry-safe requests is unchanged | maki-crypto `review_r5_endpoint_attribution.rs`, with a retryable control | #3 |
| BUG-095, XTS key with identical halves | IEEE 1619 requires distinct data and tweak keys; a doubled 32-byte key loaded silently. It is refused like a wrong-length key | maki-crypto-local `phase2.rs` | #3 |
| BUG-096, root `blkid` read a mount source as an option | A stacked FUSE mount chooses the mountinfo source (`fsname=-c/etc/shadow`). Only absolute paths are probed, after `--` | maki-privileged `exec_tests.rs` | #6 |
| BUG-097, gRPC CA unusable with an empty host store | tonic refuses an empty native store even with a CA. Native roots are requested only when present or when no CA is configured; a CA still adds to the host roots | maki-crypto-grpc `review_custom_ca_trust.rs` (own binary: it empties the store through `SSL_CERT_FILE`/`SSL_CERT_DIR`) | #8 |
| BUG-098, panics across nbdkit callbacks; failed requests unlogged | Every working callback runs behind a panic boundary that fails it with EIO; failed requests are logged as rate-limited `WARN` lines without payload | maki-nbdkit `plugin.rs` unit tests | #9 |
| Build: tokio `test-util` in production builds | The pausable clock is requested only as a dev-dependency | `scripts/test_dependency_features_validation.py` | #7 |

### Second pass (same day)

Six further reviewers covered the engine write paths, nbdkit and control,
the crypto scheduler, the witness and rollback client, the test tooling and
the packaging. Each correction below is test-first in its own pull request.

| Finding | Correction | Permanent regression | PR |
|---|---|---|---|
| BUG-099, control bind replaced any file | `control.socket` is configurable and the daemon owns the backing root; binding renamed the socket over whatever was there (`superblock.a`). Only a dead socket is reclaimed | maki-control `review_socket_ownership.rs`: regular file and symlink at the address | #11 |
| BUG-100, superblock published before the catalog | A crash between them left a root that looked initialized but could not attach. The superblock is written last, after every other file and dirent is durable | maki-format `review_init_crash.rs`: every cut point, then power loss | #12 |
| BUG-101, failing checkpoint retried on every write | Each write above the watermark woke the worker, which reran the failing checkpoint under the exclusive lock. A failure waits one interval | maki-core `review_checkpoint_backoff.rs` (ManualClock, counting failpoint) | #13 |
| BUG-102, one unit twice in a coalesced call | Two versions of a unit are interchangeable to every per-position check; a provider answering by unit index gave both callers one plaintext. A batch never carries a unit twice | maki-crypto `review_scheduler_duplicate_units.rs` | #14 |
| BUG-103, a transient witness outage stopped the session | A read-only Inspect that could not reach the witness stopped the session for good; only a final answer does now, and an outage refuses each operation without fallback | maki-backing `remote_rollback.rs`: outage then recovery, takeover during an outage | #15 |
| BUG-104, witness slots taken before TLS | Idle unauthenticated sockets held every worker. Workers are taken after authentication; pending handshakes are bounded and the oldest is cut off | maki-witness `transport.rs`: idle sockets, then a real client | #16 |
| BUG-105, plaintext echo accepted per call | Only the self-test looked, and only for an exact echo. Every encrypt result that carries its plaintext anywhere (exact, behind a nonce, before a tag, or both) is a contract violation of that call | maki-crypto `review_plaintext_echo.rs`: exact, tag, nonce and nonce‖plaintext‖tag framing; late echo; self-test | #17 |
| BUG-106, reserve refusal woke no checkpoint | Between the worker's low-space trigger and the admission requirement every write was ENOSPC until the interval. A refusal wakes the worker | maki-core `review_reserve_refusal_reclaims.rs` | #18 |
| BUG-107, remote claim before checking the root | A witness address naming another volume's authority raised its fence or revoked its writer before failing. The current manifest is authenticated in this root first | maki-backing `remote_rollback.rs`: two independent fixtures | #20 |
| TEST-004, crash model mixed names and inodes | A durable entry without synced data vanished; a re-created name showed the unlinked inode's bytes; rename over a file restored the old target or lost it. Inodes and names are separate and a rename is atomic | maki-test-support `review_crash_posix.rs` | #21 |
| TEST-005, sweeps accepted superseded failed writes | A failed write's data stayed acceptable after a newer write was acknowledged or durable. Live and post-crash views retire it separately | maki-core `review_r3b_durability.rs` oracle self-test | #21 |
| BUG-108, control commands needed the root-owned configuration | They read and fully validated it, so a `maki-admin` member could not reach the socket and an edited configuration blocked `drain`. `--socket` names the socket; a configuration is only parsed | `bins/maki` `review_control_cli_access.rs` against a fake daemon | #22 |
| Docs: stop waits ended early | `systemctl is-active` fails for `deactivating` and `failed`; the guides poll `ActiveState` and stop on failure | `scripts/test_docs_lifecycle_validation.py` | #19 |

### Third pass (same day)

Five reviewers covered the privileged helper, journal and recovery, the
remote transports, every unsafe block, and configuration, key and credential
handling; the earlier lists' remaining concrete items were taken on too.

| Finding | Correction | Permanent regression | PR |
|---|---|---|---|
| BUG-109, superblock flags and crypto format version ignored | Unknown flags or a format version other than 1 are refused, so a later incompatible format is never read with these rules | maki-format `review_superblock_fields.rs` | #23 |
| BUG-110, `maki-check --deep` wrote into a non-volume | The deep phase took the volume lock (creating `volume.lock`) after the fast check found no superblock; a rollback-protected root was reported as corrupt | `bins/maki-check` `review_deep.rs` | #24 |
| TEST-006, no power-loss sweep issued TRIM | Writes and unit-aligned trims, flushes, checkpoints, power loss or restart, against the reference model, with a 400-seed release gate | maki-core `review_trim_power_loss.rs` | #25 |
| BUG-111, witness `serve` exited on EMFILE | Accept errors are transient: pause and keep accepting, as the control socket does | maki-witness `accept_exhaustion.rs` (own binary) | #26 |
| BUG-112, no `--help`/`--version` | Help exits 0 on stdout; `--version` prints the package version | `bins/maki` `review_cli_help.rs`, maki-check e2e | #27 |
| BUG-113, configuration errors echoed secrets | TOML errors rendered the source line and their Debug the whole document; URL errors printed userinfo and query. Errors now give line, column and field, never a value | maki-format `review_config_secret_echo.rs` | #28 |
| BUG-114, any `CRYPT-` device counted as encrypted swap | Integrity-only, verity and helper devices carry the prefix too; only encrypting cryptsetup types count | maki-nbdkit `security_swap_tests.rs` | #29 |
| BUG-115, gRPC TLS handshake without a deadline | `connect_lazy` bounds only the TCP connect; a silent TLS peer pinned the channel. The connect timeout now covers TLS | maki-crypto-grpc `review_tls_handshake_deadline.rs` | #30 |
| BUG-116, `grow --size-bytes +N` | A leading `+` parsed as an absolute size; plain digits only, and a multiple of 512 bytes, which LVM requires | `bins/maki-attach` `review_strict_arguments.rs` | #31 |
| BUG-117, WebSocket frames outside the contract dropped | Non-JSON, id-less and binary frames now fail the generation as a contract error instead of timing out | maki-crypto-websocket `review_unmatched_frames.rs` | #32 |
| BUG-118, attach over existing submounts | A mount below the mountpoint is refused before connecting, as the verify gate does | maki-privileged `exec_tests.rs`, `detach_tests.rs` | #33 |
| BUG-119, key open errors all "not a regular file" | Permission and symlink errors say so | maki-crypto-local `review_keysource.rs` | #34 |
| BUG-120, lossy nbdkit config path | A non-UTF-8 `config=` value is refused instead of rewritten | maki-nbdkit `plugin.rs` unit test | #35 |
| TEST-007, racy page-lock test | A unit test compared the process-global lock-failure counter while other tests allocated buffers; on Windows each counts. The rule is checked directly | maki-crypto `secret.rs` unit test | #36 |
| TEST-008, flaky witness transport tests | Fixture clients had 500 ms (and 2 s) deadlines for calls expected to succeed; loaded runners timed out loopback connects. Fixture clients allow 5 s (10 s); expiry tests keep their own short deadlines | maki-witness `transport.rs`, `session_erasure.rs` | #37 |

### Fourth pass (2026-10-15)

The fourth pass took two items off the open list (BUG-121, BUG-122) and ran
five new reviews: the crypto self-test, grow and the benchmark, the operator
documentation, engine concurrency, and discard.

| Finding | Correction | Permanent regression | PR |
|---|---|---|---|
| BUG-121, truncated gRPC response retried | A response that ended inside a message, or an OK status with no message, reached the caller as tonic's local `Internal` (Retryable), so `stall` retried a broken endpoint forever. The bounded body checks message boundaries at the trailers and at the end of the stream; a remote status is unchanged | maki-crypto-grpc `review_truncated_response.rs` (raw h2 server), with a remote `UNAVAILABLE` control | #38 |
| BUG-122, relative secret and TLS paths | A `file` credential and TLS `ca_file`/`client_cert_file` resolved against each process's working directory (`/` under systemd). They must be absolute, like every other path | maki-format `review_secret_paths.rs` | #39 |
| BUG-123, idle checkpoint failed on a failed punch | Hole punching is a hint, but the idle path returned its error, so `maki drain`, `maki checkpoint` and shutdown failed on a v3 volume whose punches failed. It logs and marks the scan stalled; the next checkpoint or attach retries | maki-core `review_discard_reclaim_retry.rs` | #40 |
| Docs: operator procedures | `maki status` has no overlay fields (metrics do); a full backing reaches the filesystem as EIO and XFS shuts down; the daemon start limit and `systemctl reset-failed 'maki*@<volume>.*'`; the instance naming contract; quiesce before witness takeover or restore, and `chown` the namespace they create as root | `check_docs_links.py` | #41 |
| BUG-124, shard descriptors | Every cataloged shard keeps its data file open and systemd's soft limit is 1024, so about a thousand shards failed attach, reported as "data file missing" corruption. Openers raise the soft limit to the hard limit; only an absent file is corruption | maki-core `review_shard_open_errors.rs`; maki-backing `review_open_file_limit.rs` | #42 |
| BUG-125, panic under the volume lock | The async lock does not poison: after a storage task panicked mid-mutation the engine kept serving and acknowledging. The write guard latches the engine failed while unwinding, and every request fails until the volume is attached again | maki-core `review_engine_panic.rs` | #43 |

### Open after this pass

These findings were confirmed by reading the code but are not corrected yet.
The first group needs a design decision.

- **Volume isolation on a shared host.** Every `maki@` instance runs as the
  same `maki` user, and the plugin accepts any client on its NBD socket, so a
  compromised daemon for one volume can open another volume's socket
  (SPEC §5). Options: a user per volume or `DynamicUser=`, a peer-credential
  check, and `InaccessiblePaths=` for other volumes.
- **Read-only commands claim a remote writer.** `maki volume inspect`, `maki
  check` and the benchmark's existence probe open a remote-witness root
  through `open_remote`: they claim a fence, copy the namespace and release
  it in `Drop`, which an interrupted command skips. A tested design choice
  (`review_rollback_capacity.rs`); a read-only open would avoid both.
- **Root helper `PATH`.** Child commands search `/usr/local/sbin` and
  `/usr/local/bin` first, which the documented source-built `nbd-client`
  relies on; absolute tool paths would remove the shadowing risk.
- **Privileged lifecycle.** One global attach lock is held across fsyncs that
  cannot be interrupted, and `nbd-client` has no `-timeout`; a failed or
  timed-out `maki-attach@` start runs no cleanup (no `ExecStopPost=` or
  `OnFailure=`); the stop path refuses when the configuration was edited while
  attached; detach, recovery and grow address LVM by VG name without
  `--devices`/`--select` scoping; they also match device-mapper mappings by
  VG name only, so another daemon's metadata naming this volume's VG can be
  autoactivated on its NBD device and block this volume. A workload-owned
  FUSE mount at or below the mountpoint blocks detach, cleanup and recovery,
  and detach resolves the mountpoint path again for `umount`/`xfs_growfs`.
  `maki@` has no `TimeoutStopSec`: a final
  checkpoint longer than 90 s is killed, and `OnFailure` recovery then
  restarts the lifecycle the operator stopped. The guides drain before the
  unmount, which XFS then performs against a closed device, and key rotation
  stops the attach unit, which takes the daemon with it before the drain.
- **Settings validated but not applied.** `cache.lock_memory = false` does
  not stop cache entries from being page-locked under `secure-buffers`, and
  `memory_lock_mode = "off"` requires it even with the cache off;
  `crypto.max_operation_time` is ignored under the `stall` policy;
  `nbd.socket` and `nbd.connections` are not read at runtime; the attach
  `device_block_size` is never compared with `nbd.minimum_io`. Refusing them
  would reject configurations that attach today.
- **Remote transports.** A gRPC channel keeps reusing a dead HTTP/2 connection
  after an RPC deadline (retire it as the WebSocket provider does); WebSocket
  connects are serialized behind one lock with an unbounded wait; mTLS private
  key PEM copies are not wiped; HTTP formats credential templates with
  `str::replace`; the guarded response JSON tree has no node budget; HTTP and
  gRPC accept a CA file that holds no certificate. A frontend's own etcd
  401/403 reaches clients as a final denial, so they do not fail over.
  WebSocket has no TCP keepalive and no idle check before reusing a
  connection. Query-string literals (R5-007) pass validation.
- **Dependency advisories.** RUSTSEC-2026-0346 to 0349 (2026-10-14) affect
  the vendored, erasure-patched `rustls` 0.23.45 and fail the Linux CI audit
  step, which runs before the tests. 0.23.46 fixes them; re-vendoring it
  means re-applying the erasure patch (one hunk in `common_state.rs` moved)
  and refreshing `vendor/upstream.json`, `patches.json` and the fixture
  provenance.
- **Provider self-test.** There is no nonce or keystream reuse probe. Context
  probes accept a changed plaintext as proof even when integrity is claimed,
  where SPEC §18 reads as requiring a rejection. The unit-index probe moves
  index 0 to 1, so a provider that keeps only 32 bits passes, which matters
  above 2^32 units; probing high bits would refuse such a provider on small
  volumes too. With the random-prefix wrapper the compatibility-id probe is
  answered by the wrapper's own refusal. No configuration pins the volume
  UUID, so a whole backing can be swapped for another volume under the same
  key.
- **Engine and recovery robustness.** A stuck reclamation window blocks
  every later one, and a full checkpoint resets the scan cursor; the fast
  `maki check` passes a v3 orphan shard with no discard maps; the truncated
  shard damage count includes discarded units. The checkpoint snapshot pins
  superseded ciphertext the overlay bound does not count; the monitoring
  free-space sample is refreshed only by write admission. A stopped engine
  (BUG-125) waits for an operator restart instead of exiting for the
  packaged recovery unit. A failed journal directory sync can
  leave an idle volume degraded; bounded replay stores the allocation maps
  after every 1 MiB batch; the first write after attach re-stores both map
  copies of every shard under the exclusive lock. On a filesystem without
  native `fallocate`, glibc's `posix_fallocate` emulation writes zero bytes
  into a slot a running checkpoint may be writing. Bounded replay saves no
  progress, so a recovery longer than `TimeoutStartSec` restarts from the old
  checkpoint every time; every attach rewrites and syncs the whole accepted
  journal, not only the final segment's unproven tail; recovery fails on I/O
  to the advisory durable mark. Per-buffer `mlock` fragments the address
  space and a failed `munlock` is ignored.
- **Witness service.** A restored authority is not detected although the
  backing holds newer fences; online `maki volume gc` aborts while the writer
  advances; one bad endpoint certificate defeats etcd and frontend failover.
- **Benchmark.** Every write of an offset carries the same bytes, so read
  verification cannot detect a stale version; reads in the timed window can
  come from the overlay, and a checkpoint can land in it; `nbd.threads` is
  ignored; `--seed` shifts one address stream by one operation instead of
  choosing an independent one.
- **Test tooling.** A directory sync also makes the directory's own entry
  durable; the HTTP chaos server merges
  repeated headers; the fuzz targets omit `DurableProof`, the witness decoders
  and the privileged mountinfo parsers.

Later update (2026-11-17): the guarded response JSON tree now keeps only the
values the response mapping reads (AUD-024,
[#157](https://github.com/seo-rii/maki/pull/157)).

## Boundary review follow-up (2026-10-15)

See the [PR, regression, commit and remaining-boundary map](review-boundaries-2026-10-15.md).
Open-PR evidence is separate from remote-main integration and release qualification.


## Ownership, recovery resources and operational follow-up (2026-10-19)

The review of `44d60ea` identified F01–F09 in package shutdown guidance,
volume identity, encrypted response cleanup/work, transport error and
cancellation ownership, recovery memory, native listener identity and durable
slot reservations. The [follow-up record](review-followup-2026-10-19.md)
tracks each fix's failing regression and post-fix evidence, with explicit
limits on the unexecuted host campaigns. F10–F15 remain an operational design
and qualification backlog; I01–I27 and T01–T56 are mapped there without being
reported as completed. Production qualification remains Pending.

## Additional reproduced boundaries (2026-10-19)

The additional audit used `b679b80`, whose source tree is identical to the
PR #82 merge `42e725a`. These five fixes preserve the on-disk format and do
not extend production qualification. Each has an executed failing regression
before implementation; passing observation tests from the audit were converted
to expected-behavior regressions for this change.

| Finding | Change | Regression and limits |
|---|---|---|
| BUG-134: rejected first-write reservations invisible to TRIM | A zero-only v3 TRIM marks existing unwritten slots in the discard bitmap and queues bounded checkpoint reclamation. No shard or journal record is created. Overlay versions and freshness checks still protect live reservations. | `review_failed_reservations.rs`: actual allocated-block release through Volume and Engine, TRIM after restart, both bitmap publications and directory-sync failure, failed punch retry, and later rewrite. Core unit tests cover overlapping checkpoint publication and revoked writers. Four additional reservation regressions failed before the fix. Physical power-loss qualification is separate; v2 does not gain TRIM. |
| BUG-135: gRPC TLS identity failures reported retryable | Preserve a safe typed connection-failure category and report TLS authentication/protocol errors as EndpointFatal; reset and timeout remain Retryable. | `review_grpc_tls_classification.rs`: wrong hostname and unknown CA failed before the fix; the server's TLS alert distinguishes both from socket errors. Reset is a passing control. Error text cannot spoof the classifier or expose the original URL. |
| BUG-136: inaccessible export tail | Require configured and stored export sizes to be multiples of the effective NBD minimum I/O size. Invalid creation refuses before backing files are created. | `review_export_alignment.rs`: config, creation and existing-volume attach regressions failed before the fix; aligned 512-byte and 4096-byte settings retain whole-export access. Actual new kernel attachment is not claimed. |
| BUG-137: extra unary gRPC response silently discarded | Reject bytes after the first complete unary response message, including partial second headers, before tonic can drain and ignore them. | `review_grpc_unary_cardinality.rs`: the original two-message regression failed; fragmented and partial-header cases reject, while singleton and remote-status controls preserve their contract. No data-loss or unbounded-memory claim. |
| BUG-138: daemon accepts names the helper rejects | Reject a leading `-` during configuration validation, preserving the helper's argument checks. | `review_volume_name_bound.rs` and `review_volume_name_helper.rs`: expected rejection failed before the fix; safe names and the existing 64-byte boundary remain valid. |

The targeted Linux storage suites, complete gRPC crate, and NBD/configuration
regressions passed after implementation. The pull request records final
workspace, strict lint, release-gate and platform-CI results against its code
revision. No installed systemd/LVM operation, physical power cut or long soak
is implied by these repository tests.

## BUG-153: admitted queue time and batch waiting (2026-10-23)

This change records when each group enters the admitted scheduler queue and
retains that time through dispatch-slot waits and incompatible-group carryover.
Coalescing uses the oldest live group's original `max_wait` deadline; cancelling
that group selects the surviving group's deadline. Queue admission waits remain
outside the coalescing window, and dispatch capacity still bounds concurrency.
The eleven ManualClock cases in
[`review_scheduler_queue_wait.rs`](../crates/maki-crypto/tests/review_scheduler_queue_wait.rs)
cover both lanes, expired and partly elapsed windows, a 180 ms operation budget,
context/unit incompatibility, cancellation, admission, and full/zero-wait/fresh
batch controls. Before this change, seven cases failed and four controls passed;
all eleven pass with the change. This is branch-local regression evidence;
integration and release qualification are separate.

## Mountinfo path whitespace (BUG-164, 2026-10-24)

Mount observation, detach, recovery and NBD allocation now split mountinfo
fields only at ASCII spaces. Unicode whitespace and unescaped control bytes
inside kernel path fields remain part of the path; the existing octal escapes
for spaces, tabs, newlines and backslashes still decode normally.

`maki-privileged/tests/regression_mountinfo_fields.rs` reproduces the missing
mount observation for accepted Unicode paths and covers source fields and
existing escapes. Fixture tests cover detach, nested mounts, recovery and
allocation. These are parser and simulated-sysfs regressions, not a new
privileged NBD/LVM/XFS qualification campaign.

## BUG-155 — validation launcher exits before its descendants (2026-10-23)

The GCP and Firecracker controllers retain their launcher PID until process-group
cleanup. Exit probes use `waitid(WNOWAIT)`, and normal SSH waits terminate the
owned group before reaping its leader. `close()` also cleans descendants after
an early launcher exit and never signals a group after its leader was reaped.

`scripts/test_validation_process_cleanup_validation.py` covers both controllers
with local launcher/descendant processes, including EOF, normal SSH waits,
pre-reset and crash checks, repeated cleanup, and preserved exit status. These
tests require no cloud resources, guest images, or devices; external GCE and
Firecracker qualification is unchanged.

## BUG-156 — test enumeration exceeds the campaign deadline (2026-10-23)

Storage-repeat preparation uses the remaining campaign budget for every build
and test-list invocation, checks the deadline around binary freezing, and starts
no further child after expiry or cancellation. A preparation timeout records
`incomplete`; an explicit stop retains `cancelled`. Per-child caps remain
1,800 seconds for builds and 30 seconds for enumeration.

The `bug156` regressions in `scripts/test_storage_repeat_validation.py` advance
an injected clock across build, binary copy, and enumeration stages. They check
shared-budget exhaustion, no launch after expiry, and terminal status alongside
successful preparation and explicit-stop controls. No Rust build or external
storage campaign is needed to exercise these scheduling boundaries.

## BUG-157: fractional retry-budget credit

Retry credit uses compensated accumulation for both earning and consumption,
so ten requests earn two retries at the default `0.2` ratio (one at `0.1`).
Eligibility includes the retained rounding error instead of granting credit
within an epsilon of one token; burst clipping discards the compensation too.
The ratio is the supplied binary `f64` value, not a rounded decimal fraction:
ten credits of `0.3` or `0.7` remain below three or seven tokens respectively.
Their retained deficits survive consumption of the preceding whole tokens.
Invalid ratios supplied directly to the library disable earning while the
minimum probe rate remains independent.

`review_retry_credit.rs` reproduces the lost fractional credits and covers
interleaved spending, values below the threshold, burst clipping, zero burst,
large finite credits and invalid direct-API ratios. This records the change
and regression coverage, not remote-main integration or release qualification.

## Initial attach retry safety (BUG-166, 2026-10-24)

Multi-endpoint attach probes honor the validation provider's `retry_safe`
capability. A provider that does not permit resending receives one attempt;
retry-safe providers retain up to three. This applies to both the self-test
and the key-canary probe. A failed endpoint remains quarantined while a
validated peer can serve requests, and no final backoff runs after exhaustion.

`maki-nbdkit/tests/review_attach_retry.rs` drops HTTP response bodies after
the server receives each complete request. It reproduces duplicate unsafe
self-test and canary requests, preserves safe retries and normal dispatcher
behavior, and checks the healthy peer's roundtrip. This is local transport
regression evidence; it does not establish external-provider qualification.

## BUG-158: return exhausted retry results before backoff

The endpoint dispatcher checks the completed pass against `max_attempts`
before scheduling backoff. A failed final pass returns its last provider
error immediately; peers within the pass still receive failover attempts.
Backoff remains between permitted passes, including the unlimited policy,
and the operation deadline still bounds in-flight RPCs.

`review_final_backoff.rs` reproduces the extra final sleep for encrypt,
decrypt, multiple peers and an exhausted pass with no admissible peer. It
also covers zero attempts, success, unlimited retries and operation deadlines.
This records the change and regression coverage, not remote-main integration
or release qualification.

## Scheduler deadline metrics (BUG-154, 2026-10-23)

The scheduler counts each encrypt/decrypt caller that receives an operation
deadline error, including expiry before dispatch. The control metric selects
this caller counter when batching is enabled and retains the dispatcher
counter otherwise; the two counters are never added. Coalesced callers each
contribute once, while ordinary errors and cancellation contribute nothing.

`maki-nbdkit/tests/review_deadline_metrics.rs` exercises both lanes, admission,
coalescing, batch-slot and RPC waits, inner-timer propagation, direct dispatch,
and cancellation/success/error controls with `ManualClock`. Five cases failed
before the change. This branch's tests are separate from main integration and
release qualification.

## Endpoint port preflight (BUG-165, 2026-10-24)

Shared HTTP, WebSocket and gRPC configuration validation rejects nondecimal
and out-of-range endpoint ports. HTTP provider construction also parses its
actual endpoint URL, including direct construction and a `from_config` URL
override, so these errors surface before the first request.

`maki-format/tests/review_config.rs` calls semantic configuration validation
and covers IPv4, bracketed IPv6 and port boundaries. HTTP's
`review_endpoint_ports.rs` exercises both constructors and a real loopback
roundtrip with path and query composition. Empty/default ports, zero and
65535 retain their existing URL-parser behavior. No new dependency or
production-provider qualification is introduced.

## Reachable transport batch capacity (BUG-162, 2026-10-23)

The gRPC and WebSocket configuration bounds use the number of provider units
that can fit both the item and plaintext-byte ceilings. They retain the
maximum ciphertext size, protobuf/JSON framing, and attach probe overhead,
without requiring a transport to carry an unreachable raw byte ceiling.
For example, one 4096-byte unit with a 4384-byte maximum ciphertext fits a
16 KiB transport cap even when `batch.max_bytes` is 1 MiB.

Permanent transport regressions validate that configuration and exercise
maximum-size ciphertext roundtrips plus provider self-tests over real local
connections. They retain larger-batch rejection and byte-limit controls.
The older full-batch configuration regression now selects enough items to
make its large byte budget reachable. This describes the change and its
local regression coverage; remote CI and main integration remain separate.

## GCE configuration BOM compatibility (BUG-172, 2026-10-26)

The guest's provider check accepts one leading UTF-8 BOM, matching Maki's
Rust TOML parser. The provider-evidence check added in PR #114 previously
rejected such an otherwise valid configuration before starting nbdkit.
Strict UTF-8 decoding, TOML validation, provider matching and value-free
error diagnostics remain in place.

`scripts.test_gcp_provider_validation` uses a complete local-provider
configuration with and without a BOM through the guest's actual `main()`
for both reset profiles and write/verify-only boots. All four BOM subcases
failed before the fix; the plain-input controls passed. The suite also
checks malformed UTF-8/TOML, a different provider, repeated or misplaced
BOMs and a BOM inside the provider value. VM, NBD and process boundaries
are mocked; these tests do not perform an external reset campaign.

## Attach configuration diagnostics (BUG-168, 2026-10-26)

Attach configuration parsing retained `toml::de::Error`, whose renderings can
include rejected values, unknown field names, and the input document. An
accidentally pasted credential could therefore reach helper stderr even when
the configuration was rejected. Parsing now retains only a fixed error
classification and its line/column, following the volume parser's existing
policy. The original parser error is neither stored nor exposed as a source.
Accepted attach settings and request validation are unchanged.

`review_attach_config_diagnostics.rs` in `maki-privileged` covers type,
unknown-field, syntax, and nested-schema failures through `Display`, `Debug`,
and the error source chain, plus location and successful-parse controls. The
same-named `maki-attach` suite exercises actual unprivileged `--plan` processes
and a valid plan. The regressions failed before the change. These tests do not
perform mount, LVM, NBD, service, or physical qualification operations, and
the privileged crate gains no crypto dependency.


## Provider URL Debug redaction (BUG-174, 2026-10-28)

Public HTTP and gRPC specifications retained credential-bearing URL components
in their Debug output after the earlier header, query-field and metadata
redaction. HTTP's provider Debug also printed its endpoint URL, and operation
paths could contain the same path or query tokens. The observed boundary is
an API consumer formatting these objects; this does not establish an automatic
daemon or CLI log leak.

HTTP `HttpProviderSpec`, `HttpCryptoProvider` and `OpSpec`, and gRPC
`GrpcProviderSpec`, now render complete endpoint URLs and operation/method paths
as `<redacted>`. Masking the entire field covers invalid, not-yet-validated
values as well as userinfo, path, query and fragment tokens. Field names,
methods, header/metadata names, capabilities, limits and the existing TLS
redaction remain available for diagnostics. Request composition and stored
configuration values are unaffected.

The HTTP and gRPC `review_url_debug.rs` suites cover compact and pretty Debug,
valid and malformed endpoint values, endpoint and operation path/query tokens,
userinfo and fragments. Constructor-only gRPC coverage confirms that accepted
method paths can carry the same tokens. Controls retain existing header/query
and metadata redaction and useful nonsecret diagnostics. All credentials are
synthetic; these regressions do not make network requests.

## Secure-swap filename identity (BUG-173, 2026-10-28)

When `security.require_secure_swap_policy` is enabled, `/proc/swaps` filenames
reach the device classifier without changing their identity. Only space and
tab separate the kernel's columns; Unicode whitespace and literal vertical
tab, form feed, or carriage return remain filename characters. The four
kernel filename escapes for space, tab, newline, and backslash are decoded
once, so an escaped literal backslash cannot become a second escape.

The parser requires the complete five-column header and rows, known swap
types, numeric counters and priority, and an absolute filename without NUL.
Malformed rows fail before any classification; diagnostics report the row
number without repeating its contents. Device-identity and independent-backing
checks are unchanged, and the optional policy still defaults to disabled.

`review_swap_filename_identity.rs` covers full path preservation, rejection of
a different safe prefix, escaped safe devices, one-pass decoding, malformed
headers/rows/escapes, and numeric type boundaries. Ten assertions failed before
the fix while three controls passed. The tests use synthetic inventories and
classifiers and do not change host swap, device nodes, or security policy.

## gRPC proxy error pages (BUG-175, 2026-10-30)

A gRPC endpoint behind an HTTP/2 proxy (nginx `grpc_pass`, an ingress)
answers an upstream restart with an HTTP error page: `:status 502`,
`content-type: text/html`, an HTML body and no `grpc-status`. The receive
framing wrapper of BUG-057/121 framed that body, read `<` as a compression
flag and reported a receive contract violation. `Contract` is `ProviderFatal`
class, so a transient outage failed every request at once under the `stall`
policy and refused attach as proven misconfiguration instead of quarantining
the endpoint; an auth proxy's 401/403 page did not open the breaker either.
Tonic itself maps the HTTP status only when such a body ends without framing.
HTTP and WebSocket already classified 5xx by status.

A non-200 response without `grpc-status` now maps through gRPC's
HTTP-to-status table before its body is read: 429/502/503/504 `Unavailable`
(Retryable), 401 `Unauthenticated` and 403 `PermissionDenied`
(EndpointFatal), 404 `Unimplemented` (EndpointFatal), 400 `Internal`, others
`Unknown`. A trailers-only error with its own `grpc-status` keeps that status,
and an HTTP 200 response whose body is not gRPC framing remains a contract
violation (R5-005).

`maki-crypto-grpc/tests/review_http_status_mapping.rs` serves HTML error pages
and empty error responses for seven statuses from a raw HTTP/2 server. Before
the fix the first HTML page (502) was `Contract`; the empty-body cases and the
HTTP 200 control passed. The tests use loopback sockets only.

## Remote witness transient state reads (BUG-176, 2026-10-30)

The local remote-witness authority (`StateStore`) re-reads its published
state before every request. Any failure of that read poisoned the open
handle for good, including errors that prove nothing about the file: EMFILE
from a flood of unauthenticated connections pending TLS, ENOMEM, a transient
EIO. Nothing had been written and the in-memory state was still the durably
published one, yet every later request answered "reopen required" until the
witness was restarted, so every volume using it refused reads, writes and
FLUSHes long after the cause was gone.

Only proof of an external change poisons now: bytes that differ from the
published state, or a missing, short or undecodable file (`NotFound`,
`UnexpectedEof`, `InvalidData`). Other read failures refuse only their
request; the next request reads and compares again. A failed publication
still poisons, as before. `maki-witness serve` also raises its open-file soft
limit toward the hard limit, as BUG-124 did for the daemon and CLIs.

Later update (2026-11-17): AUD-092
([#189](https://github.com/seo-rii/maki/pull/189)) narrows the publication
rule. A failure before the rename (opening, writing or syncing `remote.next`)
leaves the published state unchanged and refuses only its request; a failed
rename or directory sync still poisons until a reopen.

`maki-backing/tests/remote_witness.rs` injects a failure into opening and into
reading the state file; before the fix the following inspect answered "reopen
required". A removed-then-restored state file stays poisoned, alongside the
existing corrupt-file and publication-failure tests. The tests use private
temporary directories.

## Readiness review follow-up (2026-11-13)

This change integrates the existing gRPC HTTP-status fix (PR #125) and remote
StateStore read-error fix (PR #126), then closes the corresponding local
witness recovery gap. A failed local freshness read now rejects that operation
without poisoning either FileWitness or its parent RollbackBacking. Missing,
truncated, corrupt or mismatched anchors and uncertain publications still stop
the session. A real, isolated EMFILE regression restores descriptors and uses
the existing handles to read, write and sync, then reopens to verify durability.

The first-volume guide now owns one fail-closed bootstrap script, linked from
Quickstart. It rejects occupied NBD/VG/LV names, checks size and unique backend
identity, verifies the live device-mapper UUID and backing device immediately
before formatting, and invokes mkfs.xfs without force. Mocked execution of the
actual documentation block checks failures without formatting real storage.

SlotStore now remembers reservations whose allocation and sync_all succeeded
in the current open session. TRIM punching invalidates the affected ranges
before the operation, including partial failures; reopening starts with no
reservation knowledge. The 256-unit, 4 KiB counting regression observes 256
allocation/sync calls initially and zero additional calls for overwrites after
checkpoint. It verifies flushed data after simulated power loss and ENOSPC.
The cost is one extra in-memory bit per loaded shard slot, with no disk-format
change. New-slot reservation batching and device throughput measurement remain
follow-up work; these counts do not establish an MB/s improvement.

Both affected lockfiles use rustix 1.1.6 for RUSTSEC-2026-0486. CI audits all
root/vendor lockfiles in an independent job, retaining --deny warnings, so an
advisory cannot prevent the baseline job's tests from running. Required-check
selection remains a repository branch-protection setting. The release guides
pin the Rust 1.94.0 baseline, identify the missing nbd-client build provenance,
and require installation/upgrade/restore evidence from the exact candidate
artifacts. README now states the remote provider's plaintext and cryptographic
trust boundary. These changes do not qualify or publish a production release.

The gRPC regression also drives a real loopback HTTP/2 peer through an outage
and recovery using EndpointSet's stall policy: encryption and decryption stay
pending through 502 HTML pages and complete after valid gRPC responses return.
It models an intermediary's wire behavior; it is not a deployed nginx, kernel
NBD, filesystem or database qualification run.

Validation also exposed a native-test fixture assumption when the latest-stable
CI job advanced to Rust/Cargo 1.100. Cargo now places the test executable and
cdylib in separate unit directories, and does not include cdylibs in its dynamic
Rust-library search path. The workspace test runner captures the exact nbdkit
plugin filename from Cargo's compiler-artifact JSON for the same no-run test
build, then supplies it to the test invocation. The fixture refuses a missing
or malformed explicit path; older adjacent `deps` layouts remain supported.
The production plugin is unchanged. The tungstenite lockfile's recorded hash in
`vendor/patches.json` is updated along with the security dependency resolution
and checked by the actual vendor source inventory gate.

## Rollback arena read availability (BUG-185, 2026-11-14)

A transient EIO while reading a rollback arena page stopped the entire open
session, even after storage recovered. The failed read changed neither the
witness nor the referenced page. Ordinary I/O errors now refuse only that
operation and preserve their original error; the next operation checks the
witness and authenticates the page again. Missing, truncated or invalid pages,
hash mismatches, failed arena writes and uncertain commits still stop every
handle until reopen. Local and remote rollback modes share this page path.

`maki-backing/src/rollback/arena_read_tests.rs` covers existing-handle and
freshness recovery, original errno preservation, unchanged witness state,
retry after a multi-page write prefix, damaged or truncated evidence that
remains rejected after restoration, and partial writes that still require
reopen. The maintained tests use an injected memory arena and private witness
files; the original reproduction used a real local arena with one failed
positional read. Neither test is a physical power-loss qualification.

## Remote restore target identity (BUG-187, 2026-11-14)

An administrator-approved snapshot and authority from volume A could be restored
into volume B's configured backing root. The new A namespace then satisfied GC's
current-generation check, allowing automatic GC to delete B's quiescent data.
Restore now checks the target's immutable enrollment identity and capacity before
claiming the authority. A matching binding permits repair of damaged current
data; an older root without that file must authenticate its exact current
generation instead. Corrupt or mismatched bindings never fall back to the backup.
GC independently checks an existing root binding against the authenticated
current generation before any reclamation, preserving legacy roots, abandoned
fork cleanup and partially removed tombstones.

`review_remote_restore_identity.rs` covers foreign identity and capacity refusal
without authority or data changes, source identity refusal, damaged-current
restoration, and missing/corrupt enrollment boundaries. `remote_gc.rs` covers
foreign/corrupt bindings despite a valid current manifest and successful partial
tombstone cleanup under a matching binding. The tests use private file-backed
roots and test authorities; they do not qualify a deployed witness or a physical
power-loss scenario.

## GCP one-shot command cleanup (BUG-196, 2026-11-16)

The final offline check uses `bounded_run()` rather than the guest session's
`RemoteProcess`. Its timeout previously killed only the gcloud launcher, leaving
an SSH child alive. One-shot commands now own a local process group and keep the
leader waitable until group cleanup, including normal and failed leader exits.
Output is collected within the existing combined 1 MiB limit; timeout, output
errors and interruption also clean the owned group before reaping the leader.

`scripts/test_gcp_command_cleanup_validation.py` covers descendants with closed
or inherited pipes, successful/nonzero/signal exits, timeout, interruption, read
errors and output limits, while preserving byte output and stderr diagnostics.
These are owned local-process tests. They do not establish termination of remote
guest commands or descendants that deliberately leave the local process group.
