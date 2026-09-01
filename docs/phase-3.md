# Phase 3 — Journal and Recovery

Status: **complete** · Gate: **passed** (10,000 randomized crash/recovery cycles, silent corruption = 0)

## What was built (`maki-core`)

- **`JournalWriter`** (`journal.rs`) — one ordered writer per volume tracking `next_sequence` / `appended_sequence` / `durable_sequence` / active segment (SPEC §23). Segment-creation protocol: create → header → fdatasync → **journal-dir fsync**, completed before any record in the segment can be acknowledged — a durable record can never live in a file whose dirent might vanish. Failed rolls clean up and retry with the same index. A failed append consumes no sequence (no gaps). FUA = append + fdatasync + `durable_sequence` verification (SPEC §24); FLUSH = ordered barrier via `sync()` (SPEC §25).
- **`Overlay`** (`overlay.rs`) — per unit, the *latest* version (serves reads) **and** the latest *durable* version (what checkpoints apply). The durable copy is load-bearing: with `checkpoint_sequence = durable_sequence`, a unit whose newest write is still volatile would otherwise lose its only crash-safe copy when the covering segment is deleted. Promotion is queue-driven (sequence-ordered) as the durable boundary advances.
- **`SlotStore`** (`store.rs`) — SPEC §22 read classification (absent shard → zeros; bit 0 → zeros; bit 1 + invalid slot → EIO, never fabricated data; bit 1 + valid → ciphertext). Shard creation: data file + allocation map created, synced, dirents durable **before** the catalog commits the shard — crashes leave harmless orphans, never a cataloged shard with missing metadata.
- **Checkpoint** (`volume.rs`) — SPEC §26 order with failpoints between every step: write slots → fdatasync shards → allocation A/B + data-dir fsync → checkpoint state A/B + checkpoint-dir fsync → delete covered segments → journal-dir fsync. In-memory `checkpoint_sequence` only advances after the durable state store. Only durable journal records are consumed — `checkpoint_sequence ≤ durable_sequence` is enforced structurally (collect-durable draws from promoted overlay entries only).
- **Recovery** (`recovery.rs`) — SPEC §27 order: lock (`VOLUME_ALREADY_ATTACHED` on conflict) → superblock A/B → catalog → allocation metadata (both copies invalid ⇒ refuse) → journal scan. Torn tails are legal **only in the final segment** (older segments were synced before their successor existed) and are truncated; middle corruption, sequence gaps, foreign UUIDs, or broken cross-segment continuity ⇒ `Corrupt`, attach refused. Overlay rebuilt from records > checkpoint_sequence; resurrection of an un-fsynced segment deletion is tolerated (records are filtered by checkpoint_sequence and continuity still holds).
- **`CheckpointState`** added to `maki-format` (A/B record under `checkpoint/`).

## SPEC §45 test-first cases → tests (`tests/phase3.rs`, 16 tests + gate)

append · barrier · FUA · segment creation (`segments_roll_and_survive_crash`) · directory fsync (`segment_dirsync_failure_fails_closed`) · partial journal tail (`torn_journal_tail_is_truncated_on_recovery`) · middle-record corruption (`middle_corruption_fails_recovery_loudly`) · checkpointing (`checkpoint_moves_data_to_slots_and_deletes_segments`, `checkpoint_only_consumes_durable_records`, `crash_mid_checkpoint_at_every_boundary_recovers_consistently` — all six boundaries) · ENOSPC (append + checkpoint variants) · allocation corruption (one side falls back, both sides refuse; allocated-bit-with-invalid-slot ⇒ EIO) · double attach.

## Failpoints (all under `maki_test_support::failpoints`, feature `failpoints`)

`journal.segment.create` · `journal.segment.header_sync` · `journal.segment.dirsync` · `journal.append.write` · `journal.sync` · `store.shard_create` · `store.shard_dirsync` · `store.catalog_store` · `checkpoint.slot_write` · `checkpoint.shard_sync` · `checkpoint.alloc_store` · `checkpoint.state_store` · `checkpoint.segment_delete` · `checkpoint.dirsync`

## Phase gate

```
cargo test -p maki-core --release phase3_gate_full -- --ignored
```

10,000 seeds × 60 ops (write/FUA/FLUSH/checkpoint/crash-with-random-survival) verified against `ReferenceBlockModel` after every crash and on live reads — **0 violations** (~17 s). 150-seed smoke runs in the normal suite.

## Bugs the tests caught (kept as regression coverage)

- Checkpointing the *latest* overlay version with `ck = durable_sequence` loses a unit whose newest write is volatile — fixed by the durable-copy overlay design.
- Advancing in-memory `checkpoint_sequence` before the A/B store succeeds makes a failed checkpoint unrecoverable in-process.
- Global failpoints require serializing all tests in the binary (`failpoints::test_lock`), not just the ones that set them.
