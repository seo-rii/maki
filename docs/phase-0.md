# Phase 0 — Executable Specification

Status: **complete** · Gate: **passed** (10,000 randomized sequences, 0 durability-oracle violations)

## What was built (SPEC §42)

| Component | Location | Purpose |
|---|---|---|
| `ReferenceBlockModel` | `maki-test-support/src/model.rs` | The durability oracle. Tracks durable content plus every acknowledged-unflushed version per crypto unit; after a crash the observed value must be in the allowed set (`crash_adopt`). FUA and FLUSH collapse the allowed set to exactly the new value. |
| `CrashableBacking` | `maki-test-support/src/crash_backing.rs` | In-memory `maki_backing::Backing` with POSIX-faithful crash semantics: unsynced writes independently kept/lost, torn tail writes (`crash_keep_torn_prefix`, `with_tearing`), unsynced dirents vanish (orphan inode), unsynced deletions resurrect. Fault hook for ENOSPC/EIO injection at any operation. |
| `FakeCryptoProvider` | `maki-test-support/src/fake_provider.rs` | Deterministic keystream cipher with CRC integrity + context binding (volume UUID, compat ID, unit index). Injection: queued errors, latency via `Clock`, contract `Misbehavior` (reorder/drop/duplicate/oversize/mismatched index) for validator tests. |
| `ManualClock` | `maki-test-support/src/clock.rs` | Implements `maki_crypto::Clock`; sleepers complete only on `advance`. |
| `DeterministicScheduler` | `maki-test-support/src/sched.rs` | Seeded single-thread executor; each step polls one randomly chosen task, so a seed fully reproduces an interleaving. |
| Failpoint framework | `maki-test-support/src/failpoints.rs` | Named failpoints (`hit("journal.append.pre_sync")`) with Panic / IoError / Callback actions, guard-scoped; used at every persistence boundary from Phase 3 on. |

Foundations defined alongside (needed by the fakes, owned by their real crates):

- `maki-crypto`: `CryptoProvider` trait (SPEC §15), `SecretBuffer` (zeroize-on-drop, no `Clone`, redacted `Debug`), `CryptoCapabilities` with `Capability::{Absent, Contractual, Verified}` (unprovable ⇒ Absent, SPEC §16), `CryptoError` with the five SPEC §31 classes, `Clock`/`SystemClock`.
- `maki-backing`: `Backing`/`BackingFile`/`VolumeLock` traits, escape-proof relative paths, `FileBacking` (real FS, positional I/O, `try_lock` for `VOLUME_ALREADY_ATTACHED`), `MemBacking`.

## Test-first cases (SPEC §42) → tests

All in `crates/maki-test-support/tests/phase0.rs`:

- normal write followed by crash → `normal_write_then_crash_may_be_old_or_new` (both outcomes must actually occur across seeds)
- FUA followed by crash → `fua_write_then_crash_is_durable`
- FLUSH followed by crash → `flush_then_crash_is_durable`
- partial record → `partial_record_torn_write_is_detectable` (len+CRC framing rejects torn tail)
- same-unit concurrent write → `same_unit_concurrent_writes_serialize` (100 seeded interleavings)
- allocation mismatch → `unsynced_file_creation_is_lost_after_crash` (fdatasync'd data in an unsynced dirent is lost; `sync_dir` fixes it — the hazard the allocation/catalog protocol must close)
- retry semaphore release → `retry_backoff_releases_semaphore` (permit is free while the retrier parks on `ManualClock`)

Plus: `manual_clock_sleep_requires_advance`, `fake_provider_roundtrip_and_integrity`, `oracle_rejects_impossible_content`, `sequences_are_reproducible`.

## Phase gate

```
cargo test -p maki-test-support --release phase0_gate_full -- --ignored
```

10,000 randomized sequences (8 units × 60 ops: writes/FUA/FLUSH/crash + live-view checks), **0 violations** (~2 s). A 500-sequence smoke version runs in the normal test suite.

## Notes / limitations

- `CrashableBacking.crash()` keeps each volatile op independently (p=0.5) — models out-of-order persistence. Tearing is opt-in so the unit-granularity oracle stays exact; torn-write behavior is exercised by the dedicated partial-record test and later journal tests.
- The trivial store used by the gate syncs the whole file on FUA (stronger than the model requires); the oracle checks membership, so a stronger implementation always passes.
