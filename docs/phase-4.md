# Phase 4 — Block Core

Status: **complete** · Gate: **passed** (110,000 randomized I/O operations vs the reference model, mismatch = 0)

## What was built (`maki-core/src/engine.rs`)

The **Engine**: a byte-addressed, encrypted block device over the Phase-3 ciphertext volume.

- **Attach** (SPEC §27 tail): `Volume::recover` → build `CryptoContext` from the superblock (volume UUID, format version, compatibility ID) → verify the provider's contract fits the volume geometry (`max_ciphertext_size`) → run the Phase-2 `provider_self_test` (crypto profile mismatch prevents attach, SPEC §12) → wrap in `CheckedProvider`.
- **Read path**: consistent per-unit ciphertext snapshot under a shared volume lock → one chunked `decrypt_batch` → assemble bytes; unwritten units are zeros without a provider call. No unit locks — a racing read sees old or new unit content, never a mix.
- **Write path** (SPEC §23/§28): lock touched units in ascending order (deadlock-free) → RMW partial units (decrypt existing or zeros, merge) → **encrypt outside the volume lock** → append every record + publish overlay under the exclusive volume lock → FUA syncs after the whole request's records are appended (SPEC §24).
- **Batch chunking**: encrypt/decrypt calls are split to the provider's declared `batch.max_items`/`max_bytes` (SPEC §16) — found by the differential sweep hitting the fake's 128-item cap.
- Range/alignment validation (`CoreError::Invalid` ⇒ EINVAL), `EngineStats` for the metrics layer.

## SPEC §46 test-first cases → tests (`tests/phase4.rs`, 15 tests + gate)

zero read · read/write · multi-unit request (mid-unit start, 3½ units) · partial-unit RMW (merge with existing and with zeros) · concurrent writes (32 distinct units in parallel; 4 racing quarter-RMWs on one unit × 10 rounds — no lost updates) · concurrent read/write (no torn unit content observed across 200 racing reads) · FUA (`fua_write_survives_crash`) · FLUSH (`flush_makes_prior_writes_durable`) · attach guards (profile mismatch, wrong unit size) · **corrupted ciphertext with a *fixed-up* slot CRC ⇒ EIO from the provider's integrity check, never plaintext**.

## Phase gate

```
cargo test -p maki-core --release --test phase4 -- --ignored
```

51 seeds × ~2,000–10,000 ops (writes 1–8 blocks with random offsets/FUA, reads compared byte-for-byte against a plain array model, FLUSH, checkpoint) + full-device final sweeps = **110,000+ operations, 0 mismatches** (~15 s). A 10-seed smoke runs in the normal suite.

## Notes

- The volume mutex serializes journal appends (the SPEC's single ordered journal writer); encryption never happens under it.
- Unit-lock map is pruned opportunistically (entries with no waiters) once it exceeds 8192 entries.
- Blocking backing I/O currently runs inline on the async executor; nbdkit integration (Phase 6) drives the engine from worker threads, and `FileBacking` fsyncs there are acceptable. Revisit with `spawn_blocking` if profiling demands.
