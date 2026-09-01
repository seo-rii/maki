# Phase 10 — Cache and Operations

Status: **complete** (stale read = 0 across all cache tests, plaintext handled exclusively in `SecretBuffer`, growth-crash tests green)

## Versioned plaintext LRU cache (`maki-cache`)

`VersionedLruCache` — SPEC §29 exactly: **read caching only**, key `(unit_index, write_sequence)`.

- **Stale-read prevention**: a lookup hits only when the caller's *current* write sequence (taken from the volume under the read snapshot) matches the cached one. A version mismatch evicts the stale entry and misses. This makes correctness independent of invalidation timing: even if a racing writer publishes between a reader's snapshot and its cache fill, the filled entry carries the old sequence and can never satisfy a later read.
- LRU eviction under a byte budget (recency-stamped), TTL expiry (injectable `Clock` → `ManualClock` tests), oversized entries never cached.
- **Runtime resize** (`set_max_bytes`, SPEC §20 hot-reloadable): shrinking evicts immediately, zero disables caching entirely; `set_ttl` too.
- **Zeroization**: plaintext lives in `SecretBuffer` (zeroize-on-drop); eviction drops the buffer immediately. No write-back, no dirty entries, no persistence.
- Hit/miss/bytes/entries stats.

## Engine integration (`maki-core`)

- `EngineOptions.cache: Option<EngineCacheConfig>` (`None` = mode off, from `[cache]` config in the daemon).
- Read path: per-unit `(seq, ct)` snapshot → cache hit skips decryption entirely (verified: second read makes zero provider calls) → misses decrypt and fill.
- Write path: eager invalidation after journal publish (space hygiene; correctness comes from the version key).
- `Engine::resize_cache` wired to `maki reload <cfg> cache` with `{"max_bytes": …}` via the control backend.
- `EngineStats` + control metrics now expose `maki_cache_hits_total`, `maki_cache_misses_total`, cache bytes/entries alongside the journal/checkpoint/overlay series (SPEC §40).

## Growth (SPEC §38, §52)

The NBD virtual capacity is fixed; block-layer growth is `lvextend + xfs_growfs` via the privileged helper (Phase 7 `plan_grow`). At the Maki level, growth = writes reaching untouched regions, creating shards on demand:

- `growth_during_workload_creates_shards_consistently` — a steady writer and a "grower" walking through 30 fresh shards concurrently; all data verified after flush + checkpoint.
- `crash_during_shard_creation_recovers` — checkpoint fails at the catalog-commit boundary, then a lose-everything crash: the FUA write into the half-created shard survives (journal is authoritative), the retried checkpoint completes, and a second crash confirms slot durability. Growth corruption = 0.

## Mount guard (SPEC §39, §52)

Implemented and tested in Phase 7 (`maki-privileged::verify`): wrong volume UUID, missing mount, wrong fstype/fs-UUID, missing sentinel, NBD down, failed rw-probe — each individually refuses, so the dependent container cannot start.

## Test suites

`maki-cache/tests/phase10_cache.rs` (10 tests: versioned behavior, TTL, LRU/byte bound, resize, zero-budget, counters, eviction-drop) · `maki-core/tests/phase10_engine.rs` (8 tests: provider-call elision, overwrite + RMW invalidation, racing read/write monotonicity with cache on, off-mode, runtime resize, growth ×2, metrics).

## Also in this phase: WebSocket reconnect race fix

The full-workspace suite exposed a race in `maki-crypto-websocket` (found via 40-iteration stress under build load): the pending-request map was shared across connection generations, so a *dying* connection's failure sweep — arriving late (e.g. WSAECONNABORTED) — could kill a request already in flight on the *successor* connection, exhausting the retry budget. Fix: pending entries are keyed with the generation they were sent on; a death sweep fails only `generation ≤ dying`; the dead-generation marker is set *before* the sweep so no interleaving can strand a waiter; registration now happens under the connection lock with the known generation.
