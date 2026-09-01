# Phase 1 — Configuration and On-Disk Format

Status: **complete** · Gate: **passed** (parser panic = 0 across fuzz smoke, golden vectors frozen)

## What was built (SPEC §43), all in `maki-format`

- **Geometry** (`geometry.rs`) — SPEC §13/§14 validation and slot-size math with fully checked arithmetic. `slot_size = align_up(64 + max_ciphertext_size, slot_alignment)`; the SPEC example (64+4384 → 4608) is a test. Overflow (`u32::MAX` ciphertext, `u64::MAX`-scale virtual sizes) returns `FormatError::Overflow`, never panics or wraps.
- **Superblock** (`superblock.rs`) — fixed 4096-byte v1 image: magic, version, generation, volume UUID, full geometry, provider type, crypto compatibility ID, key identity, trailing CRC-32. Decode re-derives geometry and cross-checks the stored slot math.
- **A/B protocol** (`ab.rs`) — generic dual-copy store for any `AbRecord` (superblock, shard catalog, per-shard allocation maps). `store` bumps the generation and always overwrites the *stale* side; `load` picks the valid copy with the highest generation, so a torn write can only lose the update in progress, never the volume.
- **Slot header** (`slot.rs`) — 64-byte CRC-protected header: unit index, write sequence, ciphertext length + CRC, flags.
- **Allocation map** (`allocation.rs`) — per-shard bitmap, A/B replicated, popcount, CRC.
- **Shard catalog** (`catalog.rs`) — durable set of existing shards (absent shard ⇒ unwritten zeros, SPEC §22); strictly-ascending encoding enforced on decode.
- **Journal framing** (`journal.rs`) — 32-byte record header (magic, sequence, unit, payload len+CRC, header CRC) and segment header. `scan_segment` classifies **Clean** / **TornTail** (truncate — normal crash) / **Corrupt** (payload CRC failure *followed by a valid successor record*, or a sequence gap — recovery must fail loudly, SPEC "silent corruption = 0").
- **Config schema** (`config.rs`) — full SPEC §57 TOML schema with defaults, `deny_unknown_fields` everywhere, `ByteSize`/`MakiDuration`/`Rate` parsing, and SPEC §9 enforcement: sensitive headers (`Authorization`, `X-Api-Key`, …) must be `{ source = "credential", name = "…" }` references — literals are rejected at validation; a stray inline `token = "…"` cannot even parse.
- **Volume init** (`init.rs`) — mkfs: dirs, lock file, both superblock copies, empty catalog, directory syncs; verified to survive a lose-everything crash immediately after creation.
- **Format checker** (`checker.rs`) — offline metadata verification for `maki-check` (superblock/catalog/allocation consistency, orphaned shard files).

## Test-first coverage (`tests/phase1.rs`, 25 tests)

geometry validation · slot-size calc (SPEC example) · integer overflow · superblock A/B (fallback on corruption, torn-write of the new side) · allocation A/B · catalog A/B · torn journal tail truncation · middle-record corruption detection · sequence-gap detection · full/minimal/secret-rejecting config parsing · byte/duration parsing · volume init crash survival.

## Phase gate

- **parser panic = 0**: 4,000 mutated/garbage inputs into every binary decoder + 1,500 into the TOML parser — no panics (`binary_decoders_never_panic_on_garbage`, `config_parser_never_panics_on_garbage`).
- **golden vectors frozen**: `tests/golden/*.crc` freeze the v1 superblock, slot-header, and journal-record encodings. Note: self-checksummed images are hashed *excluding* their trailing CRC, because `crc32(data ‖ crc32_le(data))` is a constant residue (0x2144df1c) for any data — hashing the full image would freeze nothing.

## Decisions of record

- Every A/B record shares the prefix `magic[8] version[4] generation[8]` so the store can compare generations without knowing the record type.
- Allocation maps live per shard (`data/shard-XXXXXXXX.alloc.{a,b}`) next to their data file (`.dat`); layout names are centralized in `maki_format::layout`.
- Journal middle-corruption policy: torn tails truncate (crash-normal); anything before valid data is a hard `Corrupt` — consumed by Phase 3 recovery.
