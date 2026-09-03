# Maki development guide

Maki is a crash-consistent, bounded, privilege-separated encrypted block-storage
layer exposed through nbdkit. `SPEC.md` is normative. Start with
`docs/architecture.md`, `docs/configuration.md`, `docs/operations.md`, and
`docs/testing.md` for maintained project documentation.

## Ground rules

- **TDD is mandatory** (SPEC §41): failing tests land before implementation; bug fixes start with a reproducing regression test. Extended gates live as `#[ignore]`d tests; their historical `phase*_gate_full` names remain stable test identifiers.
- **Durability invariants are non-negotiable** (SPEC §12): plaintext never persisted; FLUSH/FUA-acknowledged data survives any crash; `checkpoint_sequence ≤ durable_sequence`; corrupted ciphertext ⇒ EIO, never data; allocated-but-invalid slots ⇒ EIO, never zeros.
- **Secrets**: plaintext and keys travel in `SecretBuffer` (zeroize-on-drop, no `Clone`, redacted Debug). Never log payloads; never put literals in configs (SPEC §9). `maki-privileged` must never gain a dependency on any crypto crate (PRIV-010 by construction).
- **Providers are untrusted**: results go through `CheckedProvider`/validators; unprovable capabilities are `Absent` (SPEC §16).

## Commands

```bash
cargo test --workspace --locked
cargo test --workspace --release --locked -- --ignored
cargo test -p maki-core --locked --test phase3 -- --nocapture
```

Unix-only suites (control socket, `statvfs`, privileged executor, process
hardening) are skipped on Windows; run them on Linux (CI, or WSL from this
machine) before claiming a change is verified. `review_*.rs` test files are
the regression suites for the 2026-09-02 external review; their scope and the
status of every finding live in `docs/review-remediation.md`.

Failpoint-using tests must hold `failpoints::test_lock()` (failpoints are process-global). Timing-sensitive async code uses the injectable `Clock` (`ManualClock` in tests) — never real sleeps.

## Map

| Crate | Contents |
|---|---|
| `maki-test-support` | executable spec: `ReferenceBlockModel` (durability oracle), `CrashableBacking` (POSIX-faithful crash sim + fault hook), `FakeCryptoProvider`, `ManualClock`, `DeterministicScheduler`, failpoints, HTTP chaos server |
| `maki-backing` | escape-proof `Backing` trait; `FileBacking` (real FS), `MemBacking` |
| `maki-format` | geometry, superblock, A/B protocol, slot/allocation/catalog/journal codecs (all CRC, panic-free, golden-frozen), TOML config schema |
| `maki-crypto` | `CryptoProvider` trait, `SecretBuffer`, error classes, `CheckedProvider`, self-tests + conformance suite, flow control (`DualSemaphore`, `BoundedQueue`), retry/budget/breaker, `EndpointSet` dispatcher (retry-safe aware, deadlines, quarantine), `BatchScheduler` (cross-request coalescing, bounded lanes) |
| `maki-crypto-local` / `-http` / `-websocket` / `-grpc` | providers; all pass `provider_conformance` |
| `maki-core` | `JournalWriter`, `Overlay` (latest + latest-durable per unit), `SlotStore`, checkpoint, recovery, `Engine` (RMW, per-unit locks, cache, admission) |
| `maki-cache` | versioned plaintext LRU, key `(unit, write_sequence)` |
| `maki-nbdkit` | blocking `NbdAdapter` (panic boundary), daemon assembly from config, Linux `plugin.rs` C shim |
| `maki-control` / `maki-privileged` | control socket (bound by the daemon, chgrp'd, no privileged verbs); attach/detach/grow plans with rollback, root-owned attach config + argument hygiene, pure mount/sysfs probes, Linux executor (no crypto deps) |
| `bins/` | `maki`, `maki-attach`, `maki-check`, `maki-benchmark` |

## Traps that already bit us (don't re-learn)

- crc32 of a self-checksummed image is a constant; golden vectors hash the payload excluding the trailing CRC ([architecture](docs/architecture.md)).
- Checkpointing the newest overlay version can lose a unit whose newest write is volatile; keep latest and latest-durable versions separately ([architecture](docs/architecture.md)).
- A dying WebSocket connection must only fail requests from its own generation ([architecture](docs/architecture.md)).
- WAL-style replay needs a flushed header or salt to gate epochs ([testing](docs/testing.md)).
- On-disk format changes require a format-version bump + new golden vectors; `tests/golden/*.crc` failing means you broke compatibility.
- An automatic journal roll advances `durable_sequence` *inside* `append`; always promote the overlay before publishing a newer version of the same unit, or a checkpoint can delete the only copy of a durable write ([remediation log](docs/review-remediation.md), M-002).
- Clear a persistence dirty flag only after the directory fsync that makes the new file durable; clearing earlier lets a retry skip the step (M-003).
- Unsynced journal records persist in any order: a valid record after damaged bytes does not prove the damage is durable. Classify with the durable mark, never by what follows (M-007). The mark is a plain write and is often lost in the crash itself; with no mark for the final segment only its header is proven, so everything beyond is a torn tail (S-04). Recovery must leave the final segment ending exactly at its last record: a surviving zero tail becomes "corruption" once the segment is sealed as non-final (S-05). Crash tests must use `CrashableBacking::with_tearing`, which tears *any* unsynced write.
- An A/B record falling back to its older generation is *normal* (torn write, later damage), and the older allocation map / shard catalog does not list the newest slots or shard. Slot headers are authoritative: probe them instead of reading "bit 0" as zeros ([remediation log](docs/review-remediation.md), S-01).
- Debug builds run `check_invariants()` on the overlay, journal, and volume after every mutation; a sanitizer panic in a test is a real accounting bug, not a flaky test. Keep the checks O(1)-ish on large structures (they sample).
- Journal segment indexes are never reused: the durable mark outlives the segment it names, so numbering continues above the mark even when a checkpoint has deleted every segment (S-03). Run the release gates (`-- --ignored`) after touching recovery; the default suite did not catch this.

## External qualification

Kernel NBD/filesystem checks, OS-enforced privilege checks, vendor endpoint
qualification, real databases, and disruptive power-loss testing require
dedicated Linux or hardware environments. Follow `docs/testing.md`; operational
commands and safety boundaries are in `docs/operations.md`.
