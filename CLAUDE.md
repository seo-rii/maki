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
- A process restart is not a power loss: recovery reads back page-cache bytes that were never fdatasync'd. Everything recovery accepts must be fsync'd before the writer resumes, or a later FLUSH acknowledges data the next power loss removes (K-01). `CrashableBacking` models this: `drop` + `recover` is a restart, only `crash*` drops pending writes.
- An A/B side that passes its CRC but does not decode as the record type is *invalid*, not "newest": choose the side to overwrite from the typed view (O-10).
- Anything an HTTP endpoint can steer must not re-send plaintext: redirects are refused, never followed (C-01).
- A failed `fdatasync` is never retried by calling it again: Linux marks the dirty pages clean and the retry "succeeds" without writing them. The journal fingerprints the records accepted since the last sync, re-reads and rewrites them in bounded chunks, verifies the fingerprint and only then syncs (changed or lost bytes refuse the barrier); recovery rewrites and verifies every accepted segment prefix before syncing it (F01 / BUG-021). `CrashableBacking` models this by default (a failed sync loses its dirty writes but keeps them readable).
- `write_at` can persist a prefix and then fail: the file is then longer than the writer's logical end, and sealing it makes that tail "corruption". Truncate back to the logical end before appending or sealing, and keep the cleanup flag until that truncation is synced; the debug sanitizer checks the file length (F03 / BUG-020).
- `mlock`/`munlock` work on whole pages with no reference count: `SecretBuffer` counts owners per page under one lock, and only the last owner unlocks, after zeroization (F04 / BUG-006).
- The rewrite rule applies to A/B records too: before the stale side is overwritten, the preserved (typed-valid) side's exact bytes are rewritten and synced (file and directory), so the durable copy is safe before the target is touched. A failed sync of the target is *not* emptied — the preserve step already protected the durable copy, and a readable newer generation is kept for a later store to preserve in turn. This BUG-001 preserve-first rule subsumes the earlier N-09 empty-on-failure approach; do not re-add the emptying (it discards a newer generation and the two designs' tests contradict each other).
- A circuit-breaker probe must return its half-open slot on every exit, verdict or not: the dispatcher holds a `BreakerPermit` whose drop releases the slot, so a deadline or a cancelled future never wedges the circuit (N-10 / BUG-004).
- Recovery must make the checkpoint state it selects durable *before* the writer resumes: a restart can hand it a page-cache-only newer checkpoint, and reclaiming journal against it then losing power leaves an older checkpoint whose covering segment is gone ("does not bridge"). `recover` re-stores the selected state; a failed A/B store also empties its unsynced side (BUG-022).
- `grow` is not exempt from attach identity: it takes the attach lock and must match the trusted record (targets and live NBD backend identity) before any `lvextend`/`xfs_growfs`, exactly like detach — its plan carries the `AttachmentIdentity` (BUG-018).
- A clean `shutdown` must drain live control sessions, not just stop accepting: sessions run in a `JoinSet` that `serve_with_shutdown` aborts *and awaits*, or a lingering session keeps an `Engine` clone and the volume lock past a "successful" detach (BUG-015).
- A remote transport needs an overall per-RPC timeout, not only a connection timeout: a server that stalls after headers or before trailers otherwise pins its inflight slot forever. The gRPC provider wraps readiness + the unary call in one `tokio::time::timeout` (BUG-017).
- Request-side JSON pointers must RFC 6901-unescape each token (`~1`→`/`, `~0`→`~`) to match the response side's `Value::pointer`, or a vendor field named `key/slot` is sent as `key~1slot` (BUG-024).
- Every shard-catalog commit publishes the *whole* in-memory catalog, including shards adopted at open (orphan data files). An adopted shard's allocation map must be stored and dir-synced before *any* commit, not only the one in `persist_allocations`; and a map an adopted shard loaded after a plain restart may exist only in the page cache (K-01), so it is re-stored, never trusted as durable (K-03 residuals, `review_r3b_durability.rs`). The randomized sweep there (workload → power loss or restart → oracle, with random sync failures) is the fastest way to shake out ordering bugs of this kind.
- A remote provider that declares context binding must receive the whole context on the wire (volume UUID, compatibility id, format version); the self-test probes each field, and a transport or config that omits one fails attach with a "decrypts to the original plaintext" probe error (R3-006).
- An `EndpointSet` reports the *intersection* of its endpoints' capabilities, quarantined ones included; never one endpoint's own contract (R3-004).
- Per-crate builds on Windows cover the cross-platform code; the Linux-only suites (`review_abi.rs`, `review_secret.rs` smaps check, the control backlog test, the backing symlink test) need WSL, where `nbdkit-plugin-dev` is installed for the ABI probe.

## External qualification

Kernel NBD/filesystem checks, OS-enforced privilege checks, vendor endpoint
qualification, real databases, and disruptive power-loss testing require
dedicated Linux or hardware environments. Follow `docs/testing.md`; operational
commands and safety boundaries are in `docs/operations.md`.
