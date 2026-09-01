# Maki — development guide

Maki is a crash-consistent, bounded, privilege-separated encrypted block-storage layer (NBD via nbdkit). `SPEC.md` is the authoritative specification; `docs/phase-N.md` records what each phase built, its gate results, and any deferred Linux/hardware checklist.

## Ground rules

- **TDD is mandatory** (SPEC §41): failing tests land before implementation; bug fixes start with a reproducing regression test. Phase gates live as `#[ignore]`d tests named `phase*_gate_full`.
- **Durability invariants are non-negotiable** (SPEC §12): plaintext never persisted; FLUSH/FUA-acknowledged data survives any crash; `checkpoint_sequence ≤ durable_sequence`; corrupted ciphertext ⇒ EIO, never data; allocated-but-invalid slots ⇒ EIO, never zeros.
- **Secrets**: plaintext and keys travel in `SecretBuffer` (zeroize-on-drop, no `Clone`, redacted Debug). Never log payloads; never put literals in configs (SPEC §9). `maki-privileged` must never gain a dependency on any crypto crate (PRIV-010 by construction).
- **Providers are untrusted**: results go through `CheckedProvider`/validators; unprovable capabilities are `Absent` (SPEC §16).

## Commands

```
cargo test --workspace                                  # PR suite (~1 min)
cargo test --workspace --release -- --ignored           # phase gates
cargo test -p maki-core --test phase3 -- --nocapture    # one phase
```

Failpoint-using tests must hold `failpoints::test_lock()` (failpoints are process-global). Timing-sensitive async code uses the injectable `Clock` (`ManualClock` in tests) — never real sleeps.

## Map

| Crate | Contents |
|---|---|
| `maki-test-support` | executable spec: `ReferenceBlockModel` (durability oracle), `CrashableBacking` (POSIX-faithful crash sim + fault hook), `FakeCryptoProvider`, `ManualClock`, `DeterministicScheduler`, failpoints, HTTP chaos server |
| `maki-backing` | escape-proof `Backing` trait; `FileBacking` (real FS), `MemBacking` |
| `maki-format` | geometry, superblock, A/B protocol, slot/allocation/catalog/journal codecs (all CRC, panic-free, golden-frozen), TOML config schema |
| `maki-crypto` | `CryptoProvider` trait, `SecretBuffer`, error classes, `CheckedProvider`, self-tests + conformance suite, flow control (`DualSemaphore`, `BoundedQueue`), retry/budget/breaker, `EndpointSet` dispatcher, `Batcher` |
| `maki-crypto-local` / `-http` / `-websocket` / `-grpc` | providers; all pass `provider_conformance` |
| `maki-core` | `JournalWriter`, `Overlay` (latest + latest-durable per unit), `SlotStore`, checkpoint, recovery, `Engine` (RMW, per-unit locks, cache, admission) |
| `maki-cache` | versioned plaintext LRU, key `(unit, write_sequence)` |
| `maki-nbdkit` | blocking `NbdAdapter` (panic boundary), daemon assembly from config, Linux `plugin.rs` C shim |
| `maki-control` / `maki-privileged` | control socket (no privileged verbs); attach/detach/grow plans + mount guard (no crypto deps) |
| `bins/` | `maki`, `maki-attach`, `maki-check`, `maki-benchmark` |

## Traps that already bit us (don't re-learn)

- crc32 of a self-checksummed image is a constant — golden vectors hash the payload *excluding* the trailing CRC (`docs/phase-1.md`).
- Checkpointing the newest overlay version loses a unit whose newest write is volatile — hence the dual latest/latest-durable overlay (`docs/phase-3.md`).
- A dying websocket connection's failure sweep must be generation-scoped or it kills requests on the successor connection (`docs/phase-10.md`).
- WAL-style replay needs a flushed header/salt gating epochs — validation alone lets older transactions replay over newer durably-applied data (`docs/phase-11.md`).
- On-disk format changes require a format-version bump + new golden vectors; `tests/golden/*.crc` failing means you broke compatibility.

## What still needs a Linux/hardware host

Phase 6 nbdkit ABI + libnbd/fio verification, Phase 7 OS-enforced PRIV checks (`docs/phase-7.md` checklist), Phase 8 vendor-endpoint contract + 24 h soak, Phase 11 real-database qualification, Phase 12 QEMU/bare-metal power cuts. Each has a runbook in its phase doc.
