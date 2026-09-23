# Contributing to Maki

Thanks for helping. Maki is durability-critical code, so the rules below are
stricter than in most projects. `SPEC.md` is normative; `CLAUDE.md` is the
in-repository development guide with the traps that already bit us.

## Build and check

```bash
cargo build --workspace --locked
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --release --locked -- --ignored   # extended release gates
python3 -B scripts/check_docs_links.py                    # documentation links
```

Formatting and strict Clippy block CI. The release gates are expensive; run
them after touching recovery, journal, overlay, store or checkpoint code (the
default suite did not catch every ordering bug in the past).

Unix-only suites (control socket, `statvfs`, privileged executor, process
hardening, nbdkit ABI probe) are skipped on Windows and macOS. Run them on
Linux before claiming a change is verified. The Linux CI job installs
`nbdkit`, `nbdkit-plugin-dev` and `libnbd-bin` for the native tests.

## Test-first, always

SPEC §41 applies to every change:

- A feature starts with an invariant and a failing test, then the minimum
  implementation, then fault and property cases.
- A bug fix starts with a reproducing regression test that fails before the
  fix and stays in the tree permanently. Name it after the finding when there
  is one (`review_*.rs` files are the regression suites for external
  reviews; `docs/review-remediation.md` records each finding's status).
- Extended tests live behind `#[ignore]`; their historical `phase*_gate_full`
  names are stable identifiers.

Rules the test infrastructure imposes:

- Failpoint-using tests hold `maki_test_support::failpoints::test_lock()`
  (failpoints are process-global).
- Time-dependent code uses the injectable `Clock` (`ManualClock` in tests);
  never real sleeps.
- Crash tests use `CrashableBacking::with_tearing`, and distinguish a restart
  (`drop` + `recover`, page cache survives) from a power loss (`crash*`).
- Debug builds run `check_invariants()` after every mutation; a sanitizer
  panic is a real bug, not flakiness.

## Non-negotiable invariants

From SPEC §12: plaintext is never persisted; FLUSH/FUA-acknowledged data
survives any crash; `checkpoint_sequence ≤ durable_sequence`; corrupted
ciphertext or an allocated-but-invalid slot returns EIO, never data or zeros.
Secrets travel only in `SecretBuffer`; nothing logs payloads; configuration
never holds secret literals; `maki-privileged` must never gain a crypto
dependency; provider results always pass through `CheckedProvider`.

## On-disk format and compatibility

Any change to bytes on disk needs a format-version bump, new golden vectors
(`tests/golden/*.crc` failing means compatibility broke), a migration note in
`docs/durable-recovery.md`, and an entry in `CHANGELOG.md`. There is no
in-place upgrade between envelopes; say so wherever the change is described.

## Documentation

- `docs/status.md` is the only place that states current support. If your
  change alters what Maki supports, update it (and
  `docs/deployment/support-matrix.md`) in the same pull request.
- External campaign results go into a new dated file under
  `docs/qualification/` and a row in its README; never rewrite an existing
  report to reflect later fixes.
- Procedures belong in `docs/operations.md` or a getting-started/deployment
  page; keep them copy-pasteable and state what they do not cover.
- Run `scripts/check_docs_links.py` before pushing.

## Commits and pull requests

- Use the conventional prefixes already in the history: `feat`, `fix`,
  `test`, `docs`, `ci`, `perf`, `style`, `chore`; `feat!` for a breaking
  change. Keep one logical change per commit.
- Say in the message which test failed before the change when it is a fix.
- A pull request that touches recovery, format or privileged code should
  state which suites and gates ran, on which platform.
- Do not commit secrets, campaign credentials, or cloud resource identifiers
  beyond what a report needs for reproducibility.

## Security

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions are licensed under the
Apache License 2.0 ([LICENSE](LICENSE)).
