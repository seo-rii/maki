# Maki

A daemonized, crash-consistent, bounded, privilege-separated Linux block-storage
layer that adapts local or remote cryptographic providers into a filesystem- and
database-compatible encrypted block device (NBD via nbdkit).

See [SPEC.md](SPEC.md) for the full technical specification and
[docs/](docs/) for per-phase implementation notes.

## Status

| Phase | Scope | Status |
|---|---|---|
| 0 | Executable specification (reference model, crash backing, fakes) | ✅ gate passed |
| 1 | Configuration and on-disk format | ✅ gate passed |
| 2 | CryptoProvider (local AES-GCM-SIV / AES-XTS) | ✅ complete |
| 3 | Journal and recovery | ✅ gate passed |
| 4 | Block core | ✅ gate passed |
| 5 | Backpressure, retry, HA | ✅ complete |
| 6 | nbdkit adapter | ◑ adapter + Linux build/symbol pass; ABI/live NBD pending |
| 7 | Daemon and privilege model | ◑ unit/packaging checks pass; live OS enforcement pending |
| 8 | HTTP remote provider | ◑ loopback chaos/TLS pass; vendor contract/soak pending |
| 9 | WebSocket and gRPC | ✅ complete |
| 10 | Cache and operations | ✅ complete |
| 11 | Database qualification | ◑ simulation tier passes; real DB pending |
| 12 | Power-loss qualification | ◑ simulation tier passes; QEMU/metal pending |

Validation evidence: [CI and release qualification](docs/ci.md) ·
[2026-09-02 Linux VM validation report](docs/native-linux-validation-2026-09-02.md)

## Workspace layout

Matches SPEC §11: engine crates under `crates/`, binaries under `bins/`
(`maki`, `maki-attach`, `maki-check`, `maki-benchmark`), deployment assets
under `packaging/`.

## Development

Test-driven throughout (SPEC §41): every phase lands its failing tests first,
then the implementation, then fault/property cases. Run the repository test
suites with:

```
cargo test --workspace            # PR-level suite
cargo test --workspace --release -- --ignored   # phase gates (long)
```

Development on Windows/macOS is supported for all pure-logic crates; the
nbdkit data path, privilege separation, and qualification phases require
Linux (see per-phase docs).
