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
| 4 | Block core | ⏳ |
| 5 | Backpressure, retry, HA | ⏳ |
| 6 | nbdkit adapter | ⏳ |
| 7 | Daemon and privilege model | ⏳ |
| 8 | HTTP remote provider | ⏳ |
| 9 | WebSocket and gRPC | ⏳ |
| 10 | Cache and operations | ⏳ |
| 11 | Database qualification | ⏳ |
| 12 | Power-loss qualification | ⏳ |

## Workspace layout

Matches SPEC §11: engine crates under `crates/`, binaries under `bins/`
(`maki`, `maki-attach`, `maki-check`, `maki-benchmark`), deployment assets
under `packaging/`.

## Development

Test-driven throughout (SPEC §41): every phase lands its failing tests first,
then the implementation, then fault/property cases. Run everything with:

```
cargo test --workspace            # PR-level suite
cargo test --workspace --release -- --ignored   # phase gates (long)
```

Development on Windows/macOS is supported for all pure-logic crates; the
nbdkit data path, privilege separation, and qualification phases require
Linux (see per-phase docs).
