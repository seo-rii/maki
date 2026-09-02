# Maki

Maki is a crash-consistent encrypted block-storage layer for Linux. It exposes
a standard NBD device through nbdkit and can use either local cryptography or a
remote HTTP, WebSocket, or gRPC crypto service.

Maki is designed around four constraints:

- plaintext is never written to the backing store;
- acknowledged FLUSH and FUA operations survive recovery;
- queues, requests, and remote-provider retries are bounded; and
- the long-running data plane runs without root privileges.

> [!WARNING]
> Maki is not yet production-qualified. The userspace nbdkit path and simulated
> durability suites pass, and one Debian kernel-NBD/XFS smoke run is recorded.
> Forced-crash, broader database, vendor-provider, and hardware power-loss
> qualification remain open.

## Features

- Crash-safe ciphertext journal, checkpointing, and A/B metadata.
- Local AES-256-GCM-SIV and AES-256-XTS providers.
- Configurable HTTP, WebSocket, and gRPC crypto transports.
- Provider contract validation, retry budgets, circuit breakers, and failover.
- Versioned plaintext read cache with zeroization on eviction.
- Offline format checking and deterministic crash simulation.
- Privilege-separated attach, detach, mount, and growth operations.

## Project status

| Area | Status |
|---|---|
| Core engine, format, recovery, and provider contracts | Implemented and covered by workspace tests |
| nbdkit ABI and userspace libnbd/fio path | Validated on Debian 12/KVM |
| HTTP transport TLS and loopback chaos handling | Validated in automated tests |
| WebSocket and gRPC transports | Implemented; TLS currently fails closed |
| Kernel `/dev/nbd`, LVM, XFS, and fio path | Validated on Debian 12/KVM; broader destructive qualification open |
| Real database and vendor-provider workloads | SQLite smoke passed; broader qualification open |
| QEMU and bare-metal power-loss testing | Not qualified |

See [Testing and qualification](docs/testing.md) for the exact evidence and
remaining release gates.

## Build

The Rust workspace builds on Linux, macOS, and Windows. The nbdkit plugin and
privileged integration require Linux.

```bash
cargo build --workspace --locked
cargo test --workspace --locked
```

To create and inspect a volume from a configuration file:

```bash
cargo run --locked -p maki -- volume create path/to/config.toml
cargo run --locked -p maki -- volume inspect path/to/config.toml
cargo run --locked -p maki -- check path/to/config.toml
```

The repository includes a production-oriented remote HTTP example at
[`packaging/examples/postgres-prod.toml`](packaging/examples/postgres-prod.toml).
Review the configuration and use a disposable backing directory before running
`volume create`.

## Documentation

| Document | Contents |
|---|---|
| [Documentation index](docs/README.md) | Entry point for users, operators, and contributors |
| [Architecture](docs/architecture.md) | Data path, durability model, provider boundary, and security model |
| [Configuration](docs/configuration.md) | Configuration sections, providers, credentials, and compatibility |
| [Operations](docs/operations.md) | Volume lifecycle, nbdkit, systemd, control socket, and recovery |
| [Testing and qualification](docs/testing.md) | CI, fault testing, database tests, power loss, and release status |
| [Privileged Linux validation](docs/privileged-linux-validation.md) | Reproducible kernel NBD, LVM, XFS, fio, privilege, and SQLite run |
| [Technical specification](SPEC.md) | Normative storage and security requirements |

## Repository layout

| Path | Purpose |
|---|---|
| `crates/` | Storage engine, format, crypto providers, control plane, and test support |
| `bins/` | `maki`, `maki-attach`, `maki-check`, and `maki-benchmark` |
| `packaging/` | systemd, sysusers, tmpfiles, and provider examples |
| `docs/` | User, operator, architecture, and qualification documentation |

## Development

Changes follow the test-first rules in SPEC §41. Formatting and strict Clippy
are blocking CI checks:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```
