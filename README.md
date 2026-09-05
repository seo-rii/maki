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
| 2026-09-02 external review (18 findings) | All addressed with regression tests; see [Review remediation log](docs/review-remediation.md) for scope and residual external validation |
| 2026-09-03 sanitizer and randomized-suite pass | Debug-build invariant checkers plus fuzz, stress, corruption, and model suites; five findings (S-01 data read as zeros after an A/B fallback, S-02 overlay accounting, S-03 stale durable mark, S-04/S-05 recovery under out-of-order sector persistence) fixed with regression tests; see the [remediation log](docs/review-remediation.md#sanitizers-and-randomized-suites-2026-09-03) |
| 2026-09-03 second audit (core, crypto, operations) | 27 confirmed findings fixed with regression tests, among them recovery accepting never-synced page-cache bytes after a process restart, HTTP redirects re-sending plaintext, the root helper following symlinks in the mount root, and detach disconnecting the wrong NBD device; see the [remediation log](docs/review-remediation.md#second-audit-2026-09-03-core-crypto-layer-operational-layers) |

The [2026-09-05 review](docs/project-review-2026-09-05.md) identified nine further
issues in A/B retries, request lifetimes, credentials, and deployment boundaries.
All nine have TDD fixes; the [remediation log](docs/review-remediation.md#follow-up-review-2026-09-05)
records the evidence. The updated helper requires a new runtime layout and NBD
backend identity support; follow the [upgrade procedure](docs/operations.md#upgrading-the-runtime-layout)
and qualify it on the target host before deployment.

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
