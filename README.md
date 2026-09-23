# Maki

Maki is a crash-consistent encrypted block-storage layer for Linux. It exposes
a standard NBD device through nbdkit, keeps only ciphertext on disk, and can
use local AES-256-GCM-SIV or a remote HTTP, WebSocket or gRPC crypto service.

```text
 database / files            root-owned helper: attach, verify, detach, grow
        │                                     │
   XFS on LVM on /dev/nbdN  ◀── nbd-client ◀──┘
        │
   nbdkit + maki plugin (unprivileged `maki` user)
        │   ciphertext journal ─ checkpoint ─ A/B metadata
   /var/lib/maki/<volume>  (local filesystem)     ⇄  crypto provider (local or remote)
```

## Why Maki

- Plaintext never reaches the backing store; keys and plaintext live in
  zeroizing, page-locked buffers.
- Every acknowledged FLUSH and FUA survives a crash: journal, mirrored
  durable proofs and checkpoint ordering are verified by an executable
  durability model, crash simulation and fault injection.
- Bounded everything: requests, queues, provider retries, circuit breakers,
  memory during recovery.
- Privilege separation: the data plane runs without root; NBD, LVM and mount
  operations run in a separate helper that has no crypto code and pins the
  storage identity it manages.
- Providers are untrusted: contracts are probed at attach and every response
  is validated.

## Status

Maki is **not production-qualified**. Its most-tested environment is Debian 12
on Google Compute Engine with one XFS data LV on one NBD device; scoped
campaigns there covered nbdkit crashes, whole-instance resets, package
upgrades, SQLite and one PostgreSQL 15 crash. Physical power loss, commercial
crypto vendors, other distributions and long soaks are open.

- [Current status](docs/status.md): the one page that states what is supported.
- [Support matrix](docs/deployment/support-matrix.md): hosts, backing stores,
  storage topologies, RAID.
- [Qualification evidence](docs/qualification/README.md): dated campaign reports.

## Installation

Debian 12 is the primary platform. The stock `nbd-client` 3.24 is too old;
3.27.0 or later is required, and the guide shows how to build the backport
and the Maki package:

- [Installing on Debian 12](docs/getting-started/installation-debian.md)

No prebuilt packages are published yet.

## Quick start

The [quick start](docs/getting-started/quickstart.md) runs one local-key volume
through the packaged systemd lifecycle and a full stop/start round trip. In
outline:

```bash
head -c 32 /dev/urandom > /etc/maki/secrets/demo.token            # key
install -m 0640 -o root -g maki demo.toml /etc/maki/volumes/demo.toml
install -d -o maki -g maki -m 0700 /var/lib/maki/demo
sudo -u maki maki volume create /etc/maki/volumes/demo.toml
# one-time: pvcreate / vgcreate / lvcreate / mkfs.xfs on the export,
# then pin the UUIDs in /etc/maki/attach/demo.toml  (docs/getting-started/first-volume.md)
systemctl start maki-workload@demo.target
maki-attach verify --volume demo && echo hello > /srv/demo/hello.txt
maki drain /etc/maki/volumes/demo.toml && systemctl stop maki-workload@demo.target
```

## Production deployment

- [PostgreSQL deployment guide](docs/deployment/postgres.md) and the matching
  file bundle in [`examples/postgres-local/`](examples/postgres-local/README.md).
- [Operations](docs/operations.md): lifecycle, control socket, recovery,
  growth, upgrades.
- [Configuration](docs/configuration.md): every section and validation rule.

## Documentation

| Audience | Start at |
|---|---|
| New users | [Getting started](docs/README.md#getting-started) |
| Operators | [Operations](docs/operations.md), [storage recovery](docs/storage-recovery.md), [key rotation](docs/key-rotation.md) |
| Architects and reviewers | [Architecture](docs/architecture.md), [technical specification](SPEC.md), [durable recovery](docs/durable-recovery.md) |
| Release and QA | [Testing and qualification](docs/testing.md), [qualification evidence](docs/qualification/README.md) |

The full index is [`docs/README.md`](docs/README.md).

## Development

The Rust workspace builds on Linux, macOS and Windows; the nbdkit plugin and
the privileged helper are Linux-only.

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --release --locked -- --ignored   # release gates
```

Development follows the test-first rules in SPEC §41; see
[CONTRIBUTING.md](CONTRIBUTING.md). Security reports: [SECURITY.md](SECURITY.md).
Format and behaviour changes: [CHANGELOG.md](CHANGELOG.md).

## Repository layout

| Path | Purpose |
|---|---|
| `crates/` | Storage engine, format, crypto providers, control plane, test support |
| `bins/` | `maki`, `maki-attach`, `maki-check`, `maki-benchmark` |
| `packaging/` | Debian package builder, systemd, sysusers, tmpfiles, provider examples |
| `examples/` | Complete deployment bundles |
| `docs/` | User, operator, reference and qualification documentation |
| `scripts/` | Validation harnesses and repository checks |

## License

Apache License 2.0; see [LICENSE](LICENSE).
