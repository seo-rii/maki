# Maki documentation

Documentation is organized by what the reader is trying to do. Two rules
hold everywhere:

- [`status.md`](status.md) is the only document that states what Maki
  currently supports. Everything under [`qualification/`](qualification/README.md)
  is dated evidence and never claims current state.
- [`SPEC.md`](../SPEC.md) is normative for storage, durability, provider and
  security requirements; these pages explain and operate it.

## Getting started

| Task | Document |
|---|---|
| Install on Debian 12, including `nbd-client` 3.27+ | [Installation](getting-started/installation-debian.md) |
| Run one volume end to end and survive a restart | [Quick start](getting-started/quickstart.md) |
| Create the first LVM/XFS layout on a new export | [Provisioning the first volume](getting-started/first-volume.md) |

## Deployment

| Task | Document |
|---|---|
| Find out whether a host, backing store or topology is supported | [Support matrix](deployment/support-matrix.md) |
| Understand RAID below, across or above Maki | [RAID and Maki](deployment/raid.md) |
| Deploy PostgreSQL with the production profile | [PostgreSQL deployment guide](deployment/postgres.md), [example bundle](../examples/postgres-local/README.md) |
| Use a remote HTTP/WSS/gRPC crypto provider | [Configuration: providers](configuration.md#providers), [`postgres-prod.toml`](../packaging/examples/postgres-prod.toml) |

## Operations

| Task | Document |
|---|---|
| Volume lifecycle, nbdkit, systemd, control socket, growth, upgrades | [Operations](operations.md) |
| Clean up a disconnected attachment; helper limits | [Storage recovery](storage-recovery.md) |
| Gate a workload start on storage identity | [Repeatable attachment verification](storage-recovery.md#checking-storage-before-each-workload-start) |
| Replace credentials or move to a new key | [Credential rotation and key migration](key-rotation.md) |
| Interpret status and metrics during a stall | [Observability](observability.md) |
| Enable TRIM and space reclamation (v3) | [Discard and space reclamation](space-reclamation.md) |
| Restore or migrate a volume, legacy v1 handling | [Durable recovery and compatibility](durable-recovery.md) |

## Reference

| Topic | Document |
|---|---|
| Every configuration section and validation rule | [Configuration](configuration.md) |
| Data path, durability model, provider boundary, security model | [Architecture](architecture.md) |
| Normative requirements | [Technical specification](../SPEC.md) |
| Remote plaintext buffer lifetimes | [Transport memory](transport-memory.md) |
| Rollback-protected backing (experimental) | [Rollback protection](rollback-protection.md), [design proposal](rollback-protection-design.md) |
| Format and behaviour changes | [Changelog](../CHANGELOG.md) |

## Testing and qualification

| Topic | Document |
|---|---|
| Automated tiers, release gates, current qualification status | [Testing and qualification](testing.md) |
| Dated external campaigns, reviews and readiness records | [Qualification evidence](qualification/README.md) |
| Unattended local repetition of storage suites | [Background storage runs](background-storage-validation.md) |
| Review findings and their regression tests | [Review remediation log](review-remediation.md) |

## Contributing and policy

| Topic | Document |
|---|---|
| Build, test, TDD and documentation rules | [Contributing](../CONTRIBUTING.md) |
| Reporting a vulnerability | [Security policy](../SECURITY.md) |
| Repository-level development guide | [`CLAUDE.md`](../CLAUDE.md) |

## Layout

```text
docs/
├── status.md                 current state (authoritative)
├── getting-started/          install, quick start, first volume
├── deployment/               support matrix, RAID, PostgreSQL guide
├── *.md                      operations and reference pages
└── qualification/            dated campaign reports
    └── historical-reviews/   external and internal reviews, R3 record
```

Historical `phase*` test filenames and `phase*_gate_full` gate names remain
stable internal identifiers and do not define this structure.
