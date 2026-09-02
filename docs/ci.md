# Continuous Integration and Release Qualification

This document separates automated repository checks from manual qualification
on dedicated Linux and hardware runners. Passing a lower tier does not imply
that a higher tier is complete. Requirements originate in [SPEC §55–56](../SPEC.md).

The executable workflow is [`.github/workflows/ci.yml`](../.github/workflows/ci.yml).
Weekly and release tiers below describe qualification policy; they are not
currently implemented as GitHub Actions jobs.

## Qualification tiers

| Tier | Trigger | Platform | Enforcement | Implementation |
|---|---|---|---|---|
| Baseline | Pull request, push to `main`/`master`, or scheduled run | Ubuntu and Windows | Formatting, Clippy, and workspace tests block | Automated: `pr` job |
| Nightly | Daily schedule at 03:00 UTC | Ubuntu | Phase gates and plugin checks block the job | Automated: `nightly-gates` job |
| Weekly Linux | Maintainer-run | Dedicated Linux host | Policy-defined qualification | Manual; runner automation pending |
| Release | Before a release | Dedicated VM and physical hardware | All release gates required | Manual; runner automation pending |

## Automated checks

### Baseline (`pr` job)

| Check | Command | Enforcement |
|---|---|---|
| Formatting | `cargo fmt --all --check` | Blocking |
| Clippy | `cargo clippy --workspace --all-targets -- -D warnings` | Blocking |
| Workspace suite | `cargo test --workspace` | Blocking |

The workspace suite includes unit and integration tests, property and crash
smokes, codec/parser mutation smokes, local and loopback transport tests,
failpoint coverage, privilege-plan tests, NBD adapter tests, database
simulation, and simulated power-loss scenarios.

### Nightly schedule

The scheduled Linux job runs these ignored release-mode gates:

| Gate | Workload |
|---|---|
| `phase0_gate_full` | 10,000 seeds x 60 model operations |
| `phase3_gate_full` | 10,000 seeds x 60 mixed operations, including randomized crash/recovery |
| `phase4_gate_full` | 110,000 randomized model operations |
| `phase5_gate_endpoint_cycles_full` | 10,000 deterministic endpoint-failure cycles through the dispatcher |
| `phase5_gate_breaker_cycles_full` | 10,000 complete circuit-breaker lifecycles |
| `phase11_gate_dbsim_full` | 500 runs x 40 transactions |
| `phase12_gate_full` | 500 critical-sequence + 500 FUA simulated power-loss cycles |

It also builds the Linux `maki-nbdkit` cdylib and asserts that the dynamic
symbol table exports `plugin_init`.

## Manual qualification tiers

### Weekly Linux qualification

The intended weekly run on a dedicated Linux host covers:

- the SQLite and PostgreSQL subsets from [Phase 11](phase-11.md);
- online growth through `maki-attach grow` and `xfs_growfs` under load;
- credential rotation and the TLS suite against rotated certificates; and
- a 24-hour provider workload with resource and retry monitoring.

### Release hardware qualification

The release tier adds:

- every automated phase gate;
- at least 300 QEMU hard-power-loss cycles from [Phase 12](phase-12.md);
- the bare-metal durability runbook;
- a 72-hour mixed workload; and
- upgrade and recovery runbook rehearsal.

These checks require isolated targets and explicit authorization because they
include privileged block-device access or disruptive power operations.

## Run checks locally

Use the locked dependency graph for reproducible Rust checks on Linux,
Windows, or macOS:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --release --locked -- --ignored
```

On Linux with GNU binutils, also build and inspect the nbdkit plugin:

```bash
cargo build --release --locked -p maki-nbdkit
nm -D --defined-only target/release/libmaki_nbdkit.so |
  grep -Eq '[[:space:]]T[[:space:]]plugin_init$'
```

The ignored suite is intentionally more expensive than the default workspace
suite. It uses simulated backing stores; it does not perform a real power cut.

## Release-gate status

| Requirement | Threshold | Status | Evidence | Last verified |
|---|---:|---|---|---|
| Randomized model operations | 100,000+ | **Pass** | 110,000-operation Phase 4 gate | 2026-09-02 |
| Process crash/recovery | 10,000+ | **Partial** | In-process backing simulation: 10,000 seeds x 60 mixed operations; no process-level count | 2026-09-02 |
| Endpoint failure cycles | 10,000+ | **Pass (simulation)** | 10,000 deterministic dispatcher cycles; zero failed requests or permit leaks | 2026-09-02 |
| Circuit-breaker cycles | 10,000+ | **Pass (simulation)** | 10,000 open/half-open/closed lifecycles, including failed-probe reopen | 2026-09-02 |
| QEMU hard power loss | 300+ | **Pending** | Simulation: 500+500 cycles; no QEMU evidence | 2026-09-02 |
| Parser fuzzing | 24 CPU-hours/target | **Partial** | 4,000 decoder + 1,500 config mutation inputs; cargo-fuzz pending | 2026-09-02 |
| Mixed workload | 72 hours | **Pending** | Dedicated hardware run not recorded | — |

At revision
[`8f8b13d56539ae02ea29fcf6959a3f910f16acb4`](https://github.com/seo-rii/maki/commit/8f8b13d56539ae02ea29fcf6959a3f910f16acb4),
the executed workspace, extended simulation, formatter, strict Clippy, ABI,
and userspace nbdkit/libnbd/fio checks passed. They reported no silent
corruption, FLUSH/FUA, plaintext-leak, queue-bound, semaphore, privilege,
checksum, or lint violations. This statement does not cover unexecuted manual,
kernel-device, service, or hardware tiers.

## Validation reports

| Date | Revision | Environment | Outcome | Report |
|---|---|---|---|---|
| 2026-09-02 | `8f8b13d` | Debian 12, KVM guest | Partial; functional, quality, ABI, and userspace NBD checks pass; privileged and hardware gates open | [Linux validation report](native-linux-validation-2026-09-02.md) |

## Planned CI work

- Wire cargo-fuzz targets and a maintained corpus into an extended runner.
- Add dedicated weekly Linux and release-hardware automation.
- Provide supported vendor-contract and duration-based soak invocations.
