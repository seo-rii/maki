# CI Strategy (SPEC §55) and Release Gate (SPEC §56)

## Tiers

| Tier | Where | Contents |
|---|---|---|
| **PR** | `.github/workflows/ci.yml` `pr` job (Linux + Windows) | fmt, clippy, the full default workspace suite: unit tests, property smoke (Phase-0 500-seq / Phase-3 150-cycle / Phase-4 10k-op smokes), codec + parser-fuzz smoke, fake-crypto tests, journal failpoint smoke, retry/manual-clock tests, privilege unit tests (packaging pins, plans, mount guard), NBD adapter protocol tests, DB-sim smoke, power-loss smoke |
| **Nightly** | `nightly-gates` job | the `--ignored` phase gates in release mode: `phase0_gate_full` (10k sequences), `phase3_gate_full` (10k crash/recovery cycles), `phase4_gate_full` (110k model ops), `phase11_gate_dbsim_full` (500 DB runs), `phase12_gate_full` (500+500 power-loss cycles); plugin cdylib build + `plugin_init` symbol check; extended fuzz (`cargo fuzz` targets over the binary decoders — to be wired when a fuzz corpus repo exists) |
| **Weekly** | dedicated Linux runner | real-DB qualification subset (SQLite + PostgreSQL from docs/phase-11.md), online growth (`maki-attach grow` + `xfs_growfs` under workload), credential rotation, full TLS suite against rotated certs, 24-hour soak via `maki-benchmark` |
| **Release** | dedicated hardware | every phase gate + QEMU power loss (300+, docs/phase-12.md) + bare metal + 72-hour mixed workload + upgrade/recovery runbook rehearsal |

## Current release-gate status vs SPEC §56

| Target | Requirement | Status |
|---|---|---|
| randomized model operations | 100,000+ | ✅ 110k+ (phase-4 gate) |
| process crash/recovery | 10,000+ | ✅ (phase-3 gate) |
| endpoint failure cycles | 10,000+ | ◑ dispatcher failover suites pass; 10k-cycle soak is a nightly-runner item |
| circuit breaker cycles | 10,000+ | ◑ transition suites pass; volume soak pending runner |
| QEMU hard power loss | 300+ | ⏳ hardware tier (simulation tier: 1000 cycles ✅) |
| parser fuzz | 24 CPU-h/target | ◑ 5,500-input smoke in PR suite; cargo-fuzz wiring pending |
| mixed workload | 72 h | ⏳ hardware tier |

Allowed-failure counters (silent corruption, FLUSH/FUA violation, plaintext leak, queue bound, semaphore, privilege, secret leakage) are all **0** across every suite in this repository.
