# Linux Validation Report: Debian 12 on KVM — 2026-09-02

> **Outcome:** Partial validation
>
> **Tested revision:** [`ea7448804f8f50bd00cf91ece8fe5f64fc5d7813`](https://github.com/seo-rii/maki/commit/ea7448804f8f50bd00cf91ece8fe5f64fc5d7813)
>
> **Release qualification:** Not complete

This report records the non-privileged checks that were available on a
non-WSL Linux VM. Every functional and simulation test that ran passed. Code
quality checks did not pass, and the kernel, privileged-service, vendor,
real-database, and physical power-loss qualifications remain open.

Related documentation: [CI and release qualification](ci.md) ·
[Phase 6: nbdkit adapter](phase-6.md) ·
[Phase 11: database qualification](phase-11.md) ·
[Phase 12: power-loss qualification](phase-12.md)

## Summary

| Area | Outcome | Evidence |
|---|---|---|
| Default workspace tests | **Pass** | 200 passed, 0 failed, 5 ignored |
| Extended simulation gates | **Pass** | All 5 release-mode phase gates passed |
| Linux plugin smoke test | **Partial pass** | Shared library build and symbol export passed; live nbdkit path not run |
| File-backed CLI smoke test | **Pass** | Create, inspect, check, workload, and post-workload check passed |
| Packaging inspection | **Partial pass** | Sysusers and offline security inspection ran; installed-unit verification remains open |
| Code quality | **Fail (CI-advisory)** | `cargo fmt --all --check` and strict Clippy failed at the tested revision |
| Kernel and bare-metal qualification | **Not run** | Missing tools, privilege requirements, or disruptive operation |
| Overall release qualification | **Not complete** | Phase 6 kernel and Phase 12 hardware gates remain open |

Result terms in this report are intentionally narrow:

- **Pass** means the listed command completed successfully on this host.
- **Partial pass** means only the stated portion of a larger gate ran.
- **Fail** means an executed command returned a non-zero status.
- **Not run** means no result was produced; the reason and prerequisite are
  listed below.
- **Info** is an observation, not a release-gate result.

## Scope and safety boundaries

The run used an ordinary user account and a disposable fake-provider volume.
It did not:

- use `sudo` or install system packages;
- attach, format, mount, or overwrite a block device;
- install, start, stop, or crash a system service;
- connect to a vendor endpoint or use production credentials;
- exhaust memory or run a 24/72-hour saturation workload; or
- stop a VM, interrupt host power, or operate a physical power controller.

## Test environment

| Item | Value |
|---|---|
| Date | 2026-09-02 (Asia/Seoul) |
| OS | Debian GNU/Linux 12 (bookworm) |
| Kernel | `6.1.0-52-cloud-amd64` |
| Architecture | x86_64, 8 vCPUs, 31 GiB RAM |
| CPU / virtualization | AMD EPYC 7B12; KVM guest |
| Test filesystem | ext4 |
| Rust toolchain | `rustc 1.94.0`, `cargo 1.94.0` |
| systemd | `252 (252.39-1~deb12u2)` |

The host was a KVM guest, not physical bare metal. These results therefore
provide non-WSL Linux coverage but no bare-metal durability evidence.

## Reproduce the non-privileged checks

Run these commands from the repository root at the tested revision. `--locked`
keeps dependency resolution pinned to `Cargo.lock`.

### Workspace, phase gates, plugin, and quality checks

```bash
cargo test --workspace --locked
cargo test --workspace --release --locked -- --ignored

cargo build --release --locked -p maki-nbdkit
nm -D --defined-only target/release/libmaki_nbdkit.so |
  grep -Eq '[[:space:]]T[[:space:]]plugin_init$'
readelf -h target/release/libmaki_nbdkit.so
ldd target/release/libmaki_nbdkit.so

cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

### Disposable FileBacking smoke test

The following fixture uses the development-only fake provider and a 2 MiB
virtual volume. The benchmark writes deterministic `0xA5` data, so never point
this configuration at an existing volume.

```bash
validation_dir="$(mktemp -d)"
config_path="$validation_dir/volume.toml"

cat >"$config_path" <<EOF
config_schema_version = 1

[volume]
name = "host-validation"
max_virtual_size = "2MiB"
device_block_size = 512
crypto_unit_size = 4096
shard_logical_size = "256KiB"

[crypto]
provider = "fake"
crypto_compatibility_id = "host-validation-v1"

[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4104

[backing]
root = "$validation_dir/backing"
EOF

cargo build --release --locked \
  -p maki -p maki-check -p maki-benchmark

target/release/maki volume create "$config_path"
target/release/maki volume inspect "$config_path"
target/release/maki check "$config_path"
target/release/maki-check "$validation_dir/backing"
target/release/maki-benchmark "$config_path" 10000 4096
target/release/maki check "$config_path"
target/release/maki-check "$validation_dir/backing"
```

The plan-rendering smoke test is non-privileged only when `--plan` is present:

```bash
cargo run --locked -p maki-attach -- \
  attach --volume hosttest --plan
cargo run --locked -p maki-attach -- \
  detach --volume hosttest --plan
cargo run --locked -p maki-attach -- \
  grow --volume hosttest --add-bytes 1048576 --plan
```

Do not remove `--plan`: without it, the Linux helper executes the printed
NBD, LVM, mount, or filesystem-growth operations.

### Packaging inspection

```bash
systemd-sysusers --dry-run \
  "$(realpath packaging/sysusers.d/maki.conf)"
systemd-analyze security --offline=yes \
  packaging/systemd/maki@.service
systemd-analyze verify \
  packaging/systemd/maki@.service \
  packaging/systemd/maki-attach@.service
```

`systemd-analyze verify` is expected to report unresolved installed paths on a
source-only host. It does not replace validation after package installation.

## Detailed results

### Functional and simulation checks

| Check | Result | Observation |
|---|---|---|
| Default workspace suite | **Pass** | 200 passed, 0 failed, 5 ignored phase gates |
| Extended phase gates | **Pass** | 5/5 passed in 51.527 s including compilation |
| Phase 0 full gate | **Pass** | 10,000 seeds x 60 randomized model operations |
| Phase 3 full gate | **Pass** | 10,000 seeds x 60 mixed operations, including randomized crash/recovery |
| Phase 4 full gate | **Pass** | 110,000 randomized model operations |
| Phase 11 full gate | **Pass** | 500 database-simulation runs, 40 transactions per run |
| Phase 12 full gate | **Pass** | 500 critical-sequence and 500 FUA simulated power-loss cycles |
| FileBacking CLI flow | **Pass** | Create, inspect, and both offline checkers passed before the workload |
| Fake-provider workload | **Pass** | 10,000 x 4 KiB writes and reads; both offline checkers passed afterwards |
| Plan rendering | **Pass** | CLI dry-run smoke only: attach, detach, and 1 MiB grow plans rendered; no command, device, mount, or privilege validation |

The workload measured 175.5 MiB/s write and 864.2 MiB/s read throughput on
this host. These numbers are smoke-test observations, not a performance
qualification or a provider benchmark.

### Linux integration and packaging checks

| Check | Result | Observation |
|---|---|---|
| `maki-nbdkit` release build | **Pass** | ELF64 x86-64 shared object built; dynamic dependencies resolved |
| `plugin_init` export | **Pass** | `nm -D` found a global text symbol |
| nbdkit header-layout comparison | **Not run** | nbdkit development metadata/headers unavailable; repository has no comparison test yet |
| nbdkit/libnbd socket round trip | **Not run** | `nbdkit` and `nbdinfo` unavailable |
| `/dev/nbd` + `fio` data path | **Not run** | Tools unavailable; attach and raw writes also require a disposable privileged target |
| sysusers configuration | **Pass** | `systemd-sysusers --dry-run` parsed the packaged users and groups |
| systemd security analysis | **Info** | Offline score: 5.3, `MEDIUM` |
| systemd unit verification | **Fail (host prerequisite)** | Exit 1: source-host check could not resolve uninstalled `/usr/bin/nbdkit` or `/usr/bin/maki-attach` |

The plugin build emitted a `private_interfaces` warning because the public
`plugin_init` function returns a private Rust representation of
`nbdkit_plugin`.

### Code-quality checks

| Check | Result | Observation |
|---|---|---|
| `cargo fmt --all --check` | **Fail** | Exit 1; 133 `Diff in` records across 44 files |
| Strict Clippy | **Fail** | Exit 101; first stopped in `maki-backing` on `suspicious_open_options` and `len_without_is_empty` |
| Advisory Clippy | **Info** | Completed without `-D warnings` and reported additional warnings |

Formatting and Clippy are marked `continue-on-error` in the current PR
workflow. Their failures do not invalidate the passing functional tests, but
they prevent this revision from being formatter- and lint-clean.

## Checks not run

| Qualification | Why it was not run | Prerequisite to close it | Runbook |
|---|---|---|---|
| nbdkit ABI and libnbd round trip | Required tools and headers absent | Install nbdkit/libnbd development tools; add and run the header-layout comparison | [Phase 6](phase-6.md) |
| Raw NBD and `fio` | Privileged and destructive against the selected block device | Dedicated disposable NBD target and authorized root environment | [Phase 6](phase-6.md) |
| Live privilege, ACL, capability, and crash checks | Packaging and dedicated service identities absent; includes intentional crash | Installed package on an isolated Linux host | [Phase 7](phase-7.md) |
| Vendor contract and soak | No endpoint or credential supplied | Vendor test environment and a supported invocation; current docs mention CLI modes not implemented by the binaries | [Phase 8](phase-8.md) |
| Real SQLite/PostgreSQL qualification | Requires the privileged NBD/XFS path first | Completed Phase 6 path and disposable database instance | [Phase 11](phase-11.md) |
| QEMU hard cuts and bare-metal cuts | Intentionally disruptive | Dedicated VM/hardware, independent ledger, and authorized power control | [Phase 12](phase-12.md) |
| 24/72-hour soak and 24 CPU-hour parser fuzzing | Long, resource-intensive qualification; fuzz wiring is pending | Dedicated runner, bounded monitoring, and cargo-fuzz targets/corpus | [CI strategy](ci.md) |

## Impact on release qualification

- Executed functional and simulation suites reported zero silent-corruption,
  durability, secrecy, queue-bound, semaphore, or privilege invariant
  violations.
- Phase 6 remains open because neither the live nbdkit/libnbd path nor the raw
  NBD/fio path ran.
- The Phase 3 in-process crash simulation passed, but it did not record 10,000
  operating-system process crashes; that release requirement remains partial.
- Phase 7 OS-enforced checks, Phase 8 vendor qualification, Phase 11 real
  database qualification, and Phase 12 QEMU/bare-metal qualification remain
  open.
- Formatting and strict Clippy remain red, although they are advisory in the
  current CI workflow.

Passing this report's test set must not be interpreted as production or
release qualification.

## Provenance

- The worktree was clean and matched the tested revision before execution.
- Test counts were taken from the test harness listing and command results.
- The benchmark used a temporary 2 MiB virtual fake-provider volume; it was
  deleted after the post-workload checks.
- Raw command logs were not retained. This report preserves the commands,
  environment, exit interpretation, and summarized observations.
