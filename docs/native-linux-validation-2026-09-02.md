# Native Linux Validation — 2026-09-02

This run re-executed every repository-provided check that was safe for an
unprivileged account. It deliberately did not attach or overwrite a block
device, install or stop services, exhaust memory, terminate a VM, or interrupt
power.

## Environment

| Item | Value |
|---|---|
| Commit | `ea74488` |
| OS | Debian GNU/Linux 12 (bookworm) |
| Kernel | `6.1.0-52-cloud-amd64` |
| Architecture | x86_64, 8 vCPUs, 31 GiB RAM |
| CPU / virtualization | AMD EPYC 7B12; KVM guest |
| Test filesystem | ext4 |
| Rust | `rustc 1.94.0`, `cargo 1.94.0` |

This is a non-WSL native Linux run, but it is not a physical bare-metal run.
No bare-metal durability claim is made from these results.

## Results

| Check | Result | Detail |
|---|---|---|
| `cargo test --workspace --locked` | **PASS** | 200 passed, 0 failed, 5 ignored phase gates |
| `cargo test --workspace --release --locked -- --ignored` | **PASS** | All 5 extended gates passed in 51.527 s including compilation: Phase 0 10,000+ sequences; Phase 3 10,000+ crash/recovery cycles; Phase 4 110,000 operations; Phase 11 500 DB-sim runs; Phase 12 500+500 simulated power-loss cycles |
| `cargo build --release -p maki-nbdkit --locked` | **PASS** | Linux ELF64 shared object built; the build emitted the existing `private_interfaces` warning for `plugin_init` |
| `nm -D target/release/libmaki_nbdkit.so` | **PASS** | Global `plugin_init` symbol exported |
| temporary FileBacking CLI flow | **PASS** | `maki volume create`, `volume inspect`, `maki check`, and standalone `maki-check` all passed before workload |
| temporary fake-provider benchmark | **PASS** | 10,000 x 4 KiB writes and reads; 175.5 MiB/s write, 864.2 MiB/s read; both offline checkers passed afterwards |
| `maki-attach ... --plan` | **PASS** | attach, detach, and 1 MiB grow plans rendered successfully; no plan was executed |
| `systemd-sysusers --dry-run` | **PASS** | Parsed the packaged users/groups without changing the host |
| `systemd-analyze security --offline=yes` | **OBSERVED** | Data-plane unit exposure score 5.3 (`MEDIUM`); static `verify` could not resolve `/usr/bin/nbdkit` and `/usr/bin/maki-attach` because packaging is not installed |
| `cargo fmt --all --check` | **FAIL** | Existing formatting drift: 133 diffs across 44 files; CI currently marks formatting advisory |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | **FAIL** | Rust 1.94 stopped in `maki-backing` on `suspicious_open_options` and `len_without_is_empty`; advisory clippy completed with warnings |

The benchmark used a dedicated 2 MiB temporary fake-provider volume under the
ignored `target/` tree. It did not touch an existing Maki volume or block
device. Its throughput figures are a smoke-test observation, not a performance
qualification.

## Not run

| Check | Reason |
|---|---|
| nbdkit + `nbdinfo`/libnbd Unix-socket round trip | `nbdkit`, `nbdinfo`, and nbdkit development metadata/headers are not installed; the documented header-layout comparison test is not present in the repository |
| `/dev/nbdN` attach and raw `fio` verification | `nbd-client` and `fio` are not installed; attaching and writing a raw block device also requires privilege and can destroy data |
| live Phase 7 privilege/ACL/capability checks | Require packaging installation, dedicated users, system services, NBD access, and in one case an intentional daemon crash |
| vendor provider contract and soak | No vendor endpoint or credential was supplied. The documented `maki check --provider` and `maki-benchmark --duration 24h` interfaces are not implemented by the current CLIs |
| real SQLite/PostgreSQL qualification | Requires the privileged NBD/XFS data path first; the full in-memory DB simulation gate did pass |
| QEMU hard cuts and bare-metal power cuts | Explicitly excluded as disruptive; only the full Phase 12 simulated-power-loss gate was run |
| 24/72-hour soak and 24 CPU-hour parser fuzzing | Long resource-exhaustive workload was outside the safe host run; cargo-fuzz corpus/wiring is still pending per `docs/ci.md` |

The unresolved items above remain release/hardware-tier work. In particular,
this run does not close the Phase 6 kernel data-path gate or the Phase 12
bare-metal durability gate.
