# Linux Validation Report: Debian 12 on KVM — 2026-09-02

> **Outcome:** Partial validation; all executed functional, quality, and
> rootless NBD data-path checks passed
>
> **Tested revision:**
> [`8f8b13d56539ae02ea29fcf6959a3f910f16acb4`](https://github.com/seo-rii/maki/commit/8f8b13d56539ae02ea29fcf6959a3f910f16acb4)
>
> **Release qualification:** Not complete

This report records the non-privileged checks run on a non-WSL Linux VM.
The workspace suites, extended simulations, formatter, strict Clippy, distro
header ABI probe, and live Maki nbdkit/libnbd/fio path all passed. Kernel NBD,
installed-service, vendor, real-database, and physical power-loss
qualifications remain open.

Related documentation: [CI and release qualification](ci.md) ·
[Phase 6: nbdkit adapter](phase-6.md) ·
[Phase 11: database qualification](phase-11.md) ·
[Phase 12: power-loss qualification](phase-12.md)

## Summary

| Area | Outcome | Evidence |
|---|---|---|
| Default workspace tests | **Pass** | 200 passed, 0 failed, 5 ignored |
| Extended simulation gates | **Pass** | All 5 release-mode phase gates passed |
| Code quality | **Pass** | Formatter clean; strict Clippy clean across the workspace, all targets, and all features |
| Plugin build and ABI | **Pass** | ELF/symbol checks and Debian 12 nbdkit API-v2 prefix comparison passed |
| Rootless Maki NBD path | **Pass** | `nbdinfo`, 8 MiB `nbdcopy` round trip, fio CRC32C verification, and post-I/O offline checks passed |
| File-backed CLI smoke test | **Pass** | Create, inspect, check, workload, and post-workload checks passed |
| Packaging inspection | **Partial pass** | Sysusers and offline security inspection passed; installed-unit verification remains open |
| Privileged and hardware qualification | **Not run** | Requires root, a destructive disposable target, external services, or disruptive operation |
| Overall release qualification | **Not complete** | Kernel NBD, service, vendor, database, and hardware gates remain open |

Result terms in this report are intentionally narrow:

- **Pass** means the listed command completed successfully on this host.
- **Partial pass** means only the stated portion of a larger gate ran.
- **Fail** means an executed command returned a non-zero status.
- **Not run** means no result was produced; the reason and prerequisite are
  listed below.
- **Info** is an observation, not a release-gate result.

## Scope and safety boundaries

The run used an ordinary user account and disposable fake-provider volumes.
It did not:

- use `sudo`, change the dpkg database, or write under `/usr`;
- attach, format, mount, or overwrite `/dev/nbd` or another kernel block-device
  node;
- install, start, stop, or intentionally crash a system service;
- connect to a vendor endpoint or use production credentials;
- exhaust memory or run a 24/72-hour saturation workload; or
- stop a VM, interrupt host power, or operate a physical power controller.

The previously unavailable Debian tools were downloaded as `.deb` archives
and extracted beneath a temporary user-owned directory. This is a rootless
test prefix, not a system package installation. The prefix and every test
volume were disposable.

## Test environment

| Item | Value |
|---|---|
| Date | 2026-09-02 (Asia/Seoul) |
| OS | Debian GNU/Linux 12 (bookworm) |
| Kernel | `6.1.0-52-cloud-amd64` |
| Architecture | x86_64, 8 vCPUs, 31 GiB RAM |
| CPU / virtualization | AMD EPYC 7B12; KVM guest |
| Test filesystem | ext4; build and disposable test data also used tmpfs |
| Rust toolchain | `rustc 1.94.0`, `cargo 1.94.0` |
| systemd | `252 (252.39-1~deb12u2)` |
| nbdkit | `1.32.5` (`nbdkit-plugin-dev 1.32.5-1`) |
| libnbd tools | `nbdinfo` and `nbdcopy` `1.14.2` |
| NBD client | `nbd-client 3.24` |
| fio | `3.33` |

The host was a KVM guest, not physical bare metal. These results therefore
provide non-WSL Linux coverage but no bare-metal durability evidence.

### Rootless tool provisioning

The requested packages were `nbdkit`, `nbdkit-plugin-dev`, `libnbd-bin`,
`nbd-client`, and `fio`. Alongside libraries already present on this Debian 12
host, the rootless prefix needed 22 archives:

```text
fio libaio1 libboost-iostreams1.74.0 libboost-thread1.74.0 libdaxctl1
libfmt9 libgfapi0 libgfrpc0 libgfxdr0 libglusterfs0 libibverbs1
libnbd-bin libnbd0 libndctl6 libpmem1 libpmemblk1 librados2 librbd1
librdmacm1 nbd-client nbdkit nbdkit-plugin-dev
```

Each archive was fetched with `apt-get download` and unpacked with
`dpkg-deb -x` into the temporary prefix. Commands then used:

```bash
tool_root=/absolute/path/to/the/extracted/root
export PATH="$tool_root/usr/bin:$tool_root/sbin:$PATH"
export LD_LIBRARY_PATH="$tool_root/usr/lib/x86_64-linux-gnu:$tool_root/usr/lib/x86_64-linux-gnu/ceph"
```

All selected binaries resolved their dynamic libraries under that environment.
Dependency names and paths are Debian 12 specific; normal installations should
use the target distribution's package manager.

## Reproduce the non-privileged checks

Run these commands from the repository root at the tested revision. `--locked`
keeps dependency resolution pinned to `Cargo.lock`.

### Workspace, phase gates, plugin, and quality checks

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --release --locked -- --ignored

cargo build --release --locked -p maki-nbdkit
nm -D --defined-only target/release/libmaki_nbdkit.so |
  grep -Eq '[[:space:]]T[[:space:]]plugin_init$'
readelf -h target/release/libmaki_nbdkit.so
ldd target/release/libmaki_nbdkit.so
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

### Rootless nbdkit/libnbd/fio data path

This test needs `nbdkit`, `nbdinfo`, `nbdcopy`, and fio's `nbd` engine, but it
does not need `/dev/nbd` or root. Use a dedicated 8 MiB fake-provider fixture
with `shard_logical_size = "1MiB"`, then build and create it as above.

Start nbdkit in one terminal:

```bash
socket_path=/absolute/path/to/a/disposable/nbd.sock
config_path=/absolute/path/to/the/8MiB-volume.toml

nbdkit --foreground \
  -U "$socket_path" \
  "$(pwd)/target/release/libmaki_nbdkit.so" \
  config="$config_path"
```

Run the clients in another terminal. Both `nbdcopy` and fio overwrite the
entire disposable export:

```bash
uri="nbd+unix:///?socket=$socket_path"
test_dir="$(mktemp -d)"

nbdinfo "$uri"
dd if=/dev/urandom of="$test_dir/source.bin" bs=1M count=8 status=none
nbdcopy --flush --synchronous "$test_dir/source.bin" "$uri"
nbdcopy --synchronous "$uri" "$test_dir/roundtrip.bin"
cmp "$test_dir/source.bin" "$test_dir/roundtrip.bin"
sha256sum "$test_dir/source.bin" "$test_dir/roundtrip.bin"

fio --name=maki-nbd-verify \
  --ioengine=nbd --uri="$uri" \
  --rw=write --bs=4k --size=8M --iodepth=1 --fsync=32 \
  --verify=crc32c --do_verify=1 --verify_fatal=1 \
  --verify_state_save=0
```

Stop nbdkit normally, then run both offline checkers again. A separate
`nbd-client -l` against a loopback TCP listener can smoke-test negotiation,
but it does not attach a kernel device or validate a data path.

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
source-only host. A rootless tool prefix does not populate `/usr/bin`, and it
does not replace validation after package installation.

## Detailed results

### Functional, simulation, and quality checks

| Check | Result | Observation |
|---|---|---|
| Default workspace suite | **Pass** | 200 passed, 0 failed, 5 ignored phase gates |
| Extended phase gates | **Pass** | 5/5 release-mode gates passed |
| Phase 0 full gate | **Pass** | 10,000 seeds x 60 randomized model operations |
| Phase 3 full gate | **Pass** | 10,000 seeds x 60 mixed operations, including randomized crash/recovery |
| Phase 4 full gate | **Pass** | 110,000 randomized model operations |
| Phase 11 full gate | **Pass** | 500 database-simulation runs, 40 transactions per run |
| Phase 12 full gate | **Pass** | 500 critical-sequence and 500 FUA simulated power-loss cycles |
| `cargo fmt --all --check` | **Pass** | The previous 44-file formatting drift is resolved |
| Strict Clippy | **Pass** | Workspace, all targets, all features, `-D warnings` |
| FileBacking CLI flow | **Pass** | Create, inspect, and both offline checkers passed before and after the workload |
| Fake-provider workload | **Pass** | 10,000 x 4 KiB writes and reads |
| Plan rendering | **Pass** | Attach, detach, and 1 MiB grow plans rendered; no command was executed |

The FileBacking workload observed 381.0 MiB/s write and 878.6 MiB/s read on
this host. These are smoke-test observations, not performance qualification or
provider benchmarks.

### Linux integration and packaging checks

| Check | Result | Observation |
|---|---|---|
| `maki-nbdkit` release build | **Pass** | ELF64 x86-64 shared object built; dynamic dependencies resolved |
| `plugin_init` export | **Pass** | `nm -D` found a global text symbol |
| Distro-header ABI probe | **Pass** | Debian `nbdkit-plugin-dev 1.32.5-1`; all 33 API-v2 prefix offsets matched |
| ABI boundary and callbacks | **Pass** | Rust prefix 256 B equals C `magic_config_key` offset; all 15 runtime field checks passed |
| `nbdinfo` handshake | **Pass** | 8 MiB writable export; FLUSH and emulated FUA available; multi-connection and TRIM unavailable |
| `nbdcopy` round trip | **Pass** | 8 MiB upload with FLUSH and download were byte-identical; SHA-256 `f7ba2a204612b68ced6d9c1189abaf33095f94a43c501d7f1fefb1712e90319a` |
| fio over Maki Unix NBD | **Pass** | CRC32C verified 2,048 writes + 2,048 reads at 4 KiB; 63 sync operations; `err=0` |
| Post-I/O offline checks | **Pass** | Both checkers passed after clean nbdkit shutdown; 8 shards observed |
| `nbd-client` loopback negotiation | **Pass (smoke)** | `nbd-client -l` negotiated with the Maki TCP listener; no device was attached |
| Kernel `/dev/nbd` + filesystem | **Not run** | Requires root and a dedicated destructive target |
| sysusers configuration | **Pass** | `systemd-sysusers --dry-run` parsed the packaged users and groups |
| systemd security analysis | **Info** | Offline score: 5.3, `MEDIUM` |
| systemd unit verification | **Fail (host prerequisite)** | Exit 1: source host lacks installed `/usr/bin/nbdkit` and `/usr/bin/maki-attach` |

The ABI probe compiled the official header with `NBDKIT_API_VERSION=2`,
loaded the actual release cdylib with `dlopen`, and called `plugin_init`.
The header's full current structure is 384 bytes; Maki intentionally publishes
only the validated 256-byte API-v2 prefix. The probe also confirmed that
`can_fua()` returns `NBDKIT_FUA_EMULATE`, not native FUA.

The fio observation covers the Maki plugin through nbdkit and libnbd over a
Unix socket. It is not evidence for the kernel NBD client, filesystem behavior,
raw-device durability, or hard-power-loss recovery.

## Checks not run

| Qualification | Why it was not run | Prerequisite to close it | Runbook |
|---|---|---|---|
| Kernel `/dev/nbd`, filesystem, and raw-device fio | Root-only attachment and destructive writes to the selected device | Dedicated disposable NBD target and authorized root environment | [Phase 6](phase-6.md) |
| Live privilege, ACL, capability, and service-crash checks | Packaging and dedicated service identities absent; includes intentional crash | Installed package on an isolated Linux host | [Phase 7](phase-7.md) |
| Vendor contract and soak | No endpoint or credential supplied | Vendor test environment and a supported invocation; current docs mention CLI modes not implemented by the binaries | [Phase 8](phase-8.md) |
| Real SQLite/PostgreSQL qualification | Requires the privileged NBD/XFS path first | Completed Phase 6 kernel path and disposable database instance | [Phase 11](phase-11.md) |
| QEMU hard cuts and bare-metal cuts | Intentionally disruptive | Dedicated VM/hardware, independent ledger, and authorized power control | [Phase 12](phase-12.md) |
| 24/72-hour soak and 24 CPU-hour parser fuzzing | Long, resource-intensive qualification; fuzz wiring is pending | Dedicated runner, bounded monitoring, and cargo-fuzz targets/corpus | [CI strategy](ci.md) |

## Impact on release qualification

- Executed functional, simulation, quality, ABI, and userspace NBD checks
  passed without reported corruption, durability, secrecy, queue-bound,
  semaphore, privilege, checksum, or lint violations.
- Phase 6 now has distro-header and userspace nbdkit/libnbd/fio evidence, but
  its kernel `/dev/nbd`, filesystem, and raw-device gate remains open.
- The Phase 3 in-process crash simulation passed, but it did not record 10,000
  operating-system process crashes; that release requirement remains partial.
- Phase 7 OS-enforced checks, Phase 8 vendor qualification, Phase 11 real
  database qualification, and Phase 12 QEMU/bare-metal qualification remain
  open.
- Formatting and strict Clippy are clean at the tested revision. They remain
  advisory in the current GitHub Actions workflow.

Passing this report's test set must not be interpreted as production or
release qualification.

## Provenance

- The authoritative rerun used a clean worktree at the tested revision.
- Test counts were taken from the Rust harness output; client counts were
  taken from fio's final report.
- Builds, extracted packages, random test images, sockets, and backing files
  lived under a disposable tmpfs directory.
- The ABI comparison was a one-off probe against the stated Debian header; it
  is not yet an automated repository test.
- No raw device, installed system path, dpkg state, service, mount, or host
  power state was modified.
