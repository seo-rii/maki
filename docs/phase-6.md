# nbdkit Adapter (Phase 6)

The `maki-nbdkit` crate exposes Maki's asynchronous engine through nbdkit's
synchronous plugin ABI. The adapter, Linux cdylib, Debian header prefix, and
rootless nbdkit/libnbd/fio path pass. Kernel NBD and filesystem qualification
are still required.

## Status

| Qualification | Status | Evidence |
|---|---|---|
| Adapter behavior | **Pass** | [9 adapter integration tests](../crates/maki-nbdkit/tests/phase6.rs) |
| Linux cdylib build | **Pass on Debian 12/KVM** | [2026-09-02 validation report](native-linux-validation-2026-09-02.md) |
| `plugin_init` export | **Pass** | [2026-09-02 validation report](native-linux-validation-2026-09-02.md) |
| ABI layout vs distro header | **Pass on Debian 12/KVM** | API-v2 prefix checked against `nbdkit-plugin-dev 1.32.5-1` |
| nbdkit/libnbd socket round trip | **Pass on Debian 12/KVM** | `nbdinfo` plus byte-identical 8 MiB `nbdcopy` round trip |
| fio over userspace NBD | **Pass on Debian 12/KVM** | 2,048 CRC32C-verified 4 KiB writes and reads; 63 FLUSH operations |
| Kernel `/dev/nbd` + filesystem | **Not run** | Requires a privileged, disposable block-device target |
| Kernel data-path gate | **Open** | Kernel attachment, filesystem, and raw-device checks incomplete |

## Responsibilities and boundaries

The crate has three responsibilities:

1. adapt synchronous NBD callbacks to the asynchronous Maki engine;
2. assemble a volume from its validated configuration; and
3. export the Linux nbdkit C ABI entry point.

It does not perform privileged NBD attachment, LVM activation, filesystem
mounting, or filesystem growth. Those operations belong to the separate
`maki-attach` helper described in [Phase 7](phase-7.md).

## Architecture

| Layer | Source | Responsibility | Platform |
|---|---|---|---|
| Blocking adapter | [`adapter.rs`](../crates/maki-nbdkit/src/adapter.rs) | Runtime bridge, bounds/error mapping, panic boundary, clean shutdown | Any supported Rust host |
| Daemon assembly | [`daemon.rs`](../crates/maki-nbdkit/src/daemon.rs) | Configuration, backing store, provider, recovery, and engine construction | Any supported Rust host |
| nbdkit ABI shim | [`plugin.rs`](../crates/maki-nbdkit/src/plugin.rs) | API-v2 structure and C callbacks; built as a cdylib | Linux only |

The daemon opens `FileBacking` from `[backing].root`, resolves the configured
provider, applies engine limits, runs recovery, and performs the provider
self-test before serving I/O. Local AES-GCM-SIV and AES-XTS providers are
supported; the fake provider is enabled for development, and the remote HTTP
provider is implemented as part of [Phase 8](phase-8.md).

The ABI shim exports an nbdkit API-v2 prefix with
`THREAD_MODEL_PARALLEL` and `errno_is_preserved = 1`. Its Tokio runtime is
created lazily after nbdkit forks. The declared structure ends after the v2
callbacks so later optional callbacks use nbdkit's defaults.

## NBD capability contract

| Capability | Advertised | Behavior |
|---|---|---|
| Read and write | Yes | Requests must be aligned and within the virtual device |
| FLUSH | Yes | Completes the engine durability barrier |
| FUA | Emulated by nbdkit | The current callback returns `NBDKIT_FUA_EMULATE`; nbdkit follows the write with FLUSH |
| TRIM | No | Callback is not advertised |
| Write zeroes | No | nbdkit may fall back to ordinary zero-filled writes |
| Multi-connection | No | Disabled by the API-prefix/default contract |

In the rootless live probe, `nbdinfo` reported `can_zero: true` because nbdkit
can emulate zero requests with ordinary writes. That negotiated capability
does not mean Maki exports a native write-zeroes callback.

The FUA behavior follows the
[nbdkit `can_fua` contract](https://libguestfs.org/nbdkit-plugin.3.html): the
current callback value is `1` (`NBDKIT_FUA_EMULATE`), not
`NBDKIT_FUA_NATIVE`. nbdkit therefore does not pass `NBDKIT_FLAG_FUA` into the
write callback.

At the Rust adapter boundary, `block_sizes()` reports the configured minimum,
preferred, and maximum I/O sizes. The current ABI prefix does not export the
later nbdkit block-size callback; live negotiation therefore remains part of
the kernel integration gate.

## Error, panic, and shutdown contract

- Invalid alignment or range maps to `EINVAL`.
- Backing-store exhaustion maps to `ENOSPC`.
- Other engine failures map to `EIO`.
- Engine operations routed through `NbdAdapter::run` (`pread`, `pwrite`,
  `flush`, and `checkpoint`) are wrapped in `catch_unwind`; a panic becomes
  `EIO`. The injected provider-panic test proves recovery for that I/O path,
  not for every plugin callback.
- Clean shutdown performs FLUSH, checkpoint, and engine drop in that order,
  releasing the volume lock only after durable state is established.

## Test coverage

All tests below exercise `NbdAdapter`, the blocking surface on which the C
callbacks are built.

| Behavior | Test evidence |
|---|---|
| Device geometry and block sizes | `get_size_and_block_sizes` |
| Capability flags | `trim_zero_and_multiconn_are_disabled` |
| Read/write and zero-filled unwritten regions | `pread_pwrite_roundtrip` |
| Alignment and bounds | `unaligned_or_oob_requests_are_einval` |
| Direct-adapter FUA and FLUSH durability | `fua_and_flush_are_durable` (does not exercise live nbdkit negotiation) |
| Parallel callbacks | `parallel_callbacks_from_many_threads` (8 threads x 16 write/read pairs) |
| Panic containment and recovery | `panic_inside_engine_becomes_eio_and_adapter_survives` |
| Clean detach and lock release | `clean_detach_flushes_checkpoints_and_releases_lock` |
| Config-driven create, attach, shutdown, and recovery | `adapter_opens_from_config_file` |

Run the adapter suite with:

```bash
cargo test --locked -p maki-nbdkit --test phase6
```

## Build and unprivileged smoke test

Building and checking the exported entry point require no root privileges:

```bash
cargo build --release --locked -p maki-nbdkit
nm -D --defined-only target/release/libmaki_nbdkit.so |
  grep -Eq '[[:space:]]T[[:space:]]plugin_init$'
```

After nbdkit, libnbd tools, and fio are available, the userspace NBD path can
run without `/dev/nbd` or root. Debian package names are `nbdkit`,
`nbdkit-plugin-dev`, `libnbd-bin`, and `fio`; `nbd-client` is optional for the
negotiation-only smoke. The validation report documents the rootless `.deb`
extraction used when system installation was unavailable.

Create a dedicated 8 MiB fake-provider volume with a writable backing root.
The commands below overwrite the complete export, so do not reuse a real
volume. Then use two terminals:

```bash
# Terminal 1
config_path=/absolute/path/to/volume.toml
socket_dir="$(mktemp -d)"
cargo run --release --locked -p maki -- \
  volume create "$config_path"
printf 'socket: %s\n' "$socket_dir/nbd.sock"
nbdkit --foreground \
  -U "$socket_dir/nbd.sock" \
  target/release/libmaki_nbdkit.so \
  config="$config_path"
```

```bash
# Terminal 2; substitute the socket path printed/selected in Terminal 1
uri="nbd+unix:///?socket=/absolute/path/to/nbd.sock"
test_dir="$(mktemp -d)"

nbdinfo "$uri"
dd if=/dev/urandom of="$test_dir/source.bin" bs=1M count=8 status=none
nbdcopy --flush --synchronous "$test_dir/source.bin" "$uri"
nbdcopy --synchronous "$uri" "$test_dir/roundtrip.bin"
cmp "$test_dir/source.bin" "$test_dir/roundtrip.bin"

fio --name=maki-nbd-verify \
  --ioengine=nbd --uri="$uri" \
  --rw=write --bs=4k --size=8M --iodepth=1 --fsync=32 \
  --verify=crc32c --do_verify=1 --verify_fatal=1 \
  --verify_state_save=0
```

Stop nbdkit normally and run both offline checkers after it releases the volume
lock. This userspace test exercises Maki through nbdkit and libnbd, including
read, write, and FLUSH. It is not a substitute for kernel `/dev/nbd`,
filesystem, raw-device durability, or hard-power-loss qualification.

## Linux qualification checklist

| Step | Privilege / risk | Status |
|---|---|---|
| Build the release cdylib on the target distribution | Unprivileged | **Pass on Debian 12/KVM** |
| Assert the global `plugin_init` export | Unprivileged | **Pass** |
| Compare `nbdkit_plugin` size, offsets, and callbacks with the distro's `nbdkit-plugin.h` | Unprivileged after dev-package install | **Pass for Debian 12 header 1.32.5-1** |
| Run nbdkit + `nbdinfo`/`nbdcopy` over a temporary Unix socket | Unprivileged | **Pass on Debian 12/KVM** |
| Run fio CRC verification and periodic FLUSH over the Unix-socket export | Unprivileged; destructive only to the disposable export | **Pass on Debian 12/KVM** |
| Attach a disposable `/dev/nbdN` and run aligned read/write verification | Root; destructive to selected target | **Not run** |
| Run `fio --verify` against the kernel device and filesystem | Root; sustained writes to selected target | **Not run** |
| Compare acknowledged FLUSH/FUA operations after hard power loss | Disruptive; isolated VM/hardware only | **Not run** |

The kernel data-path gate closes only when every row is complete on the target
distribution and the raw-device workloads report zero durability or corruption
violations.

## Known limitations

- The one-off ABI probe covers the Debian `nbdkit-plugin-dev 1.32.5-1` header's
  API-v2 prefix. It is not yet an automated repository test and does not prove
  compatibility with every distribution or future nbdkit release.
- Userspace I/O has been observed through nbdkit and libnbd. Kernel NBD,
  filesystem behavior, and configured block-size negotiation remain untested.
- The C shim currently advertises emulated rather than native FUA, despite the
  direct Rust adapter accepting a `fua` argument.
- TRIM, write-zeroes callbacks, and multi-connection are intentionally
  disabled.
- QEMU and bare-metal power-loss evidence belongs to [Phase 12](phase-12.md),
  not to the in-process adapter suite.

## Related documentation

- [Linux validation report — 2026-09-02](native-linux-validation-2026-09-02.md)
- [Continuous integration and release qualification](ci.md)
- [Maki specification](../SPEC.md)
