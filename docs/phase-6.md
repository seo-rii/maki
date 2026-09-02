# Phase 6 — nbdkit Adapter

Status: **logic complete & tested** · Kernel-level gate (libnbd, `/dev/nbd` fio) **pending Linux validation** — see "Linux checklist" below.

## Architecture (`maki-nbdkit`)

| Layer | File | Testable on |
|---|---|---|
| Blocking adapter | `adapter.rs` | any OS (this is where all logic lives) |
| Daemon assembly | `daemon.rs` | any OS |
| nbdkit C ABI shim | `plugin.rs` (`cfg(target_os = "linux")`, cdylib) | Linux only |

- **`NbdAdapter`** — the exact surface the C shim calls: `get_size`, `block_sizes` (min = device block, preferred = crypto unit, max = 1 MiB / config), `pread`, `pwrite(fua)`, `flush`, `shutdown`. Every entry point runs under `catch_unwind`: a panic anywhere in the engine maps to EIO and **never unwinds across the FFI boundary**; the adapter remains fully usable afterwards (tested with a provider that panics on demand). Errors map to errnos (EINVAL for range/alignment, ENOSPC, EIO otherwise).
- Capability surface per SPEC §48: FLUSH + native FUA on; **trim disabled, write-zeroes disabled** (nbdkit emulates via pwrite — "zero fallback"), **multi-connection disabled**.
- **`shutdown`** = clean detach: FLUSH barrier → checkpoint → drop engine (volume lock released). Verified: re-attach succeeds immediately and data survives a lose-everything crash.
- **`daemon`** — config-driven assembly: `FileBacking` from `[backing].root`, provider from `[crypto].provider` (`local-aes-gcm-siv` / `local-aes-xts` with key-source resolution — env / file / systemd credentials, failing closed; `fake` behind the default `fake-provider` feature for development; `remote-http` lands in Phase 8), engine limits from `[limits]`. Also `create_volume_from_config_str` (used by `maki volume create`).
- **`plugin.rs`** — `nbdkit_plugin` API-v2 struct with v2 rpc callbacks, `errno_is_preserved = 1`, `THREAD_MODEL_PARALLEL`. `_struct_size` deliberately stops after the v2 callbacks so later optional fields read as NULL in nbdkit — whose defaults (multi-conn off, no zero, no trim) match our requirements. The tokio runtime is created lazily at first `open` (post-fork), standing in for `after_fork`.

## SPEC §48 test-first cases → tests (`tests/phase6.rs`, 9 tests)

get_size/block_size · trim/zero/multi-conn disabled flags · read/write roundtrip + zeros · EINVAL on unaligned/OOB · FUA + FLUSH durability across crash · parallel callbacks (8 OS threads × 16 ops through the blocking facade) · panic boundary · disconnect/clean detach (lock release + durability) · config-driven open (`volume create` → attach → write FUA → shutdown → recovery reopen).

## Linux checklist (before the phase gate is claimable)

1. `cargo build --release -p maki-nbdkit` on the target distro; verify `plugin_init` symbol and struct layout against that distro's `nbdkit-plugin.h` (compile the header comparison test in CI).
2. `nbdkit --foreground -U /run/maki/<v>/nbd.sock ./libmaki_nbdkit.so config=<v>.toml` + `nbdinfo`/libnbd round-trip suite.
3. `nbd-client`/`nbd_connect_uri` attach, then `fio --verify` (randwrite + fsync workloads) on `/dev/nbdN`.
4. FLUSH/FUA behavior vs the model: `fio --fsync=1` + power-cut simulation (Phase 12 harness).

The plugin shim is intentionally thin; all engine behavior it exposes is covered by the adapter tests on every platform.

## Native Linux validation record

The [2026-09-02 native Linux run](native-linux-validation-2026-09-02.md)
passed the release plugin build, exported-symbol check, adapter suite, and a
temporary FileBacking CLI/benchmark flow on Debian 12. The host did not have
nbdkit/libnbd/fio tooling installed, and raw NBD attachment was excluded as a
privileged, destructive operation. The kernel-level checklist therefore
remains open.
