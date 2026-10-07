# Changelog

All notable changes to Maki, in particular anything that affects on-disk
compatibility, the runtime layout, credentials or operator procedures. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
Maki has no tagged release yet, so everything is under *Unreleased* with the
commit that introduced it. Procedures for each change live in the linked
documents.

## Unreleased

### Breaking changes

- **Executing `maki-attach` verbs require a root-controlled attach config**
  (R5-030): a root-owned regular file with one link, not group/other
  writable, below root-owned directories. `--plan` reads any file.
- **A CA bundle or a WebSocket/gRPC `client_cert_file` containing a private
  key is refused** (R5-028); supply the key through `client_key`.
- **The mountpoint directory must be root-owned and not group/other
  writable** (R5-024), like its ancestors: a workload-owned mountpoint let
  the workload stack a FUSE mount over it before attach mounted the volume.
  Recreate it with `install -d -m 0755 /srv/<volume>` (root) before attach;
  the volume's own root directory keeps the workload's ownership.
- **`maki-benchmark` refuses an existing volume without `--destroy-data`**
  (R5-017): it overwrites the start of the device (partition table,
  filesystem superblock) and used to do so to whatever volume its
  configuration named.
- **Credential-like header names refuse literal values** (R5-007). An HTTP
  header or gRPC metadata name containing `auth`, `token`, `secret`,
  `passw`, `cookie`, `session`, `signature`, `credential`, `apikey`,
  `api_key`, `-key` or `_key` must use a credential reference
  ([configuration](docs/configuration.md#credentials-and-secrets)); a
  configuration that put such a value inline no longer validates.
- **Superblock envelope v2 with mirrored durable proofs is required for
  writable volumes** (`1bc0ab5`, 2026-09-12). Older binaries reject v2
  volumes; this build refuses writable recovery of legacy v1 volumes and
  supports them read-only with a warning. There is no in-place upgrade:
  follow [durable recovery and migration](docs/durable-recovery.md). The
  crypto AAD `format_version` is unchanged.
- **Privileged helper runtime layout** (2026-09-05 review fixes). Attachment
  records moved to `/run/maki-attach/<volume>.nbd` with a versioned trusted
  format; legacy `/run/maki/attach/*.nbd` records are refused. The default
  control socket is `/run/maki-control/<volume>/control.sock`. Detach with
  the old helper before upgrading:
  [upgrade procedure](docs/operations.md#upgrading-the-runtime-layout).
- **`nbd-client` 3.27.0 or later is required** for privileged attachment; the
  helper verifies the kernel NBD backend identifier over netlink and fails
  closed otherwise. Debian 12's 3.24 is too old
  ([installation](docs/getting-started/installation-debian.md)).
- **Credential sources no longer fall back**: `credential`, `file` and `env`
  are each read only from the source they declare; the same name may not be
  declared with different sources in one configuration.
- **`crypto.capabilities.mode` accepts only `declared`**; `hybrid` and
  `probed` are configuration errors.
- **Plaintext transports to non-loopback hosts are refused**; `http://`,
  `ws://` and gRPC `http://` endpoints are accepted only for loopback.
- **Production remote-provider contracts must declare `integrity` and
  `context_binding`**, and a provider that declares context binding must
  receive the whole context (volume UUID, compatibility id, format version)
  or attach fails (`be23a11`).
- **`maki-attach grow` takes an absolute `--size-bytes`**; the relative
  `--add-bytes` is rejected because a retry could not identify itself.

### Added

- **Benchmark reports**: `maki-benchmark --json` records throughput, IOPS,
  bounded-memory p50/p95/p99 latency estimates, final FLUSH time and verified
  readback; `--fua` selects durable individual writes. Invalid workload
  arguments are refused before creating a volume; recovered geometry is
  rechecked before I/O. See
  [performance profiles](docs/performance.md).
- **Release candidate preparation**: `scripts/prepare_release.py` builds
  committed source in isolation and bundles the Debian package, source
  archive, host/toolchain provenance and SHA-256 checksums without publishing.
  See [release preparation](docs/releasing.md).

- **Overlay memory bound**: `limits.max_overlay_bytes` (default 256 MiB)
  and `limits.max_overlay_entries` (default 262144) bound the in-memory
  ciphertext overlay independently of the on-disk journal; a write over the
  bound checkpoints inline and fails with ENOSPC if that cannot make room,
  and the worker checkpoints at half the bound (R4-005;
  [configuration](docs/configuration.md#journal-bounds)). Existing
  configurations gain the defaults; set either to `0` to keep the old
  unbounded behaviour.
- **Deep-check verdict**: `maki check --deep` and `maki-check --deep` end
  with `deep check verdict: clean | recoverable | unrecoverable`; slot damage
  that a validated journal record repairs is a warning, not an error
  (R4-004; [operations](docs/operations.md#volume-lifecycle)).
- **Debian package safety**: `prerm` refuses removal while a volume is
  attached (upgrades are exempt), the builder verifies every artifact's ELF
  architecture against `--architecture`, and native library dependencies are
  added to `Depends` with `dpkg-shlibdeps` by default (the build now needs
  `dpkg-dev`; `--no-shlibdeps` opts out for test fixtures only) (R4-003, R4-007;
  [packaging README](packaging/debian/README.md)).
- **Runtime logging**: the nbdkit plugin, `maki` and `maki-check` install a
  stderr `tracing` subscriber (`MAKI_LOG` filter, default `info`), so
  checkpoint, journal-sync, control-server and store-repair warnings reach
  the service journal (R4-001; [operations](docs/operations.md#logging)).
- Opt-in **envelope v3** with durable TRIM and Linux backing-space
  reclamation: `maki volume create <config> --discard` (`8f7606f`,
  `e911471`; [space reclamation](docs/space-reclamation.md)).
- Experimental **rollback-protected backing** with an independent local
  witness for new Linux volumes (`d2c4fb7`, `64ff710`;
  [rollback protection](docs/rollback-protection.md)). Not qualified.
- **Debian package** builder and package contract tests (`8b69efc`,
  `07fed8b`); the package owns nothing under `/etc/maki` and never starts a
  volume.
- **`[lvm_identity]` pins** (complete PV set, VG and target LV UUIDs) in the
  attach configuration, rechecked by recovery, grow and detach.
- **Native readiness**: the data-plane unit is `Type=notify` and reports
  `READY=1` only after recovery, provider checks and control binding
  (`2a3f023`).
- **Physical write reservation**: `posix_fallocate` of the journal range and
  the checkpoint slot before a record is published (`ced2bda`).
- **Bounded recovery replay** through a fixed 1 MiB payload batch (`733833c`).
- **Volume capacity plan** in `maki volume inspect` (`5803be8`).
- Verified **WSS and gRPC TLS/mTLS** for the WebSocket and gRPC providers
  (`a1aac42`).
- **RustSec dependency audit** in CI (`47058d2`).
- Optional **random plaintext prefix** (`crypto.random_prefix_bytes`, 16 to
  256 bytes in multiples of 16) prepended to every crypto unit before
  provider encryption; new volumes only (`562b397`, `1115e1d`;
  [random plaintext prefixes](docs/random-plaintext-prefix.md)).
- Getting-started, deployment and status documentation; `LICENSE`,
  `SECURITY.md`, `CONTRIBUTING.md`, this changelog, and a documentation link
  checker in CI (2026-09-23).

### Fixed

- **HTTP response JSON ownership**: completed strings and object keys are
  guarded before the full response is parsed, so malformed partial JSON and
  duplicate replacement erase their owned plaintext too. Single-item and
  batch responses share the guarded parser; serde scratch and transport-private
  allocations remain outside that ownership guarantee
  ([memory scope](docs/transport-memory.md)).

- A request's provider batches run concurrently within the
  `max_active_callbacks` limit, and a per-item HTTP mapping (no
  `items_path`) is batched one unit per call. Sequential I/O through such a
  mapping with 10 ms of provider latency went from about 330 KiB/s to
  2.8 MiB/s (R5-039).
- **Writes longer than `nbd.maximum_io` were refused and, under buffered
  writeback, silently lost** (R5-038). Linux 6.12 (Debian 13) sends up to
  1280 KiB per request regardless of the advertised 1 MiB maximum; XFS made
  on such a volume could not be mounted. Longer reads and writes are now
  served in `maximum_io` chunks.
- `maki@.service` starts under systemd 257 (Debian 13), which writes
  `LoadCredential=` files with mode `0440`; the credentials directory now
  accepts group read for the service's own group (R5-037).
- NBD WRITE_ZEROES longer than `nbd.maximum_io` (sent by userspace clients
  such as nbdcopy for the holes of a sparse image) failed with EINVAL: the plugin left it to nbdkit's
  single-`pwrite` emulation. Zeroing is now native and chunked, and may
  discard whole units on a `--discard` volume when the client allows it
  (R5-036).
- A bearer token (HTTP header or gRPC metadata credential) or PEM private
  key that happens to be an even-length hex string is used verbatim; the
  daemon used to hex-decode it like a local key and refused to start
  (R5-035). Tokens generated with `openssl rand -hex` were affected.
- `maki@.service` sets `SystemCallFilter=@system-service` with
  `SystemCallErrorNumber=EPERM`, after three packaged PostgreSQL lifecycles
  ran under it without a denial, and `MemoryDenyWriteExecute=yes`, after the
  local and all three remote providers round-tripped data under it.
- Rollback-protected backing (experimental): a write's cost no longer grows
  with committed data (R5-034); a 64 KiB write at 128 MiB committed went
  from about 150 ms to under 1 ms.
- Lowering `backing.journal_segment_size` no longer makes a cleanly stopped
  volume fail recovery as corrupt (R5-033); the setting is now limited to
  1 GiB.
- `maki@.service` adds kernel-log, clock, hostname, realtime, namespace,
  syscall-ABI and address-family restrictions (R5-031).
- `maki-check` no longer creates a missing root directory (R5-026), and the
  deep check no longer reports nonexistent units of a truncated partial last
  shard (R5-027).
- Detach, cleanup and attach rollback no longer require
  `<mountpoint>/.maki-sentinel` (R5-006): a workload that deleted or
  rewrote it blocked `maki-attach cleanup`. The mount is identified from
  kernel metadata, as recovery already did; attach and `verify` still check
  the sentinel.
- `maki-attach` refuses `mountpoint = "/"` (R5-019).
- `maki volume create` refuses a backing root that still holds an earlier
  volume's `data/`, `journal/` or `checkpoint/` files (R5-018); they used to
  be adopted and served by the new volume.
- Package removal is also refused while a `maki-recover@` unit is active
  (R5-015).
- A huge configured circuit-breaker duration no longer panics the
  dispatcher on the first trip (R5-013); `reload cache` refuses a size of 0
  or larger than the device (R5-014).
- v3 discard works under space pressure and on damaged units (R5-011,
  R5-012): tombstones are admitted against the emergency reserve alone, not
  the checkpoint headroom, and a unit whose slot is damaged can be discarded
  (previously EIO). "Already zero" is decided from the slot header, so a
  discard no longer reads every payload twice under the volume lock.
- v3 discard: **trims longer than `nbd.maximum_io` are accepted** (R5-010).
  The maximum block size bounds payloads; kernel discards (`fstrim`,
  `-o discard`) are far larger and all failed with EINVAL.
- v3 discard: a checkpoint **punches retired slots only after its state is
  durable** (R5-008), so a crash or failed state store can no longer leave
  recovery replaying an older write into a released hole (ENOSPC on a full
  backing). A failed punch now defers reclamation instead of failing the
  checkpoint. A failed shard-catalog commit no longer makes later
  reclamation checkpoints panic (R5-009).
- Remote providers: a **broken endpoint now fails over** (R5-005). A
  contract-violating response (malformed JSON, wrong item count, bad
  encoding) or HTTP 404/405/410 counts as an endpoint failure, opens that
  endpoint's circuit and lets a retry-safe request move to a healthy peer;
  previously every request failed while the circuit stayed closed.
- `remote-http` **ignores environment proxies** (R5-003): an inherited
  `HTTP_PROXY`/`ALL_PROXY` no longer receives plaintext encrypt requests.
  Deployments that relied on a proxy to reach the provider must connect to
  it directly.
- **The volume is mounted `nosuid,nodev`** (R5-002). A setuid binary or a
  device node inside the volume no longer takes effect on the host; attach
  verification refuses a mount without both flags, and `maki@.service` sets
  `DevicePolicy=closed`. Workloads that need setuid programs or device nodes
  on the volume are not supported. The `maki-attach verify` workload gate
  refuses a mount without both flags as well: reattach volumes mounted by an
  earlier build before restarting their workload.
- `remote-http`: a combined certificate/private-key PEM (`client_cert_file`
  without `client_key`) now passes the `file` credential checks (no symlink,
  not group/other-readable); every TLS file must be a regular file, so a
  FIFO cannot hang attach ([configuration](docs/configuration.md)).
- `remote-http`: a header credential that resolves to an invalid header
  value (a control character inside it) is refused at attach as
  `ProviderFatal` instead of failing every request as a retryable error.

- `maki-attach` refuses to mount onto a path a non-root user could redirect:
  every ancestor of the mountpoint must be a root-owned, non-group/other-
  writable real directory and the mountpoint a real directory. A workload
  that replaced the mountpoint with a symlink previously got its filesystem
  mounted by root at the symlink target (e.g. `/etc`), beyond rollback and
  detach ([operations](docs/operations.md#privileged-helper)).
- Pinned NBD devices must be spelled canonically (`/dev/nbd1`, not
  `/dev/nbd01` or `/dev/nbd+1`).

- Remote providers: an integrity (or other non-retryable, request-specific)
  rejection of a coalesced batch no longer fails every request merged into
  it; the batch scheduler re-sends each request alone, so a tampered unit
  read by one client cannot turn another client's healthy read into EIO.
  The re-send happens only for a retry-safe provider (a provider that is
  not retry-safe gets the error fanned out, as before), and each re-send is
  counted in flight and abandoned when its caller leaves (R5-004).

- Configuration validation refuses a `control.socket` that names the same
  file as `nbd.socket` (defaults included); binding the control socket
  replaces whatever is at its path.
- The control server's "unknown command" error echoes at most 64 characters
  of the name, so the response always fits the client's 64 KiB line limit.

- `control.group` resolution retries `getgrnam_r` with a larger buffer on
  `ERANGE`; a directory group whose record exceeded 16 KiB made attach fail.

- `file` and `credential` key sources open the credential once
  (`O_NOFOLLOW | O_NONBLOCK` on Unix) and run the regular-file and mode
  checks on the opened descriptor; checking the path and opening it again
  let a swap in between be loaded as the key, and a FIFO could block the
  open.

- `maki check --deep` now probes the slots the allocation map does not list:
  a damaged header there reads as EIO, but the check walked only allocated
  units and reported such a volume `clean` (R4-004 follow-up;
  [operations](docs/operations.md#volume-lifecycle)).

- A write that still exceeded the overlay bound or the journal hard limit
  after its inline reclaim failed with ENOSPC even when the space was held
  by another writer's volatile records, which that reclaim could not retire;
  it now syncs and reclaims again (up to four rounds) before refusing
  (R4-005 follow-up; [configuration](docs/configuration.md#journal-bounds)).

- `maki-attach` now installs a stderr `tracing` sink (`MAKI_LOG`, default
  `info`); its executed steps and halted-rollback errors were silently
  dropped before ([operations](docs/operations.md#logging)).
- The package `prerm` refuses removal when `systemctl list-units` fails,
  instead of reading the empty output as "no active maki units"
  ([packaging README](packaging/debian/README.md#removal-and-upgrade-behaviour)).

- A plaintext-cache hit now skips the ciphertext payload read (it reads the
  64-byte slot header to establish the version) instead of only skipping
  decryption; a hit no longer re-verifies an already validated payload's
  CRC until the entry is evicted; `cache.verify_on_hit = true` restores
  payload verification on every hit and skips only the decryption (R4-006;
  [configuration](docs/configuration.md#read-cache)).
- Local providers now encrypt and decrypt in place inside pre-allocated
  `SecretBuffer`s and key files are read straight into guarded memory, so
  plaintext and keys never first exist in an unlocked allocation; the
  expanded AES key schedules live in a page-locked `SecretBox` under
  `secure-buffers` and are zeroized on drop (R4-002;
  [transport memory](docs/transport-memory.md#local-providers-and-key-material)).

Every fix has a regression test named in the
[review remediation log](docs/review-remediation.md). Highlights that change
observable behaviour:

- Recovery no longer accepts never-synced page-cache bytes after a process
  restart (K-01) and makes the checkpoint state it selects durable before the
  writer resumes (BUG-022).
- A failed `fdatasync` is never retried bare: the journal rewrites and
  verifies the unsynced records before syncing again (F01 / BUG-021).
- Media damage to a shard data file (truncation, damaged slot headers on
  cleared allocation bits) reads as EIO, never as zeros (S-01 residuals,
  `db39faa`).
- The attach helper rolls back observed steps on failure, refuses foreign
  mounts, verifies the backend identity before every disconnect, and drains
  control sessions on shutdown (BUG-015, BUG-018, O-07, F06).
- HTTP redirects are refused instead of re-sending plaintext (C-01);
  remote error bodies are redacted.
- Circuit-breaker half-open slots are always returned (N-10 / BUG-004);
  per-RPC deadlines cover gRPC readiness plus the call (BUG-017).

### Documentation

- [Remote transports under the syscall filter](docs/qualification/remote-transport-syscall-filter-validation-2026-10-04.md):
  the first external campaign for WebSocket and gRPC.
- [PostgreSQL over gRPC, NBD zeroing, MemoryDenyWriteExecute](docs/qualification/remote-database-zero-mdwe-validation-2026-10-04.md).
- [Debian 13: remote transports, sandbox, latency, zeroing](docs/qualification/debian13-remote-transport-validation-2026-10-04.md);
  the support matrix lists Debian 13 as campaign-passed (scoped).
- [Debian 13: PostgreSQL 17 over per-item HTTP, R5-039 throughput](docs/qualification/debian13-postgresql-http-validation-2026-10-05.md).
- [Cross-host remote transports under the sandbox](docs/qualification/cross-host-sandbox-validation-2026-10-05.md).
- [Provider host reset under a writing client](docs/qualification/provider-host-reset-validation-2026-10-05.md).
- The quick start and first-volume bootstrap passed `/dev/nbd0` to
  `nbd-client`; version 3.27, which Maki requires, connects over netlink and
  refuses it ("Invalid nbd device target"). They now pass the kernel name
  (`nbd0`); found by the 2026-10-03 packaged-lifecycle campaign.
- Validation reports moved to `docs/qualification/`; the README now links to
  [status](docs/status.md) instead of carrying the campaign history.
- `docs/architecture.md` now describes the experimental rollback-protected
  backing as implemented and the default formats' rollback limitation
  separately.
