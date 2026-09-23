# Changelog

All notable changes to Maki, in particular anything that affects on-disk
compatibility, the runtime layout, credentials or operator procedures. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
Maki has no tagged release yet, so everything is under *Unreleased* with the
commit that introduced it. Procedures for each change live in the linked
documents.

## Unreleased

### Breaking changes

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

- Local providers now encrypt and decrypt in place inside pre-allocated
  `SecretBuffer`s and key files are read straight into guarded memory, so
  plaintext and keys never first exist in an unlocked allocation; the AES key
  schedule is zeroized on drop (R4-002;
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

- Validation reports moved to `docs/qualification/`; the README now links to
  [status](docs/status.md) instead of carrying the campaign history.
- `docs/architecture.md` now describes the experimental rollback-protected
  backing as implemented and the default formats' rollback limitation
  separately.
