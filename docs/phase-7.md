# Phase 7 — Daemon and Privilege Model

Status: **complete for everything host-verifiable**; OS-enforced items pinned in packaging + Linux checklist below.

## What was built

- **`maki-control`** — the control plane (SPEC §7): newline-delimited JSON with a hard 64 KiB line bound (control plane cannot be memory-bombed), `ControlBackend` trait, generic `serve_connection` (tested over in-memory duplex), Unix socket listener with mode 0660 (`uds.rs`, owner maki / group maki-admin per SPEC §7). Served commands: `status`, `metrics`, `checkpoint`, `reload <section>`. **Privileged verbs (attach/detach/mount/umount/grow/nbd-*) are structurally absent** and answer with a pointer to the privileged helper.
- **`maki-privileged`** — pure, auditable operation *plans* (`plan_attach`: modprobe → nbd-connect → block size → LVM activate → mount XFS → verify identity; `plan_detach` reversed; `plan_grow`: lvextend → xfs_growfs per SPEC §38) plus a trivial Linux-only executor. **The crate has no dependency on any crypto crate** (Cargo.toml documents the invariant) — PRIV-010 holds by construction and plan rendering is test-pinned to contain no credential-adjacent terms.
- **Secure mount validation** (`verify.rs`, SPEC §39): mountpoint exists / fstype is XFS / fs UUID / Maki sentinel UUID / NBD state / rw-probe — every single mismatch case is tested to refuse (the container must not start).
- **Packaging** — `systemd/maki@.service` (User=maki, empty `CapabilityBoundingSet=`/`AmbientCapabilities=`, `NoNewPrivileges`, `LimitCORE=0`, `ProtectSystem=strict`, `RuntimeDirectory`, `LoadCredential`, `Restart=on-failure`), `systemd/maki-attach@.service` (oneshot, no credential directives), `sysusers.d`, `tmpfiles.d` (no "other" access anywhere), `examples/postgres-prod.toml`.
- **Binaries** — `maki` (volume create/inspect, check, status/metrics/checkpoint/reload via control socket; attach/detach/grow delegate to the helper), `maki-attach` (plans + `--plan` audit mode; executes on Linux), `maki-check`, `maki-benchmark`. Smoke-verified end-to-end.
- **`EngineControlBackend`** in maki-nbdkit wires the control plane to a live engine.

## PRIV-001…016 disposition

| ID | How it is held |
|---|---|
| 001 UID≠0, 002 empty caps | unit-file pins (`data_plane_unit_is_unprivileged_and_sandboxed`) + Linux checklist |
| 003 foreign backing | escape-proof backing paths (maki-backing tests) + `ReadWritePaths=` pins |
| 004 /etc immutable, 005 no mount syscall | `ProtectSystem=strict`, empty capability set (pins) + checklist |
| 006/007 socket ACLs | `tmpfiles` mode pins + `uds.rs` 0660 + checklist |
| 008 admin status/reload | `status_and_metrics_work`, `checkpoint_and_hot_reload_work` |
| 009 admin cannot attach/mount | `privileged_verbs_are_rejected` (verbs don't exist on the socket) |
| 010 helper has no credentials | no-crypto-deps invariant + `plans_contain_no_credential_material` + unit pin |
| 011 duplicate attach | volume lock tests (Phases 3/6) |
| 012 restart on failure | `Restart=on-failure` pin |
| 013 no READY without backing | attach fails without valid superblock (recovery tests) |
| 014 missing credential fails closed | Phase-2 key-source tests + daemon `resolve_key_source` |
| 015 no core dumps | `LimitCORE=0` pin (+ PR_SET_DUMPABLE in the Linux checklist) |
| 016 I/O under sandbox | Linux checklist |

## Linux checklist (final PRIV qualification)

1. Install packaging; `systemd-analyze security maki@postgres` review.
2. As `maki-admin`: `maki status` works; `mount`/NBD ioctls fail (EPERM).
3. As unrelated user: control + NBD sockets refuse (EACCES).
4. Verify `/proc/<pid>/status` CapEff = 0, `prctl(PR_SET_DUMPABLE)=0`, no core files after `kill -SEGV`.
5. Duplicate `systemctl start maki@v` + manual nbdkit → `VOLUME_ALREADY_ATTACHED`.
6. fio through the sandboxed unit (PRIV-016).
