//! `maki-control` — the daemon control plane (SPEC §7).
//!
//! Newline-delimited JSON over the per-volume control socket
//! (`/run/maki/<volume>/control.sock`, owner `maki`, group `maki-admin`,
//! mode 0660). Allowed operations: status, metrics snapshot, hot reloads,
//! graceful checkpoint. Attach/detach/mount/grow are **not** part of this
//! protocol — they require the privileged helper (SPEC §7, PRIV-009).

pub mod protocol;
pub mod server;

#[cfg(unix)]
pub mod uds;
