//! `maki-control` — the daemon control plane (SPEC §7).
//!
//! Newline-delimited JSON over the per-volume control socket
//! (`/run/maki-control/<volume>/control.sock`, owner `maki`, group `maki-admin`,
//! mode 0660). Allowed operations: status, metrics snapshot, hot reloads,
//! graceful checkpoint, drain. Attach/detach/mount/grow are **not** part of this
//! protocol — they require the privileged helper (SPEC §7, PRIV-009).

// Diagnostics go through `tracing`: the `print!` family panics when the
// write fails (a closed pipe, a full disk). Tests may print.
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]

pub mod protocol;
pub mod server;

#[cfg(unix)]
pub mod uds;
