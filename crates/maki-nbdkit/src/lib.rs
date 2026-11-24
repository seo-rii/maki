//! `maki-nbdkit` — the nbdkit plugin (SPEC §48).
//!
//! Three layers:
//! - [`adapter`]: cross-platform blocking facade over the async engine —
//!   the exact surface the C shim calls; fully tested on any OS.
//! - [`daemon`]: config-driven assembly (backing + provider + engine).
//! - [`config_file`]: the checked reader every volume-configuration loader
//!   uses (SPEC §8).
//! - `plugin` (Linux only): the `nbdkit_plugin` C ABI shim exporting
//!   `plugin_init`.

// Diagnostics go through `tracing` and the plugin's `diagnostic!`: the
// `print!` family panics when the write fails (a closed pipe, a full disk),
// and nbdkit's stderr can be either. Tests may print.
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]

pub mod adapter;
pub mod config_file;
pub mod control;
pub mod daemon;
mod drain;
// Refuses to compile unless panics unwind; the panic boundaries rely on it.
mod panic_strategy;
pub mod security;

#[cfg(target_os = "linux")]
pub mod plugin;

// Socket fixtures of the unit tests bind below a short temporary directory.
#[cfg(all(test, target_os = "linux"))]
#[path = "../tests/support/short_dir.rs"]
mod short_dir;
