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
