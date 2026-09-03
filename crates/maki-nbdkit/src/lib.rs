//! `maki-nbdkit` — the nbdkit plugin (SPEC §48).
//!
//! Three layers:
//! - [`adapter`]: cross-platform blocking facade over the async engine —
//!   the exact surface the C shim calls; fully tested on any OS.
//! - [`daemon`]: config-driven assembly (backing + provider + engine).
//! - `plugin` (Linux only): the `nbdkit_plugin` C ABI shim exporting
//!   `plugin_init`.

pub mod adapter;
pub mod control;
pub mod daemon;
pub mod security;

#[cfg(target_os = "linux")]
pub mod plugin;
