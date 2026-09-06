//! `maki-privileged` — the privileged one-shot helper (`maki-attach`,
//! SPEC §6). Strictly a storage connection and control-plane component:
//! it plans and executes NBD attach/detach, LVM activation, XFS mount and
//! growth — and by construction has no code path that touches plaintext,
//! ciphertext, keys, or crypto credentials (PRIV-010; see Cargo.toml note).
//!
//! - [`plan`]: pure, auditable step sequences plus rollback derivation;
//! - [`config`]: the root-owned attach configuration and argument hygiene;
//! - [`probe`]: pure parsers for mountinfo, sysfs and swap listings;
//! - [`verify`]: the secure-mount verifier;
//! - `exec` (Linux): command execution, observation, allocation, rollback.

pub mod config;
pub mod plan;
pub mod probe;
pub mod verify;

#[cfg(target_os = "linux")]
pub mod exec;

#[cfg(target_os = "linux")]
mod state;

#[cfg(target_os = "linux")]
mod detach;
