//! `maki-privileged` — the privileged one-shot helper (`maki-attach`,
//! SPEC §6). Strictly a storage connection and control-plane component:
//! it plans and executes NBD attach/detach, LVM activation, XFS mount and
//! growth — and by construction has no code path that touches plaintext,
//! ciphertext, keys, or crypto credentials (PRIV-010; see Cargo.toml note).

pub mod plan;
pub mod verify;

#[cfg(target_os = "linux")]
pub mod exec;
