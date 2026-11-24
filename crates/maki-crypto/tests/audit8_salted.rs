//! Audit round 8 (long-seeds): every committed randomized integration test of
//! this crate, with each RNG seed XORed with `AUDIT8_SALT` (see
//! `audit8_salted/*.rs`; generated, not part of the maintained suite).
//! Run one module per process, as the originals are separate binaries:
//! `AUDIT8_SALT=7 <binary> phase3:: --test-threads=1 [--include-ignored]`.
#![allow(dead_code, unused_imports, clippy::all)]

/// XORed into every RNG seed of the salted copies (0 = committed seeds).
pub fn a8_salt() -> u64 {
    static SALT: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *SALT.get_or_init(|| {
        std::env::var("AUDIT8_SALT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    })
}

#[path = "audit8_salted/review_stress_crypto.rs"]
mod review_stress_crypto;
#[path = "audit8_salted/phase5_flow.rs"]
mod phase5_flow;
#[path = "audit8_salted/review_jitter_progress.rs"]
mod review_jitter_progress;
