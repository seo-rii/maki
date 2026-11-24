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

#[path = "audit8_salted/review_r3b_durability.rs"]
mod review_r3b_durability;
#[path = "audit8_salted/review_trim_power_loss.rs"]
mod review_trim_power_loss;
#[path = "audit8_salted/phase3.rs"]
mod phase3;
#[path = "audit8_salted/phase4.rs"]
mod phase4;
#[path = "audit8_salted/phase11_dbsim.rs"]
mod phase11_dbsim;
#[path = "audit8_salted/phase12_powerloss.rs"]
mod phase12_powerloss;
#[path = "audit8_salted/review_stress.rs"]
mod review_stress;
#[path = "audit8_salted/review_corruption.rs"]
mod review_corruption;
#[path = "audit8_salted/review_discard_crash.rs"]
mod review_discard_crash;
#[path = "audit8_salted/review_discard_model.rs"]
mod review_discard_model;
#[path = "audit8_salted/review_discard_storage.rs"]
mod review_discard_storage;
#[path = "audit8_salted/review_discard_engine.rs"]
mod review_discard_engine;
#[path = "audit8_salted/review_journal_torn_header.rs"]
mod review_journal_torn_header;
#[path = "audit8_salted/review_journal_legacy_torn_header.rs"]
mod review_journal_legacy_torn_header;
#[path = "audit8_salted/review_recovery_batch_latest.rs"]
mod review_recovery_batch_latest;
#[path = "audit8_salted/review_recovery_prefix_rewrite.rs"]
mod review_recovery_prefix_rewrite;
#[path = "audit8_salted/review_superblock_durability.rs"]
mod review_superblock_durability;
#[path = "audit8_salted/review_checkpoint_raise.rs"]
mod review_checkpoint_raise;
#[path = "audit8_salted/review_checkpoint_concurrency.rs"]
mod review_checkpoint_concurrency;
#[path = "audit8_salted/review_ab_retry.rs"]
mod review_ab_retry;
#[path = "audit8_salted/review_audit.rs"]
mod review_audit;
