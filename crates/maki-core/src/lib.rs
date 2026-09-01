//! `maki-core` — the crash-consistent ciphertext block core.
//!
//! Phase 3: ciphertext journal, slot store, checkpointing, recovery
//! (SPEC §21–§27). Phase 4 layers crypto, RMW, and per-unit concurrency on
//! top; Phase 5 adds admission control.
//!
//! Failpoints: with the `failpoints` feature, every persistence boundary
//! calls into `maki_test_support::failpoints` under a stable name (see
//! `docs/phase-3.md` for the list).

pub mod error;
pub mod journal;
pub mod overlay;
pub mod recovery;
pub mod store;
pub mod volume;

pub use error::CoreError;

/// Evaluate a named failpoint (no-op without the `failpoints` feature).
#[inline]
pub(crate) fn fp(name: &str) -> std::io::Result<()> {
    #[cfg(feature = "failpoints")]
    {
        maki_test_support::failpoints::hit(name)
    }
    #[cfg(not(feature = "failpoints"))]
    {
        let _ = name;
        Ok(())
    }
}
