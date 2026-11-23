//! Build guard: the nbdkit panic boundaries need `panic = "unwind"`.
//!
//! The plugin callbacks (`plugin::guarded`), the adapter's engine calls and
//! plugin startup catch panics with `catch_unwind` and report EIO or a failed
//! start (SPEC §48 panic containment). With `panic = "abort"`, whether from a
//! profile override such as `CARGO_PROFILE_RELEASE_PANIC=abort` or from
//! `-C panic=abort` in `RUSTFLAGS`, there is nothing to catch: the first panic
//! aborts nbdkit and every connection with it. Refuse to build instead.
//!
//! This file has no other items so `tests/review_panic_strategy.rs` can
//! compile it on its own.

#[cfg(not(panic = "unwind"))]
compile_error!(
    "maki-nbdkit requires panic = \"unwind\": its nbdkit callback, adapter and startup \
     boundaries catch panics with catch_unwind, and panic = \"abort\" turns every panic \
     into an nbdkit abort"
);
