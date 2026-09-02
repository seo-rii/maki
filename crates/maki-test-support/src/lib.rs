//! `maki-test-support` — the executable specification (SPEC §42).
//!
//! Phase 0 deliverables:
//! - [`model::ReferenceBlockModel`] — the durability oracle every phase is
//!   verified against,
//! - [`crash_backing::CrashableBacking`] — a `maki_backing::Backing` with
//!   POSIX-faithful crash semantics (unsynced writes may be lost or torn,
//!   unsynced dirents disappear, unsynced deletions resurrect),
//! - [`fake_provider::FakeCryptoProvider`] — deterministic, integrity-checking
//!   crypto fake with fault/misbehavior injection,
//! - [`clock::ManualClock`] — manually advanced `Clock`,
//! - [`sched::DeterministicScheduler`] — seeded single-thread interleaving
//!   executor,
//! - [`failpoints`] — named failpoints injected at persistence boundaries.

pub mod clock;
pub mod crash_backing;
pub mod failpoints;
pub mod fake_provider;
pub mod http_chaos;
pub mod model;
pub mod oracle;
pub mod sched;

pub use clock::ManualClock;
pub use crash_backing::CrashableBacking;
pub use fake_provider::FakeCryptoProvider;
pub use model::{OracleViolation, ReferenceBlockModel};
pub use sched::DeterministicScheduler;
