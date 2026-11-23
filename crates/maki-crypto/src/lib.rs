//! `maki-crypto` — the CryptoProvider abstraction and flow-control machinery.
//!
//! Phase 0: trait + core types (`SecretBuffer`, capabilities, errors, `Clock`).
//! Phase 2: provider self-test and batch-result validation.
//! Phase 5: batching, retry, retry budget, circuit breaker, endpoint set.

// Diagnostics go through `tracing`: the `print!` family panics when the
// write fails (a closed pipe, a full disk). Tests may print.
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]

pub mod breaker;
pub mod checked;
pub mod clock;
pub mod endpoint;
pub mod error;
pub mod flow;
pub mod provider;
pub mod random_prefix;
pub mod retry;
pub mod scheduler;
pub mod secret;
pub mod selftest;
pub mod types;

pub use clock::{Clock, SystemClock};
pub use error::{ContextField, CryptoError, ErrorClass, NotSentError};
pub use provider::CryptoProvider;
pub use random_prefix::RandomPrefixProvider;
pub use secret::{SecretBox, SecretBuffer};
pub use types::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, PlaintextUnit,
};
