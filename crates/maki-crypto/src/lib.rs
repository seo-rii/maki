//! `maki-crypto` — the CryptoProvider abstraction and flow-control machinery.
//!
//! Phase 0: trait + core types (`SecretBuffer`, capabilities, errors, `Clock`).
//! Phase 2: provider self-test and batch-result validation.
//! Phase 5: batching, retry, retry budget, circuit breaker, endpoint set.

pub mod checked;
pub mod clock;
pub mod error;
pub mod provider;
pub mod secret;
pub mod selftest;
pub mod types;

pub use clock::{Clock, SystemClock};
pub use error::{CryptoError, ErrorClass};
pub use provider::CryptoProvider;
pub use secret::SecretBuffer;
pub use types::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, PlaintextUnit,
};
