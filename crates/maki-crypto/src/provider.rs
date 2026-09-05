//! The `CryptoProvider` interface (SPEC §15).

use async_trait::async_trait;
use std::time::Duration;

use crate::error::CryptoError;
use crate::types::{CiphertextUnit, CryptoCapabilities, CryptoContext, PlaintextUnit};

/// A local or remote cryptographic provider.
///
/// Contract (validated by the caller — see `batch_check` in Phase 2):
/// - the result vector has exactly one entry per input item,
/// - in the same order, with matching `unit_index`,
/// - ciphertext never exceeds `capabilities().max_ciphertext_size`,
/// - a decrypt of corrupted ciphertext returns `CryptoError::Integrity`
///   (or another error) — never fabricated plaintext.
#[async_trait]
pub trait CryptoProvider: Send + Sync {
    /// Maximum elapsed time for one caller operation, including admission
    /// and batching in outer wrappers. `None` keeps stall semantics.
    fn max_operation_time(&self) -> Option<Duration> {
        None
    }

    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError>;

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError>;

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError>;
}
