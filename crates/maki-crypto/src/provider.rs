//! The `CryptoProvider` interface (SPEC §15).

use async_trait::async_trait;
use std::time::Duration;

use crate::error::CryptoError;
use crate::types::{CiphertextUnit, CryptoCapabilities, CryptoContext, PlaintextUnit};

// A private argument seals just the validation and self-test hooks.
// Third-party providers can implement CryptoProvider, but cannot exempt their
// output from scanning or answer the self-test's probe differently from an
// ordinary decrypt.
pub(crate) mod private {
    pub struct ValidationCaller;
    pub struct SelfTestCaller;
}

/// A local or remote cryptographic provider.
///
/// Contract (validated by the caller — see `validate_encrypt_result` and
/// `validate_decrypt_result` in `checked.rs`, applied by `CheckedProvider`):
/// - the result vector has exactly one entry per input item,
/// - in the same order, with matching `unit_index`,
/// - ciphertext never exceeds `capabilities().max_ciphertext_size`,
/// - a decrypt of corrupted ciphertext returns `CryptoError::Integrity`
///   (or another error) — never fabricated plaintext.
#[async_trait]
pub trait CryptoProvider: Send + Sync {
    /// Only report a completed scan when each returned ciphertext was checked
    /// against these exact plaintext bytes. Transforming wrappers need a new scan.
    #[doc(hidden)]
    fn checks_plaintext_echo(&self, _: private::ValidationCaller) -> bool {
        false
    }

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

    /// The attach self-test's compatibility-id probe (SPEC §18): decrypt
    /// `items`, made under `context`, under a compatibility id the volume
    /// does not use. The probe must reach the provider that binds the id, so
    /// the foreign id is chosen where the id goes on the wire, not by the
    /// caller: the random-prefix wrapper, which translates the id, forwards
    /// the probe with the context it sends below, and the other wrapping
    /// layers of this crate forward it unchanged. This default, for a
    /// provider that receives the id itself, decrypts under
    /// `<compatibility id>.selftest-probe`. Under a wrapper from another
    /// crate, which has this default, a random-prefix wrapper below receives
    /// an ordinary decrypt under a foreign id and refuses it; that refusal is
    /// not field evidence, so the self-test fails closed.
    #[doc(hidden)]
    async fn decrypt_compatibility_probe(
        &self,
        _caller: private::SelfTestCaller,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.decrypt_batch(
            &crate::selftest::foreign_compatibility_context(context),
            items,
        )
        .await
    }
}
