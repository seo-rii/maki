//! Review R3-006: `CryptoContext` promises a context-binding capability ties
//! ciphertext to the volume UUID, the format version *and* the compatibility
//! id. The self-test probed only the unit index and the UUID, so a provider
//! that normalizes the other two fields was certified as fully bound. Every
//! context field now has a negative probe: decrypting under a foreign value
//! must not reproduce the plaintext (an explicit rejection is fine; only a
//! successful decrypt to the original is a broken binding).

use std::sync::Arc;

use async_trait::async_trait;

use maki_crypto::selftest::provider_self_test;
use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit,
};
use maki_test_support::fake_provider::FakeCryptoProvider;

const UNIT: usize = 256;
const PROFILE: &str = "test-profile-v1";

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x1234_5678_9abc_def0_1234_5678_9abc_def0),
        format_version: 1,
        crypto_compatibility_id: PROFILE.to_string(),
    }
}

fn fake() -> Arc<FakeCryptoProvider> {
    Arc::new(FakeCryptoProvider::new(UNIT as u32).with_context_binding(true))
}

/// Normalizes a context field before calling the inner (fully bound) fake, so
/// that field no longer takes part in the binding.
struct Normalizing {
    inner: Arc<FakeCryptoProvider>,
    normalize: fn(&mut CryptoContext),
}

#[async_trait]
impl CryptoProvider for Normalizing {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.inner.capabilities().await
    }
    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        let mut normalized = context.clone();
        (self.normalize)(&mut normalized);
        self.inner.encrypt_batch(&normalized, items).await
    }
    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        let mut normalized = context.clone();
        (self.normalize)(&mut normalized);
        self.inner.decrypt_batch(&normalized, items).await
    }
}

#[tokio::test]
async fn context_binding_selftest_exercises_format_version() {
    let provider = Normalizing {
        inner: fake(),
        normalize: |c| c.format_version = 1,
    };
    let result = provider_self_test(&provider, &ctx(), UNIT, PROFILE).await;
    assert!(
        result.is_err(),
        "a provider that ignores format_version must not be certified as context-bound"
    );
}

#[tokio::test]
async fn context_binding_selftest_exercises_compatibility_id() {
    let provider = Normalizing {
        inner: fake(),
        normalize: |c| c.crypto_compatibility_id = PROFILE.to_string(),
    };
    let result = provider_self_test(&provider, &ctx(), UNIT, PROFILE).await;
    assert!(
        result.is_err(),
        "a provider that ignores the compatibility id must not be certified as context-bound"
    );
}

/// A provider that refuses a foreign format version or compatibility id with
/// a plain request error (rather than decrypting to garbage) is honouring the
/// binding: the probes must accept an explicit rejection.
struct RejectsForeignContext(Arc<FakeCryptoProvider>);

impl RejectsForeignContext {
    fn check(context: &CryptoContext) -> Result<(), CryptoError> {
        if context.format_version != 1 || context.crypto_compatibility_id != PROFILE {
            return Err(CryptoError::NonRetryableRequest(
                "unsupported crypto context".into(),
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl CryptoProvider for RejectsForeignContext {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.0.capabilities().await
    }
    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        Self::check(context)?;
        self.0.encrypt_batch(context, items).await
    }
    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        Self::check(context)?;
        self.0.decrypt_batch(context, items).await
    }
}

#[tokio::test]
async fn explicit_rejection_of_a_foreign_context_passes_the_selftest() {
    let provider = RejectsForeignContext(fake());
    let result = provider_self_test(&provider, &ctx(), UNIT, PROFILE).await;
    assert!(
        result.is_ok(),
        "explicit rejection is a valid binding: {result:?}"
    );
}

/// The fully bound reference provider still passes every probe.
#[tokio::test]
async fn fully_bound_provider_passes_the_selftest() {
    let provider = fake();
    let result = provider_self_test(provider.as_ref(), &ctx(), UNIT, PROFILE).await;
    assert!(result.is_ok(), "{result:?}");
}

/// Answers every decrypt the same way, regardless of the ciphertext.
struct ConstantDecrypt {
    inner: Arc<FakeCryptoProvider>,
    error: fn() -> CryptoError,
}

#[async_trait]
impl CryptoProvider for ConstantDecrypt {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.inner.capabilities().await
    }
    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.inner.encrypt_batch(context, items).await
    }
    async fn decrypt_batch(
        &self,
        _context: &CryptoContext,
        _items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        Err((self.error)())
    }
}

/// "Integrity" for untampered ciphertext is not integrity: the round trip
/// fails first, so the tamper probe's evidence is never reached.
#[tokio::test]
async fn integrity_for_every_decrypt_never_certifies_a_provider() {
    let provider = ConstantDecrypt {
        inner: fake(),
        error: || CryptoError::Integrity("tag".into()),
    };
    assert!(provider_self_test(&provider, &ctx(), UNIT, PROFILE)
        .await
        .is_err());
}

#[tokio::test]
async fn retryable_for_every_decrypt_never_certifies_a_provider() {
    let provider = ConstantDecrypt {
        inner: fake(),
        error: || CryptoError::Retryable("later".into()),
    };
    let result = provider_self_test(&provider, &ctx(), UNIT, PROFILE).await;
    match result {
        Ok(()) => panic!("a provider that never decrypts must not pass"),
        Err(e) => assert!(
            e.is_retryable(),
            "transport trouble stays inconclusive: {e}"
        ),
    }
}
