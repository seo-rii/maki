//! R3-006: every advertised context field must be exercised before attach.
use async_trait::async_trait;
use maki_crypto::selftest::provider_self_test;
use maki_crypto::{
    CiphertextUnit, ContextField, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    PlaintextUnit,
};
use maki_test_support::fake_provider::FakeCryptoProvider;

const UNIT: usize = 256;
const PROFILE: &str = "test-profile-v1";

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x6006),
        format_version: 1,
        crypto_compatibility_id: PROFILE.into(),
    }
}

#[derive(Clone, Copy)]
enum Probe {
    Format,
    Profile,
    Volume,
    Unit,
    Tamper,
}

struct RejectsProbe {
    inner: FakeCryptoProvider,
    probe: Probe,
    error: CryptoError,
}

#[async_trait]
impl CryptoProvider for RejectsProbe {
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
        ctx: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        let matches = match self.probe {
            Probe::Format => ctx.format_version != context().format_version,
            Probe::Profile => ctx.crypto_compatibility_id != PROFILE,
            Probe::Volume => ctx.volume_uuid != context().volume_uuid,
            Probe::Unit => items.len() == 1 && items[0].unit_index == 1,
            Probe::Tamper => items.len() == 1 && items[0].unit_index == 2,
        };
        if matches {
            return Err(self.error.duplicate());
        }
        self.inner.decrypt_batch(ctx, items).await
    }
}

#[tokio::test]
async fn matching_explicit_context_refusals_are_valid_only_for_that_probe() {
    for (probe, field) in [
        (Probe::Format, ContextField::FormatVersion),
        (Probe::Profile, ContextField::CompatibilityId),
    ] {
        let provider = RejectsProbe {
            inner: FakeCryptoProvider::new(UNIT as u32),
            probe,
            error: CryptoError::UnsupportedContext(field),
        };
        provider_self_test(&provider, &context(), UNIT, PROFILE)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn wrong_field_or_generic_errors_are_never_context_evidence() {
    for (probe, field) in [
        (Probe::Format, ContextField::CompatibilityId),
        (Probe::Profile, ContextField::FormatVersion),
        (Probe::Volume, ContextField::FormatVersion),
        (Probe::Unit, ContextField::CompatibilityId),
        (Probe::Tamper, ContextField::CompatibilityId),
    ] {
        let provider = RejectsProbe {
            inner: FakeCryptoProvider::new(UNIT as u32),
            probe,
            error: CryptoError::UnsupportedContext(field),
        };
        assert!(matches!(
            provider_self_test(&provider, &context(), UNIT, PROFILE).await,
            Err(CryptoError::ProviderFatal(_))
        ));
    }
    for probe in [Probe::Format, Probe::Profile] {
        for error in [
            CryptoError::ProviderFatal("bad profile".into()),
            CryptoError::NonRetryableRequest("bad request".into()),
        ] {
            let provider = RejectsProbe {
                inner: FakeCryptoProvider::new(UNIT as u32),
                probe,
                error,
            };
            assert!(matches!(
                provider_self_test(&provider, &context(), UNIT, PROFILE).await,
                Err(CryptoError::ProviderFatal(_))
            ));
        }
    }
}

#[tokio::test]
async fn unavailable_context_probes_remain_inconclusive() {
    for probe in [Probe::Format, Probe::Profile] {
        let provider = RejectsProbe {
            inner: FakeCryptoProvider::new(UNIT as u32),
            probe,
            error: CryptoError::Retryable("offline".into()),
        };
        assert!(matches!(
            provider_self_test(&provider, &context(), UNIT, PROFILE).await,
            Err(CryptoError::Retryable(_))
        ));
    }
}
