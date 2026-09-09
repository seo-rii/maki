//! R3-009: every conformance response is untrusted, including the final repeat.

use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use maki_crypto::selftest::provider_conformance;
use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit,
    SecretBuffer,
};
use maki_test_support::fake_provider::FakeCryptoProvider;

const UNIT: usize = 256;

#[derive(Clone, Copy, Debug)]
enum Shape {
    Empty,
    Extra,
    WrongIndex,
    WrongLength,
}

struct BadRepeat {
    inner: FakeCryptoProvider,
    shape: Shape,
    corrupt_encrypt: bool,
    repeated: AtomicBool,
}

#[async_trait]
impl CryptoProvider for BadRepeat {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.inner.capabilities().await
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        // The wide batch has already exercised this unit; only the final
        // single-unit repeat misbehaves. All earlier conformance probes pass.
        let repeated = items.len() == 1 && items[0].unit_index == 1000;
        self.repeated.store(repeated, Ordering::SeqCst);
        let mut out = self.inner.encrypt_batch(context, items).await?;
        if repeated && self.corrupt_encrypt {
            match self.shape {
                Shape::Empty => out.clear(),
                Shape::Extra => out.push(out[0].clone()),
                Shape::WrongIndex => out[0].unit_index += 1,
                Shape::WrongLength => out[0].data.resize(UNIT + 100, 0),
            }
        }
        Ok(out)
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        let mut out = self.inner.decrypt_batch(context, items).await?;
        if self.repeated.load(Ordering::SeqCst) && !self.corrupt_encrypt {
            match self.shape {
                Shape::Empty => out.clear(),
                Shape::Extra => out.push(PlaintextUnit {
                    unit_index: out[0].unit_index,
                    data: out[0].data.duplicate(),
                }),
                Shape::WrongIndex => out[0].unit_index += 1,
                Shape::WrongLength => out[0].data = SecretBuffer::from_slice(&[0; UNIT - 1]),
            }
        }
        Ok(out)
    }
}

async fn rejects(shape: Shape, corrupt_encrypt: bool) {
    let result = tokio::spawn(async move {
        let provider = BadRepeat {
            inner: FakeCryptoProvider::new(UNIT as u32),
            shape,
            corrupt_encrypt,
            repeated: AtomicBool::new(false),
        };
        provider_conformance(
            &provider,
            &CryptoContext {
                volume_uuid: uuid::Uuid::from_u128(0x9009),
                format_version: 1,
                crypto_compatibility_id: "test-profile-v1".into(),
            },
            UNIT,
            "test-profile-v1",
        )
        .await
    })
    .await
    .expect("malformed conformance responses must return an error, not panic");
    assert!(
        matches!(result, Err(CryptoError::Contract(_))),
        "malformed final {} {shape:?} response was not rejected as a contract violation: {result:?}",
        if corrupt_encrypt { "encrypt" } else { "decrypt" }
    );
}

macro_rules! regression {
    ($name:ident, $shape:ident, $encrypt:literal) => {
        #[tokio::test]
        async fn $name() {
            rejects(Shape::$shape, $encrypt).await;
        }
    };
}

regression!(repeat_encrypt_empty, Empty, true);
regression!(repeat_encrypt_extra, Extra, true);
regression!(repeat_encrypt_wrong_index, WrongIndex, true);
regression!(repeat_encrypt_wrong_length, WrongLength, true);
regression!(repeat_decrypt_empty, Empty, false);
regression!(repeat_decrypt_extra, Extra, false);
regression!(repeat_decrypt_wrong_index, WrongIndex, false);
regression!(repeat_decrypt_wrong_length, WrongLength, false);
