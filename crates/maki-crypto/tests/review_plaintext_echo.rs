//! BUG-105: only the attach self-test looked for a provider that returns its
//! plaintext, and only for an exact echo. An endpoint that passed attach and
//! later echoed (a stub backend added behind a load balancer, a debug mode)
//! had its "ciphertext" accepted and persisted, and an echo with a tag
//! appended (`plaintext ‖ MAC`) or a nonce prepended passed even the
//! self-test. Every encrypt result is now refused when it carries its own
//! plaintext at either end, as a contract violation of that call.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;

use maki_crypto::checked::{validate_encrypt_result, CheckedProvider};
use maki_crypto::selftest::provider_self_test;
use maki_crypto::{
    Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    PlaintextUnit, SecretBuffer,
};
use maki_test_support::fake_provider::FakeCryptoProvider;

const UNIT: usize = 256;

/// Room for a 16-byte tag or a 12-byte nonce within the declared maximum,
/// so the echoes below break no other part of the contract.
fn fake() -> FakeCryptoProvider {
    FakeCryptoProvider::new(UNIT as u32).with_overhead(32)
}

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x0105),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".to_string(),
    }
}

fn pt(unit: u64) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: unit,
        data: SecretBuffer::from_slice(
            &(0..UNIT)
                .map(|i| (i as u8) ^ unit as u8)
                .collect::<Vec<_>>(),
        ),
    }
}

#[derive(Clone, Copy)]
enum Echo {
    Exact,
    WithTag,
    WithNonce,
}

fn echo(item: &PlaintextUnit, shape: Echo) -> CiphertextUnit {
    let plain = item.data.expose();
    let data = match shape {
        Echo::Exact => plain.to_vec(),
        Echo::WithTag => [plain, &[0xA5; 16]].concat(),
        Echo::WithNonce => [&[0x5A; 12][..], plain].concat(),
    };
    CiphertextUnit {
        unit_index: item.unit_index,
        data,
    }
}

async fn caps() -> CryptoCapabilities {
    fake().capabilities().await.unwrap()
}

#[tokio::test]
async fn an_encrypt_result_carrying_its_plaintext_is_a_contract_violation() {
    let caps = caps().await;
    let items = [pt(1), pt(2)];
    for shape in [Echo::Exact, Echo::WithTag, Echo::WithNonce] {
        let mut out: Vec<_> = items
            .iter()
            .map(|item| CiphertextUnit {
                unit_index: item.unit_index,
                data: vec![0x11; UNIT + 16],
            })
            .collect();
        validate_encrypt_result(&items, &out, &caps).expect("unrelated ciphertext is accepted");
        out[1] = echo(&items[1], shape);
        assert!(
            matches!(
                validate_encrypt_result(&items, &out, &caps),
                Err(CryptoError::Contract(_))
            ),
            "an echo of the plaintext was accepted as ciphertext"
        );
    }
}

/// Encrypts correctly until switched into one of the echo shapes; then it
/// "decrypts" by stripping the framing, so it round-trips perfectly. Like
/// any pass-through it can claim neither integrity nor context binding.
struct Switching {
    inner: FakeCryptoProvider,
    echo: AtomicBool,
    shape: Echo,
}

#[async_trait]
impl CryptoProvider for Switching {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        let mut caps = self.inner.capabilities().await?;
        caps.integrity = Capability::Absent;
        caps.context_binding = Capability::Absent;
        Ok(caps)
    }
    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        if self.echo.load(Ordering::SeqCst) {
            return Ok(items.iter().map(|item| echo(item, self.shape)).collect());
        }
        self.inner.encrypt_batch(context, items).await
    }
    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        if !self.echo.load(Ordering::SeqCst) {
            return self.inner.decrypt_batch(context, items).await;
        }
        Ok(items
            .iter()
            .map(|item| {
                let data = &item.data;
                let plain = match self.shape {
                    Echo::Exact => &data[..],
                    Echo::WithTag => &data[..data.len() - 16],
                    Echo::WithNonce => &data[12..],
                };
                PlaintextUnit {
                    unit_index: item.unit_index,
                    data: SecretBuffer::from_slice(plain),
                }
            })
            .collect())
    }
}

#[tokio::test]
async fn a_provider_that_starts_echoing_after_attach_is_refused_per_call() {
    for shape in [Echo::Exact, Echo::WithTag, Echo::WithNonce] {
        let provider = Arc::new(Switching {
            inner: fake(),
            echo: AtomicBool::new(false),
            shape,
        });
        let checked = CheckedProvider::new(provider.clone());
        checked.encrypt_batch(&ctx(), &[pt(3)]).await.unwrap();
        provider.echo.store(true, Ordering::SeqCst);
        assert!(matches!(
            checked.encrypt_batch(&ctx(), &[pt(3)]).await,
            Err(CryptoError::Contract(_))
        ));
    }
}

#[tokio::test]
async fn the_self_test_refuses_an_echo_with_a_tag_or_nonce() {
    for shape in [Echo::WithTag, Echo::WithNonce] {
        let provider = Switching {
            inner: fake(),
            echo: AtomicBool::new(true),
            shape,
        };
        assert!(
            provider_self_test(&provider, &ctx(), UNIT, "test-profile-v1")
                .await
                .is_err(),
            "a pass-through provider with framing passed the self-test"
        );
    }
}
