//! Audit round 4 (crypto-dispatch): the attach self-test's compatibility-id
//! context-binding probe (R3-006, SPEC §18 "Context on the wire") never
//! reaches the provider when `crypto.random_prefix_bytes` is enabled.
//!
//! `RandomPrefixProvider::inner_context` refuses every outer compatibility
//! id other than its own derived id with
//! `UnsupportedContext(CompatibilityId)`, before any RPC. The probe accepts
//! exactly that refusal as proof, so a provider that declares context
//! binding but ignores the compatibility id on the wire passes attach with
//! the prefix enabled, while the same provider is refused without it.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use maki_crypto::selftest::provider_self_test;
use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError,
    CryptoProvider, PlaintextUnit, RandomPrefixProvider, SecretBuffer,
};

const LOGICAL: u32 = 64;
const PREFIX: u32 = 16;
const OVERHEAD: usize = 8;
const BASE: &str = "vendor-profile-v1";

/// Binds the volume UUID, unit index and format version into its keystream
/// and tag, but not the compatibility id: it decrypts ciphertext under any
/// profile name while declaring context binding.
struct IgnoresProfile {
    plain: u32,
    decrypts_with_foreign_profile: AtomicUsize,
}

fn key(ctx: &CryptoContext, unit: u64) -> u64 {
    (ctx.volume_uuid.as_u128() as u64)
        ^ ((ctx.volume_uuid.as_u128() >> 64) as u64).rotate_left(7)
        ^ unit.wrapping_mul(0x9E37_79B9_7F4A_7C15)
        ^ u64::from(ctx.format_version).rotate_left(41)
}

fn stream(mut x: u64, len: usize) -> Vec<u8> {
    x |= 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn tag(k: u64, body: &[u8]) -> u64 {
    body.iter().fold(k ^ 0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3)
    })
}

#[async_trait]
impl CryptoProvider for IgnoresProfile {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        Ok(CryptoCapabilities {
            provider_id: "ignores-profile".into(),
            crypto_compatibility_id: BASE.into(),
            supported_plaintext_sizes: vec![self.plain],
            max_ciphertext_size: self.plain + OVERHEAD as u32,
            stateless: true,
            retry_safe: true,
            batch: BatchCapability {
                supported: true,
                max_items: 16,
                max_bytes: 16 * u64::from(self.plain),
            },
            integrity: Capability::Contractual,
            context_binding: Capability::Contractual,
            replay_protection: Capability::Absent,
        })
    }

    async fn encrypt_batch(
        &self,
        ctx: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        Ok(items
            .iter()
            .map(|item| {
                let k = key(ctx, item.unit_index);
                let body: Vec<u8> = item
                    .data
                    .expose()
                    .iter()
                    .zip(stream(k, item.data.len()))
                    .map(|(p, s)| p ^ s)
                    .collect();
                let mut data = tag(k, &body).to_le_bytes().to_vec();
                data.extend_from_slice(&body);
                CiphertextUnit {
                    unit_index: item.unit_index,
                    data,
                }
            })
            .collect())
    }

    async fn decrypt_batch(
        &self,
        ctx: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        if ctx.crypto_compatibility_id != BASE {
            self.decrypts_with_foreign_profile
                .fetch_add(1, Ordering::SeqCst);
        }
        let mut out = Vec::new();
        for item in items {
            let k = key(ctx, item.unit_index);
            let (t, body) = item.data.split_at(OVERHEAD);
            if u64::from_le_bytes(t.try_into().unwrap()) != tag(k, body) {
                return Err(CryptoError::Integrity("tag mismatch".into()));
            }
            let plain: Vec<u8> = body
                .iter()
                .zip(stream(k, body.len()))
                .map(|(c, s)| c ^ s)
                .collect();
            out.push(PlaintextUnit {
                unit_index: item.unit_index,
                data: SecretBuffer::from_slice(&plain),
            });
        }
        Ok(out)
    }
}

fn context(compat: &str) -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x4A0D_17C0_FFEE),
        format_version: 3,
        crypto_compatibility_id: compat.into(),
    }
}

#[tokio::test]
async fn compat_id_binding_is_probed_without_a_prefix() {
    let provider = IgnoresProfile {
        plain: LOGICAL,
        decrypts_with_foreign_profile: AtomicUsize::new(0),
    };
    let result = provider_self_test(&provider, &context(BASE), LOGICAL as usize, BASE).await;
    let error = result.expect_err("a provider ignoring the compatibility id must be refused");
    assert!(
        error.to_string().contains("compatibility id"),
        "unexpected refusal: {error}"
    );
    assert_eq!(
        provider
            .decrypts_with_foreign_profile
            .load(Ordering::SeqCst),
        1
    );
}

#[tokio::test]
async fn compat_id_binding_is_never_probed_with_a_random_prefix() {
    let provider = Arc::new(IgnoresProfile {
        plain: LOGICAL + PREFIX,
        decrypts_with_foreign_profile: AtomicUsize::new(0),
    });
    let derived = format!("maki-random-prefix-v1:{PREFIX}:{BASE}");
    let wrapped = RandomPrefixProvider::new(provider.clone(), LOGICAL, PREFIX, derived.clone())
        .await
        .unwrap();
    // Same provider, same declared context binding: attach's self-test now
    // passes, and no probe ever carried a foreign profile on the wire.
    let result = provider_self_test(&wrapped, &context(&derived), LOGICAL as usize, &derived).await;
    assert!(
        result.is_err(),
        "the compatibility-id binding the provider declares was accepted without \
         being exercised (foreign-profile decrypts reaching the provider: {})",
        provider
            .decrypts_with_foreign_profile
            .load(Ordering::SeqCst)
    );
}
