//! The public constructor must reject sizes whose ciphertext length cannot
//! be represented by the capability report, without allocating a whole unit.

use maki_crypto::{CryptoContext, CryptoError, CryptoProvider, PlaintextUnit, SecretBuffer};
use maki_crypto_local::gcm_siv::GCM_SIV_OVERHEAD;
use maki_crypto_local::keysource::MapKeySource;
use maki_crypto_local::AesGcmSivProvider;

const COMPATIBILITY_ID: &str = "local-gcm-siv-size-bound";

fn keys() -> MapKeySource {
    let mut keys = MapKeySource::new();
    keys.insert("key", vec![0x31; 32]);
    keys
}

#[tokio::test]
async fn largest_representable_ciphertext_size_is_reported_exactly() {
    let unit_size = u32::MAX - GCM_SIV_OVERHEAD;
    let provider = AesGcmSivProvider::new(&keys(), "key", unit_size, COMPATIBILITY_ID).unwrap();
    let capabilities = provider.capabilities().await.unwrap();
    assert_eq!(capabilities.supported_plaintext_sizes, [unit_size]);
    assert_eq!(capabilities.max_ciphertext_size, u32::MAX);
}

#[test]
fn constructor_rejects_all_unrepresentable_ciphertext_sizes() {
    for unit_size in (u32::MAX - GCM_SIV_OVERHEAD + 1)..=u32::MAX {
        let result = AesGcmSivProvider::new(&keys(), "key", unit_size, COMPATIBILITY_ID);
        assert!(
            matches!(result, Err(CryptoError::ProviderFatal(_))),
            "unit_size {unit_size} must be rejected at construction: {result:?}"
        );
    }
}

#[tokio::test]
async fn representable_sizes_keep_exact_ciphertext_lengths_and_round_trip() {
    let context = CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0xAABB),
        format_version: 1,
        crypto_compatibility_id: COMPATIBILITY_ID.to_string(),
    };
    // The provider API does not impose the daemon's block geometry rules.
    for unit_size in [0, 1, 4096] {
        let provider = AesGcmSivProvider::new(&keys(), "key", unit_size, COMPATIBILITY_ID).unwrap();
        let plaintext = PlaintextUnit {
            unit_index: 7,
            data: SecretBuffer::from_slice(&vec![0x5A; unit_size as usize]),
        };
        let ciphertext = provider
            .encrypt_batch(&context, std::slice::from_ref(&plaintext))
            .await
            .unwrap();
        let capabilities = provider.capabilities().await.unwrap();
        assert_eq!(
            capabilities.max_ciphertext_size,
            unit_size + GCM_SIV_OVERHEAD
        );
        assert_eq!(ciphertext.len(), 1);
        assert_eq!(
            ciphertext[0].data.len(),
            capabilities.max_ciphertext_size as usize
        );
        let decrypted = provider.decrypt_batch(&context, &ciphertext).await.unwrap();
        assert_eq!(decrypted.len(), 1);
        assert_eq!(decrypted[0].unit_index, plaintext.unit_index);
        assert_eq!(decrypted[0].data.expose(), plaintext.data.expose());
    }
}
