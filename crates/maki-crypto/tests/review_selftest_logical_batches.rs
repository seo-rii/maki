//! BUG-053: attach checks use plaintext batch bytes even for compact results.
#[path = "common/compact_provider.rs"]
mod compact;
use compact::{CompactProvider, UNIT};
use maki_crypto::selftest::{cross_endpoint_self_test, provider_conformance, provider_self_test};
use maki_crypto::{CryptoContext, CryptoProvider, PlaintextUnit, SecretBuffer};

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(53),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".into(),
    }
}

#[tokio::test]
async fn attach_selftest_splits_short_ciphertexts_by_the_original_unit_size() {
    let provider = CompactProvider::new(4, UNIT as u64, true);
    provider_self_test(&provider, &context(), UNIT as usize, "test-profile-v1")
        .await
        .unwrap();
    assert_eq!(&provider.encrypt_groups()[..3], &[1, 1, 1]);
    assert_eq!(&provider.decrypt_groups()[..3], &[1, 1, 1]);
}

#[tokio::test]
async fn conformance_wide_and_repeated_reads_keep_logical_limits() {
    let provider = CompactProvider::new(8, 2 * UNIT as u64, true);
    provider_conformance(&provider, &context(), UNIT as usize, "test-profile-v1")
        .await
        .unwrap();
    let decrypts = provider.decrypt_groups();
    assert_eq!(&decrypts[..2], &[2, 1]);
    assert!(decrypts.iter().all(|count| *count <= 2));
    assert_eq!(
        decrypts.last(),
        Some(&1),
        "the final repeat remains a single request"
    );
}

#[tokio::test]
async fn cross_endpoint_probes_respect_each_receivers_logical_budget() {
    let a = CompactProvider::new(4, 2 * UNIT as u64, true);
    let b = CompactProvider::new(4, UNIT as u64, true);
    cross_endpoint_self_test(&a, &b, &context(), UNIT as usize)
        .await
        .unwrap();
    assert_eq!(a.decrypt_groups(), vec![2, 1]);
    assert_eq!(b.decrypt_groups(), vec![1, 1, 1]);
}

#[tokio::test]
async fn ciphertext_overhead_does_not_reduce_a_valid_logical_batch() {
    let provider = CompactProvider::new(4, 2 * UNIT as u64, false);
    provider_self_test(&provider, &context(), UNIT as usize, "test-profile-v1")
        .await
        .unwrap();
    assert_eq!(&provider.decrypt_groups()[..2], &[2, 1]);
}

#[tokio::test]
async fn item_limit_still_bounds_attach_probes() {
    let provider = CompactProvider::new(1, 4 * UNIT as u64, true);
    provider_conformance(&provider, &context(), UNIT as usize, "test-profile-v1")
        .await
        .unwrap();
    assert!(provider.encrypt_groups().iter().all(|count| *count == 1));
    assert!(provider.decrypt_groups().iter().all(|count| *count == 1));
}

#[tokio::test]
async fn compact_encodings_are_stateless_and_interchangeable() {
    let a = CompactProvider::new(1, UNIT as u64, true);
    let b = CompactProvider::new(1, UNIT as u64, true);
    let plain = PlaintextUnit {
        unit_index: 17,
        data: SecretBuffer::from_slice(&[0x53; UNIT as usize]),
    };
    let ciphertext = a.encrypt_batch(&context(), &[plain]).await.unwrap();
    assert_eq!(ciphertext[0].data.len(), 520);
    assert_eq!(
        b.decrypt_batch(&context(), &ciphertext).await.unwrap()[0]
            .data
            .expose(),
        &[0x53; UNIT as usize]
    );
}
