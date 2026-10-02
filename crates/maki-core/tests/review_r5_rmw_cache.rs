//! R5-032: a partial-unit write reads, decrypts and re-encrypts the whole
//! unit. Reads already serve a cached `(unit, sequence)` without the
//! payload read or the provider call (R4-006); the read-modify-write path
//! ignored the cache and paid a provider round trip on every small write.

use std::sync::Arc;
use std::time::Duration;

use maki_backing::Backing;
use maki_core::engine::{CheckpointPolicy, Engine, EngineCacheConfig, EngineOptions};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::CrashableBacking;

async fn engine(verify_on_hit: bool) -> (Arc<FakeCryptoProvider>, Engine) {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0x5a11),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, 4096, 512, 4104, 256 * 1024, 64 * 1024).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let provider = Arc::new(FakeCryptoProvider::new(4096));
    let engine = Engine::attach(
        backing as Arc<dyn Backing>,
        provider.clone(),
        EngineOptions {
            checkpoint: CheckpointPolicy {
                journal_high_watermark_bytes: u64::MAX,
                emergency_reserve_bytes: 0,
                low_space_checkpoint_bytes: 0,
                interval: Duration::from_secs(3600),
                ..Default::default()
            },
            cache: Some(EngineCacheConfig {
                max_bytes: 1 << 20,
                ttl: Duration::from_secs(3600),
                verify_on_hit,
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    (provider, engine)
}

#[tokio::test]
async fn a_partial_write_over_a_cached_unit_needs_no_decryption() {
    for verify_on_hit in [false, true] {
        let (provider, engine) = engine(verify_on_hit).await;
        engine.write(0, &[1; 4096], true).await.unwrap();
        engine.checkpoint().await.unwrap();
        assert_eq!(engine.read(0, 4096).await.unwrap(), vec![1; 4096]); // cached
        let decrypts = provider.decrypt_calls();

        engine.write(512, &[2; 512], true).await.unwrap();
        assert_eq!(
            provider.decrypt_calls(),
            decrypts,
            "verify_on_hit={verify_on_hit}: the RMW decrypted a cached unit"
        );
        let mut expected = vec![1; 4096];
        expected[512..1024].fill(2);
        assert_eq!(engine.read(0, 4096).await.unwrap(), expected);
    }
}

#[tokio::test]
async fn a_partial_write_without_a_cached_copy_still_reads_the_unit() {
    let (provider, engine) = engine(false).await;
    engine.write(0, &[1; 4096], true).await.unwrap();
    engine.checkpoint().await.unwrap();
    let decrypts = provider.decrypt_calls();
    engine.write(512, &[2; 512], true).await.unwrap();
    assert_eq!(provider.decrypt_calls(), decrypts + 1);
    let mut expected = vec![1; 4096];
    expected[512..1024].fill(2);
    assert_eq!(engine.read(0, 4096).await.unwrap(), expected);
}
