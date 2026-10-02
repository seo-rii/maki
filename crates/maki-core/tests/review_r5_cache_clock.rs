//! R5-029: the plaintext cache was built with its own `SystemClock`, not
//! the engine's injectable clock, so its TTL ignored `EngineOptions::clock`
//! (`ManualClock` in tests) — against the rule that timing-sensitive code
//! uses the injected `Clock`.

use std::sync::Arc;
use std::time::Duration;

use maki_backing::Backing;
use maki_core::engine::{CheckpointPolicy, Engine, EngineCacheConfig, EngineOptions};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::{CrashableBacking, ManualClock};

#[tokio::test]
async fn the_cache_ttl_follows_the_engine_clock() {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xc10c),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, 1024, 512, 1032, 64 * 1024, 16 * 1024).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let clock = Arc::new(ManualClock::new());
    let engine = Engine::attach(
        backing.clone() as Arc<dyn Backing>,
        Arc::new(FakeCryptoProvider::new(1024)),
        EngineOptions {
            checkpoint: CheckpointPolicy {
                journal_high_watermark_bytes: u64::MAX,
                emergency_reserve_bytes: 0,
                low_space_checkpoint_bytes: 0,
                interval: Duration::from_secs(1 << 30),
                ..Default::default()
            },
            cache: Some(EngineCacheConfig {
                max_bytes: 64 * 1024,
                ttl: Duration::from_secs(30),
                verify_on_hit: false,
            }),
            clock: Some(clock.clone()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    engine.write(0, &[7; 1024], true).await.unwrap();
    engine.checkpoint().await.unwrap();
    engine.read(0, 1024).await.unwrap(); // miss, cached
    engine.read(0, 1024).await.unwrap(); // hit
    let stats = engine.monitoring_snapshot().cache.unwrap();
    assert_eq!(stats.hits, 1);

    clock.advance(Duration::from_secs(31));
    engine.read(0, 1024).await.unwrap();
    let after = engine.monitoring_snapshot().cache.unwrap();
    assert_eq!(
        after.hits, 1,
        "an entry past its TTL on the engine clock was served"
    );
    assert_eq!(after.misses, stats.misses + 1);
}
