//! BUG-051: cache reload validates every field before applying size and TTL.
use maki_backing::Backing;
use maki_control::server::ControlBackend;
use maki_core::engine::{CheckpointPolicy, Engine, EngineCacheConfig, EngineOptions};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_nbdkit::control::EngineControlBackend;
use maki_test_support::{fake_provider::FakeCryptoProvider, CrashableBacking, ManualClock};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

async fn fixture(cache: bool) -> (Engine, EngineControlBackend, Arc<ManualClock>) {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(51),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, 4096, 512, 4104, 64 * 4096, 16 * 4096).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let clock = Arc::new(ManualClock::new());
    let engine = Engine::attach(
        backing as Arc<dyn Backing>,
        Arc::new(FakeCryptoProvider::new(4096)),
        EngineOptions {
            cache: cache.then_some(EngineCacheConfig {
                max_bytes: 8192,
                ttl: Duration::from_secs(60),
                verify_on_hit: false,
            }),
            checkpoint: CheckpointPolicy {
                emergency_reserve_bytes: 0,
                interval: Duration::from_secs(3600),
                ..Default::default()
            },
            clock: Some(clock.clone()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    engine.write(0, &[0x51; 8192], true).await.unwrap();
    engine.read(0, 8192).await.unwrap();
    let backend = EngineControlBackend::new(engine.clone(), "ttl-reload");
    (engine, backend, clock)
}

#[tokio::test]
async fn size_and_ttl_are_both_applied_to_existing_entries() {
    let (engine, backend, clock) = fixture(true).await;
    backend
        .reload("cache", &json!({"max_bytes": 4096, "ttl": "1s"}))
        .await
        .unwrap();
    assert_eq!(engine.monitoring_snapshot().cache.unwrap().bytes, 4096);
    let before = engine.monitoring_snapshot().cache.unwrap();
    clock.advance(Duration::from_secs(2));
    engine.read(4096, 4096).await.unwrap();
    let after = engine.monitoring_snapshot().cache.unwrap();
    assert_eq!(
        after.hits, before.hits,
        "a shortened TTL must expire the existing entry"
    );
    assert_eq!(after.misses, before.misses + 1);
    engine.stop_checkpoint_worker().await;
}

#[tokio::test]
async fn invalid_ttl_and_unknown_fields_do_not_partially_resize() {
    let (engine, backend, clock) = fixture(true).await;
    for payload in [
        json!({"max_bytes": 4096, "ttl": "bogus"}),
        json!({"max_bytes": 4096, "ttl": "0s"}),
        json!({"max_bytes": 4096, "ttl": 1}),
        json!({"max_bytes": 4096, "ttl": null}),
        json!({"max_bytes": 4096, "ttl": "18446744073709551615m"}),
        json!({"max_bytes": 4096, "tt1": "1s"}),
        json!({"max_bytes": 4096, "unsupported": true}),
        json!({"max_bytes": 4096.5, "ttl": "1s"}),
        Value::Null,
    ] {
        let result = backend.reload("cache", &payload).await;
        assert!(result.is_err(), "invalid reload was accepted: {payload}");
        assert_eq!(
            engine.monitoring_snapshot().cache.unwrap().bytes,
            8192,
            "partially applied: {payload}"
        );
    }
    clock.advance(Duration::from_secs(2));
    let before = engine.monitoring_snapshot().cache.unwrap();
    engine.read(0, 8192).await.unwrap();
    let after = engine.monitoring_snapshot().cache.unwrap();
    assert_eq!(
        after.hits,
        before.hits + 2,
        "invalid reload changed the old TTL"
    );
    engine.stop_checkpoint_worker().await;
}

#[tokio::test]
async fn invalid_size_does_not_change_ttl() {
    let (engine, backend, clock) = fixture(true).await;
    for max_bytes in [0, u64::MAX] {
        assert!(backend
            .reload("cache", &json!({"max_bytes": max_bytes, "ttl": "1s"}))
            .await
            .is_err());
    }
    clock.advance(Duration::from_secs(2));
    let before = engine.monitoring_snapshot().cache.unwrap();
    engine.read(0, 8192).await.unwrap();
    assert_eq!(
        engine.monitoring_snapshot().cache.unwrap().hits,
        before.hits + 2
    );
    engine.stop_checkpoint_worker().await;
}

#[tokio::test]
async fn size_only_reload_preserves_ttl_and_longer_ttl_extends_entries() {
    let (engine, backend, clock) = fixture(true).await;
    backend
        .reload("cache", &json!({"max_bytes": 8192}))
        .await
        .unwrap();
    clock.advance(Duration::from_secs(2));
    let before = engine.monitoring_snapshot().cache.unwrap();
    engine.read(0, 4096).await.unwrap();
    assert_eq!(
        engine.monitoring_snapshot().cache.unwrap().hits,
        before.hits + 1
    );
    backend
        .reload("cache", &json!({"max_bytes": 8192, "ttl": "120s"}))
        .await
        .unwrap();
    clock.advance(Duration::from_secs(60));
    engine.read(0, 4096).await.unwrap();
    assert_eq!(
        engine.monitoring_snapshot().cache.unwrap().hits,
        before.hits + 2
    );
    engine.stop_checkpoint_worker().await;
}

#[tokio::test]
async fn cache_off_refuses_size_and_ttl_reload() {
    let (engine, backend, _) = fixture(false).await;
    assert!(backend
        .reload("cache", &json!({"max_bytes": 4096, "ttl": "1s"}))
        .await
        .is_err());
    assert_eq!(engine.monitoring_snapshot().cache.unwrap().bytes, 0);
    engine.stop_checkpoint_worker().await;
}
