//! Shared setup within this transport's authenticated integration tests.
use maki_backing::MemBacking;
use maki_core::engine::{AttachError, CheckpointPolicy, Engine, EngineOptions};
use maki_crypto::breaker::BreakerConfig;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::scheduler::{BatchScheduler, SchedulerConfig};
use maki_crypto::{
    CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit, SecretBuffer,
    SystemClock,
};
use maki_crypto_local::{keysource::MapKeySource, AesGcmSivProvider};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use std::sync::Arc;
use std::time::Duration;

pub const UNIT: usize = 512;
pub const PROFILE: &str = "r3-authenticated-v1";
pub const REMOTE_SECRET: &str = "SECRET plaintext=PRIVATE\ninjected";

fn simulated_engine_options() -> EngineOptions {
    EngineOptions {
        checkpoint: CheckpointPolicy {
            emergency_reserve_bytes: 0,
            ..Default::default()
        },
        ..Default::default()
    }
}

pub fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0xA311),
        format_version: 1,
        crypto_compatibility_id: PROFILE.into(),
    }
}
pub fn local(seed: u8) -> AesGcmSivProvider {
    let mut keys = MapKeySource::new();
    keys.insert("fixture", vec![seed; 32]);
    AesGcmSivProvider::new(&keys, "fixture", UNIT as u32, PROFILE).unwrap()
}
pub async fn capabilities() -> CryptoCapabilities {
    let mut caps = local(1).capabilities().await.unwrap();
    caps.batch.max_items = 16;
    caps.batch.max_bytes = 64 << 10;
    caps
}
pub fn plaintext() -> PlaintextUnit {
    PlaintextUnit {
        unit_index: 7,
        data: SecretBuffer::from_slice(&[0x41; UNIT]),
    }
}
pub fn assert_private(error: &CryptoError) {
    let message = format!("{error:?} {error}");
    assert!(
        !message.contains("SECRET")
            && !message.contains("PRIVATE")
            && !message.contains("injected"),
        "remote text leaked: {message}"
    );
}
pub fn pipeline(provider: Arc<dyn CryptoProvider>) -> Arc<dyn CryptoProvider> {
    let clock = Arc::new(SystemClock::new());
    let set = Arc::new(EndpointSet::new(
        vec![("authenticated".into(), provider)],
        DispatchConfig {
            retry: RetryPolicy {
                initial_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(2),
            },
            budget: RetryBudgetConfig {
                retry_ratio: 1.0,
                burst: 4,
                min_probe_per_sec: 1.0,
            },
            breaker: BreakerConfig {
                failure_threshold: 3,
                open_initial: Duration::from_millis(10),
                open_max: Duration::from_millis(20),
                half_open_max_requests: 1,
                success_threshold: 1,
            },
            global_max_inflight_batches: 4,
            global_max_inflight_bytes: 1 << 20,
            per_endpoint_max_inflight: 4,
            per_endpoint_max_bytes: 1 << 20,
            max_attempts: Some(1),
            max_operation_time: Some(Duration::from_secs(2)),
            retry_safe: true,
            validation_interval: Duration::from_secs(1),
        },
        clock.clone(),
    ));
    Arc::new(BatchScheduler::new(
        set,
        SchedulerConfig {
            target_items: 1,
            ..Default::default()
        },
        clock,
    ))
}
pub fn fresh_volume() -> Arc<MemBacking> {
    let backing = Arc::new(MemBacking::new());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: context().volume_uuid,
            provider_type: "remote-authenticated".into(),
            crypto_compatibility_id: PROFILE.into(),
            key_identity: "fixture".into(),
            geometry: Geometry::compute(
                512,
                UNIT as u32,
                512,
                UNIT as u32 + 28,
                128 * UNIT as u64,
                32 * UNIT as u64,
            )
            .unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    backing
}
pub async fn verify_engine(provider: Arc<dyn CryptoProvider>, wrong_key: Arc<dyn CryptoProvider>) {
    let backing = fresh_volume();
    let engine = Engine::attach(
        backing.clone(),
        pipeline(provider),
        simulated_engine_options(),
    )
    .await
    .unwrap();
    engine.write(0, &[0x61; UNIT], true).await.unwrap();
    assert_eq!(engine.read(0, UNIT).await.unwrap(), vec![0x61; UNIT]);
    engine.checkpoint().await.unwrap();
    drop(engine);
    assert!(
        matches!(
            Engine::attach(backing, pipeline(wrong_key), simulated_engine_options()).await,
            Err(AttachError::KeyMismatch(_))
        ),
        "a different remote key must fail the established canary"
    );
}
pub async fn verify_probes(provider: &dyn CryptoProvider) {
    let ct = provider
        .encrypt_batch(&context(), &[plaintext()])
        .await
        .unwrap();
    let pt = provider.decrypt_batch(&context(), &ct).await.unwrap();
    assert_eq!(pt[0].data.expose(), &[0x41; UNIT]);
    let mut tampered = ct[0].clone();
    tampered.data[20] ^= 1;
    let error = provider
        .decrypt_batch(&context(), &[tampered])
        .await
        .unwrap_err();
    assert!(matches!(error, CryptoError::Integrity(_)), "{error}");
    assert_private(&error);
    let mut moved = ct[0].clone();
    moved.unit_index += 1;
    assert!(matches!(
        provider.decrypt_batch(&context(), &[moved]).await,
        Err(CryptoError::Integrity(_))
    ));
    let mut other_volume = context();
    other_volume.volume_uuid = uuid::Uuid::from_u128(0xB311);
    assert!(matches!(
        provider.decrypt_batch(&other_volume, &ct).await,
        Err(CryptoError::Integrity(_))
    ));
}
