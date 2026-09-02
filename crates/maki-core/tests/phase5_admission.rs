//! Phase 5 — engine admission control (SPEC §30, §47):
//! request-count and byte limits at the block-core entry, and FLUSH/FUA
//! behavior under queue saturation.

use std::sync::Arc;
use std::time::Duration;

use uuid::Uuid;

use maki_backing::Backing;
use maki_core::engine::{Engine, EngineLimits, EngineOptions};
use maki_core::volume::VolumeOptions;
use maki_crypto::{Clock, SystemClock};
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::CrashableBacking;

const UNIT: u32 = 1024;
const DEVICE_SIZE: u64 = 256 * UNIT as u64;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0x55),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, UNIT, 512, UNIT + 8, DEVICE_SIZE, 64 * UNIT as u64)
            .unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

async fn engine_with(
    backing: &Arc<CrashableBacking>,
    provider: Arc<FakeCryptoProvider>,
    limits: EngineLimits,
) -> Engine {
    if !backing.exists("superblock.a").unwrap() {
        init::create_volume(backing.as_ref(), superblock()).unwrap();
    }
    Engine::attach(
        backing.clone() as Arc<dyn Backing>,
        provider,
        EngineOptions {
            volume: VolumeOptions::default(),
            limits,
            cache: None,
        },
    )
    .await
    .unwrap()
}

/// max_active_callbacks bounds provider concurrency even with many pending
/// requests; FLUSH and FUA issued during saturation still complete and hold
/// their guarantees.
#[tokio::test(start_paused = true)]
async fn saturation_respects_callback_limit_and_flush_fua_complete() {
    let backing = Arc::new(CrashableBacking::new());
    let provider = Arc::new(FakeCryptoProvider::new(UNIT));
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    provider.set_latency(clock, Duration::from_millis(20));
    let engine = engine_with(
        &backing,
        provider.clone(),
        EngineLimits {
            max_active_callbacks: 2,
            max_plaintext_bytes: 1 << 20,
        },
    )
    .await;

    let mut tasks = Vec::new();
    for i in 0..12u64 {
        let engine = engine.clone();
        tasks.push(tokio::spawn(async move {
            engine
                .write(i * UNIT as u64, &vec![i as u8 + 1; UNIT as usize], false)
                .await
                .unwrap();
        }));
    }
    // FLUSH and FUA join the saturated pipeline.
    let flusher = {
        let engine = engine.clone();
        tokio::spawn(async move { engine.flush().await.unwrap() })
    };
    let fua = {
        let engine = engine.clone();
        tokio::spawn(async move {
            engine
                .write(100 * UNIT as u64, &vec![0xFA; UNIT as usize], true)
                .await
                .unwrap();
        })
    };
    for t in tasks {
        t.await.unwrap();
    }
    flusher.await.unwrap();
    fua.await.unwrap();

    assert!(
        provider.max_concurrent_calls() <= 2,
        "callback limit violated: {} concurrent provider calls",
        provider.max_concurrent_calls()
    );

    // FUA write durable across crash.
    drop(engine);
    backing.crash_all_lost();
    let provider2 = Arc::new(FakeCryptoProvider::new(UNIT));
    let engine = engine_with(&backing, provider2, EngineLimits::default()).await;
    assert_eq!(
        engine.read(100 * UNIT as u64, UNIT as usize).await.unwrap(),
        vec![0xFA; UNIT as usize]
    );
}

/// Byte limit admits large requests one at a time.
#[tokio::test(start_paused = true)]
async fn byte_admission_bounds_inflight_plaintext() {
    let backing = Arc::new(CrashableBacking::new());
    let provider = Arc::new(FakeCryptoProvider::new(UNIT));
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    provider.set_latency(clock, Duration::from_millis(5));
    let engine = engine_with(
        &backing,
        provider.clone(),
        EngineLimits {
            max_active_callbacks: 64,
            max_plaintext_bytes: UNIT as u64, // one unit at a time
        },
    )
    .await;

    let mut tasks = Vec::new();
    for i in 0..8u64 {
        let engine = engine.clone();
        tasks.push(tokio::spawn(async move {
            engine
                .write(i * UNIT as u64, &vec![7u8; UNIT as usize], false)
                .await
                .unwrap();
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    assert!(
        provider.max_concurrent_calls() <= 1,
        "byte admission violated: {}",
        provider.max_concurrent_calls()
    );
    // permit leak = 0: a full-size request still gets through afterwards.
    engine
        .write(0, &vec![9u8; UNIT as usize], true)
        .await
        .unwrap();
}
