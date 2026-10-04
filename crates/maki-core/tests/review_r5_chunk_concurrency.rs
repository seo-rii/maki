//! R5-039: the engine awaited a request's provider batches one after
//! another. With a per-item HTTP mapping (one unit per batch) every unit
//! cost a full round trip: the 2026-10-04 Debian 13 campaign read at about
//! 100 KiB/s under 10 ms of latency. A request now runs its batches
//! concurrently, each extra one under an idle callback slot taken without
//! waiting, so `max_active_callbacks` still bounds provider concurrency
//! (SPEC §30) and waiting requests are not starved.

use std::sync::Arc;
use std::time::Duration;

use uuid::Uuid;

use maki_backing::Backing;
use maki_core::engine::{CheckpointPolicy, Engine, EngineLimits, EngineOptions};
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
        volume_uuid: Uuid::from_u128(0x39),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, UNIT, 512, UNIT + 8, DEVICE_SIZE, 64 * UNIT as u64)
            .unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

/// One unit per provider batch, 5 ms per call.
fn provider() -> Arc<FakeCryptoProvider> {
    let provider = Arc::new(FakeCryptoProvider::new(UNIT).with_max_batch(1, 1 << 20));
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    provider.set_latency(clock, Duration::from_millis(5));
    provider
}

async fn engine(
    backing: &Arc<CrashableBacking>,
    provider: Arc<FakeCryptoProvider>,
    max_active_callbacks: u32,
) -> Engine {
    if !backing.exists("superblock.a").unwrap() {
        init::create_volume(backing.as_ref(), superblock()).unwrap();
    }
    Engine::attach(
        backing.clone() as Arc<dyn Backing>,
        provider,
        EngineOptions {
            identity: None,
            volume: VolumeOptions::default(),
            limits: EngineLimits {
                max_active_callbacks,
                max_plaintext_bytes: 1 << 20,
                max_request_bytes: 1 << 20,
                ..EngineLimits::default()
            },
            cache: None,
            checkpoint: CheckpointPolicy {
                emergency_reserve_bytes: 0,
                ..Default::default()
            },
            clock: None,
        },
    )
    .await
    .unwrap()
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[tokio::test(start_paused = true)]
async fn one_request_runs_its_batches_concurrently_when_slots_are_idle() {
    let backing = Arc::new(CrashableBacking::new());
    let writer = provider();
    let engine_a = engine(&backing, writer.clone(), 64).await;
    let data = pattern(8 * UNIT as usize);
    engine_a.write(0, &data, true).await.unwrap();
    assert!(
        writer.max_concurrent_calls() >= 8,
        "eight single-unit encrypt batches ran {} at a time",
        writer.max_concurrent_calls()
    );
    drop(engine_a);

    let reader = provider();
    let engine_b = engine(&backing, reader.clone(), 64).await;
    assert_eq!(engine_b.read(0, data.len()).await.unwrap(), data);
    assert!(
        reader.max_concurrent_calls() >= 8,
        "eight single-unit decrypt batches ran {} at a time",
        reader.max_concurrent_calls()
    );
}

#[tokio::test(start_paused = true)]
async fn batch_concurrency_stays_within_max_active_callbacks() {
    let backing = Arc::new(CrashableBacking::new());
    let provider = provider();
    let engine = engine(&backing, provider.clone(), 3).await;
    let data = pattern(16 * UNIT as usize);
    let mut tasks = Vec::new();
    for request in 0..4u64 {
        let engine = engine.clone();
        let data = data.clone();
        tasks.push(tokio::spawn(async move {
            let offset = request * 16 * UNIT as u64;
            engine.write(offset, &data, false).await.unwrap();
            assert_eq!(engine.read(offset, data.len()).await.unwrap(), data);
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert!(
        provider.max_concurrent_calls() <= 3,
        "callback limit exceeded: {} concurrent provider calls",
        provider.max_concurrent_calls()
    );
    assert!(provider.max_concurrent_calls() > 1);
}
