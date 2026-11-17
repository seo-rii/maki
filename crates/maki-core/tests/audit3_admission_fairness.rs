//! Audit round 3 (engine-concurrency): admission fairness under
//! contention. A request whose plaintext charge equals the whole admission
//! budget competes with a continuous stream of small requests on the same
//! and on other units. FIFO admission (count, then bytes) must let it in
//! after at most the requests that were already admitted or queued ahead of
//! it: it must not starve while small requests keep arriving, and no slot or
//! byte may stay charged afterwards.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use maki_core::engine::{CheckpointPolicy, Engine, EngineLimits, EngineOptions};
use maki_core::volume::VolumeOptions;
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::{CrashableBacking, FakeCryptoProvider};

const UNIT: usize = 2048;
const UNITS: usize = 32;

async fn engine(callbacks: u32, budget_units: u64) -> Engine {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume_with_discard(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xa3_fa_17),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(
                512,
                UNIT as u32,
                512,
                UNIT as u32 + 8,
                (UNITS * UNIT) as u64,
                8 * UNIT as u64,
            )
            .unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    Engine::attach(
        backing,
        Arc::new(FakeCryptoProvider::new(UNIT as u32).with_max_batch(1, 1 << 20)),
        EngineOptions {
            volume: VolumeOptions {
                journal_segment_size: 16 << 10,
            },
            limits: EngineLimits {
                max_active_callbacks: callbacks,
                max_plaintext_bytes: budget_units * UNIT as u64,
                max_request_bytes: 4 * UNIT as u64,
                max_overlay_bytes: 0,
                max_overlay_entries: 0,
            },
            cache: None,
            identity: None,
            checkpoint: CheckpointPolicy {
                journal_high_watermark_bytes: 32 << 10,
                journal_max_bytes: 1 << 30,
                max_pending_bytes: 1 << 20,
                emergency_reserve_bytes: 0,
                low_space_checkpoint_bytes: 0,
                interval: Duration::from_secs(3600),
            },
            clock: None,
        },
    )
    .await
    .unwrap()
}

async fn race(callbacks: u32) -> (u64, u64) {
    // 4 units + 1 unit of misalignment = 5 units = the whole budget.
    let engine = engine(callbacks, 5).await;
    let stop = Arc::new(AtomicBool::new(false));
    let small_done = Arc::new(AtomicU64::new(0));
    let mut smalls = Vec::new();
    for t in 0..6u64 {
        let engine = engine.clone();
        let stop = stop.clone();
        let small_done = small_done.clone();
        smalls.push(tokio::spawn(async move {
            let mut i = 0u64;
            while !stop.load(Ordering::SeqCst) {
                // Half on the big request's units, half elsewhere; partial
                // units so every one is an RMW.
                let unit = if i % 2 == 0 { 1 + (t % 4) } else { 8 + t };
                let off = unit * UNIT as u64 + 512;
                engine.write(off, &[t as u8 + 1; 512], false).await.unwrap();
                small_done.fetch_add(1, Ordering::SeqCst);
                i += 1;
                tokio::task::yield_now().await;
            }
        }));
    }
    // Let the stream saturate admission first.
    while small_done.load(Ordering::SeqCst) < 200 {
        tokio::task::yield_now().await;
    }
    let before = small_done.load(Ordering::SeqCst);
    let big = vec![0xbb; 4 * UNIT];
    tokio::time::timeout(
        Duration::from_secs(30),
        engine.write(UNIT as u64 + 1024, &big, false),
    )
    .await
    .expect("the full-budget write starved behind small requests")
    .unwrap();
    let overtakers = small_done.load(Ordering::SeqCst) - before;
    stop.store(true, Ordering::SeqCst);
    for s in smalls {
        s.await.unwrap();
    }
    let stats = engine.stats().await;
    let leaked = stats.admission_slots + stats.plaintext_bytes_in_flight;
    engine.stop_checkpoint_worker().await;
    (overtakers, leaked)
}

#[test]
fn full_budget_request_is_not_starved_by_small_ones() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    for callbacks in [2u32, 4, 8, 64] {
        let mut worst = 0;
        for _ in 0..20 {
            let (overtakers, leaked) = rt.block_on(race(callbacks));
            assert_eq!(leaked, 0, "admission charge leaked");
            worst = worst.max(overtakers);
        }
        eprintln!("callbacks {callbacks}: at most {worst} small writes completed while the full-budget write waited");
        // FIFO: only requests admitted or queued ahead of it (bounded by the
        // six writers plus the callback slots) may finish first.
        assert!(
            worst <= 6 + callbacks as u64 + 6,
            "{worst} small writes overtook the full-budget write (callbacks {callbacks})"
        );
    }
}
