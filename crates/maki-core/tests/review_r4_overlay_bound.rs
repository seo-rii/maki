//! R4-005: the ciphertext overlay (journaled, not yet checkpointed records
//! held in memory) has its own bound, independent of the on-disk journal
//! limit and of the remote-crypto pending-ciphertext budget.
//!
//! `journal_max_bytes` is a disk budget measured in GiB; an instance's RAM
//! budget is not the same number, and `limits.max_ciphertext_bytes` only
//! governs the remote scheduler's queue. Without an overlay bound a slow or
//! failing checkpoint let the overlay grow to the whole journal. With one,
//! a write that would exceed it first syncs and checkpoints inline (like
//! the journal hard limit), the worker checkpoints at half the bound, and
//! a write that cannot be admitted after reclaim fails with ENOSPC instead
//! of growing memory.
//!
//! Every test holds the process-global failpoint lock (one injects a
//! checkpoint fault); the guard is held across awaits of a single-threaded
//! runtime on purpose.
#![allow(clippy::await_holding_lock)]

use std::io;
use std::sync::Arc;
use std::time::Duration;

use uuid::Uuid;

use maki_backing::Backing;
use maki_core::engine::{CheckpointPolicy, Engine, EngineLimits, EngineOptions, EngineState};
use maki_core::volume::VolumeOptions;
use maki_crypto::Clock;
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::{failpoints, CrashableBacking, ManualClock};

const UNIT: u32 = 1024;
const UNITS: u64 = 256;
const SEGMENT: u64 = 64 * 1024;
/// Ciphertext of one unit as the overlay charges it.
const CT: u64 = UNIT as u64 + 8;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0x0BE4),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(
            512,
            UNIT,
            512,
            UNIT + 8,
            UNITS * UNIT as u64,
            32 * UNIT as u64,
        )
        .unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

/// Journal limits far above anything these tests write, so only the overlay
/// bound can trigger a checkpoint.
fn lenient_journal() -> CheckpointPolicy {
    CheckpointPolicy {
        journal_high_watermark_bytes: u64::MAX,
        journal_max_bytes: 64 << 20,
        max_pending_bytes: 64 << 20,
        emergency_reserve_bytes: 0,
        low_space_checkpoint_bytes: 0,
        interval: Duration::from_secs(3600),
    }
}

async fn engine(
    backing: &Arc<CrashableBacking>,
    limits: EngineLimits,
    clock: Option<Arc<dyn Clock>>,
) -> Engine {
    if !backing.exists("superblock.a").unwrap() {
        init::create_volume(backing.as_ref(), superblock()).unwrap();
    }
    Engine::attach(
        backing.clone() as Arc<dyn Backing>,
        Arc::new(FakeCryptoProvider::new(UNIT)),
        EngineOptions {
            volume: VolumeOptions {
                journal_segment_size: SEGMENT,
            },
            checkpoint: lenient_journal(),
            limits,
            clock,
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

fn off(unit: u64) -> u64 {
    unit * UNIT as u64
}

fn data(stamp: u8) -> Vec<u8> {
    vec![stamp; UNIT as usize]
}

fn manual_clock() -> Arc<dyn Clock> {
    Arc::new(ManualClock::new())
}

#[tokio::test]
async fn overlay_bytes_never_exceed_their_limit_under_sustained_writes() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    // Room for eight units held twice (latest + durable copy).
    let limit = 16 * CT;
    let engine = engine(
        &backing,
        EngineLimits {
            max_overlay_bytes: limit,
            ..Default::default()
        },
        Some(manual_clock()),
    )
    .await;

    for i in 0..96u64 {
        engine
            .write(off(i % 64), &data(i as u8), false)
            .await
            .unwrap_or_else(|e| panic!("write {i} failed: {e}"));
        let stats = engine.stats().await;
        assert!(
            stats.overlay_bytes <= limit,
            "write {i}: overlay {} exceeds limit {limit}",
            stats.overlay_bytes
        );
    }
    let stats = engine.stats().await;
    assert!(stats.checkpoints_total > 0, "inline reclaim must have run");
    assert_eq!(stats.state, EngineState::Ready);
    for unit in 0..64u64 {
        let expect = (32..96u64).find(|i| i % 64 == unit).unwrap() as u8;
        assert_eq!(
            engine.read(off(unit), UNIT as usize).await.unwrap(),
            data(expect)
        );
    }
}

#[tokio::test]
async fn overlay_entry_limit_bounds_the_number_of_units_held() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let engine = engine(
        &backing,
        EngineLimits {
            max_overlay_entries: 4,
            ..Default::default()
        },
        Some(manual_clock()),
    )
    .await;
    for i in 0..40u64 {
        engine.write(off(i), &data(i as u8), false).await.unwrap();
        let stats = engine.stats().await;
        assert!(
            stats.overlay_units <= 4,
            "write {i}: {} units in the overlay",
            stats.overlay_units
        );
    }
    assert!(engine.stats().await.checkpoints_total > 0);
    assert_eq!(engine.read(off(39), UNIT as usize).await.unwrap(), data(39));
}

#[tokio::test]
async fn worker_checkpoints_when_the_overlay_crosses_half_its_limit() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let limit = 16 * CT;
    let engine = engine(
        &backing,
        EngineLimits {
            max_overlay_bytes: limit,
            ..Default::default()
        },
        Some(manual_clock()),
    )
    .await;
    // Five distinct units, no FUA. Their projected charge (2 * 5 * CT) is
    // above the watermark (limit / 2 = 8 * CT) but below the limit itself,
    // so write admission never reclaims inline: only the worker, woken by
    // the watermark, can sync and checkpoint here — without the interval
    // elapsing (the clock is manual).
    for i in 0..5u64 {
        engine.write(off(i), &data(i as u8), false).await.unwrap();
    }
    let stats = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let s = engine.stats().await;
            if s.checkpoint_sequence >= 4 {
                break s;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the worker did not checkpoint on the overlay watermark");
    assert!(stats.checkpoints_total >= 1);
    assert!(stats.overlay_units <= 1, "{}", stats.overlay_units);
}

#[test]
fn failed_reclaim_at_the_overlay_limit_refuses_the_write_and_degrades() {
    let _guard = failpoints::test_lock();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let backing = Arc::new(CrashableBacking::new());
        let engine = engine(
            &backing,
            EngineLimits {
                max_overlay_bytes: 8 * CT,
                ..Default::default()
            },
            Some(manual_clock()),
        )
        .await;
        let fp = failpoints::set(
            "checkpoint.slot_write",
            failpoints::FailpointAction::IoError(io::ErrorKind::Other, "injected".to_string()),
        );
        let mut failed = None;
        for i in 0..32u64 {
            if let Err(e) = engine.write(off(i), &data(i as u8), false).await {
                failed = Some((i, e));
                break;
            }
            assert!(engine.stats().await.overlay_bytes <= 8 * CT);
        }
        let (at, err) = failed.expect("the overlay limit must refuse when reclaim fails");
        assert!(
            matches!(&err, maki_core::CoreError::Io(e)
                if matches!(e.kind(), io::ErrorKind::Other | io::ErrorKind::StorageFull)),
            "{err}"
        );
        assert!(matches!(engine.state(), EngineState::Degraded { .. }));
        assert!(engine.stats().await.overlay_bytes <= 8 * CT, "memory kept growing");
        // Acknowledged data stays readable.
        assert_eq!(
            engine.read(off(at - 1), UNIT as usize).await.unwrap(),
            data((at - 1) as u8)
        );
        drop(fp);
        engine.write(off(at), &data(0xEE), false).await.unwrap();
        assert_eq!(engine.state(), EngineState::Ready);
    });
}

#[tokio::test]
async fn a_zero_limit_keeps_the_overlay_unbounded_for_library_callers() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let engine = engine(&backing, EngineLimits::default(), Some(manual_clock())).await;
    for i in 0..48u64 {
        engine.write(off(i), &data(i as u8), false).await.unwrap();
    }
    let stats = engine.stats().await;
    assert_eq!(stats.checkpoints_total, 0);
    assert_eq!(stats.overlay_units, 48);
}
