//! Regression tests for review M-004: the journal is bounded on every
//! runtime path, not only at clean shutdown. Sustained writes without any
//! explicit checkpoint must keep journal and overlay within their limits,
//! the background worker must checkpoint on the watermark and on time, the
//! unsynced tail must be bounded, low backing free space must refuse writes
//! before the backing fills, and a failed reclaim must be visible as a
//! degraded state that a later success clears.
//!
//! Every test holds the process-global failpoint lock (one test here injects
//! a checkpoint fault); holding a parking_lot guard across the awaits of a
//! single-threaded test runtime is intentional serialization, not a hazard.
#![allow(clippy::await_holding_lock)]

use std::io;
use std::sync::Arc;
use std::time::Duration;

use uuid::Uuid;

use maki_backing::Backing;
use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions, EngineState};
use maki_core::volume::VolumeOptions;
use maki_crypto::Clock;
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::{failpoints, CrashableBacking, ManualClock};

const UNIT: u32 = 1024;
const UNITS: u64 = 256;
const SEGMENT: u64 = 8192;
/// One journal record for a unit: 32-byte header + ciphertext (unit + 8).
const RECORD: u64 = 32 + UNIT as u64 + 8;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xB0DE),
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

fn policy() -> CheckpointPolicy {
    CheckpointPolicy {
        journal_high_watermark_bytes: 32 * 1024,
        journal_max_bytes: 64 * 1024,
        max_pending_bytes: 16 * 1024,
        emergency_reserve_bytes: 1 << 20,
        low_space_checkpoint_bytes: 0,
        interval: Duration::from_secs(30),
    }
}

async fn engine(
    backing: &Arc<CrashableBacking>,
    policy: CheckpointPolicy,
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
            checkpoint: policy,
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

async fn settle() {
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
}

// ---------- hard limit ----------

/// Sustained overwrites, no FUA, no explicit FLUSH or checkpoint: the
/// journal on disk never exceeds the hard limit (plus the segment being
/// filled), the overlay stays bounded, and every write succeeds.
#[tokio::test]
async fn sustained_writes_keep_journal_and_overlay_within_hard_limits() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let p = policy();
    let engine = engine(&backing, p.clone(), None).await;

    let mut max_journal = 0u64;
    let mut max_overlay = 0u64;
    for i in 0..600u64 {
        let unit = i % 64;
        engine
            .write(off(unit), &data(i as u8), false)
            .await
            .unwrap_or_else(|e| panic!("write {i} failed: {e}"));
        let s = engine.stats().await;
        max_journal = max_journal.max(s.journal_total_bytes);
        max_overlay = max_overlay.max(s.overlay_bytes);
        assert!(
            s.journal_total_bytes <= p.journal_max_bytes + SEGMENT + RECORD,
            "write {i}: journal {} exceeds hard limit {}",
            s.journal_total_bytes,
            p.journal_max_bytes
        );
    }
    let s = engine.stats().await;
    assert!(s.checkpoints_total > 0, "reclaim must have run");
    assert_eq!(s.state, EngineState::Ready);
    // Overlay is bounded by what one journal-full of records can hold, twice
    // over (latest + durable copies).
    assert!(
        max_overlay <= 2 * (p.journal_max_bytes + SEGMENT),
        "overlay peaked at {max_overlay}"
    );
    for unit in 0..64u64 {
        let expect = (536..600u64).find(|i| i % 64 == unit).unwrap() as u8;
        assert_eq!(
            engine.read(off(unit), UNIT as usize).await.unwrap(),
            data(expect)
        );
    }
    let _ = max_journal;
}

// ---------- worker ----------

#[tokio::test]
async fn worker_checkpoints_when_watermark_is_crossed() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let p = policy();
    let engine = engine(&backing, p.clone(), None).await;

    // Enough FUA writes to cross the watermark but stay under the hard cap.
    let n = p.journal_high_watermark_bytes / RECORD + 2;
    for i in 0..n {
        engine.write(off(i % UNITS), &data(1), true).await.unwrap();
    }
    settle().await;
    let s = engine.stats().await;
    assert!(s.checkpoints_total >= 1, "worker did not checkpoint: {s:?}");
    assert!(s.journal_total_bytes < p.journal_high_watermark_bytes);
    assert_eq!(s.checkpoint_sequence, s.durable_sequence);
}

#[tokio::test]
async fn worker_checkpoints_on_interval_and_syncs_pending_records() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let clock = Arc::new(ManualClock::new());
    let engine = engine(&backing, policy(), Some(clock.clone())).await;

    engine.write(off(3), &data(7), false).await.unwrap();
    settle().await;
    let before = engine.stats().await;
    assert_eq!(before.checkpoint_sequence, 0);
    assert_eq!(before.durable_sequence, 0, "not synced yet");

    clock.advance(Duration::from_secs(31));
    settle().await;
    let after = engine.stats().await;
    assert_eq!(after.durable_sequence, 1, "interval pass syncs the tail");
    assert_eq!(after.checkpoint_sequence, 1, "and applies it");
    assert_eq!(after.checkpoints_total, 1);

    // Nothing new: another interval is a no-op.
    clock.advance(Duration::from_secs(31));
    settle().await;
    assert_eq!(engine.stats().await.checkpoints_total, 1);
}

#[tokio::test]
async fn worker_stops_when_engine_is_dropped() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let clock = Arc::new(ManualClock::new());
    let engine = engine(&backing, policy(), Some(clock.clone())).await;
    settle().await;
    assert_eq!(clock.sleeper_count(), 1, "worker parked on the clock");
    drop(engine);
    settle().await;
    clock.advance(Duration::from_secs(31));
    settle().await;
    assert_eq!(clock.sleeper_count(), 0, "worker exited after drop");
}

// ---------- unsynced tail ----------

#[tokio::test]
async fn pending_bytes_limit_forces_journal_sync() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut p = policy();
    p.max_pending_bytes = 3 * RECORD;
    let engine = engine(&backing, p.clone(), None).await;

    // No FUA, no FLUSH: the unsynced tail must still never exceed the
    // limit, which means the write path forces barriers on its own.
    for i in 0..8u64 {
        engine.write(off(i), &data(1), false).await.unwrap();
        let s = engine.stats().await;
        assert!(
            s.journal_pending_bytes <= p.max_pending_bytes,
            "write {i}: pending {} > limit {}",
            s.journal_pending_bytes,
            p.max_pending_bytes
        );
    }
    let s = engine.stats().await;
    assert_eq!(s.appended_sequence, 8);
    assert!(s.durable_sequence >= 4, "barriers were forced: {s:?}");
    assert!(
        s.durable_sequence < 8,
        "the last write itself is not synced"
    );
}

// ---------- free space ----------

#[tokio::test]
async fn emergency_reserve_refuses_writes_until_space_returns() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let clock = Arc::new(ManualClock::new());
    let engine = engine(&backing, policy(), Some(clock.clone())).await;
    engine.write(off(0), &data(0xAA), true).await.unwrap();

    backing.set_free_bytes(Some(4096));
    clock.advance(Duration::from_secs(2)); // free-space cache expires
    let err = engine.write(off(1), &data(1), false).await.unwrap_err();
    match err {
        maki_core::CoreError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::StorageFull),
        other => panic!("expected ENOSPC, got {other}"),
    }
    // Reads keep working; the metric shows the shortage.
    assert_eq!(
        engine.read(off(0), UNIT as usize).await.unwrap(),
        data(0xAA)
    );
    assert_eq!(engine.stats().await.backing_free_bytes, Some(4096));

    backing.set_free_bytes(Some(1 << 30));
    clock.advance(Duration::from_secs(2));
    engine.write(off(1), &data(1), false).await.unwrap();
}

// ---------- degraded state ----------

#[test]
fn failed_reclaim_at_hard_limit_degrades_then_recovers() {
    // Failpoints are process-global: hold the lock from a sync test and
    // drive the async body on a private runtime.
    let _guard = failpoints::test_lock();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
    let backing = Arc::new(CrashableBacking::new());
    let mut p = policy();
    p.journal_max_bytes = 2 * SEGMENT + 4096;
    p.journal_high_watermark_bytes = u64::MAX; // keep the worker out of it
    let engine = engine(&backing, p, None).await;

    let fp = failpoints::set(
        "checkpoint.slot_write",
        failpoints::FailpointAction::IoError(io::ErrorKind::Other, "injected".to_string()),
    );
    let mut failed = None;
    for i in 0..64u64 {
        if let Err(e) = engine.write(off(i % 8), &data(i as u8), false).await {
            failed = Some((i, e));
            break;
        }
    }
    let (at, err) = failed.expect("hard limit must refuse when reclaim fails");
    assert!(
        matches!(&err, maki_core::CoreError::Io(e) if e.kind() == io::ErrorKind::Other)
            || matches!(&err, maki_core::CoreError::Io(e) if e.kind() == io::ErrorKind::StorageFull),
        "{err}"
    );
    assert!(matches!(engine.state(), EngineState::Degraded { .. }));
    assert!(engine.stats().await.checkpoint_failures_total >= 1);
    // Reads still work on the data acknowledged so far.
    let last_ok = at - 1;
    assert_eq!(
        engine.read(off(last_ok % 8), UNIT as usize).await.unwrap(),
        data(last_ok as u8)
    );

    drop(fp);
    engine.write(off(0), &data(0xEE), false).await.unwrap();
    assert_eq!(engine.state(), EngineState::Ready, "success clears degraded");
    assert_eq!(engine.read(off(0), UNIT as usize).await.unwrap(), data(0xEE));
    });
}
