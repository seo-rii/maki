//! A worker checkpoint applies only durable records, so every trigger that
//! exists to shrink the journal must sync an unsynced tail first.
//!
//! The interval, overlay and space-refusal triggers did; the journal-size
//! watermark and the low-free-space trigger did not. With volatile records
//! (no FUA, no FLUSH) above the watermark, every write woke the worker into
//! a checkpoint that applied nothing: two exclusive volume-lock passes and
//! overlay scans per write, `checkpoints_total` counting them, and the
//! journal growing toward its hard limit while the checkpoint sequence
//! stayed put. Syncing from the worker is the same barrier the interval
//! trigger already uses.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions, EngineStats};
use maki_core::volume::VolumeOptions;
use maki_crypto::{clock::SleepFuture, Clock};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::{CrashableBacking, FakeCryptoProvider, ManualClock};

const UNIT: u64 = 1024;
const INTERVAL: Duration = Duration::from_secs(30);

/// A manual clock that counts sleeps: the worker creates one at the top of
/// every loop iteration, so a new sleep means its previous pass finished.
struct ObservedClock {
    inner: ManualClock,
    sleeps: AtomicUsize,
}

impl Clock for ObservedClock {
    fn now(&self) -> Duration {
        self.inner.now()
    }

    fn sleep(&self, duration: Duration) -> SleepFuture {
        let sleep = self.inner.sleep(duration);
        self.sleeps.fetch_add(1, Ordering::SeqCst);
        sleep
    }
}

impl ObservedClock {
    /// Wait until the worker has finished a pass and parked again.
    async fn parked(&self, minimum_sleeps: usize) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while self.sleeps.load(Ordering::SeqCst) < minimum_sleeps
                || self.inner.sleeper_count() != 1
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the checkpoint worker must finish its pass and park");
    }
}

async fn engine(
    backing: &Arc<CrashableBacking>,
    clock: &Arc<ObservedClock>,
    checkpoint: CheckpointPolicy,
) -> Engine {
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0x7A11_5EC5),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(
                512,
                UNIT as u32,
                512,
                UNIT as u32 + 8,
                256 * UNIT,
                64 * UNIT,
            )
            .unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let engine = Engine::attach(
        backing.clone(),
        Arc::new(FakeCryptoProvider::new(UNIT as u32)),
        EngineOptions {
            volume: VolumeOptions {
                // One segment holds the whole test: nothing rolls, so no
                // record becomes durable unless something syncs it.
                journal_segment_size: 64 * UNIT * 2,
            },
            checkpoint,
            clock: Some(clock.clone() as Arc<dyn Clock>),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    clock.parked(1).await;
    engine
}

fn clock() -> Arc<ObservedClock> {
    Arc::new(ObservedClock {
        inner: ManualClock::new(),
        sleeps: AtomicUsize::new(0),
    })
}

fn applied(stats: &EngineStats) -> bool {
    stats.durable_sequence == stats.appended_sequence
        && stats.checkpoint_sequence == stats.appended_sequence
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watermark_checkpoint_applies_a_volatile_tail() {
    const WATERMARK: u64 = 8 * UNIT;
    let backing = Arc::new(CrashableBacking::new());
    let clock = clock();
    let engine = engine(
        &backing,
        &clock,
        CheckpointPolicy {
            journal_high_watermark_bytes: WATERMARK,
            journal_max_bytes: 1 << 20,
            max_pending_bytes: 1 << 20,
            emergency_reserve_bytes: 0,
            low_space_checkpoint_bytes: 0,
            interval: INTERVAL,
        },
    )
    .await;

    // Volatile writes up to the watermark; the clock never moves, so only
    // the watermark can trigger the worker, first after the crossing write.
    let mut unit = 0u64;
    loop {
        let sleeps = clock.sleeps.load(Ordering::SeqCst);
        engine
            .write(unit * UNIT, &[0x33; UNIT as usize], false)
            .await
            .unwrap();
        unit += 1;
        if engine.stats().await.journal_total_bytes >= WATERMARK {
            clock.parked(sleeps + 1).await;
            break;
        }
    }
    let start = engine.stats().await;
    assert!(
        applied(&start),
        "the watermark pass ran without applying the volatile tail: {start:?}"
    );

    // Each further volatile write wakes the worker; each pass must apply it.
    for write in 0..20u64 {
        let sleeps = clock.sleeps.load(Ordering::SeqCst);
        engine
            .write(unit * UNIT, &[0x44; UNIT as usize], false)
            .await
            .unwrap();
        unit += 1;
        clock.parked(sleeps + 1).await;
        let stats = engine.stats().await;
        assert!(
            applied(&stats),
            "write {write}: a watermark pass did not apply the volatile tail \
             ({} checkpoints since the watermark): {stats:?}",
            stats.checkpoints_total - start.checkpoints_total
        );
    }
    for written in 0..unit {
        let expected = if written < unit - 20 { 0x33 } else { 0x44 };
        assert_eq!(
            engine.read(written * UNIT, UNIT as usize).await.unwrap(),
            vec![expected; UNIT as usize]
        );
    }
    engine.stop_checkpoint_worker().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn low_space_checkpoint_applies_a_volatile_tail() {
    const RESERVE: u64 = 1 << 20;
    let backing = Arc::new(CrashableBacking::new());
    let clock = clock();
    let engine = engine(
        &backing,
        &clock,
        CheckpointPolicy {
            journal_high_watermark_bytes: u64::MAX,
            journal_max_bytes: 1 << 20,
            max_pending_bytes: 1 << 20,
            // Admission keeps its opt-out; only the worker watches space.
            emergency_reserve_bytes: 0,
            low_space_checkpoint_bytes: RESERVE,
            interval: INTERVAL,
        },
    )
    .await;

    // A checkpoint that makes progress 20 s into the worker's 30 s sleep
    // restarts the interval, so the pass that the sleep ends is not an
    // interval pass: only low free space triggers it.
    engine.write(0, &[0x51; UNIT as usize], true).await.unwrap();
    clock.inner.advance(Duration::from_secs(20));
    assert_eq!(engine.checkpoint().await.unwrap(), 1);
    engine
        .write(UNIT, &[0x52; UNIT as usize], false)
        .await
        .unwrap();
    backing.set_free_bytes(Some(RESERVE / 2));

    let sleeps = clock.sleeps.load(Ordering::SeqCst);
    clock.inner.advance(Duration::from_secs(11));
    clock.parked(sleeps + 1).await;
    let stats = engine.stats().await;
    assert!(
        stats.checkpoints_total >= 2,
        "the low-space pass did not run: {stats:?}"
    );
    assert!(
        applied(&stats),
        "the low-space pass ran without applying the volatile tail: {stats:?}"
    );
    assert_eq!(
        engine.read(UNIT, UNIT as usize).await.unwrap(),
        vec![0x52; UNIT as usize]
    );
    engine.stop_checkpoint_worker().await;
}
