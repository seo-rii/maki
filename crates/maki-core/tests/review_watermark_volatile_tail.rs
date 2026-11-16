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
//!
//! A failed sync must not take away what those two triggers did before they
//! synced: a checkpoint of the records that are already durable, which
//! deletes covered sealed segments. With a journal whose syncs keep failing
//! and backing space running out, that is the only reclaim left.

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions, EngineState, EngineStats};
use maki_core::volume::VolumeOptions;
use maki_crypto::{clock::SleepFuture, Clock};
use maki_format::{geometry::Geometry, init, layout, superblock::Superblock};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::{CrashableBacking, FakeCryptoProvider, ManualClock};

const UNIT: u64 = 1024;
const INTERVAL: Duration = Duration::from_secs(30);
/// One segment holds a whole volatile-tail test: nothing rolls, so no record
/// becomes durable unless something syncs it.
const TAIL_SEGMENT: u64 = 128 * UNIT;
/// Three records per segment: the fourth write rolls, which seals and syncs
/// the full segment.
const SMALL_SEGMENT: u64 = 4096;

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
    journal_segment_size: u64,
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
                journal_segment_size,
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

/// Fail every journal segment fdatasync from now on, counting the attempts.
fn fail_journal_syncs(backing: &CrashableBacking) -> Arc<AtomicUsize> {
    let attempts = Arc::new(AtomicUsize::new(0));
    let counted = attempts.clone();
    let segments = format!("{}/", layout::JOURNAL_DIR);
    backing.set_fault_hook(Some(Arc::new(move |op: &FaultOp<'_>| match op {
        FaultOp::SyncData { path }
            if path
                .strip_prefix(segments.as_str())
                .and_then(layout::parse_journal_segment)
                .is_some() =>
        {
            counted.fetch_add(1, Ordering::SeqCst);
            Some(io::Error::other("injected journal sync failure"))
        }
        _ => None,
    })));
    attempts
}

async fn write(engine: &Engine, unit: u64, fua: bool) {
    engine
        .write(unit * UNIT, &[unit as u8 + 1; UNIT as usize], fua)
        .await
        .unwrap();
}

async fn assert_units(engine: &Engine, units: std::ops::Range<u64>) {
    for unit in units {
        assert_eq!(
            engine.read(unit * UNIT, UNIT as usize).await.unwrap(),
            vec![unit as u8 + 1; UNIT as usize],
            "unit {unit}"
        );
    }
}

/// After a pass whose journal sync failed: nothing new is durable, the
/// records that were durable are applied and their sealed segments deleted.
fn assert_durable_reclaimed(stats: &EngineStats, durable: u64) {
    assert_eq!(
        stats.durable_sequence, durable,
        "a failed sync proves nothing new"
    );
    assert_eq!(
        stats.checkpoint_sequence, durable,
        "the pass left durable records unapplied after its sync failed: {stats:?}"
    );
    assert_eq!(
        stats.journal_segments, 1,
        "covered sealed segments were not deleted: {stats:?}"
    );
    assert!(
        matches!(stats.state, EngineState::Degraded { .. }),
        "a failing journal is reported: {stats:?}"
    );
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
        TAIL_SEGMENT,
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
        TAIL_SEGMENT,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watermark_pass_reclaims_durable_segments_while_journal_sync_fails() {
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
        SMALL_SEGMENT,
    )
    .await;

    // Seven volatile writes: two rolls seal and sync two full segments, and
    // the journal stays below the watermark, so the worker keeps sleeping.
    for unit in 0..7 {
        write(&engine, unit, false).await;
    }
    let before = engine.stats().await;
    assert_eq!(
        (
            before.durable_sequence,
            before.checkpoint_sequence,
            before.journal_segments
        ),
        (6, 0, 3),
        "{before:?}"
    );
    assert!(before.journal_total_bytes < WATERMARK);

    // No journal sync succeeds from now on. One more volatile write fits the
    // active segment and crosses the watermark, which wakes the worker (the
    // journal is not sampled here: the pass may already have shrunk it).
    let attempts = fail_journal_syncs(&backing);
    let sleeps = clock.sleeps.load(Ordering::SeqCst);
    write(&engine, 7, false).await;
    clock.parked(sleeps + 1).await;

    let stats = engine.stats().await;
    assert!(attempts.load(Ordering::SeqCst) >= 1, "the pass syncs first");
    assert_durable_reclaimed(&stats, 6);
    assert!(stats.journal_total_bytes < WATERMARK, "{stats:?}");
    assert_units(&engine, 0..8).await;
    engine.stop_checkpoint_worker().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn low_space_pass_reclaims_durable_segments_while_journal_sync_fails() {
    const RESERVE: u64 = 1 << 20;
    let backing = Arc::new(CrashableBacking::new());
    backing.set_free_bytes(Some(1 << 30));
    let clock = clock();
    let engine = engine(
        &backing,
        &clock,
        CheckpointPolicy {
            journal_high_watermark_bytes: u64::MAX,
            journal_max_bytes: 1 << 20,
            max_pending_bytes: 1 << 20,
            // Admission refuses writes once space is low, which wakes the
            // worker within its interval.
            emergency_reserve_bytes: RESERVE,
            low_space_checkpoint_bytes: RESERVE,
            interval: INTERVAL,
        },
        SMALL_SEGMENT,
    )
    .await;

    // A checkpoint that makes progress 20 s into the worker's 30 s sleep
    // restarts the interval, so the pass that the sleep ends is not an
    // interval pass: only low free space triggers it.
    write(&engine, 0, true).await;
    clock.inner.advance(Duration::from_secs(20));
    assert_eq!(engine.checkpoint().await.unwrap(), 1);
    // Six volatile writes: two rolls seal and sync two full segments.
    for unit in 1..7 {
        write(&engine, unit, false).await;
    }
    let before = engine.stats().await;
    assert_eq!(
        (
            before.durable_sequence,
            before.checkpoint_sequence,
            before.journal_segments
        ),
        (6, 1, 3),
        "{before:?}"
    );

    // No journal sync succeeds from now on; one more volatile write, then
    // free space drops below the checkpoint reserve.
    let attempts = fail_journal_syncs(&backing);
    write(&engine, 7, false).await;
    backing.set_free_bytes(Some(RESERVE / 2));
    let sleeps = clock.sleeps.load(Ordering::SeqCst);
    clock.inner.advance(Duration::from_secs(11));
    clock.parked(sleeps + 1).await;

    let stats = engine.stats().await;
    assert!(attempts.load(Ordering::SeqCst) >= 1, "the pass syncs first");
    assert_durable_reclaimed(&stats, 6);

    // A write refused for space wakes the worker within the interval. The
    // failed sync still waits out the interval (BUG-101): no new attempt and
    // no checkpoint until then.
    let tried = attempts.load(Ordering::SeqCst);
    let checkpoints = stats.checkpoints_total;
    let sleeps = clock.sleeps.load(Ordering::SeqCst);
    let refused = engine
        .write(8 * UNIT, &[9; UNIT as usize], false)
        .await
        .unwrap_err();
    assert!(
        matches!(&refused, maki_core::CoreError::Io(e) if e.kind() == io::ErrorKind::StorageFull),
        "{refused}"
    );
    clock.parked(sleeps + 1).await;
    assert_eq!(attempts.load(Ordering::SeqCst), tried, "sync retried early");
    assert_eq!(engine.stats().await.checkpoints_total, checkpoints);

    // After the interval the worker tries the sync again.
    let sleeps = clock.sleeps.load(Ordering::SeqCst);
    clock.inner.advance(INTERVAL + Duration::from_secs(1));
    clock.parked(sleeps + 1).await;
    assert!(
        attempts.load(Ordering::SeqCst) > tried,
        "sync never retried"
    );
    assert_units(&engine, 0..8).await;
    engine.stop_checkpoint_worker().await;
}
