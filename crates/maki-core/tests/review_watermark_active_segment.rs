//! The journal watermark must count only journal a checkpoint can delete.
//!
//! A checkpoint deletes covered sealed segments, never the active one. With
//! a library-configured watermark at or below the segment size, the active
//! segment alone kept the journal above the watermark after every
//! checkpoint, so every write above it woke the worker, and since the
//! watermark trigger syncs first each of those passes was a real journal
//! sync plus a checkpoint: a FLUSH-like barrier and an exclusive checkpoint
//! per write, without giving back a byte of journal. Such a pass belongs at
//! the roll that seals a segment, once per segment, like it is for every
//! validated daemon configuration (whose watermark, half the hard limit,
//! is above the largest active segment).
//!
//! The worker is woken here by a test-controlled "kick" through its clock
//! (the clock never advances, so the interval cannot trigger): after each
//! write the test runs one pass of its own and waits for it to finish, so
//! a pass that checkpoints for the active segment alone is observed
//! deterministically, whatever the timing of the worker's own wake-ups.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions, EngineStats};
use maki_core::volume::VolumeOptions;
use maki_crypto::{clock::SleepFuture, Clock};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::{CrashableBacking, FakeCryptoProvider, ManualClock};
use tokio::sync::Notify;

const UNIT: u64 = 1024;
/// A journal record of one unit: 32-byte header plus `UNIT + 8` bytes of
/// fake ciphertext.
const RECORD: u64 = 32 + UNIT + 8;
/// Fifteen records per segment: every fifteenth write after the first
/// segment rolls, sealing (and syncing) a full segment.
const SEGMENT: u64 = 16 * UNIT;
const RECORDS_PER_SEGMENT: u64 = 15;
// Fifteen records and the 48-byte segment header fit; a sixteenth does not.
const _: () = assert!(48 + RECORDS_PER_SEGMENT * RECORD <= SEGMENT);
const _: () = assert!(48 + (RECORDS_PER_SEGMENT + 1) * RECORD > SEGMENT);
/// Far below one segment: four records in the active segment reach it.
const WATERMARK: u64 = 4 * UNIT;

/// A manual clock whose sleeps a test can also end at once ("kick"), so the
/// worker runs one pass at the current time. It counts the sleeps (one per
/// worker loop iteration) and remembers which sleep the last kick ended.
struct KickClock {
    inner: ManualClock,
    sleeps: Arc<AtomicUsize>,
    kick: Arc<Notify>,
    kicks_taken: Arc<AtomicUsize>,
    last_kicked: Arc<AtomicUsize>,
}

impl Clock for KickClock {
    fn now(&self) -> Duration {
        self.inner.now()
    }

    fn sleep(&self, duration: Duration) -> SleepFuture {
        let sleep = self.inner.sleep(duration);
        let index = self.sleeps.fetch_add(1, Ordering::SeqCst) + 1;
        let kick = self.kick.clone();
        let taken = self.kicks_taken.clone();
        let last = self.last_kicked.clone();
        Box::pin(async move {
            tokio::select! {
                _ = sleep => {}
                _ = kick.notified() => {
                    last.store(index, Ordering::SeqCst);
                    taken.fetch_add(1, Ordering::SeqCst);
                }
            }
        })
    }
}

impl KickClock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: ManualClock::new(),
            sleeps: Arc::new(AtomicUsize::new(0)),
            kick: Arc::new(Notify::new()),
            kicks_taken: Arc::new(AtomicUsize::new(0)),
            last_kicked: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Wait until the worker is parked in a sleep.
    async fn parked(&self) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while self.sleeps.load(Ordering::SeqCst) == 0 || self.inner.sleeper_count() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the checkpoint worker must park");
    }

    /// End the worker's sleep and wait until the pass that follows has
    /// finished and the worker is parked again. That pass starts after
    /// everything the caller did before; a pass the worker started on its
    /// own may run before it, never after it without being waited for.
    async fn kicked_pass(&self, kicks: &mut usize) {
        *kicks += 1;
        self.kick.notify_one();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let last = self.last_kicked.load(Ordering::SeqCst);
                if self.kicks_taken.load(Ordering::SeqCst) == *kicks
                    && self.sleeps.load(Ordering::SeqCst) > last
                    && self.inner.sleeper_count() == 1
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the checkpoint worker must finish the kicked pass and park");
    }
}

async fn engine(backing: &Arc<CrashableBacking>, clock: &Arc<KickClock>) -> Engine {
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xAC71_5E61),
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
                journal_segment_size: SEGMENT,
            },
            checkpoint: CheckpointPolicy {
                journal_high_watermark_bytes: WATERMARK,
                journal_max_bytes: 1 << 20,
                // No write reaches the pending-bytes barrier, so every
                // explicit journal sync is the worker's.
                max_pending_bytes: 1 << 20,
                emergency_reserve_bytes: 0,
                low_space_checkpoint_bytes: 0,
                interval: Duration::from_secs(30),
            },
            clock: Some(clock.clone() as Arc<dyn Clock>),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    clock.parked().await;
    engine
}

fn applied(stats: &EngineStats) -> bool {
    stats.durable_sequence == stats.appended_sequence
        && stats.checkpoint_sequence == stats.appended_sequence
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watermark_below_the_segment_size_checkpoints_once_per_sealed_segment() {
    let backing = Arc::new(CrashableBacking::new());
    let clock = KickClock::new();
    let engine = engine(&backing, &clock).await;

    let mut kicks = 0;
    let mut rolls = 0u64;
    let mut above_watermark = 0u64;
    let writes = 3 * RECORDS_PER_SEGMENT + 1;
    for write in 1..=writes {
        let unit = write - 1;
        engine
            .write(unit * UNIT, &[unit as u8 + 1; UNIT as usize], false)
            .await
            .unwrap();
        let rolled = write > 1 && (write - 1) % RECORDS_PER_SEGMENT == 0;
        rolls += u64::from(rolled);
        clock.kicked_pass(&mut kicks).await;
        let stats = engine.stats().await;
        if !rolled && stats.journal_total_bytes >= WATERMARK {
            above_watermark += 1;
        }
        assert_eq!(
            stats.checkpoints_total, rolls,
            "write {write}: the worker checkpointed for an active segment it can never \
             delete ({rolls} segments sealed): {stats:?}"
        );
        assert_eq!(
            stats.journal_sync_latency.count, rolls,
            "write {write}: the worker synced the journal for an active segment it can \
             never delete ({rolls} segments sealed): {stats:?}"
        );
        if rolled {
            // The pass at the roll syncs the new active segment first, so it
            // applies everything and deletes the sealed segment.
            assert!(applied(&stats), "write {write}: {stats:?}");
            assert_eq!(stats.journal_segments, 1, "write {write}: {stats:?}");
        } else {
            assert!(
                stats.durable_sequence < stats.appended_sequence,
                "write {write}: nothing needed this write to become durable: {stats:?}"
            );
        }
    }
    assert_eq!(rolls, 3);
    assert!(
        above_watermark >= 20,
        "the active segment alone must have been above the watermark for most \
         writes ({above_watermark})"
    );
    // Every pass the worker ran was a kick or the wake-up of a write that
    // sealed a segment: writes that only fill the active segment do not
    // wake it.
    let passes = clock.sleeps.load(Ordering::SeqCst) - 1;
    assert!(
        passes as u64 <= kicks as u64 + rolls,
        "{passes} worker passes for {kicks} kicks and {rolls} sealed segments"
    );

    engine.flush().await.unwrap();
    for unit in 0..writes {
        assert_eq!(
            engine.read(unit * UNIT, UNIT as usize).await.unwrap(),
            vec![unit as u8 + 1; UNIT as usize],
            "unit {unit}"
        );
    }
    engine.stop_checkpoint_worker().await;
}
