//! Audit (core write path): the journal-size watermark trigger does not sync
//! before checkpointing (only the interval, overlay and space-refusal
//! triggers do). With a volatile journal tail above the watermark, every
//! write wakes the worker, which runs a checkpoint that can apply nothing
//! (durable <= checkpoint): two exclusive volume-lock acquisitions and two
//! O(overlay) scans per write, while the journal keeps growing toward the
//! hard limit. The watermark never shrinks the journal on its own.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
use maki_crypto::{clock::SleepFuture, Clock};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::{CrashableBacking, FakeCryptoProvider, ManualClock};

struct ObservedClock {
    inner: ManualClock,
    sleeps: AtomicUsize,
}

impl Clock for ObservedClock {
    fn now(&self) -> Duration {
        self.inner.now()
    }
    fn sleep(&self, duration: Duration) -> SleepFuture {
        let result = self.inner.sleep(duration);
        self.sleeps.fetch_add(1, Ordering::SeqCst);
        result
    }
}

async fn parked(clock: &ObservedClock, minimum_sleeps: usize) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while clock.sleeps.load(Ordering::SeqCst) < minimum_sleeps
            || clock.inner.sleeper_count() != 1
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("worker must complete a pass and park");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watermark_wakeups_run_useless_checkpoints_for_a_volatile_tail() {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xa0d1_3a7e),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "audit".into(),
            geometry: Geometry::compute(512, 1024, 512, 1032, 256 * 1024, 64 * 1024).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let clock = Arc::new(ObservedClock {
        inner: ManualClock::new(),
        sleeps: AtomicUsize::new(0),
    });
    let engine = Engine::attach(
        backing,
        Arc::new(FakeCryptoProvider::new(1024)),
        EngineOptions {
            checkpoint: CheckpointPolicy {
                interval: Duration::from_secs(30),
                journal_high_watermark_bytes: 8 * 1024,
                journal_max_bytes: 1 << 20,
                max_pending_bytes: 1 << 20,
                emergency_reserve_bytes: 0,
                low_space_checkpoint_bytes: 0,
            },
            clock: Some(clock.clone() as Arc<dyn Clock>),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    parked(&clock, 1).await;

    // Volatile writes (no FUA, no FLUSH) past the watermark.
    let mut unit = 0u64;
    while engine.stats().await.journal_total_bytes < 8 * 1024 {
        engine.write(unit * 1024, &[0x33; 1024], false).await.unwrap();
        unit += 1;
    }
    let before = clock.sleeps.load(Ordering::SeqCst);
    parked(&clock, before).await;
    let start = engine.stats().await;

    // Each further write wakes the worker; let it finish each pass.
    const WRITES: u64 = 20;
    for _ in 0..WRITES {
        let sleeps = clock.sleeps.load(Ordering::SeqCst);
        engine.write(unit * 1024, &[0x44; 1024], false).await.unwrap();
        unit += 1;
        parked(&clock, sleeps + 1).await;
    }
    let end = engine.stats().await;
    let useless = end.checkpoints_total - start.checkpoints_total;
    eprintln!(
        "journal {} -> {} bytes, checkpoint seq {} -> {}, durable {}, appended {}, \
         worker checkpoints during {WRITES} writes: {useless}",
        start.journal_total_bytes,
        end.journal_total_bytes,
        start.checkpoint_sequence,
        end.checkpoint_sequence,
        end.durable_sequence,
        end.appended_sequence,
    );
    // The watermark trigger made no progress at all ...
    assert_eq!(end.checkpoint_sequence, 0);
    assert!(end.journal_total_bytes > start.journal_total_bytes);
    // ... yet ran a checkpoint for (almost) every write.
    assert!(
        useless < WRITES / 2,
        "the worker ran {useless} no-op checkpoints for {WRITES} volatile writes \
         above the watermark without shrinking the journal"
    );
    engine.stop_checkpoint_worker().await;
}
