//! Audit (core write path): a no-op checkpoint that fails while persisting
//! the metadata a reopened store must re-establish (`has_pending_repairs`:
//! loaded allocation pairs awaiting proof, adopted shards, repaired maps)
//! degrades the engine, and the idle checkpoint worker never retries it:
//! `worker_pass` has no trigger for pending repairs, unlike the BUG-183
//! journal-cleanup flag. The volume stays `Degraded` indefinitely after the
//! transient fault is gone, until an operator runs a checkpoint or a write
//! arrives.

use std::io;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions, EngineState};
use maki_crypto::{clock::SleepFuture, Clock};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::failpoints::{self, FailpointAction};
use maki_test_support::{CrashableBacking, FakeCryptoProvider, ManualClock};

fn block() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(0xa0d1_7e9a),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "audit".into(),
        geometry: Geometry::compute(512, 1024, 512, 1032, 16384, 8192).unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

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

fn options(clock: Option<Arc<dyn Clock>>) -> EngineOptions {
    EngineOptions {
        checkpoint: CheckpointPolicy {
            interval: Duration::from_secs(30),
            journal_high_watermark_bytes: u64::MAX,
            emergency_reserve_bytes: 0,
            low_space_checkpoint_bytes: 0,
            ..Default::default()
        },
        clock,
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn idle_worker_never_retries_a_failed_repair_persist() {
    let _serial = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), block()).unwrap();
    {
        let engine = Engine::attach(
            backing.clone(),
            Arc::new(FakeCryptoProvider::new(1024)),
            options(None),
        )
        .await
        .unwrap();
        engine.write(0, &[0x5a; 1024], true).await.unwrap();
        engine.checkpoint().await.unwrap();
        engine.stop_checkpoint_worker().await;
    }
    // Reopen: the loaded shard's allocation pair awaits proof (map_stored =
    // false), so the next checkpoint, even a no-op one, must store it.
    let clock = Arc::new(ObservedClock {
        inner: ManualClock::new(),
        sleeps: AtomicUsize::new(0),
    });
    let engine = Engine::attach(
        backing.clone(),
        Arc::new(FakeCryptoProvider::new(1024)),
        options(Some(clock.clone() as Arc<dyn Clock>)),
    )
    .await
    .unwrap();
    parked(&clock, 1).await;
    let st = engine.stats().await;
    eprintln!(
        "after reopen: appended {} durable {} checkpoint {} segments {} checkpoints {}",
        st.appended_sequence, st.durable_sequence, st.checkpoint_sequence, st.journal_segments,
        st.checkpoints_total
    );

    let attempts = Arc::new(AtomicUsize::new(0));
    let counted = attempts.clone();
    let fault = failpoints::set(
        "checkpoint.alloc_store",
        FailpointAction::Callback(Arc::new(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            Some(io::Error::other("transient allocation-map store failure"))
        })),
    );
    // An administrative (or drain) checkpoint on the idle volume fails.
    assert!(engine.checkpoint().await.is_err());
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert!(matches!(engine.state(), EngineState::Degraded { .. }));
    drop(fault);

    // The fault is gone. Let the worker run several full intervals.
    for step in 1..=4u64 {
        let before = clock.sleeps.load(Ordering::SeqCst);
        clock.inner.set(Duration::from_secs(30 * step + 1));
        parked(&clock, before + 1).await;
    }
    let st = engine.stats().await;
    eprintln!("after intervals: checkpoints {} failures {}", st.checkpoints_total, st.checkpoint_failures_total);
    let state = engine.state();
    eprintln!("state after four idle worker intervals: {state:?}");
    // Expected (BUG-183 semantics): the worker retries and the volume
    // returns to Ready. Observed: it stays Degraded.
    assert_eq!(
        state,
        EngineState::Ready,
        "idle worker never retried the failed metadata persist"
    );
    engine.stop_checkpoint_worker().await;
}
