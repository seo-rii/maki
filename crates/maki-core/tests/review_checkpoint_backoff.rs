//! BUG-101: a failing background checkpoint was retried on every wake-up.
//! Each journaled write above the high watermark notifies the worker, and
//! each pass reran the whole checkpoint under the exclusive volume lock, so
//! a degraded device was hammered and foreground I/O stalled behind
//! checkpoints that kept failing. After a failure the worker waits out the
//! regular interval before it tries again; a later success clears that.

use maki_backing::Backing;
use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions, EngineState};
use maki_core::volume::VolumeOptions;
use maki_crypto::{clock::SleepFuture, Clock};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::failpoints::{self, FailpointAction};
use maki_test_support::{fake_provider::FakeCryptoProvider, CrashableBacking, ManualClock};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use uuid::Uuid;

const UNIT: u32 = 1024;
const INTERVAL: Duration = Duration::from_secs(30);

fn block() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xBAC0FF),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(
            512,
            UNIT,
            512,
            UNIT + 8,
            256 * UNIT as u64,
            32 * UNIT as u64,
        )
        .unwrap(),
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
    fn sleep(&self, d: Duration) -> SleepFuture {
        let f = self.inner.sleep(d);
        self.sleeps.fetch_add(1, Ordering::SeqCst);
        f
    }
}

/// Wait until the worker has finished a pass and parked again.
async fn parked(clock: &ObservedClock, sleeps: usize) {
    tokio::time::timeout(Duration::from_secs(15), async {
        while clock.sleeps.load(Ordering::SeqCst) < sleeps || clock.inner.sleeper_count() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the checkpoint worker did not finish its pass and park");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)] // failpoints are process-global
async fn a_failing_checkpoint_is_not_retried_on_every_write() {
    let _serial = failpoints::test_lock();
    let clock = Arc::new(ObservedClock {
        inner: ManualClock::new(),
        sleeps: AtomicUsize::new(0),
    });
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), block()).unwrap();
    let engine = Engine::attach(
        backing as Arc<dyn Backing>,
        Arc::new(FakeCryptoProvider::new(UNIT)),
        EngineOptions {
            volume: VolumeOptions {
                journal_segment_size: 8192,
            },
            checkpoint: CheckpointPolicy {
                // Every journaled write is above the watermark and wakes
                // the worker; the hard bound is far away, so no write ever
                // needs an inline checkpoint.
                journal_high_watermark_bytes: 1024,
                journal_max_bytes: 1 << 20,
                max_pending_bytes: 64 * 1024,
                emergency_reserve_bytes: 0,
                low_space_checkpoint_bytes: 0,
                interval: INTERVAL,
            },
            clock: Some(clock.clone() as Arc<dyn Clock>),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    parked(&clock, 1).await;

    let attempts = Arc::new(AtomicUsize::new(0));
    let counted = attempts.clone();
    let failing = failpoints::set(
        "checkpoint.state_store",
        FailpointAction::Callback(Arc::new(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            Some(std::io::Error::other("degraded device"))
        })),
    );

    for unit in 0..12u64 {
        let before = clock.sleeps.load(Ordering::SeqCst);
        engine
            .write(unit * UNIT as u64, &[unit as u8 + 1; UNIT as usize], true)
            .await
            .unwrap();
        parked(&clock, before + 1).await;
    }
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "the worker reran a failing checkpoint on every write instead of \
         waiting for its retry interval"
    );
    assert!(matches!(engine.state(), EngineState::Degraded { .. }));

    // The retry interval elapses: one more attempt, which fails again.
    let before = clock.sleeps.load(Ordering::SeqCst);
    clock.inner.set(INTERVAL);
    parked(&clock, before + 1).await;
    assert_eq!(attempts.load(Ordering::SeqCst), 2);

    // The device recovers: the next retry succeeds and a success clears the
    // backoff, so later writes wake the worker as before.
    drop(failing);
    let before = clock.sleeps.load(Ordering::SeqCst);
    clock.inner.set(INTERVAL * 2);
    parked(&clock, before + 1).await;
    assert_eq!(engine.state(), EngineState::Ready);
    let checkpoints = engine.stats().await.checkpoints_total;
    assert!(checkpoints >= 1);

    let before = clock.sleeps.load(Ordering::SeqCst);
    engine.write(0, &[0x55; UNIT as usize], true).await.unwrap();
    parked(&clock, before + 1).await;
    assert!(
        engine.stats().await.checkpoints_total > checkpoints,
        "after a success a write above the watermark checkpoints at once"
    );
}
