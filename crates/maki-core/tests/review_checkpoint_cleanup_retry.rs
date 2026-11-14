//! Publishing a checkpoint does not finish journal directory cleanup.
//! An idle worker must retry the remaining barrier after transient failure.

use std::io;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions, EngineState};
use maki_core::volume::{Volume, VolumeOptions};
use maki_crypto::{clock::SleepFuture, Clock};
use maki_format::{geometry::Geometry, init, layout, superblock::Superblock};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::failpoints::{self, FailpointAction};
use maki_test_support::{CrashableBacking, FakeCryptoProvider, ManualClock};

fn block() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(0xa0d178),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn idle_worker_retries_a_late_directory_sync_failure() {
    let _serial = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), block()).unwrap();
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
                journal_high_watermark_bytes: u64::MAX,
                emergency_reserve_bytes: 0,
                low_space_checkpoint_bytes: 0,
                ..Default::default()
            },
            clock: Some(clock.clone() as Arc<dyn Clock>),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    parked(&clock, 1).await;
    engine.write(0, &[0x62; 1024], true).await.unwrap();
    let attempts = Arc::new(AtomicUsize::new(0));
    let counted = attempts.clone();
    let fault = failpoints::set(
        "checkpoint.dirsync",
        FailpointAction::Callback(Arc::new(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            Some(io::Error::other("temporary journal directory sync failure"))
        })),
    );
    let before = clock.sleeps.load(Ordering::SeqCst);
    clock.inner.set(Duration::from_secs(30));
    parked(&clock, before + 1).await;
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert!(matches!(engine.state(), EngineState::Degraded { .. }));
    // The checkpoint horizon has already advanced and no new write arrives.
    // A persistent fault gets one attempt per retry interval, without spinning.
    for _ in 0..200 {
        tokio::task::yield_now().await;
    }
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    let before = clock.sleeps.load(Ordering::SeqCst);
    clock.inner.set(Duration::from_secs(60));
    parked(&clock, before + 1).await;
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert!(matches!(engine.state(), EngineState::Degraded { .. }));
    drop(fault);
    let before = clock.sleeps.load(Ordering::SeqCst);
    clock.inner.set(Duration::from_secs(90));
    parked(&clock, before + 1).await;
    assert_eq!(engine.state(), EngineState::Ready);
    assert_eq!(engine.read(0, 1024).await.unwrap(), vec![0x62; 1024]);
    engine.stop_checkpoint_worker().await;
}

#[test]
fn deleted_segments_do_not_hide_a_failed_journal_directory_barrier() {
    let _serial = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), block()).unwrap();
    let options = VolumeOptions {
        journal_segment_size: 4096,
    };
    let mut volume = Volume::recover(backing.clone(), options.clone()).unwrap();
    for unit in 0..8 {
        volume
            .write_ct(unit, &[unit as u8 + 1; 1032], true)
            .unwrap();
    }
    assert!(volume.journal_segment_count() > 1);
    let attempts = Arc::new(AtomicUsize::new(0));
    let counted = attempts.clone();
    backing.set_fault_hook(Some(Arc::new(move |operation| {
        if matches!(operation, FaultOp::SyncDir { dir } if *dir == layout::JOURNAL_DIR) {
            let attempt = counted.fetch_add(1, Ordering::SeqCst);
            if attempt < 2 {
                return Some(io::Error::other(
                    "journal directory temporarily unavailable",
                ));
            }
        }
        None
    })));
    assert!(volume.checkpoint().is_err());
    assert_eq!(
        volume.checkpoint_sequence(),
        volume.journal_appended_sequence()
    );
    assert_eq!(volume.journal_covered_segment_count(), 0);
    assert!(
        volume.checkpoint().is_err(),
        "cleanup must retry the failed barrier even without sealed segments"
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    volume.checkpoint().unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
    // Once the barrier succeeds, an idle pass need not repeat it.
    volume.checkpoint().unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
    drop(volume);
    backing.set_fault_hook(None);
    backing.crash_all_lost();
    let recovered = Volume::recover(backing, options).unwrap();
    for unit in 0..8 {
        assert_eq!(
            recovered.read_ct(unit).unwrap().unwrap().1,
            vec![unit as u8 + 1; 1032]
        );
    }
}
