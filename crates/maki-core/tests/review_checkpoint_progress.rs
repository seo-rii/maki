//! No-progress administrative checkpoints cannot postpone the worker deadline.

use maki_backing::Backing;
use maki_core::engine::{AttachError, CheckpointPolicy, Engine, EngineOptions};
use maki_core::volume::VolumeOptions;
use maki_crypto::{clock::SleepFuture, Clock};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::{fake_provider::FakeCryptoProvider, CrashableBacking, ManualClock};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use uuid::Uuid;
const UNIT: u32 = 1024;
const RECORD: u64 = 32 + 1024 + 8;
fn block() -> Superblock {
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
            256 * UNIT as u64,
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
        emergency_reserve_bytes: 0,
        low_space_checkpoint_bytes: 0,
        interval: Duration::from_secs(30),
    }
}
async fn engine(p: CheckpointPolicy, clock: Option<Arc<dyn Clock>>) -> Result<Engine, AttachError> {
    let backing = Arc::new(CrashableBacking::new().with_tearing(17));
    init::create_volume(backing.as_ref(), block()).unwrap();
    Engine::attach(
        backing as Arc<dyn Backing>,
        Arc::new(FakeCryptoProvider::new(UNIT)),
        EngineOptions {
            volume: VolumeOptions {
                journal_segment_size: 8192,
            },
            checkpoint: p,
            clock,
            limits: maki_core::engine::EngineLimits {
                max_request_bytes: 4096,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await
}
struct ObservedClock {
    inner: ManualClock,
    sleeps: AtomicUsize,
}
impl ObservedClock {
    fn new() -> Self {
        Self {
            inner: ManualClock::new(),
            sleeps: AtomicUsize::new(0),
        }
    }
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
async fn parked(clock: &ObservedClock, count: usize) {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if clock.sleeps.load(Ordering::SeqCst) >= count && clock.inner.sleeper_count() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("worker did not finish pass and park");
}
#[tokio::test]
async fn no_progress_admin_checkpoints_cannot_starve_periodic_sync() {
    let c = Arc::new(ObservedClock::new());
    let e = engine(policy(), Some(c.clone())).await.unwrap();
    parked(&c, 1).await;
    e.write(0, &[9; 1024], false).await.unwrap();
    let mut passes = 0;
    let mut admins = 0;
    for time in [20, 30, 40, 60, 80, 90, 100, 120] {
        c.inner.set(Duration::from_secs(time));
        if time % 20 == 0 {
            let s = e.checkpoint().await.unwrap();
            admins += 1;
            println!("admin t={time} result={s}");
        }
        if time % 30 == 0 {
            passes += 1;
            parked(&c, passes + 1).await;
        }
        let s = e.stats().await;
        println!(
            "t={time} appended={} durable={} checkpoint={} pending={} worker_passes={passes}",
            s.appended_sequence, s.durable_sequence, s.checkpoint_sequence, s.journal_pending_bytes
        );
    }
    let s = e.stats().await;
    assert_eq!(admins, 6);
    assert_eq!(passes, 4);
    assert_eq!(
        s.durable_sequence, 1,
        "automatic sync starved despite four completed passes"
    );
    assert_eq!(s.checkpoint_sequence, 1);
    assert_eq!(s.journal_pending_bytes, 0);
}
#[tokio::test]
async fn periodic_worker_without_admin_syncs_on_time() {
    let c = Arc::new(ObservedClock::new());
    let e = engine(policy(), Some(c.clone())).await.unwrap();
    parked(&c, 1).await;
    e.write(0, &[9; 1024], false).await.unwrap();
    c.inner.set(Duration::from_secs(30));
    parked(&c, 2).await;
    let s = e.stats().await;
    println!(
        "control t=30 durable={} checkpoint={} pending={}",
        s.durable_sequence, s.checkpoint_sequence, s.journal_pending_bytes
    );
    assert_eq!(s.durable_sequence, 1);
    assert_eq!(s.checkpoint_sequence, 1);
    assert_eq!(s.journal_pending_bytes, 0);
}
#[tokio::test]
async fn explicit_checkpoint_remains_a_durable_only_operation() {
    let e = engine(policy(), Some(Arc::new(ManualClock::new())))
        .await
        .unwrap();
    e.write(0, &[9; 1024], false).await.unwrap();
    assert_eq!(e.checkpoint().await.unwrap(), 0);
    let s = e.stats().await;
    assert_eq!(s.durable_sequence, 0);
    assert_eq!(s.checkpoint_sequence, 0);
    assert_eq!(s.journal_pending_bytes, RECORD);
}
