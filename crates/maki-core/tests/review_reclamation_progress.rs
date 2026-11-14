//! Physical release is a hint, but a failed range must not starve healthy
//! ranges or prevent an idle retry once the backing recovers.

use std::io;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use maki_backing::Backing;
use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions, EngineState};
use maki_core::volume::{Volume, VolumeOptions};
use maki_crypto::{clock::SleepFuture, Clock};
use maki_format::{geometry::Geometry, init, layout, superblock::Superblock};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::{CrashableBacking, FakeCryptoProvider, ManualClock};

fn initialized_backing(geometry: &Geometry) -> Arc<CrashableBacking> {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume_with_discard(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xa0d184),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "key".into(),
            geometry: geometry.clone(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    backing
}

fn recovered_discards(geometry: &Geometry, units: &[u64]) -> (Arc<CrashableBacking>, Volume) {
    let backing = initialized_backing(geometry);
    let mut volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
    for &unit in units {
        volume.write_ct(unit, &[0x73; 1032], true).unwrap();
    }
    volume.checkpoint().unwrap();
    for &unit in units {
        volume.discard_ct(unit, true).unwrap();
    }
    drop(volume);
    // Replay publishes tombstones while deliberately deferring physical release.
    let recovered = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
    for &unit in units {
        assert!(recovered.read_ct(unit).unwrap().is_none());
        assert!(slot_has_bytes(&backing, geometry, unit));
    }
    (backing, recovered)
}

fn slot_has_bytes(backing: &CrashableBacking, geometry: &Geometry, unit: u64) -> bool {
    let (shard, in_shard) = geometry.shard_of_unit(unit);
    let mut bytes = vec![0; geometry.slot_size as usize];
    backing
        .open(&layout::shard_data(shard), false)
        .unwrap()
        .read_at(geometry.slot_offset(in_shard), &mut bytes)
        .unwrap();
    bytes.iter().any(|byte| *byte != 0)
}

#[test]
fn failed_shards_and_repeated_earlier_hints_do_not_block_a_healthy_shard() {
    let geometry = Geometry::compute(512, 1024, 512, 1032, 24576, 8192).unwrap();
    let (backing, mut volume) = recovered_discards(&geometry, &[1, 9, 17]);
    backing.set_fault_hook(Some(Arc::new(|operation| {
        matches!(operation, FaultOp::WriteAt { path, .. }
            if path == &layout::shard_data(0) || path == &layout::shard_data(2))
        .then(|| io::Error::other("two shards cannot release space"))
    })));
    volume.checkpoint().unwrap(); // shard 0 fails; a later window stays pending
    assert!(slot_has_bytes(&backing, &geometry, 9));
    // Repeating an already-zero TRIM must not rewind the current sweep.
    volume.discard_ct(1, true).unwrap();
    volume.checkpoint().unwrap(); // shard 1 succeeds despite the earlier hint
    assert!(!slot_has_bytes(&backing, &geometry, 9));
    assert!(slot_has_bytes(&backing, &geometry, 1));
    volume.checkpoint().unwrap(); // shard 2 fails; the failed sweep is deferred
    assert!(slot_has_bytes(&backing, &geometry, 17));
    for unit in [1, 9, 17] {
        assert!(volume.read_ct(unit).unwrap().is_none());
    }
    backing.set_fault_hook(None);
    for _ in 0..3 {
        volume.checkpoint().unwrap();
    }
    for unit in [1, 9, 17] {
        assert!(!slot_has_bytes(&backing, &geometry, unit));
    }
}

#[test]
fn failed_window_does_not_block_later_windows_in_the_same_shard() {
    let geometry = Geometry::compute(512, 1024, 512, 1032, 32 << 20, 16 << 20).unwrap();
    let (backing, mut volume) = recovered_discards(&geometry, &[1, 4097]);
    let failed_offset = geometry.slot_offset(1);
    backing.set_fault_hook(Some(Arc::new(move |operation| {
        matches!(operation, FaultOp::WriteAt { path, offset, .. }
            if path == &layout::shard_data(0) && *offset == failed_offset)
        .then(|| io::Error::other("only the first scan window fails"))
    })));
    volume.checkpoint().unwrap();
    assert!(slot_has_bytes(&backing, &geometry, 1));
    assert!(
        slot_has_bytes(&backing, &geometry, 4097),
        "a pass must still scan at most 4096 positions"
    );
    volume.checkpoint().unwrap();
    assert!(slot_has_bytes(&backing, &geometry, 1));
    assert!(!slot_has_bytes(&backing, &geometry, 4097));
    backing.set_fault_hook(None);
    // Finish the two untouched windows, then revisit the failed first one.
    for _ in 0..3 {
        volume.checkpoint().unwrap();
    }
    assert!(!slot_has_bytes(&backing, &geometry, 1));
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
        let sleep = self.inner.sleep(duration);
        self.sleeps.fetch_add(1, Ordering::SeqCst);
        sleep
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
    .expect("worker must finish the bounded sweep and park");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_worker_backs_off_failed_sweeps_then_recovers_without_new_writes() {
    let geometry = Geometry::compute(512, 1024, 512, 1032, 16384, 8192).unwrap();
    let backing = initialized_backing(&geometry);
    // A real first attach binds the key canary before all data is trimmed.
    // The next attach must not need readable legacy ciphertext as key proof.
    let initial = Engine::attach(
        backing.clone(),
        Arc::new(FakeCryptoProvider::new(1024)),
        EngineOptions {
            checkpoint: CheckpointPolicy {
                emergency_reserve_bytes: 0,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await
    .unwrap();
    initial.stop_checkpoint_worker().await;
    for unit in [1, 9] {
        initial
            .write(unit * 1024, &[0x73; 1024], true)
            .await
            .unwrap();
    }
    initial.checkpoint().await.unwrap();
    for unit in [1, 9] {
        initial.trim(unit * 1024, 1024, true).await.unwrap();
    }
    drop(initial);
    let attempts = Arc::new(AtomicUsize::new(0));
    let counted = attempts.clone();
    backing.set_fault_hook(Some(Arc::new(move |operation| {
        matches!(operation, FaultOp::WriteAt { path, .. } if path == &layout::shard_data(0)).then(
            || {
                counted.fetch_add(1, Ordering::SeqCst);
                io::Error::other("first shard temporarily cannot release space")
            },
        )
    })));
    let clock = Arc::new(ObservedClock {
        inner: ManualClock::new(),
        sleeps: AtomicUsize::new(0),
    });
    let engine = Engine::attach(
        backing.clone(),
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
    for (seconds, expected_attempts) in [(30, 1), (60, 2)] {
        let before = clock.sleeps.load(Ordering::SeqCst);
        clock.inner.set(Duration::from_secs(seconds));
        parked(&clock, before + 2).await; // one bounded pass per shard
        assert_eq!(attempts.load(Ordering::SeqCst), expected_attempts);
        assert!(slot_has_bytes(&backing, &geometry, 1));
        assert!(!slot_has_bytes(&backing, &geometry, 9));
        assert_eq!(engine.state(), EngineState::Ready);
        for _ in 0..200 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            expected_attempts,
            "failed sweeps must wait for the retry interval"
        );
    }
    backing.set_fault_hook(None);
    let before = clock.sleeps.load(Ordering::SeqCst);
    clock.inner.set(Duration::from_secs(90));
    parked(&clock, before + 2).await;
    assert!(!slot_has_bytes(&backing, &geometry, 1));
    assert!(!slot_has_bytes(&backing, &geometry, 9));
    for unit in [1, 9] {
        assert_eq!(engine.read(unit * 1024, 1024).await.unwrap(), vec![0; 1024]);
    }
    engine.stop_checkpoint_worker().await;
}
