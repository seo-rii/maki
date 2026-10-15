//! BUG-106: write admission refuses with ENOSPC unless free space covers the
//! emergency reserve, the checkpoint headroom and the append footprint, but
//! the worker checkpoints eagerly only below the checkpoint headroom alone,
//! and a refused write woke nobody. Between the two thresholds every write
//! failed with ENOSPC until the regular interval ran a checkpoint, although
//! that checkpoint deletes covered journal segments and gives the space
//! back; a guest filesystem can shut down on the first such error. A refusal
//! stays side-effect free, but it now wakes the worker for a reclaiming pass.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use maki_backing::{Backing, BackingFile, VolumeLock};
use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
use maki_core::volume::VolumeOptions;
use maki_core::CoreError;
use maki_crypto::{clock::SleepFuture, Clock};
use maki_format::{geometry::Geometry, init, layout, superblock::Superblock};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::{CrashableBacking, ManualClock};

const UNIT: u32 = 1024;
const RESERVE: u64 = 1 << 20;
const HEADROOM: u64 = 2 << 20;
const PLENTY: u64 = 1 << 40;

/// Free space is whatever the test sets, except that removing a journal
/// segment gives `returned` bytes back, as deleting a file would.
struct SpaceBacking {
    storage: CrashableBacking,
    free: AtomicU64,
    returned: AtomicU64,
}

impl Backing for SpaceBacking {
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        self.storage.open(path, create)
    }
    fn exists(&self, path: &str) -> io::Result<bool> {
        self.storage.exists(path)
    }
    fn remove(&self, path: &str) -> io::Result<()> {
        self.storage.remove(path)?;
        if path.starts_with("journal/seg-") {
            self.free
                .fetch_add(self.returned.load(Ordering::SeqCst), Ordering::SeqCst);
        }
        Ok(())
    }
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        self.storage.rename(from, to)
    }
    fn create_dir_all(&self, path: &str) -> io::Result<()> {
        self.storage.create_dir_all(path)
    }
    fn list(&self, dir: &str) -> io::Result<Vec<String>> {
        self.storage.list(dir)
    }
    fn sync_dir(&self, dir: &str) -> io::Result<()> {
        self.storage.sync_dir(dir)
    }
    fn try_lock(&self, path: &str) -> io::Result<Box<dyn VolumeLock>> {
        self.storage.try_lock(path)
    }
    fn free_bytes(&self) -> io::Result<Option<u64>> {
        Ok(Some(self.free.load(Ordering::SeqCst)))
    }
}

fn assert_storage_full(result: Result<(), CoreError>) {
    assert!(
        matches!(result, Err(CoreError::Io(ref error)) if error.kind() == io::ErrorKind::StorageFull),
        "expected ENOSPC, got {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reserve_refusal_wakes_a_reclaiming_checkpoint() {
    let backing = Arc::new(SpaceBacking {
        storage: CrashableBacking::new(),
        free: AtomicU64::new(PLENTY),
        returned: AtomicU64::new(0),
    });
    let clock = Arc::new(ManualClock::new());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0x106),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(
                512,
                UNIT,
                512,
                UNIT + 8,
                64 * UNIT as u64,
                16 * UNIT as u64,
            )
            .unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let engine = Engine::attach(
        backing.clone() as Arc<dyn Backing>,
        Arc::new(FakeCryptoProvider::new(UNIT)),
        EngineOptions {
            volume: VolumeOptions {
                journal_segment_size: 8192,
            },
            checkpoint: CheckpointPolicy {
                // Neither the journal size nor the interval triggers a
                // checkpoint during this test: the clock never moves.
                journal_high_watermark_bytes: u64::MAX,
                journal_max_bytes: u64::MAX,
                max_pending_bytes: u64::MAX,
                emergency_reserve_bytes: RESERVE,
                low_space_checkpoint_bytes: HEADROOM,
                interval: Duration::from_secs(3600),
            },
            clock: Some(clock.clone()),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // Several sealed, durable segments that only a checkpoint can delete.
    for unit in 0..24u64 {
        engine
            .write(unit * UNIT as u64, &[unit as u8 + 1; UNIT as usize], true)
            .await
            .unwrap();
    }
    let checkpoints = engine.stats().await.checkpoints_total;

    // Free space falls between the worker's eager threshold (the headroom)
    // and the admission requirement; deleting segments gives space back.
    backing.free.store(RESERVE + HEADROOM, Ordering::SeqCst);
    backing.returned.store(64 * 1024, Ordering::SeqCst);
    assert_storage_full(engine.write(0, &[0xEE; UNIT as usize], true).await);

    let reclaimed = tokio::time::timeout(Duration::from_secs(15), async {
        while engine.stats().await.checkpoints_total == checkpoints {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        reclaimed.is_ok(),
        "a write refused for space did not wake a checkpoint; writes would keep \
         failing until the interval elapsed"
    );
    engine
        .write(0, &[0xEE; UNIT as usize], true)
        .await
        .expect("the space a checkpoint gave back admits the write");
    assert_eq!(
        engine.read(0, UNIT as usize).await.unwrap(),
        [0xEE; UNIT as usize]
    );
    assert_eq!(clock.now(), Duration::ZERO);
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

async fn parked(clock: &ObservedClock, sleeps: usize) {
    tokio::time::timeout(Duration::from_secs(15), async {
        while clock.sleeps.load(Ordering::SeqCst) < sleeps || clock.inner.sleeper_count() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("checkpoint worker did not finish its pass and park");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reserve_refusal_retries_stalled_reclamation_without_journal_work() {
    let backing = Arc::new(SpaceBacking {
        storage: CrashableBacking::new(),
        free: AtomicU64::new(PLENTY),
        returned: AtomicU64::new(0),
    });
    let geometry = Geometry::compute(512, UNIT, 512, UNIT + 8, 16 << 10, 8 << 10).unwrap();
    init::create_volume_with_discard(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0x106123),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: geometry.clone(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let clock = Arc::new(ObservedClock {
        inner: ManualClock::new(),
        sleeps: AtomicUsize::new(0),
    });
    let options = || EngineOptions {
        checkpoint: CheckpointPolicy {
            journal_high_watermark_bytes: u64::MAX,
            emergency_reserve_bytes: RESERVE,
            low_space_checkpoint_bytes: HEADROOM,
            interval: Duration::from_secs(3600),
            ..Default::default()
        },
        clock: Some(clock.clone()),
        ..Default::default()
    };
    let provider = Arc::new(FakeCryptoProvider::new(UNIT));
    let engine = Engine::attach(backing.clone(), provider.clone(), options())
        .await
        .unwrap();
    engine.stop_checkpoint_worker().await;
    engine
        .write(UNIT as u64, &[0x41; UNIT as usize], true)
        .await
        .unwrap();
    engine.checkpoint().await.unwrap();
    engine.trim(UNIT as u64, UNIT as usize, true).await.unwrap();
    drop(engine);

    // Recovery checkpoints the discard and deletes its journal, but retains
    // the physical slot and a reclamation cursor for an idle checkpoint.
    let before = clock.sleeps.load(Ordering::SeqCst);
    let engine = Engine::attach(backing.clone(), provider, options())
        .await
        .unwrap();
    parked(&clock, before + 1).await;
    let stats = engine.stats().await;
    assert_eq!(stats.appended_sequence, stats.checkpoint_sequence);
    assert_eq!(
        stats.journal_segments, 0,
        "no journal work can wake reclamation"
    );
    let raw_slot = || {
        let mut bytes = vec![0; geometry.slot_size as usize];
        backing
            .open(&layout::shard_data(0), false)
            .unwrap()
            .read_at(geometry.slot_offset(1), &mut bytes)
            .unwrap();
        bytes
    };
    assert!(raw_slot().iter().any(|byte| *byte != 0));

    let attempts = Arc::new(AtomicUsize::new(0));
    let counted = attempts.clone();
    let failing = Arc::new(AtomicBool::new(true));
    let fault = failing.clone();
    let weak = Arc::downgrade(&backing);
    let slot_size = geometry.slot_size as usize;
    backing
        .storage
        .set_fault_hook(Some(Arc::new(move |operation| {
            if matches!(operation, FaultOp::WriteAt { path, len, .. }
            if path.ends_with(".dat") && *len == slot_size)
            {
                counted.fetch_add(1, Ordering::SeqCst);
                if fault.load(Ordering::SeqCst) {
                    return Some(io::Error::from_raw_os_error(28));
                }
                // Successful punching makes enough room for the next write.
                weak.upgrade().unwrap().free.store(PLENTY, Ordering::SeqCst);
            }
            None
        })));
    engine.checkpoint().await.unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 1);

    // No journal record is appended by the refusal. It must still trigger
    // one retry of the stalled cursor, and a failing hint must not spin.
    backing.free.store(RESERVE + HEADROOM, Ordering::SeqCst);
    let before = clock.sleeps.load(Ordering::SeqCst);
    assert_storage_full(
        engine
            .write(UNIT as u64, &[0x42; UNIT as usize], true)
            .await,
    );
    parked(&clock, before + 1).await;
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        2,
        "space refusal did not retry stalled reclamation after journal deletion"
    );
    for _ in 0..200 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        2,
        "persistent punch failure triggered an autonomous retry loop"
    );
    assert!(raw_slot().iter().any(|byte| *byte != 0));

    // Once the device recovers, another refusal wakes the retained cursor.
    // Neither the clock nor any new checkpointable work advances.
    failing.store(false, Ordering::SeqCst);
    let before = clock.sleeps.load(Ordering::SeqCst);
    assert_storage_full(
        engine
            .write(UNIT as u64, &[0x43; UNIT as usize], true)
            .await,
    );
    parked(&clock, before + 1).await;
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
    assert!(raw_slot().iter().all(|byte| *byte == 0));
    assert_eq!(clock.now(), Duration::ZERO);
    engine
        .write(UNIT as u64, &[0x44; UNIT as usize], true)
        .await
        .expect("physical reclamation must admit the next write");
    assert_eq!(
        engine.read(UNIT as u64, UNIT as usize).await.unwrap(),
        [0x44; UNIT as usize]
    );
    engine.stop_checkpoint_worker().await;
}
