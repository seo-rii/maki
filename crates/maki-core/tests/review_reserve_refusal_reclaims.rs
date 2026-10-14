//! BUG-106: write admission refuses with ENOSPC unless free space covers the
//! emergency reserve, the checkpoint headroom and the append footprint, but
//! the worker checkpoints eagerly only below the checkpoint headroom alone,
//! and a refused write woke nobody. Between the two thresholds every write
//! failed with ENOSPC until the regular interval ran a checkpoint, although
//! that checkpoint deletes covered journal segments and gives the space
//! back; a guest filesystem can shut down on the first such error. A refusal
//! stays side-effect free, but it now wakes the worker for a reclaiming pass.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use maki_backing::{Backing, BackingFile, VolumeLock};
use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
use maki_core::volume::VolumeOptions;
use maki_core::CoreError;
use maki_crypto::Clock;
use maki_format::{geometry::Geometry, init, superblock::Superblock};
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
