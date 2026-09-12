//! MAKI-021: a prior free-space sample cannot authorize a later write.
//! This is threshold enforcement, not physical allocation reservation.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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

#[derive(Default)]
struct SpaceBacking {
    storage: CrashableBacking,
    fail_query: AtomicBool,
    queries: AtomicUsize,
}

impl Backing for SpaceBacking {
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        self.storage.open(path, create)
    }
    fn exists(&self, path: &str) -> io::Result<bool> {
        self.storage.exists(path)
    }
    fn remove(&self, path: &str) -> io::Result<()> {
        self.storage.remove(path)
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
        self.queries.fetch_add(1, Ordering::SeqCst);
        if self.fail_query.load(Ordering::SeqCst) {
            Err(io::Error::other("space query unavailable"))
        } else {
            self.storage.free_bytes()
        }
    }
}

async fn fixture(reserve: u64) -> (Arc<SpaceBacking>, Arc<ManualClock>, Engine) {
    let backing = Arc::new(SpaceBacking::default());
    let clock = Arc::new(ManualClock::new());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0x215041),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(
                512,
                UNIT,
                512,
                UNIT + 8,
                16 * UNIT as u64,
                8 * UNIT as u64,
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
                journal_high_watermark_bytes: u64::MAX,
                journal_max_bytes: u64::MAX,
                max_pending_bytes: u64::MAX,
                emergency_reserve_bytes: reserve,
                low_space_checkpoint_bytes: 0,
                interval: Duration::from_secs(3600),
            },
            clock: Some(clock.clone()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    (backing, clock, engine)
}

fn assert_storage_full(result: Result<(), CoreError>) {
    assert!(
        matches!(result, Err(CoreError::Io(ref error)) if error.kind() == io::ErrorKind::StorageFull),
        "a fresh known shortage must refuse this write with ENOSPC"
    );
}

#[tokio::test]
async fn consecutive_write_observes_external_space_drop_without_clock_advance() {
    let (backing, clock, engine) = fixture(RESERVE).await;
    backing.storage.set_free_bytes(Some(2 * RESERVE));
    engine.write(0, &[0xA5; UNIT as usize], true).await.unwrap();
    let before = engine.monitoring_snapshot().stats;
    let writes = backing.storage.pending_write_count();

    // Another user of the same filesystem consumes space before the next call.
    backing.storage.set_free_bytes(Some(RESERVE - 1));
    assert_storage_full(
        engine
            .write(UNIT as u64, &[0xB6; UNIT as usize], true)
            .await,
    );
    let after = engine.monitoring_snapshot().stats;
    assert_eq!(after.appended_sequence, before.appended_sequence);
    assert_eq!(after.durable_sequence, before.durable_sequence);
    assert_eq!(
        backing.storage.pending_write_count(),
        writes,
        "refused admission changed storage"
    );
    assert_eq!(after.backing_free_bytes, Some(RESERVE - 1));
    assert_eq!(
        engine.read(0, UNIT as usize).await.unwrap(),
        [0xA5; UNIT as usize]
    );
    assert_eq!(clock.now(), Duration::ZERO);
}

#[tokio::test]
async fn recovered_space_allows_retry_without_clock_advance() {
    let (backing, clock, engine) = fixture(RESERVE).await;
    backing.storage.set_free_bytes(Some(RESERVE - 1));
    assert_storage_full(engine.write(0, &[1; UNIT as usize], false).await);
    backing.storage.set_free_bytes(Some(2 * RESERVE));
    engine
        .write(0, &[2; UNIT as usize], true)
        .await
        .expect("a stale shortage must not keep refusing after space returns");
    assert_eq!(
        engine.read(0, UNIT as usize).await.unwrap(),
        [2; UNIT as usize]
    );
    assert_eq!(clock.now(), Duration::ZERO);
}

#[tokio::test]
async fn newly_known_shortage_replaces_an_unknown_cached_sample() {
    let (backing, clock, engine) = fixture(RESERVE).await;
    engine.write(0, &[1; UNIT as usize], false).await.unwrap();
    backing.storage.set_free_bytes(Some(0));
    assert_storage_full(engine.write(UNIT as u64, &[2; UNIT as usize], false).await);
    assert_eq!(engine.monitoring_snapshot().stats.appended_sequence, 1);
    assert_eq!(clock.now(), Duration::ZERO);
}

#[tokio::test]
async fn statistics_keep_their_cache_and_monitoring_never_refreshes_space() {
    let (backing, clock, engine) = fixture(RESERVE).await;
    backing.storage.set_free_bytes(Some(2 * RESERVE));
    assert_eq!(engine.stats().await.backing_free_bytes, Some(2 * RESERVE));
    let queries = backing.queries.load(Ordering::SeqCst);
    backing.storage.set_free_bytes(Some(0));
    assert_eq!(engine.stats().await.backing_free_bytes, Some(2 * RESERVE));
    assert_eq!(
        engine.monitoring_snapshot().stats.backing_free_bytes,
        Some(2 * RESERVE)
    );
    assert_eq!(backing.queries.load(Ordering::SeqCst), queries);
    clock.advance(Duration::from_secs(2));
    assert_eq!(engine.stats().await.backing_free_bytes, Some(0));
    assert!(backing.queries.load(Ordering::SeqCst) > queries);
}

#[tokio::test]
async fn unknown_and_failed_space_queries_keep_the_existing_write_contract() {
    for fail_query in [false, true] {
        let (backing, _, engine) = fixture(RESERVE).await;
        backing.fail_query.store(fail_query, Ordering::SeqCst);
        engine.write(0, &[3; UNIT as usize], true).await.unwrap();
        let snapshot = engine.monitoring_snapshot();
        assert_eq!(snapshot.stats.backing_free_bytes, None);
        assert_eq!(snapshot.stats.appended_sequence, 1);
    }
}

#[tokio::test]
async fn disabled_reserve_skips_the_admission_space_query() {
    let (backing, _, engine) = fixture(0).await;
    backing.storage.set_free_bytes(Some(0));
    engine.write(0, &[4; UNIT as usize], true).await.unwrap();
    assert_eq!(backing.queries.load(Ordering::SeqCst), 0);
    assert_eq!(engine.monitoring_snapshot().stats.appended_sequence, 1);
}
