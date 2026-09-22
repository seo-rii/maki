use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[cfg(target_os = "linux")]
use maki_backing::RollbackBacking;
use maki_backing::{Backing, BackingFile, VolumeLock};
use maki_core::engine::{CheckpointPolicy, Engine, EngineCacheConfig, EngineOptions};
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::CrashableBacking;
use uuid::Uuid;

const UNIT: u32 = 512;

struct FreshnessBacking {
    inner: Arc<CrashableBacking>,
    fresh: AtomicBool,
}

impl FreshnessBacking {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(CrashableBacking::new()),
            fresh: AtomicBool::new(true),
        })
    }

    fn revoke(&self) {
        self.fresh.store(false, Ordering::SeqCst);
    }
}

impl Backing for FreshnessBacking {
    fn check_freshness(&self) -> io::Result<()> {
        if self.fresh.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(io::Error::other("witness no longer names this generation"))
        }
    }

    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        self.inner.open(path, create)
    }

    fn exists(&self, path: &str) -> io::Result<bool> {
        self.inner.exists(path)
    }

    fn remove(&self, path: &str) -> io::Result<()> {
        self.inner.remove(path)
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        self.inner.rename(from, to)
    }

    fn create_dir_all(&self, path: &str) -> io::Result<()> {
        self.inner.create_dir_all(path)
    }

    fn list(&self, dir: &str) -> io::Result<Vec<String>> {
        self.inner.list(dir)
    }

    fn sync_dir(&self, dir: &str) -> io::Result<()> {
        self.inner.sync_dir(dir)
    }

    fn try_lock(&self, path: &str) -> io::Result<Box<dyn VolumeLock>> {
        self.inner.try_lock(path)
    }

    fn free_bytes(&self) -> io::Result<Option<u64>> {
        self.inner.free_bytes()
    }
}

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xfeed_bacc),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, UNIT, 512, UNIT + 8, 16 * UNIT as u64, 4096).unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn create_volume(backing: &Arc<FreshnessBacking>) -> Volume {
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    Volume::recover(
        backing.clone(),
        VolumeOptions {
            journal_segment_size: 4096,
        },
    )
    .unwrap()
}

#[cfg(target_os = "linux")]
struct RollbackFixture {
    root: tempfile::TempDir,
    witness: tempfile::TempDir,
}

#[cfg(target_os = "linux")]
impl RollbackFixture {
    fn new(capacity: u64, discard: bool) -> (Self, Volume, Arc<RollbackBacking>) {
        let fixture = Self {
            root: tempfile::tempdir().unwrap(),
            witness: tempfile::tempdir_in("/dev/shm").unwrap(),
        };
        let backing = Arc::new(
            RollbackBacking::create(fixture.root.path(), fixture.witness.path(), capacity).unwrap(),
        );
        if discard {
            init::create_volume_with_discard(backing.as_ref(), superblock()).unwrap();
        } else {
            init::create_volume(backing.as_ref(), superblock()).unwrap();
        }
        let volume = Volume::recover(
            backing.clone(),
            VolumeOptions {
                journal_segment_size: 4096,
            },
        )
        .unwrap();
        (fixture, volume, backing)
    }

    fn reopen(&self) -> (Volume, Arc<RollbackBacking>) {
        let backing =
            Arc::new(RollbackBacking::open(self.root.path(), self.witness.path()).unwrap());
        let volume = Volume::recover(
            backing.clone(),
            VolumeOptions {
                journal_segment_size: 4096,
            },
        )
        .unwrap();
        (volume, backing)
    }
}

#[cfg(target_os = "linux")]
fn ciphertext(byte: u8) -> Vec<u8> {
    vec![byte; (UNIT + 8) as usize]
}

#[cfg(target_os = "linux")]
fn copy_backing(from: &std::path::Path, to: &std::path::Path) {
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
    }
}

#[test]
fn revoked_freshness_rejects_an_overlay_read_without_backing_io() {
    let backing = FreshnessBacking::new();
    let mut volume = create_volume(&backing);
    volume
        .write_ct(0, &[0x41; (UNIT + 8) as usize], false)
        .unwrap();
    assert!(volume.overlay_len() > 0);

    backing.revoke();
    let error = volume
        .read_ct(0)
        .expect_err("overlay must not bypass witness freshness");
    assert!(error.to_string().contains("witness no longer names"));
}

#[tokio::test]
async fn revoked_freshness_rejects_a_plaintext_cache_hit() {
    let backing = FreshnessBacking::new();
    let volume = create_volume(&backing);
    let engine = Engine::attach_recovered(
        volume,
        Arc::new(FakeCryptoProvider::new(UNIT)),
        EngineOptions {
            cache: Some(EngineCacheConfig {
                max_bytes: 4 * UNIT as u64,
                ttl: Duration::from_secs(60),
            }),
            checkpoint: CheckpointPolicy {
                emergency_reserve_bytes: 0,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await
    .unwrap();

    engine
        .write(0, &[0x52; UNIT as usize], false)
        .await
        .unwrap();
    assert_eq!(
        engine.read(0, UNIT as usize).await.unwrap(),
        vec![0x52; UNIT as usize]
    );
    assert_eq!(
        engine.read(0, UNIT as usize).await.unwrap(),
        vec![0x52; UNIT as usize]
    );

    backing.revoke();
    let error = engine
        .read(0, UNIT as usize)
        .await
        .expect_err("cache hit must not bypass witness freshness");
    assert!(error.to_string().contains("witness no longer names"));
    engine.stop_checkpoint_worker().await;
}

#[cfg(target_os = "linux")]
#[test]
fn rollback_backing_fua_recovers_before_checkpoint() {
    let (fixture, mut volume, backing) = RollbackFixture::new(256 * 1024, false);
    let sequence = volume.write_ct(3, &ciphertext(0xa3), true).unwrap();
    assert!(volume.journal_durable_sequence() >= sequence);
    assert_eq!(volume.checkpoint_sequence(), 0);
    drop((volume, backing));

    let (volume, _backing) = fixture.reopen();
    assert_eq!(volume.read_ct(3).unwrap().unwrap().1, ciphertext(0xa3));
}

#[cfg(target_os = "linux")]
#[test]
fn rollback_backing_checkpoint_discard_and_rewrite_roundtrip() {
    let (fixture, mut volume, backing) = RollbackFixture::new(256 * 1024, true);
    volume.write_ct(2, &ciphertext(0x21), true).unwrap();
    volume.checkpoint().unwrap();
    volume.discard_ct(2, true).unwrap();
    volume.checkpoint().unwrap();
    assert!(volume.read_ct(2).unwrap().is_none());
    volume.write_ct(2, &ciphertext(0x22), true).unwrap();
    volume.checkpoint().unwrap();
    drop((volume, backing));

    let (volume, _backing) = fixture.reopen();
    assert_eq!(volume.read_ct(2).unwrap().unwrap().1, ciphertext(0x22));
}

#[cfg(target_os = "linux")]
#[test]
fn rollback_backing_rejects_old_whole_image_with_current_witness() {
    let (fixture, mut volume, backing) = RollbackFixture::new(256 * 1024, false);
    let old_image = tempfile::tempdir().unwrap();
    volume.write_ct(1, &ciphertext(0x31), true).unwrap();
    copy_backing(fixture.root.path(), old_image.path());
    volume.write_ct(1, &ciphertext(0x32), true).unwrap();
    drop((volume, backing));

    copy_backing(old_image.path(), fixture.root.path());
    assert!(
        RollbackBacking::open(fixture.root.path(), fixture.witness.path()).is_err(),
        "the independent witness must reject a self-consistent old backing image"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn rollback_backing_full_capacity_preserves_checkpoint_reservations() {
    let (fixture, mut volume, backing) = RollbackFixture::new(72 * 1024, false);
    let mut acknowledged = Vec::new();
    for unit in 0..16 {
        match volume.write_ct(unit, &ciphertext(unit as u8), true) {
            Ok(_) => acknowledged.push(unit),
            Err(_) => break,
        }
    }
    assert!(!acknowledged.is_empty());
    assert!(
        acknowledged.len() < 16,
        "fixture must reach its arena limit"
    );
    let free_before = backing.free_bytes().unwrap().unwrap();
    assert_eq!(free_before, 0);
    drop((volume, backing));

    let (mut volume, backing) = fixture.reopen();
    assert!(backing.free_bytes().unwrap().unwrap() >= free_before);
    volume
        .checkpoint()
        .expect("every acknowledged journal record reserved checkpoint completion space");
    for unit in acknowledged {
        assert_eq!(
            volume.read_ct(unit).unwrap().unwrap().1,
            ciphertext(unit as u8)
        );
    }
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rollback_backing_concurrent_checkpoint_and_fua_journaling_roundtrip() {
    let (fixture, volume, backing) = RollbackFixture::new(512 * 1024, false);
    let engine = Engine::attach_recovered(
        volume,
        Arc::new(FakeCryptoProvider::new(UNIT)),
        EngineOptions {
            volume: VolumeOptions {
                journal_segment_size: 4096,
            },
            checkpoint: CheckpointPolicy {
                emergency_reserve_bytes: 0,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await
    .unwrap();
    engine.write(0, &[0x60; UNIT as usize], true).await.unwrap();

    let checkpoint_engine = engine.clone();
    let checkpoint = tokio::spawn(async move { checkpoint_engine.checkpoint().await });
    let writer_engine = engine.clone();
    let writer = tokio::spawn(async move {
        for unit in 1..8u64 {
            writer_engine
                .write(
                    unit * UNIT as u64,
                    &vec![0x60 + unit as u8; UNIT as usize],
                    true,
                )
                .await?;
        }
        Ok::<_, maki_core::CoreError>(())
    });
    checkpoint.await.unwrap().unwrap();
    writer.await.unwrap().unwrap();
    engine.flush().await.unwrap();
    engine.stop_checkpoint_worker().await;
    drop((engine, backing));

    let (volume, reopened_backing) = fixture.reopen();
    let recovered = Engine::attach_recovered(
        volume,
        Arc::new(FakeCryptoProvider::new(UNIT)),
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
    for unit in 0..8u64 {
        assert_eq!(
            recovered
                .read(unit * UNIT as u64, UNIT as usize)
                .await
                .unwrap(),
            vec![0x60 + unit as u8; UNIT as usize]
        );
    }
    recovered.stop_checkpoint_worker().await;
    drop((recovered, reopened_backing));
}
