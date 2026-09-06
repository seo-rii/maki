//! BUG-001: a readable A/B generation may still be volatile after a failed
//! sync or a process restart. Retrying must retain a durable typed copy.

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use maki_backing::{Backing, BackingFile, VolumeLock};
use maki_format::ab::{AbRecord, AbStore};
use maki_format::allocation::AllocationMap;
use maki_format::canary::KeyCanary;
use maki_format::catalog::ShardCatalog;
use maki_format::checkpoint::CheckpointState;
use maki_format::geometry::Geometry;
use maki_format::superblock::Superblock;
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::CrashableBacking;
use rand::{rngs::StdRng, SeedableRng};
use uuid::Uuid;

fn bytes(backing: &dyn Backing, path: &str) -> Vec<u8> {
    let file = backing.open(path, false).unwrap();
    let mut bytes = vec![0; file.len().unwrap() as usize];
    file.read_at(0, &mut bytes).unwrap();
    bytes
}

fn fail_sync(backing: &CrashableBacking, failed_path: &'static str) {
    backing.set_fault_hook(Some(Arc::new(move |op| match op {
        FaultOp::SyncData { path } if *path == failed_path => {
            Some(io::Error::other("simulated metadata sync failure"))
        }
        _ => None,
    })));
}

fn failed_retry_retains_durable_copy<T: AbRecord>(mut record: T, restart: bool) {
    let backing = CrashableBacking::new();
    let mut ab = AbStore::new("m.a", "m.b");
    record.set_generation(0);
    ab.store(&backing, &mut record).unwrap();
    ab.store(&backing, &mut record).unwrap();
    backing.sync_dir("").unwrap();
    let durable_b = bytes(&backing, "m.b");

    fail_sync(&backing, "m.a");
    assert!(ab.store(&backing, &mut record).is_err());
    assert_eq!(
        ab.side_generations::<T>(&backing).unwrap(),
        (Some(3), Some(2))
    );
    if restart {
        // A process restart retains the unsynced page-cache view. Neither
        // a new AbStore nor its loaded record can remember the failed sync.
        ab = AbStore::new("m.a", "m.b");
        record = ab.load::<T>(&backing).unwrap().unwrap();
    }
    assert!(
        ab.store(&backing, &mut record).is_err(),
        "{}: the only newer copy still cannot be made durable (restart={restart})",
        std::any::type_name::<T>()
    );
    assert_eq!(bytes(&backing, "m.b"), durable_b);

    backing.set_fault_hook(None);
    backing.crash_keep_torn_prefix("m.a", 20);
    assert_eq!(bytes(&backing, "m.b"), durable_b);
    // An earlier full write of the retried image may survive even when its
    // last write tears. Either the last durable or the newer copy is valid.
    assert!(ab.load::<T>(&backing).unwrap().unwrap().generation() >= 2);
}

#[test]
fn retry_preserves_the_durable_copy_for_every_metadata_type() {
    for restart in [false, true] {
        failed_retry_retains_durable_copy(AllocationMap::new(16384), restart);
        failed_retry_retains_durable_copy(ShardCatalog::new(), restart);
        failed_retry_retains_durable_copy(CheckpointState::default(), restart);
        failed_retry_retains_durable_copy(
            KeyCanary {
                generation: 0,
                volume_uuid: Uuid::from_u128(1),
                unit_index: 0,
                ciphertext: vec![7; 540],
            },
            restart,
        );
        failed_retry_retains_durable_copy(
            Superblock {
                generation: 0,
                volume_uuid: Uuid::from_u128(1),
                provider_type: "fake".into(),
                crypto_compatibility_id: "test-profile-v1".into(),
                key_identity: "k".into(),
                geometry: Geometry::compute(512, 512, 512, 540, 512 * 1024, 512 * 64).unwrap(),
                format_version: 1,
                created_unix: 0,
            },
            restart,
        );
    }
}

#[test]
fn repeated_sync_failure_survives_sector_tearing_after_restart() {
    for restart in [false, true] {
        let backing = CrashableBacking::new().with_tearing(512);
        let mut ab = AbStore::new("allocation.a", "allocation.b");
        let mut record = AllocationMap::new(16384);
        ab.store(&backing, &mut record).unwrap();
        ab.store(&backing, &mut record).unwrap();
        backing.sync_dir("").unwrap();

        fail_sync(&backing, "allocation.a");
        assert!(ab.store(&backing, &mut record).is_err());
        if restart {
            ab = AbStore::new("allocation.a", "allocation.b");
            record = ab.load(&backing).unwrap().unwrap();
        }
        backing.set_fault_hook(Some(Arc::new(|op| match op {
            FaultOp::SyncData { .. } => Some(io::Error::other("simulated sync failure")),
            _ => None,
        })));
        assert!(ab.store(&backing, &mut record).is_err());
        backing.set_fault_hook(None);

        // The review's seed tears both sides if the retry dirties B before
        // establishing A's durability. Reconstructing AbStore cannot help.
        backing.crash(&mut StdRng::seed_from_u64(540));
        let loaded = ab.load::<AllocationMap>(&backing).unwrap();
        assert!(loaded.is_some(), "both A/B copies lost (restart={restart})");
        assert!(loaded.unwrap().generation() >= 2);
    }
}

#[test]
fn retry_syncs_the_readable_copy_before_a_torn_write_to_the_other_side() {
    let backing = CrashableBacking::new();
    let ab = AbStore::new("m.a", "m.b");
    let mut record = AllocationMap::new(16384);
    ab.store(&backing, &mut record).unwrap();
    record.set(7, true);
    ab.store(&backing, &mut record).unwrap();
    backing.sync_dir("").unwrap();

    record.set(12000, true);
    fail_sync(&backing, "m.a");
    assert!(ab.store(&backing, &mut record).is_err());
    let ab = AbStore::new("m.a", "m.b");
    let mut record = ab.load::<AllocationMap>(&backing).unwrap().unwrap();
    fail_sync(&backing, "m.b");
    assert!(ab.store(&backing, &mut record).is_err());
    backing.set_fault_hook(None);

    backing.crash_keep_torn_prefix("m.b", 512);
    let loaded = ab.load::<AllocationMap>(&backing).unwrap().unwrap();
    assert!(loaded.get(7), "the last acknowledged allocation was lost");
    assert_eq!(loaded.generation(), 3);
    assert!(loaded.get(12000));
}

#[test]
fn failed_preservation_sync_does_not_trust_a_foreign_raw_generation() {
    let backing = CrashableBacking::new();
    let ab = AbStore::new("m.a", "m.b");
    let mut record = AllocationMap::new(16384);
    ab.store(&backing, &mut record).unwrap();
    let mut foreign = ShardCatalog::new();
    foreign.set_generation(10);
    let file = backing.open("m.b", true).unwrap();
    file.write_at(0, &foreign.encode()).unwrap();
    file.sync_data().unwrap();
    backing.sync_dir("").unwrap();

    fail_sync(&backing, "m.a");
    assert!(ab.store(&backing, &mut record).is_err());
    assert_eq!(bytes(&backing, "m.b"), foreign.encode());
    backing.set_fault_hook(None);
    ab.store(&backing, &mut record).unwrap();
    assert!(record.generation() > 10);
    assert_eq!(
        ab.side_generations::<AllocationMap>(&backing).unwrap().0,
        Some(1)
    );
}

#[test]
fn retry_preserves_a_new_side_whose_directory_sync_failed() {
    let backing = CrashableBacking::new();
    backing.create_dir_all("metadata").unwrap();
    backing.sync_dir("").unwrap();
    let ab = AbStore::new("metadata/m.a", "metadata/m.b");
    let mut record = AllocationMap::new(16384);
    ab.store(&backing, &mut record).unwrap();
    backing.sync_dir("metadata").unwrap();
    record.set(7, true);
    ab.store(&backing, &mut record).unwrap();

    backing.set_fault_hook(Some(Arc::new(|op| match op {
        FaultOp::SyncDir { dir: "metadata" } => Some(io::Error::other("directory sync failed")),
        _ => None,
    })));
    assert!(backing.sync_dir("metadata").is_err());
    let durable_a = bytes(&backing, "metadata/m.a");
    assert!(ab.store(&backing, &mut record).is_err());
    assert_eq!(bytes(&backing, "metadata/m.a"), durable_a);
}

#[test]
fn retry_makes_the_preserved_side_directory_entry_durable() {
    let backing = CrashableBacking::new();
    backing.create_dir_all("metadata").unwrap();
    backing.sync_dir("").unwrap();
    let ab = AbStore::new("metadata/m.a", "metadata/m.b");
    let mut record = AllocationMap::new(16384);
    ab.store(&backing, &mut record).unwrap();
    backing.sync_dir("metadata").unwrap();
    record.set(7, true);
    ab.store(&backing, &mut record).unwrap();
    // Simulate a restart before the caller can sync the new B dirent.
    let ab = AbStore::new("metadata/m.a", "metadata/m.b");
    let mut record = ab.load::<AllocationMap>(&backing).unwrap().unwrap();
    fail_sync(&backing, "metadata/m.a");
    assert!(ab.store(&backing, &mut record).is_err());
    backing.set_fault_hook(None);

    backing.crash_keep_torn_prefix("metadata/m.a", 512);
    let loaded = ab
        .load::<AllocationMap>(&backing)
        .unwrap()
        .expect("B's dirent must survive");
    assert_eq!(loaded.generation(), 2);
    assert!(loaded.get(7));
}

/// Linux can clear dirty page-cache bits after writeback EIO, so another
/// sync succeeds without retrying the failed writes. Keep CrashableBacking's
/// pending bytes readable, but only send them to disk after a fresh write.
/// See https://www.kernel.org/doc/html/v6.17/filesystems/iomap/operations.html
/// ("Pagecache Writeback").
#[derive(Default)]
struct FailedWritebackBacking {
    inner: CrashableBacking,
    dirty: Mutex<HashMap<String, Arc<AtomicBool>>>,
    failing: Arc<Mutex<HashSet<String>>>,
}

struct FailedWritebackFile {
    inner: Arc<dyn BackingFile>,
    path: String,
    dirty: Arc<AtomicBool>,
    failing: Arc<Mutex<HashSet<String>>>,
}

impl BackingFile for FailedWritebackFile {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.inner.read_at(offset, buf)
    }

    fn write_at(&self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        self.inner.write_at(offset, bytes)?;
        self.dirty.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.inner.set_len(len)?;
        self.dirty.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }

    fn sync_data(&self) -> io::Result<()> {
        if !self.dirty.swap(false, Ordering::SeqCst) {
            return Ok(());
        }
        if self.failing.lock().unwrap().contains(&self.path) {
            return Err(io::Error::other("writeback failed and cleared dirty bits"));
        }
        self.inner.sync_data()
    }
}

impl Backing for FailedWritebackBacking {
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        let inner = self.inner.open(path, create)?;
        let dirty = self
            .dirty
            .lock()
            .unwrap()
            .entry(path.into())
            .or_default()
            .clone();
        Ok(Arc::new(FailedWritebackFile {
            inner,
            path: path.into(),
            dirty,
            failing: self.failing.clone(),
        }))
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
}

#[test]
fn retry_rewrites_a_preserved_copy_after_writeback_discards_its_dirty_bits() {
    let backing = FailedWritebackBacking::default();
    let ab = AbStore::new("m.a", "m.b");
    let mut record = AllocationMap::new(16384);
    ab.store(&backing, &mut record).unwrap();
    record.set(7, true);
    ab.store(&backing, &mut record).unwrap();
    backing.sync_dir("").unwrap();

    backing.failing.lock().unwrap().insert("m.a".into());
    record.set(12000, true);
    assert!(ab.store(&backing, &mut record).is_err());
    backing.failing.lock().unwrap().remove("m.a");
    backing.failing.lock().unwrap().insert("m.b".into());
    let ab = AbStore::new("m.a", "m.b");
    let mut record = ab.load::<AllocationMap>(&backing).unwrap().unwrap();
    assert!(ab.store(&backing, &mut record).is_err());
    backing.failing.lock().unwrap().clear();

    backing.inner.crash_keep_torn_prefix("m.b", 512);
    let loaded = ab.load::<AllocationMap>(&backing).unwrap().unwrap();
    assert!(
        loaded.get(7),
        "sync retry accepted clean cache bytes that were never durable"
    );
    assert_eq!(loaded.generation(), 3);
    assert!(loaded.get(12000));
}
