//! F09: file length and unwritten physical extents have separate durability.
use std::collections::BTreeSet;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use maki_backing::{Backing, BackingFile, VolumeLock};
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::CrashableBacking;

#[derive(Default)]
struct Extents {
    pending: BTreeSet<(String, u64, u64)>,
    durable: BTreeSet<(String, u64, u64)>,
    full: bool,
}

#[derive(Default)]
struct ExtentBacking {
    bytes: CrashableBacking,
    extents: Arc<Mutex<Extents>>,
    fail_barrier: Arc<AtomicBool>,
}

impl ExtentBacking {
    fn power_loss_and_exhaust_space(&self) {
        self.bytes.crash_all_lost();
        let mut extents = self.extents.lock().unwrap();
        extents.pending = extents.durable.clone();
        extents.full = true;
    }
}

struct ExtentFile {
    inner: Arc<dyn BackingFile>,
    path: String,
    extents: Arc<Mutex<Extents>>,
    fail_barrier: Arc<AtomicBool>,
}

impl BackingFile for ExtentFile {
    fn read_at(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        self.inner.read_at(offset, bytes)
    }
    fn write_at(&self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        if self.path.ends_with(".dat") {
            let state = self.extents.lock().unwrap();
            if state.full
                && !state.pending.iter().any(|(path, start, len)| {
                    path == &self.path
                        && offset >= *start
                        && offset + bytes.len() as u64 <= start + len
                })
            {
                return Err(io::Error::from(io::ErrorKind::StorageFull));
            }
        }
        self.inner.write_at(offset, bytes)
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.inner.set_len(len)
    }
    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }
    fn allocate_range(&self, offset: u64, len: u64) -> io::Result<()> {
        let mut state = self.extents.lock().unwrap();
        let key = (self.path.clone(), offset, len);
        if state.full && !state.pending.contains(&key) {
            return Err(io::Error::from(io::ErrorKind::StorageFull));
        }
        self.inner.allocate_range(offset, len)?;
        state.pending.insert(key);
        Ok(())
    }
    // Deliberately does not commit unwritten extents: unchanged EOF does not
    // prove allocation metadata persisted through an fdatasync implementation.
    fn sync_data(&self) -> io::Result<()> {
        self.inner.sync_data()
    }
    fn sync_all(&self) -> io::Result<()> {
        if self.path.ends_with(".dat") && self.fail_barrier.swap(false, Ordering::SeqCst) {
            return Err(io::Error::other("allocation barrier failed"));
        }
        self.inner.sync_all()?;
        let mut state = self.extents.lock().unwrap();
        let own: Vec<_> = state
            .pending
            .iter()
            .filter(|(path, _, _)| path == &self.path)
            .cloned()
            .collect();
        state.durable.extend(own);
        Ok(())
    }
}

impl Backing for ExtentBacking {
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        Ok(Arc::new(ExtentFile {
            inner: self.bytes.open(path, create)?,
            path: path.into(),
            extents: self.extents.clone(),
            fail_barrier: self.fail_barrier.clone(),
        }))
    }
    fn exists(&self, path: &str) -> io::Result<bool> {
        self.bytes.exists(path)
    }
    fn remove(&self, path: &str) -> io::Result<()> {
        self.bytes.remove(path)
    }
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        self.bytes.rename(from, to)
    }
    fn create_dir_all(&self, path: &str) -> io::Result<()> {
        self.bytes.create_dir_all(path)
    }
    fn list(&self, dir: &str) -> io::Result<Vec<String>> {
        self.bytes.list(dir)
    }
    fn sync_dir(&self, dir: &str) -> io::Result<()> {
        self.bytes.sync_dir(dir)
    }
    fn try_lock(&self, path: &str) -> io::Result<Box<dyn VolumeLock>> {
        self.bytes.try_lock(path)
    }
}

fn fixture(segment_size: u64) -> (Arc<ExtentBacking>, Volume) {
    let backing = Arc::new(ExtentBacking::default());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xf09),
            provider_type: "fake".into(),
            crypto_compatibility_id: "reservation-durability".into(),
            key_identity: "key".into(),
            geometry: Geometry::compute(512, 512, 512, 512, 4096, 512).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let volume = Volume::recover(
        backing.clone(),
        VolumeOptions {
            journal_segment_size: segment_size,
        },
    )
    .unwrap();
    (backing, volume)
}

#[test]
fn review_f09_fua_reservation_survives_power_loss_and_external_enospc() {
    let (backing, mut volume) = fixture(8192);
    volume.write_ct(0, &[0x31; 512], true).unwrap();
    drop(volume);
    backing.power_loss_and_exhaust_space();
    let mut recovered = Volume::recover(backing, VolumeOptions::default())
        .expect("FUA replay must retain its completion extent");
    assert_eq!(recovered.read_ct(0).unwrap().unwrap().1, vec![0x31; 512]);
}

#[test]
fn review_f09_flush_preserves_reservations_on_every_touched_shard() {
    let (backing, mut volume) = fixture(8192);
    for unit in [0, 3] {
        volume.write_ct(unit, &[0x42; 512], false).unwrap();
    }
    volume.flush().unwrap();
    drop(volume);
    backing.power_loss_and_exhaust_space();
    let mut recovered = Volume::recover(backing, VolumeOptions::default())
        .expect("FLUSH replay must retain every touched extent");
    for unit in [0, 3] {
        assert_eq!(recovered.read_ct(unit).unwrap().unwrap().1, vec![0x42; 512]);
    }
}

#[test]
fn review_f09_allocation_barrier_failure_precedes_journal_publication_and_is_retryable() {
    let (backing, mut volume) = fixture(8192);
    backing.fail_barrier.store(true, Ordering::SeqCst);
    assert!(volume.write_ct(0, &[0x53; 512], true).is_err());
    assert_eq!(volume.journal_appended_sequence(), 0);
    assert_eq!(volume.journal_durable_sequence(), 0);
    assert_eq!(volume.overlay_len(), 0);
    volume.write_ct(0, &[0x53; 512], true).unwrap();
    drop(volume);
    backing.power_loss_and_exhaust_space();
    assert!(Volume::recover(backing, VolumeOptions::default()).is_ok());
}

#[test]
fn review_f09_automatic_roll_preserves_the_sealed_prefix_reservation() {
    let (backing, mut volume) = fixture(1024);
    volume.write_ct(0, &[0x64; 512], false).unwrap();
    volume.write_ct(1, &[0x65; 512], false).unwrap();
    assert_eq!(volume.journal_durable_sequence(), 1);
    drop(volume);
    backing.power_loss_and_exhaust_space();
    let recovered = Volume::recover(backing, VolumeOptions::default())
        .expect("automatic roll must preserve completion space for its sealed prefix");
    assert_eq!(recovered.read_ct(0).unwrap().unwrap().1, vec![0x64; 512]);
}

#[test]
fn review_f09_model_does_not_confuse_durable_eof_with_durable_extents() {
    let (backing, volume) = fixture(8192);
    let file = backing.open("data/extent-control.dat", true).unwrap();
    file.set_len(4096).unwrap();
    file.sync_data().unwrap();
    file.allocate_range(0, 512).unwrap();
    file.sync_data().unwrap();
    backing.sync_dir("data").unwrap();
    drop(volume);
    backing.power_loss_and_exhaust_space();
    let file = backing.open("data/extent-control.dat", false).unwrap();
    assert_eq!(file.len().unwrap(), 4096);
    assert_eq!(
        file.write_at(0, &[0x75; 512]).unwrap_err().kind(),
        io::ErrorKind::StorageFull
    );
}
