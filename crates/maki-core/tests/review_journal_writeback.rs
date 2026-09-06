//! BUG-021: Linux writeback EIO can clear dirty cache bits. A later sync
//! must not acknowledge bytes unless a verified rewrite makes them durable.
//! https://www.kernel.org/doc/html/v6.17/filesystems/iomap/operations.html

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use maki_backing::{Backing, BackingFile, VolumeLock};
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::geometry::Geometry;
use maki_format::journal::{encode_record, JournalRecord, SEGMENT_HEADER_SIZE};
use maki_format::superblock::Superblock;
use maki_format::{init, layout};
use maki_test_support::{failpoints, CrashableBacking};
use uuid::Uuid;

const CIPHERTEXT_SIZE: usize = 540;
const SECOND_PAYLOAD_OFFSET: u64 = SEGMENT_HEADER_SIZE as u64 + 32 + CIPHERTEXT_SIZE as u64 + 32;

#[derive(Default)]
struct WritebackBacking {
    inner: CrashableBacking,
    dirty: Mutex<HashMap<String, Arc<AtomicBool>>>,
    fail_sync: Arc<AtomicBool>,
    change_after_scan: Arc<AtomicBool>,
}

struct WritebackFile {
    inner: Arc<dyn BackingFile>,
    is_segment: bool,
    dirty: Arc<AtomicBool>,
    fail_sync: Arc<AtomicBool>,
    change_after_scan: Arc<AtomicBool>,
}

impl BackingFile for WritebackFile {
    fn read_at(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        self.inner.read_at(offset, bytes)?;
        if self.is_segment
            && offset == 0
            && bytes.len() > SECOND_PAYLOAD_OFFSET as usize
            && self.change_after_scan.swap(false, Ordering::SeqCst)
        {
            // The scan got the valid cached image, but subsequent reads see
            // different bytes (e.g. failed writeback pages were reclaimed).
            self.inner.write_at(SECOND_PAYLOAD_OFFSET, &[0xFE])?;
        }
        Ok(())
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
        if self.is_segment {
            if !self.dirty.swap(false, Ordering::SeqCst) {
                return Ok(()); // failed writes are no longer queued for writeback
            }
            if self.fail_sync.load(Ordering::SeqCst) {
                return Err(io::Error::other("writeback EIO cleared dirty bits"));
            }
        }
        self.inner.sync_data()
    }
}

impl Backing for WritebackBacking {
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        let dirty = self
            .dirty
            .lock()
            .unwrap()
            .entry(path.into())
            .or_default()
            .clone();
        Ok(Arc::new(WritebackFile {
            inner: self.inner.open(path, create)?,
            is_segment: path
                .strip_prefix("journal/")
                .and_then(layout::parse_journal_segment)
                .is_some(),
            dirty,
            fail_sync: self.fail_sync.clone(),
            change_after_scan: self.change_after_scan.clone(),
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

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: 256 * 1024,
    }
}

fn new_volume(backing: &Arc<WritebackBacking>) -> Volume {
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: Uuid::from_u128(0xB021),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, 512, 512, 544, 512 * 256, 512 * 16).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    Volume::recover(backing.clone(), options()).unwrap()
}

#[test]
fn a_flush_retry_rewrites_failed_writeback_bytes_before_acknowledging_them() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(WritebackBacking::default());
    let mut volume = new_volume(&backing);
    volume.write_ct(0, &[1; CIPHERTEXT_SIZE], true).unwrap();
    // More than 64 KiB of pending records exercises bounded chunk handling.
    for unit in 1..=130 {
        volume.write_ct(unit, &[2; CIPHERTEXT_SIZE], false).unwrap();
    }
    backing.fail_sync.store(true, Ordering::SeqCst);
    assert!(volume.flush().is_err());
    backing.fail_sync.store(false, Ordering::SeqCst);
    volume.flush().unwrap();
    drop(volume);
    backing.inner.crash_all_lost();

    let volume = Volume::recover(backing, options()).unwrap();
    for unit in 1..=130 {
        assert_eq!(
            volume.read_ct(unit).unwrap().map(|(_, bytes)| bytes),
            Some(vec![2; CIPHERTEXT_SIZE])
        );
    }
}

#[test]
fn process_recovery_rewrites_clean_cache_bytes_before_sealing_the_journal() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(WritebackBacking::default());
    let mut volume = new_volume(&backing);
    volume.write_ct(0, &[1; CIPHERTEXT_SIZE], true).unwrap();
    volume.write_ct(1, &[2; CIPHERTEXT_SIZE], false).unwrap();
    backing.fail_sync.store(true, Ordering::SeqCst);
    assert!(volume.flush().is_err());
    drop(volume); // cached bytes survive the process
    backing.fail_sync.store(false, Ordering::SeqCst);

    let mut volume = Volume::recover(backing.clone(), options()).unwrap();
    assert!(volume.read_ct(1).unwrap().is_some());
    volume.flush().unwrap();
    drop(volume);
    backing.inner.crash_all_lost();
    let volume = Volume::recover(backing, options())
        .expect("the previous recovery must actually persist every byte it accepted");
    assert_eq!(
        volume.read_ct(1).unwrap().unwrap().1,
        vec![2; CIPHERTEXT_SIZE]
    );
}

#[test]
fn retry_does_not_acknowledge_changed_bytes_after_failed_writeback() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(WritebackBacking::default());
    let mut volume = new_volume(&backing);
    volume.write_ct(0, &[1; CIPHERTEXT_SIZE], true).unwrap();
    volume.write_ct(1, &[2; CIPHERTEXT_SIZE], false).unwrap();
    backing.fail_sync.store(true, Ordering::SeqCst);
    assert!(volume.flush().is_err());
    backing.fail_sync.store(false, Ordering::SeqCst);
    let segment = volume.journal_active_segment_path().unwrap();
    backing
        .inner
        .open(&segment, false)
        .unwrap()
        .write_at(SECOND_PAYLOAD_OFFSET, &[0xFE])
        .unwrap();

    assert!(
        volume.flush().is_err(),
        "a successful sync cannot validate lost/changed cached records"
    );
    assert_eq!(volume.journal_durable_sequence(), 1);
}

#[test]
fn recovery_refuses_bytes_that_changed_after_the_validated_scan() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(WritebackBacking::default());
    let mut volume = new_volume(&backing);
    volume.write_ct(0, &[1; CIPHERTEXT_SIZE], true).unwrap();
    volume.write_ct(1, &[2; CIPHERTEXT_SIZE], false).unwrap();
    backing.fail_sync.store(true, Ordering::SeqCst);
    assert!(volume.flush().is_err());
    drop(volume);
    backing.fail_sync.store(false, Ordering::SeqCst);
    backing.change_after_scan.store(true, Ordering::SeqCst);

    assert!(
        Volume::recover(backing, options()).is_err(),
        "recovery must not persist a different image than it validated"
    );
}

#[test]
fn retry_rejects_a_changed_header_even_when_the_record_crc_residue_is_unchanged() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(WritebackBacking::default());
    let mut volume = new_volume(&backing);
    volume.write_ct(0, &[1; CIPHERTEXT_SIZE], true).unwrap();
    volume.write_ct(1, &[2; CIPHERTEXT_SIZE], false).unwrap();
    backing.fail_sync.store(true, Ordering::SeqCst);
    assert!(volume.flush().is_err());
    backing.fail_sync.store(false, Ordering::SeqCst);

    let original = encode_record(&JournalRecord {
        sequence: 2,
        unit_index: 1,
        payload: vec![2; CIPHERTEXT_SIZE],
    });
    let changed = encode_record(&JournalRecord {
        sequence: 2,
        unit_index: 2,
        payload: vec![2; CIPHERTEXT_SIZE],
    });
    // Hashing a self-checksummed header with the same CRC algorithm cannot
    // fingerprint its contents: both valid headers have the same residue.
    assert_eq!(crc32fast::hash(&original), crc32fast::hash(&changed));
    let segment = volume.journal_active_segment_path().unwrap();
    backing
        .inner
        .open(&segment, false)
        .unwrap()
        .write_at(SECOND_PAYLOAD_OFFSET - 32, &changed[..32])
        .unwrap();
    assert!(
        volume.flush().is_err(),
        "the pending record changed its destination unit"
    );
    assert_eq!(volume.journal_durable_sequence(), 1);
}
