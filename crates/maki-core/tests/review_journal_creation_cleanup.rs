//! BUG-060: failed segment creation must leave a durable absence before a
//! successful FLUSH/FUA. A failed pwrite may reach disk before its error; an
//! unsynced unlink can resurrect the unaccepted, invalid header after power loss.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use maki_backing::{Backing, BackingFile, VolumeLock};
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::{geometry::Geometry, init, layout, superblock::Superblock};
use maki_test_support::{failpoints, CrashableBacking};

#[derive(Default)]
struct Faults {
    partial_header: AtomicBool,
    remove: AtomicBool,
    dirsync: AtomicBool,
}

struct CreationBacking {
    inner: Arc<CrashableBacking>,
    target: String,
    faults: Arc<Faults>,
}

struct CreationFile {
    inner: Arc<dyn BackingFile>,
    backing: Arc<CrashableBacking>,
    target: bool,
    faults: Arc<Faults>,
}

impl BackingFile for CreationFile {
    fn read_at(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        self.inner.read_at(offset, bytes)
    }

    fn write_at(&self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        if self.target
            && offset == 0
            && bytes.len() == maki_format::journal::SEGMENT_HEADER_SIZE
            && self.faults.partial_header.swap(false, Ordering::SeqCst)
        {
            // Model permitted background writeback before pwrite returns EIO.
            // The original backing operations persist an actual prefix and its
            // created inode; no payload or operation result is forged.
            self.inner.write_at(offset, &bytes[..20])?;
            self.inner.sync_data()?;
            self.backing.sync_dir(layout::JOURNAL_DIR)?;
            return Err(io::Error::other("partial segment header write"));
        }
        self.inner.write_at(offset, bytes)
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.inner.set_len(len)
    }

    fn allocate_range(&self, offset: u64, len: u64) -> io::Result<()> {
        self.inner.allocate_range(offset, len)
    }

    fn punch_hole(&self, offset: u64, len: u64) -> io::Result<()> {
        self.inner.punch_hole(offset, len)
    }

    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }

    fn sync_data(&self) -> io::Result<()> {
        self.inner.sync_data()
    }
}

impl Backing for CreationBacking {
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        Ok(Arc::new(CreationFile {
            inner: self.inner.open(path, create)?,
            backing: self.inner.clone(),
            target: path == self.target,
            faults: self.faults.clone(),
        }))
    }

    fn exists(&self, path: &str) -> io::Result<bool> {
        self.inner.exists(path)
    }

    fn remove(&self, path: &str) -> io::Result<()> {
        if path == self.target && self.faults.remove.load(Ordering::SeqCst) {
            return Err(io::Error::other("segment cleanup remove failed"));
        }
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
        if dir == layout::JOURNAL_DIR && self.faults.dirsync.load(Ordering::SeqCst) {
            return Err(io::Error::other("segment cleanup dirsync failed"));
        }
        self.inner.sync_dir(dir)
    }

    fn try_lock(&self, path: &str) -> io::Result<Box<dyn VolumeLock>> {
        self.inner.try_lock(path)
    }

    fn free_bytes(&self) -> io::Result<Option<u64>> {
        self.inner.free_bytes()
    }
}

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: 4096,
    }
}

fn fixture(successor: bool, discard: bool) -> (Arc<CreationBacking>, Volume) {
    let backing = Arc::new(CreationBacking {
        inner: Arc::new(CrashableBacking::new().with_tearing(512)),
        target: layout::journal_segment(u64::from(successor)),
        faults: Arc::default(),
    });
    let sb = Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(0x2026_1013_0060),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, 512, 512, 1024, 512 * 64, 512 * 16).unwrap(),
        format_version: 1,
        created_unix: 0,
    };
    if discard {
        init::create_volume_with_discard(backing.as_ref(), sb).unwrap();
    } else {
        init::create_volume(backing.as_ref(), sb).unwrap();
    }
    let mut volume = Volume::recover(backing.clone(), options()).unwrap();
    if successor {
        for unit in 0..3 {
            volume
                .write_ct(unit, &vec![(unit + 1) as u8; 1024], true)
                .unwrap();
        }
    }
    (backing, volume)
}

fn fail_creation(backing: &CreationBacking, volume: &mut Volume, successor: bool) {
    let before = volume.journal_appended_sequence();
    backing.faults.partial_header.store(true, Ordering::SeqCst);
    let error = volume
        .write_ct(if successor { 3 } else { 0 }, &[7; 1024], false)
        .expect_err("partial header creation must fail");
    assert!(error.to_string().contains("partial segment header write"));
    assert_eq!(volume.journal_appended_sequence(), before);
    assert_eq!(volume.journal_durable_sequence(), before);
}

fn crash_recover(backing: &Arc<CreationBacking>, volume: Volume, successor: bool) -> Volume {
    drop(volume);
    backing.inner.crash_all_lost();
    let volume = Volume::recover(backing.clone(), options())
        .expect("a successful barrier must leave every acknowledged record recoverable");
    if successor {
        for unit in 0..3 {
            assert_eq!(
                volume.read_ct(unit).unwrap().unwrap().1,
                vec![(unit + 1) as u8; 1024]
            );
        }
    }
    volume
}

#[test]
fn first_segment_partial_creation_cleanup_survives_power_loss_after_flush() {
    let _serial = failpoints::test_lock();
    for discard in [false, true] {
        let (backing, mut volume) = fixture(false, discard);
        fail_creation(&backing, &mut volume, false);
        assert!(!backing.exists(&backing.target).unwrap());
        volume.flush().unwrap();
        let volume = crash_recover(&backing, volume, false);
        assert!(volume.read_ct(0).unwrap().is_none());
    }
}

#[test]
fn successor_partial_creation_cleanup_preserves_prior_fua_records() {
    let _serial = failpoints::test_lock();
    for discard in [false, true] {
        let (backing, mut volume) = fixture(true, discard);
        fail_creation(&backing, &mut volume, true);
        assert!(!backing.exists(&backing.target).unwrap());
        volume.flush().unwrap();
        crash_recover(&backing, volume, true);
    }
}

#[test]
fn failed_cleanup_remove_blocks_flush_until_removal_and_directory_sync_succeed() {
    let _serial = failpoints::test_lock();
    for successor in [false, true] {
        let (backing, mut volume) = fixture(successor, false);
        backing.faults.remove.store(true, Ordering::SeqCst);
        fail_creation(&backing, &mut volume, successor);
        assert!(backing.exists(&backing.target).unwrap());
        for _ in 0..2 {
            let error = volume
                .flush()
                .expect_err("unfinished cleanup cannot acknowledge FLUSH");
            assert!(error.to_string().contains("segment cleanup remove failed"));
        }
        assert!(volume.journal_writeback_uncertain());
        backing.faults.remove.store(false, Ordering::SeqCst);
        volume.flush().unwrap();
        assert!(!volume.journal_writeback_uncertain());
        assert!(!backing.exists(&backing.target).unwrap());
        // Completed cleanup must not be attempted by a later idle barrier.
        backing.faults.remove.store(true, Ordering::SeqCst);
        volume.flush().unwrap();
        crash_recover(&backing, volume, successor);
    }
}

#[test]
fn failed_cleanup_directory_sync_is_retried_even_when_the_file_is_already_absent() {
    let _serial = failpoints::test_lock();
    for successor in [false, true] {
        let (backing, mut volume) = fixture(successor, false);
        backing.faults.dirsync.store(true, Ordering::SeqCst);
        fail_creation(&backing, &mut volume, successor);
        assert!(!backing.exists(&backing.target).unwrap());
        for _ in 0..2 {
            let error = volume
                .flush()
                .expect_err("unsynced unlink cannot acknowledge FLUSH");
            assert!(error.to_string().contains("segment cleanup dirsync failed"));
        }
        assert!(volume.journal_writeback_uncertain());
        backing.faults.dirsync.store(false, Ordering::SeqCst);
        volume.flush().unwrap();
        assert!(!volume.journal_writeback_uncertain());
        // The directory is clean: an idle barrier needs no redundant sync.
        backing.faults.dirsync.store(true, Ordering::SeqCst);
        volume.flush().unwrap();
        backing.faults.dirsync.store(false, Ordering::SeqCst);
        crash_recover(&backing, volume, successor);
    }
}

#[test]
fn cleanup_remove_failure_blocks_fua_retry_without_consuming_a_sequence() {
    let _serial = failpoints::test_lock();
    for successor in [false, true] {
        let (backing, mut volume) = fixture(successor, false);
        backing.faults.remove.store(true, Ordering::SeqCst);
        fail_creation(&backing, &mut volume, successor);
        let before = volume.journal_appended_sequence();
        let unit = if successor { 3 } else { 0 };
        assert!(volume.write_ct(unit, &[8; 1024], true).is_err());
        assert_eq!(volume.journal_appended_sequence(), before);
        backing.faults.remove.store(false, Ordering::SeqCst);
        assert_eq!(volume.write_ct(unit, &[8; 1024], true).unwrap(), before + 1);
        let volume = crash_recover(&backing, volume, successor);
        assert_eq!(volume.read_ct(unit).unwrap().unwrap().1, vec![8; 1024]);
    }
}

#[test]
fn cleanup_directory_sync_failure_blocks_fua_index_reuse() {
    let _serial = failpoints::test_lock();
    for successor in [false, true] {
        let (backing, mut volume) = fixture(successor, false);
        backing.faults.dirsync.store(true, Ordering::SeqCst);
        fail_creation(&backing, &mut volume, successor);
        let before = volume.journal_appended_sequence();
        let unit = if successor { 3 } else { 0 };
        assert!(volume.write_ct(unit, &[8; 1024], true).is_err());
        assert_eq!(volume.journal_appended_sequence(), before);
        assert!(
            !backing.exists(&backing.target).unwrap(),
            "failed index must not be recreated before cleanup sync succeeds"
        );
        backing.faults.dirsync.store(false, Ordering::SeqCst);
        volume.write_ct(unit, &[8; 1024], true).unwrap();
        let volume = crash_recover(&backing, volume, successor);
        assert_eq!(volume.read_ct(unit).unwrap().unwrap().1, vec![8; 1024]);
    }
}

#[test]
fn successful_write_retry_recreates_the_failed_index_and_survives_restart_then_crash() {
    let _serial = failpoints::test_lock();
    for successor in [false, true] {
        for discard in [false, true] {
            let (backing, mut volume) = fixture(successor, discard);
            fail_creation(&backing, &mut volume, successor);
            let unit = if successor { 3 } else { 0 };
            volume.write_ct(unit, &[8; 1024], true).unwrap();
            drop(volume);
            let mut restarted = Volume::recover(backing.clone(), options()).unwrap();
            restarted.flush().unwrap();
            let volume = crash_recover(&backing, restarted, successor);
            assert_eq!(volume.read_ct(unit).unwrap().unwrap().1, vec![8; 1024]);
        }
    }
}

#[test]
fn cleanup_then_process_restart_does_not_need_to_recover_the_failed_creation() {
    let _serial = failpoints::test_lock();
    for successor in [false, true] {
        let (backing, mut volume) = fixture(successor, false);
        fail_creation(&backing, &mut volume, successor);
        volume.flush().unwrap();
        drop(volume);
        let mut restarted = Volume::recover(backing.clone(), options()).unwrap();
        restarted.flush().unwrap();
        crash_recover(&backing, restarted, successor);
    }
}

#[test]
fn an_unremoved_invalid_header_still_fails_closed_after_power_loss() {
    let _serial = failpoints::test_lock();
    for successor in [false, true] {
        let (backing, mut volume) = fixture(successor, false);
        backing.faults.remove.store(true, Ordering::SeqCst);
        fail_creation(&backing, &mut volume, successor);
        drop(volume);
        backing.faults.remove.store(false, Ordering::SeqCst);
        backing.inner.crash_all_lost();
        let error = Volume::recover(backing.clone(), options())
            .err()
            .expect("invalid nonzero segment headers must not be discarded as crash artifacts");
        assert!(error.to_string().contains("invalid header"));
    }
}

#[test]
fn an_explicit_cleanup_directory_sync_is_a_recovery_control() {
    let _serial = failpoints::test_lock();
    for successor in [false, true] {
        let (backing, mut volume) = fixture(successor, false);
        fail_creation(&backing, &mut volume, successor);
        backing.sync_dir(layout::JOURNAL_DIR).unwrap();
        volume.flush().unwrap();
        crash_recover(&backing, volume, successor);
    }
}

#[test]
fn checkpoint_retries_failed_creation_cleanup_before_acknowledging_reclamation() {
    let _serial = failpoints::test_lock();
    for successor in [false, true] {
        let (backing, mut volume) = fixture(successor, false);
        backing.faults.remove.store(true, Ordering::SeqCst);
        fail_creation(&backing, &mut volume, successor);
        assert!(volume.checkpoint().is_err());
        backing.faults.remove.store(false, Ordering::SeqCst);
        backing.faults.dirsync.store(true, Ordering::SeqCst);
        assert!(volume.checkpoint().is_err());
        assert!(volume.journal_writeback_uncertain());
        backing.faults.dirsync.store(false, Ordering::SeqCst);
        assert_eq!(volume.checkpoint().unwrap(), u64::from(successor) * 3);
        assert!(!volume.journal_writeback_uncertain());
        crash_recover(&backing, volume, successor);
    }
}

#[test]
fn restart_after_unsynced_unlink_reestablishes_cleanup_before_flush_or_checkpoint() {
    let _serial = failpoints::test_lock();
    for successor in [false, true] {
        for checkpoint in [false, true] {
            let (backing, mut volume) = fixture(successor, false);
            backing.faults.dirsync.store(true, Ordering::SeqCst);
            fail_creation(&backing, &mut volume, successor);
            assert!(!backing.exists(&backing.target).unwrap());
            drop(volume); // A process restart preserves the cached unlink.
            backing.faults.dirsync.store(false, Ordering::SeqCst);
            let mut restarted = Volume::recover(backing.clone(), options()).unwrap();
            if checkpoint {
                restarted.checkpoint().unwrap();
            } else {
                restarted.flush().unwrap();
            }
            crash_recover(&backing, restarted, successor);
        }
    }
}
