//! BUG-020: a failed positional write may have extended the journal. Its
//! incomplete suffix must not survive a shorter retry or become sealed.

use std::io;
use std::sync::{Arc, Mutex};

use maki_backing::{Backing, BackingFile, VolumeLock};
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::geometry::Geometry;
use maki_format::journal::SEGMENT_HEADER_SIZE;
use maki_format::superblock::Superblock;
use maki_format::{init, layout};
use maki_test_support::{failpoints, CrashableBacking};
use uuid::Uuid;

#[derive(Default)]
struct Faults {
    partial_write: Option<usize>,
    fail_truncate: bool,
}

#[derive(Default)]
struct PartialWriteBacking {
    inner: CrashableBacking,
    faults: Arc<Mutex<Faults>>,
}

struct PartialWriteFile {
    inner: Arc<dyn BackingFile>,
    is_segment: bool,
    faults: Arc<Mutex<Faults>>,
}

impl BackingFile for PartialWriteFile {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.inner.read_at(offset, buf)
    }

    fn write_at(&self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        if self.is_segment && offset >= SEGMENT_HEADER_SIZE as u64 {
            if let Some(keep) = self.faults.lock().unwrap().partial_write.take() {
                assert!(keep < bytes.len(), "fault must leave a partial record");
                self.inner.write_at(offset, &bytes[..keep])?;
                return Err(io::Error::new(io::ErrorKind::StorageFull, "partial ENOSPC"));
            }
        }
        self.inner.write_at(offset, bytes)
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        if self.is_segment && self.faults.lock().unwrap().fail_truncate {
            return Err(io::Error::other("journal truncate failed"));
        }
        self.inner.set_len(len)
    }

    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }

    fn sync_data(&self) -> io::Result<()> {
        self.inner.sync_data()
    }
}

impl Backing for PartialWriteBacking {
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        Ok(Arc::new(PartialWriteFile {
            inner: self.inner.open(path, create)?,
            is_segment: path
                .strip_prefix("journal/")
                .and_then(layout::parse_journal_segment)
                .is_some(),
            faults: self.faults.clone(),
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
        journal_segment_size: 2048,
    }
}

fn new_volume(backing: &Arc<PartialWriteBacking>) -> Volume {
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: Uuid::from_u128(0xB020),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, 512, 512, 1024, 512 * 64, 512 * 16).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    Volume::recover(backing.clone(), options()).unwrap()
}

#[test]
fn shorter_retry_after_partial_append_does_not_seal_the_failed_suffix() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(PartialWriteBacking::default());
    let mut volume = new_volume(&backing);
    let first = vec![1; 932];
    let short = vec![2; 64];
    let last = vec![3; 1024];
    volume.write_ct(0, &first, true).unwrap();
    backing.faults.lock().unwrap().partial_write = Some(700);
    assert!(volume.write_ct(1, &[9; 1000], false).is_err());
    assert_eq!(volume.write_ct(2, &short, false).unwrap(), 2);
    volume.write_ct(3, &last, true).unwrap(); // rolls the shorter retry's segment
    assert_eq!(volume.journal_segment_count(), 2);
    drop(volume);
    backing.inner.crash_all_lost();

    let volume = Volume::recover(backing, options())
        .expect("a shorter retry must not leave corrupt bytes in the sealed segment");
    assert_eq!(volume.read_ct(0).unwrap().unwrap().1, first);
    assert!(volume.read_ct(1).unwrap().is_none());
    assert_eq!(volume.read_ct(2).unwrap().unwrap().1, short);
    assert_eq!(volume.read_ct(3).unwrap().unwrap().1, last);
}

#[test]
fn flush_and_roll_after_a_partial_append_make_tail_cleanup_durable() {
    for flush_before_roll in [false, true] {
        let _guard = failpoints::test_lock();
        let backing = Arc::new(PartialWriteBacking::default());
        let mut volume = new_volume(&backing);
        let first = vec![1; 932];
        let next = vec![2; 1024];
        volume.write_ct(0, &first, true).unwrap();
        let original_segment = volume.journal_active_segment_path().unwrap();
        backing.faults.lock().unwrap().partial_write = Some(700);
        assert!(volume.write_ct(1, &[9; 1000], false).is_err());
        if flush_before_roll {
            volume.flush().unwrap();
        }
        volume.write_ct(2, &next, true).unwrap(); // rolls without retrying the failed record
        drop(volume);
        // The failed syscall's written prefix may reach disk; an unsynced
        // truncation alone cannot protect the now non-final segment.
        backing.inner.crash_keep_torn_prefix(&original_segment, 700);

        let volume = Volume::recover(backing, options()).unwrap_or_else(|error| {
            panic!("failed suffix survived a roll (flush={flush_before_roll}): {error}")
        });
        assert_eq!(volume.read_ct(0).unwrap().unwrap().1, first);
        assert!(volume.read_ct(1).unwrap().is_none());
        assert_eq!(volume.read_ct(2).unwrap().unwrap().1, next);
    }
}

#[test]
fn failed_tail_cleanup_blocks_appends_and_flush_until_retry_succeeds() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(PartialWriteBacking::default());
    let mut volume = new_volume(&backing);
    volume.write_ct(0, &[1; 932], true).unwrap();
    backing.faults.lock().unwrap().partial_write = Some(700);
    assert!(volume.write_ct(1, &[9; 1000], false).is_err());
    backing.faults.lock().unwrap().fail_truncate = true;
    assert!(volume.write_ct(2, &[2; 64], true).is_err());
    assert!(volume.flush().is_err());
    assert_eq!(volume.journal_appended_sequence(), 1);

    backing.faults.lock().unwrap().fail_truncate = false;
    volume.flush().unwrap();
    assert_eq!(volume.write_ct(2, &[2; 64], true).unwrap(), 2);
    drop(volume);
    backing.inner.crash_all_lost();
    let volume = Volume::recover(backing, options()).unwrap();
    assert!(volume.read_ct(1).unwrap().is_none());
    assert_eq!(volume.read_ct(2).unwrap().unwrap().1, vec![2; 64]);
}
