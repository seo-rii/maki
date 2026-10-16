//! BUG-128: slot I/O failures are inconclusive, not evidence of corruption.
//! A short read or invalid bytes still reports actual slot damage.
use maki_backing::{Backing, BackingFile, MemBacking, VolumeLock};
use maki_core::{
    check::deep_check,
    volume::{Volume, VolumeOptions},
    CoreError,
};
use maki_format::{geometry::Geometry, init, layout, superblock::Superblock};
use std::{
    io,
    sync::{
        atomic::{AtomicI32, AtomicU64, Ordering},
        Arc,
    },
};

struct ReadFailure {
    backing: MemBacking,
    fault: Arc<ReadFault>,
}
#[derive(Default)]
struct ReadFault {
    offset: AtomicU64,
    errno: AtomicI32,
}

struct ReadFailureFile {
    inner: Arc<dyn BackingFile>,
    fault: Arc<ReadFault>,
    shard: bool,
}
impl BackingFile for ReadFailureFile {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let errno = self.fault.errno.load(Ordering::SeqCst);
        if self.shard && offset == self.fault.offset.load(Ordering::SeqCst) && errno != 0 {
            return Err(io::Error::from_raw_os_error(errno));
        }
        self.inner.read_at(offset, buf)
    }
    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.inner.write_at(offset, data)
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.inner.set_len(len)
    }
    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }
    fn sync_data(&self) -> io::Result<()> {
        self.inner.sync_data()
    }
}
impl Backing for ReadFailure {
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        Ok(Arc::new(ReadFailureFile {
            inner: self.backing.open(path, create)?,
            fault: self.fault.clone(),
            shard: path == layout::shard_data(0),
        }))
    }
    fn exists(&self, p: &str) -> io::Result<bool> {
        self.backing.exists(p)
    }
    fn remove(&self, p: &str) -> io::Result<()> {
        self.backing.remove(p)
    }
    fn rename(&self, a: &str, b: &str) -> io::Result<()> {
        self.backing.rename(a, b)
    }
    fn create_dir_all(&self, p: &str) -> io::Result<()> {
        self.backing.create_dir_all(p)
    }
    fn list(&self, p: &str) -> io::Result<Vec<String>> {
        self.backing.list(p)
    }
    fn sync_dir(&self, p: &str) -> io::Result<()> {
        self.backing.sync_dir(p)
    }
    fn try_lock(&self, p: &str) -> io::Result<Box<dyn VolumeLock>> {
        self.backing.try_lock(p)
    }
}
fn fixture(journaled_overwrite: bool) -> Arc<ReadFailure> {
    let backing = Arc::new(ReadFailure {
        backing: MemBacking::new(),
        fault: Arc::new(ReadFault::default()),
    });
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xa011),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, 512, 512, 544, 8192, 4096).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let mut volume = Volume::recover(
        backing.clone(),
        VolumeOptions {
            journal_segment_size: 4096,
        },
    )
    .unwrap();
    volume.write_ct(0, &[7; 540], true).unwrap();
    volume.checkpoint().unwrap();
    if journaled_overwrite {
        volume.write_ct(0, &[8; 540], true).unwrap();
    }
    drop(volume);
    backing
}
fn assert_io<T: std::fmt::Debug>(result: Result<T, CoreError>, errno: i32) {
    match result {
        Err(CoreError::Io(error)) => assert_eq!(error.raw_os_error(), Some(errno)),
        other => panic!("slot read must preserve I/O error {errno}, observed {other:?}"),
    }
}

#[test]
fn slot_read_failures_preserve_errno_and_leave_the_check_inconclusive() {
    // Allocated header, allocated payload, and an unlisted slot's header.
    for (unit, offset) in [(0, 0), (0, 64), (1, 1024)] {
        for errno in [5, 13, 11] {
            let backing = fixture(false);
            assert!(deep_check(backing.clone(), 4096).unwrap().ok());
            let volume = Volume::recover(
                backing.clone(),
                VolumeOptions {
                    journal_segment_size: 4096,
                },
            )
            .unwrap();
            backing.fault.offset.store(offset, Ordering::SeqCst);
            backing.fault.errno.store(errno, Ordering::SeqCst);
            assert_io(volume.read_ct(unit), errno);
            drop(volume);
            assert_io(deep_check(backing.clone(), 4096), errno);
            backing.fault.errno.store(0, Ordering::SeqCst);
            let healthy = deep_check(backing, 4096).unwrap();
            assert!(healthy.ok());
            assert!(healthy
                .info
                .iter()
                .any(|line| line == "deep check verdict: clean"));
        }
    }
}

#[test]
fn newer_journal_can_recover_the_unit_after_the_read_fault_clears() {
    let backing = fixture(true);
    backing.fault.offset.store(64, Ordering::SeqCst);
    backing.fault.errno.store(5, Ordering::SeqCst);
    assert_io(deep_check(backing.clone(), 4096), 5);
    backing.fault.errno.store(0, Ordering::SeqCst);
    let volume = Volume::recover(
        backing.clone(),
        VolumeOptions {
            journal_segment_size: 4096,
        },
    )
    .unwrap();
    assert_eq!(volume.read_ct(0).unwrap().unwrap().1, vec![8; 540]);
    drop(volume);
    let after = deep_check(backing, 4096).unwrap();
    assert!(after.ok());
    assert!(after
        .info
        .iter()
        .any(|line| line == "deep check verdict: clean"));
}

#[test]
fn short_slots_and_invalid_bytes_remain_corruption() {
    for damage in ["short header", "short payload", "header", "payload"] {
        let backing = fixture(false);
        let file = backing.open(&layout::shard_data(0), false).unwrap();
        match damage {
            "short header" => file.set_len(32).unwrap(),
            "short payload" => file.set_len(64 + 100).unwrap(),
            "header" => file.write_at(0, &[0; 64]).unwrap(),
            "payload" => file.write_at(64, &[0xff]).unwrap(),
            _ => unreachable!(),
        }
        let volume = Volume::recover(
            backing.clone(),
            VolumeOptions {
                journal_segment_size: 4096,
            },
        )
        .unwrap();
        assert!(
            matches!(volume.read_ct(0), Err(CoreError::Corrupt(_))),
            "{damage}"
        );
        drop(volume);
        let report = deep_check(backing, 4096).unwrap();
        assert!(!report.ok(), "{damage}");
        assert!(
            report
                .info
                .iter()
                .any(|line| line == "deep check verdict: unrecoverable"),
            "{damage}"
        );
    }
}

#[test]
fn validated_journal_still_classifies_actual_slot_damage_as_recoverable() {
    let backing = fixture(true);
    backing
        .open(&layout::shard_data(0), false)
        .unwrap()
        .write_at(64, &[0xff])
        .unwrap();
    let report = deep_check(backing.clone(), 4096).unwrap();
    assert!(report.ok());
    assert!(report
        .info
        .iter()
        .any(|line| line == "deep check verdict: recoverable"));
    let volume = Volume::recover(
        backing,
        VolumeOptions {
            journal_segment_size: 4096,
        },
    )
    .unwrap();
    assert_eq!(volume.read_ct(0).unwrap().unwrap().1, vec![8; 540]);
}
