//! MAKI-020: compounded loss of the advisory mark and durable tail damage.
//! This models media damage after FUA, not ordinary loss of unsynced writes.

use std::io;
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc,
};

use maki_backing::{Backing, BackingFile, VolumeLock};
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::{geometry::Geometry, init, journal::DurableMark, layout, superblock::Superblock};
use maki_test_support::CrashableBacking;

fn check_acknowledged_corruption(missing: bool) {
    let backing = Arc::new(CrashableBacking::new());
    let superblock = Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::new_v4(),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, 512, 512, 544, 512 * 1024, 512 * 64).unwrap(),
        format_version: 1,
        created_unix: 0,
    };
    init::create_volume(backing.as_ref(), superblock).unwrap();
    let options = VolumeOptions {
        journal_segment_size: 4096,
    };
    let mut volume = Volume::recover(backing.clone(), options.clone()).unwrap();
    volume.write_ct(0, &[1; 540], true).unwrap();
    let segment = volume.journal_active_segment_path().unwrap();
    let first_end = backing.open(&segment, false).unwrap().len().unwrap();
    volume.write_ct(1, &[2; 540], true).unwrap();
    assert_eq!(volume.journal_durable_sequence(), 2);
    drop(volume);

    // Both FUA writes completed before corruption was introduced.
    let file = backing.open(&segment, false).unwrap();
    file.write_at(first_end + 32, &[0xA5]).unwrap();
    file.sync_data().unwrap();
    if missing {
        backing.remove(layout::JOURNAL_DURABLE_MARK).unwrap();
        backing.sync_dir("journal").unwrap();
    } else {
        let mark = DurableMark {
            segment_index: 0,
            durable_size: first_end,
        };
        let file = backing.open(layout::JOURNAL_DURABLE_MARK, false).unwrap();
        file.write_at(0, &mark.encode()).unwrap();
        file.sync_data().unwrap();
    }
    let recovered = Volume::recover(backing, options);
    assert!(
        recovered.is_err(),
        "missing={missing}: acknowledged corruption was silently accepted as an uncommitted tail"
    );
}

#[test]
fn missing_mark_cannot_hide_acknowledged_tail_corruption() {
    check_acknowledged_corruption(true);
}

#[test]
fn stale_mark_cannot_hide_acknowledged_tail_corruption() {
    check_acknowledged_corruption(false);
}

// One-shot faults target the required metadata only. The first FUA creates
// the journal segment before arming, so directory failures occur during proof
// publication rather than the segment creation protocol.
#[derive(Default)]
struct ProofFaultBacking {
    inner: CrashableBacking,
    fault: Arc<AtomicU8>,
}

struct ProofFaultFile {
    inner: Arc<dyn BackingFile>,
    proof: bool,
    fault: Arc<AtomicU8>,
}

fn inject(fault: &AtomicU8, point: u8) -> io::Result<()> {
    if fault
        .compare_exchange(point, 0, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        Err(io::Error::other("required proof persistence failed"))
    } else {
        Ok(())
    }
}

impl BackingFile for ProofFaultFile {
    fn read_at(&self, offset: u64, data: &mut [u8]) -> io::Result<()> {
        self.inner.read_at(offset, data)
    }
    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        if self.proof {
            inject(&self.fault, 1)?;
        }
        self.inner.write_at(offset, data)
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.inner.set_len(len)
    }
    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }
    fn sync_data(&self) -> io::Result<()> {
        if self.proof {
            inject(&self.fault, 2)?;
        }
        self.inner.sync_data()
    }
}

impl Backing for ProofFaultBacking {
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        Ok(Arc::new(ProofFaultFile {
            inner: self.inner.open(path, create)?,
            proof: path.starts_with("journal/durable-proof."),
            fault: self.fault.clone(),
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
    fn list(&self, path: &str) -> io::Result<Vec<String>> {
        self.inner.list(path)
    }
    fn sync_dir(&self, path: &str) -> io::Result<()> {
        if path == "journal" {
            inject(&self.fault, 3)?;
        }
        self.inner.sync_dir(path)
    }
    fn try_lock(&self, path: &str) -> io::Result<Box<dyn VolumeLock>> {
        self.inner.try_lock(path)
    }
}

fn initialize(backing: &dyn Backing) -> VolumeOptions {
    init::create_volume(
        backing,
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::new_v4(),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, 512, 512, 544, 512 * 1024, 512 * 64).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    VolumeOptions {
        journal_segment_size: 4096,
    }
}

#[test]
fn proof_failure_blocks_fua_checkpoint_and_retries_without_new_records() {
    for point in 1..=3 {
        let backing = Arc::new(ProofFaultBacking::default());
        let options = initialize(backing.as_ref());
        let mut volume = Volume::recover(backing.clone(), options.clone()).unwrap();
        volume.write_ct(0, &[1; 540], true).unwrap();
        backing.fault.store(point, Ordering::SeqCst);
        assert!(
            matches!(
                volume.write_ct(1, &[2; 540], true),
                Err(maki_core::CoreError::Io(_))
            ),
            "proof fault {point} must prevent FUA ACK and remain an I/O error"
        );
        assert_eq!(backing.fault.load(Ordering::SeqCst), 0, "fault must fire");
        assert_eq!(
            volume.journal_durable_sequence(),
            1,
            "data sync alone is not the public durability boundary"
        );
        assert_eq!(
            volume.checkpoint().unwrap(),
            1,
            "unproved data must not enter a checkpoint"
        );
        volume.flush().unwrap();
        assert_eq!(
            volume.journal_durable_sequence(),
            2,
            "flush without another append must retry the proof"
        );
        drop(volume);
        backing.inner.crash_all_lost();
        let volume = Volume::recover(backing, options).unwrap();
        assert_eq!(volume.read_ct(0).unwrap().unwrap().1, vec![1; 540]);
        assert_eq!(volume.read_ct(1).unwrap().unwrap().1, vec![2; 540]);
    }
}

#[test]
fn missing_acknowledged_segment_cannot_disappear_from_recovery() {
    let backing = Arc::new(CrashableBacking::new());
    let options = initialize(backing.as_ref());
    let mut volume = Volume::recover(backing.clone(), options.clone()).unwrap();
    volume.write_ct(0, &[1; 540], true).unwrap();
    let path = volume.journal_active_segment_path().unwrap();
    drop(volume);
    backing.remove(&path).unwrap();
    backing.sync_dir("journal").unwrap();
    let mutations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = mutations.clone();
    backing.set_fault_hook(Some(Arc::new(move |op| {
        if !matches!(
            op,
            maki_test_support::crash_backing::FaultOp::Open { create: false, .. }
        ) {
            count.fetch_add(1, Ordering::SeqCst);
        }
        None
    })));
    assert!(
        Volume::recover(backing, options).is_err(),
        "an absent final file can contain acknowledged history"
    );
    assert_eq!(
        mutations.load(Ordering::SeqCst),
        0,
        "validate the required history before changing recovery metadata"
    );
}

#[test]
fn exact_record_boundary_truncation_cannot_hide_acknowledged_history() {
    let backing = Arc::new(CrashableBacking::new());
    let options = initialize(backing.as_ref());
    let mut volume = Volume::recover(backing.clone(), options.clone()).unwrap();
    volume.write_ct(0, &[1; 540], true).unwrap();
    let path = volume.journal_active_segment_path().unwrap();
    let file = backing.open(&path, false).unwrap();
    let first_end = file.len().unwrap();
    volume.write_ct(1, &[2; 540], true).unwrap();
    drop(volume);
    file.set_len(first_end).unwrap();
    file.sync_data().unwrap();
    backing.remove(layout::JOURNAL_DURABLE_MARK).unwrap();
    backing.sync_dir("journal").unwrap();
    assert!(
        Volume::recover(backing, options).is_err(),
        "a clean CRC-valid shorter prefix is still lost ACKed data"
    );
}

#[test]
fn legacy_writable_recovery_is_refused_before_metadata_changes() {
    use maki_test_support::crash_backing::FaultOp;
    let backing = Arc::new(CrashableBacking::new());
    let options = initialize(backing.as_ref());
    // A legacy image has an explicit v1 envelope, regardless of the default
    // format created by this build. It must never be upgraded implicitly.
    let legacy = init::load_superblock(backing.as_ref()).unwrap().encode();
    for path in [layout::SUPERBLOCK_A, layout::SUPERBLOCK_B] {
        let file = backing.open(path, false).unwrap();
        file.write_at(0, &legacy).unwrap();
        file.sync_data().unwrap();
    }
    let mutations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = mutations.clone();
    backing.set_fault_hook(Some(Arc::new(move |op| {
        if !matches!(op, FaultOp::Open { create: false, .. }) {
            count.fetch_add(1, Ordering::SeqCst);
        }
        None
    })));
    assert!(
        Volume::recover(backing, options).is_err(),
        "legacy history lacks required evidence; do not silently enable writes"
    );
    assert_eq!(
        mutations.load(Ordering::SeqCst),
        0,
        "legacy refusal must be read-only"
    );
}

#[test]
fn losing_both_required_proofs_is_not_a_pristine_volume() {
    let backing = Arc::new(CrashableBacking::new());
    let options = initialize(backing.as_ref());
    for path in ["journal/durable-proof.a", "journal/durable-proof.b"] {
        if backing.exists(path).unwrap() {
            backing.remove(path).unwrap();
        }
    }
    backing.sync_dir("journal").unwrap();
    assert!(
        !maki_format::checker::check_volume(backing.as_ref())
            .unwrap()
            .ok(),
        "fast check must require the proof even when the journal is empty"
    );
    assert!(!maki_core::check::deep_check(backing.clone(), 4096)
        .unwrap()
        .ok());
    assert!(Volume::recover(backing, options).is_err());
}

#[test]
fn recovered_tail_is_proved_before_the_next_restart() {
    let backing = Arc::new(CrashableBacking::new());
    let options = initialize(backing.as_ref());
    let mut volume = Volume::recover(backing.clone(), options.clone()).unwrap();
    volume.write_ct(0, &[1; 540], false).unwrap();
    let path = volume.journal_active_segment_path().unwrap();
    drop(volume); // process restart: unacknowledged but valid bytes are visible
    let volume = Volume::recover(backing.clone(), options.clone()).unwrap();
    assert_eq!(volume.journal_durable_sequence(), 1);
    drop(volume);
    let file = backing.open(&path, false).unwrap();
    file.write_at(
        maki_format::journal::SEGMENT_HEADER_SIZE as u64 + 32,
        &[0xFE],
    )
    .unwrap();
    file.sync_data().unwrap();
    backing.remove(layout::JOURNAL_DURABLE_MARK).unwrap();
    backing.sync_dir("journal").unwrap();
    assert!(
        Volume::recover(backing, options).is_err(),
        "a tail adopted as durable must acquire the required proof before READY"
    );
}

#[test]
fn checkpoint_can_cover_a_pruned_proof_segment() {
    let backing = Arc::new(CrashableBacking::new());
    let options = initialize(backing.as_ref());
    let mut volume = Volume::recover(backing.clone(), options.clone()).unwrap();
    volume.write_ct(0, &[1; 540], true).unwrap();
    let path = volume.journal_active_segment_path().unwrap();
    drop(volume);
    let mut volume = Volume::recover(backing.clone(), options.clone()).unwrap();
    assert_eq!(volume.checkpoint().unwrap(), 1);
    assert!(!backing.exists(&path).unwrap());
    drop(volume);
    backing.crash_all_lost();
    let volume = Volume::recover(backing, options).unwrap();
    assert_eq!(volume.read_ct(0).unwrap().unwrap().1, vec![1; 540]);
}
