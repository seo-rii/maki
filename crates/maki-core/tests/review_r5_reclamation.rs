//! R5-008 / R5-009: v3 space reclamation ordering.
//!
//! R5-008: a checkpoint punched a discarded unit's slot before the new
//! `checkpoint_sequence` was durable. The journal can still hold an older
//! durable write of that unit, superseded by the tombstone; when the
//! checkpoint state store then fails (or power is lost), recovery replays
//! that write into the punched hole and needs new filesystem blocks, the
//! very reservation `docs/space-reclamation.md` promises survives a crash.
//!
//! R5-009: a failed shard-catalog commit left the shard in the in-memory
//! catalog but not among the open shards; the reclamation cursor then
//! indexed the missing shard and panicked every checkpoint.

use std::io;
use std::sync::Arc;

use maki_backing::Backing;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::ab::AbStore;
use maki_format::checkpoint::CheckpointState;
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::CrashableBacking;

const CT: usize = 1032;

fn fixture() -> (Arc<CrashableBacking>, Volume, Geometry) {
    let backing = Arc::new(CrashableBacking::new());
    let size = 8 << 10;
    let geometry = Geometry::compute(512, 1024, 512, CT as u32, size * 2, size).unwrap();
    init::create_volume_with_discard(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xdec1a17),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: geometry.clone(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
    (backing, volume, geometry)
}

#[test]
fn a_slot_is_punched_only_after_the_checkpoint_that_retires_it_is_durable() {
    // Punching consults the process-global `discard.punch` failpoint that
    // the last test arms.
    let _lock = maki_test_support::failpoints::test_lock();
    let (backing, mut volume, geometry) = fixture();
    volume.write_ct(1, &[0x41; CT], true).unwrap();
    volume.checkpoint().unwrap();
    // An older durable write, then a durable tombstone that supersedes it:
    // the checkpoint holds only the tombstone.
    volume.write_ct(1, &[0x42; CT], true).unwrap();
    volume.discard_ct(1, true).unwrap();
    backing.set_fault_hook(Some(Arc::new(|op| match op {
        FaultOp::WriteAt { path, .. } if path.starts_with("checkpoint/") => {
            Some(io::Error::other("checkpoint state store failed"))
        }
        _ => None,
    })));
    assert!(volume.checkpoint().is_err());
    backing.set_fault_hook(None);
    drop(volume);
    backing.crash_all_lost();

    let checkpoint = AbStore::new("checkpoint/state.a", "checkpoint/state.b")
        .load::<CheckpointState>(backing.as_ref())
        .unwrap()
        .unwrap();
    assert_eq!(
        checkpoint.checkpoint_sequence, 1,
        "the checkpoint did not advance"
    );
    let slot = geometry.slot_offset(1);
    let mut bytes = vec![0u8; geometry.slot_size as usize];
    backing
        .open("data/shard-00000000.dat", false)
        .unwrap()
        .read_at(slot, &mut bytes)
        .unwrap();
    assert!(
        bytes.iter().any(|byte| *byte != 0),
        "the slot was punched while the durable checkpoint still needs its replay"
    );

    // Recovery replays the older write into its still-reserved slot, then
    // the tombstone; unit 1 reads as discarded and a later checkpoint
    // reclaims the slot.
    let mut volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
    assert!(volume.read_ct(1).unwrap().is_none());
    volume.checkpoint().unwrap();
}

#[test]
fn a_failed_shard_catalog_commit_does_not_break_reclamation() {
    // Punching consults the process-global `discard.punch` failpoint that
    // the last test arms.
    let _lock = maki_test_support::failpoints::test_lock();
    let (backing, mut volume, _) = fixture();
    volume.write_ct(1, &[0x41; CT], true).unwrap();
    volume.checkpoint().unwrap();
    volume.discard_ct(1, true).unwrap();
    drop(volume);
    // Reopen: recovery schedules reclamation of shard 0.
    let mut volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
    backing.set_fault_hook(Some(Arc::new(|op| match op {
        FaultOp::SyncDir { dir: "" } => Some(io::Error::other("root dirsync failed")),
        _ => None,
    })));
    // Unit 9 lives in shard 1 (8 units per shard): its catalog commit fails.
    assert!(volume.write_ct(9, &[0x42; CT], true).is_err());
    backing.set_fault_hook(None);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| volume.checkpoint()));
    assert!(
        result.is_ok(),
        "checkpoint panicked after a failed catalog commit"
    );
    // The shard is created for real on the next write.
    volume.write_ct(9, &[0x43; CT], true).unwrap();
    volume.checkpoint().unwrap();
    assert_eq!(volume.read_ct(9).unwrap().unwrap().1, vec![0x43; CT]);
}

/// R5-008 follow-up: a punch that keeps failing must not fail the
/// checkpoint that already published its state. The same call used to
/// retry the just-failed units through the reclamation scan and return its
/// error after the checkpoint state was stored, the journal deleted and the
/// overlay retired, so the engine reported a successful checkpoint as
/// failed (Degraded).
#[test]
fn a_persistently_failing_punch_does_not_fail_a_published_checkpoint() {
    use maki_test_support::failpoints;
    let _lock = failpoints::test_lock();
    let (_backing, mut volume, _) = fixture();
    volume.write_ct(2, &[0x41; CT], true).unwrap();
    volume.checkpoint().unwrap();
    volume.discard_ct(2, true).unwrap();
    let before = volume.checkpoint_sequence();
    let failing = failpoints::fail_n_times(
        "discard.punch",
        100,
        io::ErrorKind::Other,
        "punch persistently failing",
    );
    let published = volume.checkpoint();
    drop(failing);
    let published = published.expect("the checkpoint was published; reclamation is deferred");
    assert!(published > before);
    assert_eq!(volume.checkpoint_sequence(), published);
    assert!(volume.read_ct(2).unwrap().is_none());
    // The deferred release completes once punching works again.
    volume.checkpoint().unwrap();
}
