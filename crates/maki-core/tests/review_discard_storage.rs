use std::sync::Arc;

use maki_backing::{Backing, MemBacking};
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::geometry::Geometry;
use maki_format::init::{create_volume, create_volume_with_discard};
use maki_format::layout;
use maki_format::superblock::Superblock;
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::failpoints;
use maki_test_support::CrashableBacking;
use rand::SeedableRng;

fn superblock(id: u128) -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(id),
        provider_type: "fake".into(),
        crypto_compatibility_id: "discard-storage-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, 1024, 512, 1032, 16 * 1024, 8 * 1024).unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

#[test]
fn v3_discard_is_logical_zero_across_checkpoint_and_recovery() {
    let backing = Arc::new(MemBacking::new());
    create_volume_with_discard(backing.as_ref(), superblock(0xd15ca4d)).unwrap();
    let mut volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
    assert!(volume.supports_discard());

    volume.write_ct(1, &[0x41; 1032], true).unwrap();
    volume.checkpoint().unwrap();
    volume.discard_ct(1, true).unwrap();
    assert!(volume.read_ct(1).unwrap().is_none());
    volume.checkpoint().unwrap();
    drop(volume);

    let recovered = Volume::recover(backing, VolumeOptions::default()).unwrap();
    assert!(recovered.read_ct(1).unwrap().is_none());
}

#[test]
fn ordinary_write_clears_checkpointed_discard_in_both_logical_copies() {
    let backing = Arc::new(MemBacking::new());
    create_volume_with_discard(backing.as_ref(), superblock(0xc1ea4)).unwrap();
    let mut volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
    volume.write_ct(2, &[0x51; 1032], true).unwrap();
    volume.checkpoint().unwrap();
    volume.discard_ct(2, true).unwrap();
    volume.checkpoint().unwrap();
    volume.write_ct(2, &[0x52; 1032], true).unwrap();
    volume.checkpoint().unwrap();
    drop(volume);

    let recovered = Volume::recover(backing, VolumeOptions::default()).unwrap();
    assert_eq!(recovered.read_ct(2).unwrap().unwrap().1, vec![0x52; 1032]);
}

#[test]
fn v2_volume_rejects_discard_without_mutation() {
    let backing = Arc::new(MemBacking::new());
    create_volume(backing.as_ref(), superblock(0x1e6ac7)).unwrap();
    let mut volume = Volume::recover(backing, VolumeOptions::default()).unwrap();
    assert!(!volume.supports_discard());
    assert!(volume.discard_ct(0, true).is_err());
    assert_eq!(volume.journal_appended_sequence(), 0);
}

#[test]
fn v2_empty_ciphertext_keeps_legacy_slot_semantics_across_checkpoint() {
    let backing = Arc::new(MemBacking::new());
    create_volume(backing.as_ref(), superblock(0xe047)).unwrap();
    let mut volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
    volume.write_ct(0, &[], true).unwrap();
    volume.checkpoint().unwrap();
    drop(volume);

    let recovered = Volume::recover(backing, VolumeOptions::default()).unwrap();
    assert_eq!(recovered.read_ct(0).unwrap(), Some((1, Vec::new())));
}

#[test]
fn failed_punch_keeps_journal_and_retries_even_when_bitmap_is_already_set() {
    let _serial = failpoints::test_lock();
    let backing = Arc::new(MemBacking::new());
    create_volume_with_discard(backing.as_ref(), superblock(0xfa11ed)).unwrap();
    let mut volume = Volume::recover(backing, VolumeOptions::default()).unwrap();
    volume.write_ct(3, &[0x63; 1032], true).unwrap();
    volume.checkpoint().unwrap();
    volume.discard_ct(3, true).unwrap();
    let owner = std::thread::current().id();
    let failure = failpoints::set(
        "discard.punch",
        failpoints::FailpointAction::Callback(Arc::new(move || {
            (std::thread::current().id() == owner).then(|| std::io::Error::other("punch failed"))
        })),
    );
    assert!(volume.checkpoint().is_err());
    assert!(volume.read_ct(3).unwrap().is_none());
    drop(failure);
    volume.checkpoint().unwrap();
    assert!(volume.read_ct(3).unwrap().is_none());
}

#[test]
fn discard_map_fallback_cannot_resurrect_a_cleared_marker() {
    let backing = Arc::new(MemBacking::new());
    create_volume_with_discard(backing.as_ref(), superblock(0xfa11ba)).unwrap();
    let mut volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
    volume.write_ct(1, &[0x71; 1032], true).unwrap();
    volume.checkpoint().unwrap();
    volume.discard_ct(1, true).unwrap();
    volume.checkpoint().unwrap();
    volume.write_ct(1, &[0x72; 1032], true).unwrap();
    volume.checkpoint().unwrap();
    drop(volume);

    // Both copies were rewritten with the clear marker, so fallback from
    // either damaged side must still expose the later ordinary slot.
    let side = backing.open(&layout::shard_discard_a(0), false).unwrap();
    side.write_at(0, &[0; 32]).unwrap();
    let recovered = Volume::recover(backing, VolumeOptions::default()).unwrap();
    assert_eq!(recovered.read_ct(1).unwrap().unwrap().1, vec![0x72; 1032]);
}

#[test]
fn crash_after_durable_punch_preserves_logical_zero() {
    let backing = Arc::new(CrashableBacking::new());
    create_volume_with_discard(backing.as_ref(), superblock(0xc4a5a)).unwrap();
    let mut volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
    volume.write_ct(4, &[0x81; 1032], true).unwrap();
    volume.checkpoint().unwrap();
    volume.discard_ct(4, true).unwrap();
    volume.checkpoint().unwrap();
    drop(volume);

    backing.crash(&mut rand::rngs::StdRng::seed_from_u64(0xd15ca4d));
    let recovered = Volume::recover(backing, VolumeOptions::default()).unwrap();
    assert!(recovered.read_ct(4).unwrap().is_none());
}

#[test]
fn recovery_replays_discard_then_later_write_in_record_order_without_punching() {
    let backing = Arc::new(CrashableBacking::new());
    create_volume_with_discard(backing.as_ref(), superblock(0x4e91a7)).unwrap();
    let mut volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
    volume.write_ct(5, &[0x91; 1032], true).unwrap();
    volume.checkpoint().unwrap();
    volume.discard_ct(5, true).unwrap();
    volume.write_ct(5, &[0x92; 1032], true).unwrap();
    drop(volume);

    backing.crash(&mut rand::rngs::StdRng::seed_from_u64(0x4e91a7));
    let recovered = Volume::recover(backing, VolumeOptions::default()).unwrap();
    assert_eq!(recovered.read_ct(5).unwrap().unwrap().1, vec![0x92; 1032]);
}

#[test]
fn failed_initial_discard_map_publication_cannot_leave_an_unattachable_data_orphan() {
    let backing = Arc::new(CrashableBacking::new());
    create_volume_with_discard(backing.as_ref(), superblock(0x0a4f4a)).unwrap();
    let mut volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
    backing.set_fault_hook(Some(Arc::new(|operation| match operation {
        FaultOp::Open { path, create: true } if path.ends_with(".discard.a") => {
            Some(std::io::Error::other("discard map creation failed"))
        }
        _ => None,
    })));
    assert!(volume.write_ct(0, &[0xa1; 1032], true).is_err());
    backing.set_fault_hook(None);
    drop(volume);

    backing.crash(&mut rand::rngs::StdRng::seed_from_u64(0x0a4f4a));
    let recovered = Volume::recover(backing, VolumeOptions::default()).unwrap();
    assert!(recovered.read_ct(0).unwrap().is_none());
}

#[test]
fn cataloged_v3_shard_without_either_discard_copy_refuses_attach() {
    let backing = Arc::new(MemBacking::new());
    create_volume_with_discard(backing.as_ref(), superblock(0xbad0a4)).unwrap();
    let mut volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
    volume.write_ct(0, &[0xb1; 1032], true).unwrap();
    volume.checkpoint().unwrap();
    drop(volume);

    for path in [layout::shard_discard_a(0), layout::shard_discard_b(0)] {
        let file = backing.open(&path, false).unwrap();
        file.set_len(0).unwrap();
        file.sync_data().unwrap();
    }
    assert!(Volume::recover(backing, VolumeOptions::default()).is_err());
}
