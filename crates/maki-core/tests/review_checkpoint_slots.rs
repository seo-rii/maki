//! Healthy checkpoints retain journal evidence, including across an interrupted
//! later checkpoint. Check and recovery both accept these normal states.

use std::io;
use std::sync::Arc;

use maki_core::check::deep_check;
use maki_core::store::{SlotRead, SlotStore};
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::{failpoints, CrashableBacking};

const SEGMENT_SIZE: u64 = 4096;

fn reopen(backing: &CrashableBacking) -> Volume {
    Volume::recover(
        backing.process(),
        VolumeOptions {
            journal_segment_size: SEGMENT_SIZE,
        },
    )
    .unwrap()
}

fn fixture(discard: bool) -> (Arc<CrashableBacking>, Volume) {
    let backing = Arc::new(CrashableBacking::new());
    let block = Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(0x199_c4ec),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "key".into(),
        geometry: Geometry::compute(512, 512, 512, 544, 8192, 4096).unwrap(),
        format_version: 1,
        created_unix: 0,
    };
    if discard {
        init::create_volume_with_discard(backing.as_ref(), block).unwrap();
    } else {
        init::create_volume(backing.as_ref(), block).unwrap();
    }
    let volume = reopen(&backing);
    (backing, volume)
}

fn assert_check_ok(backing: &CrashableBacking) {
    let report = deep_check(backing.process(), SEGMENT_SIZE).unwrap();
    assert!(report.ok(), "{:?}", report.errors);
}

#[test]
fn v2_empty_write_is_a_slot_in_a_segment_straddling_the_checkpoint() {
    let _guard = failpoints::test_lock();
    let (backing, mut volume) = fixture(false);
    volume.write_ct(0, &[0x31; 540], true).unwrap();
    // The earlier write is superseded by a legal zero-length v2 write.
    let empty = volume.write_ct(0, &[], true).unwrap();
    let covered = volume.write_ct(1, &[0x42; 540], true).unwrap();
    assert_eq!(volume.checkpoint().unwrap(), covered);
    let uncovered = volume.write_ct(2, &[0x53; 540], true).unwrap();
    assert_eq!(volume.journal_segment_count(), 1);
    assert_eq!(volume.checkpoint_sequence(), covered);
    drop(volume);

    assert_check_ok(&backing);
    let volume = reopen(&backing);
    assert_eq!(volume.read_ct(0).unwrap(), Some((empty, Vec::new())));
    assert_eq!(volume.read_ct(1).unwrap(), Some((covered, vec![0x42; 540])));
    assert_eq!(
        volume.read_ct(2).unwrap(),
        Some((uncovered, vec![0x53; 540]))
    );
    assert_eq!(volume.journal_segment_count(), 0);
    drop(volume);

    // Recovery checkpointed the uncovered write and pruned the journal.
    assert_check_ok(&backing);
    assert_eq!(
        reopen(&backing).read_ct(0).unwrap(),
        Some((empty, Vec::new()))
    );
}

#[test]
fn a_covered_v3_discard_is_logical_zero_with_its_journal_record_retained() {
    let _guard = failpoints::test_lock();
    let (backing, mut volume) = fixture(true);
    volume.write_ct(0, &[0x31; 540], true).unwrap();
    let untouched = volume.write_ct(1, &[0x42; 540], true).unwrap();
    volume.checkpoint().unwrap();
    let discard = volume.discard_ct(0, true).unwrap();
    assert_eq!(volume.checkpoint().unwrap(), discard);
    assert_eq!(volume.journal_segment_count(), 1);
    drop(volume);

    assert_check_ok(&backing);
    let volume = reopen(&backing);
    assert_eq!(volume.read_ct(0).unwrap(), None);
    assert_eq!(
        volume.read_ct(1).unwrap(),
        Some((untouched, vec![0x42; 540]))
    );
}

#[test]
fn an_interrupted_later_checkpoint_leaves_valid_replay_for_a_changed_slot() {
    let _guard = failpoints::test_lock();
    for discard in [false, true] {
        let (backing, mut volume) = fixture(true);
        volume.write_ct(0, &[0x31; 540], true).unwrap();
        let covered = volume.write_ct(1, &[0x42; 540], true).unwrap();
        assert_eq!(volume.checkpoint().unwrap(), covered);
        let later = if discard {
            volume.discard_ct(0, true).unwrap();
            None
        } else {
            let sequence = volume.write_ct(0, &[0x53; 540], true).unwrap();
            Some((sequence, vec![0x53; 540]))
        };

        // The slot or discard map is written and synced before the
        // checkpoint sequence is published. A failed publication keeps
        // the newer journal record available for replay.
        let fault = failpoints::fail_n_times(
            "checkpoint.state_store",
            1,
            io::ErrorKind::Other,
            "checkpoint publication interrupted",
        );
        assert!(volume.checkpoint().is_err());
        drop(fault);
        assert_eq!(volume.checkpoint_sequence(), covered);
        assert_eq!(volume.journal_segment_count(), 1);
        let geometry = volume.superblock().geometry.clone();
        drop(volume);

        // Check the storage view directly so the live overlay cannot mask a
        // fixture that failed before the newer slot or discard was published.
        let store = SlotStore::open(backing.process(), geometry).unwrap();
        let published = match store.read_slot(0).unwrap() {
            SlotRead::Zero => None,
            SlotRead::Ciphertext {
                write_sequence,
                data,
            } => Some((write_sequence, data)),
        };
        assert_eq!(published, later);
        drop(store);

        assert_check_ok(&backing);
        assert_eq!(reopen(&backing).read_ct(0).unwrap(), later);
    }
}
