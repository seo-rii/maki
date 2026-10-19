//! Bounded recovery validates every record, then writes only each batch's
//! latest version of a unit. Earlier allocation/discard evidence stays valid.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use maki_backing::Backing;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::ab::AbStore;
use maki_format::allocation::AllocationMap;
use maki_format::journal::{RECORD_HEADER_SIZE, SEGMENT_HEADER_SIZE};
use maki_format::{geometry::Geometry, init, layout, superblock::Superblock};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::{failpoints, CrashableBacking};
use rand::{rngs::StdRng, SeedableRng};

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: 2 << 20,
    }
}

fn fixture(discard: bool) -> (Arc<CrashableBacking>, Volume) {
    let backing = Arc::new(CrashableBacking::new().with_tearing(512));
    let superblock = Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(0xBA7C4),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "fixture".into(),
        geometry: Geometry::compute(512, 512, 512, 4096, 512 * 64, 512 * 64).unwrap(),
        format_version: 1,
        created_unix: 0,
    };
    if discard {
        init::create_volume_with_discard(backing.as_ref(), superblock).unwrap();
    } else {
        init::create_volume(backing.as_ref(), superblock).unwrap();
    }
    let volume = Volume::recover(backing.clone(), options()).unwrap();
    (backing, volume)
}

fn count_slot_writes(backing: &CrashableBacking) -> Arc<Mutex<Vec<u64>>> {
    let writes = Arc::new(Mutex::new(Vec::new()));
    let observed = writes.clone();
    backing.set_fault_hook(Some(Arc::new(move |op| {
        if let FaultOp::WriteAt { path, offset, len } = op {
            // Count complete logical slot publications by their fixed header;
            // ciphertext now uses a separate write without another allocation.
            if path.ends_with(".dat") && *len == 64 {
                observed.lock().unwrap().push(*offset);
            }
        }
        None
    })));
    writes
}

#[test]
fn one_batch_writes_only_each_units_last_sequence() {
    let _guard = failpoints::test_lock();
    for discard in [false, true] {
        let (backing, mut volume) = fixture(discard);
        for sequence in 1..=24 {
            volume
                .write_ct((sequence - 1) % 2, &[sequence as u8; 540], false)
                .unwrap();
        }
        volume.flush().unwrap();
        drop(volume);
        let writes = count_slot_writes(&backing);
        let volume = Volume::recover(backing.clone(), options()).unwrap();
        assert_eq!(volume.checkpoint_sequence(), 24);
        assert_eq!(volume.journal_segment_count(), 0);
        assert_eq!(writes.lock().unwrap().len(), 2, "one slot write per unit");
        assert_eq!(volume.read_ct(0).unwrap().unwrap(), (23, vec![23; 540]));
        assert_eq!(volume.read_ct(1).unwrap().unwrap(), (24, vec![24; 540]));
        drop(volume);
        backing.set_fault_hook(None);
        backing.crash_all_lost();
        let volume = Volume::recover(backing, options()).unwrap();
        assert_eq!(volume.read_ct(0).unwrap().unwrap(), (23, vec![23; 540]));
        assert_eq!(volume.read_ct(1).unwrap().unwrap(), (24, vec![24; 540]));
    }
}

#[test]
fn discard_last_skips_slot_write_and_write_last_preserves_data() {
    let _guard = failpoints::test_lock();
    let (backing, mut volume) = fixture(true);
    // Unit 0: write -> discard -> write -> discard. Unit 1 finishes with a
    // write after a discard. Both allocation and tombstone history matter.
    volume.write_ct(0, &[1; 540], false).unwrap();
    volume.discard_ct(0, false).unwrap();
    volume.write_ct(0, &[2; 540], false).unwrap();
    volume.discard_ct(0, false).unwrap();
    volume.write_ct(1, &[3; 540], false).unwrap();
    volume.discard_ct(1, false).unwrap();
    let sequence = volume.write_ct(1, &[4; 540], true).unwrap();
    drop(volume);
    let writes = count_slot_writes(&backing);
    let volume = Volume::recover(backing.clone(), options()).unwrap();
    assert_eq!(writes.lock().unwrap().len(), 1);
    assert!(volume.read_ct(0).unwrap().is_none());
    assert_eq!(
        volume.read_ct(1).unwrap().unwrap(),
        (sequence, vec![4; 540])
    );
    assert_eq!(volume.checkpoint_sequence(), sequence);
    let allocations: AllocationMap =
        AbStore::new(layout::shard_alloc_a(0), layout::shard_alloc_b(0))
            .load(backing.as_ref())
            .unwrap()
            .unwrap();
    assert!(
        allocations.get(0),
        "superseded writes retain allocation evidence"
    );
    assert!(allocations.get(1));
    drop(volume);
    backing.set_fault_hook(None);
    backing.crash_all_lost();
    let volume = Volume::recover(backing, options()).unwrap();
    assert!(volume.read_ct(0).unwrap().is_none());
    assert_eq!(
        volume.read_ct(1).unwrap().unwrap(),
        (sequence, vec![4; 540])
    );
}

#[test]
fn repeated_unit_across_one_mib_boundary_is_applied_once_per_batch() {
    let _guard = failpoints::test_lock();
    for discard in [false, true] {
        let (backing, mut volume) = fixture(discard);
        // 300 * (4096 payload + 32 header) crosses 1 MiB but fits one segment.
        for sequence in 1..=300 {
            volume.write_ct(0, &[sequence as u8; 4096], false).unwrap();
        }
        volume.flush().unwrap();
        assert_eq!(volume.journal_segment_count(), 1);
        drop(volume);
        let writes = count_slot_writes(&backing);
        let volume = Volume::recover(backing.clone(), options()).unwrap();
        assert_eq!(
            writes.lock().unwrap().len(),
            2,
            "batch boundaries stay bounded"
        );
        assert_eq!(
            volume.read_ct(0).unwrap().unwrap(),
            (300, vec![300u16 as u8; 4096])
        );
        assert_eq!(volume.checkpoint_sequence(), 300);
    }
}

#[test]
fn discard_and_write_across_batch_boundary_preserve_the_latest_operation() {
    let _guard = failpoints::test_lock();
    for discard_last in [false, true] {
        let (backing, mut volume) = fixture(true);
        // 254 large records leave 64 bytes in the first 1 MiB batch. The
        // tombstone fits there, while the next large write starts batch 2.
        for sequence in 1..=254 {
            volume.write_ct(0, &[sequence as u8; 4096], false).unwrap();
        }
        volume.discard_ct(0, false).unwrap();
        let written = volume.write_ct(0, &[0x77; 4096], false).unwrap();
        let final_sequence = if discard_last {
            volume.discard_ct(0, false).unwrap()
        } else {
            written
        };
        volume.flush().unwrap();
        drop(volume);
        let writes = count_slot_writes(&backing);
        let volume = Volume::recover(backing.clone(), options()).unwrap();
        assert_eq!(writes.lock().unwrap().len(), usize::from(!discard_last));
        assert_eq!(volume.checkpoint_sequence(), final_sequence);
        let expected = (!discard_last).then(|| (written, vec![0x77; 4096]));
        assert_eq!(volume.read_ct(0).unwrap(), expected);
        drop(volume);
        backing.set_fault_hook(None);
        backing.crash_all_lost();
        let volume = Volume::recover(backing, options()).unwrap();
        assert_eq!(volume.read_ct(0).unwrap(), expected);
    }
}

#[test]
fn superseded_record_corruption_is_still_rejected_before_slot_application() {
    let _guard = failpoints::test_lock();
    for discard in [false, true] {
        let (backing, mut volume) = fixture(discard);
        volume.write_ct(0, &[1; 540], false).unwrap();
        volume.write_ct(0, &[2; 540], true).unwrap();
        let path = volume.journal_active_segment_path().unwrap();
        drop(volume);
        let file = backing.open(&path, false).unwrap();
        let payload_offset = (SEGMENT_HEADER_SIZE + RECORD_HEADER_SIZE) as u64;
        file.write_at(payload_offset, &[0xFF]).unwrap();
        file.sync_data().unwrap();
        let writes = count_slot_writes(&backing);
        assert!(Volume::recover(backing.clone(), options()).is_err());
        assert!(writes.lock().unwrap().is_empty());
    }
}

#[derive(Clone, Copy, Debug)]
enum ReplayFault {
    SlotWrite,
    SlotPayloadWrite,
    SlotSync,
    AllocationSync,
    DiscardSync,
    CheckpointSync,
    JournalRemovalSync,
}

#[test]
fn failed_latest_replay_remains_recoverable_after_restart_or_power_loss() {
    let _guard = failpoints::test_lock();
    for fault in [
        ReplayFault::SlotWrite,
        ReplayFault::SlotPayloadWrite,
        ReplayFault::SlotSync,
        ReplayFault::AllocationSync,
        ReplayFault::DiscardSync,
        ReplayFault::CheckpointSync,
        ReplayFault::JournalRemovalSync,
    ] {
        for restart in [false, true] {
            for seed in 0..8 {
                let (backing, mut volume) = fixture(true);
                for sequence in 1..=16 {
                    volume
                        .write_ct((sequence - 1) % 2, &[sequence as u8; 540], false)
                        .unwrap();
                }
                let sequence = volume.discard_ct(0, true).unwrap();
                drop(volume);
                let triggered = Arc::new(AtomicBool::new(false));
                let triggered_in_hook = triggered.clone();
                let removed = AtomicBool::new(false);
                let replay_started = AtomicBool::new(false);
                backing.set_fault_hook(Some(Arc::new(move |op| {
                    if matches!(op, FaultOp::WriteAt { path, .. } if path.ends_with(".dat")) {
                        replay_started.store(true, Ordering::SeqCst);
                    }
                    if matches!(op, FaultOp::Remove { path } if path.starts_with("journal/seg-")) {
                        removed.store(true, Ordering::SeqCst);
                    }
                    let fail = match fault {
                        ReplayFault::SlotWrite => matches!(op, FaultOp::WriteAt { path, .. }
                            if path.ends_with(".dat")),
                        ReplayFault::SlotPayloadWrite => matches!(op, FaultOp::WriteAt { path, len, .. }
                            if path.ends_with(".dat") && *len == 540),
                        ReplayFault::SlotSync => matches!(op, FaultOp::SyncData { path }
                            if path.ends_with(".dat")),
                        ReplayFault::AllocationSync => matches!(op, FaultOp::SyncData { path }
                            if path.contains(".alloc.")),
                        ReplayFault::DiscardSync => matches!(op, FaultOp::SyncData { path }
                            if path.contains(".discard.")),
                        ReplayFault::CheckpointSync => matches!(op, FaultOp::SyncData { path }
                            if path.starts_with("checkpoint/state.") && replay_started.load(Ordering::SeqCst)),
                        ReplayFault::JournalRemovalSync => matches!(op, FaultOp::SyncDir { dir }
                            if *dir == layout::JOURNAL_DIR && removed.load(Ordering::SeqCst)),
                    };
                    if fail && !triggered_in_hook.swap(true, Ordering::SeqCst) {
                        Some(io::Error::other("replay persistence fault"))
                    } else {
                        None
                    }
                })));
                assert!(
                    Volume::recover(backing.clone(), options()).is_err(),
                    "{fault:?}"
                );
                assert!(triggered.load(Ordering::SeqCst), "{fault:?}");
                backing.set_fault_hook(None);
                if restart {
                    // No crash first: read back failed-sync page-cache state
                    // and repair it before the following simulated power loss.
                    let volume = Volume::recover(backing.clone(), options()).unwrap();
                    assert_eq!(volume.checkpoint_sequence(), sequence);
                    drop(volume);
                }
                backing.crash(&mut StdRng::seed_from_u64(seed));
                let volume = Volume::recover(backing, options()).unwrap();
                assert_eq!(
                    volume.checkpoint_sequence(),
                    sequence,
                    "{fault:?} {restart} {seed}"
                );
                assert!(volume.read_ct(0).unwrap().is_none());
                assert_eq!(volume.read_ct(1).unwrap().unwrap(), (16, vec![16; 540]));
            }
        }
    }
}
