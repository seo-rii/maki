//! Exercise every discard-map sync boundary with Linux writeback-error
//! semantics, process restart, power-loss simulation, and A/B fallback.
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use maki_backing::Backing;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::{geometry::Geometry, init, layout, superblock::Superblock};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::CrashableBacking;
use rand::{rngs::StdRng, SeedableRng};

fn fixture() -> (Arc<CrashableBacking>, Volume, Geometry) {
    let backing = Arc::new(CrashableBacking::new().with_tearing(512));
    let geometry = Geometry::compute(512, 1024, 512, 1032, 16 * 1024, 8 * 1024).unwrap();
    init::create_volume_with_discard(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xc4a5a),
            provider_type: "test".into(),
            crypto_compatibility_id: "opaque".into(),
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
fn failed_map_syncs_remain_recoverable_and_retryable_in_both_directions() {
    // Each AbStore::store first syncs its preserved side, then its target.
    // Two stores and the final caller dirsync make four data / three dir
    // boundaries. Test both setting and clearing a durable tombstone.
    for clearing in [false, true] {
        for directory in [false, true] {
            let boundary_count = if directory { 3 } else { 4 };
            for boundary in 1..=boundary_count {
                for restart_before_retry in [false, true] {
                    for seed in 0..4 {
                        let (backing, mut volume, geometry) = fixture();
                        volume.write_ct(1, &[0x41; 1032], true).unwrap();
                        volume.checkpoint().unwrap();
                        if clearing {
                            volume.discard_ct(1, true).unwrap();
                            volume.checkpoint().unwrap();
                            volume.write_ct(1, &[0x42; 1032], true).unwrap();
                        } else {
                            volume.discard_ct(1, true).unwrap();
                        }
                        let previous = volume.checkpoint_sequence();
                        let syncs = Arc::new(AtomicUsize::new(0));
                        let punches = Arc::new(AtomicUsize::new(0));
                        let observed = syncs.clone();
                        let observed_punches = punches.clone();
                        backing.set_fault_hook(Some(Arc::new(move |op| {
                            if matches!(op, FaultOp::WriteAt { path, len, .. }
                                if path.ends_with(".dat") && *len == geometry.slot_size as usize)
                            {
                                observed_punches.fetch_add(1, Ordering::SeqCst);
                            }
                            let boundary_op = if directory {
                                matches!(op, FaultOp::SyncDir { dir } if *dir == layout::DATA_DIR)
                            } else {
                                matches!(op, FaultOp::SyncData { path } if path.contains(".discard."))
                            };
                            if boundary_op
                                && observed.fetch_add(1, Ordering::SeqCst) + 1 == boundary
                            {
                                Some(io::Error::other("discard metadata sync failure"))
                            } else {
                                None
                            }
                        })));
                        assert!(volume.checkpoint().is_err(), "boundary {boundary}");
                        assert_eq!(volume.checkpoint_sequence(), previous);
                        assert_eq!(punches.load(Ordering::SeqCst), 0);
                        backing.set_fault_hook(None);

                        if restart_before_retry {
                            // Restart while failed-sync bytes remain readable. Recovery
                            // must redirty them before they can justify journal removal.
                            drop(volume);
                            volume =
                                Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
                        } else {
                            volume.checkpoint().unwrap();
                        }
                        drop(volume);
                        backing.crash(&mut StdRng::seed_from_u64(seed));
                        // Damage one already-stable side: the other must carry
                        // the same logical state after either transition.
                        let path = if seed % 2 == 0 {
                            layout::shard_discard_a(0)
                        } else {
                            layout::shard_discard_b(0)
                        };
                        let copy = backing.open(&path, false).unwrap();
                        copy.write_at(0, &[0; 32]).unwrap();
                        copy.sync_data().unwrap();
                        let recovered = Volume::recover(backing, VolumeOptions::default()).unwrap();
                        let actual = recovered.read_ct(1).unwrap().map(|(_, ct)| ct);
                        assert!(
                            actual == clearing.then(|| vec![0x42; 1032]),
                            "clearing={clearing} directory={directory} boundary={boundary} restart={restart_before_retry} seed={seed}: got {:?}",
                            actual.as_ref().map(|ct| (ct.len(), ct.first()))
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn crash_without_retry_replays_acknowledged_discard_after_each_sync_failure() {
    for boundary in 1..=4 {
        for seed in 0..8 {
            let (backing, mut volume, _) = fixture();
            volume.write_ct(1, &[0x51; 1032], true).unwrap();
            volume.checkpoint().unwrap();
            volume.discard_ct(1, true).unwrap();
            let syncs = AtomicUsize::new(0);
            backing.set_fault_hook(Some(Arc::new(move |op| {
                if matches!(op, FaultOp::SyncData { path } if path.contains(".discard."))
                    && syncs.fetch_add(1, Ordering::SeqCst) + 1 == boundary
                {
                    Some(io::Error::other("discard map writeback failure"))
                } else {
                    None
                }
            })));
            assert!(volume.checkpoint().is_err());
            backing.set_fault_hook(None);
            drop(volume);
            backing.crash(&mut StdRng::seed_from_u64(seed));
            let recovered = Volume::recover(backing, VolumeOptions::default()).unwrap();
            assert!(recovered.read_ct(1).unwrap().is_none());
        }
    }
}

#[test]
fn unsupported_punch_still_commits_logical_zero_and_preserves_neighbors() {
    let (backing, mut volume, geometry) = fixture();
    for unit in 0..4 {
        volume.write_ct(unit, &[0x61; 1032], true).unwrap();
    }
    volume.checkpoint().unwrap();
    volume.discard_ct(1, true).unwrap();
    let punches = Arc::new(AtomicUsize::new(0));
    let observed = punches.clone();
    backing.set_fault_hook(Some(Arc::new(move |op| {
        if matches!(op, FaultOp::WriteAt { path, len, .. }
            if path.ends_with(".dat") && *len == geometry.slot_size as usize)
        {
            observed.fetch_add(1, Ordering::SeqCst);
            Some(io::Error::new(
                io::ErrorKind::Unsupported,
                "no hole punching",
            ))
        } else {
            None
        }
    })));
    volume.checkpoint().unwrap();
    assert_eq!(punches.load(Ordering::SeqCst), 1);
    backing.set_fault_hook(None);
    drop(volume);
    backing.crash(&mut StdRng::seed_from_u64(17));
    let recovered = Volume::recover(backing, VolumeOptions::default()).unwrap();
    assert!(recovered.read_ct(1).unwrap().is_none());
    for unit in [0, 2, 3] {
        assert_eq!(
            recovered.read_ct(unit).unwrap().unwrap().1,
            vec![0x61; 1032]
        );
    }
}

#[test]
fn partial_punch_failure_keeps_both_discards_and_the_gap_across_crash() {
    let (backing, mut volume, geometry) = fixture();
    for unit in 0..5 {
        volume.write_ct(unit, &[0x71; 1032], true).unwrap();
    }
    volume.checkpoint().unwrap();
    for unit in [1, 3] {
        volume.discard_ct(unit, true).unwrap();
    }
    let previous = volume.checkpoint_sequence();
    let punches = AtomicUsize::new(0);
    backing.set_fault_hook(Some(Arc::new(move |op| {
        if matches!(op, FaultOp::WriteAt { path, len, .. }
            if path.ends_with(".dat") && *len == geometry.slot_size as usize)
            && punches.fetch_add(1, Ordering::SeqCst) == 1
        {
            Some(io::Error::other("second hole punch failed"))
        } else {
            None
        }
    })));
    assert!(volume.checkpoint().is_err());
    assert_eq!(volume.checkpoint_sequence(), previous);
    backing.set_fault_hook(None);
    drop(volume);
    backing.crash(&mut StdRng::seed_from_u64(19));
    let recovered = Volume::recover(backing, VolumeOptions::default()).unwrap();
    for unit in [1, 3] {
        assert!(recovered.read_ct(unit).unwrap().is_none());
    }
    for unit in [0, 2, 4] {
        assert_eq!(
            recovered.read_ct(unit).unwrap().unwrap().1,
            vec![0x71; 1032]
        );
    }
}

#[test]
fn repeated_discard_with_fua_makes_the_existing_tombstone_durable() {
    let (backing, mut volume, _) = fixture();
    volume.write_ct(1, &[0x81; 1032], true).unwrap();
    volume.checkpoint().unwrap();
    let sequence = volume.discard_ct(1, false).unwrap();
    assert!(volume.journal_durable_sequence() < sequence);
    assert_eq!(volume.discard_ct(1, true).unwrap(), sequence);
    assert_eq!(volume.journal_durable_sequence(), sequence);
    drop(volume);
    backing.crash(&mut StdRng::seed_from_u64(21));
    let recovered = Volume::recover(backing, VolumeOptions::default()).unwrap();
    assert!(recovered.read_ct(1).unwrap().is_none());
}

#[test]
fn discard_transitions_replay_in_order_across_multiple_bounded_batches() {
    for clearing in [false, true] {
        let (backing, mut volume, _) = fixture();
        volume.write_ct(0, &[0x91; 1032], true).unwrap();
        volume.checkpoint().unwrap();
        if clearing {
            volume.discard_ct(0, false).unwrap();
        } else {
            volume.write_ct(0, &[0x92; 1032], false).unwrap();
        }
        // More than 1 MiB of intervening payload forces separate bounded
        // recovery batches for the two transitions of unit zero.
        for _ in 0..1100 {
            volume.write_ct(1, &[0x93; 1032], false).unwrap();
        }
        if clearing {
            volume.write_ct(0, &[0x94; 1032], false).unwrap();
        } else {
            volume.discard_ct(0, false).unwrap();
        }
        volume.flush().unwrap();
        drop(volume);
        backing.crash(&mut StdRng::seed_from_u64(23));
        let recovered = Volume::recover(backing, VolumeOptions::default()).unwrap();
        let actual = recovered.read_ct(0).unwrap().map(|(_, ct)| ct);
        assert_eq!(actual, clearing.then(|| vec![0x94; 1032]));
        assert_eq!(recovered.read_ct(1).unwrap().unwrap().1, vec![0x93; 1032]);
    }
}
