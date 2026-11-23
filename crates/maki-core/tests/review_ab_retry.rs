//! BUG-001: allocation and checkpoint-state A/B retries must leave a volume
//! recoverable after failed checkpoints, including every acknowledged
//! ciphertext write.

use std::io;
use std::sync::Arc;

use maki_backing::Backing;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::ab::AbStore;
use maki_format::allocation::AllocationMap;
use maki_format::checkpoint::{CheckpointState, CHECKPOINT_STATE_A, CHECKPOINT_STATE_B};
use maki_format::geometry::Geometry;
use maki_format::superblock::Superblock;
use maki_format::{init, layout};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::{failpoints, CrashableBacking};
use rand::{rngs::StdRng, SeedableRng};
use uuid::Uuid;

#[test]
fn failed_allocation_checkpoint_retry_survives_crash_and_recovers_all_durable_units() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new().with_tearing(512));
    let geometry = Geometry::compute(512, 512, 512, 540, 512 * 4096, 512 * 4096).unwrap();
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: Uuid::from_u128(0xAB001),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry,
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let options = VolumeOptions {
        journal_segment_size: 4096,
    };
    let mut volume = Volume::recover(backing.clone(), options.clone()).unwrap();
    let first = vec![1; 540];
    let second = vec![2; 540];
    let first_sequence = volume.write_ct(0, &first, true).unwrap();
    volume.checkpoint().unwrap();
    let second_sequence = volume.write_ct(4095, &second, true).unwrap();
    let allocation = AbStore::new(layout::shard_alloc_a(0), layout::shard_alloc_b(0));
    assert_eq!(
        allocation
            .side_generations::<AllocationMap>(backing.as_ref())
            .unwrap(),
        (Some(3), Some(2))
    );

    backing.set_fault_hook(Some(Arc::new(|op| match op {
        FaultOp::SyncData { path } if *path == layout::shard_alloc_b(0) => {
            Some(io::Error::other("allocation target sync failed"))
        }
        _ => None,
    })));
    assert!(volume.checkpoint().is_err());
    // Both files were created before the first journal ACK. The failed sync
    // leaves generation 4 visible in the page cache on side B, but the
    // preserve-first rule (BUG-001) has already made side A's durable
    // generation 3 safe; the retry can target side B again without
    // ever overwriting the last durable copy.
    assert_eq!(
        allocation
            .side_generations::<AllocationMap>(backing.as_ref())
            .unwrap(),
        (Some(3), Some(4))
    );
    backing.set_fault_hook(Some(Arc::new(|op| match op {
        FaultOp::SyncData { path }
            if *path == layout::shard_alloc_a(0) || *path == layout::shard_alloc_b(0) =>
        {
            Some(io::Error::other("allocation retry sync failed"))
        }
        _ => None,
    })));
    assert!(volume.checkpoint().is_err());
    drop(volume);
    backing.set_fault_hook(None);
    backing.crash(&mut StdRng::seed_from_u64(540));

    let mut volume = Volume::recover(backing.clone(), options.clone())
        .expect("failed allocation retry must not destroy both copies");
    assert_eq!(
        volume.read_ct(0).unwrap(),
        Some((first_sequence, first.clone()))
    );
    assert_eq!(
        volume.read_ct(4095).unwrap(),
        Some((second_sequence, second.clone()))
    );
    volume.checkpoint().unwrap();
    drop(volume);
    backing.crash_all_lost();
    let volume = Volume::recover(backing, options).unwrap();
    assert_eq!(volume.read_ct(0).unwrap(), Some((first_sequence, first)));
    assert_eq!(
        volume.read_ct(4095).unwrap(),
        Some((second_sequence, second))
    );
}

/// The checkpoint state's A/B side that the next store overwrites.
fn next_checkpoint_state_target(backing: &CrashableBacking) -> &'static str {
    let store = AbStore::new(CHECKPOINT_STATE_A, CHECKPOINT_STATE_B);
    let target = store.next_target_path::<CheckpointState>(backing).unwrap();
    if target == CHECKPOINT_STATE_A {
        CHECKPOINT_STATE_A
    } else {
        CHECKPOINT_STATE_B
    }
}

fn fail_sync(backing: &CrashableBacking, failed: &'static str) {
    backing.set_fault_hook(Some(Arc::new(move |op| match op {
        FaultOp::SyncData { path } if *path == failed => {
            Some(io::Error::other("checkpoint state sync failed"))
        }
        _ => None,
    })));
}

#[test]
fn torn_checkpoint_state_restore_after_restart_keeps_a_bridging_checkpoint() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let geometry = Geometry::compute(512, 512, 512, 540, 512 * 4096, 512 * 4096).unwrap();
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: Uuid::from_u128(0xAB002),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry,
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let options = VolumeOptions {
        journal_segment_size: 4096,
    };
    let mut volume = Volume::recover(backing.process(), options.clone()).unwrap();
    let mut acknowledged = Vec::new();
    for unit in 0..16 {
        let ciphertext = vec![unit as u8 + 1; 540];
        let sequence = volume.write_ct(unit, &ciphertext, true).unwrap();
        acknowledged.push((unit, sequence, ciphertext));
    }
    let first_segment = volume.journal_first_uncheckpointed_segment_path().unwrap();
    volume.checkpoint().unwrap();
    // From here on, only a checkpoint state at least this new bridges the
    // remaining journal.
    assert!(
        !backing.exists(&first_segment).unwrap(),
        "the checkpoint must reclaim the journal it covers"
    );

    // The next checkpoint's state store fails on its target side: that
    // newer state stays readable in the page cache, but is not durable.
    let ciphertext = vec![0xAA; 540];
    let sequence = volume.write_ct(16, &ciphertext, true).unwrap();
    acknowledged.push((16, sequence, ciphertext));
    let readable = next_checkpoint_state_target(&backing);
    fail_sync(&backing, readable);
    assert!(volume.checkpoint().is_err());
    backing.set_fault_hook(None);

    // Restart: recovery selects that readable state and re-stores it before
    // the writer resumes (BUG-022), overwriting the side that holds the
    // last durable state. Its sync fails, and its write is still dirty when
    // the power fails and tears it (the new header over the old payload);
    // every unproven write is lost.
    drop(volume);
    let durable = next_checkpoint_state_target(&backing);
    assert_ne!(durable, readable);
    backing.set_lenient_sync_failures(true);
    fail_sync(&backing, durable);
    assert!(Volume::recover(backing.process(), options.clone()).is_err());
    backing.set_fault_hook(None);
    backing.set_lenient_sync_failures(false);
    backing.crash_keep_torn_prefix(durable, 20);

    // Preserve-first made the readable state durable before its other side
    // was overwritten. Without it the side left is two checkpoints old, and
    // the journal it needs was reclaimed by the first checkpoint.
    let volume = Volume::recover(backing.process(), options)
        .expect("a torn checkpoint-state retry must leave a checkpoint the journal bridges");
    for (unit, sequence, ciphertext) in acknowledged {
        assert_eq!(
            volume.read_ct(unit).unwrap(),
            Some((sequence, ciphertext)),
            "unit {unit}"
        );
    }
}
