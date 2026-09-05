//! BUG-001: allocation A/B retries must leave a volume recoverable after
//! failed checkpoints, including every acknowledged ciphertext write.

use std::io;
use std::sync::Arc;

use maki_core::volume::{Volume, VolumeOptions};
use maki_format::ab::AbStore;
use maki_format::allocation::AllocationMap;
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
        (Some(1), Some(2))
    );

    backing.set_fault_hook(Some(Arc::new(|op| match op {
        FaultOp::SyncData { path } if *path == layout::shard_alloc_a(0) => {
            Some(io::Error::other("allocation target sync failed"))
        }
        _ => None,
    })));
    assert!(volume.checkpoint().is_err());
    assert_eq!(
        allocation
            .side_generations::<AllocationMap>(backing.as_ref())
            .unwrap(),
        (Some(3), Some(2))
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
