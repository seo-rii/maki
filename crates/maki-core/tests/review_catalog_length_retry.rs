//! BUG-066: failed catalog shrink/retry must preserve acknowledged volumes.

use std::{
    io,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use maki_core::volume::{Volume, VolumeOptions};
use maki_format::{
    ab::AbStore, catalog::ShardCatalog, geometry::Geometry, init, layout, superblock::Superblock,
};
use maki_test_support::{crash_backing::FaultOp, failpoints, CrashableBacking};
use uuid::Uuid;

fn recover_after_catalog_failures(discard: bool, restart_after_shrink: bool) {
    let _lock = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new().with_tearing(512));
    let superblock = Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xB066),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, 512, 512, 520, 2048, 512).unwrap(),
        format_version: 1,
        created_unix: 0,
    };
    if discard {
        init::create_volume_with_discard(backing.as_ref(), superblock).unwrap();
    } else {
        init::create_volume(backing.as_ref(), superblock).unwrap();
    }
    let options = VolumeOptions {
        journal_segment_size: 4096,
    };
    let mut volume = Volume::recover(backing.clone(), options.clone()).unwrap();
    let sequence = volume.write_ct(2, &[0x66; 520], true).unwrap();
    volume.checkpoint().unwrap();
    drop(volume);

    // A failed reservation leaves a data-file orphan; recovery adopts it.
    let mut volume = Volume::recover(backing.clone(), options.clone()).unwrap();
    let allocation = layout::shard_alloc_a(0);
    backing.set_fault_hook(Some(Arc::new(move |op| match op {
        FaultOp::WriteAt { path, .. } if *path == allocation => {
            Some(io::Error::other("allocation write failed"))
        }
        _ => None,
    })));
    assert!(volume.write_ct(0, &[0x11; 520], true).is_err());
    backing.set_fault_hook(None);
    drop(volume);
    let mut volume = Volume::recover(backing.clone(), options.clone()).unwrap();
    let catalog = AbStore::new(layout::SHARD_CATALOG_A, layout::SHARD_CATALOG_B);

    // Both on-disk copies acquire three entries, while the failed final root
    // sync means the live store retains its previous two-entry catalog.
    for _ in 0..2 {
        let root_syncs = Arc::new(AtomicUsize::new(0));
        let counter = root_syncs.clone();
        backing.set_fault_hook(Some(Arc::new(move |op| match op {
            FaultOp::SyncDir { dir: "" } if counter.fetch_add(1, Ordering::SeqCst) == 1 => {
                Some(io::Error::other("catalog directory sync failed"))
            }
            _ => None,
        })));
        assert!(volume.write_ct(1, &[0x22; 520], true).is_err());
        backing.set_fault_hook(None);
        assert_eq!(root_syncs.load(Ordering::SeqCst), 2);
    }
    assert_eq!(
        catalog
            .load::<ShardCatalog>(backing.as_ref())
            .unwrap()
            .unwrap()
            .len(),
        3
    );
    let shortened = catalog
        .next_target_path::<ShardCatalog>(backing.as_ref())
        .unwrap()
        .to_owned();
    backing.set_fault_hook(Some(Arc::new(move |op| match op {
        FaultOp::SyncData { path } if *path == shortened => {
            Some(io::Error::other("shorter catalog sync failed"))
        }
        _ => None,
    })));
    assert!(volume.checkpoint().is_err());
    backing.set_fault_hook(None);
    assert_eq!(
        catalog
            .load::<ShardCatalog>(backing.as_ref())
            .unwrap()
            .unwrap()
            .len(),
        2
    );
    if restart_after_shrink {
        drop(volume);
        volume = Volume::recover(backing.clone(), options.clone()).unwrap();
    }

    let overwritten = catalog
        .next_target_path::<ShardCatalog>(backing.as_ref())
        .unwrap()
        .to_owned();
    let failed_path = overwritten.clone();
    backing.set_partial_write_hook(Some(Arc::new(move |op| match op {
        FaultOp::WriteAt { path, .. } if *path == failed_path => {
            Some((20, io::Error::other("other catalog partial write")))
        }
        _ => None,
    })));
    assert!(volume.checkpoint().is_err());
    backing.set_partial_write_hook(None);
    drop(volume);
    backing.crash_keep_torn_prefix(&overwritten, 20);
    let volume = Volume::recover(backing, options)
        .expect("catalog retry failures must not prevent acknowledged volume recovery");
    assert_eq!(
        volume.read_ct(2).unwrap(),
        Some((sequence, vec![0x66; 520]))
    );
}

#[test]
fn catalog_shrink_retry_preserves_fua_volume() {
    recover_after_catalog_failures(false, false);
}

#[test]
fn catalog_shrink_retry_preserves_fua_volume_after_restart() {
    recover_after_catalog_failures(false, true);
}

#[test]
fn discard_catalog_shrink_retry_preserves_fua_volume() {
    recover_after_catalog_failures(true, false);
}
