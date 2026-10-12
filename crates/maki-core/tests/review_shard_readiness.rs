//! BUG-043: a recovered data file is not proof that shard creation finished.
//! Both allocation copies and the catalog entry must be durable before FUA.

use std::collections::HashSet;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use maki_backing::Backing;
use maki_core::volume::{Volume, VolumeOptions};
use maki_core::CoreError;
use maki_format::ab::AbStore;
use maki_format::allocation::AllocationMap;
use maki_format::catalog::ShardCatalog;
use maki_format::{geometry::Geometry, init, layout, superblock::Superblock};
use maki_test_support::{crash_backing::FaultOp, failpoints, CrashableBacking};

fn geometry() -> Geometry {
    Geometry::compute(512, 512, 512, 520, 512 * 64, 512 * 16).unwrap()
}

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: 4096,
    }
}

fn fixture(discard: bool) -> Arc<CrashableBacking> {
    let backing = Arc::new(CrashableBacking::new().with_tearing(512));
    let superblock = Superblock {
        generation: 0,
        volume_uuid: Default::default(),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: geometry(),
        format_version: 1,
        created_unix: 0,
    };
    if discard {
        init::create_volume_with_discard(backing.as_ref(), superblock).unwrap();
    } else {
        init::create_volume(backing.as_ref(), superblock).unwrap();
    }
    backing
}

fn recover(backing: &Arc<CrashableBacking>) -> Volume {
    Volume::recover(backing.clone(), options()).unwrap()
}

fn catalog(backing: &Arc<CrashableBacking>) -> ShardCatalog {
    AbStore::new(layout::SHARD_CATALOG_A, layout::SHARD_CATALOG_B)
        .load::<ShardCatalog>(backing.as_ref())
        .unwrap()
        .unwrap()
}

fn assert_ready(backing: &Arc<CrashableBacking>, shard: u64) {
    let (a, b) = AbStore::new(layout::shard_alloc_a(shard), layout::shard_alloc_b(shard))
        .side_generations::<AllocationMap>(backing.as_ref())
        .unwrap();
    assert!(
        a.is_some() && b.is_some(),
        "shard {shard}: both allocation copies must be prepared before ACK: A={a:?}, B={b:?}"
    );
    assert!(
        catalog(backing).contains(shard),
        "shard {shard}: catalog entry must precede ACK"
    );
}

/// Exercise the real create prefix and fail only allocation-file creation.
/// The data file remains readable across this plain process restart.
fn interrupt_first_write(backing: &Arc<CrashableBacking>, unit: u64, target: String) {
    let mut volume = recover(backing);
    let hit = Arc::new(AtomicUsize::new(0));
    let observed = hit.clone();
    backing.set_fault_hook(Some(Arc::new(move |op| match op {
        FaultOp::Open { path, create: true } if *path == target => {
            observed.fetch_add(1, Ordering::SeqCst);
            Some(io::Error::new(
                io::ErrorKind::StorageFull,
                "allocation creation ENOSPC",
            ))
        }
        _ => None,
    })));
    let result = volume.write_ct(unit, &[0x30; 520], true);
    assert!(
        matches!(result, Err(CoreError::Io(ref e)) if e.kind() == io::ErrorKind::StorageFull),
        "{result:?}"
    );
    assert_eq!(volume.journal_appended_sequence(), 0);
    assert_eq!(volume.journal_durable_sequence(), 0);
    assert_eq!(hit.load(Ordering::SeqCst), 1);
    let shard = geometry().shard_of_unit(unit).0;
    assert!(backing.exists(&layout::shard_data(shard)).unwrap());
    backing.set_fault_hook(None);
    drop(volume);
}

/// Existing journal, slot, and metadata writes remain permitted. Only an
/// allocation file that was still missing at admission is denied creation.
fn deny_missing_allocation_creations(
    backing: &Arc<CrashableBacking>,
    shards: &[u64],
) -> Arc<AtomicUsize> {
    let missing: HashSet<_> = shards
        .iter()
        .flat_map(|shard| [layout::shard_alloc_a(*shard), layout::shard_alloc_b(*shard)])
        .filter(|path| !backing.exists(path).unwrap())
        .collect();
    let hit = Arc::new(AtomicUsize::new(0));
    let observed = hit.clone();
    backing.set_fault_hook(Some(Arc::new(move |op| match op {
        FaultOp::Open { path, create: true } if missing.contains(*path) => {
            observed.fetch_add(1, Ordering::SeqCst);
            Some(io::Error::new(
                io::ErrorKind::StorageFull,
                "new allocation metadata ENOSPC",
            ))
        }
        _ => None,
    })));
    hit
}

fn complete_and_power_loss(backing: &Arc<CrashableBacking>, volume: Volume, expected: &[u8]) {
    assert_ready(backing, 0);
    let denied = deny_missing_allocation_creations(backing, &[0]);
    drop(volume);
    backing.crash_all_lost();
    // Check the physical copies before replay or checkpoint could heal them.
    assert_ready(backing, 0);
    let mut volume = recover(backing);
    assert_eq!(volume.read_ct(0).unwrap().unwrap().1, expected);
    volume.checkpoint().unwrap();
    assert_eq!(denied.load(Ordering::SeqCst), 0);
}

#[test]
fn interrupted_shard_direct_retry_prepares_metadata_before_fua() {
    let _serial = failpoints::test_lock();
    for discard in [false, true] {
        let backing = fixture(discard);
        interrupt_first_write(&backing, 0, layout::shard_alloc_a(0));
        let mut volume = recover(&backing);
        assert_eq!(volume.write_ct(0, &[0x41; 520], true).unwrap(), 1);
        assert_eq!(volume.journal_durable_sequence(), 1);
        complete_and_power_loss(&backing, volume, &[0x41; 520]);
    }
}

#[test]
fn empty_checkpoint_before_fua_prepares_both_allocation_copies() {
    let _serial = failpoints::test_lock();
    for discard in [false, true] {
        let backing = fixture(discard);
        interrupt_first_write(&backing, 0, layout::shard_alloc_a(0));
        let mut volume = recover(&backing);
        assert_eq!(volume.checkpoint().unwrap(), 0);
        assert_eq!(volume.write_ct(0, &[0x42; 520], true).unwrap(), 1);
        complete_and_power_loss(&backing, volume, &[0x42; 520]);
    }
}

#[test]
fn cached_b_after_failed_sync_is_redirtied_before_fua() {
    let _serial = failpoints::test_lock();
    let backing = fixture(false);
    interrupt_first_write(&backing, 0, layout::shard_alloc_b(0));
    let mut volume = recover(&backing);
    let target = layout::shard_alloc_b(0);
    let armed = Arc::new(AtomicBool::new(true));
    let observed = armed.clone();
    backing.set_fault_hook(Some(Arc::new(move |op| match op {
        FaultOp::SyncData { path } if *path == target && observed.swap(false, Ordering::SeqCst) => {
            Some(io::Error::other("allocation B writeback EIO"))
        }
        _ => None,
    })));
    assert!(volume.checkpoint().is_err());
    assert!(!armed.load(Ordering::SeqCst));
    let cached = backing.open(&layout::shard_alloc_b(0), false).unwrap();
    let mut bytes = vec![0; cached.len().unwrap() as usize];
    cached.read_at(0, &mut bytes).unwrap();
    AllocationMap::decode(&bytes).unwrap();
    drop(cached);
    backing.set_fault_hook(None);
    drop(volume); // Cache remains, including clean pages whose sync failed.
    let mut volume = recover(&backing);
    assert_eq!(volume.write_ct(0, &[0x51; 520], true).unwrap(), 1);
    drop(volume);
    backing.crash_all_lost(); // Only this operation models power loss.
    assert_ready(&backing, 0);
    deny_missing_allocation_creations(&backing, &[0]);
    let volume = recover(&backing);
    assert_eq!(volume.read_ct(0).unwrap().unwrap().1, vec![0x51; 520]);
}

#[test]
fn second_copy_sync_failure_denies_fua_and_same_process_retry_completes_it() {
    let _serial = failpoints::test_lock();
    for discard in [false, true] {
        let backing = fixture(discard);
        interrupt_first_write(&backing, 0, layout::shard_alloc_a(0));
        let mut volume = recover(&backing);
        let target = layout::shard_alloc_b(0);
        let armed = Arc::new(AtomicBool::new(true));
        let observed = armed.clone();
        backing.set_fault_hook(Some(Arc::new(move |op| match op {
            FaultOp::SyncData { path }
                if *path == target && observed.swap(false, Ordering::SeqCst) =>
            {
                Some(io::Error::other("second allocation copy sync failed"))
            }
            _ => None,
        })));
        assert!(volume.write_ct(0, &[0x61; 520], true).is_err());
        assert!(!armed.load(Ordering::SeqCst));
        assert_eq!(volume.journal_appended_sequence(), 0);
        backing.set_fault_hook(None);
        assert_eq!(volume.write_ct(0, &[0x61; 520], true).unwrap(), 1);
        complete_and_power_loss(&backing, volume, &[0x61; 520]);
    }
}

#[test]
fn allocation_directory_failure_denies_fua_and_retry_keeps_preparation_pending() {
    let _serial = failpoints::test_lock();
    for discard in [false, true] {
        let backing = fixture(discard);
        interrupt_first_write(&backing, 0, layout::shard_alloc_a(0));
        let mut volume = recover(&backing);
        let syncs = Arc::new(AtomicUsize::new(0));
        let observed = syncs.clone();
        backing.set_fault_hook(Some(Arc::new(move |op| match op {
            // First: preserve A before creating B. Second: publish B's dirent.
            FaultOp::SyncDir { dir }
                if *dir == layout::DATA_DIR && observed.fetch_add(1, Ordering::SeqCst) == 1 =>
            {
                Some(io::Error::other("allocation directory publication failed"))
            }
            _ => None,
        })));
        assert!(volume.write_ct(0, &[0x62; 520], true).is_err());
        assert_eq!(syncs.load(Ordering::SeqCst), 2);
        assert_eq!(volume.journal_appended_sequence(), 0);
        let (a, b) = AbStore::new(layout::shard_alloc_a(0), layout::shard_alloc_b(0))
            .side_generations::<AllocationMap>(backing.as_ref())
            .unwrap();
        assert!(
            a.is_some() && b.is_some(),
            "fail after both copies were written"
        );
        backing.set_fault_hook(None);
        assert_eq!(volume.write_ct(0, &[0x62; 520], true).unwrap(), 1);
        complete_and_power_loss(&backing, volume, &[0x62; 520]);
    }
}

#[test]
fn empty_checkpoint_second_copy_failure_can_retry_without_cataloging_incomplete_maps() {
    let _serial = failpoints::test_lock();
    for discard in [false, true] {
        let backing = fixture(discard);
        interrupt_first_write(&backing, 0, layout::shard_alloc_a(0));
        let mut volume = recover(&backing);
        let target = layout::shard_alloc_b(0);
        let armed = Arc::new(AtomicBool::new(true));
        let observed = armed.clone();
        backing.set_fault_hook(Some(Arc::new(move |op| match op {
            FaultOp::SyncData { path }
                if *path == target && observed.swap(false, Ordering::SeqCst) =>
            {
                Some(io::Error::other(
                    "checkpoint's second allocation copy sync failed",
                ))
            }
            _ => None,
        })));
        assert!(volume.checkpoint().is_err());
        assert!(!armed.load(Ordering::SeqCst));
        assert!(!catalog(&backing).contains(0));
        assert_eq!(volume.journal_appended_sequence(), 0);
        backing.set_fault_hook(None);
        assert_eq!(volume.checkpoint().unwrap(), 0);
        assert_ready(&backing, 0);
        assert_eq!(volume.write_ct(0, &[0x63; 520], true).unwrap(), 1);
        complete_and_power_loss(&backing, volume, &[0x63; 520]);
    }
}

#[test]
fn entire_adopted_catalog_waits_for_every_shards_two_copies() {
    let _serial = failpoints::test_lock();
    for discard in [false, true] {
        let backing = fixture(discard);
        interrupt_first_write(&backing, 0, layout::shard_alloc_a(0));
        interrupt_first_write(
            &backing,
            geometry().units_per_shard(),
            layout::shard_alloc_a(1),
        );
        let mut volume = recover(&backing);
        let target = layout::shard_alloc_b(1);
        let hit = Arc::new(AtomicUsize::new(0));
        let observed = hit.clone();
        backing.set_fault_hook(Some(Arc::new(move |op| match op {
            FaultOp::Open { path, create: true } if *path == target => {
                observed.fetch_add(1, Ordering::SeqCst);
                Some(io::Error::new(
                    io::ErrorKind::StorageFull,
                    "other adopted shard's B creation ENOSPC",
                ))
            }
            _ => None,
        })));
        assert!(volume.write_ct(0, &[0x64; 520], true).is_err());
        assert_eq!(hit.load(Ordering::SeqCst), 1);
        assert_eq!(volume.journal_appended_sequence(), 0);
        assert!(!catalog(&backing).contains(0));
        assert!(!catalog(&backing).contains(1));
        backing.set_fault_hook(None);
        assert_eq!(volume.write_ct(0, &[0x64; 520], true).unwrap(), 1);
        assert_ready(&backing, 0);
        assert_ready(&backing, 1);
        drop(volume);
        backing.crash_all_lost();
        assert_ready(&backing, 0);
        assert_ready(&backing, 1);
        deny_missing_allocation_creations(&backing, &[0, 1]);
        let volume = recover(&backing);
        assert_eq!(volume.read_ct(0).unwrap().unwrap().1, vec![0x64; 520]);
    }
}

#[test]
fn reading_recovered_shards_defers_allocation_republication() {
    let _serial = failpoints::test_lock();
    for discard in [false, true] {
        let backing = fixture(discard);
        let mut volume = recover(&backing);
        volume.write_ct(0, &[0x71; 520], true).unwrap();
        volume.checkpoint().unwrap();
        drop(volume);
        let paths: HashSet<_> = [
            layout::shard_alloc_a(0),
            layout::shard_alloc_b(0),
            layout::SHARD_CATALOG_A.into(),
            layout::SHARD_CATALOG_B.into(),
        ]
        .into_iter()
        .collect();
        backing.set_fault_hook(Some(Arc::new(move |op| match op {
            FaultOp::WriteAt { path, .. }
            | FaultOp::SetLen { path, .. }
            | FaultOp::SyncData { path }
                if paths.contains(*path) =>
            {
                Some(io::Error::other(
                    "allocation metadata changed before a reservation or checkpoint",
                ))
            }
            _ => None,
        })));
        let volume = recover(&backing);
        assert_eq!(volume.read_ct(0).unwrap().unwrap().1, vec![0x71; 520]);
    }
}

#[test]
fn fresh_shard_prepares_metadata_before_fua_positive_control() {
    let _serial = failpoints::test_lock();
    for discard in [false, true] {
        let backing = fixture(discard);
        let mut volume = recover(&backing);
        assert_eq!(volume.write_ct(0, &[0x72; 520], true).unwrap(), 1);
        complete_and_power_loss(&backing, volume, &[0x72; 520]);
    }
}
