//! Fast checks and recovery must agree about the metadata needed to adopt
//! an orphan shard, including v3 discard evidence.

use std::io;
use std::sync::Arc;

use maki_backing::{Backing, MemBacking};
use maki_core::check::deep_check;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::ab::AbStore;
use maki_format::allocation::AllocationMap;
use maki_format::checker::check_volume;
use maki_format::geometry::Geometry;
use maki_format::{init, layout, superblock::Superblock, FormatError};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::CrashableBacking;

fn block() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(0xa0d17),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "key".into(),
        geometry: Geometry::compute(512, 1024, 512, 1032, 16384, 8192).unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn add_orphan(backing: &dyn Backing, shard: u64, map_units: Option<u64>) {
    // Model an uncataloged shard, e.g. after falling back to an older catalog.
    backing.open(&layout::shard_data(shard), true).unwrap();
    if let Some(units) = map_units {
        let store = AbStore::new(
            layout::shard_discard_a(shard),
            layout::shard_discard_b(shard),
        );
        let mut map = AllocationMap::new(units);
        store.store(backing, &mut map).unwrap();
        store.store(backing, &mut map).unwrap();
    }
}

fn orphan(with_discard: bool) -> Arc<MemBacking> {
    let backing = Arc::new(MemBacking::new());
    let block = block();
    let units = block.geometry.units_per_shard();
    init::create_volume_with_discard(backing.as_ref(), block).unwrap();
    add_orphan(backing.as_ref(), 0, with_discard.then_some(units));
    backing
}

#[test]
fn valid_v3_orphan_control_is_recoverable() {
    let backing = orphan(true);
    let report = check_volume(backing.as_ref()).unwrap();
    assert!(report.ok(), "{:?}", report.errors);
    let volume = Volume::recover(backing, VolumeOptions::default()).unwrap();
    assert!(volume.read_ct(0).unwrap().is_none());
}

#[test]
fn missing_v3_orphan_discard_map_must_not_claim_successful_adoption() {
    let backing = orphan(false);
    let report = check_volume(backing.as_ref()).unwrap();
    let recovery = Volume::recover(backing, VolumeOptions::default());
    let error = match recovery {
        Ok(_) => panic!("missing v3 discard metadata was unexpectedly recoverable"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("no valid discard map"),
        "{error}"
    );
    assert!(
        !report.ok(),
        "fast checker claims adoption for metadata that recovery rejects"
    );
    assert!(report
        .warnings
        .iter()
        .all(|warning| !warning.contains("recovery adopts it")));
}

#[test]
fn one_valid_orphan_discard_copy_remains_recoverable_with_a_warning() {
    let backing = orphan(true);
    backing.remove(&layout::shard_discard_a(0)).unwrap();
    let report = check_volume(backing.as_ref()).unwrap();
    assert!(report.ok(), "{:?}", report.errors);
    assert!(report
        .warnings
        .iter()
        .any(|warning| warning.contains("one valid copy")));
    Volume::recover(backing, VolumeOptions::default()).unwrap();
}

#[test]
fn wrong_sized_orphan_discard_maps_are_rejected_by_check_and_recovery() {
    let backing = orphan(false);
    add_orphan(backing.as_ref(), 0, Some(1));
    let report = check_volume(backing.as_ref()).unwrap();
    assert!(!report.ok());
    assert!(report
        .errors
        .iter()
        .any(|error| error.contains("discard map covers 1 units")));
    assert!(Volume::recover(backing, VolumeOptions::default()).is_err());
}

#[test]
fn damaged_orphan_discard_maps_are_rejected_by_check_and_recovery() {
    let backing = orphan(true);
    for path in [layout::shard_discard_a(0), layout::shard_discard_b(0)] {
        backing
            .open(&path, false)
            .unwrap()
            .write_at(0, b"broken")
            .unwrap();
    }
    let report = check_volume(backing.as_ref()).unwrap();
    assert!(!report.ok());
    assert!(Volume::recover(backing, VolumeOptions::default()).is_err());
}

#[test]
fn ignored_out_of_geometry_shards_do_not_need_discard_maps() {
    let backing = orphan(true);
    add_orphan(backing.as_ref(), 99, None);
    let report = check_volume(backing.as_ref()).unwrap();
    assert!(report.ok(), "{:?}", report.errors);
    assert!(report
        .warnings
        .iter()
        .any(|warning| warning.contains("index 99") && warning.contains("ignored")));
    Volume::recover(backing, VolumeOptions::default()).unwrap();
}

#[test]
fn v2_orphans_do_not_need_discard_maps() {
    let backing = Arc::new(MemBacking::new());
    init::create_volume(backing.as_ref(), block()).unwrap();
    add_orphan(backing.as_ref(), 0, None);
    let report = check_volume(backing.as_ref()).unwrap();
    assert!(report.ok(), "{:?}", report.errors);
    Volume::recover(backing, VolumeOptions::default()).unwrap();
}

#[test]
fn orphan_discard_io_error_remains_inconclusive() {
    let backing = CrashableBacking::new();
    let block = block();
    let units = block.geometry.units_per_shard();
    init::create_volume_with_discard(&backing, block).unwrap();
    add_orphan(&backing, 0, Some(units));
    backing.set_fault_hook(Some(Arc::new(|operation| {
        matches!(operation, FaultOp::Open { path, .. } if path == &layout::shard_discard_a(0))
            .then(|| io::Error::from_raw_os_error(24))
    })));
    assert!(
        matches!(check_volume(&backing), Err(FormatError::Io(error)) if error.raw_os_error() == Some(24))
    );
}

#[test]
fn opening_partial_shards_reads_only_logical_headers_and_each_discard_copy_once() {
    use maki_core::store::SlotStore;

    let open_bytes = |logical_units: u64, discard, missing_alloc| {
        let backing = Arc::new(CrashableBacking::new());
        let mut sb = block();
        sb.geometry = Geometry::compute(512, 1024, 512, 1032, 1024 * logical_units, 8192).unwrap();
        let geometry = sb.geometry.clone();
        if discard {
            init::create_volume_with_discard(backing.as_ref(), sb).unwrap();
        } else {
            init::create_volume(backing.as_ref(), sb).unwrap();
        }
        let mut store = SlotStore::open(backing.clone(), geometry.clone()).unwrap();
        store.reserve_slot(0).unwrap();
        drop(store);
        if missing_alloc {
            backing.remove(&layout::shard_alloc_b(0)).unwrap();
        }
        let before = backing.read_bytes();
        SlotStore::open(backing.clone(), geometry).unwrap();
        backing.read_bytes() - before
    };

    // Same physical data file and metadata sizes; only seven additional
    // addressable headers separate a full shard from its one-unit tail.
    assert_eq!(
        open_bytes(8, false, true) - open_bytes(1, false, true),
        7 * 64
    );
    assert_eq!(
        open_bytes(1, true, false) - open_bytes(1, false, false),
        2 * AllocationMap::encoded_len(8)
    );
}

#[test]
fn directory_cannot_be_adopted_or_used_as_cataloged_shard_data() {
    let backing = Arc::new(MemBacking::new());
    let sb = block();
    let units = sb.geometry.units_per_shard();
    init::create_volume(backing.as_ref(), sb).unwrap();
    backing.create_dir_all(&layout::shard_data(0)).unwrap();

    for cataloged in [false, true] {
        if cataloged {
            let mut catalog = maki_format::catalog::ShardCatalog::new();
            catalog.insert(0);
            AbStore::new(layout::SHARD_CATALOG_A, layout::SHARD_CATALOG_B)
                .store(backing.as_ref(), &mut catalog)
                .unwrap();
            AbStore::new(layout::shard_alloc_a(0), layout::shard_alloc_b(0))
                .store(backing.as_ref(), &mut AllocationMap::new(units))
                .unwrap();
        }
        let report = check_volume(backing.as_ref()).unwrap();
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains("invalid data file")),
            "{report:?}"
        );
        assert!(!report
            .warnings
            .iter()
            .any(|w| w.contains("recovery adopts it")));
        let deep = deep_check(backing.clone(), 4096).unwrap();
        assert!(
            deep.errors
                .iter()
                .any(|e| e.contains("shard 0: invalid data file")),
            "{deep:?}"
        );
        assert!(Volume::recover(backing.clone(), VolumeOptions::default()).is_err());
    }
}

#[test]
fn deep_check_preserves_the_missing_data_directory_diagnostic() {
    let root = tempfile::tempdir().unwrap();
    let backing = Arc::new(maki_backing::FileBacking::new(root.path()).unwrap());
    init::create_volume(backing.as_ref(), block()).unwrap();
    std::fs::remove_dir(root.path().join(layout::DATA_DIR)).unwrap();
    let report = deep_check(backing, 4096).unwrap();
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("data directory is missing")),
        "{report:?}"
    );
}

#[test]
fn fast_check_requires_at_least_one_checkpoint_state_file() {
    use maki_format::checkpoint::{CHECKPOINT_STATE_A, CHECKPOINT_STATE_B};
    for discard in [false, true] {
        let backing = MemBacking::new();
        if discard {
            init::create_volume_with_discard(&backing, block()).unwrap();
        } else {
            init::create_volume(&backing, block()).unwrap();
        }
        backing.remove(CHECKPOINT_STATE_A).unwrap();
        assert!(check_volume(&backing).unwrap().ok());
        backing.remove(CHECKPOINT_STATE_B).unwrap();
        let report = check_volume(&backing).unwrap();
        assert!(
            report.errors.iter().any(|e| e.contains("checkpoint state")),
            "{report:?}"
        );
        backing.create_dir_all(CHECKPOINT_STATE_B).unwrap();
        assert!(!check_volume(&backing).unwrap().ok());
    }
}

#[test]
fn fast_check_reads_each_discard_copy_once() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let backing = CrashableBacking::new();
    let sb = block();
    let units = sb.geometry.units_per_shard();
    init::create_volume_with_discard(&backing, sb).unwrap();
    add_orphan(&backing, 0, Some(units));
    let reads = Arc::new(AtomicUsize::new(0));
    let counter = reads.clone();
    backing.set_fault_hook(Some(Arc::new(move |op| {
        if matches!(op, FaultOp::Open { path, .. } if path == &layout::shard_discard_a(0) || path == &layout::shard_discard_b(0)) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        None
    })));
    assert!(check_volume(&backing).unwrap().ok());
    assert_eq!(reads.load(Ordering::Relaxed), 2);
}

#[test]
fn orphan_with_a_stored_allocation_map_must_match_the_geometry() {
    for discard in [false, true] {
        for map_units in [None, Some(4), Some(8)] {
            let backing = Arc::new(MemBacking::new());
            let sb = block();
            let units = sb.geometry.units_per_shard();
            assert_eq!(units, 8);
            if discard {
                init::create_volume_with_discard(backing.as_ref(), sb).unwrap();
            } else {
                init::create_volume(backing.as_ref(), sb).unwrap();
            }
            add_orphan(backing.as_ref(), 0, discard.then_some(units));
            if let Some(map_units) = map_units {
                AbStore::new(layout::shard_alloc_a(0), layout::shard_alloc_b(0))
                    .store(backing.as_ref(), &mut AllocationMap::new(map_units))
                    .unwrap();
            }
            let report = check_volume(backing.as_ref()).unwrap();
            let recoverable = map_units.is_none_or(|size| size == units);
            assert_eq!(
                Volume::recover(backing, VolumeOptions::default()).is_ok(),
                recoverable
            );
            assert_eq!(report.ok(), recoverable, "{report:?}");
            assert_eq!(
                report
                    .warnings
                    .iter()
                    .any(|w| w.contains("recovery adopts it")),
                recoverable
            );
            if !recoverable {
                assert!(
                    report
                        .errors
                        .iter()
                        .any(|e| e.contains("allocation map covers 4 units")),
                    "{report:?}"
                );
            }
        }
    }
}

#[test]
fn slot_store_refuses_geometry_that_differs_from_the_superblock() {
    use maki_core::store::SlotStore;
    let backing = Arc::new(MemBacking::new());
    let sb = block();
    let geometry = sb.geometry.clone();
    init::create_volume(backing.as_ref(), sb).unwrap();
    let stale_geometry = Geometry::compute(512, 1024, 512, 2048, 16384, 8192).unwrap();
    assert_ne!(stale_geometry.slot_size, geometry.slot_size);
    assert!(matches!(
        SlotStore::open(backing.clone(), stale_geometry),
        Err(maki_core::CoreError::Invalid(_))
    ));
    SlotStore::open(backing, geometry).unwrap();
}

#[test]
fn healthy_slot_store_reads_each_allocation_copy_once() {
    use maki_core::store::SlotStore;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let backing = Arc::new(CrashableBacking::new());
    let sb = block();
    let geometry = sb.geometry.clone();
    init::create_volume(backing.as_ref(), sb).unwrap();
    let mut store = SlotStore::open(backing.clone(), geometry.clone()).unwrap();
    store.reserve_slot(0).unwrap();
    drop(store);

    let reads = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
    let counters = reads.clone();
    backing.set_fault_hook(Some(Arc::new(move |op| {
        if let FaultOp::Open { path, .. } = op {
            for (side, name) in [layout::shard_alloc_a(0), layout::shard_alloc_b(0)]
                .iter()
                .enumerate()
            {
                if path == name {
                    counters[side].fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        None
    })));
    SlotStore::open(backing, geometry).unwrap();
    assert_eq!(reads.each_ref().map(|n| n.load(Ordering::Relaxed)), [1, 1]);
}

#[test]
fn both_checks_report_the_unusable_superblock_copy_without_repairing_it() {
    for path in [layout::SUPERBLOCK_A, layout::SUPERBLOCK_B] {
        for missing in [true, false] {
            let backing = Arc::new(MemBacking::new());
            init::create_volume(backing.as_ref(), block()).unwrap();
            assert!(check_volume(backing.as_ref()).unwrap().warnings.is_empty());
            if missing {
                backing.remove(path).unwrap();
            } else {
                backing.open(path, false).unwrap().set_len(0).unwrap();
            }
            let fast = check_volume(backing.as_ref()).unwrap();
            let deep = deep_check(backing.clone(), 1 << 20).unwrap();
            for report in [fast, deep] {
                assert!(report.ok(), "{report:?}");
                assert!(
                    report
                        .warnings
                        .iter()
                        .any(|w| w.contains(path) && w.contains("fallback")),
                    "{report:?}"
                );
            }
            assert_eq!(backing.exists(path).unwrap(), !missing);
            if !missing {
                assert_eq!(backing.open(path, false).unwrap().len().unwrap(), 0);
            }
        }
    }
}
