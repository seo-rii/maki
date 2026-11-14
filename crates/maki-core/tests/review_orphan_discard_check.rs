//! Fast checks and recovery must agree about the metadata needed to adopt
//! an orphan shard, including v3 discard evidence.

use std::io;
use std::sync::Arc;

use maki_backing::{Backing, MemBacking};
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
