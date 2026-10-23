//! BUG-159: invalid public SlotStore input must leave the store reopenable.

use std::{collections::BTreeMap, sync::Arc};

use maki_backing::{Backing, FileBacking, MemBacking};
use maki_core::error::CoreError;
use maki_core::store::{SlotRead, SlotStore};
use maki_format::{geometry::Geometry, init, layout, superblock::Superblock};

fn store(
    filesystem: bool,
    units: u64,
) -> (
    Arc<dyn Backing>,
    Geometry,
    SlotStore,
    Option<tempfile::TempDir>,
) {
    let directory = filesystem.then(|| tempfile::tempdir().unwrap());
    let backing: Arc<dyn Backing> = match &directory {
        Some(directory) => Arc::new(FileBacking::new(directory.path()).unwrap()),
        None => Arc::new(MemBacking::new()),
    };
    let geometry = Geometry::compute(512, 1024, 512, 1032, units * 1024, 4 * 1024).unwrap();
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(159),
            provider_type: "test".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "test".into(),
            geometry: geometry.clone(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let mut store = SlotStore::open(backing.clone(), geometry.clone()).unwrap();
    store.write_slot(0, 1, &[0x51; 32]).unwrap();
    store.mark_allocated(0).unwrap();
    store.sync_shard_data(0).unwrap();
    store.persist_allocations().unwrap();
    (backing, geometry, store, directory)
}

fn reopen_backing(
    backing: Arc<dyn Backing>,
    directory: Option<&tempfile::TempDir>,
) -> Arc<dyn Backing> {
    match directory {
        Some(directory) => {
            drop(backing);
            Arc::new(FileBacking::new(directory.path()).unwrap())
        }
        None => backing,
    }
}

fn assert_original_slot(store: &SlotStore) {
    match store.read_slot(0).unwrap() {
        SlotRead::Ciphertext {
            write_sequence,
            data,
        } => {
            assert_eq!(write_sequence, 1);
            assert_eq!(data, [0x51; 32]);
        }
        SlotRead::Zero => panic!("original committed slot vanished"),
    }
}

fn snapshot(backing: &dyn Backing) -> BTreeMap<String, Vec<u8>> {
    let paths = backing
        .list(layout::DATA_DIR)
        .unwrap()
        .into_iter()
        .map(|name| format!("{}/{name}", layout::DATA_DIR))
        .chain([
            layout::SHARD_CATALOG_A.to_owned(),
            layout::SHARD_CATALOG_B.to_owned(),
        ]);
    paths
        .filter(|path| backing.exists(path).unwrap())
        .map(|path| {
            let file = backing.open(&path, false).unwrap();
            let mut bytes = vec![0; file.len().unwrap() as usize];
            file.read_at(0, &mut bytes).unwrap();
            (path, bytes)
        })
        .collect()
}

fn invalid_unit(write: bool, filesystem: bool) {
    // Six units leaves a partial last shard: checking only the shard index
    // would still accept its unused tail. Eight units crosses the catalog
    // boundary, while u64::MAX exercises a far-out index.
    for units in [6, 8] {
        for invalid_unit in [units, u64::MAX] {
            let (backing, geometry, mut store, directory) = store(filesystem, units);
            let before = snapshot(backing.as_ref());
            let operation = if write {
                store.write_slot(invalid_unit, 2, &[0x52; 32])
            } else {
                store.mark_allocated(invalid_unit)
            };
            assert!(
                matches!(operation, Err(CoreError::Corrupt(_))),
                "unit {invalid_unit} beyond {units} units must be refused: {operation:?}"
            );
            // Also flush any accidental dirty allocation state before
            // comparing the data, maps and both catalog copies byte-for-byte.
            store.persist_allocations().unwrap();
            assert_eq!(snapshot(backing.as_ref()), before);
            assert_eq!(store.allocated_units().collect::<Vec<_>>(), vec![0]);
            assert_original_slot(&store);
            drop(store);
            let reopened =
                SlotStore::open(reopen_backing(backing, directory.as_ref()), geometry).unwrap();
            assert_original_slot(&reopened);
            assert_eq!(reopened.allocated_units().collect::<Vec<_>>(), vec![0]);
        }
    }
}

#[test]
fn out_of_range_slot_write_preserves_reopenable_catalog() {
    invalid_unit(true, false);
}

#[test]
fn out_of_range_allocation_preserves_reopenable_catalog() {
    invalid_unit(false, false);
}

#[test]
fn filesystem_out_of_range_slot_write_preserves_reopenable_catalog() {
    invalid_unit(true, true);
}

#[test]
fn filesystem_out_of_range_allocation_preserves_reopenable_catalog() {
    invalid_unit(false, true);
}

fn last_in_range_unit(filesystem: bool) {
    for units in [6, 8] {
        let (backing, geometry, mut store, directory) = store(filesystem, units);
        let unit = geometry.num_units() - 1;
        let (shard, _) = geometry.shard_of_unit(unit);
        store.write_slot(unit, 2, &[0x52; 32]).unwrap();
        store.mark_allocated(unit).unwrap();
        store.sync_shard_data(shard).unwrap();
        store.persist_allocations().unwrap();
        drop(store);
        let store = SlotStore::open(reopen_backing(backing, directory.as_ref()), geometry).unwrap();
        assert_original_slot(&store);
        match store.read_slot(unit).unwrap() {
            SlotRead::Ciphertext {
                write_sequence,
                data,
            } => {
                assert_eq!(write_sequence, 2);
                assert_eq!(data, [0x52; 32]);
            }
            SlotRead::Zero => panic!("valid last unit vanished"),
        }
    }
}

#[test]
fn last_in_range_unit_still_writes_and_reopens() {
    last_in_range_unit(false);
}

#[test]
fn filesystem_last_in_range_unit_still_writes_and_reopens() {
    last_in_range_unit(true);
}

fn out_of_range_reservation(filesystem: bool) {
    for units in [6, 8] {
        for invalid_unit in [units, u64::MAX] {
            let (backing, geometry, mut store, directory) = store(filesystem, units);
            let before = snapshot(backing.as_ref());
            assert!(matches!(
                store.reserve_slot(invalid_unit),
                Err(CoreError::Corrupt(_))
            ));
            assert_eq!(snapshot(backing.as_ref()), before);
            drop(store);
            assert_original_slot(
                &SlotStore::open(reopen_backing(backing, directory.as_ref()), geometry).unwrap(),
            );
        }
    }
}

#[test]
fn reservation_rejects_out_of_range_units_without_mutation() {
    out_of_range_reservation(false);
}

#[test]
fn filesystem_reservation_rejects_out_of_range_units_without_mutation() {
    out_of_range_reservation(true);
}
