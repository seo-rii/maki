//! BUG-066: preserving a readable A/B copy must persist its exact length.

use std::{io, sync::Arc};

use maki_backing::Backing;
use maki_format::{ab::AbStore, catalog::ShardCatalog};
use maki_test_support::{crash_backing::FaultOp, CrashableBacking};

fn catalog(count: u64) -> ShardCatalog {
    let mut catalog = ShardCatalog::new();
    for shard in 0..count {
        catalog.insert(shard);
    }
    catalog
}

fn failed_copy(new_count: u64) -> (CrashableBacking, ShardCatalog) {
    let backing = CrashableBacking::new().with_tearing(512);
    let ab = AbStore::new("catalog.a", "catalog.b");
    let mut original = catalog(2);
    ab.store(&backing, &mut original).unwrap();
    ab.store(&backing, &mut original).unwrap();
    backing.sync_dir("").unwrap();
    backing.set_fault_hook(Some(Arc::new(|op| match op {
        FaultOp::SyncData { path: "catalog.a" } => Some(io::Error::other("catalog sync failed")),
        _ => None,
    })));
    let mut changed = catalog(new_count);
    assert!(ab.store(&backing, &mut changed).is_err());
    backing.set_fault_hook(None);
    assert_eq!(
        ab.side_generations::<ShardCatalog>(&backing).unwrap(),
        (Some(3), Some(2))
    );
    (backing, changed)
}

fn retry_after_failed_sync(new_count: u64, restart: bool) {
    let (backing, mut changed) = failed_copy(new_count);
    let ab = AbStore::new("catalog.a", "catalog.b");
    if restart {
        changed = ab.load::<ShardCatalog>(&backing).unwrap().unwrap();
    }
    backing.set_partial_write_hook(Some(Arc::new(|op| match op {
        FaultOp::WriteAt {
            path: "catalog.b", ..
        } => Some((20, io::Error::other("other copy write failed"))),
        _ => None,
    })));
    assert!(ab.store(&backing, &mut changed).is_err());
    backing.set_partial_write_hook(None);
    backing.crash_keep_torn_prefix("catalog.b", 20);
    let preserved = ab
        .load::<ShardCatalog>(&backing)
        .unwrap()
        .expect("retry must preserve a valid copy before overwriting the other one");
    assert_eq!(preserved.len(), new_count as usize);
    assert_eq!(
        backing.open("catalog.a", false).unwrap().len().unwrap(),
        preserved.encode().len() as u64
    );
}

#[test]
fn shrinking_catalog_survives_failed_retry() {
    retry_after_failed_sync(1, false);
}

#[test]
fn empty_catalog_survives_failed_retry() {
    retry_after_failed_sync(0, false);
}

#[test]
fn shrinking_catalog_survives_failed_retry_after_process_restart() {
    retry_after_failed_sync(1, true);
}

#[test]
fn same_length_catalog_control() {
    retry_after_failed_sync(2, false);
}

#[test]
fn growing_catalog_control() {
    retry_after_failed_sync(3, false);
}

#[test]
fn failed_preserved_length_change_does_not_touch_other_copy() {
    let (backing, mut changed) = failed_copy(1);
    let file = backing.open("catalog.b", false).unwrap();
    let mut before = vec![0; file.len().unwrap() as usize];
    file.read_at(0, &mut before).unwrap();
    backing.set_fault_hook(Some(Arc::new(|op| match op {
        FaultOp::SetLen {
            path: "catalog.a", ..
        } => Some(io::Error::other("preserved length failed")),
        _ => None,
    })));
    assert!(AbStore::new("catalog.a", "catalog.b")
        .store(&backing, &mut changed)
        .is_err());
    let mut after = vec![0; file.len().unwrap() as usize];
    file.read_at(0, &mut after).unwrap();
    assert_eq!(before, after);
    backing.set_fault_hook(None);
    backing.crash_all_lost();
    assert_eq!(
        AbStore::new("catalog.a", "catalog.b")
            .load::<ShardCatalog>(&backing)
            .unwrap()
            .unwrap()
            .len(),
        2
    );
}
