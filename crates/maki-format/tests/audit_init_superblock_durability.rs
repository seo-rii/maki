//! Audit (config-format, init.rs): a creation that fails after superblock A
//! was written but before it was made durable leaves a root that every later
//! command treats as an initialized volume (create refuses it, the loader
//! accepts it, recovery never re-stores the superblock), yet whose only
//! superblock copy exists in the page cache. K-01: everything recovery
//! accepts must be fsync'd before the writer resumes.

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use maki_backing::Backing;
use maki_format::error::FormatError;
use maki_format::geometry::Geometry;
use maki_format::init::create_volume;
use maki_format::layout;
use maki_format::superblock::{load_volume_superblock, Superblock};
use maki_test_support::crash_backing::{CrashableBacking, FaultOp};

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(0xa0d1),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, 1024, 512, 1032, 16 * 1024, 8 * 1024).unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

/// Fail exactly the `sync_data` of `superblock.a` (writeback EIO). The
/// default CrashableBacking model is Linux's: the dirty pages are marked
/// clean and stay readable, but were never persisted.
#[test]
fn a_failed_superblock_sync_leaves_a_volume_that_attach_accepts_and_power_loss_removes() {
    let backing = CrashableBacking::new();
    backing.set_fault_hook(Some(Arc::new(|op: &FaultOp<'_>| match op {
        FaultOp::SyncData { path } if *path == layout::SUPERBLOCK_A => {
            Some(io::Error::other("EIO"))
        }
        _ => None,
    })));
    let created = create_volume(&backing, superblock());
    assert!(created.is_err(), "the failed sync is reported");
    backing.set_fault_hook(None);

    // The operator retries: the root now counts as an existing volume.
    match create_volume(&backing, superblock()) {
        Err(FormatError::AlreadyExists(_)) => {}
        other => panic!("retry: {other:?}"),
    }
    // Attach recovery loads it exactly like this (recovery.rs step 2) and
    // never re-stores it; the first attach's canary publication syncs the
    // root directory (engine.rs persist_key_canary), not the superblock data.
    let loaded = load_volume_superblock(&backing).expect("the page-cache view is a valid volume");
    assert_eq!(loaded.superblock.volume_uuid, superblock().volume_uuid);
    backing.sync_dir("").unwrap();

    backing.crash_all_lost();
    let after = load_volume_superblock(&backing);
    assert!(
        after.is_ok(),
        "a volume that create refused to re-initialize and recovery accepted was lost by a \
         power loss: {:?}",
        after.err()
    );
}

/// The same with a process kill instead of EIO: every operation from the
/// cut onwards fails, then the process restarts (page cache retained).
#[test]
fn a_killed_creation_sweep_never_leaves_a_page_cache_only_volume() {
    let total = {
        let backing = CrashableBacking::new();
        let seen = Arc::new(AtomicUsize::new(0));
        let counter = seen.clone();
        backing.set_fault_hook(Some(Arc::new(move |_op: &FaultOp<'_>| {
            counter.fetch_add(1, Ordering::SeqCst);
            None
        })));
        create_volume(&backing, superblock()).unwrap();
        seen.load(Ordering::SeqCst)
    };
    let mut bad = Vec::new();
    for cut in 0..total {
        let backing = CrashableBacking::new();
        let seen = Arc::new(AtomicUsize::new(0));
        backing.set_fault_hook(Some(Arc::new(move |_op: &FaultOp<'_>| {
            (seen.fetch_add(1, Ordering::SeqCst) >= cut).then(|| io::Error::other("killed"))
        })));
        assert!(create_volume(&backing, superblock()).is_err());
        backing.set_fault_hook(None);
        // Restart: does the root look like a volume to attach?
        if load_volume_superblock(&backing).is_ok() {
            backing.sync_dir("").unwrap();
            backing.crash_all_lost();
            if load_volume_superblock(&backing).is_err() {
                bad.push(cut);
            }
        }
    }
    assert!(
        bad.is_empty(),
        "cuts {bad:?} of {total}: after the restart the root is a valid volume (create refuses \
         it, attach accepts it) whose superblock a later power loss removes"
    );
}
