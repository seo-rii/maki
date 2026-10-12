//! BUG-039: initializers must acquire the attach lock and release it on
//! every error, while retaining the lock-file durability operations.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use maki_backing::{Backing, MemBacking};
use maki_format::durable_proof::DurableProofStore;
use maki_format::error::FormatError;
use maki_format::geometry::Geometry;
use maki_format::superblock::Superblock;
use maki_format::{init, layout};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::CrashableBacking;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(0xB039),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "fixture".into(),
        geometry: Geometry::compute(512, 512, 512, 544, 512 * 64, 512 * 16).unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn create(backing: &dyn Backing, discard: bool) -> Result<Superblock, FormatError> {
    if discard {
        init::create_volume_with_discard(backing, superblock())
    } else {
        init::create_volume(backing, superblock())
    }
}

#[test]
fn held_volume_lock_refuses_initialization_without_publishing_metadata() {
    for discard in [false, true] {
        let backing = MemBacking::new();
        let lock = backing.try_lock(layout::VOLUME_LOCK).unwrap();
        assert!(
            matches!(create(&backing, discard), Err(FormatError::Io(error))
            if error.kind() == io::ErrorKind::WouldBlock)
        );
        assert!(!backing.exists(layout::SUPERBLOCK_A).unwrap());
        assert!(!backing.exists(layout::SUPERBLOCK_B).unwrap());
        drop(lock);
        create(&backing, discard).unwrap();
    }
}

#[test]
fn initializer_releases_lock_on_lockfile_metadata_and_final_sync_errors() {
    for discard in [false, true] {
        for stage in 0..3 {
            let backing = CrashableBacking::new().with_tearing(512);
            let mark_created = Arc::new(AtomicBool::new(false));
            let mark_seen = mark_created.clone();
            let triggered = Arc::new(AtomicBool::new(false));
            let triggered_in_hook = triggered.clone();
            backing.set_fault_hook(Some(Arc::new(move |op| {
                if matches!(op, FaultOp::Open { path, create: true }
                    if *path == layout::JOURNAL_DURABLE_MARK)
                {
                    mark_seen.store(true, Ordering::SeqCst);
                }
                let fail = match stage {
                    0 => matches!(op, FaultOp::SyncData { path }
                        if *path == layout::VOLUME_LOCK),
                    1 => matches!(op, FaultOp::WriteAt { path, .. }
                        if *path == "checkpoint/state.a"),
                    2 => matches!(op, FaultOp::SyncDir { dir }
                        if dir.is_empty() && mark_seen.load(Ordering::SeqCst)),
                    _ => unreachable!(),
                };
                if fail && !triggered_in_hook.swap(true, Ordering::SeqCst) {
                    Some(io::Error::other("injected initialization failure"))
                } else {
                    None
                }
            })));
            assert!(create(&backing, discard).is_err(), "stage {stage}");
            assert!(triggered.load(Ordering::SeqCst), "stage {stage}");
            backing.set_fault_hook(None);
            let lock = backing
                .try_lock(layout::VOLUME_LOCK)
                .expect("failed initializer must release its volume lock");
            drop(lock);
        }
    }
}

#[test]
fn initialized_lockfile_and_identity_survive_immediate_power_loss() {
    for discard in [false, true] {
        let backing = CrashableBacking::new().with_tearing(512);
        let initialized = create(&backing, discard).unwrap();
        backing.crash_all_lost();
        assert!(backing.exists(layout::VOLUME_LOCK).unwrap());
        assert_eq!(
            init::load_superblock(&backing).unwrap().volume_uuid,
            initialized.volume_uuid
        );
        assert_eq!(
            DurableProofStore::load(&backing, initialized.volume_uuid)
                .unwrap()
                .durable_sequence,
            0
        );
        let lock = backing.try_lock(layout::VOLUME_LOCK).unwrap();
        drop(lock);
        assert!(matches!(
            create(&backing, discard),
            Err(FormatError::AlreadyExists(_))
        ));
        backing
            .try_lock(layout::VOLUME_LOCK)
            .expect("refused duplicate initializer must release its lock");
    }
}
