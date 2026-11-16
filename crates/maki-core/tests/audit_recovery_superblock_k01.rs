//! Audit (recovery-codecs): recovery accepts a superblock that exists only
//! in the page cache (K-01) and never makes it durable before the writer
//! resumes. Volume creation publishes the superblock last; if that
//! publication's fdatasync fails, `create_volume` returns an error but the
//! copy stays readable until the next power loss. Every later attach in the
//! same boot recovers from it, acknowledges FUA/FLUSH writes, and a power
//! loss then removes the only superblock: the acknowledged data is
//! unreachable (the root is no longer a volume).

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use maki_backing::Backing;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::{failpoints, CrashableBacking};
use uuid::Uuid;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0x5B_C001),
        provider_type: "fake".into(),
        crypto_compatibility_id: "audit-profile".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, 512, 512, 544, 512 * 64, 512 * 16).unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: 64 * 1024,
    }
}

fn run(fail: &'static (dyn Fn(&FaultOp<'_>) -> bool + Sync)) {
    let backing = Arc::new(CrashableBacking::new());
    let armed = Arc::new(AtomicBool::new(true));
    let flag = armed.clone();
    backing.set_fault_hook(Some(Arc::new(move |op| {
        if fail(op) && flag.swap(false, Ordering::SeqCst) {
            Some(io::Error::other("injected superblock publication failure"))
        } else {
            None
        }
    })));
    let created = init::create_volume(backing.as_ref(), superblock());
    backing.set_fault_hook(None);
    assert!(!armed.load(Ordering::SeqCst), "the fault must have fired");
    assert!(created.is_err(), "creation reports the failed publication");

    // Same boot: the page cache still shows a valid superblock, so a retry
    // of `volume create` says "already present" and attach works.
    assert!(init::create_volume(backing.as_ref(), superblock()).is_err());
    let mut volume = Volume::recover(backing.clone() as Arc<dyn Backing>, options())
        .expect("recovery accepts the cached superblock");
    volume.write_ct(3, &[0x5A; 544], true).expect("FUA write acknowledged");
    volume.flush().expect("FLUSH acknowledged");
    drop(volume);

    // Power loss.
    backing.crash_all_lost();
    let recovered = Volume::recover(backing.clone() as Arc<dyn Backing>, options());
    match recovered {
        Ok(volume) => assert_eq!(
            volume.read_ct(3).unwrap().map(|(_, ct)| ct),
            Some(vec![0x5A; 544]),
            "acknowledged FUA write lost"
        ),
        Err(e) => panic!(
            "FUA-acknowledged data is unreachable after power loss: recovery had accepted a \
             page-cache-only superblock without making it durable; now: {e}"
        ),
    }
}

#[test]
fn first_superblock_copy_sync_failure_then_attach_then_power_loss() {
    let _guard = failpoints::test_lock();
    run(&|op| matches!(op, FaultOp::SyncData { path } if *path == "superblock.a"));
}

/// Control: when only the dirent is volatile (the data sync succeeded), the
/// first write's shard creation happens to sync the root directory and
/// rescues the copy, so this variant passes today.
#[test]
fn superblock_preserve_dirsync_failure_then_attach_then_power_loss() {
    let _guard = failpoints::test_lock();
    // The second store's preserve step is the first root sync after
    // superblock.a was created: failing it leaves that dirent volatile.
    static SEEN_A: AtomicBool = AtomicBool::new(false);
    SEEN_A.store(false, Ordering::SeqCst);
    run(&|op| {
        if matches!(op, FaultOp::SyncData { path } if *path == "superblock.a") {
            SEEN_A.store(true, Ordering::SeqCst);
        }
        matches!(op, FaultOp::SyncDir { dir } if dir.is_empty()) && SEEN_A.load(Ordering::SeqCst)
    });
}
