//! Audit: places where `CrashableBacking` is *more lenient* than a real
//! Linux filesystem, so a durability bug could pass the crash tests.
//!
//! Each test asserts a state that real Linux can (or must) produce. A failing
//! test means the model cannot produce it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use maki_backing::Backing;
use maki_test_support::crash_backing::{CrashableBacking, FaultOp};
use rand::rngs::StdRng;
use rand::SeedableRng;

const PAGE: usize = 4096;

fn fail_next_sync(backing: &CrashableBacking) {
    let armed = Arc::new(AtomicBool::new(true));
    backing.set_fault_hook(Some(Arc::new(move |op| match op {
        FaultOp::SyncData { .. } if armed.swap(false, Ordering::SeqCst) => {
            Some(std::io::Error::other("injected writeback EIO"))
        }
        _ => None,
    })));
}

fn read_all(backing: &CrashableBacking, path: &str) -> Vec<u8> {
    let file = backing.open(path, false).unwrap();
    let mut bytes = vec![0; file.len().unwrap() as usize];
    file.read_at(0, &mut bytes).unwrap();
    bytes
}

/// Linux: dirty pages are written back by the flusher at any time (and by
/// the failing `fsync` itself, page by page). An `fsync` that returns EIO
/// only says that *some* writeback failed; pages whose writeback succeeded
/// are on disk. So after a failed sync and a power loss, page 0 can hold the
/// new bytes while page 1 (the page whose write failed) holds the old ones.
///
/// The model clears every pending write on a failed sync without persisting
/// any of them, and a later crash can then never surface them: a failed sync
/// turns "unknown" into "certainly lost".
#[test]
fn bytes_of_a_failed_sync_may_still_be_on_disk_after_a_power_loss() {
    let mut page0_survived = 0;
    for seed in 0..256 {
        let backing = CrashableBacking::new();
        let file = backing.open("f", true).unwrap();
        file.write_at(0, &[0u8; 2 * PAGE]).unwrap();
        file.sync_data().unwrap();
        backing.sync_dir("").unwrap();

        file.write_at(0, &[1u8; PAGE]).unwrap();
        file.write_at(PAGE as u64, &[2u8; PAGE]).unwrap();
        fail_next_sync(&backing);
        assert!(file.sync_data().is_err());
        backing.set_fault_hook(None);
        drop(file);

        backing.crash(&mut StdRng::seed_from_u64(seed));
        let bytes = read_all(&backing, "f");
        if bytes[..PAGE].iter().all(|b| *b == 1) {
            page0_survived += 1;
        }
    }
    assert!(
        page0_survived > 0,
        "in 256 crashes after a failed fsync the model never kept a page that \
         Linux writeback may already have persisted"
    );
}

/// Linux writes back whole pages. After a failed writeback the page stays
/// cached (clean) with the unpersisted bytes; a later write elsewhere in the
/// same page re-dirties the page, and the next successful `fsync` writes the
/// *entire* cached page, including the bytes of the failed sync.
///
/// The model persists only the byte ranges of later writes, so after a
/// successful sync the durable page differs from the page the kernel wrote.
#[test]
fn a_successful_sync_writes_the_whole_cached_page() {
    let backing = CrashableBacking::new();
    let file = backing.open("f", true).unwrap();
    file.write_at(0, &[0u8; PAGE]).unwrap();
    file.sync_data().unwrap();
    backing.sync_dir("").unwrap();

    file.write_at(0, b"AAAA").unwrap();
    fail_next_sync(&backing);
    assert!(file.sync_data().is_err());
    backing.set_fault_hook(None);

    // Same page, different bytes.
    file.write_at(8, b"CCCC").unwrap();
    file.sync_data().unwrap();
    drop(file);

    backing.crash_all_lost();
    let bytes = read_all(&backing, "f");
    assert_eq!(
        &bytes[..12],
        b"AAAA\0\0\0\0CCCC",
        "the model persisted only the later write's bytes of a page the \
         kernel writes back as a whole"
    );
}

/// A power loss kills every process: no descriptor opened before it can be
/// used afterwards. The model keeps pre-crash handles live, and they write
/// into (and sync) the post-crash state, so a test that crashes while a
/// background task still holds a handle observes a state no power loss can
/// produce.
#[test]
fn a_handle_from_before_the_power_loss_is_dead_afterwards() {
    let backing = CrashableBacking::new();
    let file = backing.open("f", true).unwrap();
    file.write_at(0, b"old").unwrap();
    file.sync_data().unwrap();
    backing.sync_dir("").unwrap();

    backing.crash_all_lost();

    let late_write = file.write_at(0, b"new").and_then(|()| file.sync_data());
    assert!(
        late_write.is_err(),
        "a handle opened before the crash still wrote and synced: post-crash \
         state now shows {:?}",
        String::from_utf8_lossy(&read_all(&backing, "f"))
    );
}
