//! A segment whose creation never completed must not make the volume
//! unattachable because only a torn prefix of its header reached the file.
//!
//! The header write of a new segment can persist a prefix and then fail
//! (the partial-write class the journal already handles for records). The
//! failed creation is cleaned up by unlink + journal directory sync, but that
//! obligation lives only in memory: if the unlink fails, or its directory
//! sync fails before a power loss, recovery finds the file as the final
//! segment. It never held a record and nothing durable names it, so it must
//! read as a creation crash (a file shorter than a header), never as a
//! complete-length header with a bad checksum, which recovery treats as
//! durable damage unless the durable proof and mark rule out a record there
//! (`review_journal_legacy_torn_header.rs`).

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rand::rngs::StdRng;
use rand::SeedableRng;

use maki_backing::Backing;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::journal::SEGMENT_HEADER_SIZE;
use maki_format::{geometry::Geometry, init, layout, superblock::Superblock};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::{failpoints, CrashableBacking};

const CT: usize = 1024;
/// Bytes of the 48-byte header that reach the file before the write fails.
const TORN: usize = 32;
/// Three 1064-byte records fit a segment; the fourth append rolls.
const PER_SEGMENT: u64 = 3;

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: 4096,
    }
}

fn backing(discard: bool) -> Arc<CrashableBacking> {
    let backing = Arc::new(CrashableBacking::new().with_tearing(512));
    let sb = Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(0x2026_1116_0048),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, 512, 512, CT as u32, 512 * 64, 512 * 16).unwrap(),
        format_version: 1,
        created_unix: 0,
    };
    if discard {
        init::create_volume_with_discard(backing.as_ref(), sb).unwrap();
    } else {
        init::create_volume(backing.as_ref(), sb).unwrap();
    }
    backing
}

fn recover(backing: &Arc<CrashableBacking>) -> Result<Volume, String> {
    Volume::recover(backing.clone() as Arc<dyn Backing>, options()).map_err(|e| e.to_string())
}

fn ct(unit: u64) -> Vec<u8> {
    vec![unit as u8 + 1; CT]
}

/// Which step of the failed creation's cleanup fails (once).
#[derive(Clone, Copy, Debug)]
enum Cleanup {
    /// The unlink fails: the torn file stays visible.
    Remove,
    /// The unlink succeeds but its journal directory sync fails: the
    /// removal is volatile and a power loss can undo it.
    DirSync,
}

/// The FUA writes that precede the failed creation: none (the torn header
/// is the volume's first segment) or one full segment (it is a successor).
fn acknowledged(successor: bool) -> u64 {
    if successor {
        PER_SEGMENT
    } else {
        0
    }
}

/// Attach, write `acknowledged(successor)` FUA units, then make the next
/// write's segment roll fail with a torn header and an unfinished cleanup.
/// Returns the volume and the torn segment's path.
fn fail_creation(
    backing: &Arc<CrashableBacking>,
    successor: bool,
    cleanup: Cleanup,
) -> (Volume, String) {
    let mut volume = recover(backing).unwrap();
    for unit in 0..acknowledged(successor) {
        volume.write_ct(unit, &ct(unit), true).unwrap();
    }
    let torn = layout::journal_segment(u64::from(successor));
    let target = torn.clone();
    let tore = Arc::new(AtomicBool::new(false));
    let tear = tore.clone();
    backing.set_partial_write_hook(Some(Arc::new(move |op| {
        let header = matches!(op, FaultOp::WriteAt { path, offset: 0, len }
            if *path == target && *len == SEGMENT_HEADER_SIZE);
        (header && !tear.swap(true, Ordering::SeqCst))
            .then(|| (TORN, io::Error::other("torn segment header write")))
    })));
    let target = torn.clone();
    let failed = Arc::new(AtomicBool::new(false));
    backing.set_fault_hook(Some(Arc::new(move |op| {
        let step = match cleanup {
            Cleanup::Remove => matches!(op, FaultOp::Remove { path } if *path == target),
            Cleanup::DirSync => {
                matches!(op, FaultOp::SyncDir { dir } if *dir == layout::JOURNAL_DIR)
            }
        };
        (step && tore.load(Ordering::SeqCst) && !failed.swap(true, Ordering::SeqCst))
            .then(|| io::Error::other("creation cleanup step failed"))
    })));

    let unit = acknowledged(successor);
    let before = volume.journal_appended_sequence();
    let error = volume
        .write_ct(unit, &ct(unit), true)
        .expect_err("the roll's header write was torn");
    assert!(error.to_string().contains("torn segment header"), "{error}");
    assert_eq!(volume.journal_appended_sequence(), before);
    backing.set_fault_hook(None);
    backing.set_partial_write_hook(None);
    (volume, torn)
}

/// Every acknowledged write is intact, the failed one never surfaces, and
/// the recovered volume keeps working across a later power loss.
fn assert_recovered(backing: &Arc<CrashableBacking>, volume: Volume, successor: bool, torn: &str) {
    for unit in 0..acknowledged(successor) {
        assert_eq!(volume.read_ct(unit).unwrap().unwrap().1, ct(unit));
    }
    let failed = acknowledged(successor);
    assert!(volume.read_ct(failed).unwrap().is_none());
    assert!(
        !backing.exists(torn).unwrap(),
        "recovery discards the unfinished segment"
    );
    let mut volume = volume;
    volume.write_ct(failed, &ct(failed), true).unwrap();
    drop(volume);
    backing.crash_all_lost();
    let volume = recover(backing).expect("the recovered volume stays attachable");
    for unit in 0..=failed {
        assert_eq!(volume.read_ct(unit).unwrap().unwrap().1, ct(unit));
    }
}

#[test]
fn torn_header_of_an_unfinished_segment_does_not_block_a_restart() {
    let _serial = failpoints::test_lock();
    for successor in [false, true] {
        for discard in [false, true] {
            let backing = backing(discard);
            let (volume, torn) = fail_creation(&backing, successor, Cleanup::Remove);
            assert!(backing.exists(&torn).unwrap(), "the failed unlink left it");
            drop(volume); // a process restart: the page cache survives

            let report =
                maki_core::check::deep_check(backing.clone() as Arc<dyn Backing>, 4096).unwrap();
            assert!(
                report.ok(),
                "the deep check must not call an unfinished creation damage: {:?}",
                report.errors
            );
            let volume = recover(&backing).unwrap_or_else(|e| {
                panic!(
                    "successor={successor} discard={discard}: a restart after a failed, never \
                     acknowledged segment creation must attach, got: {e}"
                )
            });
            assert_recovered(&backing, volume, successor, &torn);
        }
    }
}

/// Background writeback may persist the torn prefix and the new directory
/// entry at any time before the failure is even reported; the unlink then
/// fails and power is lost before anything retries it.
#[test]
fn durable_torn_header_of_an_unfinished_segment_does_not_block_power_loss_recovery() {
    let _serial = failpoints::test_lock();
    for successor in [false, true] {
        for discard in [false, true] {
            let backing = backing(discard);
            let (volume, torn) = fail_creation(&backing, successor, Cleanup::Remove);
            backing.open(&torn, false).unwrap().sync_data().unwrap();
            backing.sync_dir(layout::JOURNAL_DIR).unwrap();
            drop(volume);
            backing.crash_all_lost();

            let volume = recover(&backing).unwrap_or_else(|e| {
                panic!(
                    "successor={successor} discard={discard}: a power loss after a failed, never \
                     acknowledged segment creation must attach, got: {e}"
                )
            });
            assert_recovered(&backing, volume, successor, &torn);
        }
    }
}

/// Random power losses (torn writes included) after a failed creation
/// whose cleanup did not finish, for both cleanup steps.
#[test]
fn torn_header_of_an_unfinished_segment_survives_random_power_loss() {
    let _serial = failpoints::test_lock();
    let mut refused = Vec::new();
    for cleanup in [Cleanup::Remove, Cleanup::DirSync] {
        for successor in [false, true] {
            for seed in 0..64u64 {
                let backing = backing(false);
                let (volume, torn) = fail_creation(&backing, successor, cleanup);
                drop(volume);
                backing.crash(&mut StdRng::seed_from_u64(seed));
                match recover(&backing) {
                    Ok(volume) => assert_recovered(&backing, volume, successor, &torn),
                    Err(e) => refused.push(format!(
                        "{cleanup:?} successor={successor} seed {seed}: {e}"
                    )),
                }
            }
        }
    }
    assert!(
        refused.is_empty(),
        "{} power losses after one torn segment header left an unattachable volume:\n{}",
        refused.len(),
        refused.join("\n")
    );
}
