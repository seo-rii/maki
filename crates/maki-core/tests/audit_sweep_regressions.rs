//! Audit (durability-sweeps): deterministic minimisations of violations
//! found by the randomized harness in `audit_sweep_engine.rs`.
//!
//! Each test states the property it expects; a failing test is a finding.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rand::rngs::StdRng;
use rand::SeedableRng;
use uuid::Uuid;

use maki_backing::Backing;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::CrashableBacking;

const CT: usize = 520;

fn volume_backing() -> Arc<CrashableBacking> {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: Uuid::from_u128(0xA0D1_5EED),
            provider_type: "fake".into(),
            crypto_compatibility_id: "audit-sweep".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, 512, 512, CT as u32, 16 * 512, 8 * 512).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    backing
}

/// Every append rolls: the effective segment size (112 bytes) holds one
/// record, so the second append creates a new segment.
fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: 0,
    }
}

fn is_segment_header_write(op: &FaultOp<'_>) -> bool {
    matches!(op, FaultOp::WriteAt { path, offset: 0, len: 48 } if path.starts_with("journal/seg-"))
}

/// The next segment-header write persists only a 32-byte prefix and fails
/// (the partial-write fault class the journal already handles for records,
/// F03). `fail_remove` chooses what else fails once: the cleanup's unlink
/// (`true`), or its journal directory sync (`false`).
fn arm_torn_header(backing: &CrashableBacking, fail_remove: bool) {
    let torn = Arc::new(AtomicBool::new(false));
    let tear = torn.clone();
    backing.set_partial_write_hook(Some(Arc::new(move |op| {
        (is_segment_header_write(op) && !tear.swap(true, Ordering::SeqCst))
            .then(|| (32, io::Error::other("audit: short header write")))
    })));
    let failed = Arc::new(AtomicBool::new(false));
    backing.set_fault_hook(Some(Arc::new(move |op| {
        let target = if fail_remove {
            matches!(op, FaultOp::Remove { path } if path.starts_with("journal/seg-"))
        } else {
            matches!(op, FaultOp::SyncDir { dir } if *dir == "journal")
        };
        (target && torn.load(Ordering::SeqCst) && !failed.swap(true, Ordering::SeqCst))
            .then(|| io::Error::other("audit: cleanup step failed"))
    })));
}

/// Found by `audit_chaos_death_v3` (cfg odd-v3, seed 1164) and
/// `audit_chaos_death_v2` (cfg seg1, seed 1203).
///
/// A roll's header write persists a prefix and fails; the failed-creation
/// cleanup (unlink + journal-dir sync) does not complete before the process
/// stops. The file was extended to the full header length by
/// `allocate_range` *before* the header write, so after a plain restart the
/// final segment is "complete-length with an invalid header", which
/// recovery classifies as durable damage and refuses the volume — although
/// the segment never finished creation and holds no record at all.
#[test]
fn torn_header_of_a_never_created_segment_does_not_block_restart() {
    let backing = volume_backing();
    let mut volume = Volume::recover(backing.clone() as Arc<dyn Backing>, options()).unwrap();
    volume.write_ct(0, &[0x41; CT], true).unwrap();

    arm_torn_header(&backing, true);
    let err = volume
        .write_ct(1, &[0x42; CT], true)
        .expect_err("the roll's header write was torn");
    assert!(err.to_string().contains("short header write"), "{err}");
    backing.set_fault_hook(None);
    backing.set_partial_write_hook(None);
    drop(volume); // process restart: the page cache survives

    let recovered = Volume::recover(backing.clone() as Arc<dyn Backing>, options());
    let recovered = match recovered {
        Ok(volume) => volume,
        Err(e) => panic!(
            "a plain restart after a failed (never acknowledged) segment creation must \
             attach, got: {e}"
        ),
    };
    assert_eq!(recovered.read_ct(0).unwrap().unwrap().1, vec![0x41; CT]);
}

/// Same defect after a power loss, with the cleanup's unlink succeeding but
/// its directory sync failing once (no failed unlink needed). In the crash
/// states where the never-synced creation survives but the unlink does not,
/// and the preallocated length and the torn prefix both reach the disk, the
/// volume can no longer be attached.
#[test]
fn torn_header_of_a_never_created_segment_does_not_block_power_loss_recovery() {
    let mut refused = Vec::new();
    for seed in 0..64u64 {
        let backing = volume_backing();
        let mut volume =
            Volume::recover(backing.clone() as Arc<dyn Backing>, options()).unwrap();
        volume.write_ct(0, &[0x41; CT], true).unwrap();
        arm_torn_header(&backing, false);
        assert!(volume.write_ct(1, &[0x42; CT], true).is_err());
        backing.set_fault_hook(None);
        backing.set_partial_write_hook(None);
        drop(volume);
        backing.crash(&mut StdRng::seed_from_u64(seed));
        match Volume::recover(backing.clone() as Arc<dyn Backing>, options()) {
            Ok(volume) => {
                assert_eq!(volume.read_ct(0).unwrap().unwrap().1, vec![0x41; CT]);
            }
            Err(e) => refused.push(format!("seed {seed}: {e}")),
        }
    }
    assert!(
        refused.is_empty(),
        "{} of 64 power losses after one torn segment header left an unattachable volume:\n{}",
        refused.len(),
        refused.join("\n")
    );
}
