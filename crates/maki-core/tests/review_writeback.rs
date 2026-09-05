//! Regression tests for the 2026-09-05 review's durability findings (see
//! `docs/review-remediation.md`, third review):
//!
//! - F01: a failed `fdatasync` must not be "retried" by calling it again.
//!   Linux marks the dirty pages clean when writeback fails, so the retry
//!   succeeds without writing anything and the journal acknowledges records
//!   the next power loss removes. The writer must rewrite what it could not
//!   sync from its own copy before it syncs again, and recovery must do the
//!   same for page-cache bytes it accepts after a restart.
//! - F03: a partial `write_at` (a prefix persisted, then an error) leaves the
//!   segment file longer than the writer's logical end. A shorter retry
//!   record does not cover the torn bytes, and sealing the segment turns
//!   them into "corruption" for the next recovery. The writer must
//!   normalize the file to its logical end before it appends or seals.
//!
//! `CrashableBacking` models both failure modes (writeback loss is its
//! default for a failed sync; partial writes come from the partial-write
//! hook).

use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use uuid::Uuid;

use maki_backing::Backing;
use maki_core::recovery::RecoveryError;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::geometry::Geometry;
use maki_format::superblock::Superblock;
use maki_format::{init, layout};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::failpoints;
use maki_test_support::CrashableBacking;

const UNIT: u32 = 512;
const CT_LEN: usize = 540;
const SEGMENT: u64 = 4096;
const RECORD: u64 = 32 + CT_LEN as u64;
const RECORDS_PER_SEGMENT: u64 = (SEGMENT - 48) / RECORD; // 7
const DEVICE_UNITS: u64 = 1024;

fn geometry() -> Geometry {
    Geometry::compute(512, UNIT, 512, 544, UNIT as u64 * DEVICE_UNITS, 512 * 64).unwrap()
}

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xF01F03),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: geometry(),
        format_version: 1,
        created_unix: 0,
    }
}

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: SEGMENT,
    }
}

fn new_volume(backing: &Arc<CrashableBacking>) -> Volume {
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    Volume::recover(backing.clone() as Arc<dyn Backing>, options()).unwrap()
}

fn recover(backing: &Arc<CrashableBacking>) -> Result<Volume, RecoveryError> {
    Volume::recover(backing.clone() as Arc<dyn Backing>, options())
}

fn ct(stamp: u8) -> Vec<u8> {
    vec![stamp; CT_LEN]
}

fn eio() -> io::Error {
    io::Error::other("injected writeback error")
}

fn is_segment(path: &str) -> bool {
    path.starts_with(&format!("{}/", layout::JOURNAL_DIR))
        && layout::parse_journal_segment(path.rsplit('/').next().unwrap_or("")).is_some()
}

/// Fail the next `n` `sync_data` calls on journal segments.
fn fail_segment_syncs(backing: &CrashableBacking, n: usize) -> Arc<AtomicUsize> {
    let remaining = Arc::new(AtomicUsize::new(n));
    let counter = remaining.clone();
    backing.set_fault_hook(Some(Arc::new(move |op| match op {
        FaultOp::SyncData { path } if is_segment(path) => {
            let left = counter.load(Ordering::SeqCst);
            if left > 0 {
                counter.store(left - 1, Ordering::SeqCst);
                Some(eio())
            } else {
                None
            }
        }
        _ => None,
    })));
    remaining
}

// ---------- F01: a sync retry is not a rewrite ----------

/// The first FLUSH fails; the second one succeeds. With Linux semantics
/// the second fdatasync has nothing dirty to write, so the acknowledged
/// FLUSH covered bytes that never reached the disk.
#[test]
fn flush_after_a_failed_sync_rewrites_lost_records_before_acknowledging() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    vol.write_ct(0, &ct(1), false).unwrap();
    vol.write_ct(1, &ct(2), false).unwrap();
    fail_segment_syncs(&backing, 1);
    assert!(
        vol.flush().is_err(),
        "the first barrier must report the failure"
    );
    vol.flush().expect("the second barrier rewrites and syncs");
    drop(vol);

    backing.crash_all_lost();
    let vol = recover(&backing).expect("volume refused after an acknowledged FLUSH");
    assert_eq!(vol.read_ct(0).unwrap().map(|(_, d)| d), Some(ct(1)));
    assert_eq!(
        vol.read_ct(1).unwrap().map(|(_, d)| d),
        Some(ct(2)),
        "FLUSH-acknowledged record lost after a failed writeback"
    );
}

/// Same with FUA: the failing write is not acknowledged; the next FUA write
/// is, and it must cover the earlier record too (it was pending as well).
#[test]
fn fua_after_a_failed_sync_covers_every_pending_record() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    // Open the segment first: a sync failure during segment creation is a
    // failed roll, which appends nothing (correct, but not this scenario).
    vol.write_ct(5, &ct(5), false).unwrap();
    fail_segment_syncs(&backing, 1);
    assert!(vol.write_ct(0, &ct(1), true).is_err());
    vol.write_ct(1, &ct(2), true).unwrap();
    drop(vol);

    backing.crash_all_lost();
    let vol = recover(&backing).unwrap();
    assert_eq!(vol.read_ct(5).unwrap().map(|(_, d)| d), Some(ct(5)));
    assert_eq!(vol.read_ct(1).unwrap().map(|(_, d)| d), Some(ct(2)));
    assert_eq!(
        vol.read_ct(0).unwrap().map(|(_, d)| d),
        Some(ct(1)),
        "the record pending at the failed sync was not rewritten"
    );
}

/// A roll seals the active segment with a sync; if that sync failed
/// earlier, the seal's sync must rewrite, or a *non-final* segment ends up
/// with lost bytes and the next power loss refuses the whole volume.
#[test]
fn seal_after_a_failed_sync_rewrites_before_opening_a_successor() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    for i in 1..=RECORDS_PER_SEGMENT as u8 {
        vol.write_ct(i as u64, &ct(i), false).unwrap();
    }
    fail_segment_syncs(&backing, 1);
    assert!(vol.flush().is_err());
    // The next append needs a roll: seal (sync) + successor.
    vol.write_ct(100, &ct(0xAA), false).unwrap();
    vol.flush().unwrap();
    drop(vol);

    backing.crash_all_lost();
    let vol = recover(&backing).expect("non-final segment torn by a lost writeback");
    for i in 1..=RECORDS_PER_SEGMENT as u8 {
        assert_eq!(vol.read_ct(i as u64).unwrap().map(|(_, d)| d), Some(ct(i)));
    }
    assert_eq!(vol.read_ct(100).unwrap().map(|(_, d)| d), Some(ct(0xAA)));
}

/// While the disk keeps failing, no barrier may succeed, and the records
/// stay visible (they are in the journal and the overlay).
#[test]
fn barriers_keep_failing_until_the_rewrite_persists() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    vol.write_ct(0, &ct(1), false).unwrap();
    let remaining = fail_segment_syncs(&backing, 3);
    assert!(vol.flush().is_err());
    assert!(vol.flush().is_err());
    assert!(vol.write_ct(1, &ct(2), true).is_err());
    assert_eq!(remaining.load(Ordering::SeqCst), 0);
    assert_eq!(vol.read_ct(1).unwrap().map(|(_, d)| d), Some(ct(2)));
    vol.flush().unwrap();
    drop(vol);
    backing.crash_all_lost();
    let vol = recover(&backing).unwrap();
    assert_eq!(vol.read_ct(0).unwrap().map(|(_, d)| d), Some(ct(1)));
    assert_eq!(vol.read_ct(1).unwrap().map(|(_, d)| d), Some(ct(2)));
}

/// Process restart after a failed writeback: the page cache still shows
/// the records, recovery accepts them, and its own fdatasync has nothing
/// dirty to write. Recovery must rewrite what it accepts (K-01 was a sync
/// only) before the next FLUSH can acknowledge it.
#[test]
fn recovery_rewrites_page_cache_bytes_it_accepts_after_a_failed_writeback() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    vol.write_ct(0, &ct(1), false).unwrap();
    fail_segment_syncs(&backing, 1);
    assert!(vol.flush().is_err());
    backing.set_fault_hook(None);
    drop(vol); // restart, not a power loss: the page cache survives

    let mut vol = recover(&backing).unwrap();
    assert_eq!(vol.read_ct(0).unwrap().map(|(_, d)| d), Some(ct(1)));
    vol.flush().unwrap();
    drop(vol);

    backing.crash_all_lost();
    let vol = recover(&backing).expect("volume refused after an acknowledged FLUSH");
    assert_eq!(
        vol.read_ct(0).unwrap().map(|(_, d)| d),
        Some(ct(1)),
        "record accepted by recovery and acknowledged by FLUSH was lost"
    );
}

// ---------- F03: a partial append must not leave a tail behind ----------

/// Tear the write of the `RECORDS_PER_SEGMENT`-th record after `keep`
/// bytes; the retry is a *shorter* record, so the torn bytes outlive it.
fn tear_last_record_of_first_segment(backing: &CrashableBacking, keep: usize) -> Arc<AtomicBool> {
    let fired = Arc::new(AtomicBool::new(false));
    let flag = fired.clone();
    let torn_offset = 48 + (RECORDS_PER_SEGMENT - 1) * RECORD;
    backing.set_partial_write_hook(Some(Arc::new(move |op| match op {
        FaultOp::WriteAt { path, offset, .. }
            if is_segment(path) && *offset == torn_offset && !flag.swap(true, Ordering::SeqCst) =>
        {
            Some((keep, eio()))
        }
        _ => None,
    })));
    fired
}

#[test]
fn partial_append_failure_leaves_no_garbage_for_the_next_seal() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    for i in 1..RECORDS_PER_SEGMENT as u8 {
        vol.write_ct(i as u64, &ct(i), false).unwrap();
    }
    let fired = tear_last_record_of_first_segment(&backing, 300);
    assert!(vol.write_ct(50, &ct(0x50), false).is_err());
    assert!(fired.load(Ordering::SeqCst));
    // Shorter retry record: 100 bytes of ciphertext instead of 540.
    vol.write_ct(50, &[0x51u8; 100], false).unwrap();
    // The next record no longer fits: roll, sealing the torn segment.
    vol.write_ct(60, &ct(0x60), false).unwrap();
    vol.flush().unwrap();
    drop(vol);

    backing.crash_all_lost();
    let vol = recover(&backing).expect("sealed segment carried the torn tail as corruption");
    for i in 1..RECORDS_PER_SEGMENT as u8 {
        assert_eq!(vol.read_ct(i as u64).unwrap().map(|(_, d)| d), Some(ct(i)));
    }
    assert_eq!(
        vol.read_ct(50).unwrap().map(|(_, d)| d),
        Some(vec![0x51; 100])
    );
    assert_eq!(vol.read_ct(60).unwrap().map(|(_, d)| d), Some(ct(0x60)));
}

/// A crash right after the partial failure (final segment): the torn
/// record is a torn tail and the earlier records survive.
#[test]
fn crash_right_after_a_partial_append_is_a_torn_tail() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    for i in 1..RECORDS_PER_SEGMENT as u8 {
        vol.write_ct(i as u64, &ct(i), true).unwrap();
    }
    tear_last_record_of_first_segment(&backing, 300);
    assert!(vol.write_ct(50, &ct(0x50), false).is_err());
    drop(vol);
    backing.crash_all_lost();
    let vol = recover(&backing).unwrap();
    for i in 1..RECORDS_PER_SEGMENT as u8 {
        assert_eq!(vol.read_ct(i as u64).unwrap().map(|(_, d)| d), Some(ct(i)));
    }
    assert!(vol.read_ct(50).unwrap().is_none());
}

/// If the tail cannot be normalized (truncate fails too), the writer must
/// not append or seal past the damage; once truncation works again, it
/// resumes.
#[test]
fn appends_are_refused_while_the_torn_tail_cannot_be_normalized() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    for i in 1..RECORDS_PER_SEGMENT as u8 {
        vol.write_ct(i as u64, &ct(i), false).unwrap();
    }
    tear_last_record_of_first_segment(&backing, 300);
    assert!(vol.write_ct(50, &ct(0x50), false).is_err());
    let truncate_fails = Arc::new(AtomicBool::new(true));
    let flag = truncate_fails.clone();
    backing.set_fault_hook(Some(Arc::new(move |op| match op {
        FaultOp::SetLen { path, .. } if is_segment(path) && flag.load(Ordering::SeqCst) => {
            Some(eio())
        }
        _ => None,
    })));
    assert!(
        vol.write_ct(50, &[0x51u8; 100], false).is_err(),
        "append over an un-normalized tail must fail"
    );
    assert!(
        vol.write_ct(60, &ct(0x60), false).is_err(),
        "a roll over an un-normalized tail must fail"
    );
    assert!(
        vol.flush().is_err(),
        "a barrier must not seal past the damage"
    );
    truncate_fails.store(false, Ordering::SeqCst);
    vol.write_ct(50, &[0x51u8; 100], false).unwrap();
    vol.write_ct(60, &ct(0x60), false).unwrap();
    vol.flush().unwrap();
    drop(vol);
    backing.crash_all_lost();
    let vol = recover(&backing).unwrap();
    assert_eq!(
        vol.read_ct(50).unwrap().map(|(_, d)| d),
        Some(vec![0x51; 100])
    );
    assert_eq!(vol.read_ct(60).unwrap().map(|(_, d)| d), Some(ct(0x60)));
}
