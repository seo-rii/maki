//! Regression tests for the storage-consistency defects raised by the
//! 2026-09-02 independent review (M-002, M-003, M-007, M-009).
//!
//! Every test here reproduced acknowledged-data loss or silent replay
//! truncation before its fix landed. They drive the ciphertext-level volume
//! core over `CrashableBacking` exactly like the journal/recovery suite.

use std::io;
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
const SEGMENT_SIZE: u64 = 4096;
/// Records are 32 + CT_LEN bytes; the active segment holds this many before
/// the next append rolls.
const RECORDS_PER_SEGMENT: usize = (SEGMENT_SIZE as usize - 48) / (32 + CT_LEN);

fn geometry() -> Geometry {
    Geometry::compute(512, UNIT, 512, 544, 512 * 1024, 512 * 64).unwrap()
}

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xC0FFEE),
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
        journal_segment_size: SEGMENT_SIZE,
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

fn expect_corrupt(result: Result<Volume, RecoveryError>) -> String {
    match result.map(|_| ()) {
        Err(RecoveryError::Corrupt(msg)) => msg,
        other => panic!("expected Corrupt, got {other:?}"),
    }
}

// ---------- M-002: automatic roll vs. overlay promotion ----------

/// An automatic segment roll makes the sealed segment durable *inside*
/// `append`. The overwrite that triggered the roll must not evict the now-
/// durable previous version of the same unit from the checkpointable set:
/// a checkpoint at that boundary deletes the sealed segment, so a lost
/// promotion loses acknowledged-durable data on the next crash.
#[test]
fn auto_roll_preserves_previous_durable_overwrite() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);

    let mut last = 0;
    for i in 1..=RECORDS_PER_SEGMENT as u8 {
        last = vol.write_ct(0, &ct(i), false).unwrap();
    }
    assert!(vol.journal_durable_sequence() < last, "nothing flushed yet");

    // The next overwrite rolls: the sealed segment is fdatasync'd (making
    // `last` durable) while the new record stays volatile.
    let newest = vol.write_ct(0, &ct(0xEE), false).unwrap();
    assert_eq!(
        vol.journal_durable_sequence(),
        last,
        "roll made the sealed segment durable"
    );
    assert!(newest > last);

    // Checkpoint without an explicit flush: consumes exactly the durable
    // boundary and retires the sealed segment.
    let ck = vol.checkpoint().unwrap();
    assert_eq!(ck, last);
    drop(vol);

    // The volatile overwrite is lost; the durable one must survive.
    backing.crash_all_lost();
    let vol = recover(&backing).unwrap();
    assert_eq!(
        vol.read_ct(0).unwrap().map(|(_, d)| d),
        Some(ct(RECORDS_PER_SEGMENT as u8)),
        "durable overwrite lost across auto-roll + checkpoint"
    );
}

/// The same hazard when the append that rolled the segment then *fails*:
/// the durable boundary advanced, but no version was published. The next
/// checkpoint must still see the promoted version.
#[test]
fn failed_append_after_roll_still_promotes_durable_versions() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    for i in 1..=RECORDS_PER_SEGMENT as u8 {
        vol.write_ct(0, &ct(i), false).unwrap();
    }
    let fp = failpoints::fail_n_times(
        "journal.append.write",
        1,
        io::ErrorKind::StorageFull,
        "ENOSPC",
    );
    assert!(vol.write_ct(0, &ct(0xEE), false).is_err());
    drop(fp);
    let durable = vol.journal_durable_sequence();
    assert_eq!(
        durable, RECORDS_PER_SEGMENT as u64,
        "roll synced the segment"
    );

    let ck = vol.checkpoint().unwrap();
    assert_eq!(ck, durable);
    drop(vol);
    backing.crash_all_lost();
    let vol = recover(&backing).unwrap();
    assert_eq!(
        vol.read_ct(0).unwrap().map(|(_, d)| d),
        Some(ct(RECORDS_PER_SEGMENT as u8))
    );
}

/// A roll whose fdatasync fails must leave the active segment in place so a
/// later barrier still syncs it — never claim its records durable.
#[test]
fn failed_seal_sync_does_not_lose_active_segment_durability() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    for i in 1..=RECORDS_PER_SEGMENT as u8 {
        vol.write_ct(0, &ct(i), false).unwrap();
    }
    let fp = failpoints::fail_n_times("journal.sync", 1, io::ErrorKind::Other, "injected");
    assert!(vol.write_ct(1, &ct(0x77), false).is_err(), "roll must fail");
    drop(fp);

    // A FLUSH after the fault clears must make everything durable for real.
    vol.flush().unwrap();
    drop(vol);
    backing.crash_all_lost();
    let vol = recover(&backing).unwrap();
    assert_eq!(
        vol.read_ct(0).unwrap().unwrap().1,
        ct(RECORDS_PER_SEGMENT as u8),
        "FLUSH-acknowledged data lost"
    );
}

// ---------- M-003: allocation dirty state vs. directory fsync ----------

/// The allocation-map A/B write can succeed while the data-directory fsync
/// fails. The retry must repeat the metadata step: clearing the dirty flag
/// early lets the retry skip it, after which a crash can drop the fresh
/// (never dir-synced) copy and reclassify the slot as unwritten zeros.
#[test]
fn checkpoint_retry_keeps_allocation_dirent_durable() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    vol.write_ct(0, &ct(0x5A), true).unwrap();

    let fp = failpoints::set(
        "checkpoint.alloc_dirsync",
        failpoints::FailpointAction::IoError(io::ErrorKind::Other, "injected".to_string()),
    );
    assert!(vol.checkpoint().is_err());
    drop(fp);

    let ck = vol.checkpoint().unwrap();
    assert!(ck >= 1, "retry must complete");
    drop(vol);

    // Any dirent that was never fsync'd vanishes.
    backing.crash_all_lost();
    let vol = recover(&backing).unwrap();
    assert_eq!(
        vol.read_ct(0).unwrap().map(|(_, d)| d),
        Some(ct(0x5A)),
        "checkpointed data reclassified as unwritten after retry + crash"
    );
}

// ---------- M-007: recovery fails closed ----------

/// A surviving journal must connect to the checkpoint boundary: if the first
/// uncheckpointed segment is gone, later segments are still internally
/// contiguous, but replaying them silently drops acknowledged writes.
#[test]
fn recovery_rejects_missing_first_uncheckpointed_segment() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    for i in 0..(3 * RECORDS_PER_SEGMENT) as u8 {
        vol.write_ct(i as u64 % 4, &ct(i), false).unwrap();
    }
    vol.flush().unwrap();
    assert!(vol.journal_segment_count() >= 3);
    drop(vol);

    backing.remove(&layout::journal_segment(0)).unwrap();
    backing.sync_dir(layout::JOURNAL_DIR).unwrap();
    let msg = expect_corrupt(recover(&backing));
    assert!(msg.contains("checkpoint"), "{msg}");
}

/// Same gap after a checkpoint advanced the boundary: the first segment
/// *after* the checkpoint disappears while newer ones remain.
#[test]
fn recovery_rejects_gap_after_checkpoint_boundary() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    for i in 0..RECORDS_PER_SEGMENT as u8 {
        vol.write_ct(0, &ct(i), false).unwrap();
    }
    vol.flush().unwrap();
    vol.checkpoint().unwrap();
    // Two more segments of uncheckpointed writes; the first of them is the
    // segment created by the roll that follows the checkpoint.
    for i in 0..(2 * RECORDS_PER_SEGMENT) as u8 {
        vol.write_ct(1, &ct(i), false).unwrap();
    }
    vol.flush().unwrap();
    let victim = vol.journal_first_uncheckpointed_segment_path().unwrap();
    drop(vol);

    backing.remove(&victim).unwrap();
    backing.sync_dir(layout::JOURNAL_DIR).unwrap();
    expect_corrupt(recover(&backing));
}

/// Resurrected, fully-covered segments (deletion lost in a crash) are still
/// fine: they sit *before* the boundary and bridge to the survivors.
#[test]
fn recovery_accepts_resurrected_covered_segments() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    for i in 0..(2 * RECORDS_PER_SEGMENT) as u8 {
        vol.write_ct(i as u64 % 3, &ct(i), false).unwrap();
    }
    vol.flush().unwrap();
    // The checkpoint's segment deletion is volatile until the journal
    // directory fsync; fail that so the deletions can resurrect.
    let fp = failpoints::set(
        "checkpoint.dirsync",
        failpoints::FailpointAction::IoError(io::ErrorKind::Other, "injected".to_string()),
    );
    assert!(vol.checkpoint().is_err());
    drop(fp);
    vol.write_ct(0, &ct(0xAA), true).unwrap();
    drop(vol);

    backing.crash_all_lost(); // unsynced deletions resurrect
    let vol = recover(&backing).unwrap();
    assert_eq!(vol.read_ct(0).unwrap().unwrap().1, ct(0xAA));
}

/// A final segment with a complete but invalid header is durable damage,
/// not a creation crash: it must not be silently deleted.
#[test]
fn recovery_rejects_full_final_segment_bad_header() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    vol.write_ct(0, &ct(1), true).unwrap();
    let seg = vol.journal_active_segment_path().unwrap();
    drop(vol);

    let f = backing.open(&seg, false).unwrap();
    f.write_at(0, b"XXXXXXXX").unwrap();
    f.sync_data().unwrap();
    expect_corrupt(recover(&backing));
    assert!(
        backing.exists(&seg).unwrap(),
        "damaged segment must be kept"
    );
}

/// A creation crash can leave a short or zero-filled final segment (the
/// header write never reached the platter); that is discarded as before.
#[test]
fn recovery_discards_unwritten_final_segment() {
    let _guard = failpoints::test_lock();
    for len in [0u64, 20, 48, 4096] {
        let backing = Arc::new(CrashableBacking::new());
        let mut vol = new_volume(&backing);
        vol.write_ct(0, &ct(1), true).unwrap();
        drop(vol);
        let seg = layout::journal_segment(1);
        let f = backing.open(&seg, true).unwrap();
        f.set_len(len).unwrap();
        f.sync_data().unwrap();
        backing.sync_dir(layout::JOURNAL_DIR).unwrap();

        let vol = recover(&backing).unwrap_or_else(|e| panic!("len {len}: {e:?}"));
        assert_eq!(vol.read_ct(0).unwrap().unwrap().1, ct(1));
        assert!(!backing.exists(&seg).unwrap(), "len {len}: discarded");
    }
}

/// A corrupt record *header* in the middle of the final segment, followed
/// by valid records, is durable damage: treating it as a torn tail would
/// silently truncate acknowledged records after it.
#[test]
fn recovery_rejects_corrupt_middle_record_header_in_final_segment() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    for i in 0..3u8 {
        vol.write_ct(i as u64, &ct(i + 1), false).unwrap();
    }
    vol.flush().unwrap();
    let seg = vol.journal_active_segment_path().unwrap();
    drop(vol);

    let f = backing.open(&seg, false).unwrap();
    let off = 48 + (32 + CT_LEN) as u64; // record 1's header
    f.write_at(off, b"JUNK").unwrap();
    f.sync_data().unwrap();
    expect_corrupt(recover(&backing));
}

/// A genuinely torn final record header (nothing valid after it) is still a
/// torn tail: recovery truncates and continues.
#[test]
fn recovery_truncates_torn_final_record_header() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    vol.write_ct(0, &ct(1), false).unwrap();
    vol.flush().unwrap();
    vol.write_ct(1, &ct(2), false).unwrap();
    let seg = vol.journal_active_segment_path().unwrap();
    drop(vol);

    // Keep only 10 bytes of record 2's 32-byte header.
    backing.crash_keep_torn_prefix(&seg, 10);
    let vol = recover(&backing).unwrap();
    assert_eq!(vol.read_ct(0).unwrap().unwrap().1, ct(1));
    assert!(vol.read_ct(1).unwrap().is_none());
}

/// A journal segment far larger than the writer can ever produce is
/// rejected up front rather than read into memory.
#[test]
fn recovery_rejects_oversized_segment_before_allocation() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    vol.write_ct(0, &ct(1), true).unwrap();
    let seg = vol.journal_active_segment_path().unwrap();
    drop(vol);

    let f = backing.open(&seg, false).unwrap();
    f.set_len(maki_format::journal::max_segment_file_size(SEGMENT_SIZE) + 1)
        .unwrap();
    f.sync_data().unwrap();
    let msg = expect_corrupt(recover(&backing));
    assert!(msg.contains("exceeds"), "{msg}");
}

// ---------- M-009: metadata read errors are not "invalid copy" ----------

/// Checkpoint state is required on an initialized volume: losing both
/// copies must refuse attach, never silently restart at sequence 0.
#[test]
fn recovery_requires_valid_checkpoint_state() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    vol.write_ct(0, &ct(1), true).unwrap();
    vol.checkpoint().unwrap();
    drop(vol);

    for path in [
        maki_format::checkpoint::CHECKPOINT_STATE_A,
        maki_format::checkpoint::CHECKPOINT_STATE_B,
    ] {
        if backing.exists(path).unwrap() {
            backing.remove(path).unwrap();
        }
    }
    backing.sync_dir(layout::CHECKPOINT_DIR).unwrap();
    let msg = expect_corrupt(recover(&backing));
    assert!(msg.contains("checkpoint state"), "{msg}");
}

/// A hard I/O error reading one A/B side is surfaced, not treated as a
/// torn copy that the other side silently masks.
#[test]
fn recovery_surfaces_hard_io_error_on_checkpoint_state() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    vol.write_ct(0, &ct(1), true).unwrap();
    vol.checkpoint().unwrap();
    drop(vol);

    backing.set_fault_hook(Some(Arc::new(|op| match op {
        FaultOp::Open { path, .. } if *path == maki_format::checkpoint::CHECKPOINT_STATE_A => {
            Some(io::Error::new(io::ErrorKind::PermissionDenied, "EACCES"))
        }
        _ => None,
    })));
    let kind = match recover(&backing).map(|_| ()) {
        Err(RecoveryError::Io(e)) => e.kind(),
        Err(RecoveryError::Format(maki_format::FormatError::Io(e))) => e.kind(),
        other => panic!("expected an I/O error, got {other:?}"),
    };
    assert_eq!(kind, io::ErrorKind::PermissionDenied);
    backing.set_fault_hook(None);
    recover(&backing).unwrap();
}

// ---------- M-007 (durable mark): damage classification ----------

/// Records after the last fdatasync may persist in any order. Damage in
/// that region with a valid later record is still a torn tail: everything
/// from the damage on was never acknowledged durable.
#[test]
fn recovery_truncates_volatile_damage_despite_valid_successor() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    vol.write_ct(0, &ct(1), true).unwrap(); // durable mark covers record 1
    vol.write_ct(1, &ct(2), false).unwrap();
    vol.write_ct(2, &ct(3), false).unwrap();
    let seg = vol.journal_active_segment_path().unwrap();
    drop(vol);

    // Out-of-order persistence: record 2 lost (zeroed), record 3 kept.
    let f = backing.open(&seg, false).unwrap();
    let off = 48 + (32 + CT_LEN) as u64;
    f.write_at(off, &vec![0u8; 32 + CT_LEN]).unwrap();
    f.sync_data().unwrap();

    let vol = recover(&backing).unwrap();
    assert_eq!(vol.read_ct(0).unwrap().unwrap().1, ct(1));
    assert!(vol.read_ct(1).unwrap().is_none());
    assert!(vol.read_ct(2).unwrap().is_none(), "dropped with the tail");
}

/// Damage to the *last* record looks exactly like a torn tail — unless the
/// durable mark proves the record was fdatasync'd.
#[test]
fn recovery_rejects_damage_inside_durable_mark_even_at_the_tail() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    for i in 0..3u8 {
        vol.write_ct(i as u64, &ct(i + 1), false).unwrap();
    }
    vol.flush().unwrap(); // mark covers all three
    let seg = vol.journal_active_segment_path().unwrap();
    drop(vol);

    let f = backing.open(&seg, false).unwrap();
    let off = 48 + 2 * (32 + CT_LEN) as u64; // record 3 (the last one)
    f.write_at(off, b"JUNK").unwrap();
    f.sync_data().unwrap();
    let msg = expect_corrupt(recover(&backing));
    assert!(msg.contains("durable"), "{msg}");
}

/// The mark is a lower bound on the segment length: a shorter file lost
/// bytes that fdatasync had already made durable.
#[test]
fn recovery_rejects_segment_shorter_than_durable_mark() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    vol.write_ct(0, &ct(1), true).unwrap();
    let seg = vol.journal_active_segment_path().unwrap();
    drop(vol);

    let f = backing.open(&seg, false).unwrap();
    f.set_len(48 + 100).unwrap();
    f.sync_data().unwrap();
    let msg = expect_corrupt(recover(&backing));
    assert!(msg.contains("durable mark"), "{msg}");
}

/// Without a mark (lost, or a volume written before marks existed) the
/// scanner degrades to the heuristic: a clean journal still recovers.
#[test]
fn recovery_without_durable_mark_still_recovers_clean_journal() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    vol.write_ct(0, &ct(1), true).unwrap();
    vol.write_ct(1, &ct(2), false).unwrap();
    drop(vol);

    backing.remove(layout::JOURNAL_DURABLE_MARK).unwrap();
    backing.sync_dir(layout::JOURNAL_DIR).unwrap();
    let mut vol = recover(&backing).unwrap();
    assert_eq!(vol.read_ct(0).unwrap().unwrap().1, ct(1));
    // The writer recreates the mark on its next sync.
    vol.write_ct(2, &ct(3), true).unwrap();
    assert!(backing.exists(layout::JOURNAL_DURABLE_MARK).unwrap());
}

// ---------- follow-up audit: FUA sync failure keeps live view == journal ----------

/// A FUA write whose fdatasync fails has still been appended to the journal.
/// It must be visible to reads immediately (a later barrier or recovery
/// would surface it anyway); otherwise the live view diverges from what a
/// restart will replay.
#[test]
fn failed_fua_sync_still_publishes_the_journaled_record() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    vol.write_ct(0, &ct(1), true).unwrap();

    let fp = failpoints::fail_n_times("journal.sync", 1, io::ErrorKind::Other, "injected");
    let err = vol.write_ct(0, &ct(2), true).unwrap_err();
    drop(fp);
    assert!(matches!(err, maki_core::CoreError::Io(_)), "{err}");
    assert_eq!(
        vol.read_ct(0).unwrap().unwrap().1,
        ct(2),
        "the appended record is the live version even though FUA failed"
    );
    assert_eq!(
        vol.journal_durable_sequence(),
        1,
        "and it is not claimed durable"
    );

    // A later barrier makes it durable and a crash keeps it.
    vol.flush().unwrap();
    drop(vol);
    backing.crash_all_lost();
    let vol = recover(&backing).unwrap();
    assert_eq!(vol.read_ct(0).unwrap().unwrap().1, ct(2));
}
