//! Phase 3 — Journal and Recovery (SPEC §23–§27, §45).
//!
//! All tests drive the ciphertext-level volume core (journal writer, slot
//! store, checkpoint, recovery) over `CrashableBacking`. Failpoints are
//! exercised at persistence boundaries; the phase gate runs randomized
//! crash/recovery cycles against the durability oracle.

use std::io;
use std::sync::Arc;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use uuid::Uuid;

use maki_backing::Backing;
use maki_core::recovery::RecoveryError;
use maki_core::volume::Volume;
use maki_format::geometry::Geometry;
use maki_format::superblock::Superblock;
use maki_format::{init, layout};
use maki_test_support::failpoints;
use maki_test_support::model::ReferenceBlockModel;
use maki_test_support::CrashableBacking;

const UNIT: u32 = 512;
const CT_LEN: usize = 540; // ciphertext length used by tests (≤ max 544)

fn geometry() -> Geometry {
    // max ct 544, alignment 512 → slot = align_up(64+544)=1024
    Geometry::compute(512, UNIT, 512, 544, 512 * 1024, 512 * 64).unwrap()
}

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xBEEF),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: geometry(),
        format_version: 1,
        created_unix: 0,
    }
}

fn new_volume(backing: &Arc<CrashableBacking>) -> Volume {
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    Volume::recover(backing.clone() as Arc<dyn Backing>, small_segments()).unwrap()
}

fn small_segments() -> maki_core::volume::VolumeOptions {
    maki_core::volume::VolumeOptions {
        journal_segment_size: 4096, // force frequent segment rolls
    }
}

fn recover(backing: &Arc<CrashableBacking>) -> Result<Volume, RecoveryError> {
    Volume::recover(backing.clone() as Arc<dyn Backing>, small_segments())
}

fn ct(stamp: u8) -> Vec<u8> {
    vec![stamp; CT_LEN]
}

// ---------- append ----------

#[test]
fn append_assigns_sequences_and_tracks_durability() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    let s1 = vol.write_ct(0, &ct(1), false).unwrap();
    let s2 = vol.write_ct(1, &ct(2), false).unwrap();
    assert_eq!(s2, s1 + 1);
    assert!(vol.journal_durable_sequence() < s1, "nothing synced yet");
    vol.flush().unwrap();
    assert_eq!(vol.journal_durable_sequence(), s2);
    // overlay serves reads before checkpoint
    let (seq, data) = vol.read_ct(1).unwrap().expect("unit 1 present");
    assert_eq!(seq, s2);
    assert_eq!(data, ct(2));
    assert!(
        vol.read_ct(7).unwrap().is_none(),
        "unwritten unit reads zero"
    );
}

// ---------- barrier (FLUSH) ----------

#[test]
fn barrier_makes_prior_writes_durable_across_crash() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    vol.write_ct(0, &ct(0xA), false).unwrap();
    vol.write_ct(1, &ct(0xB), false).unwrap();
    vol.flush().unwrap(); // barrier: A and B durable
    vol.write_ct(2, &ct(0xC), false).unwrap(); // not durable
    drop(vol);

    backing.crash_all_lost();
    let vol = recover(&backing).unwrap();
    assert_eq!(vol.read_ct(0).unwrap().unwrap().1, ct(0xA));
    assert_eq!(vol.read_ct(1).unwrap().unwrap().1, ct(0xB));
    assert!(
        vol.read_ct(2).unwrap().is_none(),
        "unflushed write may be lost"
    );
}

// ---------- FUA ----------

#[test]
fn fua_write_is_durable_across_crash() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    let seq = vol.write_ct(3, &ct(0xF), true).unwrap();
    assert!(vol.journal_durable_sequence() >= seq, "FUA implies durable");
    drop(vol);

    backing.crash_all_lost();
    let vol = recover(&backing).unwrap();
    assert_eq!(vol.read_ct(3).unwrap().unwrap().1, ct(0xF));
}

// ---------- segment creation & directory fsync ----------

#[test]
fn segments_roll_and_survive_crash() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    // segment size 4096, records ~572B ⇒ several rolls over 40 writes
    for i in 0..40u8 {
        vol.write_ct(i as u64 % 8, &ct(i), false).unwrap();
    }
    vol.flush().unwrap();
    assert!(
        vol.journal_segment_count() >= 2,
        "expected multiple segments"
    );
    drop(vol);

    backing.crash_all_lost();
    let vol = recover(&backing).unwrap();
    for i in 32..40u8 {
        // last write per unit wins
        let unit = i as u64 % 8;
        assert_eq!(vol.read_ct(unit).unwrap().unwrap().1, ct(i));
    }
}

#[test]
fn segment_dirsync_failure_fails_closed() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    // Fill first segment so the next append rolls.
    for i in 0..8u8 {
        vol.write_ct(0, &ct(i), false).unwrap();
    }
    let fp = failpoints::set(
        "journal.segment.dirsync",
        failpoints::FailpointAction::IoError(
            io::ErrorKind::Other,
            "injected dirsync failure".to_string(),
        ),
    );
    // Appends must eventually fail rather than acknowledge into a segment
    // whose dirent could vanish.
    let mut failed = false;
    for i in 0..16u8 {
        if vol.write_ct(1, &ct(i), false).is_err() {
            failed = true;
            break;
        }
    }
    drop(fp);
    assert!(failed, "segment roll with failing dirsync must error");
    // The journal remains usable once the fault clears.
    vol.write_ct(1, &ct(0x77), true).unwrap();
    assert_eq!(vol.read_ct(1).unwrap().unwrap().1, ct(0x77));
}

// ---------- partial journal tail ----------

#[test]
fn torn_journal_tail_is_truncated_on_recovery() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    vol.write_ct(0, &ct(0x1), false).unwrap();
    vol.flush().unwrap();
    vol.write_ct(1, &ct(0x2), false).unwrap(); // will be torn
    let seg = vol.journal_active_segment_path().unwrap();
    let seg_len_before_tear = 48 + 32 + CT_LEN as u64; // header + rec1
    drop(vol);

    // Crash keeping only half of record 2's bytes.
    backing.crash_keep_torn_prefix(&seg, 100);
    let mut vol = recover(&backing).unwrap();
    assert_eq!(
        vol.read_ct(0).unwrap().unwrap().1,
        ct(0x1),
        "durable record kept"
    );
    assert!(vol.read_ct(1).unwrap().is_none(), "torn record dropped");
    let _ = seg_len_before_tear;

    // Journal keeps working after truncation.
    vol.write_ct(1, &ct(0x3), true).unwrap();
    drop(vol);
    backing.crash_all_lost();
    let vol = recover(&backing).unwrap();
    assert_eq!(vol.read_ct(1).unwrap().unwrap().1, ct(0x3));
}

// ---------- middle-record corruption ----------

#[test]
fn middle_corruption_fails_recovery_loudly() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    for i in 0..3u8 {
        vol.write_ct(i as u64, &ct(i + 1), false).unwrap();
    }
    vol.flush().unwrap();
    let seg = vol.journal_active_segment_path().unwrap();
    drop(vol);

    // Flip a byte inside record 1's payload (durable region!).
    let f = backing.open(&seg, false).unwrap();
    let mut b = [0u8; 1];
    let off = 48 + 32 + 10; // segment header + record header + payload byte 10
    f.read_at(off, &mut b).unwrap();
    f.write_at(off, &[b[0] ^ 0x01]).unwrap();
    f.sync_data().unwrap();

    match recover(&backing).map(|_| ()) {
        Err(RecoveryError::Corrupt(_)) => {}
        other => panic!("expected Corrupt, got {other:?}"),
    }
}

// ---------- checkpointing ----------

#[test]
fn checkpoint_moves_data_to_slots_and_deletes_segments() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    for i in 0..20u8 {
        vol.write_ct(i as u64 % 6, &ct(i), false).unwrap();
    }
    vol.flush().unwrap();
    let segs_before = vol.journal_segment_count();
    assert!(segs_before >= 2);

    let ck = vol.checkpoint().unwrap();
    assert!(ck > 0);
    assert!(
        vol.journal_segment_count() < segs_before,
        "covered segments must be deleted"
    );
    assert_eq!(vol.overlay_len(), 0, "overlay retired after checkpoint");

    // Data now served from slots (and survives a lose-all crash).
    drop(vol);
    backing.crash_all_lost();
    let vol = recover(&backing).unwrap();
    assert_eq!(vol.checkpoint_sequence(), ck);
    for unit in 0..6u64 {
        let expect = (14..20u8).find(|i| *i as u64 % 6 == unit).unwrap();
        assert_eq!(vol.read_ct(unit).unwrap().unwrap().1, ct(expect));
    }
}

#[test]
fn checkpoint_only_consumes_durable_records() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    vol.write_ct(0, &ct(1), false).unwrap();
    // No flush: nothing durable. Checkpoint must be a no-op (sequence 0).
    let ck = vol.checkpoint().unwrap();
    assert_eq!(ck, vol.checkpoint_sequence());
    assert_eq!(ck, 0, "checkpoint_sequence <= durable_sequence violated");
    // After flush it may proceed.
    vol.flush().unwrap();
    let ck = vol.checkpoint().unwrap();
    assert!(ck >= 1);
}

#[test]
fn crash_mid_checkpoint_at_every_boundary_recovers_consistently() {
    let _guard = failpoints::test_lock();
    for stage in [
        "checkpoint.slot_write",
        "checkpoint.shard_sync",
        "checkpoint.alloc_store",
        "checkpoint.alloc_dirsync",
        "checkpoint.state_store",
        "checkpoint.segment_delete",
        "checkpoint.dirsync",
    ] {
        let backing = Arc::new(CrashableBacking::new());
        let mut vol = new_volume(&backing);
        for i in 0..12u8 {
            vol.write_ct(i as u64 % 4, &ct(i), false).unwrap();
        }
        vol.flush().unwrap();

        let fp = failpoints::set(
            stage,
            failpoints::FailpointAction::IoError(io::ErrorKind::Other, "injected".to_string()),
        );
        let result = vol.checkpoint();
        drop(fp);
        assert!(result.is_err(), "stage {stage} should fail");
        drop(vol);

        // Crash with random survival of everything volatile, then recover:
        // all flushed data must still read correctly.
        let mut rng = StdRng::seed_from_u64(0xC0DE);
        backing.crash(&mut rng);
        let mut vol =
            recover(&backing).unwrap_or_else(|e| panic!("recovery after {stage} failed: {e:?}"));
        for unit in 0..4u64 {
            let expect = (8..12u8).find(|i| *i as u64 % 4 == unit).unwrap();
            assert_eq!(
                vol.read_ct(unit).unwrap().unwrap().1,
                ct(expect),
                "unit {unit} wrong after {stage}"
            );
        }
        // And a retried checkpoint completes.
        vol.checkpoint().unwrap();
        assert_eq!(vol.overlay_len(), 0);
    }
}

// ---------- ENOSPC ----------

#[test]
fn enospc_on_append_fails_write_but_preserves_consistency() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    vol.write_ct(0, &ct(1), true).unwrap();

    let fp = failpoints::set(
        "journal.append.write",
        failpoints::FailpointAction::IoError(io::ErrorKind::StorageFull, "ENOSPC".to_string()),
    );
    assert!(vol.write_ct(1, &ct(2), false).is_err());
    drop(fp);

    // Old data intact; new writes work again.
    assert_eq!(vol.read_ct(0).unwrap().unwrap().1, ct(1));
    assert!(vol.read_ct(1).unwrap().is_none());
    vol.write_ct(1, &ct(3), true).unwrap();
    drop(vol);
    backing.crash_all_lost();
    let vol = recover(&backing).unwrap();
    assert_eq!(vol.read_ct(1).unwrap().unwrap().1, ct(3));
}

#[test]
fn enospc_during_checkpoint_leaves_journal_authoritative() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    for i in 0..6u8 {
        vol.write_ct(i as u64, &ct(i + 1), false).unwrap();
    }
    vol.flush().unwrap();

    let fp = failpoints::fail_n_times(
        "checkpoint.slot_write",
        3,
        io::ErrorKind::StorageFull,
        "ENOSPC",
    );
    assert!(vol.checkpoint().is_err());
    drop(fp);

    for i in 0..6u64 {
        assert_eq!(vol.read_ct(i).unwrap().unwrap().1, ct(i as u8 + 1));
    }
    vol.checkpoint().unwrap();
    for i in 0..6u64 {
        assert_eq!(vol.read_ct(i).unwrap().unwrap().1, ct(i as u8 + 1));
    }
}

// ---------- allocation corruption ----------

#[test]
fn allocation_corruption_one_side_recovers_both_sides_fails() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    vol.write_ct(0, &ct(9), false).unwrap();
    vol.flush().unwrap();
    vol.checkpoint().unwrap();
    drop(vol);

    let corrupt = |path: &str| {
        let f = backing.open(path, false).unwrap();
        f.write_at(20, &[0xFF, 0xFF, 0xFF, 0xFF]).unwrap();
        f.sync_data().unwrap();
    };

    // One side corrupted: A/B protocol falls back.
    corrupt(&layout::shard_alloc_a(0));
    let vol = recover(&backing).unwrap();
    assert_eq!(vol.read_ct(0).unwrap().unwrap().1, ct(9));
    drop(vol);

    // Both sides corrupted: recovery must refuse (silent corruption = 0).
    corrupt(&layout::shard_alloc_b(0));
    match recover(&backing).map(|_| ()) {
        Err(RecoveryError::Corrupt(_)) => {}
        other => panic!("expected Corrupt, got {other:?}"),
    }
}

#[test]
fn allocated_bit_with_invalid_slot_is_eio_not_zeros() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    vol.write_ct(5, &ct(7), false).unwrap();
    vol.flush().unwrap();
    vol.checkpoint().unwrap();
    drop(vol);

    // Smash the slot bytes on disk (allocation bit stays 1).
    let g = geometry();
    let (shard, idx) = g.shard_of_unit(5);
    let f = backing.open(&layout::shard_data(shard), false).unwrap();
    f.write_at(g.slot_offset(idx), &[0xEE; 100]).unwrap();
    f.sync_data().unwrap();

    let vol = recover(&backing).unwrap();
    assert!(
        vol.read_ct(5).is_err(),
        "allocated unit with invalid slot must be EIO, not fabricated zeros"
    );
    // Other units unaffected.
    assert!(vol.read_ct(6).unwrap().is_none());
}

// ---------- double attach ----------

#[test]
fn volume_lock_rejects_second_attach() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let vol = new_volume(&backing);
    match recover(&backing).map(|_| ()) {
        Err(RecoveryError::AlreadyAttached) => {}
        other => panic!("expected AlreadyAttached, got {other:?}"),
    }
    drop(vol);
    recover(&backing).unwrap();
}

// ---------- phase gate: randomized crash/recovery cycles ----------

fn crash_cycle(seed: u64, ops: usize) {
    let mut rng = StdRng::seed_from_u64(seed.wrapping_mul(0x9E37_79B9).wrapping_add(7));
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    let num_units = 8u64;
    let mut model = ReferenceBlockModel::new(CT_LEN, num_units);
    let mut stamp: u8 = 0;

    for _ in 0..ops {
        match rng.random_range(0..100u32) {
            0..=44 => {
                stamp = stamp.wrapping_add(1).max(1);
                let unit = rng.random_range(0..num_units);
                vol.write_ct(unit, &ct(stamp), false).unwrap();
                model.write(unit, &ct(stamp));
            }
            45..=59 => {
                stamp = stamp.wrapping_add(1).max(1);
                let unit = rng.random_range(0..num_units);
                vol.write_ct(unit, &ct(stamp), true).unwrap();
                model.write_fua(unit, &ct(stamp));
            }
            60..=74 => {
                vol.flush().unwrap();
                model.flush();
            }
            75..=84 => {
                vol.checkpoint().unwrap();
                // model unchanged: checkpoint is invisible to durability
            }
            _ => {
                drop(vol);
                backing.crash(&mut rng);
                vol = recover(&backing)
                    .unwrap_or_else(|e| panic!("seed {seed}: recovery failed: {e:?}"));
                for unit in 0..num_units {
                    let actual = match vol.read_ct(unit) {
                        Ok(Some((_seq, data))) => data,
                        Ok(None) => vec![0u8; CT_LEN],
                        Err(e) => panic!("seed {seed}: EIO after crash on unit {unit}: {e:?}"),
                    };
                    model
                        .crash_adopt(unit, &actual)
                        .unwrap_or_else(|v| panic!("seed {seed}: {v}"));
                }
            }
        }
        // Live view must always match the model exactly.
        if rng.random_bool(0.2) {
            let unit = rng.random_range(0..num_units);
            let actual = match vol.read_ct(unit) {
                Ok(Some((_s, d))) => d,
                Ok(None) => vec![0u8; CT_LEN],
                Err(e) => panic!("seed {seed}: live EIO: {e:?}"),
            };
            assert_eq!(actual, model.read(unit), "seed {seed} live mismatch");
        }
    }
}

/// Smoke gate: 150 randomized crash/recovery cycles.
#[test]
fn phase3_gate_crash_recovery_smoke() {
    let _guard = failpoints::test_lock();
    for seed in 0..150u64 {
        crash_cycle(seed, 60);
    }
}

/// Full phase gate: 10,000+ crash/recovery cycles, silent corruption = 0.
#[test]
#[ignore = "phase gate: 10,000+ crash/recovery cycles"]
fn phase3_gate_full() {
    for seed in 0..10_000u64 {
        crash_cycle(seed, 60);
    }
}
