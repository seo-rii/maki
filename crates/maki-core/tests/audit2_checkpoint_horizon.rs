//! audit2 (decoder-fuzz): minimized cases from the CRC-valid metadata
//! mutation sweep (`audit2_metadata_mutation.rs`).
//!
//! SPEC §26: `checkpoint_sequence <= durable_sequence` is an absolute
//! invariant, and SPEC §25 makes the required durable proof the lower bound
//! on every acknowledged sequence. A checkpoint can only consume durable
//! records, so a CRC-valid checkpoint state whose sequence is ABOVE the
//! required proof's horizon contradicts the other required record. Recovery
//! computes `durable_sequence = max(checkpoint, journal)`, which makes the
//! invariant vacuous: it accepts such a state, treats every journal record
//! at or below it as already applied, and serves zeros (or an older slot
//! version) for FUA-acknowledged writes. The deep check reports the volume
//! clean. A value near u64::MAX additionally leaves the attached volume
//! unable to accept any write.

use std::sync::Arc;

use uuid::Uuid;

use maki_backing::Backing;
use maki_core::check::deep_check;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::ab::AbStore;
use maki_format::checkpoint::{CheckpointState, CHECKPOINT_STATE_A, CHECKPOINT_STATE_B};
use maki_format::durable_proof::DurableProofStore;
use maki_format::geometry::Geometry;
use maki_format::journal::DurableMark;
use maki_format::superblock::Superblock;
use maki_format::{init, layout};
use maki_test_support::failpoints;
use maki_test_support::CrashableBacking;

const SEGMENT: u64 = 4096;
const UUID: u128 = 0xA0D1_7203;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(UUID),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, 512, 512, 544, 512 * 128, 512 * 48).unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: SEGMENT,
    }
}

fn ct(stamp: u8) -> Vec<u8> {
    vec![stamp; 540]
}

/// Two FUA-acknowledged writes (sequences 1 and 2), never checkpointed.
fn volume_with_two_fua_writes() -> Arc<CrashableBacking> {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    let mut vol = Volume::recover(backing.clone() as Arc<dyn Backing>, options()).unwrap();
    assert_eq!(vol.write_ct(3, &ct(0x33), true).unwrap(), 1);
    assert_eq!(vol.write_ct(4, &ct(0x44), true).unwrap(), 2);
    drop(vol);
    backing
}

/// Publish a checkpoint state with `sequence` through the ordinary A/B
/// store: a CRC-valid, newer-generation copy, exactly what the writer
/// itself would produce.
fn set_checkpoint_sequence(backing: &CrashableBacking, sequence: u64) {
    let ab = AbStore::new(CHECKPOINT_STATE_A, CHECKPOINT_STATE_B);
    let mut state: CheckpointState = ab.load(backing).unwrap().unwrap();
    state.checkpoint_sequence = sequence;
    ab.store(backing, &mut state).unwrap();
}

#[test]
fn checkpoint_beyond_the_required_durable_proof_is_accepted_and_drops_fua_writes() {
    let _guard = failpoints::test_lock();
    let backing = volume_with_two_fua_writes();
    let proof = DurableProofStore::load(backing.as_ref(), Uuid::from_u128(UUID)).unwrap();
    assert_eq!(proof.durable_sequence, 2, "the proof attests both FUA writes");

    // Checkpoint state claims sequence 1000 was applied: impossible, the
    // required proof says nothing above 2 was ever durable.
    set_checkpoint_sequence(&backing, 1000);

    let report = deep_check(backing.clone() as Arc<dyn Backing>, SEGMENT).unwrap();
    let check_clean = report.ok();
    let recovered = Volume::recover(backing.clone() as Arc<dyn Backing>, options());
    let outcome = match &recovered {
        Err(e) => format!("recovery refused: {e}"),
        Ok(vol) => format!(
            "recovery accepted; unit 3 reads {:?}, unit 4 reads {:?}",
            vol.read_ct(3).unwrap().map(|(seq, data)| (seq, data[0])),
            vol.read_ct(4).unwrap().map(|(seq, data)| (seq, data[0])),
        ),
    };
    eprintln!("deep check clean: {check_clean}; {outcome}");
    let segments_before = backing.list(layout::JOURNAL_DIR).unwrap();
    // Either refuse the contradiction or still serve the acknowledged data.
    let served = recovered.as_ref().is_ok_and(|vol| {
        vol.read_ct(3).unwrap().is_some_and(|(_, d)| d == ct(0x33))
            && vol.read_ct(4).unwrap().is_some_and(|(_, d)| d == ct(0x44))
    });
    let refused = recovered.is_err();
    if let Ok(vol) = recovered {
        // One more write and checkpoint: the journal records the bogus
        // checkpoint "covers" are pruned, so the loss becomes permanent.
        let mut vol = vol;
        vol.write_ct(9, &ct(0x99), true).unwrap();
        let horizon = vol.checkpoint().unwrap();
        let segments_after = backing.list(layout::JOURNAL_DIR).unwrap();
        eprintln!(
            "after one more FUA write + checkpoint (horizon {horizon}): journal {segments_before:?} -> {segments_after:?}"
        );
        drop(vol);
        let again = Volume::recover(backing.clone() as Arc<dyn Backing>, options()).unwrap();
        eprintln!("re-recovered: unit 3 reads {:?}", again.read_ct(3).unwrap().map(|(s, d)| (s, d[0])));
        drop(again);
        assert!(
            served,
            "checkpoint 1000 > durable proof 2 was accepted and FUA-acknowledged data vanished \
             (deep check clean: {check_clean}): {outcome}"
        );
    }
    assert!(refused || served);
    assert!(
        !check_clean,
        "deep check reports a checkpoint above the durable proof as clean"
    );
}

#[test]
fn checkpoint_near_u64_max_is_accepted_then_every_write_fails() {
    let _guard = failpoints::test_lock();
    let backing = volume_with_two_fua_writes();
    set_checkpoint_sequence(&backing, u64::MAX - 1);

    let report = deep_check(backing.clone() as Arc<dyn Backing>, SEGMENT).unwrap();
    let recovered = Volume::recover(backing.clone() as Arc<dyn Backing>, options());
    let Ok(mut vol) = recovered else {
        return; // refusing the impossible state is the correct outcome
    };
    let write = vol.write_ct(5, &ct(0x55), true);
    eprintln!(
        "deep check clean: {}; recovery accepted; first write: {write:?}",
        report.ok()
    );
    assert!(
        write.is_ok(),
        "recovery accepted checkpoint u64::MAX-1 and the volume can never be written again: {}",
        write.unwrap_err()
    );
}

/// The advisory durable mark sets the floor for new segment indexes (S-03).
/// A CRC-valid mark naming segment u64::MAX-1 (no such segment exists) is
/// accepted; the attached volume then refuses every write.
#[test]
fn durable_mark_naming_segment_near_u64_max_is_accepted_then_every_write_fails() {
    let _guard = failpoints::test_lock();
    let backing = volume_with_two_fua_writes();
    let file = backing.open(layout::JOURNAL_DURABLE_MARK, true).unwrap();
    file.set_len(0).unwrap();
    file.write_at(
        0,
        &DurableMark {
            segment_index: u64::MAX - 1,
            durable_size: 48,
        }
        .encode(),
    )
    .unwrap();
    file.sync_data().unwrap();

    let report = deep_check(backing.clone() as Arc<dyn Backing>, SEGMENT).unwrap();
    let recovered = Volume::recover(backing.clone() as Arc<dyn Backing>, options());
    let Ok(mut vol) = recovered else {
        return;
    };
    // Fill the active segment so the next write needs a roll.
    let mut write = Ok(0);
    for i in 0..16u8 {
        write = vol.write_ct(5 + i as u64, &ct(i), true);
        if write.is_err() {
            break;
        }
    }
    eprintln!(
        "deep check clean: {}; recovery accepted; writes: {write:?}",
        report.ok()
    );
    assert!(
        write.is_ok(),
        "recovery accepted a durable mark for segment u64::MAX-1 and the volume cannot \
         roll its journal: {}",
        write.unwrap_err()
    );
}

/// Round 1 noted (and ruled out as unrealistic) that the check and recovery
/// diverge on CRC-valid generations near u64::MAX. Pinned for completeness:
/// the deep check passes, recovery refuses.
#[test]
fn checkpoint_generation_near_u64_max_check_passes_attach_refuses() {
    let _guard = failpoints::test_lock();
    let backing = volume_with_two_fua_writes();
    // generation lives at bytes 12..20 of checkpoint/state.*; raise the
    // newest copy's generation and fix its CRC.
    let ab = AbStore::new(CHECKPOINT_STATE_A, CHECKPOINT_STATE_B);
    let (ga, gb) = ab.side_generations::<CheckpointState>(backing.as_ref()).unwrap();
    let path = if ga >= gb { CHECKPOINT_STATE_A } else { CHECKPOINT_STATE_B };
    let f = backing.open(path, false).unwrap();
    let mut bytes = vec![0; f.len().unwrap() as usize];
    f.read_at(0, &mut bytes).unwrap();
    bytes[12..20].copy_from_slice(&u64::MAX.to_le_bytes());
    let n = bytes.len();
    let crc = crc32fast::hash(&bytes[..n - 4]);
    bytes[n - 4..].copy_from_slice(&crc.to_le_bytes());
    f.write_at(0, &bytes).unwrap();
    f.sync_data().unwrap();

    let report = deep_check(backing.clone() as Arc<dyn Backing>, SEGMENT).unwrap();
    let recovered = Volume::recover(backing.clone() as Arc<dyn Backing>, options());
    eprintln!(
        "deep check clean: {}; recovery: {:?}",
        report.ok(),
        recovered.as_ref().err().map(|e| e.to_string())
    );
    assert_eq!(
        report.ok(),
        recovered.is_ok(),
        "deep check and recovery disagree on a checkpoint generation of u64::MAX"
    );
}

/// Sweep case (both proof copies, `u64@44 4 -> 5`): the durable proof's
/// segment index is only validated when the proof is above the checkpoint
/// ("required"). A CRC-valid proof that names a segment index beyond every
/// segment the volume has (impossible: the proof names the segment its
/// record ends in) passes the deep check, but recovery, which advances the
/// proof to the replayed tail, refuses with "advancing durable sequence
/// regressed its segment location". The check and attach disagree.
#[test]
fn proof_segment_index_beyond_every_segment_check_passes_attach_refuses() {
    use maki_format::durable_proof::{DURABLE_PROOF_A, DURABLE_PROOF_B};
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    let mut vol = Volume::recover(backing.clone() as Arc<dyn Backing>, options()).unwrap();
    vol.write_ct(3, &ct(0x33), true).unwrap();
    vol.checkpoint().unwrap();
    vol.write_ct(4, &ct(0x44), false).unwrap(); // above the proof, page cache only
    drop(vol);
    let proof = DurableProofStore::load(backing.as_ref(), Uuid::from_u128(UUID)).unwrap();
    for path in [DURABLE_PROOF_A, DURABLE_PROOF_B] {
        let f = backing.open(path, false).unwrap();
        let mut bytes = vec![0; 64];
        f.read_at(0, &mut bytes).unwrap();
        bytes[44..52].copy_from_slice(&(proof.segment_index + 5).to_le_bytes());
        let crc = crc32fast::hash(&bytes[..60]);
        bytes[60..].copy_from_slice(&crc.to_le_bytes());
        f.write_at(0, &bytes).unwrap();
        f.sync_data().unwrap();
    }
    let report = deep_check(backing.clone() as Arc<dyn Backing>, SEGMENT).unwrap();
    let recovered = Volume::recover(backing.clone() as Arc<dyn Backing>, options());
    eprintln!(
        "proof {proof:?} -> segment_index {}; deep check clean: {} (errors {:?}); recovery: {:?}",
        proof.segment_index + 5,
        report.ok(),
        report.errors,
        recovered.as_ref().err().map(|e| e.to_string())
    );
    assert_eq!(
        report.ok(),
        recovered.is_ok(),
        "deep check and recovery disagree on a durable proof naming a nonexistent later segment"
    );
}
