//! A covered durable proof whose location lies beyond the newer journal.
//!
//! When the checkpoint covers the required proof, its segment may have been
//! pruned, so the scan does not match the proof against the journal. Recovery
//! still publishes the accepted horizon as the new proof, and the new record
//! end must follow the stored one (`DurableProof::follows`). A CRC-valid proof
//! naming a later segment, or a later byte of the same segment, than the newer
//! records end at is impossible (segment indexes only grow and the proof names
//! the record end of its horizon): recovery refused it ("advancing durable
//! sequence regressed its segment location") while the deep check reported the
//! volume clean. Both must refuse it, before any recovery write.

use std::sync::{Arc, Mutex};

use uuid::Uuid;

use maki_backing::Backing;
use maki_core::check::deep_check;
use maki_core::recovery::RecoveryError;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::durable_proof::{
    DurableProof, DurableProofStore, DURABLE_PROOF_A, DURABLE_PROOF_B,
};
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::CrashableBacking;

const SEGMENT: u64 = 4096;
const UUID: u128 = 0x9e0f_10c4;

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: SEGMENT,
    }
}

/// A FUA write (sequence 1) covered by a checkpoint, then a write above the
/// proof that survives a restart in the page cache (sequence 2, same segment).
fn covered_proof_with_a_newer_record() -> (Arc<CrashableBacking>, DurableProof, u64) {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: Uuid::from_u128(UUID),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, 512, 512, 544, 512 * 128, 512 * 48).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let mut volume = Volume::recover(backing.clone() as Arc<dyn Backing>, options()).unwrap();
    volume.write_ct(3, &[0x33; 540], true).unwrap();
    assert_eq!(volume.checkpoint().unwrap(), 1);
    volume.write_ct(4, &[0x44; 540], false).unwrap();
    let segment = volume.journal_active_segment_path().unwrap();
    let end = backing.open(&segment, false).unwrap().len().unwrap();
    drop(volume);
    let proof = DurableProofStore::load(backing.as_ref(), Uuid::from_u128(UUID)).unwrap();
    assert_eq!(proof.durable_sequence, 1);
    (backing, proof, end)
}

/// Overwrite both copies with one CRC-valid proof (same generation, same
/// bytes), so neither the A/B selection nor `follows` between them objects.
fn publish_both_copies(backing: &CrashableBacking, proof: &DurableProof) {
    for path in [DURABLE_PROOF_A, DURABLE_PROOF_B] {
        let file = backing.open(path, false).unwrap();
        file.write_at(0, &proof.encode()).unwrap();
        file.sync_data().unwrap();
    }
}

fn observe_mutations(backing: &CrashableBacking) -> Arc<Mutex<Vec<String>>> {
    let mutations = Arc::new(Mutex::new(Vec::new()));
    let observed = mutations.clone();
    backing.set_fault_hook(Some(Arc::new(move |op| {
        if !matches!(op, FaultOp::Open { create: false, .. }) {
            observed.lock().unwrap().push(format!("{op:?}"));
        }
        None
    })));
    mutations
}

fn assert_check_and_recovery_refuse(what: &str, backing: &Arc<CrashableBacking>) {
    let mutations = observe_mutations(backing);
    let report = deep_check(backing.clone() as Arc<dyn Backing>, SEGMENT).unwrap();
    let recovered = Volume::recover(backing.clone() as Arc<dyn Backing>, options());
    backing.set_fault_hook(None);
    assert!(
        !report.ok(),
        "{what}: the deep check passed (warnings {:?}); recovery: {:?}",
        report.warnings,
        recovered.as_ref().err().map(|error| error.to_string())
    );
    match recovered {
        Err(RecoveryError::Corrupt(_)) => {}
        Err(error) => panic!("{what}: expected corruption, got {error}"),
        Ok(_) => panic!("{what}: recovery accepted a proof beyond the journal"),
    }
    let mutations = mutations.lock().unwrap();
    assert!(
        mutations.is_empty(),
        "{what}: storage changed before the refusal: {mutations:?}"
    );
}

#[test]
fn covered_proof_naming_a_later_segment_is_refused_by_check_and_recovery() {
    let (backing, proof, _) = covered_proof_with_a_newer_record();
    let mut moved = proof.clone();
    moved.segment_index += 5;
    publish_both_copies(&backing, &moved);
    assert_check_and_recovery_refuse("segment index + 5", &backing);
}

#[test]
fn covered_proof_ending_where_the_newer_record_ends_is_refused_by_check_and_recovery() {
    let (backing, proof, end) = covered_proof_with_a_newer_record();
    let mut moved = proof.clone();
    moved.durable_size = end;
    publish_both_copies(&backing, &moved);
    assert_check_and_recovery_refuse("durable size at the newer record's end", &backing);
}

/// The honest location still recovers: the newer record is adopted and the
/// proof advances past the stored one.
#[test]
fn covered_proof_before_the_newer_record_still_recovers() {
    let (backing, proof, end) = covered_proof_with_a_newer_record();
    let report = deep_check(backing.clone() as Arc<dyn Backing>, SEGMENT).unwrap();
    assert!(report.ok(), "{:?}", report.errors);
    let volume = Volume::recover(backing.clone() as Arc<dyn Backing>, options()).unwrap();
    assert_eq!(volume.read_ct(4).unwrap(), Some((2, vec![0x44; 540])));
    drop(volume);
    let advanced = DurableProofStore::load(backing.as_ref(), Uuid::from_u128(UUID)).unwrap();
    assert_eq!(advanced.durable_sequence, 2);
    assert_eq!(advanced.segment_index, proof.segment_index);
    assert_eq!(advanced.durable_size, end);
}
