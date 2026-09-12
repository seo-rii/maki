//! MAKI-020: an acknowledgement horizon must survive losing either copy.
//!
//! The first three cases failed against the existing one-update A/B store
//! before these helpers were switched to the required mirrored-proof API.

use maki_backing::Backing;
use maki_format::durable_proof::{
    DurableProof, DurableProofStore, DURABLE_PROOF_A as A, DURABLE_PROOF_B as B,
};
use maki_format::FormatError;
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::CrashableBacking;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use uuid::Uuid;

const UUID: Uuid = Uuid::from_u128(0x202609120020);

fn setup() -> (CrashableBacking, DurableProof) {
    let backing = CrashableBacking::new();
    let proof = DurableProofStore::initialize(&backing, UUID).unwrap();
    (backing, proof)
}

fn advance(backing: &dyn Backing, proof: &mut DurableProof, sequence: u64) {
    proof.durable_sequence = sequence;
    proof.durable_size = 48 + 64 * sequence;
    DurableProofStore::advance(backing, proof).unwrap();
}

fn read(backing: &dyn Backing, path: &str) -> Vec<u8> {
    let file = backing.open(path, false).unwrap();
    let mut bytes = vec![0; file.len().unwrap() as usize];
    file.read_at(0, &mut bytes).unwrap();
    bytes
}

fn replace(backing: &dyn Backing, path: &str, bytes: &[u8]) {
    let file = backing.open(path, true).unwrap();
    file.set_len(bytes.len() as u64).unwrap();
    file.write_at(0, bytes).unwrap();
    file.sync_data().unwrap();
    backing.sync_dir("journal").unwrap();
}

fn one_lost_copy_does_not_lower_the_acknowledged_horizon(damage: &str) {
    let (backing, mut proof) = setup();
    let stale_b = read(&backing, B);
    advance(&backing, &mut proof, 1);
    advance(&backing, &mut proof, 2);
    match damage {
        "missing" => {
            backing.remove(B).unwrap();
            backing.sync_dir("journal").unwrap();
        }
        "stale" => replace(&backing, B, &stale_b),
        "corrupt" => replace(&backing, B, &[0; 32]),
        _ => unreachable!(),
    }
    let recovered = DurableProofStore::load(&backing, UUID).unwrap();
    assert_eq!(
        recovered.durable_sequence, 2,
        "lost {damage} copy lowered the last acknowledged horizon"
    );
}

#[test]
fn acknowledged_horizon_survives_a_missing_copy() {
    one_lost_copy_does_not_lower_the_acknowledged_horizon("missing");
}

#[test]
fn acknowledged_horizon_survives_a_valid_stale_copy() {
    one_lost_copy_does_not_lower_the_acknowledged_horizon("stale");
}

#[test]
fn acknowledged_horizon_survives_a_corrupt_copy() {
    one_lost_copy_does_not_lower_the_acknowledged_horizon("corrupt");
}

#[test]
fn initialization_and_each_advance_make_both_copies_durable() {
    let (backing, mut proof) = setup();
    for sequence in [0, 1, 2] {
        if sequence > 0 {
            advance(&backing, &mut proof, sequence);
        }
        backing.crash_all_lost();
        for path in [A, B] {
            let observed = DurableProof::decode(&read(&backing, path)).unwrap();
            assert_eq!(observed.volume_uuid, UUID);
            assert_eq!(observed.durable_sequence, sequence, "{path}");
        }
    }
}

#[test]
fn required_proof_never_falls_back_to_empty_or_reinitializes_history() {
    let backing = CrashableBacking::new();
    assert!(DurableProofStore::load(&backing, UUID).is_err());
    let (backing, mut proof) = setup();
    advance(&backing, &mut proof, 1);
    assert!(matches!(
        DurableProofStore::initialize(&backing, UUID),
        Err(FormatError::AlreadyExists(_))
    ));
    for path in [A, B] {
        replace(&backing, path, &[0; 64]);
    }
    assert!(DurableProofStore::load(&backing, UUID).is_err());
    assert!(DurableProofStore::initialize(&backing, UUID).is_err());
    for path in [A, B] {
        backing.remove(path).unwrap();
    }
    assert!(DurableProofStore::load(&backing, UUID).is_err());
}

#[test]
fn foreign_proof_is_an_error_even_when_the_other_copy_matches() {
    let (backing, proof) = setup();
    let mut foreign = proof.clone();
    foreign.volume_uuid = Uuid::from_u128(99);
    replace(&backing, A, &foreign.encode());
    assert!(matches!(
        DurableProofStore::load(&backing, UUID),
        Err(FormatError::Invalid(_))
    ));
    let mut candidate = proof;
    assert!(DurableProofStore::advance(&backing, &mut candidate).is_err());
}

#[test]
fn hard_io_does_not_select_the_other_copy() {
    let (backing, mut proof) = setup();
    let other = read(&backing, B);
    for kind in [io::ErrorKind::PermissionDenied, io::ErrorKind::Other] {
        backing.set_fault_hook(Some(Arc::new(move |op| match op {
            FaultOp::Open { path, .. } if *path == A => {
                Some(io::Error::new(kind, "proof unreadable"))
            }
            _ => None,
        })));
        assert!(matches!(
            DurableProofStore::load(&backing, UUID),
            Err(FormatError::Io(_))
        ));
        assert!(matches!(
            DurableProofStore::advance(&backing, &mut proof),
            Err(FormatError::Io(_))
        ));
        backing.set_fault_hook(None);
        assert_eq!(read(&backing, B), other);
    }
}

fn checksum(bytes: &mut [u8]) {
    let end = bytes.len() - 4;
    let crc = crc32fast::hash(&bytes[..end]);
    bytes[end..].copy_from_slice(&crc.to_le_bytes());
}

#[test]
fn unsupported_copy_cannot_be_silently_overwritten_or_ignored() {
    for extension in [0, 16] {
        let (backing, mut proof) = setup();
        let before = read(&backing, B);
        let mut future = proof.encode();
        future[8..12].copy_from_slice(&2_u32.to_le_bytes());
        future.resize(future.len() + extension, 0);
        checksum(&mut future);
        replace(&backing, A, &future);
        assert!(matches!(
            DurableProofStore::load(&backing, UUID),
            Err(FormatError::Unsupported(_))
        ));
        assert!(matches!(
            DurableProofStore::advance(&backing, &mut proof),
            Err(FormatError::Unsupported(_))
        ));
        assert_eq!(read(&backing, A), future);
        assert_eq!(read(&backing, B), before);
    }
}

#[test]
fn inconsistent_generations_or_locations_are_refused() {
    for case in 0..4 {
        let (backing, mut proof) = setup();
        advance(&backing, &mut proof, 2);
        let a = DurableProof::decode(&read(&backing, A)).unwrap();
        let mut b = a.clone();
        match case {
            0 => {
                b.durable_sequence = 1;
                b.durable_size -= 64;
            }
            1 => {
                b.generation += 1;
                b.durable_sequence = 1;
                b.durable_size -= 64;
            }
            2 => {
                b.generation += 1;
                b.segment_index += 1;
            }
            3 => {
                b.generation += 1;
                b.durable_size += 64;
            }
            _ => unreachable!(),
        }
        replace(&backing, B, &b.encode());
        let before = [read(&backing, A), read(&backing, B)];
        assert!(
            DurableProofStore::load(&backing, UUID).is_err(),
            "case {case}"
        );
        assert!(
            DurableProofStore::advance(&backing, &mut proof).is_err(),
            "case {case}"
        );
        assert_eq!([read(&backing, A), read(&backing, B)], before);
    }
}

#[test]
fn caller_cannot_regress_sequence_or_move_an_unchanged_horizon() {
    let (backing, mut proof) = setup();
    advance(&backing, &mut proof, 2);
    for case in 0..4 {
        let mut candidate = proof.clone();
        match case {
            0 => {
                candidate.durable_sequence -= 1;
                candidate.durable_size -= 64;
            }
            1 => candidate.segment_index += 1,
            2 => candidate.durable_size += 64,
            3 => {
                candidate.durable_sequence += 1;
                candidate.durable_size -= 64;
            }
            _ => unreachable!(),
        }
        let before = [read(&backing, A), read(&backing, B)];
        assert!(
            DurableProofStore::advance(&backing, &mut candidate).is_err(),
            "case {case}"
        );
        assert_eq!([read(&backing, A), read(&backing, B)], before);
    }
}

fn mutation(op: &FaultOp<'_>) -> bool {
    matches!(
        op,
        FaultOp::WriteAt { .. }
            | FaultOp::SetLen { .. }
            | FaultOp::SyncData { .. }
            | FaultOp::SyncDir { .. }
    )
}

#[test]
fn every_metadata_publication_failure_preserves_the_old_ack_and_allows_retry() {
    let (backing, mut proof) = setup();
    let count = Arc::new(AtomicUsize::new(0));
    let counted = count.clone();
    backing.set_fault_hook(Some(Arc::new(move |op| {
        if mutation(op) {
            counted.fetch_add(1, Ordering::SeqCst);
        }
        None
    })));
    advance(&backing, &mut proof, 1);
    let steps = count.load(Ordering::SeqCst);
    assert!(
        steps >= 6,
        "must exercise both proof files and their directory"
    );
    for cut in 1..=steps {
        let (backing, mut proof) = setup();
        advance(&backing, &mut proof, 1);
        proof.durable_sequence = 2;
        proof.durable_size += 64;
        let candidate = proof.clone();
        let seen = AtomicUsize::new(0);
        backing.set_fault_hook(Some(Arc::new(move |op| {
            (mutation(op) && seen.fetch_add(1, Ordering::SeqCst) + 1 == cut)
                .then(|| io::Error::other("proof publication interrupted"))
        })));
        assert!(
            DurableProofStore::advance(&backing, &mut proof).is_err(),
            "cut {cut}"
        );
        assert_eq!(
            proof, candidate,
            "failed operation changed caller's proof at cut {cut}"
        );
        backing.set_fault_hook(None);
        backing.crash_all_lost();
        let recovered = DurableProofStore::load(&backing, UUID).unwrap();
        assert!(
            recovered.durable_sequence >= 1,
            "lost prior ACK at cut {cut}"
        );
        DurableProofStore::advance(&backing, &mut proof).unwrap();
        backing.crash_all_lost();
        for path in [A, B] {
            assert_eq!(
                DurableProof::decode(&read(&backing, path))
                    .unwrap()
                    .durable_sequence,
                2,
                "{path}, cut {cut}"
            );
        }
    }
}

#[test]
fn failed_sync_retry_redirties_the_readable_new_proof_after_process_restart() {
    let (backing, mut proof) = setup();
    advance(&backing, &mut proof, 1);
    proof.durable_sequence = 2;
    proof.durable_size += 64;
    // A is the older side and receives the first newly encoded proof.
    backing.set_fault_hook(Some(Arc::new(|op| match op {
        FaultOp::SyncData { path } if *path == A => Some(io::Error::other("writeback EIO")),
        _ => None,
    })));
    assert!(DurableProofStore::advance(&backing, &mut proof).is_err());
    let mut restarted = DurableProofStore::load(&backing, UUID).unwrap();
    assert_eq!(
        restarted.durable_sequence, 2,
        "new proof is still visible in page cache"
    );
    let durable_other = read(&backing, B);
    assert!(DurableProofStore::advance(&backing, &mut restarted).is_err());
    assert_eq!(
        read(&backing, B),
        durable_other,
        "retry touched the last durable proof before preserving the newer one"
    );
    backing.set_fault_hook(None);
    DurableProofStore::advance(&backing, &mut restarted).unwrap();
    backing.crash_all_lost();
    for path in [A, B] {
        assert_eq!(
            DurableProof::decode(&read(&backing, path))
                .unwrap()
                .durable_sequence,
            2
        );
    }
}

#[test]
fn repairing_a_missing_copy_syncs_its_name_before_success() {
    let (backing, mut proof) = setup();
    advance(&backing, &mut proof, 1);
    backing.remove(A).unwrap();
    backing.sync_dir("journal").unwrap();
    DurableProofStore::advance(&backing, &mut proof).unwrap();
    backing.crash_all_lost();
    backing.remove(B).unwrap();
    assert_eq!(
        DurableProofStore::load(&backing, UUID)
            .unwrap()
            .durable_sequence,
        1
    );
}

#[test]
fn a_valid_stale_side_is_repaired_before_risking_the_newest_proof() {
    let (backing, mut proof) = setup();
    let stale = read(&backing, B);
    advance(&backing, &mut proof, 1);
    replace(&backing, B, &stale);
    proof.durable_sequence = 2;
    proof.durable_size += 64;
    backing.set_partial_write_hook(Some(Arc::new(|op| match op {
        FaultOp::WriteAt { path, .. } if *path == B => {
            Some((24, io::Error::other("torn stale-side update")))
        }
        _ => None,
    })));
    assert!(DurableProofStore::advance(&backing, &mut proof).is_err());
    backing.set_partial_write_hook(None);
    backing.crash_keep_torn_prefix(B, 24);
    assert!(
        DurableProofStore::load(&backing, UUID)
            .unwrap()
            .durable_sequence
            >= 1
    );
}

#[test]
fn codec_is_fixed_size_and_rejects_invalid_horizon_bounds() {
    let initial = DurableProof::initial(UUID);
    let bytes = initial.encode();
    assert_eq!(bytes.len(), 64);
    assert_eq!(DurableProof::decode(&bytes).unwrap(), initial);
    for len in 0..64 {
        assert!(DurableProof::decode(&bytes[..len]).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(DurableProof::decode(&extra).is_err());
    for case in 0..6 {
        let mut invalid = initial.clone();
        match case {
            0 => invalid.durable_size = 80,
            1 => invalid.segment_index = 1,
            2 => {
                invalid.durable_sequence = 1;
                invalid.durable_size = 79;
            }
            3 => {
                invalid.durable_sequence = 1;
                invalid.durable_size = 80;
                invalid.segment_index = u64::MAX;
            }
            4 => {
                invalid.durable_sequence = u64::MAX;
                invalid.durable_size = 80;
            }
            5 => {
                invalid.durable_sequence = 1;
                invalid.durable_size = u64::MAX;
            }
            _ => unreachable!(),
        }
        assert!(
            DurableProof::decode(&invalid.encode()).is_err(),
            "case {case}"
        );
    }
}

#[test]
fn generation_exhaustion_does_not_partially_publish_a_new_horizon() {
    let (backing, mut proof) = setup();
    for (path, generation) in [(A, u64::MAX - 2), (B, u64::MAX - 1)] {
        let mut old = proof.clone();
        old.generation = generation;
        replace(&backing, path, &old.encode());
    }
    proof = DurableProofStore::load(&backing, UUID).unwrap();
    proof.durable_sequence = 1;
    proof.durable_size = 112;
    let before = [read(&backing, A), read(&backing, B)];
    assert!(matches!(
        DurableProofStore::advance(&backing, &mut proof),
        Err(FormatError::Overflow(_))
    ));
    assert_eq!([read(&backing, A), read(&backing, B)], before);
}

#[test]
fn incomplete_initialization_is_not_reported_as_a_successful_mirror() {
    for failed_side in [A, B] {
        let backing = CrashableBacking::new();
        backing.set_fault_hook(Some(Arc::new(move |op| match op {
            FaultOp::SyncData { path } if *path == failed_side => {
                Some(io::Error::other("initial proof sync failed"))
            }
            _ => None,
        })));
        assert!(DurableProofStore::initialize(&backing, UUID).is_err());
        backing.set_fault_hook(None);
        let before = backing.list("journal").unwrap();
        assert!(matches!(
            DurableProofStore::initialize(&backing, UUID),
            Err(FormatError::AlreadyExists(_))
        ));
        assert_eq!(backing.list("journal").unwrap(), before);
    }
}
