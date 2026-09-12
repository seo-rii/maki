//! MAKI-020: the second mirrored publication is part of the FUA boundary.
//! These are additional failure-boundary checks, not evidence of a prior bug.

use std::io;
use std::sync::{Arc, Mutex};

use maki_backing::Backing;
use maki_core::volume::{Volume, VolumeOptions};
use maki_core::CoreError;
use maki_format::durable_proof::{
    DurableProof, DURABLE_PROOF_A, DURABLE_PROOF_B, DURABLE_PROOF_SIZE,
};
use maki_format::{geometry::Geometry, init, layout, superblock::Superblock};
use maki_test_support::{crash_backing::FaultOp, CrashableBacking};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
enum PublicationSync {
    Data(String),
    Directory,
}

fn publication_sync(op: &FaultOp<'_>) -> Option<PublicationSync> {
    match op {
        FaultOp::SyncData { path } if *path == DURABLE_PROOF_A || *path == DURABLE_PROOF_B => {
            Some(PublicationSync::Data((*path).to_owned()))
        }
        FaultOp::SyncDir { dir } if *dir == layout::JOURNAL_DIR => Some(PublicationSync::Directory),
        _ => None,
    }
}

fn attached() -> (Arc<CrashableBacking>, VolumeOptions, Volume) {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: Uuid::new_v4(),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, 512, 512, 544, 512 * 1024, 512 * 64).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let options = VolumeOptions {
        journal_segment_size: 4096,
    };
    let mut volume = Volume::recover(backing.clone(), options.clone()).unwrap();
    // Create the segment and establish H1 before tracing or arming faults.
    volume.write_ct(0, &[1; 540], true).unwrap();
    assert_eq!(volume.journal_durable_sequence(), 1);
    (backing, options, volume)
}

/// Observe an entire successful H2 publication before selecting its final
/// file or directory barrier. This excludes unrelated initialization/roll I/O.
fn successful_publication() -> Vec<PublicationSync> {
    let (backing, _options, mut volume) = attached();
    let operations = Arc::new(Mutex::new(Vec::new()));
    let observed = operations.clone();
    backing.set_fault_hook(Some(Arc::new(move |op| {
        if let Some(op) = publication_sync(op) {
            observed.lock().unwrap().push(op);
        }
        None
    })));
    volume.write_ct(1, &[2; 540], true).unwrap();
    backing.set_fault_hook(None);
    let operations = operations.lock().unwrap().clone();
    let paths: Vec<_> = operations
        .iter()
        .filter_map(|op| match op {
            PublicationSync::Data(path) => Some(path),
            _ => None,
        })
        .collect();
    assert_eq!(
        paths.len(),
        4,
        "two stores each sync their preserved side and new side"
    );
    assert_ne!(paths[0], paths[1]);
    assert_eq!(
        paths[0], paths[3],
        "the second store replaces the first preserved side"
    );
    assert_eq!(
        paths[1], paths[2],
        "the second store first preserves the newly advanced side"
    );
    assert_eq!(
        operations
            .iter()
            .filter(|op| **op == PublicationSync::Directory)
            .count(),
        4
    );
    assert_eq!(operations.last(), Some(&PublicationSync::Directory));
    operations
}

#[derive(Default)]
struct Observation {
    steps: Vec<PublicationSync>,
    matching_syncs: usize,
    fired: bool,
}

fn check_failed_final_barrier(directory: bool) {
    let expected = successful_publication();
    let is_target = |op: &PublicationSync| matches!(op, PublicationSync::Directory) == directory;
    let target_count = expected.iter().filter(|op| is_target(op)).count();
    assert_eq!(target_count, 4);
    let cut_index = expected.iter().rposition(is_target).unwrap();

    let (backing, options, mut volume) = attached();
    let observation = Arc::new(Mutex::new(Observation::default()));
    let observed = observation.clone();
    backing.set_fault_hook(Some(Arc::new(move |op| {
        let op = publication_sync(op)?;
        let matching = matches!(&op, PublicationSync::Directory) == directory;
        let mut observed = observed.lock().unwrap();
        observed.steps.push(op);
        if matching {
            observed.matching_syncs += 1;
            if observed.matching_syncs == target_count {
                observed.fired = true;
                return Some(io::Error::other("final mirrored proof barrier failed"));
            }
        }
        None
    })));

    let result = volume.write_ct(1, &[2; 540], true);
    assert!(
        matches!(result, Err(CoreError::Io(_))),
        "final barrier failure must deny FUA: {result:?}"
    );
    {
        let observed = observation.lock().unwrap();
        assert!(
            observed.fired,
            "the intended final barrier must actually fail"
        );
        assert_eq!(observed.matching_syncs, target_count);
        assert_eq!(
            observed.steps,
            expected[..=cut_index],
            "failure must occur at the observed final publication boundary"
        );
    }
    assert_eq!(volume.journal_appended_sequence(), 2);
    assert_eq!(
        volume.journal_durable_sequence(),
        1,
        "neither data sync nor a readable H2 can acknowledge the failed FUA"
    );
    assert!(
        volume.checkpoint().unwrap() <= 1,
        "unproved H2 cannot enter a checkpoint"
    );
    assert!(volume.checkpoint_sequence() <= 1);
    assert_eq!(
        volume.journal_durable_sequence(),
        1,
        "checkpoint must leave the failed proof publication for the explicit flush retry"
    );

    backing.set_fault_hook(None);
    volume.flush().unwrap(); // no new append: this must retry and heal BOTH copies
    assert_eq!(volume.journal_appended_sequence(), 2);
    assert_eq!(volume.journal_durable_sequence(), 2);
    drop(volume);
    backing.crash_all_lost();

    // Check both physical copies before recovery can repair either of them.
    // Loading only the highest A/B record would conceal an unhealed second side.
    let mut proofs = Vec::new();
    for path in [DURABLE_PROOF_A, DURABLE_PROOF_B] {
        let file = backing.open(path, false).unwrap();
        assert_eq!(file.len().unwrap(), DURABLE_PROOF_SIZE as u64);
        let mut bytes = [0; DURABLE_PROOF_SIZE];
        file.read_at(0, &mut bytes).unwrap();
        let proof = DurableProof::decode(&bytes).unwrap();
        assert_eq!(
            proof.durable_sequence, 2,
            "{path} must attest H2 after power loss"
        );
        proofs.push(proof);
    }
    assert_eq!(proofs[0].volume_uuid, proofs[1].volume_uuid);
    assert_eq!(proofs[0].segment_index, proofs[1].segment_index);
    assert_eq!(proofs[0].durable_size, proofs[1].durable_size);

    let recovered = Volume::recover(backing, options).unwrap();
    assert_eq!(recovered.read_ct(0).unwrap().unwrap().1, vec![1; 540]);
    assert_eq!(recovered.read_ct(1).unwrap().unwrap().1, vec![2; 540]);
    assert_eq!(recovered.journal_durable_sequence(), 2);
}

#[test]
fn second_proof_file_sync_failure_denies_fua_and_flush_heals_both_copies() {
    check_failed_final_barrier(false);
}

#[test]
fn final_proof_directory_sync_failure_denies_fua_and_flush_heals_both_copies() {
    check_failed_final_barrier(true);
}
