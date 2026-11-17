//! A checkpoint state above the required durable proof.
//!
//! A record becomes checkpoint-eligible only after both proof copies attest
//! it (SPEC §25), and recovery publishes the proof before it advances the
//! checkpoint, so `checkpoint_sequence` never exceeds the proof's
//! `durable_sequence` on a v2/v3 volume. A CRC-valid checkpoint state that
//! does used to be accepted: recovery treated every journal record at or
//! below it as applied, FUA-acknowledged units read zeros, the next
//! checkpoint pruned their journal, and the deep check reported the volume
//! clean. Both must refuse the contradiction before any recovery write.

use std::sync::{Arc, Mutex};

use uuid::Uuid;

use maki_backing::Backing;
use maki_core::check::deep_check;
use maki_core::recovery::RecoveryError;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::ab::AbStore;
use maki_format::checkpoint::{CheckpointState, CHECKPOINT_STATE_A, CHECKPOINT_STATE_B};
use maki_format::durable_proof::DurableProofStore;
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::CrashableBacking;

const SEGMENT: u64 = 4096;
const UUID: u128 = 0x5eb1_c0ad;

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: SEGMENT,
    }
}

fn ct(stamp: u8) -> Vec<u8> {
    vec![stamp; 540]
}

/// Two FUA-acknowledged writes (sequences 1 and 2), never checkpointed.
fn volume_with_two_fua_writes(discard: bool) -> Arc<CrashableBacking> {
    let backing = Arc::new(CrashableBacking::new());
    let superblock = Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(UUID),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, 512, 512, 544, 512 * 128, 512 * 48).unwrap(),
        format_version: 1,
        created_unix: 0,
    };
    if discard {
        init::create_volume_with_discard(backing.as_ref(), superblock).unwrap();
    } else {
        init::create_volume(backing.as_ref(), superblock).unwrap();
    }
    let mut volume = Volume::recover(backing.clone() as Arc<dyn Backing>, options()).unwrap();
    assert_eq!(volume.write_ct(3, &ct(0x33), true).unwrap(), 1);
    assert_eq!(volume.write_ct(4, &ct(0x44), true).unwrap(), 2);
    drop(volume);
    let proof = DurableProofStore::load(backing.as_ref(), Uuid::from_u128(UUID)).unwrap();
    assert_eq!(
        proof.durable_sequence, 2,
        "the proof attests both FUA writes"
    );
    backing
}

/// Publish a checkpoint state through the ordinary A/B store: a CRC-valid,
/// newer-generation copy, exactly as the writer itself stores one.
fn set_checkpoint_sequence(backing: &CrashableBacking, sequence: u64) {
    let ab = AbStore::new(CHECKPOINT_STATE_A, CHECKPOINT_STATE_B);
    let mut state: CheckpointState = ab.load(backing).unwrap().unwrap();
    state.checkpoint_sequence = sequence;
    ab.store(backing, &mut state).unwrap();
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

#[test]
fn checkpoint_above_the_durable_proof_is_refused_by_recovery_and_the_deep_check() {
    for discard in [false, true] {
        for checkpoint in [3, 1000] {
            let backing = volume_with_two_fua_writes(discard);
            set_checkpoint_sequence(&backing, checkpoint);
            let what = format!("v{} checkpoint {checkpoint}", if discard { 3 } else { 2 });

            let mutations = observe_mutations(&backing);
            let report = deep_check(backing.clone() as Arc<dyn Backing>, SEGMENT).unwrap();
            let recovered = Volume::recover(backing.clone() as Arc<dyn Backing>, options());
            backing.set_fault_hook(None);

            assert!(
                report.errors.iter().any(|e| e.contains("durable proof")),
                "{what}: the deep check passed a checkpoint above the durable proof: \
                 errors {:?}",
                report.errors
            );
            match recovered {
                Err(RecoveryError::Corrupt(error)) => {
                    assert!(error.contains("durable proof"), "{what}: {error}")
                }
                Err(error) => panic!("{what}: expected corruption, got {error}"),
                Ok(volume) => panic!(
                    "{what}: recovery accepted it; unit 3 reads {:?}, unit 4 reads {:?}",
                    volume.read_ct(3).unwrap().map(|(seq, data)| (seq, data[0])),
                    volume.read_ct(4).unwrap().map(|(seq, data)| (seq, data[0])),
                ),
            }
            let mutations = mutations.lock().unwrap();
            assert!(
                mutations.is_empty(),
                "{what}: storage changed before the refusal: {mutations:?}"
            );
        }
    }
}

/// The refusal leaves the evidence intact: restoring the honest checkpoint
/// state recovers both acknowledged writes.
#[test]
fn refused_checkpoint_horizon_leaves_the_acknowledged_journal_intact() {
    let backing = volume_with_two_fua_writes(false);
    set_checkpoint_sequence(&backing, 1000);
    assert!(Volume::recover(backing.clone() as Arc<dyn Backing>, options()).is_err());

    set_checkpoint_sequence(&backing, 0);
    let volume = Volume::recover(backing.clone() as Arc<dyn Backing>, options()).unwrap();
    assert_eq!(volume.read_ct(3).unwrap(), Some((1, ct(0x33))));
    assert_eq!(volume.read_ct(4).unwrap(), Some((2, ct(0x44))));
}
