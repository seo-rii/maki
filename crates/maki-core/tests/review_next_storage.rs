//! BUG-022: journal reclaim must not outrun the durability of the
//! checkpoint state that authorizes it.
//!
//! The failing sequence the audit found: checkpoint 1 succeeds; checkpoint
//! 2's *state* sync fails; the process restarts (its page cache survives);
//! an idle checkpoint reclaims journal; a new FUA write and then a power
//! loss follow. On the original code recovery selected the checkpoint 2
//! state from the page cache, reclaimed the journal against it, and after
//! the power loss reverted to checkpoint 1 whose covering segment was gone,
//! refusing to attach with "base sequence N does not bridge from
//! checkpoint M".
//!
//! Recovery now re-persists the checkpoint state it selects before the
//! writer resumes, and a failed A/B store empties the side it could not
//! sync (so a volatile newer generation is never adopted). Either way the
//! reclaim can only rest on a durable checkpoint. This test drives the full
//! sequence and requires the final recovery to succeed with every
//! FUA-acknowledged unit intact.

use std::io;
use std::sync::Arc;

use maki_backing::Backing;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::checkpoint::{CHECKPOINT_STATE_A, CHECKPOINT_STATE_B};
use maki_format::geometry::Geometry;
use maki_format::superblock::Superblock;
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::{failpoints, CrashableBacking};
use uuid::Uuid;

const CT: usize = 540;

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: 2048,
    }
}

fn new_volume(backing: &Arc<CrashableBacking>) -> Volume {
    maki_format::init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: Uuid::from_u128(0xB022),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, 512, 512, 1024, 512 * 4096, 512 * 4096).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    Volume::recover(backing.clone() as Arc<dyn Backing>, options()).unwrap()
}

fn is_checkpoint_state(path: &str) -> bool {
    path == CHECKPOINT_STATE_A || path == CHECKPOINT_STATE_B
}

#[test]
fn journal_reclaim_never_outruns_checkpoint_state_durability() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new().with_tearing(512));
    let mut volume = new_volume(&backing);

    let first = vec![1u8; CT];
    let second = vec![2u8; CT];
    let third = vec![3u8; CT];

    // Checkpoint 1: fully durable.
    let s1 = volume.write_ct(0, &first, true).unwrap();
    volume.checkpoint().unwrap();
    assert_eq!(volume.checkpoint_sequence(), s1);

    // Checkpoint 2: its data slots are written, but the *state* sync fails.
    let s2 = volume.write_ct(1, &second, true).unwrap();
    backing.set_fault_hook(Some(Arc::new(|op| match op {
        FaultOp::SyncData { path } if is_checkpoint_state(path) => {
            Some(io::Error::other("checkpoint state sync failed"))
        }
        _ => None,
    })));
    assert!(
        volume.checkpoint().is_err(),
        "the checkpoint-state sync failure must surface"
    );
    assert_eq!(volume.checkpoint_sequence(), s1);
    backing.set_fault_hook(None);

    // Process restart (not a power loss): the page cache survives.
    drop(volume);
    let mut volume = Volume::recover(backing.clone() as Arc<dyn Backing>, options())
        .expect("restart recovery must succeed");
    assert!(volume.read_ct(1).unwrap().is_some());

    // An idle checkpoint reclaims journal; it may only rest on a durable
    // checkpoint state.
    volume.checkpoint().unwrap();
    assert!(volume.checkpoint_sequence() >= s2);

    // A new FUA write, then a real power loss.
    let s3 = volume.write_ct(2, &third, true).unwrap();
    drop(volume);
    backing.crash_all_lost();

    // Recovery must not be refused, and every FUA-acknowledged unit is here.
    let volume = Volume::recover(backing.clone() as Arc<dyn Backing>, options())
        .expect("power-loss recovery must not be refused after checkpoint-state loss");
    assert_eq!(volume.read_ct(0).unwrap(), Some((s1, first)));
    assert_eq!(volume.read_ct(1).unwrap(), Some((s2, second)));
    assert_eq!(volume.read_ct(2).unwrap(), Some((s3, third)));
    assert!(volume.journal_durable_sequence() >= s3);
}
