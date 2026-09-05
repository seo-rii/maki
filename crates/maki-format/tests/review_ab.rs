//! Fifth pass (N-09): the A/B store after a failed sync.
//!
//! `store` writes the stale side and syncs it. On Linux a failed sync
//! leaves the new record visible in the page cache but unpersisted, so the
//! retry saw that side as the newer generation and overwrote the *other*
//! side: the only copy proven durable. A crash tearing the retry then left
//! one torn side and one side two generations old, losing metadata that
//! had been acknowledged durable. The retry must go back to the side whose
//! sync failed.
//!
//! A crash "during the retry" is modelled by letting the retry's own sync
//! fail in the lenient mode (its write stays pending) and then tearing that
//! pending write; 20 bytes of it land, enough to damage the generation
//! field so the record no longer decodes.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use maki_backing::Backing;
use maki_format::ab::AbStore;
use maki_format::checkpoint::{CheckpointState, CHECKPOINT_STATE_A, CHECKPOINT_STATE_B};
use maki_format::layout;
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::CrashableBacking;

/// Fail the next `n` syncs of either checkpoint-state side.
fn fail_syncs(backing: &CrashableBacking, n: usize) {
    let remaining = Arc::new(AtomicUsize::new(n));
    backing.set_fault_hook(Some(Arc::new(move |op| match op {
        FaultOp::SyncData { path }
            if *path == CHECKPOINT_STATE_A || *path == CHECKPOINT_STATE_B =>
        {
            let left = remaining.load(Ordering::SeqCst);
            if left > 0 {
                remaining.store(left - 1, Ordering::SeqCst);
                Some(std::io::Error::other("injected writeback error"))
            } else {
                None
            }
        }
        _ => None,
    })));
}

fn loaded_sequence(backing: &CrashableBacking, ab: &AbStore) -> u64 {
    ab.load::<CheckpointState>(backing)
        .unwrap()
        .expect("one valid copy must survive")
        .checkpoint_sequence
}

#[test]
fn a_failed_sync_never_makes_the_last_durable_copy_the_next_target() {
    let backing = CrashableBacking::new();
    backing.create_dir_all(layout::CHECKPOINT_DIR).unwrap();
    let ab = AbStore::new(CHECKPOINT_STATE_A, CHECKPOINT_STATE_B);
    let mut state = CheckpointState::default();
    state.checkpoint_sequence = 1;
    ab.store(&backing, &mut state).unwrap(); // generation 1, side A
    state.checkpoint_sequence = 2;
    ab.store(&backing, &mut state).unwrap(); // generation 2, side B
    backing.sync_dir(layout::CHECKPOINT_DIR).unwrap();
    assert_eq!(loaded_sequence(&backing, &ab), 2);

    // The next store's sync fails (Linux: its bytes stay visible but
    // unpersisted).
    fail_syncs(&backing, 1);
    state.checkpoint_sequence = 3;
    assert!(ab.store(&backing, &mut state).is_err());

    // The retry's write reaches the page cache and the machine dies before
    // its sync completes, tearing it.
    backing.set_lenient_sync_failures(true);
    fail_syncs(&backing, 1);
    let target = ab
        .next_target_path::<CheckpointState>(&backing)
        .unwrap()
        .to_string();
    state.checkpoint_sequence = 4;
    assert!(ab.store(&backing, &mut state).is_err());
    backing.crash_keep_torn_prefix(&target, 20);

    assert!(
        loaded_sequence(&backing, &ab) >= 2,
        "acknowledged generation 2 lost after a torn retry of {target}: loaded {}",
        loaded_sequence(&backing, &ab)
    );
}

/// The ordinary path is unchanged: alternating sides, the newest copy wins,
/// and a torn write only ever destroys the copy being replaced.
#[test]
fn stores_alternate_sides_and_a_torn_write_costs_only_the_stale_side() {
    let backing = CrashableBacking::new();
    backing.create_dir_all(layout::CHECKPOINT_DIR).unwrap();
    let ab = AbStore::new(CHECKPOINT_STATE_A, CHECKPOINT_STATE_B);
    let mut state = CheckpointState::default();
    for sequence in 1..=4 {
        state.checkpoint_sequence = sequence;
        ab.store(&backing, &mut state).unwrap();
    }
    backing.sync_dir(layout::CHECKPOINT_DIR).unwrap();
    assert_eq!(loaded_sequence(&backing, &ab), 4);

    backing.set_lenient_sync_failures(true);
    fail_syncs(&backing, 1);
    let target = ab
        .next_target_path::<CheckpointState>(&backing)
        .unwrap()
        .to_string();
    assert_eq!(target, CHECKPOINT_STATE_A, "generation 4 sits on side B");
    state.checkpoint_sequence = 5;
    assert!(ab.store(&backing, &mut state).is_err());
    backing.crash_keep_torn_prefix(&target, 20);
    assert_eq!(loaded_sequence(&backing, &ab), 4);
}
