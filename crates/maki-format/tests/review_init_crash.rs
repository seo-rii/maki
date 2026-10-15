//! BUG-100: `create_volume` published both superblock copies before the
//! shard catalog, the checkpoint state and the durable mark. A crash in
//! between left a root that looked initialized (create refuses it: "volume
//! superblock already present") but could not attach either (no catalog, no
//! checkpoint state). The superblock is the commit point: when either copy
//! survives a power loss, everything attach requires survives with it.

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use maki_backing::Backing;
use maki_format::ab::AbStore;
use maki_format::catalog::ShardCatalog;
use maki_format::checkpoint::{CheckpointState, CHECKPOINT_STATE_A, CHECKPOINT_STATE_B};
use maki_format::durable_proof::DurableProofStore;
use maki_format::geometry::Geometry;
use maki_format::init::{create_volume, create_volume_with_discard};
use maki_format::layout;
use maki_format::superblock::{load_volume_superblock, Superblock};
use maki_test_support::crash_backing::{CrashableBacking, FaultOp};

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(0x1417),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, 1024, 512, 1032, 16 * 1024, 8 * 1024).unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn create(backing: &CrashableBacking, discard: bool) -> Result<Superblock, String> {
    let result = if discard {
        create_volume_with_discard(backing, superblock())
    } else {
        create_volume(backing, superblock())
    };
    result.map_err(|error| error.to_string())
}

/// The process dies at operation `cut`: it and every later operation fail.
fn die_at(backing: &CrashableBacking, cut: usize) {
    let seen = Arc::new(AtomicUsize::new(0));
    backing.set_fault_hook(Some(Arc::new(move |_op: &FaultOp<'_>| {
        (seen.fetch_add(1, Ordering::SeqCst) >= cut).then(|| io::Error::other("process died"))
    })));
}

fn operations_in_a_clean_create(discard: bool) -> usize {
    let backing = CrashableBacking::new();
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = seen.clone();
    backing.set_fault_hook(Some(Arc::new(move |_op: &FaultOp<'_>| {
        counter.fetch_add(1, Ordering::SeqCst);
        None
    })));
    create(&backing, discard).unwrap();
    seen.load(Ordering::SeqCst)
}

/// Everything attach requires of an initialized volume.
fn attachable(backing: &dyn Backing) -> Result<(), String> {
    let superblock = load_volume_superblock(backing).map_err(|e| format!("superblock: {e}"))?;
    AbStore::new(layout::SHARD_CATALOG_A, layout::SHARD_CATALOG_B)
        .load::<ShardCatalog>(backing)
        .map_err(|e| format!("catalog: {e}"))?
        .ok_or("no shard catalog")?;
    AbStore::new(CHECKPOINT_STATE_A, CHECKPOINT_STATE_B)
        .load::<CheckpointState>(backing)
        .map_err(|e| format!("checkpoint state: {e}"))?
        .ok_or("no checkpoint state")?;
    DurableProofStore::load(backing, superblock.superblock.volume_uuid)
        .map_err(|e| format!("durable proof: {e}"))?;
    if !backing
        .exists(layout::JOURNAL_DURABLE_MARK)
        .map_err(|e| e.to_string())?
    {
        return Err("no journal durable mark".into());
    }
    Ok(())
}

#[test]
fn a_crash_during_creation_never_publishes_a_superblock_without_its_volume() {
    for discard in [false, true] {
        let total = operations_in_a_clean_create(discard);
        assert!(total > 10, "the sweep must see the whole creation");
        for cut in 0..=total {
            let backing = CrashableBacking::new();
            die_at(&backing, cut);
            let created = create(&backing, discard);
            assert_eq!(created.is_ok(), cut == total, "cut {cut}: {created:?}");
            backing.set_fault_hook(None);
            backing.crash_all_lost();

            let superblock_survived = backing.exists(layout::SUPERBLOCK_A).unwrap()
                || backing.exists(layout::SUPERBLOCK_B).unwrap();
            if superblock_survived {
                if let Err(missing) = attachable(&backing) {
                    panic!(
                        "discard {discard}, cut {cut}/{total}: a superblock survived the crash \
                         but the volume cannot attach: {missing}"
                    );
                }
            }
            if cut == total {
                attachable(&backing).expect("a completed creation is durable");
            }
        }
    }
}
