//! Round-8 audit (native-nbdkit, found by the creation power-loss sweep):
//! a `create_volume` that dies between creating `superblock.a` and writing
//! it leaves an empty `superblock.a`. The next `create_volume` then refuses
//! the root with "volume superblock already present", and nothing can attach
//! it ("no valid superblock").
//!
//! `docs/operations.md` describes two outcomes of an interrupted creation:
//! no superblock copy (not a volume; `volume create` refuses the leftovers
//! until the root is emptied) and "once a copy is readable, a retried
//! `volume create` reports `volume superblock already present`: the root is
//! a complete volume". This is neither: a copy exists, is not readable, and
//! is reported as "already present".
//!
//! The process death here is a kill, not a power loss: nothing the dead
//! process wrote is dropped. (A power loss that keeps the new directory
//! entry and not the file's bytes gives the same root; the round-8 probe
//! `create_pl.py` reaches it through the real `maki volume create` and the
//! real plugin.)

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use maki_backing::Backing;
use maki_format::geometry::Geometry;
use maki_format::init::{create_volume, create_volume_with_discard};
use maki_format::layout;
use maki_format::superblock::{load_volume_superblock, Superblock};
use maki_test_support::crash_backing::{CrashableBacking, FaultOp};

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(0x0A8),
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

#[test]
fn a_creation_killed_at_any_operation_never_reports_a_present_superblock_that_cannot_be_read() {
    let mut stuck = Vec::new();
    for discard in [false, true] {
        let total = operations_in_a_clean_create(discard);
        assert!(total > 10, "the sweep must see the whole creation");
        for cut in 0..total {
            let backing = CrashableBacking::new();
            // The process dies at operation `cut`: it and every later one fail.
            let seen = Arc::new(AtomicUsize::new(0));
            backing.set_fault_hook(Some(Arc::new(move |_op: &FaultOp<'_>| {
                (seen.fetch_add(1, Ordering::SeqCst) >= cut)
                    .then(|| io::Error::other("process died"))
            })));
            assert!(create(&backing, discard).is_err(), "cut {cut}");
            backing.set_fault_hook(None);

            // A kill: the next process sees everything the dead one wrote.
            let readable = load_volume_superblock(&backing).map_err(|e| e.to_string());
            let exists = |name: &str| backing.exists(name).unwrap();
            let copies = (exists(layout::SUPERBLOCK_A), exists(layout::SUPERBLOCK_B));
            let retried = create(&backing, discard);
            if let (Err(attach), Err(again)) = (&readable, &retried) {
                if again.contains("superblock already present") {
                    stuck.push(format!(
                        "discard {discard}, cut {cut}/{total}: superblock copies present (a, b) = {copies:?}; \
                         create again: {again:?}; load: {attach:?}"
                    ));
                }
            }
        }
    }
    assert!(
        stuck.is_empty(),
        "a killed creation left a root that `create` reports as holding a superblock and that \
         has no readable one:\n{}",
        stuck.join("\n")
    );
}
