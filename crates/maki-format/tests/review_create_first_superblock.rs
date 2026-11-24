//! A creation writes both superblock copies last. The first copy used to be
//! created under its own name and then written, so a creation that stopped
//! between the two (a kill, a failed write, a power loss that kept the
//! directory entry and not the bytes) left a `superblock.a` that held no
//! superblock. Such a root is neither of the two outcomes the guide
//! describes: `volume create` refused it as "volume superblock already
//! present", from the name alone, while everything that needs the volume
//! said "no valid superblock".
//!
//! A superblock name must never hold anything but a superblock. And a
//! root in which a superblock file exists that holds none, as an earlier
//! release can have left it, must be refused for what it is: it is also
//! what a used volume whose copies are damaged looks like, so it is never
//! initialized again.

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use maki_backing::{Backing, MemBacking};
use maki_format::error::FormatError;
use maki_format::geometry::Geometry;
use maki_format::init::{create_volume, create_volume_with_discard};
use maki_format::layout;
use maki_format::superblock::{load_volume_superblock, Superblock};
use maki_test_support::CrashableBacking;
use rand::{rngs::StdRng, SeedableRng};

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

fn create(backing: &dyn Backing, discard: bool) -> Result<Superblock, FormatError> {
    if discard {
        create_volume_with_discard(backing, superblock())
    } else {
        create_volume(backing, superblock())
    }
}

fn machine() -> CrashableBacking {
    CrashableBacking::new().with_tearing(512)
}

fn operations(discard: bool) -> usize {
    let backing = machine();
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = seen.clone();
    backing.set_fault_hook(Some(Arc::new(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
        None
    })));
    create(backing.process().as_ref(), discard).unwrap();
    seen.load(Ordering::SeqCst)
}

/// The creation stops before operation `cut`, and the machine then loses
/// power (`Some`) or only the process died.
fn interrupted(discard: bool, cut: usize, power_loss: Option<u64>) -> CrashableBacking {
    let backing = machine();
    let seen = Arc::new(AtomicUsize::new(0));
    backing.set_fault_hook(Some(Arc::new(move |_| {
        (seen.fetch_add(1, Ordering::SeqCst) >= cut).then(|| io::Error::other("process died"))
    })));
    let _ = create(backing.process().as_ref(), discard);
    backing.set_fault_hook(None);
    match power_loss {
        None => {}
        Some(0) => backing.crash_all_lost(),
        Some(seed) => backing.crash(&mut StdRng::seed_from_u64(seed)),
    }
    backing
}

/// Wherever a creation stops, a superblock file that exists holds a
/// superblock: the root is either a volume or holds no superblock file.
#[test]
fn a_superblock_name_never_holds_anything_but_a_superblock() {
    let mut wrong = Vec::new();
    for discard in [false, true] {
        let total = operations(discard);
        assert!(total > 10, "the sweep must see the whole creation");
        for cut in 0..=total {
            for power_loss in [None, Some(0), Some(1), Some(2), Some(3)] {
                let backing = interrupted(discard, cut, power_loss);
                let view = backing.process();
                let copies = [layout::SUPERBLOCK_A, layout::SUPERBLOCK_B]
                    .map(|name| view.exists(name).unwrap());
                let loaded = load_volume_superblock(view.as_ref());
                if copies.contains(&true) && loaded.is_err() {
                    wrong.push(format!(
                        "discard {discard}, cut {cut}/{total}, power loss {power_loss:?}: copies \
                         (a, b) = {copies:?}, load: {:?}, create again: {:?}",
                        loaded.err().map(|error| error.to_string()),
                        create(view.as_ref(), discard)
                            .err()
                            .map(|error| error.to_string())
                    ));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// A superblock file that holds no superblock, as an earlier release left
/// one, is refused as that: with both causes, what the operator may do,
/// and nothing changed. A root that holds a superblock keeps its refusal.
#[test]
fn a_superblock_file_that_holds_none_is_refused_as_that_and_left_alone() {
    for (name, bytes) in [
        (layout::SUPERBLOCK_A, &[][..]),
        (layout::SUPERBLOCK_A, &[0u8; 4096][..]),
        (layout::SUPERBLOCK_B, &b"damaged"[..]),
    ] {
        let backing = MemBacking::new();
        let file = backing.open(name, true).unwrap();
        file.write_at(0, bytes).unwrap();
        file.set_len(bytes.len() as u64).unwrap();
        let error = create(&backing, false).unwrap_err();
        assert!(matches!(error, FormatError::AlreadyExists(_)), "{error}");
        let text = error.to_string();
        assert!(
            text.contains("holds no valid superblock")
                && text.contains("never attached")
                && text.contains("damaged"),
            "{text}"
        );
        // Nothing but the lock that every creation takes first was added.
        let mut left = backing.list("").unwrap();
        left.retain(|entry| entry != layout::VOLUME_LOCK);
        assert_eq!(left, [name], "{name}");
        assert_eq!(file.len().unwrap(), bytes.len() as u64);
    }
    let backing = MemBacking::new();
    create(&backing, false).unwrap();
    let error = create(&backing, false).unwrap_err().to_string();
    assert!(
        error.contains("volume superblock already present"),
        "{error}"
    );
}
