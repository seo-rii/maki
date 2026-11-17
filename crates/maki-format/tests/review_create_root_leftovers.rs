//! `create_volume` refused an existing superblock and any file in the layout
//! directories (R5-018), but accepted the other root-level metadata of an
//! earlier volume: `canary.a`/`canary.b` and `shard-catalog.a`/`.b`. A stale
//! key canary made the new volume's first attach fail with "key canary
//! verification failed: canary belongs to a different volume", pointing the
//! operator at the key instead of the leftover file; a stale catalog copy
//! stayed the fallback side until the first catalog commit replaced it.

use maki_backing::{Backing, MemBacking};
use maki_format::error::FormatError;
use maki_format::geometry::Geometry;
use maki_format::init::{create_volume, create_volume_with_discard};
use maki_format::layout;
use maki_format::superblock::Superblock;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(0x1ef7),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, 1024, 512, 1032, 16 * 1024, 8 * 1024).unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn create(backing: &MemBacking, discard: bool) -> Result<Superblock, FormatError> {
    if discard {
        create_volume_with_discard(backing, superblock())
    } else {
        create_volume(backing, superblock())
    }
}

fn leftover(path: &str) -> MemBacking {
    let backing = MemBacking::new();
    let file = backing.open(path, true).unwrap();
    file.write_at(0, b"an earlier volume's metadata").unwrap();
    file.sync_data().unwrap();
    backing.sync_dir("").unwrap();
    backing
}

#[test]
fn a_root_with_an_earlier_volumes_root_metadata_is_refused() {
    for path in [
        layout::KEY_CANARY_A,
        layout::KEY_CANARY_B,
        layout::SHARD_CATALOG_A,
        layout::SHARD_CATALOG_B,
    ] {
        for discard in [false, true] {
            let backing = leftover(path);
            match create(&backing, discard) {
                Err(FormatError::AlreadyExists(message)) => {
                    assert!(message.contains(path), "{path}: {message}")
                }
                other => panic!("{path}: a root with leftover metadata was initialized: {other:?}"),
            }
            // Only the lock, taken before the checks, may have been added.
            let mut names = backing.list("").unwrap();
            names.retain(|name| name != layout::VOLUME_LOCK);
            assert_eq!(
                names,
                [path.to_string()],
                "{path}: nothing may be written into a refused root"
            );
        }
    }
}

#[test]
fn a_leftover_volume_lock_does_not_block_creation() {
    // The lock carries no volume state, and creation takes it first.
    for discard in [false, true] {
        let backing = leftover(layout::VOLUME_LOCK);
        create(&backing, discard).unwrap();
    }
}
