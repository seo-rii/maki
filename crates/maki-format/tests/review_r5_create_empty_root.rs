//! R5-018: `create_volume` refused only an existing superblock. A root that
//! still held an earlier volume's shard files (superblocks removed by hand,
//! a partial restore, a leftover layout) was initialized around them, and
//! `SlotStore::open` then adopted the orphans: slot headers carry no volume
//! UUID, so the new volume served the old ciphertext (EIO under an AEAD
//! provider, garbage under XTS) where it should read zeros.

use maki_backing::{Backing, MemBacking};
use maki_format::error::FormatError;
use maki_format::geometry::Geometry;
use maki_format::init::{create_volume, create_volume_with_discard};
use maki_format::superblock::Superblock;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(0x5eed),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, 1024, 512, 1032, 16 * 1024, 8 * 1024).unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn leftover(path: &str) -> MemBacking {
    let backing = MemBacking::new();
    let (dir, _) = path.split_once('/').unwrap();
    backing.create_dir_all(dir).unwrap();
    let file = backing.open(path, true).unwrap();
    file.write_at(0, b"an earlier volume's bytes").unwrap();
    file.sync_data().unwrap();
    backing
}

#[test]
fn a_root_with_leftover_volume_files_is_refused() {
    for path in [
        "data/shard-00000000.dat",
        "journal/segment-00000000.log",
        "checkpoint/state.a",
    ] {
        for discard in [false, true] {
            let backing = leftover(path);
            let result = if discard {
                create_volume_with_discard(&backing, superblock())
            } else {
                create_volume(&backing, superblock())
            };
            match result {
                Err(FormatError::AlreadyExists(message)) => {
                    assert!(message.contains(path), "{path}: {message}")
                }
                other => panic!("{path}: a non-empty root was initialized: {other:?}"),
            }
            assert!(
                !backing.exists("superblock.a").unwrap(),
                "{path}: nothing may be written into a refused root"
            );
        }
    }
}

#[test]
fn an_empty_root_is_still_initialized() {
    let backing = MemBacking::new();
    create_volume(&backing, superblock()).unwrap();
    // Empty layout directories from an earlier `mkdir` are fine too.
    let backing = MemBacking::new();
    for dir in ["data", "journal", "checkpoint"] {
        backing.create_dir_all(dir).unwrap();
    }
    create_volume_with_discard(&backing, superblock()).unwrap();
}
