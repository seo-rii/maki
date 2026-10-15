//! BUG-109: the superblock decoder read its `flags` field and discarded it,
//! and accepted any crypto `format_version`. Both exist so a later format
//! can mark itself incompatible; a binary that ignores them would open such
//! a volume and interpret it with this version's rules. This version writes
//! no flags and format version 1, and refuses anything else.

use maki_format::geometry::Geometry;
use maki_format::superblock::{Superblock, VolumeSuperblock, SUPERBLOCK_SIZE};
use maki_format::FormatError;
use uuid::Uuid;

/// Byte offsets in the frozen v1 layout (see the `superblock` module doc).
const FORMAT_VERSION: usize = 80;
const FLAGS: usize = 92;

fn superblock() -> Superblock {
    Superblock {
        generation: 1,
        volume_uuid: Uuid::from_u128(0x109),
        provider_type: "local-aes-gcm-siv".into(),
        crypto_compatibility_id: "profile-v1".into(),
        key_identity: "key-1".into(),
        geometry: Geometry::compute(4096, 4096, 512, 4384, 16 << 30, 1 << 30).unwrap(),
        format_version: 1,
        created_unix: 1_756_684_800,
    }
}

fn patched(offset: usize, value: &[u8]) -> Vec<u8> {
    let mut bytes = superblock().encode();
    bytes[offset..offset + value.len()].copy_from_slice(value);
    let crc = crc32fast::hash(&bytes[..SUPERBLOCK_SIZE - 4]);
    bytes[SUPERBLOCK_SIZE - 4..].copy_from_slice(&crc.to_le_bytes());
    bytes
}

#[test]
fn the_frozen_offsets_hold_what_this_test_patches() {
    let bytes = superblock().encode();
    assert_eq!(
        &bytes[FORMAT_VERSION..FORMAT_VERSION + 4],
        &1u32.to_le_bytes()
    );
    assert_eq!(&bytes[FLAGS..FLAGS + 8], &[0; 8]);
    assert_eq!(Superblock::decode(&bytes).unwrap(), superblock());
}

#[test]
fn unknown_flags_are_refused() {
    for flag in [1u64, 1 << 63] {
        let bytes = patched(FLAGS, &flag.to_le_bytes());
        for result in [
            Superblock::decode(&bytes).map(|_| ()),
            VolumeSuperblock::decode(&bytes).map(|_| ()),
        ] {
            assert!(
                matches!(result, Err(FormatError::Unsupported(_))),
                "flags {flag:#x}: {result:?}"
            );
        }
    }
}

#[test]
fn an_unknown_crypto_format_version_is_refused() {
    for version in [0u32, 2, u32::MAX] {
        let bytes = patched(FORMAT_VERSION, &version.to_le_bytes());
        let result = Superblock::decode(&bytes);
        assert!(
            matches!(result, Err(FormatError::Unsupported(_))),
            "format_version {version}: {result:?}"
        );
    }
}
