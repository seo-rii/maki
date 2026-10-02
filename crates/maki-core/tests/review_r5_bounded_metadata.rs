//! R5-025: allocation maps, discard maps and the shard catalog were read
//! with the generic 1 GiB record bound, so an over-long (corrupt or
//! tampered) copy was read into memory in full before decoding rejected
//! it. Their valid sizes follow from the geometry; a longer copy is
//! invalid by its length alone and is never read.

use std::sync::Arc;

use maki_backing::Backing;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::{geometry::Geometry, init, layout, superblock::Superblock};
use maki_test_support::CrashableBacking;

const PADDING: u64 = 4 << 20;

#[test]
fn over_long_metadata_copies_are_rejected_without_reading_them() {
    let backing = Arc::new(CrashableBacking::new());
    let geometry = Geometry::compute(512, 1024, 512, 1032, 16 * 1024, 8 * 1024).unwrap();
    init::create_volume_with_discard(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xb0b),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry,
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let mut volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
    volume.write_ct(1, &[0x41; 1032], true).unwrap();
    volume.checkpoint().unwrap();
    drop(volume);

    // Grow one copy of each record far past any valid size.
    for path in [
        layout::SHARD_CATALOG_A.to_string(),
        layout::shard_alloc_a(0),
        layout::shard_discard_a(0),
    ] {
        let file = backing.open(&path, false).unwrap();
        let len = file.len().unwrap();
        file.set_len(len + PADDING).unwrap();
        file.sync_data().unwrap();
    }

    let before = backing.read_bytes();
    let recovered = Volume::recover(backing.clone(), VolumeOptions::default());
    let read = backing.read_bytes() - before;
    assert!(
        read < PADDING,
        "recovery read {read} bytes: an over-long metadata copy was read in full"
    );
    // The other copy of each record is intact, so the volume still opens.
    let recovered = recovered.unwrap();
    assert_eq!(recovered.read_ct(1).unwrap().unwrap().1, vec![0x41; 1032]);
}
