//! R5-033: recovery capped each journal segment file at four times the
//! *configured* segment size. A checkpoint never deletes the active
//! segment, so after a clean stop a segment of up to the old size stays on
//! disk, and lowering `backing.journal_segment_size` (by about 4x, e.g.
//! 256 MiB to 16 MiB) made the next attach — and `maki check` — report the
//! clean volume as corrupt. The cap now follows the largest segment size
//! any configuration may use, so it still rejects a file no writer could
//! have produced but never a legitimate older segment.

use std::sync::Arc;

use maki_backing::Backing;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::CrashableBacking;

#[test]
fn a_lowered_segment_size_still_recovers_a_clean_volume() {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0x5e6),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, 65536, 512, 65536 + 64, 64 << 20, 64 << 20).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let mut volume = Volume::recover(
        backing.clone(),
        VolumeOptions {
            journal_segment_size: 64 << 20,
        },
    )
    .unwrap();
    // About 20 MiB of records in the one active segment.
    for i in 0..320u64 {
        volume
            .write_ct(i % 1000, &vec![7u8; 65536 + 16], false)
            .unwrap();
    }
    volume.flush().unwrap();
    volume.checkpoint().unwrap();
    drop(volume);

    let mut volume = Volume::recover(
        backing.clone() as Arc<dyn Backing>,
        VolumeOptions {
            journal_segment_size: 1 << 20,
        },
    )
    .expect("a clean volume was refused after lowering journal_segment_size");
    volume.write_ct(1, &vec![9u8; 65536 + 16], true).unwrap();
    assert_eq!(volume.read_ct(1).unwrap().unwrap().1, vec![9u8; 65536 + 16]);
}
