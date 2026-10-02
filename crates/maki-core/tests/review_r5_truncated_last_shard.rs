//! R5-027: when the last shard's data file is found truncated, open marks
//! the slots beyond its end allocated so they read as EIO (they may have
//! held checkpointed data). The last shard of a device whose size is not a
//! multiple of the shard size also covers positions past the device's last
//! unit; those were marked and then reported by the deep check as
//! "unrecoverable" slots of units that do not exist.

use std::sync::Arc;

use maki_backing::Backing;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::{geometry::Geometry, init, layout, superblock::Superblock};
use maki_test_support::CrashableBacking;

#[test]
fn a_truncated_last_shard_reports_only_units_that_exist() {
    let backing = Arc::new(CrashableBacking::new());
    // 12 units of 1 KiB; 8 units per shard, so shard 1 covers units 8..16
    // of which only 8..12 exist.
    let geometry = Geometry::compute(512, 1024, 512, 1032, 12 * 1024, 8 * 1024).unwrap();
    assert_eq!(geometry.num_units(), 12);
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0x7a11),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: geometry.clone(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let mut volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
    volume.write_ct(8, &[0x41; 1032], true).unwrap();
    volume.checkpoint().unwrap();
    drop(volume);

    // Truncate shard 1 right after unit 8's slot (in-shard slot 0).
    let file = backing.open(&layout::shard_data(1), false).unwrap();
    file.set_len(geometry.slot_offset(1)).unwrap();
    file.sync_data().unwrap();

    let report = maki_core::check::deep_check(backing.clone(), 256 << 20).unwrap();
    let all = [&report.errors[..], &report.warnings[..]]
        .concat()
        .join("\n");
    for missing in 12..16 {
        assert!(
            !all.contains(&format!("unit {missing}:"))
                && !all.contains(&format!("unit {missing} ")),
            "unit {missing} does not exist but was reported:\n{all}"
        );
    }
    for damaged in 9..12 {
        assert!(
            all.contains(&format!("unit {damaged}")),
            "unit {damaged} lay beyond the truncation and must be reported:\n{all}"
        );
    }
}
