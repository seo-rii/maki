//! Adjacent fixed slots share filesystem blocks. Reclaiming a run should
//! release its interior blocks rather than leaving every shared edge allocated.
#![cfg(target_os = "linux")]

use std::os::unix::fs::MetadataExt;
use std::sync::Arc;

use maki_backing::{Backing, FileBacking};
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::{geometry::Geometry, init, layout, superblock::Superblock};

#[test]
fn contiguous_discard_reclaims_shared_blocks_and_preserves_neighbors() {
    let directory = tempfile::tempdir().unwrap();
    let backing = Arc::new(FileBacking::new(directory.path()).unwrap());
    let probe = backing.open("punch-probe", true).unwrap();
    probe.write_at(0, &[0x11; 8192]).unwrap();
    if let Err(error) = probe.punch_hole(0, 8192) {
        if error.kind() == std::io::ErrorKind::Unsupported {
            eprintln!("filesystem does not support hole punching: {error}");
            return;
        }
        panic!("hole-punch probe failed: {error}");
    }
    drop(probe);
    backing.remove("punch-probe").unwrap();

    let geometry = Geometry::compute(512, 4096, 512, 4104, 1 << 20, 1 << 20).unwrap();
    assert_eq!(geometry.slot_size, 4608);
    init::create_volume_with_discard(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xdec1a1),
            provider_type: "test".into(),
            crypto_compatibility_id: "opaque".into(),
            key_identity: "k".into(),
            geometry,
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let mut volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
    for unit in 0..128 {
        volume.write_ct(unit, &[0x71; 4104], false).unwrap();
    }
    volume.flush().unwrap();
    volume.checkpoint().unwrap();
    let path = directory.path().join(layout::shard_data(0));
    let before = std::fs::metadata(&path).unwrap();
    for unit in 1..127 {
        volume.discard_ct(unit, false).unwrap();
    }
    volume.flush().unwrap();
    volume.checkpoint().unwrap();
    let after = std::fs::metadata(&path).unwrap();
    assert_eq!(after.len(), before.len());
    assert!(
        after.blocks() < before.blocks() / 4,
        "trimmed 126/128 slots but retained {} of {} allocated blocks",
        after.blocks(),
        before.blocks()
    );
    drop(volume);
    let mut recovered = Volume::recover(backing, VolumeOptions::default()).unwrap();
    for unit in [0, 127] {
        assert_eq!(
            recovered.read_ct(unit).unwrap().unwrap().1,
            vec![0x71; 4104]
        );
    }
    for unit in 1..127 {
        assert!(recovered.read_ct(unit).unwrap().is_none());
    }
    recovered.write_ct(64, &[0x72; 4104], true).unwrap();
    recovered.checkpoint().unwrap();
    assert_eq!(recovered.read_ct(64).unwrap().unwrap().1, vec![0x72; 4104]);
    assert!(recovered.read_ct(63).unwrap().is_none());
    assert!(recovered.read_ct(65).unwrap().is_none());
}
