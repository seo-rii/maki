//! Audit round 3 (PR #184 `fix/codec-canonical-20261117`): the decoder now
//! masks the bitmap's padding bits because "they name no unit" and, counted,
//! "would make an empty map look like one that lists a slot" (the
//! adopted-short-shard rule in `SlotStore::open`). In a *partial last shard*
//! the in-shard positions past the device's last unit name no unit either
//! (`allocated_units`, `unlisted_units` and the truncation marking all skip
//! them, R5-027), yet `set_count` still counts them. A CRC-valid map whose
//! only set bit is such a position flips the never-finished-shard decision
//! exactly as padding did before the fix.

use std::sync::Arc;

use uuid::Uuid;

use maki_backing::Backing;
use maki_core::check::deep_check;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::allocation::AllocationMap;
use maki_format::geometry::Geometry;
use maki_format::superblock::Superblock;
use maki_format::{init, layout};
use maki_test_support::CrashableBacking;

/// Five units per shard, seven units: shard 1 holds units 5 and 6 only
/// (in-shard 0 and 1); in-shard 2..=4 lie past the device's end.
const UNITS_PER_SHARD: u64 = 5;
const NUM_UNITS: u64 = 7;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xa3_be70_0d),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, 1024, 512, 1032, NUM_UNITS * 1024, 5 * 1024).unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

/// Shard 1 exists only as a zero-length data file (never cataloged) next to
/// two CRC-valid allocation copies holding `bitmap` as their only byte.
fn volume_with_short_orphan_last_shard(bitmap: u8) -> Arc<CrashableBacking> {
    let block = superblock();
    assert_eq!(block.geometry.units_per_shard(), UNITS_PER_SHARD);
    assert_eq!(block.geometry.num_units(), NUM_UNITS);
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), block).unwrap();

    let mut image = AllocationMap::new(UNITS_PER_SHARD).encode();
    let n = image.len();
    image[n - 5] = bitmap;
    let crc = crc32fast::hash(&image[..n - 4]);
    image[n - 4..].copy_from_slice(&crc.to_le_bytes());
    for path in [layout::shard_alloc_a(1), layout::shard_alloc_b(1)] {
        let file = backing.open(&path, true).unwrap();
        file.write_at(0, &image).unwrap();
        file.sync_data().unwrap();
    }
    let data = backing.open(&layout::shard_data(1), true).unwrap();
    assert_eq!(data.len().unwrap(), 0);
    data.sync_data().unwrap();
    backing.sync_dir(layout::DATA_DIR).unwrap();
    backing.sync_dir("").unwrap();
    backing
}

fn reads(backing: &Arc<CrashableBacking>) -> Vec<String> {
    let volume = Volume::recover(
        backing.clone() as Arc<dyn Backing>,
        VolumeOptions::default(),
    )
    .unwrap();
    (UNITS_PER_SHARD..NUM_UNITS)
        .map(|unit| match volume.read_ct(unit) {
            Ok(None) => format!("unit {unit}: hole"),
            Ok(Some(_)) => format!("unit {unit}: data"),
            Err(error) => format!("unit {unit}: error {error}"),
        })
        .collect()
}

fn deep_errors(backing: &Arc<CrashableBacking>) -> Vec<String> {
    deep_check(
        backing.clone() as Arc<dyn Backing>,
        VolumeOptions::default().journal_segment_size,
    )
    .unwrap()
    .errors
}

/// Control (mirrors the PR's own test): padding bits alone leave the shard
/// unwritten after the fix.
#[test]
fn control_padding_bits_alone_leave_the_last_shard_unwritten() {
    let backing = volume_with_short_orphan_last_shard(0b1110_0000);
    assert!(deep_errors(&backing).is_empty());
    assert_eq!(reads(&backing), ["unit 5: hole", "unit 6: hole"]);
}

/// Only in-shard position 4 (unit 9, past the device's last unit 6) is set:
/// it names no unit, so the shard is as unwritten as with padding bits.
#[test]
fn bits_past_the_device_end_alone_leave_the_last_shard_unwritten() {
    let backing = volume_with_short_orphan_last_shard(0b0001_0000);
    let errors = deep_errors(&backing);
    let reads = reads(&backing);
    assert!(
        errors.is_empty() && reads == ["unit 5: hole", "unit 6: hole"],
        "a map whose only set bit lies past the device's end made a never-finished \
         shard 'truncated': deep check errors {errors:?}, reads {reads:?}"
    );
}
