//! A shard data file the loaded catalog copy does not list is adopted at
//! open. When that file is shorter than its physical size, the allocation
//! map decides what it is (SPEC §22): with an empty map the shard was never
//! checkpointed into and its holes stay holes; a map that lists a slot
//! proves a finished creation, so the file was truncated and every cleared
//! slot beyond its end reads EIO. The bitmap's last byte has padding bits
//! past the shard's last unit when the unit count is not a multiple of
//! eight, and in a partial last shard the positions past the device's last
//! unit name no unit either. A map whose only set bits are padding or such
//! positions is empty, and the deep check and attach must both treat the
//! shard as unwritten.

use std::ops::Range;
use std::sync::Arc;

use uuid::Uuid;

use maki_backing::Backing;
use maki_core::check::deep_check;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::ab::AbStore;
use maki_format::allocation::AllocationMap;
use maki_format::canary::{KeyCanary, CANARY_UNIT_INDEX};
use maki_format::geometry::Geometry;
use maki_format::superblock::Superblock;
use maki_format::{init, layout};
use maki_test_support::CrashableBacking;

/// Five units per shard: the bitmap's single byte has three padding bits.
const UNITS_PER_SHARD: u64 = 5;
/// Seven units: shard 1 holds units 5 and 6, and its positions 2..=4
/// (units 7..=9) lie past the device's last unit.
const NUM_UNITS: u64 = 7;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0x9add_1e05),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(
            512,
            1024,
            512,
            1032,
            NUM_UNITS * 1024,
            UNITS_PER_SHARD * 1024,
        )
        .unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

/// The device's units in `shard`.
fn units_of(shard: u64) -> Range<u64> {
    assert_eq!(superblock().geometry.num_units(), NUM_UNITS);
    shard * UNITS_PER_SHARD..((shard + 1) * UNITS_PER_SHARD).min(NUM_UNITS)
}

/// A volume whose `shard` exists only as a zero-length data file next to
/// two CRC-valid allocation copies holding `bitmap` as their only byte.
fn volume_with_short_orphan(shard: u64, bitmap: u8) -> Arc<CrashableBacking> {
    let block = superblock();
    assert_eq!(block.geometry.units_per_shard(), UNITS_PER_SHARD);
    let volume_uuid = block.volume_uuid;
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), block).unwrap();

    // An engine binds its key canary before it can create a shard. Without
    // one, even an unwritten shard makes the volume non-pristine, with no
    // ciphertext available to prove the key: a separate attach refusal.
    let canary_ab = AbStore::new(layout::KEY_CANARY_A, layout::KEY_CANARY_B);
    let mut canary = KeyCanary {
        generation: 0,
        volume_uuid,
        unit_index: CANARY_UNIT_INDEX,
        ciphertext: vec![0x5a; 64],
    };
    canary_ab.store(backing.as_ref(), &mut canary).unwrap();
    canary_ab.store(backing.as_ref(), &mut canary).unwrap();

    let mut image = AllocationMap::new(UNITS_PER_SHARD).encode();
    let n = image.len();
    image[n - 5] = bitmap;
    let crc = crc32fast::hash(&image[..n - 4]);
    image[n - 4..].copy_from_slice(&crc.to_le_bytes());
    for path in [layout::shard_alloc_a(shard), layout::shard_alloc_b(shard)] {
        let file = backing.open(&path, true).unwrap();
        file.write_at(0, &image).unwrap();
        file.sync_data().unwrap();
    }
    let data = backing.open(&layout::shard_data(shard), true).unwrap();
    assert_eq!(data.len().unwrap(), 0);
    data.sync_data().unwrap();
    backing.sync_dir(layout::DATA_DIR).unwrap();
    backing.sync_dir("").unwrap();
    backing
}

fn recover(backing: &Arc<CrashableBacking>) -> Volume {
    Volume::recover(
        backing.clone() as Arc<dyn Backing>,
        VolumeOptions::default(),
    )
    .unwrap()
}

fn deep_errors(backing: &Arc<CrashableBacking>) -> Vec<String> {
    deep_check(
        backing.clone() as Arc<dyn Backing>,
        VolumeOptions::default().journal_segment_size,
    )
    .unwrap()
    .errors
}

/// The deep check finds nothing and every unit of `shard` reads as a hole.
fn assert_unwritten(shard: u64, bitmap: u8) {
    let backing = volume_with_short_orphan(shard, bitmap);
    let errors = deep_errors(&backing);
    assert!(
        errors.is_empty(),
        "shard {shard}, bitmap {bitmap:#010b}: deep check: a shard with no allocated unit is \
         unwritten: {errors:?}"
    );
    let volume = recover(&backing);
    for unit in units_of(shard) {
        assert!(
            matches!(volume.read_ct(unit), Ok(None)),
            "shard {shard}, bitmap {bitmap:#010b}: unit {unit} of a never-finished shard reads \
             as a hole, got {:?}",
            volume
                .read_ct(unit)
                .map(|ct| ct.map(|(sequence, _)| sequence))
        );
    }
}

#[test]
fn padding_bits_do_not_make_a_never_finished_shard_truncated() {
    // Every padding bit set, no unit allocated.
    assert_unwritten(0, 0b1110_0000);
}

#[test]
fn positions_past_the_device_end_do_not_make_a_never_finished_shard_truncated() {
    // Shard 1's positions past the device's last unit: the first and the
    // last alone, all of them, and all of them with the padding bits.
    for bitmap in [0b0000_0100, 0b0001_0000, 0b0001_1100, 0b1111_1100] {
        assert_unwritten(1, bitmap);
    }
}

/// Control: the same short orphan with a map that lists a real unit is
/// truncated, so the classification above is the one under test. In the
/// partial last shard this holds for its last unit too, set next to a
/// position past the device's end.
#[test]
fn a_listed_unit_still_makes_a_short_orphan_truncated() {
    for (shard, bitmap) in [(0, 0b0000_0001), (1, 0b0000_0001), (1, 0b0001_0010)] {
        let backing = volume_with_short_orphan(shard, bitmap);
        assert!(
            !deep_errors(&backing).is_empty(),
            "shard {shard}, bitmap {bitmap:#010b}: deep check: a truncated shard's cleared \
             slots beyond its end are damage"
        );
        let volume = recover(&backing);
        for unit in units_of(shard) {
            assert!(
                volume.read_ct(unit).is_err(),
                "shard {shard}, bitmap {bitmap:#010b}: unit {unit} of a truncated shard reads EIO"
            );
        }
    }
}
