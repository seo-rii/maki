//! An allocation bitmap ends on a byte boundary: when a shard's unit count
//! is not a multiple of eight, the last byte holds padding bits past the
//! last unit. No writer sets them (`AllocationMap::new` starts clear and
//! `set` refuses a unit out of range), but the decoder never looked at them
//! and `set_count` counted every set bit. A CRC-valid map whose only set
//! bits were padding therefore reported allocations no unit has, which is
//! the evidence `SlotStore::open` uses to tell a never-finished shard from a
//! truncated one (SPEC §22). The decoder keeps accepting such an image (an
//! older or foreign writer's padding must not make a copy invalid) but
//! padding never reaches the decoded map.

use maki_format::ab::AbRecord;
use maki_format::allocation::AllocationMap;

/// Bytes before the bitmap: magic, version, generation, units.
const BITMAP_OFFSET: usize = 8 + 4 + 8 + 8;

fn recrc(image: &mut [u8]) {
    let n = image.len();
    let crc = crc32fast::hash(&image[..n - 4]);
    image[n - 4..].copy_from_slice(&crc.to_le_bytes());
}

/// A map over `units` units with `allocated` set, at generation 7.
fn map(units: u64, allocated: &[u64]) -> AllocationMap {
    let mut map = AllocationMap::new(units);
    for unit in allocated {
        map.set(*unit, true);
    }
    map.set_generation(7);
    map
}

/// `map`'s encoding with every padding bit of the last bitmap byte set.
fn with_padding_set(map: &AllocationMap) -> Vec<u8> {
    let units = map.units();
    assert_ne!(units % 8, 0, "this geometry has no padding bits");
    let mut image = map.encode();
    let last = BITMAP_OFFSET + units.div_ceil(8) as usize - 1;
    assert_eq!(
        last,
        image.len() - 5,
        "the last bitmap byte precedes the CRC"
    );
    image[last] |= 0xffu8 << (units % 8);
    recrc(&mut image);
    image
}

#[test]
fn padding_bits_are_not_allocated_units() {
    for (units, allocated) in [
        (1u64, vec![]),
        (3, vec![]),
        (5, vec![0]),
        (5, vec![4]),
        (1001, vec![]),
        (1001, vec![0, 999, 1000]),
    ] {
        let expected = map(units, &allocated);
        let image = with_padding_set(&expected);
        let decoded = AllocationMap::decode(&image)
            .unwrap_or_else(|e| panic!("{units} units: a CRC-valid padded map stays valid: {e}"));
        assert_eq!(
            decoded.set_count(),
            allocated.len() as u64,
            "{units} units, {allocated:?} allocated: padding counted as allocations"
        );
        assert_eq!(
            decoded, expected,
            "{units} units, {allocated:?} allocated: padding bits reached the decoded map"
        );
        assert_eq!(
            decoded.encode(),
            expected.encode(),
            "{units} units: re-storing a decoded map writes its padding clear"
        );
    }
}

#[test]
fn canonical_maps_decode_unchanged() {
    for (units, allocated) in [
        (5u64, vec![0, 2, 4]),
        (8, vec![0, 7]),
        (1001, vec![1, 500, 1000]),
        (4096, vec![1, 4000]),
    ] {
        let expected = map(units, &allocated);
        let image = expected.encode();
        let decoded = AllocationMap::decode(&image).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(decoded.set_count(), allocated.len() as u64);
        assert_eq!(decoded.encode(), image, "{units} units: round trip");
    }
}
