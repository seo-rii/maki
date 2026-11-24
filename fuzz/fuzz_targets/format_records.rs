#![no_main]
//! Coverage-guided fuzzing of what the on-disk decoders of `maki-format` do
//! behind their checksum. Every decoder verifies a CRC-32 before it looks at
//! a field, so a fuzzer that feeds raw bytes (`format_decoders`) stays in
//! front of it. This target makes the last four bytes of the frame the
//! decoder will check the CRC-32 of the bytes before them, and then requires
//! of every image a decoder accepts:
//!
//! 1. the decoded record encodes again without a panic, within the record
//!    type's own length bound;
//! 2. that encoding decodes to the same record. The A/B store rewrites a
//!    record from its decoded form, so a record that does not survive the
//!    round trip changes on its next store.
//!
//! The first input byte selects the record type; the rest is the candidate
//! image.

use libfuzzer_sys::fuzz_target;

use maki_format::ab::AbRecord;
use maki_format::allocation::AllocationMap;
use maki_format::canary::KeyCanary;
use maki_format::catalog::ShardCatalog;
use maki_format::checkpoint::CheckpointState;
use maki_format::durable_proof::DurableProof;
use maki_format::journal::{DurableMark, SegmentHeader};
use maki_format::slot::SlotHeader;
use maki_format::superblock::{Superblock, VolumeSuperblock};

/// Make the last four bytes of `frame` the CRC-32 of the bytes before them.
fn repair(frame: &mut [u8]) {
    if frame.len() >= 4 {
        let payload = frame.len() - 4;
        let crc = crc32fast::hash(&frame[..payload]);
        frame[payload..].copy_from_slice(&crc.to_le_bytes());
    }
}

/// A fixed-size frame is checked on a prefix of the input.
fn repair_prefix(body: &mut [u8], size: usize) {
    if body.len() >= size {
        repair(&mut body[..size]);
    }
}

fn round_trip<T: AbRecord + PartialEq + std::fmt::Debug>(body: &[u8]) {
    if let Ok(record) = T::decode(body) {
        let again = record.encode();
        assert!(
            again.len() as u64 <= T::MAX_ENCODED_LEN,
            "an accepted record encodes beyond its type's bound"
        );
        let back = T::decode(&again).expect("an accepted record must decode again");
        assert_eq!(back, record, "an accepted record changed in a round trip");
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, body)) = data.split_first() else {
        return;
    };
    let mut body = body.to_vec();
    match sel % 10 {
        0 => {
            repair_prefix(&mut body, 4096);
            if let Ok(superblock) = Superblock::decode(&body) {
                let again = superblock.encode();
                assert_eq!(again.len(), 4096);
                assert_eq!(Superblock::decode(&again).expect("decode again"), superblock);
            }
        }
        1 => {
            repair_prefix(&mut body, 48);
            if let Ok(header) = SegmentHeader::decode(&body) {
                assert_eq!(
                    SegmentHeader::decode(&header.encode()).expect("decode again"),
                    header
                );
            }
        }
        2 => {
            repair_prefix(&mut body, 32);
            if let Ok(mark) = DurableMark::decode(&body) {
                assert_eq!(
                    DurableMark::decode(&mark.encode()).expect("decode again"),
                    mark
                );
            }
        }
        3 => {
            repair(&mut body);
            round_trip::<KeyCanary>(&body);
        }
        4 => {
            repair_prefix(&mut body, 64);
            if let Ok(header) = SlotHeader::decode(&body) {
                assert_eq!(
                    SlotHeader::decode(&header.encode()).expect("decode again"),
                    header
                );
            }
        }
        5 => {
            repair(&mut body);
            if let Ok(map) = <AllocationMap as AbRecord>::decode(&body) {
                let again = AbRecord::encode(&map);
                assert_eq!(AllocationMap::encoded_len(map.units()), again.len() as u64);
                let back = <AllocationMap as AbRecord>::decode(&again).expect("decode again");
                assert_eq!(AbRecord::encode(&back), again);
                assert_eq!(back.units(), map.units());
                // No unit at or beyond `units` is ever reported as set.
                assert!(map.set_count() <= map.units());
                assert_eq!(map.set_units(u64::MAX).count() as u64, map.set_count());
            }
        }
        6 => {
            repair(&mut body);
            round_trip::<ShardCatalog>(&body);
        }
        7 => {
            repair(&mut body);
            round_trip::<CheckpointState>(&body);
        }
        8 => {
            repair(&mut body);
            round_trip::<DurableProof>(&body);
        }
        _ => {
            repair_prefix(&mut body, 4096);
            round_trip::<VolumeSuperblock>(&body);
        }
    }
});
