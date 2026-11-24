#![no_main]
//! Round-8 audit target (not in the repository). The committed
//! `format_decoders` target feeds raw bytes: every decoder verifies a CRC-32
//! first, so a coverage-guided fuzzer never gets past the checksum except
//! with an unmodified seed. This variant repairs the trailing CRC of the
//! frame the decoder will check, so field validation behind it is reached,
//! and adds two invariants on every accepted image:
//!   1. re-encoding the decoded record never panics, and
//!   2. the re-encoded image decodes to the same record (a record the A/B
//!      store rewrites from its decoded form must stay itself).
//! Selector 8 = durable proof, 9 = volume superblock envelope (both absent
//! from the committed target).

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
fn fix(frame: &mut [u8]) {
    if frame.len() >= 4 {
        let n = frame.len() - 4;
        let crc = crc32fast::hash(&frame[..n]);
        frame[n..].copy_from_slice(&crc.to_le_bytes());
    }
}

/// Fixed-size frames are checked on a prefix of the input.
fn fix_prefix(body: &mut [u8], size: usize) {
    if body.len() >= size {
        fix(&mut body[..size]);
    }
}

fn ab<T: AbRecord + PartialEq + std::fmt::Debug>(body: &[u8]) {
    if let Ok(rec) = T::decode(body) {
        let again = rec.encode();
        let back = T::decode(&again).expect("a re-encoded record must decode");
        assert_eq!(back, rec, "re-encoded record decodes differently");
        assert!(
            again.len() as u64 <= T::MAX_ENCODED_LEN,
            "encoding exceeds the record's own bound"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, body)) = data.split_first() else {
        return;
    };
    let mut body = body.to_vec();
    match sel % 10 {
        0 => {
            fix_prefix(&mut body, 4096);
            if let Ok(sb) = Superblock::decode(&body) {
                let again = sb.encode();
                assert_eq!(again.len(), 4096);
                // `encode` writes the v1 envelope; the model must survive it.
                assert_eq!(Superblock::decode(&again).expect("re-decode"), sb);
            }
        }
        1 => {
            fix_prefix(&mut body, 48);
            if let Ok(h) = SegmentHeader::decode(&body) {
                assert_eq!(SegmentHeader::decode(&h.encode()).expect("re-decode"), h);
            }
        }
        2 => {
            fix_prefix(&mut body, 32);
            if let Ok(m) = DurableMark::decode(&body) {
                assert_eq!(DurableMark::decode(&m.encode()).expect("re-decode"), m);
            }
        }
        3 => {
            fix(&mut body);
            ab::<KeyCanary>(&body);
        }
        4 => {
            fix_prefix(&mut body, 64);
            if let Ok(h) = SlotHeader::decode(&body) {
                assert_eq!(SlotHeader::decode(&h.encode()).expect("re-decode"), h);
            }
        }
        5 => {
            fix(&mut body);
            if let Ok(map) = <AllocationMap as AbRecord>::decode(&body) {
                let again = AbRecord::encode(&map);
                let back = <AllocationMap as AbRecord>::decode(&again).expect("re-decode");
                assert_eq!(AbRecord::encode(&back), again);
                assert_eq!(back.units(), map.units());
                assert_eq!(back.set_count(), map.set_count());
                // No unit at or beyond `units` may ever be reported set.
                assert!(map.set_count() <= map.units());
                assert_eq!(
                    map.set_units(u64::MAX).count() as u64,
                    map.set_count(),
                    "set_units and set_count disagree"
                );
                assert_eq!(AllocationMap::encoded_len(map.units()), again.len() as u64);
            }
        }
        6 => {
            fix(&mut body);
            ab::<ShardCatalog>(&body);
        }
        7 => {
            fix(&mut body);
            ab::<CheckpointState>(&body);
        }
        8 => {
            fix(&mut body);
            ab::<DurableProof>(&body);
        }
        _ => {
            fix_prefix(&mut body, 4096);
            ab::<VolumeSuperblock>(&body);
        }
    }
});
