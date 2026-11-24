#![no_main]
//! Coverage-guided fuzzing of every on-disk decoder. A decoder must reject
//! any corrupt image with an error — never panic, over-allocate, or loop.
//! The first input byte selects the decoder; the rest is the candidate
//! image.

use libfuzzer_sys::fuzz_target;

use maki_format::ab::AbRecord;
use maki_format::allocation::AllocationMap;
use maki_format::canary::KeyCanary;
use maki_format::catalog::ShardCatalog;
use maki_format::checkpoint::CheckpointState;
use maki_format::journal::{DurableMark, SegmentHeader};
use maki_format::slot::SlotHeader;
use maki_format::superblock::Superblock;

fuzz_target!(|data: &[u8]| {
    let Some((&sel, body)) = data.split_first() else {
        return;
    };
    match sel % 8 {
        0 => drop(Superblock::decode(body)),
        1 => drop(SegmentHeader::decode(body)),
        2 => drop(DurableMark::decode(body)),
        3 => drop(KeyCanary::decode(body)),
        4 => drop(SlotHeader::decode(body)),
        5 => drop(<AllocationMap as AbRecord>::decode(body)),
        6 => drop(<ShardCatalog as AbRecord>::decode(body)),
        _ => drop(<CheckpointState as AbRecord>::decode(body)),
    }
});
