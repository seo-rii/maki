#![no_main]
//! Coverage-guided fuzzing of every on-disk decoder of `maki-format`, on raw
//! bytes. A decoder must reject any corrupt image with an error — never
//! panic, over-allocate, or loop. The first input byte selects the decoder;
//! the rest is the candidate image.
//!
//! Every decoder checks a magic, a length and a CRC-32 before it looks at a
//! field, and a fuzzer starting from an empty corpus almost never produces
//! an image that passes them: this target exercises those checks.
//! `format_records` repairs the checksum first and exercises what lies
//! behind it. The journal's record frames have their own target,
//! `journal_scan`.

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

fuzz_target!(|data: &[u8]| {
    let Some((&sel, body)) = data.split_first() else {
        return;
    };
    match sel % 10 {
        0 => drop(Superblock::decode(body)),
        1 => drop(SegmentHeader::decode(body)),
        2 => drop(DurableMark::decode(body)),
        3 => drop(KeyCanary::decode(body)),
        4 => drop(SlotHeader::decode(body)),
        5 => drop(<AllocationMap as AbRecord>::decode(body)),
        6 => drop(<ShardCatalog as AbRecord>::decode(body)),
        7 => drop(<CheckpointState as AbRecord>::decode(body)),
        8 => drop(<DurableProof as AbRecord>::decode(body)),
        _ => drop(<VolumeSuperblock as AbRecord>::decode(body)),
    }
});
