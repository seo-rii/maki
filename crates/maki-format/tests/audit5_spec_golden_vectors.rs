//! Round-5 audit (docs-spec): which on-disk records have a frozen golden
//! vector.
//!
//! SPEC §43: "Superblocks, allocation maps, shard catalogs, slots, journal
//! records, and checkpoint state use versioned, CRC-protected encodings with
//! frozen golden vectors." CLAUDE.md: "On-disk format changes require a
//! format-version bump + new golden vectors; `tests/golden/*.crc` failing
//! means you broke compatibility."
//!
//! `tests/golden/` freezes six images: the v1 superblock, the slot header,
//! a journal record, the durable mark and the key canary (plaintext and
//! record). Nothing freezes the allocation map, the shard catalog, the
//! checkpoint state, the durable proof, the journal segment header or the
//! v2/v3 superblock envelopes: every test of those codecs goes through the
//! same `encode` and `decode`, so a changed magic, field width, field order
//! or bitmap bit order passes the whole suite and breaks every existing
//! volume.
//!
//! `every_record_spec_43_names_has_a_frozen_vector` fails on the current
//! tree and prints the values to freeze (the payload CRC without the
//! trailing self-checksum, like the existing vectors).

use std::path::PathBuf;

use maki_format::ab::AbRecord;
use maki_format::allocation::AllocationMap;
use maki_format::catalog::ShardCatalog;
use maki_format::checkpoint::CheckpointState;
use maki_format::durable_proof::DurableProof;
use maki_format::geometry::Geometry;
use maki_format::journal::SegmentHeader;
use maki_format::superblock::{
    Superblock, VolumeSuperblock, SUPERBLOCK_VERSION_V2, SUPERBLOCK_VERSION_V3,
};
use uuid::Uuid;

fn uuid1() -> Uuid {
    Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef)
}

/// The CRC the existing golden files hold: over the image without its
/// trailing self-checksum.
fn payload_crc(image: &[u8]) -> u32 {
    crc32fast::hash(&image[..image.len() - 4])
}

fn fixtures() -> Vec<(&'static str, &'static str, u32)> {
    let mut map = AllocationMap::new(67);
    for unit in [0, 7, 32, 35, 63, 65] {
        map.set(unit, true);
    }
    map.set_generation(7);

    let mut catalog = ShardCatalog::new();
    for shard in [1, 5, 9, 0x00ff_ffff] {
        catalog.insert(shard);
    }
    catalog.set_generation(3);

    let mut checkpoint = CheckpointState::default();
    checkpoint.set_generation(11);
    checkpoint.checkpoint_sequence = 0x0102_0304_0506_0708;

    let proof = DurableProof {
        generation: 5,
        volume_uuid: uuid1(),
        durable_sequence: 1000,
        segment_index: 9,
        durable_size: 48 + 32 + 4384,
    };

    let segment = SegmentHeader {
        segment_index: 9,
        volume_uuid: uuid1(),
        base_sequence: 1000,
    };

    let superblock = Superblock {
        generation: 2,
        volume_uuid: uuid1(),
        provider_type: "local-aes-gcm-siv".into(),
        crypto_compatibility_id: "golden-profile-v1".into(),
        key_identity: "vol-key".into(),
        geometry: Geometry::compute(4096, 4096, 512, 4384, 1 << 30, 64 << 20).unwrap(),
        format_version: 1,
        created_unix: 1_700_000_000,
    };
    let envelope = |metadata_version| {
        VolumeSuperblock {
            superblock: superblock.clone(),
            metadata_version,
        }
        .encode()
    };

    vec![
        (
            "allocation maps",
            "allocation_map_v1.crc",
            payload_crc(&AllocationMap::encode(&map)),
        ),
        (
            "shard catalogs",
            "shard_catalog_v1.crc",
            payload_crc(&ShardCatalog::encode(&catalog)),
        ),
        (
            "checkpoint state",
            "checkpoint_state_v1.crc",
            payload_crc(&CheckpointState::encode(&checkpoint)),
        ),
        (
            "durable proof (SPEC §21 layout)",
            "durable_proof_v1.crc",
            payload_crc(&proof.encode()),
        ),
        (
            "journal segment header",
            "segment_header_v1.crc",
            payload_crc(&segment.encode()),
        ),
        (
            "superblock envelope v2",
            "superblock_v2.crc",
            payload_crc(&envelope(SUPERBLOCK_VERSION_V2)),
        ),
        (
            "superblock envelope v3",
            "superblock_v3.crc",
            payload_crc(&envelope(SUPERBLOCK_VERSION_V3)),
        ),
    ]
}

/// The six vectors that exist are the ones the documents can rely on.
#[test]
fn the_golden_directory_holds_exactly_the_six_known_vectors() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    eprintln!("tests/golden: {names:?}");
    assert_eq!(
        names,
        [
            "canary_plaintext_v1.crc",
            "canary_record_v1.crc",
            "durable_mark_v1.crc",
            "journal_record_v1.crc",
            "slot_header_v1.crc",
            "superblock_v1.crc",
        ]
    );
}

/// Fails on the current tree: SPEC §43 names allocation maps, shard catalogs
/// and checkpoint state among the records with frozen golden vectors, and
/// none of them (nor the durable proof, the segment header or the v2/v3
/// envelopes) has one.
#[test]
fn every_record_spec_43_names_has_a_frozen_vector() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden");
    let mut missing = Vec::new();
    for (what, file, crc) in fixtures() {
        match std::fs::read_to_string(dir.join(file)) {
            Ok(text) => {
                let frozen = text.trim().trim_start_matches("0x");
                let frozen = u32::from_str_radix(frozen, 16)
                    .or_else(|_| text.trim().parse::<u32>())
                    .unwrap_or_else(|_| panic!("{file}: not a CRC"));
                assert_eq!(crc, frozen, "{what}: encoding changed ({file})");
            }
            Err(_) => missing.push(format!(
                "{what}: no tests/golden/{file} (would be {crc:#010x})"
            )),
        }
    }
    assert!(
        missing.is_empty(),
        "records without a frozen golden vector:\n  {}",
        missing.join("\n  ")
    );
}
