//! Frozen golden vectors for the allocation map (also the v3 discard map),
//! the shard catalog, the checkpoint state, the durable proof, the journal
//! segment header, the journal record header and the v2/v3 superblock
//! envelopes (SPEC §43).
//!
//! Each expected image is written out byte by byte from the documented
//! layout (SPEC §14 and §21 and the codec modules' comments) instead of being
//! produced by the encoder. Encoder and decoder change together, so a round
//! trip still passes after a changed magic, field order, field width, byte
//! order or bitmap bit order; these images do not.
//!
//! `golden/*.crc` holds the CRC-32 of an image without its trailing
//! self-checksum (the CRC of a whole self-checksummed image is the same
//! constant for any content), which is also the value that trailer stores.
//! If a test here fails, you broke on-disk compatibility.

use std::collections::BTreeSet;
use std::path::Path;

use uuid::Uuid;

use maki_format::ab::AbRecord;
use maki_format::allocation::AllocationMap;
use maki_format::catalog::ShardCatalog;
use maki_format::checkpoint::CheckpointState;
use maki_format::durable_proof::{DurableProof, DURABLE_PROOF_SIZE};
use maki_format::geometry::Geometry;
use maki_format::journal::{
    encode_record, encode_record_parts, scan_segment_bounded, JournalRecord, ScanOutcome,
    SegmentHeader, RECORD_HEADER_SIZE, SEGMENT_HEADER_SIZE,
};
use maki_format::superblock::{
    Superblock, VolumeSuperblock, SUPERBLOCK_SIZE, SUPERBLOCK_VERSION, SUPERBLOCK_VERSION_V2,
    SUPERBLOCK_VERSION_V3,
};

/// Compare an encoded record with its hand-assembled `layout` (the image
/// without the trailing CRC-32) and with its frozen value.
fn assert_frozen(what: &str, encoded: &[u8], layout: &[u8], frozen: u32) {
    let (body, trailer) = encoded.split_at(encoded.len() - 4);
    assert_eq!(
        body, layout,
        "{what}: the encoding differs from the documented layout"
    );
    let crc = crc32fast::hash(body);
    assert_eq!(crc, frozen, "{what} encoding changed! crc={crc:#010x}");
    assert_eq!(
        trailer,
        frozen.to_le_bytes(),
        "{what}: the trailer is the little-endian CRC-32 of the bytes before it"
    );
}

/// The complete hand-assembled image: layout, then its CRC-32.
fn image(layout: &[u8], frozen: u32) -> Vec<u8> {
    [layout, &frozen.to_le_bytes()].concat()
}

// ---------- allocation map (and discard map) ----------

const ALLOCATED_UNITS: [u64; 10] = [0, 3, 9, 16, 17, 30, 39, 40, 58, 65];

#[rustfmt::skip]
const ALLOCATION_MAP_LAYOUT: [u8; 37] = [
    b'M', b'A', b'K', b'I', b'A', b'L', b'C', b'1',
    // version u32 = 1
    0x01, 0x00, 0x00, 0x00,
    // generation u64 = 0x0102_0304_0506_0708
    0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
    // units u64 = 67
    0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // bitmap, ceil(67 / 8) = 9 bytes: unit `u` is bit `u % 8` of byte
    // `u / 8`, least significant bit first; the last byte's bits 3..8 are
    // padding and stay clear
    0x09, 0x02, 0x03, 0x40, 0x80, 0x01, 0x00, 0x04, 0x02,
];

/// The v1 allocation-map encoding is frozen. A v3 volume's per-shard
/// discard map (`data/shard-<n>.discard.{a,b}`) is this same record.
#[test]
fn allocation_map_golden_vector_frozen() {
    let mut map = AllocationMap::new(67);
    for unit in ALLOCATED_UNITS {
        map.set(unit, true);
    }
    map.set_generation(0x0102_0304_0506_0708);

    let frozen: u32 = include!("golden/allocation_map_v1.crc");
    let bytes = AllocationMap::encode(&map);
    // SPEC §14: 32 bytes around ceil(units / 8) bytes of bitmap.
    assert_eq!(bytes.len(), 32 + 9);
    assert_eq!(bytes.len() as u64, AllocationMap::encoded_len(67));
    assert_frozen("allocation map", &bytes, &ALLOCATION_MAP_LAYOUT, frozen);

    let decoded = AllocationMap::decode(&image(&ALLOCATION_MAP_LAYOUT, frozen)).unwrap();
    assert_eq!(decoded, map);
    assert_eq!(decoded.generation(), 0x0102_0304_0506_0708);
    assert_eq!(decoded.units(), 67);
    assert_eq!(
        decoded.set_units(u64::MAX).collect::<Vec<_>>(),
        ALLOCATED_UNITS
    );
}

// ---------- shard catalog ----------

#[rustfmt::skip]
const SHARD_CATALOG_LAYOUT: [u8; 48] = [
    b'M', b'A', b'K', b'I', b'C', b'A', b'T', b'1',
    // version u32 = 1
    0x01, 0x00, 0x00, 0x00,
    // generation u64 = 0x1112_1314_1516_1718
    0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
    // shard count u32 = 3
    0x03, 0x00, 0x00, 0x00,
    // shard indexes, u64 each, strictly ascending: 3, 0x0102, 0x00A1_B2C3
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC3, 0xB2, 0xA1, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// The v1 shard-catalog encoding is frozen.
#[test]
fn shard_catalog_golden_vector_frozen() {
    let mut catalog = ShardCatalog::new();
    // Inserted out of order: the encoding lists shards in ascending order.
    for shard in [0x00A1_B2C3, 3, 0x0102] {
        catalog.insert(shard);
    }
    catalog.set_generation(0x1112_1314_1516_1718);

    let frozen: u32 = include!("golden/shard_catalog_v1.crc");
    let bytes = ShardCatalog::encode(&catalog);
    // SPEC §14: 28 bytes around 8 bytes per shard.
    assert_eq!(bytes.len(), 28 + 8 * 3);
    assert_eq!(bytes.len() as u64, ShardCatalog::max_encoded_len(3));
    assert_frozen("shard catalog", &bytes, &SHARD_CATALOG_LAYOUT, frozen);

    let decoded = ShardCatalog::decode(&image(&SHARD_CATALOG_LAYOUT, frozen)).unwrap();
    assert_eq!(decoded, catalog);
    assert_eq!(decoded.generation(), 0x1112_1314_1516_1718);
    assert_eq!(
        decoded.shard_indices().collect::<Vec<_>>(),
        [3, 0x0102, 0x00A1_B2C3]
    );
}

// ---------- checkpoint state ----------

#[rustfmt::skip]
const CHECKPOINT_STATE_LAYOUT: [u8; 28] = [
    b'M', b'A', b'K', b'I', b'C', b'K', b'P', b'1',
    // version u32 = 1
    0x01, 0x00, 0x00, 0x00,
    // generation u64 = 0x2122_2324_2526_2728
    0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21,
    // checkpoint_sequence u64 = 0x3132_3334_3536_3738
    0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31,
];

/// The v1 checkpoint-state encoding is frozen: a fixed 32 bytes.
#[test]
fn checkpoint_state_golden_vector_frozen() {
    let mut state = CheckpointState::default();
    state.checkpoint_sequence = 0x3132_3334_3536_3738;
    state.set_generation(0x2122_2324_2526_2728);

    let frozen: u32 = include!("golden/checkpoint_state_v1.crc");
    let bytes = CheckpointState::encode(&state);
    assert_eq!(bytes.len() as u64, CheckpointState::MAX_ENCODED_LEN);
    assert_frozen("checkpoint state", &bytes, &CHECKPOINT_STATE_LAYOUT, frozen);

    let decoded = CheckpointState::decode(&image(&CHECKPOINT_STATE_LAYOUT, frozen)).unwrap();
    assert_eq!(decoded, state);
    assert_eq!(decoded.generation(), 0x2122_2324_2526_2728);
    assert_eq!(decoded.checkpoint_sequence, 0x3132_3334_3536_3738);
}

// ---------- durable proof ----------

#[rustfmt::skip]
const DURABLE_PROOF_LAYOUT: [u8; 60] = [
    // SPEC §21
    b'M', b'A', b'K', b'I', b'J', b'D', b'P', b'1',
    // version u32 = 1
    0x01, 0x00, 0x00, 0x00,
    // generation u64 = 0x4142_4344_4546_4748
    0x48, 0x47, 0x46, 0x45, 0x44, 0x43, 0x42, 0x41,
    // volume_uuid a0a1a2a3-a4a5-a6a7-a8a9-aaabacadaeaf, in its text order
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    // durable_sequence u64 = 0x5152_5354_5556_5758
    0x58, 0x57, 0x56, 0x55, 0x54, 0x53, 0x52, 0x51,
    // segment_index u64 = 0x6162_6364_6566_6768
    0x68, 0x67, 0x66, 0x65, 0x64, 0x63, 0x62, 0x61,
    // durable_size u64 = 0x7172_7374_7576_7778
    0x78, 0x77, 0x76, 0x75, 0x74, 0x73, 0x72, 0x71,
];

/// The v1 durable-proof encoding is frozen: exactly 64 bytes.
#[test]
fn durable_proof_golden_vector_frozen() {
    let proof = DurableProof {
        generation: 0x4142_4344_4546_4748,
        volume_uuid: Uuid::from_u128(0xA0A1_A2A3_A4A5_A6A7_A8A9_AAAB_ACAD_AEAF),
        durable_sequence: 0x5152_5354_5556_5758,
        segment_index: 0x6162_6364_6566_6768,
        durable_size: 0x7172_7374_7576_7778,
    };

    let frozen: u32 = include!("golden/durable_proof_v1.crc");
    let bytes = proof.encode();
    assert_eq!(bytes.len(), DURABLE_PROOF_SIZE);
    assert_frozen("durable proof", &bytes, &DURABLE_PROOF_LAYOUT, frozen);

    let decoded = DurableProof::decode(&image(&DURABLE_PROOF_LAYOUT, frozen)).unwrap();
    assert_eq!(decoded, proof);
}

// ---------- journal segment header ----------

#[rustfmt::skip]
const SEGMENT_HEADER_LAYOUT: [u8; 44] = [
    b'M', b'A', b'K', b'I', b'J', b'S', b'G', b'1',
    // version u32 = 1
    0x01, 0x00, 0x00, 0x00,
    // segment_index u64 = 0x8182_8384_8586_8788
    0x88, 0x87, 0x86, 0x85, 0x84, 0x83, 0x82, 0x81,
    // volume_uuid b0b1b2b3-b4b5-b6b7-b8b9-babbbcbdbebf, in its text order
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    // base_sequence u64 = 0x9192_9394_9596_9798
    0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92, 0x91,
];

/// The v1 journal segment header encoding is frozen: a fixed 48 bytes.
#[test]
fn segment_header_golden_vector_frozen() {
    let header = SegmentHeader {
        segment_index: 0x8182_8384_8586_8788,
        volume_uuid: Uuid::from_u128(0xB0B1_B2B3_B4B5_B6B7_B8B9_BABB_BCBD_BEBF),
        base_sequence: 0x9192_9394_9596_9798,
    };

    let frozen: u32 = include!("golden/segment_header_v1.crc");
    let bytes = header.encode();
    assert_eq!(bytes.len(), SEGMENT_HEADER_SIZE);
    assert_frozen(
        "journal segment header",
        &bytes,
        &SEGMENT_HEADER_LAYOUT,
        frozen,
    );

    let decoded = SegmentHeader::decode(&image(&SEGMENT_HEADER_LAYOUT, frozen)).unwrap();
    assert_eq!(decoded, header);
}

// ---------- journal record header ----------

const RECORD_PAYLOAD: [u8; 13] = [
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC,
];

#[rustfmt::skip]
const RECORD_HEADER_LAYOUT: [u8; 28] = [
    b'M', b'J', b'R', b'1',
    // sequence u64 = 0xD1D2_D3D4_D5D6_D7D8
    0xD8, 0xD7, 0xD6, 0xD5, 0xD4, 0xD3, 0xD2, 0xD1,
    // unit_index u64 = 0xE1E2_E3E4_E5E6_E7E8
    0xE8, 0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2, 0xE1,
    // payload_len u32 = 13
    0x0D, 0x00, 0x00, 0x00,
    // payload_crc u32 = 0x3356_48E6, the CRC-32 of the payload
    0xE6, 0x48, 0x56, 0x33,
];

/// The v1 journal record header is frozen: 28 bytes, their CRC-32, then the
/// payload. `golden/journal_record_v1.crc` hashes a whole record, header CRC
/// included, so it depends on the payload alone and not on any header field.
#[test]
fn journal_record_header_golden_vector_frozen() {
    let record = JournalRecord {
        sequence: 0xD1D2_D3D4_D5D6_D7D8,
        unit_index: 0xE1E2_E3E4_E5E6_E7E8,
        payload: RECORD_PAYLOAD.to_vec(),
    };

    let frozen: u32 = include!("golden/journal_record_header_v1.crc");
    let bytes = encode_record(&record).unwrap();
    assert_eq!(bytes.len(), RECORD_HEADER_SIZE + RECORD_PAYLOAD.len());
    let (header, payload) = bytes.split_at(RECORD_HEADER_SIZE);
    assert_frozen(
        "journal record header",
        header,
        &RECORD_HEADER_LAYOUT,
        frozen,
    );
    assert_eq!(payload, RECORD_PAYLOAD);
    assert_eq!(
        encode_record_parts(record.sequence, record.unit_index, &record.payload).unwrap(),
        bytes
    );

    let hand_assembled = [
        image(&RECORD_HEADER_LAYOUT, frozen),
        RECORD_PAYLOAD.to_vec(),
    ]
    .concat();
    let (records, outcome) = scan_segment_bounded(
        &hand_assembled,
        0xD1D2_D3D4_D5D6_D7D8,
        Some(hand_assembled.len()),
    );
    assert_eq!(outcome, ScanOutcome::Clean);
    assert_eq!(records, [record]);
}

// ---------- superblock envelopes ----------

fn superblock() -> Superblock {
    Superblock {
        generation: 0x0A0B_0C0D_0E0F_1011,
        volume_uuid: Uuid::from_u128(0xC0C1_C2C3_C4C5_C6C7_C8C9_CACB_CCCD_CECF),
        provider_type: "remote-grpc".into(),
        crypto_compatibility_id: "vendor-profile-v7".into(),
        key_identity: "tenant-a/key-3".into(),
        geometry: Geometry::compute(512, 4096, 2048, 4124, 3 << 30, 96 << 20).unwrap(),
        format_version: 1,
        created_unix: 1_700_000_000,
    }
}

/// The 4096-byte image of [`superblock`] without its CRC-32, under the
/// given envelope version (the layout in the `superblock` module comment).
fn superblock_layout(envelope: u8) -> Vec<u8> {
    #[rustfmt::skip]
    let fixed: [u8; 100] = [
        b'M', b'A', b'K', b'I', b'S', b'B', b'0', b'1',
        // envelope (metadata) version u32
        envelope, 0x00, 0x00, 0x00,
        // generation u64 = 0x0A0B_0C0D_0E0F_1011
        0x11, 0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A,
        // volume_uuid c0c1c2c3-c4c5-c6c7-c8c9-cacbcccdcecf, in its text order
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
        0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
        // device_block_size u32 = 512
        0x00, 0x02, 0x00, 0x00,
        // crypto_unit_size u32 = 4096
        0x00, 0x10, 0x00, 0x00,
        // slot_alignment u32 = 2048
        0x00, 0x08, 0x00, 0x00,
        // max_ciphertext_size u32 = 4124
        0x1C, 0x10, 0x00, 0x00,
        // slot_header_size u32 = 64
        0x40, 0x00, 0x00, 0x00,
        // slot_size u64 = 6144: 64 + 4124 rounded up to the alignment
        0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // max_virtual_size u64 = 3 GiB
        0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00,
        // shard_logical_size u64 = 96 MiB
        0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00,
        // crypto format_version u32 = 1
        0x01, 0x00, 0x00, 0x00,
        // created_unix u64 = 1_700_000_000
        0x00, 0xF1, 0x53, 0x65, 0x00, 0x00, 0x00, 0x00,
        // flags u64 = 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut layout = fixed.to_vec();
    // provider_type, crypto_compatibility_id, key_identity: u16 length, UTF-8
    layout.extend_from_slice(&[0x0B, 0x00]);
    layout.extend_from_slice(b"remote-grpc");
    layout.extend_from_slice(&[0x11, 0x00]);
    layout.extend_from_slice(b"vendor-profile-v7");
    layout.extend_from_slice(&[0x0E, 0x00]);
    layout.extend_from_slice(b"tenant-a/key-3");
    assert_eq!(layout.len(), 148);
    // zero padding up to the CRC-32 in the last four bytes
    layout.resize(SUPERBLOCK_SIZE - 4, 0);
    layout
}

/// The v2 and v3 superblock envelopes are frozen. They are the v1 image
/// with another envelope version: nothing else in the block moves.
#[test]
fn superblock_envelope_v2_and_v3_golden_vectors_frozen() {
    let model = superblock();
    assert_eq!(model.geometry.slot_size, 6144);

    for (metadata_version, envelope, frozen) in [
        (
            SUPERBLOCK_VERSION_V2,
            2,
            include!("golden/superblock_v2.crc"),
        ),
        (
            SUPERBLOCK_VERSION_V3,
            3,
            include!("golden/superblock_v3.crc"),
        ),
    ] {
        let what = format!("superblock envelope v{envelope}");
        let volume = VolumeSuperblock {
            superblock: model.clone(),
            metadata_version,
        };
        let layout = superblock_layout(envelope);
        let bytes = volume.encode();
        assert_eq!(bytes.len(), SUPERBLOCK_SIZE);
        assert_frozen(&what, &bytes, &layout, frozen);

        let hand_assembled = image(&layout, frozen);
        assert_eq!(VolumeSuperblock::decode(&hand_assembled).unwrap(), volume);
        assert_eq!(Superblock::decode(&hand_assembled).unwrap(), model);
    }

    // The frozen v1 image (`golden/superblock_v1.crc`) comes from a model
    // whose device block and crypto unit sizes are equal; this one tells
    // every field apart under the v1 envelope too.
    let v1 = model.encode();
    assert_eq!(v1[..SUPERBLOCK_SIZE - 4], superblock_layout(1));
    let volume = VolumeSuperblock::decode(&v1).unwrap();
    assert_eq!(volume.metadata_version, SUPERBLOCK_VERSION);
    assert_eq!(volume.superblock, model);
}

// ---------- inventory ----------

/// Every record magic the format crate defines, with the files under
/// `golden/` that freeze its encoding.
const FROZEN_RECORDS: [(&str, &[&str]); 10] = [
    (
        "MAKISB01",
        &[
            "superblock_v1.crc",
            "superblock_v2.crc",
            "superblock_v3.crc",
        ],
    ),
    ("MAKIALC1", &["allocation_map_v1.crc"]),
    ("MAKICAT1", &["shard_catalog_v1.crc"]),
    ("MAKICKP1", &["checkpoint_state_v1.crc"]),
    (
        "MAKICNY1",
        &["canary_record_v1.crc", "canary_plaintext_v1.crc"],
    ),
    ("MAKISLT1", &["slot_header_v1.crc"]),
    (
        "MJR1",
        &["journal_record_header_v1.crc", "journal_record_v1.crc"],
    ),
    ("MAKIJSG1", &["segment_header_v1.crc"]),
    ("MAKIJDM1", &["durable_mark_v1.crc"]),
    ("MAKIJDP1", &["durable_proof_v1.crc"]),
];

/// A record magic added to the format crate fails here until it is listed
/// with its golden vector, and so does a vector no listed record accounts
/// for.
#[test]
fn every_record_magic_has_a_frozen_vector() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));

    let mut defined = BTreeSet::new();
    for entry in std::fs::read_dir(manifest.join("src")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|extension| extension != "rs") {
            continue;
        }
        for line in std::fs::read_to_string(&path).unwrap().lines() {
            let Some((declaration, literal)) = line.split_once(" = b\"") else {
                continue;
            };
            if declaration.contains("_MAGIC: &[u8; ") {
                let magic = literal.split('"').next().unwrap();
                defined.insert(magic.to_string());
            }
        }
    }
    let listed: BTreeSet<String> = FROZEN_RECORDS
        .iter()
        .map(|(magic, _)| magic.to_string())
        .collect();
    assert_eq!(
        defined, listed,
        "record magics defined in src/ and records with a frozen vector differ"
    );

    let present: BTreeSet<String> = std::fs::read_dir(manifest.join("tests/golden"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    let expected: BTreeSet<String> = FROZEN_RECORDS
        .iter()
        .flat_map(|(_, files)| files.iter().map(|file| file.to_string()))
        .collect();
    assert_eq!(
        present, expected,
        "files under tests/golden and the vectors listed here differ"
    );
}
