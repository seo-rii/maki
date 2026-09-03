//! Mutation fuzzing of every on-disk decoder and of configuration
//! validation. Two properties per CRC-protected record: (1) any single
//! byte flip anywhere in the encoded image is rejected, never accepted or
//! panicked on; (2) thousands of random mutations (flips, truncation,
//! insertion, zero runs, garbage) never panic. The journal scanner and the
//! URL/config validators get the same random treatment.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use uuid::Uuid;

use maki_format::ab::AbRecord;
use maki_format::allocation::AllocationMap;
use maki_format::canary::{canary_plaintext, KeyCanary, CANARY_UNIT_INDEX};
use maki_format::catalog::ShardCatalog;
use maki_format::checkpoint::CheckpointState;
use maki_format::config::{parse_config, parse_endpoint_url};
use maki_format::geometry::Geometry;
use maki_format::journal::{
    encode_record, scan_segment_bounded, DurableMark, JournalRecord, ScanOutcome, SegmentHeader,
};
use maki_format::slot::SlotHeader;
use maki_format::superblock::Superblock;

const ITERATIONS: usize = 3000;

fn mutate(rng: &mut StdRng, input: &[u8]) -> Vec<u8> {
    let mut out = input.to_vec();
    let ops = rng.random_range(1..=3);
    for _ in 0..ops {
        match rng.random_range(0..7u32) {
            0 if !out.is_empty() => {
                let i = rng.random_range(0..out.len());
                out[i] ^= 1 << rng.random_range(0..8);
            }
            1 if !out.is_empty() => {
                let keep = rng.random_range(0..out.len());
                out.truncate(keep);
            }
            2 => {
                let extra: Vec<u8> = (0..rng.random_range(0..64)).map(|_| rng.random()).collect();
                out.extend(extra);
            }
            3 if !out.is_empty() => {
                let i = rng.random_range(0..out.len());
                out.insert(i, rng.random());
            }
            4 if out.len() > 2 => {
                let a = rng.random_range(0..out.len());
                let b = rng.random_range(a..out.len());
                out[a..b].fill(0);
            }
            5 if !out.is_empty() => {
                let i = rng.random_range(0..out.len());
                out[i] = rng.random();
            }
            _ => {
                out = (0..rng.random_range(0..200))
                    .map(|_| rng.random())
                    .collect();
            }
        }
    }
    out
}

fn geometry() -> Geometry {
    Geometry::compute(4096, 4096, 512, 4384, 1 << 30, 64 << 20).unwrap()
}

fn superblock() -> Vec<u8> {
    Superblock {
        generation: 3,
        volume_uuid: Uuid::from_u128(0xF00D),
        provider_type: "remote-http".into(),
        crypto_compatibility_id: "vendor-v1".into(),
        key_identity: "key".into(),
        geometry: geometry(),
        format_version: 1,
        created_unix: 1_700_000_000,
    }
    .encode()
}

fn segment_header() -> Vec<u8> {
    SegmentHeader {
        segment_index: 7,
        volume_uuid: Uuid::from_u128(0xF00D),
        base_sequence: 99,
    }
    .encode()
}

fn durable_mark() -> Vec<u8> {
    DurableMark {
        segment_index: 7,
        durable_size: 12345,
    }
    .encode()
    .to_vec()
}

fn canary() -> Vec<u8> {
    KeyCanary {
        generation: 1,
        volume_uuid: Uuid::from_u128(0xF00D),
        unit_index: CANARY_UNIT_INDEX,
        ciphertext: canary_plaintext(&Uuid::from_u128(0xF00D), 128),
    }
    .encode()
}

fn slot_header() -> Vec<u8> {
    SlotHeader {
        unit_index: 42,
        write_sequence: 1000,
        ciphertext_len: 4384,
        flags: 0,
        ciphertext_crc: 0xDEADBEEF,
    }
    .encode()
    .to_vec()
}

fn allocation_map() -> Vec<u8> {
    let mut map = AllocationMap::new(4096);
    map.set(1, true);
    map.set(4000, true);
    <AllocationMap as AbRecord>::encode(&map)
}

fn catalog() -> Vec<u8> {
    let mut c = ShardCatalog::new();
    c.insert(0);
    c.insert(5);
    <ShardCatalog as AbRecord>::encode(&c)
}

fn checkpoint_state() -> Vec<u8> {
    let mut s = CheckpointState::default();
    s.checkpoint_sequence = 77;
    <CheckpointState as AbRecord>::encode(&s)
}

type Decoder = fn(&[u8]) -> bool;

fn decoders() -> Vec<(&'static str, Vec<u8>, Decoder)> {
    vec![
        ("superblock", superblock(), |b| {
            Superblock::decode(b).is_ok()
        }),
        ("segment header", segment_header(), |b| {
            SegmentHeader::decode(b).is_ok()
        }),
        ("durable mark", durable_mark(), |b| {
            DurableMark::decode(b).is_ok()
        }),
        ("key canary", canary(), |b| KeyCanary::decode(b).is_ok()),
        ("slot header", slot_header(), |b| {
            SlotHeader::decode(b).is_ok()
        }),
        ("allocation map", allocation_map(), |b| {
            <AllocationMap as AbRecord>::decode(b).is_ok()
        }),
        ("shard catalog", catalog(), |b| {
            <ShardCatalog as AbRecord>::decode(b).is_ok()
        }),
        ("checkpoint state", checkpoint_state(), |b| {
            <CheckpointState as AbRecord>::decode(b).is_ok()
        }),
    ]
}

#[test]
fn every_decoder_accepts_its_own_encoding() {
    for (name, image, decode) in decoders() {
        assert!(decode(&image), "{name}: pristine image must decode");
    }
}

/// Every byte of every record is covered by its CRC (or by a magic/length
/// check): no single bit flip is ever accepted.
#[test]
fn every_single_bit_flip_is_rejected() {
    for (name, image, decode) in decoders() {
        for i in 0..image.len() {
            for bit in 0..8 {
                let mut bad = image.clone();
                bad[i] ^= 1 << bit;
                assert!(
                    !decode(&bad),
                    "{name}: flipping bit {bit} of byte {i} was accepted"
                );
            }
        }
    }
}

#[test]
fn decoders_never_panic_on_random_mutations() {
    let mut rng = StdRng::seed_from_u64(0xF0_F0_F0);
    for (name, image, decode) in decoders() {
        for _ in 0..ITERATIONS {
            let bad = mutate(&mut rng, &image);
            let _ = decode(&bad);
        }
        // Also pure garbage of assorted lengths.
        for len in [
            0usize, 1, 3, 4, 7, 8, 16, 31, 32, 47, 48, 63, 64, 4095, 4096, 4097,
        ] {
            let garbage: Vec<u8> = (0..len).map(|_| rng.random()).collect();
            let _ = decode(&garbage);
            let _ = decode(&vec![0u8; len]);
            let _ = decode(&vec![0xFFu8; len]);
        }
        let _ = name;
    }
}

#[test]
fn journal_scanner_never_panics_and_never_accepts_a_corrupt_durable_prefix() {
    let mut rng = StdRng::seed_from_u64(0x5CA7);
    for _ in 0..ITERATIONS {
        let count = rng.random_range(0..6u64);
        let mut body = Vec::new();
        let mut lengths = Vec::new();
        for seq in 0..count {
            let payload: Vec<u8> = (0..rng.random_range(0..300))
                .map(|_| rng.random())
                .collect();
            let rec = encode_record(&JournalRecord {
                sequence: 10 + seq,
                unit_index: seq * 3,
                payload,
            });
            lengths.push(rec.len());
            body.extend(rec);
        }
        let durable_len = if rng.random_bool(0.5) {
            Some(rng.random_range(0..=body.len() + 8))
        } else {
            None
        };
        let bad = mutate(&mut rng, &body);
        let (records, outcome) = scan_segment_bounded(&bad, 10, durable_len);
        // Whatever the outcome, records are a contiguous prefix in order.
        for (i, r) in records.iter().enumerate() {
            assert_eq!(r.sequence, 10 + i as u64);
        }
        if let ScanOutcome::TornTail { at } = outcome {
            assert!(at <= bad.len());
            if let Some(d) = durable_len {
                assert!(at >= d.min(bad.len()), "torn tail inside durable prefix");
            }
        }
        // The unmodified body scans clean and yields every record.
        let (all, clean) = scan_segment_bounded(&body, 10, Some(body.len()));
        assert_eq!(all.len(), count as usize);
        assert_eq!(clean, ScanOutcome::Clean);
    }
}

#[test]
fn endpoint_url_parser_never_panics() {
    let mut rng = StdRng::seed_from_u64(0x0B5E);
    let seeds = [
        "https://crypto.internal:8443/v1",
        "http://[::1]:7000",
        "ws://localhost",
        "://",
        "a://",
        "http://",
        "http://user@host",
        "HTTPS://Host",
    ];
    for seed in seeds {
        for _ in 0..500 {
            let bytes = mutate(&mut rng, seed.as_bytes());
            let text = String::from_utf8_lossy(&bytes);
            let _ = parse_endpoint_url(&text);
        }
    }
}

const SAMPLE: &str = include_str!("../../../packaging/examples/postgres-prod.toml");

#[test]
fn config_validation_never_panics_on_mutated_production_sample() {
    let mut rng = StdRng::seed_from_u64(0xC0F1);
    let alphabet: &[u8] = b"\"[]{}=.,-_/\\ \n\t0123456789abcxyzABC:@#%'";
    for _ in 0..ITERATIONS {
        let mut text = SAMPLE.as_bytes().to_vec();
        for _ in 0..rng.random_range(1..=4) {
            match rng.random_range(0..4u32) {
                0 => {
                    let i = rng.random_range(0..text.len());
                    text[i] = alphabet[rng.random_range(0..alphabet.len())];
                }
                1 => {
                    let i = rng.random_range(0..text.len());
                    text.remove(i);
                }
                2 => {
                    let i = rng.random_range(0..text.len());
                    text.insert(i, alphabet[rng.random_range(0..alphabet.len())]);
                }
                _ => {
                    // Duplicate or swap a whole line: catches table/key redefinition paths.
                    let lines: Vec<&[u8]> = text.split(|b| *b == b'\n').collect();
                    if lines.len() > 2 {
                        let a = rng.random_range(0..lines.len());
                        let b = rng.random_range(0..lines.len());
                        let mut rebuilt: Vec<u8> = Vec::with_capacity(text.len() + 64);
                        for (i, line) in lines.iter().enumerate() {
                            let src = if i == a { lines[b] } else { line };
                            rebuilt.extend_from_slice(src);
                            rebuilt.push(b'\n');
                        }
                        text = rebuilt;
                    }
                }
            }
        }
        if let Ok(s) = String::from_utf8(text) {
            if let Ok(cfg) = parse_config(&s) {
                let _ = cfg.validate();
                let _ = cfg.geometry();
            }
        }
    }
}
