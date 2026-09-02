//! Phase 1 — Configuration and On-Disk Format (SPEC §43).

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use uuid::Uuid;

use maki_backing::Backing;
use maki_format::ab::{AbRecord, AbStore};
use maki_format::allocation::AllocationMap;
use maki_format::catalog::ShardCatalog;
use maki_format::config::{parse_config, ByteSize};
use maki_format::error::FormatError;
use maki_format::geometry::Geometry;
use maki_format::journal::{
    encode_record, scan_segment, JournalRecord, ScanOutcome, SegmentHeader,
};
use maki_format::slot::{SlotHeader, SLOT_HEADER_SIZE};
use maki_format::superblock::{Superblock, SUPERBLOCK_SIZE};
use maki_test_support::CrashableBacking;

fn uuid1() -> Uuid {
    Uuid::from_u128(0x0123_4567_89AB_CDEF_0123_4567_89AB_CDEF)
}

fn geom() -> Geometry {
    Geometry::compute(4096, 4096, 512, 4384, 16 << 40, 64 << 30).unwrap()
}

fn sb() -> Superblock {
    Superblock {
        generation: 1,
        volume_uuid: uuid1(),
        provider_type: "remote-http".into(),
        crypto_compatibility_id: "vendor-profile-v1".into(),
        key_identity: "key-1".into(),
        geometry: geom(),
        format_version: 1,
        created_unix: 1_756_684_800,
    }
}

// ---------- geometry validation and slot-size calculation ----------

#[test]
fn slot_size_matches_spec_example() {
    // SPEC §14: header 64 + max ciphertext 4384 = 4448, aligned to 512 = 4608.
    let g = geom();
    assert_eq!(g.slot_header_size, 64);
    assert_eq!(g.slot_size, 4608);
}

#[test]
fn geometry_validation_rejects_bad_inputs() {
    // non-power-of-two device block
    assert!(Geometry::compute(4000, 4096, 512, 4384, 1 << 30, 64 << 20).is_err());
    // crypto unit not a multiple of device block
    assert!(Geometry::compute(4096, 6000, 512, 6100, 1 << 30, 64 << 20).is_err());
    // max ciphertext smaller than unit
    assert!(Geometry::compute(4096, 4096, 512, 100, 1 << 30, 64 << 20).is_err());
    // virtual size not unit-aligned
    assert!(Geometry::compute(4096, 4096, 512, 4384, (1 << 30) + 1, 64 << 20).is_err());
    // shard size not unit-aligned
    assert!(Geometry::compute(4096, 4096, 512, 4384, 1 << 30, (64 << 20) + 5).is_err());
    // zero alignment
    assert!(Geometry::compute(4096, 4096, 0, 4384, 1 << 30, 64 << 20).is_err());
}

#[test]
fn geometry_integer_overflow_is_an_error_not_a_panic() {
    // enormous ciphertext size must not overflow slot_size math
    let r = Geometry::compute(4096, 4096, 512, u32::MAX, 1 << 30, 64 << 20);
    match r {
        Ok(g) => assert!(g.slot_size >= u32::MAX as u64),
        Err(FormatError::Overflow(_)) => {}
        Err(e) => panic!("unexpected error {e}"),
    }
    // total slot bytes per shard must be checked
    let r2 = Geometry::compute(4096, 4096, 512, 4384, u64::MAX - 4095, u64::MAX - 4095);
    assert!(r2.is_err());
}

#[test]
fn unit_addressing_roundtrip() {
    let g = Geometry::compute(4096, 4096, 512, 4384, 1 << 30, 16 << 20).unwrap();
    assert_eq!(g.num_units(), (1u64 << 30) / 4096);
    assert_eq!(g.units_per_shard(), (16u64 << 20) / 4096);
    let (shard, idx) = g.shard_of_unit(g.units_per_shard() + 3);
    assert_eq!((shard, idx), (1, 3));
    assert_eq!(g.slot_offset(2), 2 * g.slot_size);
}

// ---------- superblock ----------

#[test]
fn superblock_roundtrip_and_size() {
    let s = sb();
    let bytes = s.encode();
    assert_eq!(bytes.len(), SUPERBLOCK_SIZE);
    let d = Superblock::decode(&bytes).unwrap();
    assert_eq!(d.volume_uuid, s.volume_uuid);
    assert_eq!(d.crypto_compatibility_id, s.crypto_compatibility_id);
    assert_eq!(d.geometry.slot_size, s.geometry.slot_size);
    assert_eq!(d.generation, 1);
}

#[test]
fn superblock_rejects_corruption() {
    let mut bytes = sb().encode();
    bytes[100] ^= 0x40;
    assert!(matches!(
        Superblock::decode(&bytes),
        Err(FormatError::BadChecksum(_))
    ));
    let mut short = sb().encode();
    short.truncate(100);
    assert!(Superblock::decode(&short).is_err());
    let mut badmagic = sb().encode();
    badmagic[0] ^= 0xFF;
    assert!(matches!(
        Superblock::decode(&badmagic),
        Err(FormatError::BadMagic(_))
    ));
}

/// Golden vector: the v1 superblock encoding is frozen. If this test fails,
/// you broke on-disk compatibility.
#[test]
fn superblock_golden_vector_frozen() {
    let bytes = sb().encode();
    assert_eq!(bytes.len(), 4096);
    assert_eq!(&bytes[0..8], b"MAKISB01");
    // Frozen CRC of the image payload. (Excludes the trailing self-CRC:
    // crc32(data ‖ crc32_le(data)) is a constant residue for ANY data, so
    // hashing the full self-checksummed image would freeze nothing.)
    let crc = crc32fast::hash(&bytes[..bytes.len() - 4]);
    let expected = golden::SUPERBLOCK_V1_CRC;
    assert_eq!(
        crc, expected,
        "superblock encoding changed! bytes-crc={crc:#010x}"
    );
}

mod golden {
    /// Computed once at freeze time; do not update without a format-version bump.
    pub const SUPERBLOCK_V1_CRC: u32 = include!("golden/superblock_v1.crc");
    pub const SLOT_HEADER_V1_CRC: u32 = include!("golden/slot_header_v1.crc");
    pub const JOURNAL_RECORD_V1_CRC: u32 = include!("golden/journal_record_v1.crc");
}

// ---------- A/B protocol (superblock, allocation, catalog) ----------

#[test]
fn ab_store_prefers_highest_valid_generation() {
    let backing = CrashableBacking::new();
    let ab = AbStore::new("superblock.a", "superblock.b");

    assert!(ab.load::<Superblock>(&backing).unwrap().is_none());

    let mut s = sb();
    ab.store(&backing, &mut s).unwrap(); // gen bumped, side A
    ab.store(&backing, &mut s).unwrap(); // side B, higher gen
    let g2 = s.generation();
    let loaded = ab.load::<Superblock>(&backing).unwrap().unwrap();
    assert_eq!(loaded.generation(), g2);

    // Corrupt the newest side: loader falls back to the older valid side.
    let (a, b) = (
        backing.open("superblock.a", false).unwrap(),
        backing.open("superblock.b", false).unwrap(),
    );
    // find which side holds g2
    let mut buf = vec![0u8; SUPERBLOCK_SIZE];
    a.read_at(0, &mut buf).unwrap();
    let newest_is_a = Superblock::decode(&buf)
        .map(|s| s.generation() == g2)
        .unwrap_or(false);
    let newest = if newest_is_a { a } else { b };
    newest.write_at(64, &[0xFF; 8]).unwrap();
    newest.sync_data().unwrap();

    let fallback = ab.load::<Superblock>(&backing).unwrap().unwrap();
    assert_eq!(
        fallback.generation(),
        g2 - 1,
        "must fall back to older side"
    );
}

#[test]
fn ab_store_survives_torn_write_of_new_side() {
    let backing = CrashableBacking::new();
    let ab = AbStore::new("superblock.a", "superblock.b");
    let mut s = sb();
    ab.store(&backing, &mut s).unwrap();
    backing.sync_dir("").unwrap();
    let g1 = s.generation();

    // Second store, but the write is torn mid-superblock by a crash.
    // Perform the update without sync by writing directly to the target side.
    let target = ab.next_target_path(&backing).unwrap();
    s.set_generation(g1 + 1);
    let f = backing.open(target, true).unwrap();
    f.write_at(0, &s.encode()).unwrap();
    backing.crash_keep_torn_prefix(target, 1000); // torn!

    let loaded = ab.load::<Superblock>(&backing).unwrap().unwrap();
    assert_eq!(
        loaded.generation(),
        g1,
        "torn new side must not be selected"
    );
}

#[test]
fn allocation_map_ab_roundtrip_and_bits() {
    let mut m = AllocationMap::new(1000);
    m.set(0, true);
    m.set(999, true);
    m.set(500, true);
    m.set(500, false);
    assert!(m.get(0) && m.get(999) && !m.get(500) && !m.get(1));
    assert_eq!(m.set_count(), 2);

    let backing = CrashableBacking::new();
    let ab = AbStore::new("alloc.a", "alloc.b");
    ab.store(&backing, &mut m).unwrap();
    let loaded: AllocationMap = ab.load(&backing).unwrap().unwrap();
    assert_eq!(loaded.set_count(), 2);
    assert!(loaded.get(999));

    // corruption detected
    let bytes = m.encode();
    let mut bad = bytes.clone();
    bad[bytes.len() - 10] ^= 1;
    assert!(AllocationMap::decode(&bad).is_err());
}

#[test]
fn shard_catalog_ab_roundtrip() {
    let mut c = ShardCatalog::new();
    assert!(!c.contains(3));
    c.insert(3);
    c.insert(7);
    let backing = CrashableBacking::new();
    let ab = AbStore::new("shard-catalog.a", "shard-catalog.b");
    ab.store(&backing, &mut c).unwrap();
    let loaded: ShardCatalog = ab.load(&backing).unwrap().unwrap();
    assert!(loaded.contains(3) && loaded.contains(7) && !loaded.contains(4));
    assert_eq!(loaded.shard_indices().collect::<Vec<_>>(), vec![3, 7]);
}

// ---------- slot header ----------

#[test]
fn slot_header_roundtrip_and_golden() {
    let h = SlotHeader {
        unit_index: 42,
        write_sequence: 7,
        ciphertext_len: 4384,
        flags: 0,
        ciphertext_crc: 0xDEAD_BEEF,
    };
    let bytes = h.encode();
    assert_eq!(bytes.len(), SLOT_HEADER_SIZE as usize);
    let d = SlotHeader::decode(&bytes).unwrap();
    assert_eq!(d.unit_index, 42);
    assert_eq!(d.ciphertext_len, 4384);
    assert_eq!(
        crc32fast::hash(&bytes[..bytes.len() - 4]),
        golden::SLOT_HEADER_V1_CRC
    );

    let mut bad = bytes;
    bad[9] ^= 1;
    assert!(SlotHeader::decode(&bad).is_err());
}

// ---------- journal record framing ----------

fn rec(seq: u64, unit: u64, fill: u8, len: usize) -> JournalRecord {
    JournalRecord {
        sequence: seq,
        unit_index: unit,
        payload: vec![fill; len],
    }
}

#[test]
fn journal_records_scan_cleanly() {
    let mut buf = Vec::new();
    for i in 0..5u64 {
        buf.extend(encode_record(&rec(i + 1, i * 2, i as u8, 100 + i as usize)));
    }
    let (records, outcome) = scan_segment(&buf, 1);
    assert_eq!(records.len(), 5);
    assert_eq!(records[4].sequence, 5);
    assert!(matches!(outcome, ScanOutcome::Clean));
}

#[test]
fn journal_torn_tail_is_truncated() {
    let mut buf = Vec::new();
    buf.extend(encode_record(&rec(1, 0, 1, 200)));
    buf.extend(encode_record(&rec(2, 1, 2, 200)));
    let full = buf.len();
    buf.extend(encode_record(&rec(3, 2, 3, 200)));
    buf.truncate(full + 50); // torn mid-record-3

    let (records, outcome) = scan_segment(&buf, 1);
    assert_eq!(records.len(), 2);
    match outcome {
        ScanOutcome::TornTail { at } => assert_eq!(at, full),
        o => panic!("expected torn tail, got {o:?}"),
    }
}

#[test]
fn journal_middle_corruption_is_detected_not_truncated() {
    let mut buf = Vec::new();
    let r1 = encode_record(&rec(1, 0, 1, 200));
    let r1_len = r1.len();
    buf.extend(r1);
    buf.extend(encode_record(&rec(2, 1, 2, 200)));
    buf.extend(encode_record(&rec(3, 2, 3, 200)));
    // Flip one payload byte in record 1: its CRC fails but record 2 is valid.
    buf[r1_len - 10] ^= 0x01;

    let (_records, outcome) = scan_segment(&buf, 1);
    assert!(
        matches!(outcome, ScanOutcome::Corrupt { .. }),
        "middle corruption must be a hard error, got {outcome:?}"
    );
}

#[test]
fn journal_sequence_gap_is_corruption() {
    let mut buf = Vec::new();
    buf.extend(encode_record(&rec(1, 0, 1, 100)));
    buf.extend(encode_record(&rec(5, 1, 2, 100))); // gap!
    let (_r, outcome) = scan_segment(&buf, 1);
    assert!(matches!(outcome, ScanOutcome::Corrupt { .. }));
}

#[test]
fn segment_header_roundtrip_and_journal_golden() {
    let h = SegmentHeader {
        segment_index: 9,
        volume_uuid: uuid1(),
        base_sequence: 1000,
    };
    let bytes = h.encode();
    let d = SegmentHeader::decode(&bytes).unwrap();
    assert_eq!(d.segment_index, 9);
    assert_eq!(d.base_sequence, 1000);

    let record_bytes = encode_record(&rec(77, 12, 0xAA, 64));
    assert_eq!(
        crc32fast::hash(&record_bytes),
        golden::JOURNAL_RECORD_V1_CRC
    );
}

// ---------- config schema ----------

const FULL_CONFIG: &str = include_str!("data/full_config.toml");

#[test]
fn full_spec_config_parses() {
    let cfg = parse_config(FULL_CONFIG).unwrap();
    assert_eq!(cfg.volume.name, "postgres-prod");
    assert_eq!(cfg.volume.max_virtual_size, ByteSize(16 << 40));
    assert_eq!(cfg.volume.crypto_unit_size, 4096);
    assert_eq!(cfg.crypto.provider, "remote-http");
    assert_eq!(cfg.crypto.capabilities.max_ciphertext_size, 4384);
    assert_eq!(cfg.limits.max_active_callbacks, 64);
    assert_eq!(cfg.limits.max_plaintext_bytes, ByteSize(128 << 20));
    assert_eq!(cfg.crypto.batch.max_wait.0.as_micros(), 150);
    assert_eq!(cfg.crypto.retry.initial_delay.0.as_millis(), 50);
    assert_eq!(cfg.crypto.retry_budget.retry_ratio, 0.20);
    assert_eq!(cfg.crypto.circuit_breaker.failure_threshold, 8);
    assert_eq!(cfg.cache.mode, maki_format::config::CacheMode::Off);
    assert_eq!(cfg.crypto.http.as_ref().unwrap().endpoint.len(), 2);
    cfg.validate().unwrap();
    // derived geometry works
    let g = cfg.geometry().unwrap();
    assert_eq!(g.slot_size, 4608);
}

#[test]
fn minimal_config_gets_defaults() {
    let cfg = parse_config(
        r#"
config_schema_version = 1
[volume]
name = "t"
max_virtual_size = "1GiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "local-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "/var/lib/maki/t"
"#,
    )
    .unwrap();
    assert_eq!(cfg.volume.device_block_size, 4096);
    assert_eq!(cfg.volume.crypto_unit_size, 4096);
    assert_eq!(cfg.crypto.availability_policy_default(), "stall");
    cfg.validate().unwrap();
}

#[test]
fn config_rejects_inline_secrets() {
    // SPEC §9: raw secrets in TOML are forbidden.
    let bad = r#"
config_schema_version = 1
[volume]
name = "t"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "v1"
token = "actual-secret"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "/x"
"#;
    assert!(parse_config(bad).is_err(), "inline token must be rejected");

    let bad_header = r#"
config_schema_version = 1
[volume]
name = "t"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[crypto.http.encrypt]
method = "POST"
path = "/encrypt"
[crypto.http.encrypt.headers]
Authorization = "Bearer sk-actual-secret"
[backing]
root = "/x"
"#;
    let parsed = parse_config(bad_header);
    match parsed {
        Err(_) => {}
        Ok(cfg) => assert!(
            cfg.validate().is_err(),
            "sensitive header with literal value must be rejected"
        ),
    }
}

#[test]
fn config_credential_reference_is_accepted() {
    let good = r#"
config_schema_version = 1
[volume]
name = "t"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[crypto.http.encrypt]
method = "POST"
path = "/encrypt"
[crypto.http.encrypt.headers]
Authorization = { source = "credential", name = "crypto-token" }
[backing]
root = "/x"
"#;
    let cfg = parse_config(good).unwrap();
    cfg.validate().unwrap();
}

#[test]
fn grpc_section_parses_with_paths_and_credential_metadata() {
    let good = r#"
config_schema_version = 1
[volume]
name = "t"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-grpc"
crypto_compatibility_id = "v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[crypto.grpc]
encrypt_path = "/vendor.Kms/Encrypt"
decrypt_path = "/vendor.Kms/Decrypt"
max_message_bytes = "4MiB"
[[crypto.grpc.endpoint]]
name = "primary"
url = "http://crypto.internal:7000"
[crypto.grpc.metadata]
authorization = { source = "credential", name = "crypto-token" }
[backing]
root = "/x"
"#;
    let cfg = parse_config(good).unwrap();
    cfg.validate().unwrap();
    let grpc = cfg.crypto.grpc.as_ref().unwrap();
    assert_eq!(grpc.encrypt_path.as_deref(), Some("/vendor.Kms/Encrypt"));
    assert_eq!(grpc.endpoint.len(), 1);
    assert_eq!(grpc.max_message_bytes.unwrap(), ByteSize(4 << 20));
}

#[test]
fn grpc_metadata_rejects_literal_secrets() {
    // SPEC §9 applies to gRPC metadata exactly as to HTTP headers.
    let bad = r#"
config_schema_version = 1
[volume]
name = "t"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-grpc"
crypto_compatibility_id = "v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[[crypto.grpc.endpoint]]
name = "primary"
url = "http://crypto.internal:7000"
[crypto.grpc.metadata]
authorization = "Bearer sk-actual-secret"
[backing]
root = "/x"
"#;
    match parse_config(bad) {
        Err(_) => {}
        Ok(cfg) => assert!(
            cfg.validate().is_err(),
            "sensitive gRPC metadata with literal value must be rejected"
        ),
    }
}

#[test]
fn byte_size_and_duration_parsing() {
    use maki_format::config::{ByteSize, MakiDuration};
    assert_eq!("128MiB".parse::<ByteSize>().unwrap().0, 128 << 20);
    assert_eq!("4GiB".parse::<ByteSize>().unwrap().0, 4 << 30);
    assert_eq!("16TiB".parse::<ByteSize>().unwrap().0, 16 << 40);
    assert_eq!("512".parse::<ByteSize>().unwrap().0, 512);
    assert_eq!("1KiB".parse::<ByteSize>().unwrap().0, 1024);
    assert!("12XB".parse::<ByteSize>().is_err());
    assert!("-5MiB".parse::<ByteSize>().is_err());

    assert_eq!("150us".parse::<MakiDuration>().unwrap().0.as_micros(), 150);
    assert_eq!("50ms".parse::<MakiDuration>().unwrap().0.as_millis(), 50);
    assert_eq!("5s".parse::<MakiDuration>().unwrap().0.as_secs(), 5);
    assert_eq!("2m".parse::<MakiDuration>().unwrap().0.as_secs(), 120);
    assert!("5 parsecs".parse::<MakiDuration>().is_err());
}

// ---------- malformed input: parser panic = 0 ----------

/// Fuzz-smoke: random and mutated bytes into every binary decoder — the
/// process must never panic (Err is fine).
#[test]
fn binary_decoders_never_panic_on_garbage() {
    let mut rng = StdRng::seed_from_u64(0xF0F0);
    let valid_sb = sb().encode();
    let valid_slot = SlotHeader {
        unit_index: 1,
        write_sequence: 2,
        ciphertext_len: 100,
        flags: 0,
        ciphertext_crc: 5,
    }
    .encode()
    .to_vec();
    let valid_alloc = AllocationMap::new(64).encode();
    let valid_cat = {
        let mut c = ShardCatalog::new();
        c.insert(1);
        c.encode()
    };
    let mut record_stream = Vec::new();
    for i in 0..3 {
        record_stream.extend(encode_record(&rec(i + 1, i, 9, 50)));
    }

    for i in 0..4000 {
        let base: &[u8] = match i % 6 {
            0 => &valid_sb,
            1 => &valid_slot,
            2 => &valid_alloc,
            3 => &valid_cat,
            4 => &record_stream,
            _ => &[],
        };
        let mut data = base.to_vec();
        // random mutations: truncate / extend / flip
        match rng.random_range(0..4u32) {
            0 => {
                let n = rng.random_range(0..=data.len());
                data.truncate(n);
            }
            1 => {
                for _ in 0..rng.random_range(1..20) {
                    data.push(rng.random());
                }
            }
            2 => {
                for _ in 0..rng.random_range(1..30) {
                    if data.is_empty() {
                        break;
                    }
                    let idx = rng.random_range(0..data.len());
                    data[idx] ^= 1 << rng.random_range(0..8);
                }
            }
            _ => {
                data = (0..rng.random_range(0..300))
                    .map(|_| rng.random())
                    .collect();
            }
        }
        // must not panic:
        let _ = Superblock::decode(&data);
        let _ = SlotHeader::decode(&data);
        let _ = AllocationMap::decode(&data);
        let _ = ShardCatalog::decode(&data);
        let _ = SegmentHeader::decode(&data);
        let _ = scan_segment(&data, 1);
    }
}

/// Fuzz-smoke for the TOML config parser: mutated configs must never panic.
#[test]
fn config_parser_never_panics_on_garbage() {
    let mut rng = StdRng::seed_from_u64(0xC0FF);
    let base = FULL_CONFIG.as_bytes();
    for _ in 0..1500 {
        let mut data = base.to_vec();
        match rng.random_range(0..3u32) {
            0 => {
                let n = rng.random_range(0..=data.len());
                data.truncate(n);
            }
            1 => {
                for _ in 0..rng.random_range(1..40) {
                    if data.is_empty() {
                        break;
                    }
                    let idx = rng.random_range(0..data.len());
                    data[idx] = rng.random();
                }
            }
            _ => {
                data = (0..rng.random_range(0..500))
                    .map(|_| rng.random())
                    .collect();
            }
        }
        if let Ok(s) = String::from_utf8(data) {
            let _ = parse_config(&s); // must not panic
        }
    }
}

// ---------- volume initialization ----------

#[test]
fn create_volume_initializes_durable_layout() {
    let backing = CrashableBacking::new();
    let s = maki_format::init::create_volume(&backing, sb()).unwrap();
    // Everything must survive a lose-all crash immediately after creation.
    backing.crash_all_lost();
    let ab = AbStore::new("superblock.a", "superblock.b");
    let loaded = ab.load::<Superblock>(&backing).unwrap().unwrap();
    assert_eq!(loaded.volume_uuid, s.volume_uuid);
    let cat_ab = AbStore::new("shard-catalog.a", "shard-catalog.b");
    let cat: ShardCatalog = cat_ab.load(&backing).unwrap().unwrap();
    assert_eq!(cat.shard_indices().count(), 0);
    for d in ["data", "journal", "checkpoint"] {
        assert!(backing.exists(d).unwrap(), "{d} must exist after crash");
    }
    // double-create refuses
    assert!(maki_format::init::create_volume(&backing, sb()).is_err());
}
