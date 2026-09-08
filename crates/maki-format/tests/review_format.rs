//! Format-level regression tests for the 2026-09-02 review: the journal
//! durable mark, boundary-aware segment scanning, A/B read classification,
//! and the initial checkpoint state written at volume creation.

use std::io;
use std::sync::Arc;

use uuid::Uuid;

use maki_backing::Backing;
use maki_format::ab::AbStore;
use maki_format::checkpoint::{CheckpointState, CHECKPOINT_STATE_A, CHECKPOINT_STATE_B};
use maki_format::error::FormatError;
use maki_format::geometry::Geometry;
use maki_format::journal::{
    encode_record, max_segment_file_size, scan_segment_bounded, DurableMark, JournalRecord,
    ScanOutcome, DURABLE_MARK_SIZE, MAX_PAYLOAD, RECORD_HEADER_SIZE, SEGMENT_HEADER_SIZE,
};
use maki_format::superblock::Superblock;
use maki_format::{init, layout};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::CrashableBacking;

fn sb() -> Superblock {
    Superblock {
        generation: 1,
        volume_uuid: Uuid::from_u128(0x0123_4567_89AB_CDEF_0123_4567_89AB_CDEF),
        provider_type: "remote-http".into(),
        crypto_compatibility_id: "vendor-profile-v1".into(),
        key_identity: "key-1".into(),
        geometry: Geometry::compute(4096, 4096, 512, 4384, 16 << 40, 64 << 30).unwrap(),
        format_version: 1,
        created_unix: 1_756_684_800,
    }
}

fn rec(seq: u64, fill: u8, len: usize) -> Vec<u8> {
    encode_record(&JournalRecord {
        sequence: seq,
        unit_index: seq * 3,
        payload: vec![fill; len],
    })
}

// ---------- durable mark ----------

#[test]
fn durable_mark_roundtrip_and_corruption() {
    let m = DurableMark {
        segment_index: 7,
        durable_size: 123_456,
    };
    let bytes = m.encode();
    assert_eq!(bytes.len(), DURABLE_MARK_SIZE);
    assert_eq!(DurableMark::decode(&bytes).unwrap(), m);

    let mut bad = bytes;
    bad[20] ^= 0x01;
    assert!(matches!(
        DurableMark::decode(&bad),
        Err(FormatError::BadChecksum(_))
    ));
    assert!(DurableMark::decode(&bytes[..10]).is_err());
    let mut magic = m.encode();
    magic[0] ^= 0xFF;
    assert!(matches!(
        DurableMark::decode(&magic),
        Err(FormatError::BadMagic(_))
    ));
}

/// Golden vector: the v1 durable-mark encoding is frozen.
#[test]
fn durable_mark_golden_vector_frozen() {
    let bytes = DurableMark {
        segment_index: 0x0102_0304_0506_0708,
        durable_size: 0x1122_3344_5566_7788,
    }
    .encode();
    assert_eq!(&bytes[0..8], b"MAKIJDM1");
    let crc = crc32fast::hash(&bytes[..bytes.len() - 4]);
    let expected: u32 = include!("golden/durable_mark_v1.crc");
    assert_eq!(
        crc, expected,
        "durable mark encoding changed! crc={crc:#010x}"
    );
}

// ---------- boundary-aware scanning ----------

#[test]
fn bounded_scan_treats_damage_before_boundary_as_corruption() {
    let mut buf = Vec::new();
    buf.extend(rec(1, 1, 100));
    buf.extend(rec(2, 2, 100));
    let durable = buf.len();
    buf.extend(rec(3, 3, 100));

    // Damage inside the durable prefix, at the very last durable record:
    // nothing valid needs to follow for this to be corruption.
    let mut hdr = buf.clone();
    hdr.truncate(durable); // record 3 absent
    let r2 = RECORD_HEADER_SIZE + 100;
    hdr[r2] ^= 0xFF; // record 2's magic
    let (records, outcome) = scan_segment_bounded(&hdr, 1, Some(durable));
    assert_eq!(records.len(), 1);
    assert!(
        matches!(outcome, ScanOutcome::Corrupt { at, .. } if at == r2),
        "{outcome:?}"
    );

    // Zeroed durable record: also corruption (not a preallocated tail).
    let mut zeroed = buf.clone();
    zeroed[r2..durable].fill(0);
    zeroed.truncate(durable);
    let (_, outcome) = scan_segment_bounded(&zeroed, 1, Some(durable));
    assert!(
        matches!(outcome, ScanOutcome::Corrupt { .. }),
        "{outcome:?}"
    );

    // Payload damage in the durable prefix.
    let mut payload = buf.clone();
    payload[r2 + RECORD_HEADER_SIZE + 5] ^= 0x01;
    let (_, outcome) = scan_segment_bounded(&payload, 1, Some(durable));
    assert!(
        matches!(outcome, ScanOutcome::Corrupt { .. }),
        "{outcome:?}"
    );

    // Truncated inside the durable prefix.
    let mut short = buf.clone();
    short.truncate(durable - 10);
    let (_, outcome) = scan_segment_bounded(&short, 1, Some(durable));
    assert!(
        matches!(outcome, ScanOutcome::Corrupt { .. }),
        "{outcome:?}"
    );
}

#[test]
fn bounded_scan_treats_damage_after_boundary_as_torn_tail() {
    let mut buf = Vec::new();
    buf.extend(rec(1, 1, 100));
    let durable = buf.len();
    buf.extend(rec(2, 2, 100));
    buf.extend(rec(3, 3, 100));

    // Record 2 lost (zeroed) but record 3 persisted: torn at record 2.
    let mut lost = buf.clone();
    let r3 = 2 * (RECORD_HEADER_SIZE + 100);
    lost[durable..r3].fill(0);
    let (records, outcome) = scan_segment_bounded(&lost, 1, Some(durable));
    assert_eq!(records.len(), 1);
    assert_eq!(outcome, ScanOutcome::TornTail { at: durable });

    // Record 2's payload torn, record 3 intact: still a torn tail.
    let mut torn = buf.clone();
    torn[durable + RECORD_HEADER_SIZE + 3] ^= 0x01;
    let (records, outcome) = scan_segment_bounded(&torn, 1, Some(durable));
    assert_eq!(records.len(), 1);
    assert_eq!(outcome, ScanOutcome::TornTail { at: durable });

    // Whereas the heuristic (no boundary) calls the payload case corrupt.
    let (_, outcome) = scan_segment_bounded(&torn, 1, None);
    assert!(matches!(outcome, ScanOutcome::Corrupt { .. }));

    // Intact volatile records are kept.
    let (records, outcome) = scan_segment_bounded(&buf, 1, Some(durable));
    assert_eq!(records.len(), 3);
    assert_eq!(outcome, ScanOutcome::Clean);
}

#[test]
fn bounded_scan_still_rejects_logical_inconsistencies_anywhere() {
    let mut buf = Vec::new();
    buf.extend(rec(1, 1, 100));
    let durable = buf.len();
    buf.extend(rec(5, 2, 100)); // gap, in the volatile region
    let (_, outcome) = scan_segment_bounded(&buf, 1, Some(durable));
    assert!(matches!(outcome, ScanOutcome::Corrupt { .. }));
}

#[test]
fn segment_size_cap_is_generous_but_finite() {
    let cap = max_segment_file_size(256 << 20);
    assert!(
        cap >= (256 << 20)
            + SEGMENT_HEADER_SIZE as u64
            + RECORD_HEADER_SIZE as u64
            + MAX_PAYLOAD as u64
    );
    assert!(cap < 4 << 30);
    assert_eq!(max_segment_file_size(u64::MAX), u64::MAX);
}

// ---------- A/B read classification ----------

#[test]
fn ab_load_reports_hard_io_errors_instead_of_masking_them() {
    let backing = CrashableBacking::new();
    let ab = AbStore::new("m.a", "m.b");
    let mut s = CheckpointState::default();
    s.checkpoint_sequence = 9;
    ab.store(&backing, &mut s).unwrap();
    ab.store(&backing, &mut s).unwrap();

    backing.set_fault_hook(Some(Arc::new(|op| match op {
        FaultOp::Open { path, .. } if *path == "m.b" => {
            Some(io::Error::new(io::ErrorKind::PermissionDenied, "EACCES"))
        }
        _ => None,
    })));
    match ab.load::<CheckpointState>(&backing) {
        Err(FormatError::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::PermissionDenied),
        other => panic!("expected an I/O error, got {:?}", other.map(|_| ())),
    }
    assert!(ab.next_target_path::<CheckpointState>(&backing).is_err());
    assert!(ab.store(&backing, &mut s).is_err());
    backing.set_fault_hook(None);
    assert_eq!(
        ab.load::<CheckpointState>(&backing)
            .unwrap()
            .unwrap()
            .checkpoint_sequence,
        9
    );
}

#[test]
fn ab_load_treats_missing_empty_and_corrupt_sides_as_invalid_copies() {
    let backing = CrashableBacking::new();
    let ab = AbStore::new("m.a", "m.b");
    assert!(ab.load::<CheckpointState>(&backing).unwrap().is_none());

    let mut s = CheckpointState::default();
    s.checkpoint_sequence = 4;
    ab.store(&backing, &mut s).unwrap(); // side A
                                         // Side B: empty file.
    backing.open("m.b", true).unwrap().set_len(0).unwrap();
    assert_eq!(
        ab.load::<CheckpointState>(&backing)
            .unwrap()
            .unwrap()
            .checkpoint_sequence,
        4
    );
    // Side B: garbage.
    backing
        .open("m.b", true)
        .unwrap()
        .write_at(0, b"not a record at all")
        .unwrap();
    assert_eq!(
        ab.load::<CheckpointState>(&backing)
            .unwrap()
            .unwrap()
            .checkpoint_sequence,
        4
    );
}

// ---------- initial layout ----------

#[test]
fn create_volume_writes_checkpoint_state_and_durable_mark() {
    let backing = CrashableBacking::new();
    init::create_volume(&backing, sb()).unwrap();
    backing.crash_all_lost();

    let state = AbStore::new(CHECKPOINT_STATE_A, CHECKPOINT_STATE_B)
        .load::<CheckpointState>(&backing)
        .unwrap()
        .expect("checkpoint state exists on a fresh volume");
    assert_eq!(state.checkpoint_sequence, 0);
    for path in [CHECKPOINT_STATE_A, CHECKPOINT_STATE_B] {
        assert!(backing.exists(path).unwrap(), "{path} must survive a crash");
    }
    assert!(backing.exists(layout::JOURNAL_DURABLE_MARK).unwrap());
    assert_eq!(
        backing
            .open(layout::JOURNAL_DURABLE_MARK, false)
            .unwrap()
            .len()
            .unwrap(),
        0,
        "no durable information yet"
    );
}

// ---------- key canary (M-001) ----------

#[test]
fn canary_plaintext_is_deterministic_and_volume_bound() {
    let a = Uuid::from_u128(1);
    let b = Uuid::from_u128(2);
    let pa = maki_format::canary::canary_plaintext(&a, 4096);
    assert_eq!(pa.len(), 4096);
    assert_eq!(pa, maki_format::canary::canary_plaintext(&a, 4096));
    assert_ne!(pa, maki_format::canary::canary_plaintext(&b, 4096));
    assert!(pa.starts_with(b"MAKI-KEY-CANARY-V1"));
    assert!(pa[32..].iter().any(|b| *b != 0), "pattern, not zeros");
    // Tiny units still work (tag truncated).
    assert_eq!(maki_format::canary::canary_plaintext(&a, 8).len(), 8);
}

#[test]
fn key_canary_roundtrip_and_corruption() {
    use maki_format::canary::KeyCanary;
    let c = KeyCanary {
        generation: 3,
        volume_uuid: Uuid::from_u128(0xC0DE),
        unit_index: maki_format::canary::CANARY_UNIT_INDEX,
        ciphertext: (0..300u32).map(|i| i as u8).collect(),
    };
    let bytes = c.encode();
    assert_eq!(KeyCanary::decode(&bytes).unwrap(), c);
    let mut bad = bytes.clone();
    bad[60] ^= 0x01;
    assert!(matches!(
        KeyCanary::decode(&bad),
        Err(FormatError::BadChecksum(_))
    ));
    assert!(KeyCanary::decode(&bytes[..40]).is_err());
    assert!(KeyCanary::decode(b"nonsense").is_err());
}

#[test]
fn canary_unit_index_is_json_safe_and_out_of_range() {
    let idx = maki_format::canary::CANARY_UNIT_INDEX;
    assert!(idx < (1u64 << 53));
    // 16 TiB of 512-byte units is far below the reserved index.
    let g = Geometry::compute(512, 512, 512, 512, 16 << 40, 1 << 30).unwrap();
    assert!(g.num_units() < idx);
}

/// Golden vector: the v1 canary record and plaintext are frozen (an old
/// canary must verify forever).
#[test]
fn key_canary_golden_vectors_frozen() {
    use maki_format::canary::{canary_plaintext, KeyCanary};
    let uuid = Uuid::from_u128(0x0123_4567_89AB_CDEF_0123_4567_89AB_CDEF);
    let plain_crc = crc32fast::hash(&canary_plaintext(&uuid, 4096));
    let expected_plain: u32 = include!("golden/canary_plaintext_v1.crc");
    assert_eq!(
        plain_crc, expected_plain,
        "canary plaintext changed! crc={plain_crc:#010x}"
    );
    let bytes = KeyCanary {
        generation: 1,
        volume_uuid: uuid,
        unit_index: maki_format::canary::CANARY_UNIT_INDEX,
        ciphertext: vec![0xAB; 64],
    }
    .encode();
    assert_eq!(&bytes[0..8], b"MAKICNY1");
    let crc = crc32fast::hash(&bytes[..bytes.len() - 4]);
    let expected: u32 = include!("golden/canary_record_v1.crc");
    assert_eq!(
        crc, expected,
        "canary record encoding changed! crc={crc:#010x}"
    );
}

// ---------- audit: geometry bounds the journal and allocation map impose ----------

#[test]
fn geometry_rejects_units_the_journal_or_allocation_map_cannot_hold() {
    // One unit's ciphertext must fit a journal record (MAX_PAYLOAD).
    let err =
        Geometry::compute(4096, 32 << 20, 512, (32 << 20) + 288, 1 << 30, 64 << 30).unwrap_err();
    assert!(err.to_string().contains("max_ciphertext_size"), "{err}");
    // Exactly at the bound is fine.
    Geometry::compute(4096, 4096, 512, MAX_PAYLOAD, 1 << 30, 64 << 30).unwrap();

    // A shard's unit count must fit the allocation map's u32 index space.
    let err = Geometry::compute(4096, 4096, 512, 4384, 1 << 30, 32 << 40).unwrap_err();
    assert!(err.to_string().contains("units_per_shard"), "{err}");
    Geometry::compute(4096, 4096, 512, 4384, 1 << 30, (u32::MAX as u64) * 4096).unwrap();
}

// ---------- audit: A/B store target chosen from the typed view ----------

#[test]
fn ab_store_overwrites_the_side_that_does_not_decode_as_the_record_type() {
    use maki_format::ab::AbRecord;
    use maki_format::catalog::ShardCatalog;

    let backing = CrashableBacking::new();
    let ab = AbStore::new("m.a", "m.b");
    let mut s = CheckpointState::default();
    s.checkpoint_sequence = 4;
    ab.store(&backing, &mut s).unwrap(); // side A, generation 1
    ab.store(&backing, &mut s).unwrap(); // side B, generation 2

    // Side A now holds a CRC-valid record of *another* type with a higher
    // raw generation: it passes the raw generation probe but is not a
    // loadable CheckpointState.
    let mut foreign = ShardCatalog::new();
    foreign.set_generation(10);
    let bytes = foreign.encode();
    let file = backing.open("m.a", true).unwrap();
    file.set_len(bytes.len() as u64).unwrap();
    file.write_at(0, &bytes).unwrap();
    file.sync_data().unwrap();
    assert_eq!(
        ab.side_generations::<CheckpointState>(&backing).unwrap(),
        (None, Some(2))
    );
    assert_eq!(
        ab.next_target_path::<CheckpointState>(&backing).unwrap(),
        "m.a",
        "the undecodable side is the one to overwrite"
    );

    // The store must overwrite A (invalid for this type), never B (the
    // only loadable copy), and still move past every raw generation.
    ab.store(&backing, &mut s).unwrap();
    assert_eq!(
        ab.side_generations::<CheckpointState>(&backing).unwrap(),
        (Some(11), Some(2))
    );
    let loaded = ab.load::<CheckpointState>(&backing).unwrap().unwrap();
    assert_eq!((loaded.generation(), loaded.checkpoint_sequence), (11, 4));
}

// ---------- MAKI-026 / MAKI-027 (2026-09-07): parser and integer robustness ----------

/// MAKI-026: a superblock copy is always exactly one fixed-size block. A file
/// longer than that is corruption and must be rejected as an invalid copy
/// *by its size*, before it is read into memory — not read whole and then
/// decoded from its valid-looking prefix (which would both accept corruption
/// and allow a tampered length to force a large allocation).
#[test]
fn oversized_superblock_copy_is_rejected_before_it_is_read() {
    let backing = Arc::new(CrashableBacking::new());
    let encoded = sb().encode();
    let file = backing.open(layout::SUPERBLOCK_A, true).unwrap();
    file.write_at(0, &encoded).unwrap();
    // A valid superblock prefix followed by padding: a larger-than-a-block file.
    file.set_len(encoded.len() as u64 * 4).unwrap();
    file.sync_data().unwrap();
    let store = AbStore::new(layout::SUPERBLOCK_A, layout::SUPERBLOCK_B);
    assert!(
        store.load::<Superblock>(backing.as_ref()).unwrap().is_none(),
        "an over-long superblock copy must be treated as invalid, not decoded from its prefix"
    );
}

/// MAKI-027: an A/B store at the top of the generation space must fail closed
/// rather than wrap `generation + 1` to 0 (a wrapped record would lose to every
/// existing copy and could never be selected).
#[test]
fn storing_at_max_generation_fails_closed_instead_of_wrapping() {
    use maki_format::ab::AbRecord;
    let backing = Arc::new(CrashableBacking::new());
    let store = AbStore::new(CHECKPOINT_STATE_A, CHECKPOINT_STATE_B);
    let mut state = CheckpointState::default();
    state.set_generation(u64::MAX);
    let err = store.store(backing.as_ref(), &mut state).unwrap_err();
    assert!(matches!(err, FormatError::Invalid(_)), "{err:?}");
}

// ---------- Follow-up review 2026-09-08: FUP-012 (A/B read bounds) ----------

/// FUP-012: the fixed-size checkpoint record must carry a tight per-type read
/// bound, not inherit the 1 GiB last-resort cap.
#[test]
fn followup_checkpoint_v1_has_a_tight_read_bound() {
    assert_eq!(CheckpointState::default().encode().len(), 32);
    assert_eq!(
        <CheckpointState as maki_format::ab::AbRecord>::MAX_ENCODED_LEN,
        32,
        "the fixed-size checkpoint must not inherit a 1GiB allocation cap"
    );
}

/// FUP-012: a frozen v1 record must consume exactly its length; trailing bytes
/// under a valid CRC are corruption, not a forward-compatible extension.
#[test]
fn followup_checkpoint_rejects_crc_valid_trailing_payload() {
    let encoded = CheckpointState::default().encode();
    let mut padded = encoded[..encoded.len() - 4].to_vec();
    padded.extend_from_slice(&[0x55; 4096]);
    let crc = crc32fast::hash(&padded);
    padded.extend_from_slice(&crc.to_le_bytes());
    assert!(
        CheckpointState::decode(&padded).is_err(),
        "a v1 record must consume exactly its frozen format length"
    );
}

struct FollowupReadSpy {
    inner: Arc<CrashableBacking>,
    largest: Arc<std::sync::atomic::AtomicUsize>,
}
struct FollowupReadSpyFile {
    inner: Arc<dyn maki_backing::BackingFile>,
    largest: Arc<std::sync::atomic::AtomicUsize>,
}
impl maki_backing::BackingFile for FollowupReadSpyFile {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.largest
            .fetch_max(buf.len(), std::sync::atomic::Ordering::SeqCst);
        self.inner.read_at(offset, buf)
    }
    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.inner.write_at(offset, data)
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.inner.set_len(len)
    }
    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }
    fn sync_data(&self) -> io::Result<()> {
        self.inner.sync_data()
    }
}
impl Backing for FollowupReadSpy {
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn maki_backing::BackingFile>> {
        Ok(Arc::new(FollowupReadSpyFile {
            inner: self.inner.open(path, create)?,
            largest: self.largest.clone(),
        }))
    }
    fn exists(&self, p: &str) -> io::Result<bool> {
        self.inner.exists(p)
    }
    fn remove(&self, p: &str) -> io::Result<()> {
        self.inner.remove(p)
    }
    fn rename(&self, a: &str, b: &str) -> io::Result<()> {
        self.inner.rename(a, b)
    }
    fn create_dir_all(&self, p: &str) -> io::Result<()> {
        self.inner.create_dir_all(p)
    }
    fn list(&self, p: &str) -> io::Result<Vec<String>> {
        self.inner.list(p)
    }
    fn sync_dir(&self, p: &str) -> io::Result<()> {
        self.inner.sync_dir(p)
    }
    fn try_lock(&self, p: &str) -> io::Result<Box<dyn maki_backing::VolumeLock>> {
        self.inner.try_lock(p)
    }
}

/// FUP-012: the generation probe on the write (store) path must also respect
/// the per-type read bound — a corrupt oversized file must not be read whole by
/// `RawGeneration` before the typed parse.
#[test]
fn followup_superblock_store_raw_generation_probe_is_also_bounded() {
    let backing = Arc::new(CrashableBacking::new());
    let file = backing.open(layout::SUPERBLOCK_A, true).unwrap();
    file.write_at(0, &vec![0x55; 16384]).unwrap();
    let largest = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let spy = FollowupReadSpy {
        inner: backing,
        largest: largest.clone(),
    };
    let mut current = sb();
    AbStore::new(layout::SUPERBLOCK_A, layout::SUPERBLOCK_B)
        .store(&spy, &mut current)
        .unwrap();
    assert!(
        largest.load(std::sync::atomic::Ordering::SeqCst) <= 4096,
        "RawGeneration must not reintroduce an oversized whole-file read before typed parsing"
    );
}
