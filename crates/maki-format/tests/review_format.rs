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
    assert!(ab.next_target_path(&backing).is_err());
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
