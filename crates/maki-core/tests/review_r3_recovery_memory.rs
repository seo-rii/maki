//! MAKI-025 (partial): segment scan scratch must not grow with journal size.
//! The uncheckpointed replay result and the eventual overlay are separate,
//! still-unbounded consumers; these tests isolate checkpoint-covered input.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Arc;

use maki_backing::{Backing, FileBacking};
use maki_core::recovery::{scan_journal, JournalRepair, RecoveryError};
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::geometry::Geometry;
use maki_format::journal::{
    encode_record, scan_segment_bounded, DurableMark, JournalRecord, ScanOutcome, SegmentHeader,
    SEGMENT_HEADER_SIZE,
};
use maki_format::superblock::Superblock;
use maki_format::{init, layout};
use uuid::Uuid;

#[derive(Clone, Copy, Default, Debug)]
struct Allocations {
    live: isize,
    peak: usize,
    largest: usize,
}

thread_local! {
    static ALLOCATIONS: Cell<Option<Allocations>> = const { Cell::new(None) };
}

struct MeasuredAllocator;

fn account(delta: isize, allocated: usize) {
    let _ = ALLOCATIONS.try_with(|cell| {
        if let Some(mut stats) = cell.get() {
            stats.live += delta;
            stats.peak = stats.peak.max(stats.live.max(0) as usize);
            stats.largest = stats.largest.max(allocated);
            cell.set(Some(stats));
        }
    });
}

unsafe impl GlobalAlloc for MeasuredAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            account(layout.size() as isize, layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            account(layout.size() as isize, layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        account(-(layout.size() as isize), 0);
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let ptr = unsafe { System.realloc(ptr, layout, size) };
        if !ptr.is_null() {
            account(size as isize - layout.size() as isize, size);
        }
        ptr
    }
}

#[global_allocator]
static ALLOCATOR: MeasuredAllocator = MeasuredAllocator;

struct Fixture {
    _directory: tempfile::TempDir,
    backing: Arc<dyn Backing>,
    superblock: Superblock,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let backing: Arc<dyn Backing> = Arc::new(FileBacking::new(directory.path()).unwrap());
        let superblock = Superblock {
            generation: 0,
            volume_uuid: Uuid::from_u128(0x2500),
            provider_type: "fake".into(),
            crypto_compatibility_id: "recovery-memory".into(),
            key_identity: "key".into(),
            geometry: Geometry::compute(512, 512, 512, 4096, 1 << 20, 1 << 16).unwrap(),
            format_version: 1,
            created_unix: 0,
        };
        init::create_volume(backing.as_ref(), superblock.clone()).unwrap();
        Self {
            _directory: directory,
            backing,
            superblock,
        }
    }

    fn segment(&self, body: &[u8], durable_body: Option<usize>) {
        let file = self
            .backing
            .open(&layout::journal_segment(0), true)
            .unwrap();
        let header = SegmentHeader {
            segment_index: 0,
            volume_uuid: self.superblock.volume_uuid,
            base_sequence: 1,
        }
        .encode();
        file.set_len(0).unwrap();
        file.write_at(0, &header).unwrap();
        file.write_at(header.len() as u64, body).unwrap();
        if let Some(bytes) = durable_body {
            let mark = DurableMark {
                segment_index: 0,
                durable_size: (SEGMENT_HEADER_SIZE + bytes) as u64,
            };
            self.backing
                .open(layout::JOURNAL_DURABLE_MARK, true)
                .unwrap()
                .write_at(0, &mark.encode())
                .unwrap();
        } else if self.backing.exists(layout::JOURNAL_DURABLE_MARK).unwrap() {
            self.backing.remove(layout::JOURNAL_DURABLE_MARK).unwrap();
        }
    }
}

fn covered_scan_allocations(records: u64) -> Allocations {
    let fixture = Fixture::new();
    fixture.segment(&[], None);
    let file = fixture
        .backing
        .open(&layout::journal_segment(0), false)
        .unwrap();
    let mut position = SEGMENT_HEADER_SIZE as u64;
    for sequence in 1..=records {
        let record = encode_record(&JournalRecord {
            sequence,
            unit_index: 0,
            payload: vec![sequence as u8; 4096],
        });
        file.write_at(position, &record).unwrap();
        position += record.len() as u64;
    }
    // The fixture and its payload construction are outside measurement. The
    // real-file backing does not accumulate read-event traces or copy a mock
    // file image, and scan_journal only borrows the pre-existing fixture.
    ALLOCATIONS.with(|cell| cell.set(Some(Allocations::default())));
    let result = scan_journal(&fixture.backing, &fixture.superblock, records, position);
    let stats = ALLOCATIONS.with(|cell| cell.replace(None).unwrap());
    let scan = result.unwrap();
    assert!(scan.replay.is_empty());
    assert_eq!(scan.segments[0].record_count, records);
    assert_eq!(scan.durable_sequence, records);
    assert!(scan.repairs.is_empty());
    stats
}

#[test]
fn checkpoint_covered_segments_use_bounded_scan_memory() {
    let small = covered_scan_allocations(256);
    let large = covered_scan_allocations(16_384);
    eprintln!("covered segment scan allocations: small={small:?}, large={large:?}");
    assert!(
        large.largest <= 128 * 1024,
        "a segment must not become one allocation: small={small:?}, large={large:?}"
    );
    assert!(
        large.peak <= 512 * 1024 && large.peak <= small.peak + 64 * 1024,
        "covered records must be discarded during scanning: small={small:?}, large={large:?}"
    );
}

#[test]
fn a_geometry_oversized_record_is_checked_without_allocating_its_payload() {
    for intact in [false, true] {
        let fixture = Fixture::new();
        let mut body = encode_record(&JournalRecord {
            sequence: 1,
            unit_index: 0,
            payload: vec![5; 1 << 20],
        });
        if !intact {
            *body.last_mut().unwrap() ^= 1;
        }
        fixture.segment(&body, None);
        ALLOCATIONS.with(|cell| cell.set(Some(Allocations::default())));
        let result = scan_journal(&fixture.backing, &fixture.superblock, 0, 1 << 20);
        let stats = ALLOCATIONS.with(|cell| cell.replace(None).unwrap());
        if intact {
            assert!(
                matches!(result, Err(RecoveryError::Corrupt(ref error)) if error.contains("maximum ciphertext size"))
            );
        } else {
            // Geometry does not turn an invalid, unsynced payload into a
            // valid record: retain the existing torn-tail classification.
            let scan = result.unwrap();
            assert!(scan.replay.is_empty());
            assert_eq!(scan.segments[0].size, SEGMENT_HEADER_SIZE as u64);
        }
        assert!(stats.largest <= 128 * 1024, "intact={intact}: {stats:?}");
    }
}

fn record(sequence: u64) -> Vec<u8> {
    encode_record(&JournalRecord {
        sequence,
        unit_index: 0,
        payload: vec![sequence as u8; 512],
    })
}

#[test]
fn streaming_scan_matches_the_format_scanner_at_tail_and_durability_boundaries() {
    let fixture = Fixture::new();
    let original: Vec<u8> = (1..=3).flat_map(record).collect();
    let record_size = record(1).len();
    let mut cases = vec![original.clone()];
    for end in [
        0,
        1,
        31,
        32,
        record_size - 1,
        record_size + 17,
        original.len() - 1,
    ] {
        cases.push(original[..end].to_vec());
    }
    for offset in [0, 31, 32, record_size, record_size + 39, original.len() - 1] {
        let mut bad = original.clone();
        bad[offset] ^= 0x80;
        cases.push(bad);
    }
    let mut zeros = original.clone();
    zeros.resize(original.len() + 128 * 1024 + 3, 0);
    cases.push(zeros.clone());
    *zeros.last_mut().unwrap() = 1;
    cases.push(zeros);
    cases.push(vec![0; 128 * 1024 + 7]);
    let mut wrong_sequence = record(1);
    wrong_sequence.extend(record(7));
    cases.push(wrong_sequence);
    let mut impossible_length = record(1);
    impossible_length[20..24]
        .copy_from_slice(&(maki_format::journal::MAX_PAYLOAD + 1).to_le_bytes());
    let header_crc = crc32fast::hash(&impossible_length[..28]);
    impossible_length[28..32].copy_from_slice(&header_crc.to_le_bytes());
    cases.push(impossible_length);
    cases.push(encode_record(&JournalRecord {
        sequence: 1,
        unit_index: 0,
        payload: Vec::new(),
    }));

    for (case, body) in cases.iter().enumerate() {
        for durable in [None, Some(0), Some(body.len() / 2), Some(body.len())] {
            fixture.segment(body, durable);
            let (records, expected) = scan_segment_bounded(body, 1, Some(durable.unwrap_or(0)));
            let actual = scan_journal(&fixture.backing, &fixture.superblock, 1, 1 << 20);
            match expected {
                ScanOutcome::Corrupt { at, reason } => {
                    let error = match actual {
                        Err(RecoveryError::Corrupt(error)) => error,
                        _ => panic!(
                            "case={case}, durable={durable:?}: expected corrupt at {at}: {reason}"
                        ),
                    };
                    assert!(
                        error.contains(&reason),
                        "case={case}, durable={durable:?}: {error}"
                    );
                }
                outcome => {
                    let scan = actual.unwrap_or_else(|error| {
                        panic!("case={case}, durable={durable:?}: {error}")
                    });
                    let accepted = records
                        .iter()
                        .map(|record| 32 + record.payload.len())
                        .sum::<usize>();
                    let end = match outcome {
                        ScanOutcome::TornTail { at } => at,
                        ScanOutcome::Clean => accepted,
                        ScanOutcome::Corrupt { .. } => unreachable!(),
                    };
                    assert_eq!(scan.segments[0].size, (SEGMENT_HEADER_SIZE + end) as u64);
                    assert_eq!(scan.segments[0].record_count, records.len() as u64);
                    assert_eq!(
                        scan.replay,
                        records
                            .into_iter()
                            .filter(|record| record.sequence > 1)
                            .collect::<Vec<_>>()
                    );
                    let repairs = if end < body.len() {
                        vec![JournalRepair::Truncate {
                            path: layout::journal_segment(0),
                            len: (SEGMENT_HEADER_SIZE + end) as u64,
                        }]
                    } else {
                        Vec::new()
                    };
                    assert_eq!(scan.repairs, repairs, "case={case}, durable={durable:?}");
                }
            }
            assert_eq!(
                fixture
                    .backing
                    .open(&layout::journal_segment(0), false)
                    .unwrap()
                    .len()
                    .unwrap(),
                (SEGMENT_HEADER_SIZE + body.len()) as u64,
                "the scan must stay read-only"
            );
        }
    }
}

#[test]
fn a_creation_segment_must_be_zero_beyond_the_first_read_chunk() {
    for all_zero in [true, false] {
        let fixture = Fixture::new();
        let mut image = vec![0; 128 * 1024 + 11];
        if !all_zero {
            *image.last_mut().unwrap() = 1;
        }
        fixture
            .backing
            .open(&layout::journal_segment(0), true)
            .unwrap()
            .write_at(0, &image)
            .unwrap();
        let result = scan_journal(&fixture.backing, &fixture.superblock, 0, 1 << 20);
        if all_zero {
            let scan = result.unwrap();
            assert!(scan.segments.is_empty());
            assert_eq!(
                scan.repairs,
                [JournalRepair::Discard {
                    path: layout::journal_segment(0)
                }]
            );
        } else {
            assert!(
                matches!(result, Err(RecoveryError::Corrupt(ref error)) if error.contains("invalid header"))
            );
        }
    }
}

#[test]
fn normalized_prefix_fingerprint_matches_rewrite_chunk_boundaries() {
    for torn in [false, true] {
        let fixture = Fixture::new();
        let mut body: Vec<u8> = (1..=257).flat_map(record).collect();
        let accepted = body.len();
        if torn {
            body.extend_from_slice(&record(258)[..47]);
        } else {
            body.resize(body.len() + 70_000, 0);
        }
        fixture.segment(&body, None);
        let volume = Volume::recover(
            fixture.backing.clone(),
            VolumeOptions {
                journal_segment_size: 1 << 20,
            },
        )
        .unwrap();
        assert_eq!(volume.journal_durable_sequence(), 257);
        assert_eq!(volume.read_ct(0).unwrap().unwrap(), (257, vec![1; 512]));
        assert_eq!(
            fixture
                .backing
                .open(&layout::journal_segment(0), false)
                .unwrap()
                .len()
                .unwrap(),
            (SEGMENT_HEADER_SIZE + accepted) as u64
        );
    }
}
