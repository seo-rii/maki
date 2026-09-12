//! The public slice scanner must not wrap a record sequence or panic while
//! classifying a damaged payload's possible successor. Production recovery
//! uses its separate streaming scanner; these exercise the format API itself.

use maki_format::journal::{
    encode_record, scan_segment, scan_segment_bounded, JournalRecord, ScanOutcome,
    RECORD_HEADER_SIZE,
};

fn record(sequence: u64) -> Vec<u8> {
    encode_record(&JournalRecord {
        sequence,
        unit_index: 7,
        payload: vec![42; 8],
    })
}

#[test]
fn maximum_record_sequence_is_corrupt_before_it_enters_the_valid_prefix() {
    let body = record(u64::MAX);
    for durable in [None, Some(0), Some(body.len())] {
        let (records, outcome) = scan_segment_bounded(&body, u64::MAX, durable);
        assert!(records.is_empty());
        assert!(
            matches!(outcome, ScanOutcome::Corrupt { at: 0, .. }),
            "{outcome:?}"
        );
    }
}

#[test]
fn exhausting_sequence_preserves_only_the_representable_prefix() {
    let mut body = record(u64::MAX - 1);
    let prefix_len = body.len();
    body.extend(record(u64::MAX));
    // A wrapped zero must never look like a valid continuation in release.
    body.extend(record(0));
    let (records, outcome) = scan_segment(&body, u64::MAX - 1);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].sequence, u64::MAX - 1);
    assert!(
        matches!(outcome, ScanOutcome::Corrupt { at, .. } if at == prefix_len),
        "{outcome:?}"
    );
}

#[test]
fn heuristic_successor_lookahead_at_maximum_sequence_is_corrupt_without_wrapping() {
    for next_sequence in [0, 17, u64::MAX] {
        let mut body = record(u64::MAX);
        body[RECORD_HEADER_SIZE] ^= 1;
        body.extend(record(next_sequence));
        let (records, outcome) = scan_segment(&body, u64::MAX);
        assert!(records.is_empty());
        assert!(
            matches!(outcome, ScanOutcome::Corrupt { at: 0, .. }),
            "{outcome:?}"
        );
    }
}

#[test]
fn maximum_minus_one_remains_a_complete_valid_record_in_each_mode() {
    let body = record(u64::MAX - 1);
    for durable in [None, Some(0), Some(body.len())] {
        let (records, outcome) = scan_segment_bounded(&body, u64::MAX - 1, durable);
        assert_eq!(outcome, ScanOutcome::Clean);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].sequence, u64::MAX - 1);
        assert_eq!(records[0].payload, vec![42; 8]);
    }
}

#[test]
fn empty_and_unwritten_tail_do_not_consume_the_maximum_next_sequence() {
    for body in [&[][..], &[0; RECORD_HEADER_SIZE][..]] {
        let (records, outcome) = scan_segment(body, u64::MAX);
        assert!(records.is_empty());
        assert_eq!(outcome, ScanOutcome::Clean);
    }
}

#[test]
fn truncated_tail_keeps_its_durable_prefix_classification_at_the_boundary() {
    for sequence in [u64::MAX - 1, u64::MAX] {
        let mut body = record(sequence);
        body.pop();
        for durable in [None, Some(0)] {
            let (records, outcome) = scan_segment_bounded(&body, sequence, durable);
            assert!(records.is_empty());
            assert_eq!(outcome, ScanOutcome::TornTail { at: 0 });
        }
        let (_, outcome) = scan_segment_bounded(&body, sequence, Some(body.len()));
        assert!(matches!(outcome, ScanOutcome::Corrupt { at: 0, .. }));
    }
}

#[test]
fn damaged_last_payload_without_a_successor_retains_its_tail_classification() {
    for sequence in [u64::MAX - 1, u64::MAX] {
        let mut body = record(sequence);
        body[RECORD_HEADER_SIZE] ^= 1;
        for durable in [None, Some(0)] {
            let (records, outcome) = scan_segment_bounded(&body, sequence, durable);
            assert!(records.is_empty());
            assert_eq!(outcome, ScanOutcome::TornTail { at: 0 });
        }
        let (_, outcome) = scan_segment_bounded(&body, sequence, Some(body.len()));
        assert!(matches!(outcome, ScanOutcome::Corrupt { at: 0, .. }));
    }
}

#[test]
fn representable_successor_preserves_heuristic_and_explicit_durability_rules() {
    let mut body = record(u64::MAX - 1);
    body[RECORD_HEADER_SIZE] ^= 1;
    body.extend(record(u64::MAX));
    let (records, outcome) = scan_segment(&body, u64::MAX - 1);
    assert!(records.is_empty());
    assert!(matches!(outcome, ScanOutcome::Corrupt { at: 0, .. }));
    let (_, outcome) = scan_segment_bounded(&body, u64::MAX - 1, Some(0));
    assert_eq!(outcome, ScanOutcome::TornTail { at: 0 });
    let (_, outcome) = scan_segment_bounded(&body, u64::MAX - 1, Some(body.len()));
    assert!(matches!(outcome, ScanOutcome::Corrupt { at: 0, .. }));
}
