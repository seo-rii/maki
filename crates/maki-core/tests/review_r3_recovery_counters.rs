//! CRC-valid counter exhaustion must refuse recovery before metadata repair.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

use maki_backing::Backing;
use maki_core::check::deep_check;
use maki_core::recovery::{scan_journal, RecoveryError};
use maki_core::volume::{Volume, VolumeOptions};
use maki_core::CoreError;
use maki_format::ab::AbStore;
use maki_format::checkpoint::{CheckpointState, CHECKPOINT_STATE_A, CHECKPOINT_STATE_B};
use maki_format::geometry::Geometry;
use maki_format::journal::{encode_record, DurableMark, JournalRecord, SegmentHeader};
use maki_format::superblock::Superblock;
use maki_format::{init, layout};
use maki_test_support::{crash_backing::FaultOp, CrashableBacking};
use uuid::Uuid;

const SEGMENT_SIZE: u64 = 4096;

struct Fixture {
    backing: Arc<CrashableBacking>,
    superblock: Superblock,
    checkpoint: u64,
}

impl Fixture {
    fn new(checkpoint: u64) -> Self {
        let backing = Arc::new(CrashableBacking::new());
        let superblock = Superblock {
            generation: 0,
            volume_uuid: Uuid::from_u128(0xc017),
            provider_type: "fake".into(),
            crypto_compatibility_id: "counter-boundaries".into(),
            key_identity: "key".into(),
            geometry: Geometry::compute(512, 512, 512, 544, 512 * 1024, 512 * 64).unwrap(),
            format_version: 1,
            created_unix: 0,
        };
        init::create_volume(backing.as_ref(), superblock.clone()).unwrap();
        let mut state = CheckpointState::default();
        state.checkpoint_sequence = checkpoint;
        let store = AbStore::new(CHECKPOINT_STATE_A, CHECKPOINT_STATE_B);
        store.store(backing.as_ref(), &mut state).unwrap();
        store.store(backing.as_ref(), &mut state).unwrap();
        Self {
            backing,
            superblock,
            checkpoint,
        }
    }

    fn segment(&self, index: u64, base: u64, sequences: &[u64]) {
        let header = SegmentHeader {
            segment_index: index,
            volume_uuid: self.superblock.volume_uuid,
            base_sequence: base,
        };
        let mut bytes = header.encode();
        for &sequence in sequences {
            bytes.extend(encode_record(&JournalRecord {
                sequence,
                unit_index: 0,
                payload: vec![42; 540],
            }));
        }
        self.backing
            .open(&layout::journal_segment(index), true)
            .unwrap()
            .write_at(0, &bytes)
            .unwrap();
    }

    fn observe_mutations(&self) -> Arc<Mutex<Vec<String>>> {
        let mutations = Arc::new(Mutex::new(Vec::new()));
        let observed = mutations.clone();
        self.backing.set_fault_hook(Some(Arc::new(move |op| {
            if !matches!(op, FaultOp::Open { create: false, .. }) {
                observed.lock().unwrap().push(format!("{op:?}"));
            }
            None
        })));
        mutations
    }
}

fn is_corruption(error: RecoveryError) -> bool {
    matches!(error, RecoveryError::Corrupt(_) | RecoveryError::Format(_))
}

fn assert_public_apis_refuse(checkpoint: u64, configure: impl Fn(&Fixture)) {
    let mut failures = Vec::new();
    for api in ["scan_journal", "deep_check", "Volume::recover"] {
        // Independent fixtures expose all three API results even if one
        // panics or incorrectly mutates its own volume before returning.
        let fixture = Fixture::new(checkpoint);
        configure(&fixture);
        let mutations = fixture.observe_mutations();
        let backing: Arc<dyn Backing> = fixture.backing.clone();
        let result = catch_unwind(AssertUnwindSafe(|| match api {
            "scan_journal" => scan_journal(
                &backing,
                &fixture.superblock,
                fixture.checkpoint,
                SEGMENT_SIZE,
            )
            .err()
            .is_some_and(is_corruption),
            "deep_check" => deep_check(backing, SEGMENT_SIZE)
                .map(|report| !report.errors.is_empty())
                .unwrap_or(false),
            _ => Volume::recover(
                backing,
                VolumeOptions {
                    journal_segment_size: SEGMENT_SIZE,
                },
            )
            .err()
            .is_some_and(is_corruption),
        }));
        fixture.backing.set_fault_hook(None);
        if !matches!(result, Ok(true)) {
            failures.push(format!("{api}: refused without panic = {result:?}"));
        }
        let mutations = mutations.lock().unwrap();
        if !mutations.is_empty() {
            failures.push(format!("{api}: mutated before refusal: {mutations:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn maximum_checkpoint_with_empty_journal_is_refused_without_recovery_writes() {
    assert_public_apis_refuse(u64::MAX, |_| {});
}

#[test]
fn maximum_checkpoint_with_a_segment_is_refused_without_overflow() {
    assert_public_apis_refuse(u64::MAX, |fixture| fixture.segment(0, 1, &[]));
}

#[test]
fn maximum_segment_index_is_refused_without_index_reuse() {
    assert_public_apis_refuse(0, |fixture| fixture.segment(u64::MAX, 1, &[]));
}

#[test]
fn maximum_advisory_mark_index_is_refused_even_after_its_segment_was_pruned() {
    assert_public_apis_refuse(0, |fixture| {
        fixture
            .backing
            .open(layout::JOURNAL_DURABLE_MARK, true)
            .unwrap()
            .write_at(
                0,
                &DurableMark {
                    segment_index: u64::MAX,
                    durable_size: 48,
                }
                .encode(),
            )
            .unwrap();
    });
}

#[test]
fn record_at_maximum_base_sequence_is_refused_without_sequence_wrap() {
    assert_public_apis_refuse(u64::MAX - 1, |fixture| {
        fixture.segment(0, u64::MAX, &[u64::MAX]);
    });
}

#[test]
fn a_segment_crossing_into_maximum_sequence_is_refused_without_sequence_wrap() {
    assert_public_apis_refuse(u64::MAX - 2, |fixture| {
        fixture.segment(0, u64::MAX - 1, &[u64::MAX - 1, u64::MAX]);
    });
}

#[test]
fn last_representable_horizon_remains_readable_with_exact_record_count() {
    for legacy in [false, true] {
        let fixture = Fixture::new(u64::MAX - 2);
        if legacy {
            // Exercise the preserved v1 read-only path with real frozen v1
            // envelopes, not a policy bypass or an in-place product migration.
            for path in [layout::SUPERBLOCK_A, layout::SUPERBLOCK_B] {
                fixture
                    .backing
                    .open(path, false)
                    .unwrap()
                    .write_at(0, &fixture.superblock.encode())
                    .unwrap();
            }
        }
        fixture.segment(u64::MAX - 1, u64::MAX - 1, &[u64::MAX - 1]);
        let mutations = fixture.observe_mutations();
        let backing: Arc<dyn Backing> = fixture.backing.clone();
        let scan = scan_journal(
            &backing,
            &fixture.superblock,
            fixture.checkpoint,
            SEGMENT_SIZE,
        )
        .unwrap();
        assert_eq!(scan.durable_sequence, u64::MAX - 1);
        assert_eq!(scan.next_segment_index, u64::MAX);
        assert_eq!(scan.replay.len(), 1);
        assert_eq!(scan.replay[0].sequence, u64::MAX - 1);
        let report = deep_check(backing, SEGMENT_SIZE).unwrap();
        assert!(
            report.errors.is_empty(),
            "legacy={legacy}: {:?}",
            report.errors
        );
        assert!(report.info.iter().any(|line| line.contains(
            "journal: 1 segment(s), 1 record(s) newer than the checkpoint, durable sequence 18446744073709551614"
        )));
        fixture.backing.set_fault_hook(None);
        assert!(mutations.lock().unwrap().is_empty());
    }
}

#[test]
fn empty_segment_at_maximum_base_preserves_the_representable_horizon() {
    let fixture = Fixture::new(u64::MAX - 1);
    fixture.segment(0, u64::MAX, &[]);
    let mutations = fixture.observe_mutations();
    let backing: Arc<dyn Backing> = fixture.backing.clone();
    let scan = scan_journal(
        &backing,
        &fixture.superblock,
        fixture.checkpoint,
        SEGMENT_SIZE,
    )
    .unwrap();
    assert_eq!(scan.durable_sequence, u64::MAX - 1);
    assert!(scan.replay.is_empty());
    assert!(scan.repairs.is_empty());
    let report = deep_check(backing, SEGMENT_SIZE).unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert!(report.info.iter().any(|line| line.contains(
        "journal: 1 segment(s), 0 record(s) newer than the checkpoint, durable sequence 18446744073709551614"
    )));
    fixture.backing.set_fault_hook(None);
    assert!(mutations.lock().unwrap().is_empty());
    let volume = Volume::recover(fixture.backing.clone(), VolumeOptions::default()).unwrap();
    assert_eq!(volume.journal_durable_sequence(), u64::MAX - 1);
}

#[test]
fn append_refuses_exhausted_sequence_before_writing_and_keeps_the_last_valid_record() {
    let fixture = Fixture::new(u64::MAX - 2);
    let mut volume = Volume::recover(fixture.backing.clone(), VolumeOptions::default()).unwrap();
    assert_eq!(volume.write_ct(0, &[42; 540], true).unwrap(), u64::MAX - 1);
    let mutations = fixture.observe_mutations();
    let result = catch_unwind(AssertUnwindSafe(|| volume.write_ct(0, &[99; 540], true)));
    fixture.backing.set_fault_hook(None);
    let operations = mutations.lock().unwrap();
    assert!(
        matches!(
            result,
            Ok(Err(CoreError::Corrupt(_) | CoreError::Format(_)))
        ),
        "the exhausted append must return a typed error: {result:?}; operations={operations:?}"
    );
    assert!(operations.is_empty(), "{operations:?}");
    assert_eq!(volume.journal_appended_sequence(), u64::MAX - 1);
    assert_eq!(volume.journal_durable_sequence(), u64::MAX - 1);
    assert_eq!(
        volume.read_ct(0).unwrap(),
        Some((u64::MAX - 1, vec![42; 540]))
    );
    volume.flush().unwrap();
}

#[test]
fn roll_refuses_exhausted_index_before_sealing_or_creating_a_segment() {
    let fixture = Fixture::new(0);
    fixture.segment(u64::MAX - 2, 1, &[]);
    let mut volume = Volume::recover(
        fixture.backing.clone(),
        VolumeOptions {
            journal_segment_size: 48 + 32 + 540,
        },
    )
    .unwrap();
    assert_eq!(volume.write_ct(0, &[42; 540], false).unwrap(), 1);
    assert!(fixture
        .backing
        .exists(&layout::journal_segment(u64::MAX - 1))
        .unwrap());
    let mutations = fixture.observe_mutations();
    let result = catch_unwind(AssertUnwindSafe(|| volume.write_ct(1, &[99; 540], false)));
    fixture.backing.set_fault_hook(None);
    let operations = mutations.lock().unwrap();
    assert!(
        matches!(
            result,
            Ok(Err(CoreError::Corrupt(_) | CoreError::Format(_)))
        ),
        "the exhausted roll must return a typed error: {result:?}; operations={operations:?}"
    );
    assert!(operations.is_empty(), "{operations:?}");
    assert!(!fixture
        .backing
        .exists(&layout::journal_segment(u64::MAX))
        .unwrap());
    assert_eq!(volume.journal_appended_sequence(), 1);
    assert_eq!(volume.journal_durable_sequence(), 0);
    assert_eq!(volume.read_ct(0).unwrap(), Some((1, vec![42; 540])));
    assert_eq!(volume.read_ct(1).unwrap(), None);
    volume.flush().unwrap();
    assert_eq!(volume.journal_durable_sequence(), 1);
}
