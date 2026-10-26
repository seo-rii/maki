//! BUG-133: unavailable metadata is an inconclusive check, not proven damage.

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use maki_backing::Backing;
use maki_core::check::deep_check;
use maki_core::volume::{Volume, VolumeOptions};
use maki_core::CoreError;
use maki_format::ab::AbStore;
use maki_format::canary::{KeyCanary, CANARY_UNIT_INDEX};
use maki_format::checkpoint::{CHECKPOINT_STATE_A, CHECKPOINT_STATE_B};
use maki_format::durable_proof::DURABLE_PROOF_A;
use maki_format::geometry::Geometry;
use maki_format::superblock::Superblock;
use maki_format::{init, layout, FormatError};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::CrashableBacking;
use uuid::Uuid;

const SEGMENT_SIZE: u64 = 4096;
const VOLUME_UUID: Uuid = Uuid::from_u128(133);

fn healthy_volume() -> Arc<CrashableBacking> {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: VOLUME_UUID,
            provider_type: "fake".into(),
            crypto_compatibility_id: "metadata-io-v1".into(),
            key_identity: "test".into(),
            geometry: Geometry::compute(512, 512, 512, 544, 4096, 4096).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let mut volume = Volume::recover(backing.clone(), options()).unwrap();
    volume.write_ct(0, &[0x51; 544], true).unwrap();
    volume.checkpoint().unwrap();
    volume.write_ct(1, &[0x62; 544], true).unwrap();
    drop(volume);
    store_canary(backing.as_ref(), VOLUME_UUID);
    backing
}

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: SEGMENT_SIZE,
    }
}

fn store_canary(backing: &dyn Backing, volume_uuid: Uuid) {
    let mut canary = KeyCanary {
        generation: 0,
        volume_uuid,
        unit_index: CANARY_UNIT_INDEX,
        ciphertext: vec![0x73; 544],
    };
    let store = AbStore::new(layout::KEY_CANARY_A, layout::KEY_CANARY_B);
    store.store(backing, &mut canary).unwrap();
    store.store(backing, &mut canary).unwrap();
    backing.sync_dir("").unwrap();
}

fn assert_clean_and_readable(backing: Arc<CrashableBacking>) {
    let report = deep_check(backing.clone(), SEGMENT_SIZE).unwrap();
    assert!(report.ok(), "{report:?}");
    assert!(report
        .info
        .iter()
        .any(|line| line == "deep check verdict: clean"));
    let volume = Volume::recover(backing, options()).unwrap();
    assert_eq!(volume.read_ct(0).unwrap(), Some((1, vec![0x51; 544])));
    assert_eq!(volume.read_ct(1).unwrap(), Some((2, vec![0x62; 544])));
}

/// A one-shot open failure lets an earlier inspection succeed, or a later
/// retry succeed, without changing any stored bytes. On Unix the codes are
/// EIO and EACCES; preserve the platform's own kind mapping and raw code.
fn assert_open_failure_is_inconclusive(path: &str, fail_on_open: usize) {
    for errno in [5, 13] {
        let backing = healthy_volume();
        let opens = Arc::new(AtomicUsize::new(0));
        let observed = opens.clone();
        let target = path.to_owned();
        backing.set_fault_hook(Some(Arc::new(move |operation| match operation {
            FaultOp::Open {
                path,
                create: false,
            } if *path == target
                && observed.fetch_add(1, Ordering::Relaxed) + 1 == fail_on_open =>
            {
                Some(io::Error::from_raw_os_error(errno))
            }
            _ => None,
        })));
        let result = deep_check(backing.clone(), SEGMENT_SIZE);
        backing.set_fault_hook(None);
        assert!(opens.load(Ordering::Relaxed) >= fail_on_open);
        match result {
            Err(CoreError::Io(error) | CoreError::Format(FormatError::Io(error))) => {
                assert_eq!(error.kind(), io::Error::from_raw_os_error(errno).kind());
                assert_eq!(error.raw_os_error(), Some(errno));
            }
            other => panic!("{path} open {fail_on_open}: expected I/O error, got {other:?}"),
        }
        assert_clean_and_readable(backing);
    }
}

#[test]
fn checkpoint_copy_inspection_io_is_inconclusive_even_if_the_next_read_succeeds() {
    for path in [CHECKPOINT_STATE_A, CHECKPOINT_STATE_B] {
        assert_open_failure_is_inconclusive(path, 1);
    }
}

#[test]
fn checkpoint_load_io_after_successful_copy_inspection_is_inconclusive() {
    for path in [CHECKPOINT_STATE_A, CHECKPOINT_STATE_B] {
        assert_open_failure_is_inconclusive(path, 2);
    }
}

#[test]
fn canary_copy_io_is_inconclusive() {
    for path in [layout::KEY_CANARY_A, layout::KEY_CANARY_B] {
        assert_open_failure_is_inconclusive(path, 1);
    }
}

#[test]
fn journal_proof_io_after_successful_fast_check_is_inconclusive() {
    assert_open_failure_is_inconclusive(DURABLE_PROOF_A, 2);
}

#[test]
fn slot_store_metadata_io_after_successful_fast_check_is_inconclusive() {
    assert_open_failure_is_inconclusive(layout::SHARD_CATALOG_A, 2);
}

#[test]
fn fast_check_metadata_io_remains_inconclusive() {
    assert_open_failure_is_inconclusive(DURABLE_PROOF_A, 1);
}

fn corrupt(backing: &dyn Backing, path: &str) {
    let file = backing.open(path, false).unwrap();
    // Damage the magic without updating the checksum.
    file.write_at(0, &[0xff]).unwrap();
    file.sync_data().unwrap();
}

#[test]
fn both_damaged_checkpoint_copies_still_report_corruption() {
    let backing = healthy_volume();
    corrupt(backing.as_ref(), CHECKPOINT_STATE_A);
    corrupt(backing.as_ref(), CHECKPOINT_STATE_B);
    let report = deep_check(backing, SEGMENT_SIZE).unwrap();
    assert!(!report.ok());
    assert!(report
        .errors
        .iter()
        .any(|line| line.contains("no valid checkpoint state copy")));
}

#[test]
fn one_damaged_checkpoint_copy_still_uses_the_valid_copy() {
    let backing = healthy_volume();
    corrupt(backing.as_ref(), CHECKPOINT_STATE_A);
    let report = deep_check(backing.clone(), SEGMENT_SIZE).unwrap();
    assert!(report.ok(), "{report:?}");
    assert!(report
        .warnings
        .iter()
        .any(|line| line.contains("checkpoint state: one copy is invalid")));
    assert_clean_and_readable(backing);
}

#[test]
fn foreign_canary_still_reports_unrecoverable_metadata() {
    let backing = healthy_volume();
    store_canary(backing.as_ref(), Uuid::from_u128(134));
    let report = deep_check(backing, SEGMENT_SIZE).unwrap();
    assert!(!report.ok());
    assert!(report
        .errors
        .iter()
        .any(|line| line == "key canary belongs to a different volume"));
    assert!(report
        .info
        .iter()
        .any(|line| line == "deep check verdict: unrecoverable"));
}

#[test]
fn one_damaged_canary_copy_still_uses_the_valid_copy() {
    let backing = healthy_volume();
    corrupt(backing.as_ref(), layout::KEY_CANARY_A);
    let report = deep_check(backing.clone(), SEGMENT_SIZE).unwrap();
    assert!(report.ok(), "{report:?}");
    assert!(report.info.iter().any(|line| line == "key canary: present"));
    assert_clean_and_readable(backing);
}
