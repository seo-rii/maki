//! Review M-018: the deep offline check must find what the fast check
//! cannot (slot damage, lost checkpoint state, journal corruption, a
//! missing segment) and must not flag what recovery tolerates (a torn
//! tail, a resurrected covered segment).

use std::sync::Arc;

use uuid::Uuid;

use maki_backing::Backing;
use maki_core::check::deep_check;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::checker::{check_volume, CheckReport};
use maki_format::geometry::Geometry;
use maki_format::superblock::Superblock;
use maki_format::{init, layout};
use maki_test_support::failpoints;
use maki_test_support::CrashableBacking;

const UNIT: u32 = 512;
const CT_LEN: usize = 540;
const SEGMENT: u64 = 4096;

fn geometry() -> Geometry {
    Geometry::compute(512, UNIT, 512, 544, 512 * 1024, 512 * 64).unwrap()
}

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xC4EC),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: geometry(),
        format_version: 1,
        created_unix: 0,
    }
}

fn ct(stamp: u8) -> Vec<u8> {
    vec![stamp; CT_LEN]
}

fn new_volume(backing: &Arc<CrashableBacking>) -> Volume {
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    Volume::recover(
        backing.clone() as Arc<dyn Backing>,
        VolumeOptions {
            journal_segment_size: SEGMENT,
        },
    )
    .unwrap()
}

fn deep(backing: &Arc<CrashableBacking>) -> CheckReport {
    deep_check(backing.clone() as Arc<dyn Backing>, SEGMENT).unwrap()
}

fn fast(backing: &Arc<CrashableBacking>) -> CheckReport {
    check_volume(backing.as_ref()).unwrap()
}

fn errors(report: &CheckReport) -> String {
    report.errors.join("\n")
}

#[test]
fn deep_check_passes_on_a_healthy_volume_with_data_and_journal() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    for i in 0..12u8 {
        vol.write_ct(i as u64 % 5, &ct(i), false).unwrap();
    }
    vol.flush().unwrap();
    vol.checkpoint().unwrap();
    vol.write_ct(7, &ct(0x77), true).unwrap(); // uncheckpointed, durable
    vol.write_ct(8, &ct(0x88), false).unwrap(); // volatile
    drop(vol);

    let report = deep(&backing);
    assert!(report.ok(), "{}", errors(&report));
    assert!(
        report
            .info
            .iter()
            .any(|i| i.contains("slots: 5 allocated, 0 invalid")),
        "{:?}",
        report.info
    );
    assert!(report.info.iter().any(|i| i.starts_with("journal:")));
    assert!(report
        .info
        .iter()
        .any(|i| i.starts_with("checkpoint sequence:")));
}

#[test]
fn deep_check_finds_slot_damage_the_fast_check_misses() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    vol.write_ct(5, &ct(7), true).unwrap();
    vol.checkpoint().unwrap();
    drop(vol);

    let g = geometry();
    let (shard, idx) = g.shard_of_unit(5);
    let f = backing.open(&layout::shard_data(shard), false).unwrap();
    f.write_at(g.slot_offset(idx) + 64 + 10, &[0xEE; 8])
        .unwrap();
    f.sync_data().unwrap();

    assert!(fast(&backing).ok(), "fast check cannot see slot payloads");
    let report = deep(&backing);
    assert!(!report.ok());
    assert!(errors(&report).contains("unit 5"), "{}", errors(&report));
}

#[test]
fn deep_check_requires_checkpoint_state() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    vol.write_ct(0, &ct(1), true).unwrap();
    vol.checkpoint().unwrap();
    drop(vol);
    for path in [
        maki_format::checkpoint::CHECKPOINT_STATE_A,
        maki_format::checkpoint::CHECKPOINT_STATE_B,
    ] {
        if backing.exists(path).unwrap() {
            backing.remove(path).unwrap();
        }
    }
    backing.sync_dir(layout::CHECKPOINT_DIR).unwrap();

    assert!(fast(&backing).ok());
    let report = deep(&backing);
    assert!(
        errors(&report).contains("checkpoint state"),
        "{}",
        errors(&report)
    );
}

#[test]
fn deep_check_reports_journal_corruption_and_missing_segments() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    for i in 0..24u8 {
        vol.write_ct(i as u64 % 4, &ct(i), false).unwrap();
    }
    vol.flush().unwrap();
    let seg = vol.journal_active_segment_path().unwrap();
    drop(vol);

    // Corrupt a durable record payload in the final segment.
    let f = backing.open(&seg, false).unwrap();
    f.write_at(48 + 32 + 5, &[0xAB; 4]).unwrap();
    f.sync_data().unwrap();
    assert!(fast(&backing).ok());
    let report = deep(&backing);
    assert!(errors(&report).contains("journal:"), "{}", errors(&report));

    // Repair by removing the whole first segment instead: a missing
    // uncheckpointed segment is also reported.
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    for i in 0..24u8 {
        vol.write_ct(i as u64 % 4, &ct(i), false).unwrap();
    }
    vol.flush().unwrap();
    drop(vol);
    backing.remove(&layout::journal_segment(0)).unwrap();
    backing.sync_dir(layout::JOURNAL_DIR).unwrap();
    let report = deep(&backing);
    assert!(errors(&report).contains("bridge"), "{}", errors(&report));
}

#[test]
fn deep_check_tolerates_a_torn_tail_and_reports_the_repair() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    vol.write_ct(0, &ct(1), true).unwrap();
    vol.write_ct(1, &ct(2), false).unwrap();
    let seg = vol.journal_active_segment_path().unwrap();
    drop(vol);
    backing.crash_keep_torn_prefix(&seg, 100);

    let report = deep(&backing);
    assert!(report.ok(), "{}", errors(&report));
    assert!(
        report.info.iter().any(|i| i.contains("torn tail")),
        "{:?}",
        report.info
    );
    // Read-only: the torn bytes are still there for recovery to handle.
    let len = backing.open(&seg, false).unwrap().len().unwrap();
    assert!(len > 48 + 32 + CT_LEN as u64);
    Volume::recover(
        backing.clone() as Arc<dyn Backing>,
        VolumeOptions {
            journal_segment_size: SEGMENT,
        },
    )
    .unwrap();
}

#[test]
fn deep_check_refuses_to_race_an_attached_volume() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let vol = new_volume(&backing);
    let report = deep(&backing);
    assert!(
        errors(&report).contains("lock is held"),
        "{}",
        errors(&report)
    );
    drop(vol);
    assert!(deep(&backing).ok());
}
