//! R4-004: `maki check --deep` must distinguish slot damage that recovery
//! will repair from a validated journal record ("recoverable") from damage
//! with no surviving source ("unrecoverable"), and say which of the three
//! states — clean, recoverable, unrecoverable — the volume is in.
//!
//! The checker reads raw slots; recovery replays the journal over them. A
//! checkpointed slot whose newer value is still durable in the journal is
//! therefore an *error* for the raw reader and a *repair* for recovery. The
//! old report called every CRC failure an error and let an operator treat a
//! routinely recoverable volume as a data-loss incident.

use std::sync::Arc;

use uuid::Uuid;

use maki_backing::Backing;
use maki_core::check::deep_check;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::checker::CheckReport;
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
        volume_uuid: Uuid::from_u128(0xC4E4),
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

fn recover(backing: &Arc<CrashableBacking>) -> Volume {
    Volume::recover(
        backing.clone() as Arc<dyn Backing>,
        VolumeOptions {
            journal_segment_size: SEGMENT,
        },
    )
    .unwrap()
}

fn new_volume(backing: &Arc<CrashableBacking>) -> Volume {
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    recover(backing)
}

fn deep(backing: &Arc<CrashableBacking>) -> CheckReport {
    deep_check(backing.clone() as Arc<dyn Backing>, SEGMENT).unwrap()
}

fn damage_slot(backing: &Arc<CrashableBacking>, unit: u64) {
    let g = geometry();
    let (shard, idx) = g.shard_of_unit(unit);
    let f = backing.open(&layout::shard_data(shard), false).unwrap();
    f.write_at(g.slot_offset(idx) + 64 + 10, &[0xEE; 8])
        .unwrap();
    f.sync_data().unwrap();
}

fn joined(lines: &[String]) -> String {
    lines.join("\n")
}

fn verdict(report: &CheckReport) -> String {
    report
        .info
        .iter()
        .find_map(|line| line.strip_prefix("deep check verdict: "))
        .unwrap_or_else(|| panic!("no verdict line in {:?}", report.info))
        .to_string()
}

/// Unit 1 and unit 5 are checkpointed; unit 5 then gets a newer, FUA-durable
/// value that stays in the journal (no further checkpoint).
fn volume_with_journaled_overwrite(backing: &Arc<CrashableBacking>) {
    let _guard = failpoints::test_lock();
    let mut vol = new_volume(backing);
    vol.write_ct(1, &ct(0x11), true).unwrap();
    vol.write_ct(5, &ct(0xA5), true).unwrap();
    vol.checkpoint().unwrap();
    vol.write_ct(5, &ct(0xB5), true).unwrap();
    drop(vol);
}

#[test]
fn slot_damage_covered_by_a_durable_journal_record_is_recoverable_not_an_error() {
    let backing = Arc::new(CrashableBacking::new());
    volume_with_journaled_overwrite(&backing);
    damage_slot(&backing, 5);

    let report = deep(&backing);
    assert!(
        report.ok(),
        "a slot that recovery rewrites from the journal is not an error:\n{}",
        joined(&report.errors)
    );
    let warnings = joined(&report.warnings);
    assert!(
        warnings.contains("recoverable") && warnings.contains("unit 5"),
        "the damaged unit must be reported as recoverable:\n{warnings}"
    );
    assert_eq!(verdict(&report), "recoverable");
    let info = joined(&report.info);
    assert!(
        info.contains("1 recoverable") && info.contains("0 unrecoverable"),
        "{info}"
    );

    // Recovery indeed repairs it, after which the volume is clean.
    let vol = recover(&backing);
    let (_, data) = vol.read_ct(5).unwrap().expect("unit 5 has data");
    assert_eq!(data, ct(0xB5));
    drop(vol);
    let after = deep(&backing);
    assert!(after.ok(), "{}", joined(&after.errors));
    assert_eq!(verdict(&after), "clean");
    assert!(
        !joined(&after.warnings).contains("recoverable"),
        "{}",
        joined(&after.warnings)
    );
}

#[test]
fn slot_damage_without_a_journal_source_is_unrecoverable() {
    let backing = Arc::new(CrashableBacking::new());
    volume_with_journaled_overwrite(&backing);
    damage_slot(&backing, 1);

    let report = deep(&backing);
    assert!(!report.ok());
    let errors = joined(&report.errors);
    assert!(errors.contains("unit 1"), "{errors}");
    assert_eq!(verdict(&report), "unrecoverable");
    assert!(
        joined(&report.info).contains("1 unrecoverable"),
        "{}",
        joined(&report.info)
    );
}

#[test]
fn mixed_damage_reports_both_classes_and_an_unrecoverable_verdict() {
    let backing = Arc::new(CrashableBacking::new());
    volume_with_journaled_overwrite(&backing);
    damage_slot(&backing, 1);
    damage_slot(&backing, 5);

    let report = deep(&backing);
    assert!(!report.ok());
    assert!(joined(&report.errors).contains("unit 1"));
    assert!(!joined(&report.errors).contains("unit 5"), "unit 5 is recoverable");
    assert!(joined(&report.warnings).contains("unit 5"));
    assert_eq!(verdict(&report), "unrecoverable");
    let info = joined(&report.info);
    assert!(info.contains("1 recoverable") && info.contains("1 unrecoverable"), "{info}");
}

#[test]
fn a_healthy_volume_reports_a_clean_verdict() {
    let backing = Arc::new(CrashableBacking::new());
    volume_with_journaled_overwrite(&backing);
    let report = deep(&backing);
    assert!(report.ok());
    assert_eq!(verdict(&report), "clean");
}
