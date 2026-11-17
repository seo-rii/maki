//! A torn segment header left by a writer that preallocated it must not keep
//! a volume from attaching.
//!
//! Writers before the fix in `review_journal_torn_header.rs` extended a new
//! journal segment to the full 48-byte header length before writing the
//! header. When that write persisted only a prefix (or the whole header
//! reached the file and was damaged there) and the failed creation's cleanup
//! (unlink, then journal directory sync) never finished, the volume was left
//! with a final segment exactly one header long whose header fails its
//! checksum. Such a file holds no record byte, and the durable proof, which is
//! published to both copies before every acknowledgement and names the
//! segment holding the newest acknowledged record, names an earlier segment;
//! so does the durable mark, which names a segment only after its creation
//! completed. Recovery must discard it as an unfinished creation, as it
//! discards a shorter or all-zero one.
//!
//! Every invalid header recovery cannot prove empty and unnamed stays durable
//! damage: one followed by record bytes, one the proof or the mark names, one
//! below the segment the proof or the mark names, one that is not final, and
//! an intact header (valid checksum) that does not decode.

use std::sync::Arc;

use rand::rngs::StdRng;
use rand::SeedableRng;

use maki_backing::Backing;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::journal::{DurableMark, SegmentHeader, DURABLE_MARK_SIZE, SEGMENT_HEADER_SIZE};
use maki_format::{geometry::Geometry, init, layout, superblock::Superblock};
use maki_test_support::{failpoints, CrashableBacking};

const CT: usize = 1024;
/// Three 1056-byte records fit a 4096-byte segment; the fourth append rolls.
const PER_SEGMENT: u64 = 3;
const VOLUME_UUID: u128 = 0x2026_1117_0048;

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: 4096,
    }
}

fn backing(discard: bool) -> Arc<CrashableBacking> {
    let backing = Arc::new(CrashableBacking::new().with_tearing(512));
    let sb = Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(VOLUME_UUID),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, 512, 512, CT as u32, 512 * 64, 512 * 16).unwrap(),
        format_version: 1,
        created_unix: 0,
    };
    if discard {
        init::create_volume_with_discard(backing.as_ref(), sb).unwrap();
    } else {
        init::create_volume(backing.as_ref(), sb).unwrap();
    }
    backing
}

fn recover(backing: &Arc<CrashableBacking>) -> Result<Volume, String> {
    Volume::recover(backing.clone() as Arc<dyn Backing>, options()).map_err(|e| e.to_string())
}

fn deep_check(backing: &Arc<CrashableBacking>) -> maki_format::checker::CheckReport {
    maki_core::check::deep_check(backing.clone() as Arc<dyn Backing>, 4096).unwrap()
}

fn ct(unit: u64) -> Vec<u8> {
    vec![unit as u8 + 1; CT]
}

fn header(index: u64, base_sequence: u64) -> Vec<u8> {
    SegmentHeader {
        segment_index: index,
        volume_uuid: uuid::Uuid::from_u128(VOLUME_UUID),
        base_sequence,
    }
    .encode()
}

/// What reached a segment file preallocated to exactly one header.
#[derive(Clone, Copy, Debug)]
enum Torn {
    /// The first bytes of the header; the rest are the preallocated zeros.
    Prefix(usize),
    /// The whole header, later damaged in place (one bit flipped).
    Damaged,
}

const TORN: [Torn; 8] = [
    Torn::Prefix(1),
    Torn::Prefix(8),
    Torn::Prefix(12),
    Torn::Prefix(20),
    Torn::Prefix(32),
    Torn::Prefix(44),
    Torn::Prefix(47),
    Torn::Damaged,
];

fn torn_image(index: u64, base_sequence: u64, torn: Torn) -> [u8; SEGMENT_HEADER_SIZE] {
    let header = header(index, base_sequence);
    let mut image = [0u8; SEGMENT_HEADER_SIZE];
    match torn {
        Torn::Prefix(n) => image[..n].copy_from_slice(&header[..n]),
        Torn::Damaged => {
            image.copy_from_slice(&header);
            image[12] ^= 0x40;
        }
    }
    assert!(SegmentHeader::decode(&image).is_err());
    assert!(image.iter().any(|byte| *byte != 0));
    image
}

/// Attach, acknowledge `acknowledged` FUA writes (a multiple of
/// `PER_SEGMENT`, so the next write rolls), optionally restart (recovery then
/// checkpoints and prunes every segment, leaving the proof and the mark
/// naming a deleted one), and stop. Then leave exactly what the legacy
/// writer's failed roll left behind when its cleanup never finished: the next
/// segment, created, preallocated to one header, holding `torn`. Returns its
/// path.
fn leave_legacy_segment(
    backing: &Arc<CrashableBacking>,
    acknowledged: u64,
    restart_first: bool,
    torn: Torn,
    durable: bool,
) -> String {
    assert_eq!(acknowledged % PER_SEGMENT, 0);
    let mut volume = recover(backing).unwrap();
    for unit in 0..acknowledged {
        volume.write_ct(unit, &ct(unit), true).unwrap();
    }
    drop(volume);
    if restart_first {
        drop(recover(backing).unwrap());
    }

    let index = acknowledged / PER_SEGMENT;
    let path = layout::journal_segment(index);
    assert!(!backing.exists(&path).unwrap());
    let image = torn_image(index, acknowledged + 1, torn);
    let file = backing.open(&path, true).unwrap();
    file.set_len(0).unwrap();
    file.allocate_range(0, SEGMENT_HEADER_SIZE as u64).unwrap();
    file.write_at(0, &image).unwrap();
    if durable {
        // Background writeback persisted the inode, its length and the
        // torn bytes, and the directory entry.
        file.sync_data().unwrap();
        backing.sync_dir(layout::JOURNAL_DIR).unwrap();
    }
    path
}

/// Every acknowledged write is intact, the legacy segment is gone, and the
/// volume keeps working across a later power loss.
fn assert_recovered(
    backing: &Arc<CrashableBacking>,
    volume: Volume,
    acknowledged: u64,
    legacy: &str,
    case: &str,
) {
    for unit in 0..acknowledged {
        assert_eq!(volume.read_ct(unit).unwrap().unwrap().1, ct(unit), "{case}");
    }
    assert!(volume.read_ct(acknowledged).unwrap().is_none(), "{case}");
    assert!(
        !backing.exists(legacy).unwrap(),
        "{case}: recovery discards the unfinished segment"
    );
    let mut volume = volume;
    volume
        .write_ct(acknowledged, &ct(acknowledged), true)
        .unwrap();
    drop(volume);
    backing.crash_all_lost();
    let volume = recover(backing).unwrap_or_else(|e| panic!("{case}: stays attachable: {e}"));
    for unit in 0..=acknowledged {
        assert_eq!(volume.read_ct(unit).unwrap().unwrap().1, ct(unit), "{case}");
    }
}

#[derive(Clone, Copy, Debug)]
enum Stop {
    /// A process restart: the page cache, including the never-synced torn
    /// file, survives.
    Restart,
    /// A power loss after background writeback made the torn file durable.
    PowerLoss,
}

#[test]
fn legacy_torn_header_only_final_segment_is_discarded() {
    let _serial = failpoints::test_lock();
    for stop in [Stop::Restart, Stop::PowerLoss] {
        for acknowledged in [0, PER_SEGMENT] {
            for restart_first in [false, true] {
                for discard in [false, true] {
                    for torn in TORN {
                        let case = format!(
                            "{stop:?} acknowledged={acknowledged} restart_first={restart_first} \
                             discard={discard} {torn:?}"
                        );
                        let backing = backing(discard);
                        let durable = matches!(stop, Stop::PowerLoss);
                        let legacy = leave_legacy_segment(
                            &backing,
                            acknowledged,
                            restart_first,
                            torn,
                            durable,
                        );
                        if durable {
                            backing.crash_all_lost();
                            assert!(backing.exists(&legacy).unwrap(), "{case}");
                        }

                        let report = deep_check(&backing);
                        assert!(
                            report.ok(),
                            "{case}: the deep check must not call an unfinished creation \
                             damage: {:?}",
                            report.errors
                        );
                        assert!(
                            report
                                .info
                                .iter()
                                .any(|line| line.contains("never completed creation")),
                            "{case}: the deep check reports the discard: {:?}",
                            report.info
                        );
                        let volume = recover(&backing).unwrap_or_else(|e| {
                            panic!(
                                "{case}: a final segment holding only a torn header above \
                                 everything the durable proof and mark name must attach, got: {e}"
                            )
                        });
                        assert_recovered(&backing, volume, acknowledged, &legacy, &case);
                    }
                }
            }
        }
    }
}

/// Random power losses (torn writes included) while the legacy segment's
/// creation, preallocation and torn header write were still volatile.
#[test]
fn legacy_torn_header_survives_random_power_loss() {
    let _serial = failpoints::test_lock();
    let mut refused = Vec::new();
    for acknowledged in [0, PER_SEGMENT] {
        for torn in [Torn::Prefix(20), Torn::Prefix(32), Torn::Damaged] {
            for seed in 0..32u64 {
                let case = format!("acknowledged={acknowledged} {torn:?} seed {seed}");
                let backing = backing(false);
                let legacy = leave_legacy_segment(&backing, acknowledged, false, torn, false);
                backing.crash(&mut StdRng::seed_from_u64(seed));
                match recover(&backing) {
                    Ok(volume) => assert_recovered(&backing, volume, acknowledged, &legacy, &case),
                    Err(e) => refused.push(format!("{case}: {e}")),
                }
            }
        }
    }
    assert!(
        refused.is_empty(),
        "{} power losses left an unattachable volume:\n{}",
        refused.len(),
        refused.join("\n")
    );
}

/// Recovery and the deep check both refuse the volume as damaged.
fn assert_refused(backing: &Arc<CrashableBacking>, case: &str, expected: &str) {
    let report = deep_check(backing);
    assert!(
        report.errors.iter().any(|error| error.contains(expected)),
        "{case}: the deep check must report the damage: {:?}",
        report.errors
    );
    let error = recover(backing)
        .err()
        .unwrap_or_else(|| panic!("{case}: recovery must refuse the damaged header"));
    assert!(error.contains(expected), "{case}: {error}");
}

fn flip_header_bit(backing: &Arc<CrashableBacking>, path: &str) {
    let file = backing.open(path, false).unwrap();
    let mut header = [0u8; SEGMENT_HEADER_SIZE];
    file.read_at(0, &mut header).unwrap();
    assert!(SegmentHeader::decode(&header).is_ok());
    header[12] ^= 0x40;
    file.write_at(0, &header).unwrap();
    file.sync_data().unwrap();
}

fn read_mark(backing: &Arc<CrashableBacking>) -> Option<DurableMark> {
    let file = backing.open(layout::JOURNAL_DURABLE_MARK, false).ok()?;
    let mut bytes = [0u8; DURABLE_MARK_SIZE];
    file.read_at(0, &mut bytes).ok()?;
    DurableMark::decode(&bytes).ok()
}

/// The final segment holds acknowledged records, so the proof names it.
/// Damage to its header is durable damage, also after the file lost every
/// byte past its header.
#[test]
fn a_damaged_header_on_a_segment_the_proof_names_still_fails_closed() {
    let _serial = failpoints::test_lock();
    for stop in [Stop::Restart, Stop::PowerLoss] {
        for header_only in [false, true] {
            let case = format!("{stop:?} header_only={header_only}");
            let backing = backing(false);
            let mut volume = recover(&backing).unwrap();
            for unit in 0..PER_SEGMENT + 1 {
                volume.write_ct(unit, &ct(unit), true).unwrap();
            }
            let path = volume.journal_active_segment_path().unwrap();
            assert_eq!(path, layout::journal_segment(1));
            drop(volume);
            if matches!(stop, Stop::PowerLoss) {
                backing.crash_all_lost();
            }
            flip_header_bit(&backing, &path);
            if header_only {
                let file = backing.open(&path, false).unwrap();
                file.set_len(SEGMENT_HEADER_SIZE as u64).unwrap();
                file.sync_data().unwrap();
            }
            let expected = if header_only {
                "durable mark covers"
            } else {
                "invalid header"
            };
            assert_refused(&backing, &case, expected);
        }
    }
}

/// A final segment holding record bytes is not provably empty, even when
/// neither the proof nor the mark names it (its records were never
/// acknowledged): a damaged header there is durable damage.
#[test]
fn a_damaged_header_on_a_segment_with_unacknowledged_records_still_fails_closed() {
    let _serial = failpoints::test_lock();
    let backing = backing(false);
    let mut volume = recover(&backing).unwrap();
    for unit in 0..PER_SEGMENT {
        volume.write_ct(unit, &ct(unit), true).unwrap();
    }
    // Rolls to segment 1 (header synced) and appends one unsynced record.
    volume
        .write_ct(PER_SEGMENT, &ct(PER_SEGMENT), false)
        .unwrap();
    let path = volume.journal_active_segment_path().unwrap();
    assert_eq!(path, layout::journal_segment(1));
    drop(volume); // a restart: the unsynced record stays in the page cache
    backing.remove(layout::JOURNAL_DURABLE_MARK).unwrap();
    backing.sync_dir(layout::JOURNAL_DIR).unwrap();
    flip_header_bit(&backing, &path);
    assert!(backing.open(&path, false).unwrap().len().unwrap() > SEGMENT_HEADER_SIZE as u64);
    assert_refused(&backing, "unacknowledged records", "invalid header");
}

/// A header-only final segment whose creation completed: the mark names it.
/// Damage to its header is durable damage.
#[test]
fn a_damaged_header_only_segment_the_mark_names_still_fails_closed() {
    let _serial = failpoints::test_lock();
    let backing = backing(false);
    let mut volume = recover(&backing).unwrap();
    for unit in 0..PER_SEGMENT {
        volume.write_ct(unit, &ct(unit), true).unwrap();
    }
    // Rolls to segment 1 (header and directory synced, mark pointed at it)
    // and appends one record that the power loss below removes.
    volume
        .write_ct(PER_SEGMENT, &ct(PER_SEGMENT), false)
        .unwrap();
    let path = volume.journal_active_segment_path().unwrap();
    assert_eq!(path, layout::journal_segment(1));
    // Background writeback persisted the mark's plain write.
    backing
        .open(layout::JOURNAL_DURABLE_MARK, false)
        .unwrap()
        .sync_data()
        .unwrap();
    drop(volume);
    backing.crash_all_lost();
    assert_eq!(
        read_mark(&backing),
        Some(DurableMark {
            segment_index: 1,
            durable_size: SEGMENT_HEADER_SIZE as u64,
        })
    );
    assert_eq!(
        backing.open(&path, false).unwrap().len().unwrap(),
        SEGMENT_HEADER_SIZE as u64
    );
    flip_header_bit(&backing, &path);
    assert_refused(&backing, "mark names it", "invalid header");
}

/// A header-only final segment below the segment the proof names (here a
/// pruned one) is not an unfinished creation: creations always take an index
/// above it.
#[test]
fn a_torn_header_only_segment_below_the_proof_still_fails_closed() {
    let _serial = failpoints::test_lock();
    let backing = backing(false);
    let mut volume = recover(&backing).unwrap();
    for unit in 0..2 * PER_SEGMENT {
        volume.write_ct(unit, &ct(unit), true).unwrap();
    }
    drop(volume);
    // Recovery checkpoints and prunes segments 0 and 1; the proof still
    // names segment 1. Remove the advisory mark so only the proof can tell.
    drop(recover(&backing).unwrap());
    assert!(backing
        .list(layout::JOURNAL_DIR)
        .unwrap()
        .iter()
        .all(|name| { layout::parse_journal_segment(name).is_none() }));
    backing.remove(layout::JOURNAL_DURABLE_MARK).unwrap();
    backing.sync_dir(layout::JOURNAL_DIR).unwrap();
    let path = layout::journal_segment(0);
    let file = backing.open(&path, true).unwrap();
    file.write_at(0, &torn_image(0, 1, Torn::Prefix(32)))
        .unwrap();
    file.sync_data().unwrap();
    backing.sync_dir(layout::JOURNAL_DIR).unwrap();
    assert_refused(&backing, "below the proof", "invalid header");
}

/// Likewise below the segment the mark names: the mark names a segment only
/// once its creation completed, and creations always take an index above it.
#[test]
fn a_torn_header_only_segment_below_the_mark_still_fails_closed() {
    let _serial = failpoints::test_lock();
    let backing = backing(false);
    let legacy = leave_legacy_segment(&backing, PER_SEGMENT, false, Torn::Prefix(32), true);
    let mark = backing.open(layout::JOURNAL_DURABLE_MARK, true).unwrap();
    let above = DurableMark {
        segment_index: 2,
        durable_size: SEGMENT_HEADER_SIZE as u64,
    };
    mark.write_at(0, &above.encode()).unwrap();
    mark.sync_data().unwrap();
    backing.sync_dir(layout::JOURNAL_DIR).unwrap();
    backing.crash_all_lost();
    assert!(backing.exists(&legacy).unwrap());
    assert_eq!(read_mark(&backing), Some(above));
    assert_refused(&backing, "below the mark", "invalid header");
}

/// Only the final segment can be an unfinished creation.
#[test]
fn a_torn_header_only_segment_that_is_not_final_still_fails_closed() {
    let _serial = failpoints::test_lock();
    let backing = backing(false);
    let legacy = leave_legacy_segment(&backing, PER_SEGMENT, false, Torn::Prefix(32), true);
    let next = layout::journal_segment(2);
    let file = backing.open(&next, true).unwrap();
    file.write_at(0, &header(2, PER_SEGMENT + 1)).unwrap();
    file.sync_data().unwrap();
    backing.sync_dir(layout::JOURNAL_DIR).unwrap();
    backing.crash_all_lost();
    assert!(backing.exists(&legacy).unwrap());
    assert_refused(&backing, "not final", "invalid header");
}

/// A header whose checksum is valid reached the file whole; one that does
/// not decode (here: another format version) is not a torn write.
#[test]
fn an_intact_header_that_does_not_decode_is_not_an_unfinished_creation() {
    let _serial = failpoints::test_lock();
    let backing = backing(false);
    let mut volume = recover(&backing).unwrap();
    for unit in 0..PER_SEGMENT {
        volume.write_ct(unit, &ct(unit), true).unwrap();
    }
    drop(volume);
    let mut image = header(1, PER_SEGMENT + 1);
    image[8..12].copy_from_slice(&99u32.to_le_bytes());
    let crc = crc32fast::hash(&image[..SEGMENT_HEADER_SIZE - 4]);
    image[SEGMENT_HEADER_SIZE - 4..].copy_from_slice(&crc.to_le_bytes());
    let path = layout::journal_segment(1);
    let file = backing.open(&path, true).unwrap();
    file.write_at(0, &image).unwrap();
    file.sync_data().unwrap();
    backing.sync_dir(layout::JOURNAL_DIR).unwrap();
    backing.crash_all_lost();
    assert_refused(&backing, "intact header", "invalid header");
}
