//! A slot whose allocation bit is clear is a hole only if nothing of it was
//! ever written (SPEC §22, round-10 audit D-1).
//!
//! SPEC §22 starts with "Maki MUST NOT infer that an all-zero backing slot
//! means an unwritten block". The probe of a cleared slot looked at its 64
//! header bytes only: an all-zero header read as a hole, whatever the rest of
//! the slot held. A checkpointed, FLUSH-acknowledged unit whose journal record
//! a later checkpoint had reclaimed, whose newest allocation-map copy no
//! longer decoded (the older copy predates the checkpoint that first wrote
//! the slot) and whose header sector read back as zeros (a remapped or
//! zero-filled bad sector) was then served as zeros, and `check --deep`
//! called the volume `clean`, although the slot still held its ciphertext.
//! The S-01 residual's reason applies to the whole slot: a hole is never
//! partly written. So only a slot whose header and ciphertext area are all
//! zero below the end of the file reads as zeros; anything else that is not a
//! header for the unit is damage (EIO), for the read path, the deep check
//! (through a writable backing and through a read-only view) and the open of
//! a shard the loaded catalog copy does not name.
//!
//! What a crash or a discard legitimately leaves keeps its meaning: a torn
//! first slot write (the header lost, the ciphertext kept) whose journal
//! record is newer than the checkpoint is rewritten from that record, and the
//! slot of a discarded unit, however much of it a hole punch released, reads
//! as zeros by its discard bit.

use std::io;
use std::sync::Arc;

use uuid::Uuid;

use maki_backing::{Backing, BackingFile, MemBacking, VolumeLock};
use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
use maki_core::error::CoreError;
use maki_core::store::{SlotRead, SlotStore};
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::ab::{AbRecord, AbStore};
use maki_format::allocation::AllocationMap;
use maki_format::catalog::ShardCatalog;
use maki_format::checker::CheckReport;
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::journal::{RECORD_HEADER_SIZE, SEGMENT_HEADER_SIZE};
use maki_format::layout;
use maki_format::superblock::Superblock;
use maki_test_support::failpoints::{self, FailpointAction};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::CrashableBacking;

const UNIT: u32 = 512;
/// The provider's ciphertext for one unit, and the volume's maximum.
const CT_LEN: usize = UNIT as usize + 8;
const DEVICE_UNITS: u64 = 48;
/// Eight units per shard; a slot is 1024 bytes (64 + 520, aligned to 512).
const SHARD_BYTES: u64 = 8 * UNIT as u64;
/// Two records per journal segment, so a checkpoint deletes the sealed
/// segments that held the first records.
const SMALL_SEGMENT: u64 =
    SEGMENT_HEADER_SIZE as u64 + 2 * (RECORD_HEADER_SIZE as u64 + CT_LEN as u64);

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0x2E80_5107_D001),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(
            UNIT,
            UNIT,
            512,
            CT_LEN as u32,
            DEVICE_UNITS * UNIT as u64,
            SHARD_BYTES,
        )
        .unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn geometry() -> Geometry {
    superblock().geometry
}

fn fixture(discard: bool) -> Arc<CrashableBacking> {
    let backing = Arc::new(CrashableBacking::new());
    if discard {
        init::create_volume_with_discard(backing.as_ref(), superblock()).unwrap();
    } else {
        init::create_volume(backing.as_ref(), superblock()).unwrap();
    }
    backing
}

async fn attach(backing: &Arc<CrashableBacking>) -> Engine {
    Engine::attach(
        backing.process(),
        Arc::new(FakeCryptoProvider::new(UNIT)),
        EngineOptions {
            checkpoint: CheckpointPolicy {
                emergency_reserve_bytes: 0,
                ..Default::default()
            },
            volume: VolumeOptions {
                journal_segment_size: SMALL_SEGMENT,
            },
            ..EngineOptions::default()
        },
    )
    .await
    .unwrap()
}

fn recover(backing: &Arc<CrashableBacking>, segment: u64) -> Result<Volume, String> {
    Volume::recover(
        backing.process(),
        VolumeOptions {
            journal_segment_size: segment,
        },
    )
    .map_err(|e| e.to_string())
}

/// Unit-sized plaintext, never all zero.
fn image(stamp: u8) -> Vec<u8> {
    (0..UNIT as usize)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(stamp) | 1)
        .collect()
}

/// Ciphertext of the largest size, no byte of it zero.
fn ciphertext(stamp: u8) -> Vec<u8> {
    (0..CT_LEN)
        .map(|i| (i as u8).wrapping_mul(29).wrapping_add(stamp) | 1)
        .collect()
}

fn verdict(report: &CheckReport) -> &str {
    report
        .info
        .iter()
        .find_map(|line| line.strip_prefix("deep check verdict: "))
        .unwrap_or("none")
}

fn deep_check(backing: &Arc<CrashableBacking>, segment: u64) -> CheckReport {
    maki_core::check::deep_check(backing.process() as Arc<dyn Backing>, segment).unwrap()
}

fn read_only_deep_check(backing: &Arc<CrashableBacking>, segment: u64) -> CheckReport {
    maki_core::check::deep_check(Arc::new(ReadOnlyView(backing.process())), segment).unwrap()
}

/// The newest valid side of an A/B pair; both sides must be valid.
fn newest<T: AbRecord>(backing: &CrashableBacking, a: &str, b: &str) -> String {
    let (ga, gb) = AbStore::new(a, b).side_generations::<T>(backing).unwrap();
    assert!(ga.is_some() && gb.is_some(), "{a}: {ga:?} {gb:?}");
    if ga > gb { a } else { b }.to_string()
}

/// Media damage: one bit of the newest valid copy flips, so `load` falls
/// back to the older copy.
fn damage_newest<T: AbRecord>(backing: &CrashableBacking, a: &str, b: &str) -> String {
    let newest = newest::<T>(backing, a, b);
    let file = backing.open(&newest, false).unwrap();
    let mut byte = [0u8; 1];
    file.read_at(4, &mut byte).unwrap();
    file.write_at(4, &[byte[0] ^ 0x10]).unwrap();
    file.sync_data().unwrap();
    let (ga, gb) = AbStore::new(a, b).side_generations::<T>(backing).unwrap();
    assert!(
        ga.is_none() ^ gb.is_none(),
        "{a}: exactly one valid copy left"
    );
    newest
}

fn damage_newest_map(backing: &CrashableBacking, shard: u64) -> AllocationMap {
    let (a, b) = (layout::shard_alloc_a(shard), layout::shard_alloc_b(shard));
    damage_newest::<AllocationMap>(backing, &a, &b);
    AbStore::new(a, b).load(backing).unwrap().unwrap()
}

fn data_file(backing: &CrashableBacking, shard: u64) -> Arc<dyn BackingFile> {
    backing.open(&layout::shard_data(shard), false).unwrap()
}

/// Overwrite `len` bytes from the start of a unit's slot with zeros, durably.
fn zero_slot_start(backing: &CrashableBacking, unit: u64, len: usize) {
    let geometry = geometry();
    let (shard, in_shard) = geometry.shard_of_unit(unit);
    let data = data_file(backing, shard);
    data.write_at(geometry.slot_offset(in_shard), &vec![0; len])
        .unwrap();
    data.sync_data().unwrap();
}

/// Non-zero bytes of a unit's slot after its first `skip` bytes.
fn nonzero_after(backing: &CrashableBacking, unit: u64, skip: u64) -> usize {
    let geometry = geometry();
    let (shard, in_shard) = geometry.shard_of_unit(unit);
    let mut rest = vec![0u8; (geometry.slot_size - skip) as usize];
    data_file(backing, shard)
        .read_at(geometry.slot_offset(in_shard) + skip, &mut rest)
        .unwrap();
    rest.iter().filter(|b| **b != 0).count()
}

/// Journal segments (the directory also holds the durable mark).
fn segments(backing: &CrashableBacking) -> usize {
    backing
        .list(layout::JOURNAL_DIR)
        .unwrap()
        .iter()
        .filter(|name| name.starts_with("seg-"))
        .count()
}

fn is_damage<T: std::fmt::Debug>(result: &Result<T, CoreError>) -> bool {
    matches!(result, Err(CoreError::Corrupt(_)) | Err(CoreError::Io(_)))
}

fn errors_name(report: &CheckReport, unit: u64) -> bool {
    let needle = format!("unit {unit}:");
    report.errors.iter().any(|line| line.contains(&needle))
}

/// The auditor's reproduction (seeds 26838, 41847, 47106 and 49743 of the
/// damage sweep), with the verdicts of both deep-check views. `zero` bytes
/// from the start of the slot read back as zeros: 64 is exactly the header,
/// 512 the 512-byte sector that holds it.
async fn checkpointed_unit_with_zeroed_header_and_lost_newest_map(zero: usize) {
    let geometry = geometry();
    let unit = 3u64;
    let (shard, in_shard) = geometry.shard_of_unit(unit);
    let backing = fixture(false);

    // Unit 3 is written, flushed and checkpointed: the checkpoint writes its
    // slot and stores the shard's allocation map once (one side lists it).
    // Two writes into other shards roll the journal, so the checkpoint also
    // deletes the sealed segment that held unit 3's record: nothing in the
    // journal speaks for the slot any more.
    let engine = attach(&backing).await;
    engine
        .write(unit * UNIT as u64, &image(7), false)
        .await
        .unwrap();
    for other in [10u64, 20] {
        engine
            .write(other * UNIT as u64, &image(other as u8), false)
            .await
            .unwrap();
    }
    engine.flush().await.unwrap();
    engine.checkpoint().await.unwrap();
    assert_eq!(
        segments(&backing),
        1,
        "the segment that held unit 3's record is reclaimed"
    );
    engine.stop_checkpoint_worker().await;
    drop(engine);

    // Damage 1: the newest allocation copy no longer decodes; the older one
    // predates the slot.
    let older = damage_newest_map(&backing, shard);
    assert!(!older.get(in_shard), "the older copy must predate the slot");
    // Damage 2: the start of the slot reads back as zeros, its ciphertext
    // after that is still there.
    zero_slot_start(&backing, unit, zero);
    assert!(nonzero_after(&backing, unit, zero as u64) > 0);

    let report = deep_check(&backing, SMALL_SEGMENT);
    assert_eq!(
        verdict(&report),
        "unrecoverable",
        "zero {zero}: a slot that is neither a hole nor a header is damage: {report:?}"
    );
    assert!(
        errors_name(&report, unit),
        "zero {zero}: {:?}",
        report.errors
    );
    let read_only = read_only_deep_check(&backing, SMALL_SEGMENT);
    assert_eq!(verdict(&read_only), "unrecoverable", "{read_only:?}");
    assert_eq!(
        read_only.errors, report.errors,
        "both views report the same damage"
    );

    // Attach serves EIO for the unit, never zeros, and every other unit as
    // before: a genuine hole in the same shard is still zeros.
    for attempt in ["after the damage", "after a restart"] {
        let engine = attach(&backing).await;
        let read = engine.read(unit * UNIT as u64, UNIT as usize).await;
        assert!(
            is_damage(&read),
            "zero {zero}, {attempt}: a checkpointed unit whose slot still holds its \
             ciphertext must read EIO, not {}",
            match &read {
                Ok(value) if value.iter().all(|b| *b == 0) => "zeros",
                Ok(_) => "data",
                Err(_) => "another error",
            }
        );
        assert_eq!(
            engine.read(5 * UNIT as u64, UNIT as usize).await.unwrap(),
            vec![0; UNIT as usize],
            "a never-written slot of the same shard is a hole"
        );
        for other in [10u64, 20] {
            assert_eq!(
                engine
                    .read(other * UNIT as u64, UNIT as usize)
                    .await
                    .unwrap(),
                image(other as u8)
            );
        }
        engine.stop_checkpoint_worker().await;
        drop(engine);
    }
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // failpoints are process-global
async fn a_zeroed_slot_header_with_a_lost_newest_map_reads_eio_not_zeros() {
    let _serial = failpoints::test_lock();
    checkpointed_unit_with_zeroed_header_and_lost_newest_map(64).await;
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // failpoints are process-global
async fn a_zeroed_header_sector_with_a_lost_newest_map_reads_eio_not_zeros() {
    let _serial = failpoints::test_lock();
    checkpointed_unit_with_zeroed_header_and_lost_newest_map(512).await;
}

/// The one crash state with an all-zero header over written slot bytes: a
/// checkpoint wrote the first slot of a unit, and the header did not reach
/// the disk while its ciphertext did. The checkpoint never completed, so the
/// unit's journal record is newer than the checkpoint: the deep check calls
/// the slot recoverable (it did not see it before), recovery rewrites it from
/// the record, and the data reads back.
#[test]
fn a_torn_first_slot_write_is_rewritten_from_its_journal_record() {
    let _serial = failpoints::test_lock();
    let segment = VolumeOptions::default().journal_segment_size;
    let backing = fixture(false);
    let unit = 3u64;
    let mut volume = recover(&backing, segment).unwrap();
    volume.write_ct(unit, &ciphertext(0x30), true).unwrap();
    {
        let _sync = failpoints::set(
            "checkpoint.shard_sync",
            FailpointAction::IoError(io::ErrorKind::Other, "injected shard sync failure".into()),
        );
        volume
            .checkpoint()
            .expect_err("the checkpoint stops before its slot is synced");
    }
    drop(volume);
    // The slot write tore: its header is lost, its ciphertext persisted.
    zero_slot_start(&backing, unit, 64);
    assert!(nonzero_after(&backing, unit, 64) > 0);

    let report = deep_check(&backing, segment);
    assert!(report.errors.is_empty(), "{report:?}");
    assert_eq!(verdict(&report), "recoverable", "{report:?}");
    assert!(
        report
            .warnings
            .iter()
            .any(|line| line.starts_with("slot: recoverable:") && line.contains("unit 3:")),
        "{:?}",
        report.warnings
    );
    let read_only = read_only_deep_check(&backing, segment);
    assert!(read_only.errors.is_empty(), "{read_only:?}");
    assert_eq!(verdict(&read_only), "unproven");

    let volume = recover(&backing, segment).unwrap();
    assert_eq!(volume.read_ct(unit).unwrap().unwrap().1, ciphertext(0x30));
    drop(volume);
    assert_eq!(verdict(&deep_check(&backing, segment)), "clean");
    backing.crash_all_lost();
    let volume = recover(&backing, segment).unwrap();
    assert_eq!(volume.read_ct(unit).unwrap().unwrap().1, ciphertext(0x30));
}

/// A record the checkpoint covers is still in the active segment and names
/// the slot. With its header zeroed over the ciphertext the slot is damage,
/// as a slot with any other damaged header is: recovery's comparison with
/// the record leaves it to the read path, which answers EIO, and the deep
/// check reports it. It used to look like a hole, which recovery refused as
/// "covered journal write ... has no visible slot".
#[test]
fn a_zeroed_header_under_a_covered_record_reads_eio() {
    let _serial = failpoints::test_lock();
    let segment = VolumeOptions::default().journal_segment_size;
    let backing = fixture(false);
    let mut volume = recover(&backing, segment).unwrap();
    volume.write_ct(1, &ciphertext(0x11), true).unwrap();
    volume.write_ct(3, &ciphertext(0x33), true).unwrap();
    volume.checkpoint().unwrap();
    drop(volume);
    assert_eq!(segments(&backing), 1);
    damage_newest_map(&backing, 0);
    zero_slot_start(&backing, 3, 64);

    let report = deep_check(&backing, segment);
    assert_eq!(verdict(&report), "unrecoverable", "{report:?}");
    assert!(errors_name(&report, 3), "{:?}", report.errors);
    let volume = recover(&backing, segment).unwrap();
    assert!(is_damage(&volume.read_ct(3)));
    assert_eq!(volume.read_ct(1).unwrap().unwrap().1, ciphertext(0x11));
}

/// A stray non-zero byte where a slot write would have put ciphertext makes
/// a never-written slot damage, as a stray byte in its header already did:
/// nothing tells it from a written slot whose header was zeroed. The slot's
/// alignment padding after the largest ciphertext holds nothing a slot write
/// puts there and is not evidence of a write.
#[test]
fn a_hole_is_only_a_slot_with_no_written_byte() {
    let _serial = failpoints::test_lock();
    let segment = VolumeOptions::default().journal_segment_size;
    let geometry = geometry();
    let backing = fixture(false);
    let mut volume = recover(&backing, segment).unwrap();
    volume.write_ct(1, &ciphertext(0x11), true).unwrap();
    volume.checkpoint().unwrap();
    drop(volume);
    let data = data_file(&backing, 0);
    let extent = 64 + geometry.max_ciphertext_size as u64;
    assert!(
        extent < geometry.slot_size,
        "the slot has alignment padding"
    );
    // Unit 5: the last byte a slot write can reach. Unit 6: its padding.
    data.write_at(geometry.slot_offset(5) + extent - 1, &[0x40])
        .unwrap();
    data.write_at(geometry.slot_offset(6) + extent, &[0x40])
        .unwrap();
    data.sync_data().unwrap();

    let volume = recover(&backing, segment).unwrap();
    assert!(is_damage(&volume.read_ct(5)), "{:?}", volume.read_ct(5));
    assert_eq!(volume.read_ct(6).unwrap(), None, "padding is not slot data");
    assert_eq!(volume.read_ct(4).unwrap(), None);
    assert_eq!(volume.read_ct(1).unwrap().unwrap().1, ciphertext(0x11));
    drop(volume);
    let report = deep_check(&backing, segment);
    assert!(errors_name(&report, 5), "{:?}", report.errors);
    assert!(!errors_name(&report, 6), "{:?}", report.errors);
    assert_eq!(
        read_only_deep_check(&backing, segment).errors,
        report.errors
    );
}

/// A ciphertext area larger than one read of the probe (64 KiB) is checked
/// to its last byte, and its alignment padding is not.
#[test]
fn a_large_ciphertext_area_is_probed_to_its_last_byte() {
    let max = 128 * 1024 + 1;
    let geometry = Geometry::compute(512, 512, 512, max, 512 * 8, 512 * 8).unwrap();
    let extent = 64 + u64::from(max);
    assert!(
        extent < geometry.slot_size,
        "the slot has alignment padding"
    );
    let backing = Arc::new(MemBacking::new());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            geometry: geometry.clone(),
            ..superblock()
        },
    )
    .unwrap();
    let mut store = SlotStore::open(backing.clone(), geometry.clone()).unwrap();
    store.write_slot(0, 1, &vec![7; max as usize]).unwrap();
    store.sync_shard_data(0).unwrap();
    store.mark_allocated(0).unwrap();
    store.persist_allocations().unwrap();
    assert!(matches!(store.read_slot(1).unwrap(), SlotRead::Zero));
    let data = backing.open(&layout::shard_data(0), false).unwrap();
    let inside = geometry.slot_offset(1) + 64 + 3 * 4096 + 5;
    data.write_at(inside, &[1]).unwrap();
    assert!(
        matches!(store.read_slot(1), Err(CoreError::Corrupt(_))),
        "a written byte inside the ciphertext area is not a hole"
    );
    data.write_at(inside, &[0]).unwrap();
    assert!(matches!(store.read_slot(1).unwrap(), SlotRead::Zero));
    let last = geometry.slot_offset(1) + extent - 1;
    data.write_at(last, &[1]).unwrap();
    assert!(
        matches!(store.read_slot(1), Err(CoreError::Corrupt(_))),
        "a written byte at the end of the ciphertext area is not a hole"
    );
    data.write_at(last, &[0]).unwrap();
    data.write_at(last + 1, &[1]).unwrap();
    assert!(matches!(store.read_slot(1).unwrap(), SlotRead::Zero));
}

/// v3 discard: a checkpoint persists the discard bit in both map copies and
/// only then punches the slot, and the bit is cleared only by a checkpoint
/// (or replay) that wrote and synced the unit's new slot first. A punch that
/// released only part of the slot (it failed after the first block, or its
/// zeros tore in a crash) therefore leaves an all-zero header over old
/// ciphertext only under a set discard bit, which answers zeros before the
/// slot is probed, whichever copies survive.
#[test]
fn a_partly_punched_slot_of_a_discarded_unit_reads_as_zeros() {
    let _serial = failpoints::test_lock();
    let segment = VolumeOptions::default().journal_segment_size;
    let geometry = geometry();
    let unit = 3u64;
    let (shard, in_shard) = geometry.shard_of_unit(unit);
    let backing = fixture(true);
    let mut volume = recover(&backing, segment).unwrap();
    volume.write_ct(1, &ciphertext(0x11), true).unwrap();
    volume.write_ct(unit, &ciphertext(0x33), true).unwrap();
    volume.checkpoint().unwrap();
    let offset = geometry.slot_offset(in_shard);
    let mut body = vec![0u8; CT_LEN];
    data_file(&backing, shard)
        .read_at(offset + 64, &mut body)
        .unwrap();
    volume.discard_ct(unit, true).unwrap();
    volume.checkpoint().unwrap();
    drop(volume);
    let (a, b) = (
        layout::shard_discard_a(shard),
        layout::shard_discard_b(shard),
    );
    for side in [&a, &b] {
        let file = backing.open(side, false).unwrap();
        let mut bytes = vec![0u8; file.len().unwrap() as usize];
        file.read_at(0, &mut bytes).unwrap();
        assert!(
            AllocationMap::decode(&bytes).unwrap().get(in_shard),
            "{side} lists the discard before the punch"
        );
    }
    assert_eq!(nonzero_after(&backing, unit, 0), 0, "the punch ran");
    // Only the first part of the range was released.
    let data = data_file(&backing, shard);
    data.write_at(offset + 64, &body).unwrap();
    data.sync_data().unwrap();
    damage_newest_map(&backing, shard);
    damage_newest::<AllocationMap>(&backing, &a, &b);

    let report = deep_check(&backing, segment);
    assert!(report.errors.is_empty(), "{report:?}");
    assert_eq!(verdict(&report), "clean");
    for restart in [false, true] {
        if restart {
            backing.crash_all_lost();
        }
        let volume = recover(&backing, segment).unwrap();
        assert_eq!(volume.read_ct(unit).unwrap(), None);
        assert_eq!(volume.read_ct(1).unwrap().unwrap().1, ciphertext(0x11));
    }
    let mut volume = recover(&backing, segment).unwrap();
    volume.write_ct(unit, &ciphertext(0x44), true).unwrap();
    volume.checkpoint().unwrap();
    drop(volume);
    backing.crash_all_lost();
    let volume = recover(&backing, segment).unwrap();
    assert_eq!(volume.read_ct(unit).unwrap().unwrap().1, ciphertext(0x44));
    drop(volume);
    assert_eq!(verdict(&deep_check(&backing, segment)), "clean");
}

/// A shard the loaded catalog copy does not name, whose allocation copies
/// list nothing, is one whose creation never finished only if no slot of it
/// holds a written byte: a slot write needs the data file's size proven
/// first, so its ciphertext proves the size as its header does. Here the
/// newest catalog and allocation copies were lost, the only written slot
/// below the end of a truncated data file has its header zeroed, and the
/// file ends before unit 5's slot: unit 5 must read EIO (its slot was cut
/// off), not zeros, before and after the file grows back.
#[test]
fn a_zeroed_header_still_proves_a_short_uncataloged_shard_truncated() {
    let _serial = failpoints::test_lock();
    let geometry = geometry();
    let backing = fixture(false);
    let mut volume = recover(&backing, SMALL_SEGMENT).unwrap();
    // Shards 1 and 2 first, so the older catalog copy names them but not
    // shard 0; then units 1 and 5 of shard 0; then two more records roll
    // the journal past theirs, which the checkpoint reclaims.
    for (unit, stamp) in [
        (10, 0x10),
        (20, 0x20),
        (1, 0x01),
        (5, 0x05),
        (11, 0x11),
        (21, 0x21),
    ] {
        volume.write_ct(unit, &ciphertext(stamp), false).unwrap();
    }
    volume.flush().unwrap();
    volume.checkpoint().unwrap();
    drop(volume);
    assert_eq!(segments(&backing), 1);

    damage_newest::<ShardCatalog>(&backing, layout::SHARD_CATALOG_A, layout::SHARD_CATALOG_B);
    let catalog: ShardCatalog = AbStore::new(layout::SHARD_CATALOG_A, layout::SHARD_CATALOG_B)
        .load(backing.as_ref())
        .unwrap()
        .unwrap();
    assert!(!catalog.contains(0) && catalog.contains(1) && catalog.contains(2));
    let older = damage_newest_map(&backing, 0);
    assert!((0..8).all(|in_shard| !older.get(in_shard)));
    zero_slot_start(&backing, 1, 64);
    assert!(nonzero_after(&backing, 1, 64) > 0);
    let data = data_file(&backing, 0);
    data.set_len(geometry.slot_offset(3)).unwrap();
    data.sync_data().unwrap();

    let report = deep_check(&backing, SMALL_SEGMENT);
    assert!(
        errors_name(&report, 1) && errors_name(&report, 5),
        "{:?}",
        report.errors
    );
    let mut volume = recover(&backing, SMALL_SEGMENT).unwrap();
    for unit in [1, 5] {
        assert!(
            is_damage(&volume.read_ct(unit)),
            "unit {unit}: {:?}",
            volume.read_ct(unit)
        );
    }
    assert_eq!(volume.read_ct(10).unwrap().unwrap().1, ciphertext(0x10));
    // A write into the shard grows the file back; unit 5 stays damage.
    volume.write_ct(7, &ciphertext(0x07), true).unwrap();
    volume.checkpoint().unwrap();
    assert_eq!(
        data.len().unwrap(),
        geometry.units_per_shard() * geometry.slot_size
    );
    for unit in [1, 5] {
        assert!(
            is_damage(&volume.read_ct(unit)),
            "unit {unit}: {:?}",
            volume.read_ct(unit)
        );
    }
    drop(volume);
    backing.crash_all_lost();
    let volume = recover(&backing, SMALL_SEGMENT).unwrap();
    for unit in [1, 5] {
        assert!(
            is_damage(&volume.read_ct(unit)),
            "unit {unit}: {:?}",
            volume.read_ct(unit)
        );
    }
    assert_eq!(volume.read_ct(7).unwrap().unwrap().1, ciphertext(0x07));
}

/// A read-only view of a backing, as `FileBacking::read_only` is: every
/// change fails, `is_read_only` is true, and the shared lock is granted for
/// an existing file only.
struct ReadOnlyView(Arc<CrashableBacking>);

struct SharedLock;
impl VolumeLock for SharedLock {}

struct ReadOnlyFile(Arc<dyn BackingFile>);

fn refused() -> io::Error {
    io::Error::new(io::ErrorKind::ReadOnlyFilesystem, "read-only view")
}

impl BackingFile for ReadOnlyFile {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.0.read_at(offset, buf)
    }
    fn write_at(&self, _: u64, _: &[u8]) -> io::Result<()> {
        Err(refused())
    }
    fn set_len(&self, _: u64) -> io::Result<()> {
        Err(refused())
    }
    fn allocate_range(&self, _: u64, _: u64) -> io::Result<()> {
        Err(refused())
    }
    fn punch_hole(&self, _: u64, _: u64) -> io::Result<()> {
        Err(refused())
    }
    fn len(&self) -> io::Result<u64> {
        self.0.len()
    }
    fn sync_data(&self) -> io::Result<()> {
        Err(refused())
    }
}

impl Backing for ReadOnlyView {
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        if create {
            return Err(refused());
        }
        Ok(Arc::new(ReadOnlyFile(self.0.open(path, false)?)))
    }
    fn exists(&self, path: &str) -> io::Result<bool> {
        self.0.exists(path)
    }
    fn remove(&self, _: &str) -> io::Result<()> {
        Err(refused())
    }
    fn rename(&self, _: &str, _: &str) -> io::Result<()> {
        Err(refused())
    }
    fn create_dir_all(&self, _: &str) -> io::Result<()> {
        Err(refused())
    }
    fn list(&self, dir: &str) -> io::Result<Vec<String>> {
        self.0.list(dir)
    }
    fn sync_dir(&self, _: &str) -> io::Result<()> {
        Err(refused())
    }
    fn try_lock(&self, _: &str) -> io::Result<Box<dyn VolumeLock>> {
        Err(refused())
    }
    fn is_read_only(&self) -> bool {
        true
    }
    fn try_lock_shared_existing(&self, path: &str) -> io::Result<Box<dyn VolumeLock>> {
        if self.0.exists(path)? {
            Ok(Box::new(SharedLock))
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, path.to_string()))
        }
    }
}
