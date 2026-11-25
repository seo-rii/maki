//! The shard catalog and the allocation maps are accelerators that an A/B
//! fallback can leave one generation behind (S-01): a shard the loaded
//! catalog copy does not name is found by its files. An allocation map that
//! lists a slot proves that a checkpoint wrote into the shard, whatever the
//! catalog says, so a shard with such a map and no data file has lost its
//! data: attach refuses and the checks report it, as for a cataloged shard
//! whose data file is missing. An allocation copy that lists nothing is what
//! an interrupted shard creation leaves, and stays harmless.

use std::sync::Arc;

use maki_backing::Backing;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::ab::AbStore;
use maki_format::allocation::AllocationMap;
use maki_format::catalog::ShardCatalog;
use maki_format::{checker, geometry::Geometry, init, layout, superblock::Superblock};
use maki_test_support::{failpoints, CrashableBacking};

const UNITS_PER_SHARD: u64 = 16;

fn geometry() -> Geometry {
    Geometry::compute(512, 512, 512, 520, 512 * 64, 512 * UNITS_PER_SHARD).unwrap()
}

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: 4096,
    }
}

fn fixture(discard: bool) -> Arc<CrashableBacking> {
    let backing = Arc::new(CrashableBacking::new().with_tearing(512));
    let superblock = Superblock {
        generation: 0,
        volume_uuid: Default::default(),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: geometry(),
        format_version: 1,
        created_unix: 0,
    };
    if discard {
        init::create_volume_with_discard(backing.as_ref(), superblock).unwrap();
    } else {
        init::create_volume(backing.as_ref(), superblock).unwrap();
    }
    backing
}

fn recover(backing: &Arc<CrashableBacking>) -> Result<Volume, String> {
    Volume::recover(backing.clone(), options()).map_err(|e| e.to_string())
}

fn ciphertext(stamp: u8) -> Vec<u8> {
    vec![stamp; 520]
}

/// Cut one byte off the newest valid copy of an A/B pair.
fn damage_newest<T: maki_format::ab::AbRecord>(backing: &CrashableBacking, a: &str, b: &str) {
    let (ga, gb) = AbStore::new(a, b).side_generations::<T>(backing).unwrap();
    assert!(ga.is_some() && gb.is_some(), "{a}: {ga:?} {gb:?}");
    let newest = if ga >= gb { a } else { b };
    let file = backing.open(newest, false).unwrap();
    file.set_len(file.len().unwrap() - 1).unwrap();
    file.sync_data().unwrap();
}

fn deep_check_errors(backing: &Arc<CrashableBacking>) -> Vec<String> {
    maki_core::check::deep_check(backing.process() as Arc<dyn Backing>, 4096)
        .unwrap()
        .errors
}

/// Shard 0 first, then shard 1 (units 16 and 20), each checkpointed; later
/// traffic goes to shard 0 only, so the journal no longer holds shard 1's
/// records. The older catalog copy names shard 0 alone.
fn two_shard_history(backing: &Arc<CrashableBacking>) {
    let mut volume = recover(backing).unwrap();
    volume.write_ct(1, &ciphertext(0x11), true).unwrap();
    volume.checkpoint().unwrap();
    for unit in [UNITS_PER_SHARD, UNITS_PER_SHARD + 4] {
        volume.write_ct(unit, &ciphertext(0x20), true).unwrap();
    }
    volume.checkpoint().unwrap();
    for stamp in 0..24u8 {
        volume.write_ct(1, &ciphertext(0x30 + stamp), true).unwrap();
    }
    volume.checkpoint().unwrap();
    drop(volume);
    backing.crash_all_lost();
}

/// The newest catalog copy is damaged, so the loaded one does not name
/// shard 1, and shard 1's data file is lost. Its allocation copies, which
/// list units 16 and 20, are still there. Before, open looked for shards by
/// data file name only: the volume attached and both units read as zeros,
/// and neither check reported anything but a fallback warning.
#[test]
fn allocation_copies_that_list_slots_without_a_data_file_refuse_attach() {
    let _serial = failpoints::test_lock();
    for discard in [false, true] {
        let backing = fixture(discard);
        two_shard_history(&backing);
        damage_newest::<ShardCatalog>(&backing, layout::SHARD_CATALOG_A, layout::SHARD_CATALOG_B);
        let loaded = AbStore::new(layout::SHARD_CATALOG_A, layout::SHARD_CATALOG_B)
            .load::<ShardCatalog>(backing.as_ref())
            .unwrap()
            .unwrap();
        assert!(loaded.contains(0) && !loaded.contains(1));
        backing.remove(&layout::shard_data(1)).unwrap();
        backing.sync_dir(layout::DATA_DIR).unwrap();

        match recover(&backing) {
            Err(e) => assert!(
                e.contains("shard 1") && e.contains("data file missing"),
                "discard {discard}: unexpected refusal: {e}"
            ),
            Ok(volume) => panic!(
                "discard {discard}: attach must refuse a shard whose allocation map lists \
                 written slots and whose data file is missing; unit 16 reads {:?}",
                volume
                    .read_ct(UNITS_PER_SHARD)
                    .map(|r| r.map(|(seq, _)| seq))
            ),
        }
        let fast = checker::check_volume(backing.as_ref()).unwrap();
        assert!(
            fast.errors
                .iter()
                .any(|e| e.contains("shard 1") && e.contains("data file")),
            "discard {discard}: the fast check must report shard 1's missing data file: {:?}",
            fast.errors
        );
        let deep = deep_check_errors(&backing);
        assert!(
            deep.iter()
                .any(|e| e.contains("shard 1") && e.contains("data file")),
            "discard {discard}: the deep check must report shard 1's missing data file: {deep:?}"
        );
    }
}

/// What an interrupted shard creation can leave: allocation copies (and, on
/// a v3 volume, discard copies) that list nothing, beside no data file, or
/// one such copy beside a torn one. The shard was never written into: the
/// volume attaches, the units read as zeros, the checks report no error and
/// a write creates the shard.
#[test]
fn allocation_copies_that_list_nothing_without_a_data_file_stay_harmless() {
    let _serial = failpoints::test_lock();
    for discard in [false, true] {
        for torn_second_copy in [false, true] {
            let backing = fixture(discard);
            two_shard_history(&backing);
            let shard = 2;
            let mut empty = AllocationMap::new(UNITS_PER_SHARD);
            let alloc = AbStore::new(layout::shard_alloc_a(shard), layout::shard_alloc_b(shard));
            alloc.store(backing.as_ref(), &mut empty).unwrap();
            if torn_second_copy {
                let file = backing.open(&layout::shard_alloc_b(shard), true).unwrap();
                file.write_at(0, b"MAKIALC1").unwrap();
                file.sync_data().unwrap();
            } else {
                alloc.store(backing.as_ref(), &mut empty).unwrap();
            }
            if discard {
                let discard_ab = AbStore::new(
                    layout::shard_discard_a(shard),
                    layout::shard_discard_b(shard),
                );
                discard_ab.store(backing.as_ref(), &mut empty).unwrap();
                discard_ab.store(backing.as_ref(), &mut empty).unwrap();
            }
            backing.sync_dir(layout::DATA_DIR).unwrap();
            assert!(!backing.exists(&layout::shard_data(shard)).unwrap());

            let fast = checker::check_volume(backing.as_ref()).unwrap();
            assert!(
                fast.errors.is_empty(),
                "{discard} {torn_second_copy}: {:?}",
                fast.errors
            );
            let deep = deep_check_errors(&backing);
            assert!(deep.is_empty(), "{discard} {torn_second_copy}: {deep:?}");
            let unit = shard * UNITS_PER_SHARD + 3;
            let mut volume = recover(&backing).unwrap();
            assert_eq!(volume.read_ct(unit).unwrap(), None);
            volume.write_ct(unit, &ciphertext(0x44), true).unwrap();
            volume.checkpoint().unwrap();
            drop(volume);
            backing.crash_all_lost();
            let volume = recover(&backing).unwrap();
            assert_eq!(volume.read_ct(unit).unwrap().unwrap().1, ciphertext(0x44));
            assert_eq!(
                volume.read_ct(UNITS_PER_SHARD).unwrap().unwrap().1,
                ciphertext(0x20)
            );
        }
    }
}

/// The newest catalog copy and the newest allocation copy of the volume's
/// only shard are damaged, and its data file is cut inside slot 4 (or
/// inside the header of unit 1, the first written slot). The older catalog
/// copy does not name the shard and the older allocation copy is the empty
/// map of its creation, so open took the shard for one whose creation never
/// finished, whose short file proves nothing, although the header bytes of
/// unit 1 below the cut show that a checkpoint wrote into it. Unit 5 then
/// read as zeros, and the first checkpoint grew the file back and cataloged
/// the shard, after which every later open and the deep check saw a healthy
/// shard. Written slot header bytes are evidence that the file's size was
/// proven: the file is truncated and the units beyond the cut read EIO,
/// before and after a checkpoint and a restart.
#[test]
fn a_short_uncataloged_shard_with_a_written_slot_reads_eio_beyond_its_end() {
    let _serial = failpoints::test_lock();
    let cuts = [
        (geometry().slot_offset(4) + 447, true),
        (geometry().slot_offset(1) + 20, false),
    ];
    for (discard, (cut, unit_1_survives)) in [false, true]
        .into_iter()
        .flat_map(|discard| cuts.map(|cut| (discard, cut)))
    {
        let backing = fixture(discard);
        let mut volume = recover(&backing).unwrap();
        for unit in [1, 5] {
            volume
                .write_ct(unit, &ciphertext(0x50 + unit as u8), true)
                .unwrap();
        }
        volume.checkpoint().unwrap();
        // Unit 1's bit is already set: no later checkpoint stores the map.
        for stamp in 0..24u8 {
            volume.write_ct(1, &ciphertext(0x60 + stamp), true).unwrap();
        }
        volume.checkpoint().unwrap();
        drop(volume);
        backing.crash_all_lost();

        damage_newest::<ShardCatalog>(&backing, layout::SHARD_CATALOG_A, layout::SHARD_CATALOG_B);
        damage_newest::<AllocationMap>(
            &backing,
            &layout::shard_alloc_a(0),
            &layout::shard_alloc_b(0),
        );
        let data = backing.open(&layout::shard_data(0), false).unwrap();
        data.set_len(cut).unwrap();
        data.sync_data().unwrap();
        drop(data);

        let mut failures = Vec::new();
        if deep_check_errors(&backing).is_empty() {
            failures.push("the deep check reports no error before the first attach".to_string());
        }
        for attach in 1..=2 {
            let mut volume = recover(&backing).unwrap();
            if unit_1_survives {
                assert_eq!(volume.read_ct(1).unwrap().unwrap().1, ciphertext(0x60 + 23));
            }
            let beyond: &[u64] = if unit_1_survives { &[5] } else { &[1, 5] };
            for &unit in beyond {
                match volume.read_ct(unit) {
                    Err(_) => {}
                    Ok(read) => failures.push(format!(
                        "attach {attach}: unit {unit} reads {:?} (None = zeros)",
                        read.map(|(sequence, _)| sequence)
                    )),
                }
            }
            // What the worker does next: the idle checkpoint stores the
            // repairs open made (the adopted shard, the damage marks).
            volume.checkpoint().unwrap();
            drop(volume);
            if deep_check_errors(&backing).is_empty() {
                failures.push(format!(
                    "the deep check reports no error after attach {attach}"
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "discard {discard}, cut at {cut}: {failures:?}"
        );
    }
}
