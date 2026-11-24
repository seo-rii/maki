//! Audit round 9 (r8-storage): `SlotStore::open` decides whether a short
//! shard data file is "never finished" (holes) or "truncated" (EIO) BEFORE
//! it probes the slot headers, from the loaded catalog copy and the loaded
//! allocation copy alone. Both are accelerators that fall back to an older
//! generation; slot headers are the authority (S-01).
//!
//! A shard that was checkpointed into exactly once has an older allocation
//! copy that is still the empty map of its creation, and if it is the
//! volume's newest shard the older catalog copy does not list it. When media
//! damage takes the newest copy of both and truncates the data file, the
//! shard is classified `Unproven` (uncataloged, empty map), although the
//! header probe that follows finds checkpointed data in it. Every
//! checkpointed unit beyond the cut then reads as zeros instead of EIO.
//!
//! The first test needs three damaged files, one more than the maintained
//! damage sweep injects. The second needs two: the catalog copy that names
//! the shard was never durable (its sync failed at shard creation, a restart
//! read it back from the page cache, and nothing stores the catalog again),
//! so a power loss alone removes it. Both tests FAIL on the audited tree
//! (1d4c7ea) with "ZEROS-FOR-CHECKPOINTED-DATA"; `native/f2_real.py` in the
//! audit scratchpad shows the first through nbdkit and the plugin.

use std::sync::Arc;

use uuid::Uuid;

use maki_backing::Backing;
use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
use maki_core::error::CoreError;
use maki_core::volume::VolumeOptions;
use maki_format::journal::{RECORD_HEADER_SIZE, SEGMENT_HEADER_SIZE};
use maki_format::ab::AbStore;
use maki_format::allocation::AllocationMap;
use maki_format::catalog::ShardCatalog;
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::layout;
use maki_format::superblock::Superblock;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::CrashableBacking;

const UNIT: u32 = 512;
const PER: u64 = 8;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0x0A9_D0D0),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(UNIT, UNIT, 512, UNIT + 8, 4 * PER * UNIT as u64, PER * UNIT as u64)
            .unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

async fn attach(backing: &Arc<CrashableBacking>) -> Engine {
    Engine::attach(
        backing.process(),
        Arc::new(FakeCryptoProvider::new(UNIT)),
        EngineOptions {
            // Two records per journal segment, so a few rewrites roll it and
            // a checkpoint reclaims the segments that held the first writes.
            volume: VolumeOptions {
                journal_segment_size: SEGMENT_HEADER_SIZE as u64
                    + 2 * (RECORD_HEADER_SIZE as u64 + UNIT as u64 + 8),
            },
            checkpoint: CheckpointPolicy {
                emergency_reserve_bytes: 0,
                ..Default::default()
            },
            ..EngineOptions::default()
        },
    )
    .await
    .unwrap()
}

fn image(unit: u64) -> Vec<u8> {
    (0..UNIT).map(|i| (unit as u8).wrapping_mul(31).wrapping_add(i as u8) | 1).collect()
}

fn newest<T: maki_format::ab::AbRecord>(backing: &CrashableBacking, a: String, b: String) -> String {
    let (ga, gb) = AbStore::new(a.clone(), b.clone())
        .side_generations::<T>(backing)
        .unwrap();
    assert!(ga.is_some() && gb.is_some(), "{a}: {ga:?} {gb:?}");
    if ga >= gb {
        a
    } else {
        b
    }
}

fn damage(backing: &CrashableBacking, path: &str) {
    let file = backing.open(path, false).unwrap();
    file.set_len(file.len().unwrap() - 1).unwrap();
    file.sync_data().unwrap();
}

#[tokio::test]
async fn audit9_a_used_shard_that_loses_both_newest_copies_and_its_tail_reads_zeros() {
    let _serial = maki_test_support::failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    let geometry = superblock().geometry;

    // One shard, checkpointed into once: units 1 and 5.
    let engine = attach(&backing).await;
    for unit in [1u64, 5] {
        engine
            .write(unit * UNIT as u64, &image(unit), true)
            .await
            .unwrap();
    }
    engine.checkpoint().await.unwrap();
    // The same session goes on rewriting unit 1 only: its bit is already
    // set, so no later checkpoint stores the allocation map again, and the
    // journal segments that held the first writes are reclaimed.
    for _ in 0..8 {
        engine.write(UNIT as u64, &image(1), true).await.unwrap();
    }
    engine.checkpoint().await.unwrap();
    for unit in [1u64, 5] {
        assert_eq!(
            engine.read(unit * UNIT as u64, UNIT as usize).await.unwrap(),
            image(unit)
        );
    }
    drop(engine);
    backing.crash_all_lost();
    {
        let segments: Vec<String> = backing.list(layout::JOURNAL_DIR).unwrap();
        println!("journal after the workload: {segments:?}");
        let (a, b) = AbStore::new(layout::shard_alloc_a(0), layout::shard_alloc_b(0))
            .side_generations::<AllocationMap>(backing.as_ref())
            .unwrap();
        println!("allocation copies: a {a:?} b {b:?}");
    }

    // Media damage: the newest catalog copy, the newest allocation copy,
    // and the data file cut inside slot 4 (slots 5..7 gone).
    let catalog = newest::<ShardCatalog>(
        &backing,
        layout::SHARD_CATALOG_A.into(),
        layout::SHARD_CATALOG_B.into(),
    );
    damage(&backing, &catalog);
    let alloc = newest::<AllocationMap>(&backing, layout::shard_alloc_a(0), layout::shard_alloc_b(0));
    damage(&backing, &alloc);
    let data = backing.open(&layout::shard_data(0), false).unwrap();
    data.set_len(geometry.slot_offset(4) + 447).unwrap();
    data.sync_data().unwrap();
    drop(data);

    let engine = attach(&backing).await;
    // The header probe still finds unit 1: the shard was checkpointed into.
    assert_eq!(
        engine.read(UNIT as u64, UNIT as usize).await.unwrap(),
        image(1),
        "unit 1 lies before the cut and its header is intact"
    );
    // SPEC section 12 / 22: a checkpointed unit whose slot is gone is EIO,
    // never zeros.
    match engine.read(5 * UNIT as u64, UNIT as usize).await {
        Err(CoreError::Corrupt(_)) | Err(CoreError::Io(_)) => {}
        Ok(bytes) if bytes.iter().all(|b| *b == 0) => panic!(
            "ZEROS-FOR-CHECKPOINTED-DATA: unit 5 was checkpointed, its slot was removed by the \
             truncation, and it reads as zeros (the shard was classified as never finished \
             although the header probe found unit 1 in it)"
        ),
        Ok(bytes) => panic!("unit 5 reads as data: {:02x?}", &bytes[..8]),
        Err(e) => panic!("unexpected error class: {e}"),
    }
}

/// The same outcome with TWO damaged files, the number the maintained
/// media-damage sweep injects, after a crash history that needs no damage:
/// the catalog copy that names the shard was never durable. Its sync failed
/// when the shard was created (the write was refused), the process
/// restarted and read the copy back from the page cache, and nothing stores
/// the catalog again until another shard is created (the catalog is an
/// accelerator: an unlisted data file is adopted, K-03). A power loss then
/// leaves the older catalog copy, which does not list the shard.
#[tokio::test]
async fn audit9_two_damaged_files_after_a_volatile_catalog_read_zeros() {
    use maki_test_support::crash_backing::FaultOp;
    use std::sync::atomic::{AtomicBool, Ordering};

    let _serial = maki_test_support::failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    let geometry = superblock().geometry;

    // Session 1: the shard's creation fails at the catalog copy's sync.
    let engine = attach(&backing).await;
    let fired = Arc::new(AtomicBool::new(false));
    let once = fired.clone();
    backing.set_fault_hook(Some(Arc::new(move |op| match op {
        FaultOp::SyncData { path } if path.contains("shard-catalog.b") => {
            (!once.swap(true, Ordering::SeqCst)).then(|| std::io::Error::other("injected"))
        }
        _ => None,
    })));
    assert!(engine.write(UNIT as u64, &image(1), true).await.is_err());
    assert!(fired.load(Ordering::SeqCst), "the catalog sync was not reached");
    backing.set_fault_hook(None);
    drop(engine);

    // Session 2 (a restart, no power loss): the volume is used.
    let engine = attach(&backing).await;
    for unit in [1u64, 5] {
        engine
            .write(unit * UNIT as u64, &image(unit), true)
            .await
            .unwrap();
    }
    engine.checkpoint().await.unwrap();
    for _ in 0..8 {
        engine.write(UNIT as u64, &image(1), true).await.unwrap();
    }
    engine.checkpoint().await.unwrap();
    drop(engine);

    // Power loss: no damage yet, and both units are served.
    backing.crash_all_lost();
    let engine = attach(&backing).await;
    for unit in [1u64, 5] {
        assert_eq!(
            engine.read(unit * UNIT as u64, UNIT as usize).await.unwrap(),
            image(unit),
            "after the power loss alone"
        );
    }
    drop(engine);
    backing.crash_all_lost();
    let (ca, cb) = AbStore::new(layout::SHARD_CATALOG_A, layout::SHARD_CATALOG_B)
        .side_generations::<ShardCatalog>(backing.as_ref())
        .unwrap();
    println!("catalog copies after the power loss: a {ca:?} b {cb:?}");

    // Media damage to two files: the newest allocation copy and the data
    // file's tail.
    let alloc = newest::<AllocationMap>(&backing, layout::shard_alloc_a(0), layout::shard_alloc_b(0));
    damage(&backing, &alloc);
    let data = backing.open(&layout::shard_data(0), false).unwrap();
    data.set_len(geometry.slot_offset(4) + 447).unwrap();
    data.sync_data().unwrap();
    drop(data);

    let engine = attach(&backing).await;
    assert_eq!(
        engine.read(UNIT as u64, UNIT as usize).await.unwrap(),
        image(1)
    );
    match engine.read(5 * UNIT as u64, UNIT as usize).await {
        Err(CoreError::Corrupt(_)) | Err(CoreError::Io(_)) => {}
        Ok(bytes) if bytes.iter().all(|b| *b == 0) => panic!(
            "ZEROS-FOR-CHECKPOINTED-DATA: unit 5 reads as zeros after damage to two files"
        ),
        Ok(bytes) => panic!("unit 5 reads as data: {:02x?}", &bytes[..8]),
        Err(e) => panic!("unexpected error class: {e}"),
    }
}

/// A sibling with two lost files: the newest catalog copy and the newest
/// shard's data file itself (what a filesystem repair that moves a file to
/// `lost+found` leaves). Nothing lists the shard any more, so its
/// allocation copies, which still say that its units hold data, are never
/// looked at: the volume attaches and the shard reads as zeros. With only
/// the data file missing, attach is refused ("data file missing"); while a
/// journal record of one of its units survives, recovery refuses too
/// ("covered journal write ... has no visible slot").
#[tokio::test]
async fn audit9_a_lost_data_file_behind_a_lost_catalog_copy_reads_zeros() {
    let _serial = maki_test_support::failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    let engine = attach(&backing).await;
    // Shard 0 first, then shard 1 (units 9 and 13): the older catalog copy
    // lists shard 0 only.
    engine.write(UNIT as u64, &image(1), true).await.unwrap();
    engine.checkpoint().await.unwrap();
    for unit in [9u64, 13] {
        engine
            .write(unit * UNIT as u64, &image(unit), true)
            .await
            .unwrap();
    }
    engine.checkpoint().await.unwrap();
    // Later traffic goes to shard 0; the journal forgets shard 1.
    for _ in 0..8 {
        engine.write(UNIT as u64, &image(1), true).await.unwrap();
    }
    engine.checkpoint().await.unwrap();
    drop(engine);
    backing.crash_all_lost();

    let catalog = newest::<ShardCatalog>(
        &backing,
        layout::SHARD_CATALOG_A.into(),
        layout::SHARD_CATALOG_B.into(),
    );
    damage(&backing, &catalog);
    backing.remove(&layout::shard_data(1)).unwrap();
    backing.sync_dir(layout::DATA_DIR).unwrap();
    println!("data directory: {:?}", backing.list(layout::DATA_DIR).unwrap());

    let engine = match Engine::attach(
        backing.process(),
        Arc::new(FakeCryptoProvider::new(UNIT)),
        EngineOptions::default(),
    )
    .await
    {
        Ok(engine) => engine,
        Err(e) => {
            println!("attach refused, as it should be: {e}");
            return;
        }
    };
    assert_eq!(
        engine.read(UNIT as u64, UNIT as usize).await.unwrap(),
        image(1)
    );
    for unit in [9u64, 13] {
        match engine.read(unit * UNIT as u64, UNIT as usize).await {
            Err(CoreError::Corrupt(_)) | Err(CoreError::Io(_)) => {}
            Ok(bytes) if bytes.iter().all(|b| *b == 0) => panic!(
                "ZEROS-FOR-CHECKPOINTED-DATA: unit {unit} reads as zeros; its shard's data file \
                 and the newest catalog copy are gone, its allocation copies still list it"
            ),
            Ok(bytes) => panic!("unit {unit} reads as data: {:02x?}", &bytes[..8]),
            Err(e) => panic!("unexpected error class: {e}"),
        }
    }
}

/// The two above combined: after the crash history of the second test (no
/// damage: the only catalog copy that names the shard was never durable),
/// ONE lost file, the shard's data file, makes the whole shard read as
/// zeros. A shard the catalog names would refuse the attach instead
/// ("data file missing").
#[tokio::test]
async fn audit9_one_lost_data_file_after_a_volatile_catalog_reads_zeros() {
    use maki_test_support::crash_backing::FaultOp;
    use std::sync::atomic::{AtomicBool, Ordering};

    let _serial = maki_test_support::failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), superblock()).unwrap();

    // Session 1: shard 0 is created and used; shard 1's creation fails at
    // the sync of the catalog copy that names it.
    let engine = attach(&backing).await;
    engine.write(UNIT as u64, &image(1), true).await.unwrap();
    engine.checkpoint().await.unwrap();
    let fired = Arc::new(AtomicBool::new(false));
    let once = fired.clone();
    backing.set_fault_hook(Some(Arc::new(move |op| match op {
        // The target of this catalog store is side A (generation 3).
        FaultOp::SyncData { path } if path.contains("shard-catalog.a") => {
            (!once.swap(true, Ordering::SeqCst)).then(|| std::io::Error::other("injected"))
        }
        _ => None,
    })));
    assert!(engine.write(9 * UNIT as u64, &image(9), true).await.is_err());
    assert!(fired.load(Ordering::SeqCst), "the catalog sync was not reached");
    backing.set_fault_hook(None);
    drop(engine);

    // Session 2 (restart): shard 1 is used; later traffic goes to shard 0.
    let engine = attach(&backing).await;
    for unit in [9u64, 13] {
        engine
            .write(unit * UNIT as u64, &image(unit), true)
            .await
            .unwrap();
    }
    engine.checkpoint().await.unwrap();
    for _ in 0..8 {
        engine.write(UNIT as u64, &image(1), true).await.unwrap();
    }
    engine.checkpoint().await.unwrap();
    drop(engine);

    // Power loss. The volume is intact...
    backing.crash_all_lost();
    let (ca, cb) = AbStore::new(layout::SHARD_CATALOG_A, layout::SHARD_CATALOG_B)
        .side_generations::<ShardCatalog>(backing.as_ref())
        .unwrap();
    println!("catalog copies after the power loss: a {ca:?} b {cb:?}");
    // ...but before the next attach, one file is lost.
    backing.remove(&layout::shard_data(1)).unwrap();
    backing.sync_dir(layout::DATA_DIR).unwrap();

    let engine = match Engine::attach(
        backing.process(),
        Arc::new(FakeCryptoProvider::new(UNIT)),
        EngineOptions::default(),
    )
    .await
    {
        Ok(engine) => engine,
        Err(e) => {
            println!("attach refused, as it should be: {e}");
            return;
        }
    };
    for unit in [9u64, 13] {
        match engine.read(unit * UNIT as u64, UNIT as usize).await {
            Err(CoreError::Corrupt(_)) | Err(CoreError::Io(_)) => {}
            Ok(bytes) if bytes.iter().all(|b| *b == 0) => panic!(
                "ZEROS-FOR-CHECKPOINTED-DATA: unit {unit} reads as zeros after ONE lost file"
            ),
            Ok(bytes) => panic!("unit {unit} reads as data: {:02x?}", &bytes[..8]),
            Err(e) => panic!("unexpected error class: {e}"),
        }
    }
}
