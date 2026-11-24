//! Audit round 9 (r8-storage, successor): the shard catalog and K-01.
//!
//! SPEC §27: "a process restart hands recovery page-cache bytes: nothing it
//! accepts may stay unsynced once the writer resumes". Open stores every
//! loaded allocation map again before the first reservation (`map_stored`)
//! and every discard map (`dirty_discard`), but the shard catalog only when
//! it adopted an orphan (`catalog_dirty`). A catalog copy whose sync failed
//! when a shard was created is read back from the page cache by the next
//! (restart) recovery, accepted, and never stored again until another shard
//! is created; the next power loss removes it.
//!
//! - `audit9_k01_*` shows that directly, with no damage: FAILS.
//! - `audit9_first_attach_erases_the_evidence` shows that the zeros of
//!   `audit9_unproven_after_damage.rs` are not a transient misread: the
//!   first attach grows the data file back, catalogs the shard and stores
//!   its map, after which a second attach and the deep check see a healthy
//!   shard: FAILS.
//! - `audit9_volatile_catalog_crash_only_sweep` drives the same window
//!   (failed catalog / allocation / directory syncs, restarts, power losses
//!   with tearing, the Linux failed-sync model) with no damage and checks
//!   every acknowledged write: PASSES (crash-only histories are safe; the
//!   data-file adoption covers the dropped catalog entry).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use uuid::Uuid;

use maki_backing::Backing;
use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
use maki_core::error::CoreError;
use maki_core::volume::VolumeOptions;
use maki_format::ab::AbStore;
use maki_format::allocation::AllocationMap;
use maki_format::catalog::ShardCatalog;
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::journal::{RECORD_HEADER_SIZE, SEGMENT_HEADER_SIZE};
use maki_format::layout;
use maki_format::superblock::Superblock;
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::{CrashableBacking, ManualClock};

const UNIT: u32 = 512;
const PER: u64 = 8;
const SHARDS: u64 = 4;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0x0A9_C0C0),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(
            UNIT,
            UNIT,
            512,
            UNIT + 8,
            SHARDS * PER * UNIT as u64,
            PER * UNIT as u64,
        )
        .unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn segment_size() -> u64 {
    SEGMENT_HEADER_SIZE as u64 + 2 * (RECORD_HEADER_SIZE as u64 + UNIT as u64 + 8)
}

fn options() -> EngineOptions {
    EngineOptions {
        // Two records per segment: a few rewrites roll the journal and a
        // checkpoint reclaims the segments that held the first writes.
        volume: VolumeOptions {
            journal_segment_size: segment_size(),
        },
        checkpoint: CheckpointPolicy {
            emergency_reserve_bytes: 0,
            ..Default::default()
        },
        // No interval checkpoints: the history is the test's alone.
        clock: Some(Arc::new(ManualClock::new())),
        ..EngineOptions::default()
    }
}

async fn attach(backing: &Arc<CrashableBacking>) -> Result<Engine, String> {
    Engine::attach(
        backing.process(),
        Arc::new(FakeCryptoProvider::new(UNIT)),
        options(),
    )
    .await
    .map_err(|e| e.to_string())
}

fn image(unit: u64, stamp: u64) -> Vec<u8> {
    (0..UNIT)
        .map(|i| (unit as u8).wrapping_mul(31) ^ (stamp as u8).wrapping_mul(7) ^ (i as u8) | 1)
        .collect()
}

fn fail_first_sync_of(backing: &CrashableBacking, needle: &'static str) -> Arc<AtomicBool> {
    let fired = Arc::new(AtomicBool::new(false));
    let once = fired.clone();
    backing.set_fault_hook(Some(Arc::new(move |op| match op {
        FaultOp::SyncData { path } if path.contains(needle) => {
            (!once.swap(true, Ordering::SeqCst)).then(|| std::io::Error::other("injected"))
        }
        _ => None,
    })));
    fired
}

fn catalog_generations(backing: &CrashableBacking) -> (Option<u64>, Option<u64>) {
    AbStore::new(layout::SHARD_CATALOG_A, layout::SHARD_CATALOG_B)
        .side_generations::<ShardCatalog>(backing)
        .unwrap()
}

/// No damage, no lost file. The first store of the catalog that names shard
/// 0 fails at its fdatasync (the write that needed the shard is refused).
/// Two restarts follow, each with FUA writes, a FLUSH and a checkpoint, all
/// acknowledged. Both recoveries accepted the page-cache copy that names the
/// shard; neither stored it again. A power loss then leaves the creation's
/// empty catalog copy: shard 0 is named by no catalog copy, although the
/// allocation maps that the same recoveries read from the page cache were
/// stored again and survive.
#[tokio::test]
async fn audit9_k01_a_catalog_copy_read_from_the_page_cache_is_never_made_durable() {
    let _serial = maki_test_support::failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), superblock()).unwrap();

    let engine = attach(&backing).await.unwrap();
    let fired = fail_first_sync_of(&backing, "shard-catalog.b");
    assert!(engine.write(UNIT as u64, &image(1, 0), true).await.is_err());
    assert!(fired.load(Ordering::SeqCst), "the catalog sync was not reached");
    backing.set_fault_hook(None);
    drop(engine);
    println!("after the failed store (page cache): catalog {:?}", catalog_generations(&backing));

    for session in 1..=2u64 {
        let engine = attach(&backing).await.unwrap();
        for unit in [1u64, 5] {
            engine
                .write(unit * UNIT as u64, &image(unit, session), true)
                .await
                .unwrap();
        }
        engine.flush().await.unwrap();
        engine.checkpoint().await.unwrap();
        drop(engine);
    }
    println!("after two acknowledged sessions (page cache): catalog {:?}", catalog_generations(&backing));

    backing.crash_all_lost();
    let (ca, cb) = catalog_generations(&backing);
    let (aa, ab) = AbStore::new(layout::shard_alloc_a(0), layout::shard_alloc_b(0))
        .side_generations::<AllocationMap>(backing.as_ref())
        .unwrap();
    println!("after the power loss: catalog a {ca:?} b {cb:?}; shard 0 allocation a {aa:?} b {ab:?}");
    assert!(
        aa.is_some() && ab.is_some(),
        "the allocation maps are stored again after a restart (K-01): both copies survive"
    );
    let catalog = AbStore::new(layout::SHARD_CATALOG_A, layout::SHARD_CATALOG_B)
        .load::<ShardCatalog>(backing.as_ref())
        .unwrap()
        .expect("a valid catalog copy");
    assert!(
        catalog.contains(0),
        "K01-CATALOG: two recoveries accepted the page-cache catalog copy that names shard 0 \
         and the writer acknowledged FUA writes, a FLUSH and two checkpoints after them, yet no \
         durable catalog copy names shard 0 (durable copies: a {ca:?} b {cb:?})"
    );
}

/// The zeros are permanent: the history of
/// `audit9_two_damaged_files_after_a_volatile_catalog_read_zeros` (a volatile
/// catalog, then damage to two files: the newest allocation copy and the
/// data file's tail). The first attach reads unit 5 as zeros and, believing
/// the shard never finished, sets the data file's size again, catalogs the
/// shard and stores its map. After a restart the shard is cataloged, full
/// size and consistent: the second attach and the deep check see nothing.
#[tokio::test]
async fn audit9_first_attach_erases_the_evidence() {
    let _serial = maki_test_support::failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    let geometry = superblock().geometry;

    let engine = attach(&backing).await.unwrap();
    let fired = fail_first_sync_of(&backing, "shard-catalog.b");
    assert!(engine.write(UNIT as u64, &image(1, 0), true).await.is_err());
    assert!(fired.load(Ordering::SeqCst));
    backing.set_fault_hook(None);
    drop(engine);

    let engine = attach(&backing).await.unwrap();
    for unit in [1u64, 5] {
        engine
            .write(unit * UNIT as u64, &image(unit, 1), true)
            .await
            .unwrap();
    }
    engine.checkpoint().await.unwrap();
    for stamp in 2..10 {
        engine.write(UNIT as u64, &image(1, stamp), true).await.unwrap();
    }
    engine.checkpoint().await.unwrap();
    drop(engine);
    backing.crash_all_lost();

    // Two damaged files.
    let (ga, gb) = AbStore::new(layout::shard_alloc_a(0), layout::shard_alloc_b(0))
        .side_generations::<AllocationMap>(backing.as_ref())
        .unwrap();
    let newest = if ga >= gb { layout::shard_alloc_a(0) } else { layout::shard_alloc_b(0) };
    let file = backing.open(&newest, false).unwrap();
    file.set_len(file.len().unwrap() - 1).unwrap();
    file.sync_data().unwrap();
    let data = backing.open(&layout::shard_data(0), false).unwrap();
    data.set_len(geometry.slot_offset(4) + 447).unwrap();
    data.sync_data().unwrap();
    drop((file, data));

    let mut violations = Vec::new();
    for attach_no in 1..=2 {
        let engine = attach(&backing).await.unwrap();
        assert_eq!(
            engine.read(UNIT as u64, UNIT as usize).await.unwrap(),
            image(1, 9)
        );
        match engine.read(5 * UNIT as u64, UNIT as usize).await {
            Err(CoreError::Corrupt(_)) | Err(CoreError::Io(_)) => {}
            Ok(bytes) if bytes.iter().all(|b| *b == 0) => {
                violations.push(format!("attach {attach_no}: unit 5 reads zeros"))
            }
            other => violations.push(format!("attach {attach_no}: unit 5: {other:?}")),
        }
        // A checkpoint, as the daemon's worker would run one.
        let _ = engine.checkpoint().await;
        drop(engine);
        let len = backing.open(&layout::shard_data(0), false).unwrap().len().unwrap();
        let cataloged = AbStore::new(layout::SHARD_CATALOG_A, layout::SHARD_CATALOG_B)
            .load::<ShardCatalog>(backing.as_ref())
            .unwrap()
            .is_some_and(|c| c.contains(0));
        let report = maki_core::check::deep_check(backing.process() as Arc<dyn Backing>, segment_size()).unwrap();
        println!(
            "after attach {attach_no}: data file {len} bytes (physical {}), cataloged {cataloged}, \
             deep check errors {:?} warnings {:?}",
            PER * geometry.slot_size,
            report.errors,
            report.warnings
        );
        if report.errors.is_empty() {
            violations.push(format!("after attach {attach_no}: the deep check reports no error"));
        }
    }
    assert!(
        violations.is_empty(),
        "EVIDENCE-ERASED: checkpointed unit 5 lost its slot to the truncation: {violations:?}"
    );
}

// ---------------------------------------------------------------------------
// Crash-only sweep of the volatile-catalog window.

#[derive(Default)]
struct UnitModel {
    /// Values a crash may expose now.
    allowed: Vec<Vec<u8>>,
    /// Writes since the last narrowing: (value, acknowledged).
    since: Vec<(Vec<u8>, bool)>,
}

struct Model {
    units: Vec<UnitModel>,
}

impl Model {
    fn new(n: u64) -> Self {
        Self {
            units: (0..n)
                .map(|_| UnitModel {
                    allowed: vec![vec![0u8; UNIT as usize]],
                    since: Vec::new(),
                })
                .collect(),
        }
    }

    fn write(&mut self, unit: u64, value: Vec<u8>, ok: bool, fua: bool) {
        let u = &mut self.units[unit as usize];
        if ok && fua {
            u.allowed = vec![value];
            u.since.clear();
        } else {
            u.allowed.push(value.clone());
            u.since.push((value, ok));
        }
    }

    fn flush(&mut self) {
        for u in &mut self.units {
            if let Some(last_ok) = u.since.iter().rposition(|(_, ok)| *ok) {
                let mut allowed = vec![u.since[last_ok].0.clone()];
                allowed.extend(u.since[last_ok + 1..].iter().map(|(v, _)| v.clone()));
                u.allowed = allowed;
                u.since.clear();
            }
        }
    }

    fn observe(&mut self, unit: u64, value: &[u8]) -> Result<(), String> {
        let u = &mut self.units[unit as usize];
        if !u.allowed.iter().any(|v| v == value) {
            return Err(format!(
                "unit {unit}: observed {:02x?}.. matches none of {} allowed value(s)",
                &value[..4],
                u.allowed.len()
            ));
        }
        u.allowed = vec![value.to_vec()];
        u.since.clear();
        Ok(())
    }
}

#[derive(Default)]
struct Totals {
    seeds: u64,
    cycles: u64,
    power_losses: u64,
    all_lost: u64,
    restarts: u64,
    injected: u64,
    catalog_failures: u64,
    adopted_after_crash: u64,
    acked_writes: u64,
    checks: u64,
    planted: u64,
}

async fn run_seed(seed: u64, totals: &mut Totals, plant: bool) -> Result<(), String> {
    let strict_model = std::env::var("AUDIT9_K01_PLANT").as_deref() == Ok("strict-model");
    let mut rng = StdRng::seed_from_u64(seed ^ 0xC47A_1060);
    let gran = [1usize, 17, 512, 4096][rng.random_range(0..4)];
    let backing = Arc::new(CrashableBacking::new().with_tearing(gran));
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    let units = SHARDS * PER;
    let mut model = Model::new(units);
    let mut history = vec![format!("seed {seed} tear {gran}")];
    let fault_rng = Arc::new(Mutex::new(StdRng::seed_from_u64(seed ^ 0xFA17)));
    let injected = Arc::new(Mutex::new(Vec::<String>::new()));
    let mut stamp = 0u64;
    for cycle in 0..6 {
        totals.cycles += 1;
        let engine = attach(&backing)
            .await
            .map_err(|e| format!("ATTACH-REFUSED cycle {cycle}: {e}\n{}", history.join("\n")))?;
        for unit in 0..units {
            let value = engine
                .read(unit * UNIT as u64, UNIT as usize)
                .await
                .map_err(|e| format!("READ-ERROR unit {unit}: {e}\n{}", history.join("\n")))?;
            model
                .observe(unit, &value)
                .map_err(|e| format!("ORACLE {e}\n{}", history.join("\n")))?;
        }
        totals.checks += 1;
        // Faults on catalog and allocation syncs and on directory syncs:
        // the catalog ones are the window under audit.
        let catalog_pm = [0u32, 300, 1000][rng.random_range(0..3)];
        let other_pm = [0u32, 50, 150][rng.random_range(0..3)];
        {
            let fault_rng = fault_rng.clone();
            let injected = injected.clone();
            backing.set_fault_hook(Some(Arc::new(move |op| {
                let (what, pm) = match op {
                    FaultOp::SyncData { path } if path.contains("shard-catalog") => {
                        (format!("sync {path}"), catalog_pm)
                    }
                    FaultOp::SyncData { path } if path.contains(".alloc.") => {
                        (format!("sync {path}"), other_pm)
                    }
                    FaultOp::SyncDir { dir } => (format!("dirsync {dir:?}"), other_pm),
                    _ => return None,
                };
                if fault_rng.lock().unwrap().random_range(0..1000) < pm {
                    injected.lock().unwrap().push(what);
                    return Some(std::io::Error::other("injected"));
                }
                None
            })));
        }
        let ops = rng.random_range(4..30);
        for _ in 0..ops {
            match rng.random_range(0..10) {
                0..=6 => {
                    // Writes favour a fresh shard now and then (a creation,
                    // i.e. a catalog store) and one hot unit (journal rolls).
                    let unit = if rng.random_bool(0.3) { 1 } else { rng.random_range(0..units) };
                    let fua = rng.random_bool(0.5);
                    stamp += 1;
                    let value = image(unit, stamp);
                    let ok = engine.write(unit * UNIT as u64, &value, fua).await.is_ok();
                    totals.acked_writes += ok as u64;
                    history.push(format!("  write unit {unit} stamp {stamp} fua {fua} -> {ok}"));
                    // Self-test `AUDIT9_K01_PLANT=strict-model`: count every
                    // acknowledged write as durable at once. Power losses
                    // legitimately drop unflushed writes, so the oracle must
                    // then report ORACLE violations.
                    model.write(unit, value, ok, fua || (ok && strict_model));
                }
                7 | 8 => {
                    let ok = engine.flush().await.is_ok();
                    history.push(format!("  flush -> {ok}"));
                    if ok {
                        model.flush();
                    }
                }
                _ => {
                    let ok = engine.checkpoint().await.is_ok();
                    history.push(format!("  checkpoint -> {ok}"));
                }
            }
            for what in injected.lock().unwrap().drain(..) {
                totals.injected += 1;
                totals.catalog_failures += what.contains("shard-catalog") as u64;
                history.push(format!("      ! fault {what}"));
            }
        }
        backing.set_fault_hook(None);
        drop(engine);
        let before = catalog_generations(&backing);
        match rng.random_range(0..10) {
            0..=3 => {
                totals.restarts += 1;
                history.push("  == restart".into());
            }
            4..=8 => {
                totals.power_losses += 1;
                backing.crash(&mut rng);
                history.push("  == power loss".into());
            }
            _ => {
                totals.all_lost += 1;
                backing.crash_all_lost();
                history.push("  == power loss, all volatile lost".into());
            }
        }
        // Count crashes after which a data file exists that the durable
        // catalog does not name (the adoption the window relies on).
        if let Some(catalog) = AbStore::new(layout::SHARD_CATALOG_A, layout::SHARD_CATALOG_B)
            .load::<ShardCatalog>(backing.as_ref())
            .unwrap()
        {
            let orphans = (0..SHARDS)
                .filter(|s| !catalog.contains(*s) && backing.exists(&layout::shard_data(*s)).unwrap())
                .count();
            if orphans > 0 {
                totals.adopted_after_crash += 1;
                history.push(format!(
                    "    {orphans} data file(s) not named by the catalog (catalog before {before:?}, after {:?})",
                    catalog_generations(&backing)
                ));
                // Self-test / variant (d): `AUDIT9_K01_PLANT=lose-orphan`
                // loses those data files (one lost file each) and ends the
                // seed after the next attach: a refused attach is the
                // required outcome, ORACLE (zeros for acknowledged data) is
                // the defect.
                if plant {
                    for s in 0..SHARDS {
                        if !catalog.contains(s) && backing.exists(&layout::shard_data(s)).unwrap() {
                            backing.remove(&layout::shard_data(s)).unwrap();
                            history.push(format!("    PLANT: lost {}", layout::shard_data(s)));
                        }
                    }
                    backing.sync_dir(layout::DATA_DIR).unwrap();
                    totals.planted += 1;
                    let engine = attach(&backing).await.map_err(|e| {
                        format!("ATTACH-REFUSED after the plant: {e}\n{}", history.join("\n"))
                    })?;
                    for unit in 0..units {
                        match engine.read(unit * UNIT as u64, UNIT as usize).await {
                            Ok(value) => model.observe(unit, &value).map_err(|e| {
                                format!("ORACLE after the plant: {e}\n{}", history.join("\n"))
                            })?,
                            Err(e) => {
                                return Err(format!("EIO after the plant: unit {unit}: {e}"))
                            }
                        }
                    }
                    return Err("PLANT-HARMLESS: every unit read back as allowed (the lost file held no acknowledged data)".into());
                }
            }
        }
    }
    totals.seeds += 1;
    Ok(())
}

/// `AUDIT9_K01_SEEDS` (default 300) and `AUDIT9_K01_SECS` (default 60)
/// bound the run; `AUDIT9_K01_START` moves the seed range.
#[tokio::test]
async fn audit9_volatile_catalog_crash_only_sweep() {
    let _serial = maki_test_support::failpoints::test_lock();
    let env = |name: &str, default: u64| {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    };
    let start = env("AUDIT9_K01_START", 0);
    let count = env("AUDIT9_K01_SEEDS", 300);
    let budget = Duration::from_secs(env("AUDIT9_K01_SECS", 60));
    let plant = std::env::var("AUDIT9_K01_PLANT").as_deref() == Ok("lose-orphan");
    let began = Instant::now();
    let mut totals = Totals::default();
    let mut failures = Vec::new();
    for seed in start..start + count {
        if began.elapsed() > budget {
            break;
        }
        if let Err(text) = run_seed(seed, &mut totals, plant).await {
            failures.push((seed, text));
        }
    }
    println!(
        "AUDIT9-K01 seeds={}..{} run={} failures={} elapsed={:.0}s cycles={} restarts={} \
         power-losses={} all-lost={} injected={} catalog-sync-failures={} \
         crashes-leaving-an-uncataloged-data-file={} acked-writes={} full-checks={}",
        start,
        start + totals.seeds,
        totals.seeds,
        failures.len(),
        began.elapsed().as_secs_f64(),
        totals.cycles,
        totals.restarts,
        totals.power_losses,
        totals.all_lost,
        totals.injected,
        totals.catalog_failures,
        totals.adopted_after_crash,
        totals.acked_writes,
        totals.checks
    );
    if plant {
        let mut classes = std::collections::BTreeMap::<String, Vec<u64>>::new();
        for (seed, text) in &failures {
            let class = text.split(':').next().unwrap_or("?").to_string();
            classes.entry(class).or_default().push(*seed);
        }
        println!("AUDIT9-K01-PLANT planted={} outcomes:", totals.planted);
        for (class, seeds) in &classes {
            println!("  {class}: {} seed(s), first {:?}", seeds.len(), &seeds[..seeds.len().min(12)]);
        }
        if let Some((seed, text)) = failures.iter().find(|(_, t)| t.starts_with("ORACLE")) {
            println!("first ORACLE seed {seed}:\n{text}");
        }
        return;
    }
    if let Some((seed, text)) = failures.first() {
        panic!(
            "{} failing seed(s) {:?}; first {seed}:\n{text}",
            failures.len(),
            failures.iter().map(|(s, _)| *s).collect::<Vec<_>>()
        );
    }
}

/// What `maki check --deep` says before the attach in the two "lost data
/// file" variants of `audit9_unproven_after_damage.rs`: (c) the newest
/// catalog copy damaged and the newest shard's data file lost (no special
/// history), and (d) the volatile-catalog history of the first test above
/// and ONE lost file. In both the shard's allocation copies, which list its
/// checkpointed units, are still on disk. A missing data file of a shard
/// the catalog names is an error (attach refuses, BUG-027); here the check
/// must report an error as well, or at least the attach must not serve
/// zeros. FAILS when the check reports no error and attach serves zeros.
#[tokio::test]
async fn audit9_lost_data_file_of_an_uncataloged_shard_is_not_reported() {
    let _serial = maki_test_support::failpoints::test_lock();
    let mut violations = Vec::new();
    for variant in ["c: damaged newest catalog copy + lost data file", "d: volatile catalog + lost data file"] {
        let backing = Arc::new(CrashableBacking::new());
        init::create_volume(backing.as_ref(), superblock()).unwrap();
        // Shard 0 first (unit 1), checkpointed, so a durable catalog copy
        // names it; then shard 1 (units 9, 13).
        let engine = attach(&backing).await.unwrap();
        engine.write(UNIT as u64, &image(1, 0), true).await.unwrap();
        engine.checkpoint().await.unwrap();
        let engine = if variant.starts_with('d') {
            // Shard 1's creation fails at the sync of the catalog copy
            // that names it (side a, generation 3); restart.
            let fired = fail_first_sync_of(&backing, "shard-catalog.a");
            assert!(engine.write(9 * UNIT as u64, &image(9, 0), true).await.is_err());
            assert!(fired.load(Ordering::SeqCst));
            backing.set_fault_hook(None);
            drop(engine);
            attach(&backing).await.unwrap()
        } else {
            engine
        };
        for unit in [9u64, 13] {
            engine
                .write(unit * UNIT as u64, &image(unit, 1), true)
                .await
                .unwrap();
        }
        engine.checkpoint().await.unwrap();
        // Later traffic goes to shard 0; the journal forgets shard 1.
        for stamp in 2..10 {
            engine.write(UNIT as u64, &image(1, stamp), true).await.unwrap();
        }
        engine.checkpoint().await.unwrap();
        drop(engine);
        backing.crash_all_lost();
        let (ca, cb) = catalog_generations(&backing);
        if variant.starts_with('c') {
            let newest = if ca >= cb { layout::SHARD_CATALOG_A } else { layout::SHARD_CATALOG_B };
            let file = backing.open(newest, false).unwrap();
            file.set_len(file.len().unwrap() - 1).unwrap();
            file.sync_data().unwrap();
        }
        backing.remove(&layout::shard_data(1)).unwrap();
        backing.sync_dir(layout::DATA_DIR).unwrap();
        let report = maki_core::check::deep_check(backing.process() as Arc<dyn Backing>, segment_size()).unwrap();
        println!(
            "variant {variant}: catalog after the power loss a {ca:?} b {cb:?}; data dir {:?}\n  deep check errors {:?}\n  warnings {:?}",
            backing.list(layout::DATA_DIR).unwrap(),
            report.errors,
            report.warnings
        );
        match attach(&backing).await {
            Err(e) => println!("  attach refused: {e}"),
            Ok(engine) => {
                for unit in [9u64, 13] {
                    match engine.read(unit * UNIT as u64, UNIT as usize).await {
                        Ok(bytes) if bytes.iter().all(|b| *b == 0) => {
                            println!("  unit {unit}: zeros");
                            if report.errors.is_empty() {
                                violations.push(format!(
                                    "{variant}: deep check reports no error and unit {unit} reads zeros"
                                ));
                            }
                        }
                        other => println!("  unit {unit}: {:?}", other.map(|b| b[..4].to_vec())),
                    }
                }
            }
        }
    }
    assert!(violations.is_empty(), "LOST-DATA-FILE-UNREPORTED: {violations:?}");
}
