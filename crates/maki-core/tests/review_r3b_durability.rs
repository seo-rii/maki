//! Review R3 follow-up: randomized multi-cycle durability sweep.
//!
//! The SPEC §54 scenarios (phase 12) fix one sequence and vary the crash.
//! This sweep varies the *sequence* too: seeded random single- and
//! multi-unit writes, FUA, FLUSH, explicit checkpoints, automatic journal
//! rolls (tiny journal), then a power loss with torn writes — or a plain
//! restart, which is *not* a power loss (K-01: recovery reads back page-cache
//! bytes, and whatever it accepts must be durable before the writer resumes,
//! because the next cycle may crash before any FLUSH). Every unit is checked
//! against the `ReferenceBlockModel` oracle after every cycle, and
//! `checkpoint_sequence ≤ durable_sequence` after every recovery.
//!
//! A second sweep injects random `fdatasync` failures (Linux semantics: the
//! dirty writes are lost) during the workload; acknowledged data must still
//! obey the oracle and a failed write may surface but never a foreign value.

// The process-global failpoint lock is held across the whole body of the
// deterministic tests (single-threaded runtime, like `review_audit2.rs`).
#![allow(clippy::await_holding_lock)]

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::Arc;

use parking_lot::Mutex;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use uuid::Uuid;

use maki_backing::Backing;
use maki_core::engine::{AttachError, Engine, EngineCacheConfig, EngineOptions};
use maki_core::error::CoreError;
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::{CrashableBacking, ReferenceBlockModel};

const UNIT: u32 = 512;
const DEVICE_UNITS: u64 = 48;
/// Tiny journal: a handful of writes roll it, so automatic rolls and
/// checkpoints happen constantly, not only when asked.
const JOURNAL_BYTES: u64 = 8 * UNIT as u64;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0x5EED),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(
            UNIT,
            UNIT,
            512,
            UNIT + 8,
            DEVICE_UNITS * UNIT as u64,
            JOURNAL_BYTES,
        )
        .unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

async fn try_attach(backing: &Arc<CrashableBacking>) -> Result<Engine, AttachError> {
    try_attach_with(backing, false).await
}

/// A deliberately tiny plaintext cache (a few units) so that hits, misses,
/// evictions and version changes all happen constantly under the sweeps.
fn cache_options(unit: u32, cache: bool) -> EngineOptions {
    EngineOptions {
        cache: cache.then(|| EngineCacheConfig {
            max_bytes: 6 * unit as u64,
            ttl: std::time::Duration::from_secs(3600),
        }),
        ..EngineOptions::default()
    }
}

async fn try_attach_with(
    backing: &Arc<CrashableBacking>,
    cache: bool,
) -> Result<Engine, AttachError> {
    if !backing.exists("superblock.a").unwrap() {
        init::create_volume(backing.as_ref(), superblock()).unwrap();
    }
    Engine::attach(
        backing.clone() as Arc<dyn Backing>,
        Arc::new(FakeCryptoProvider::new(UNIT)),
        cache_options(UNIT, cache),
    )
    .await
}

async fn attach(backing: &Arc<CrashableBacking>) -> Engine {
    try_attach(backing).await.unwrap()
}

/// Every operation of a sweep, and every injected fault, for the failure
/// report: a randomized sweep is only useful if its failure is reproducible
/// and readable.
#[derive(Default)]
struct Trace {
    ops: Vec<String>,
    faults: Arc<Mutex<Vec<String>>>,
}

impl Trace {
    fn op(&mut self, s: String) {
        self.ops.push(s);
    }
    fn report(&self) -> String {
        format!(
            "ops:\n  {}\ninjected faults:\n  {}",
            self.ops.join("\n  "),
            self.faults.lock().join("\n  ")
        )
    }
}

fn sync_fault_hook(
    seed: u64,
    permille: u32,
    faults: Arc<Mutex<Vec<String>>>,
    verbose: Option<&'static str>,
) -> maki_test_support::crash_backing::FaultHook {
    let fault_rng = Mutex::new(StdRng::seed_from_u64(seed));
    Arc::new(move |op| {
        let text = format!("{op:?}");
        if verbose.is_some_and(|needle| {
            text.contains(needle) || text.contains("catalog") || text.contains("alloc")
        }) {
            faults.lock().push(format!("  op {text}"));
        }
        match op {
            FaultOp::SyncData { .. } | FaultOp::SyncDir { .. }
                if fault_rng.lock().random_range(0..1000) < permille =>
            {
                faults.lock().push(format!("INJECTED {text}"));
                Some(io::Error::other("injected sync failure"))
            }
            _ => None,
        }
    })
}

fn off(unit: u64) -> u64 {
    unit * UNIT as u64
}

/// Unit-sized content unique to (unit, stamp) so a foreign or torn value is
/// distinguishable from any legitimate one.
fn image(unit: u64, stamp: u32) -> Vec<u8> {
    let mut v = vec![0u8; UNIT as usize];
    let seed = (unit as u32).wrapping_mul(0x9E37_79B1) ^ stamp.wrapping_mul(0x85EB_CA6B);
    for (i, b) in v.iter_mut().enumerate() {
        *b = (seed.wrapping_add(i as u32).wrapping_mul(0x2545_F491) >> 24) as u8;
    }
    v
}

#[derive(Default)]
struct Maybe {
    /// Values a failed (unacknowledged) write may have landed in a unit.
    by_unit: BTreeMap<u64, BTreeSet<Vec<u8>>>,
}

/// Compare every unit after a recovery against the oracle and adopt what
/// was observed as the new durable state.
async fn check_all(
    engine: &Engine,
    model: &mut ReferenceBlockModel,
    maybe: &mut Maybe,
    what: &str,
    history: &str,
) {
    let stats = engine.stats().await;
    assert!(
        stats.checkpoint_sequence <= stats.durable_sequence,
        "{what}: checkpoint_sequence {} > durable_sequence {}\n{history}",
        stats.checkpoint_sequence,
        stats.durable_sequence
    );
    for unit in 0..DEVICE_UNITS {
        // No damage is injected in these sweeps: every unit must be readable.
        let actual = match engine.read(off(unit), UNIT as usize).await {
            Ok(actual) => actual,
            Err(e) => panic!("{what}: unit {unit}: read failed: {e}\n{history}"),
        };
        if let Err(violation) = model.crash_adopt(unit, &actual) {
            // An unacknowledged write may or may not have landed; anything
            // else is a durability violation.
            let landed = maybe
                .by_unit
                .get(&unit)
                .is_some_and(|set| set.contains(&actual));
            assert!(landed, "{what}: {violation}\n{history}");
            model.write_fua(unit, &actual);
        }
        maybe.by_unit.remove(&unit);
    }
}

struct Cycle {
    ops: usize,
    /// `true` = power loss with torn writes; `false` = plain restart.
    power_loss: bool,
}

/// One seeded workload → crash/restart → recovery → oracle cycle set.
async fn sweep(seed: u64, cycles: usize, sync_fault_permille: u32) {
    sweep_verbose(seed, cycles, sync_fault_permille, None, false).await
}

async fn sweep_cached(seed: u64, cycles: usize, sync_fault_permille: u32) {
    sweep_verbose(seed, cycles, sync_fault_permille, None, true).await
}

async fn sweep_verbose(
    seed: u64,
    cycles: usize,
    sync_fault_permille: u32,
    verbose: Option<&'static str>,
    cache: bool,
) {
    let mut rng = StdRng::seed_from_u64(seed.wrapping_mul(0x9E37_79B9).wrapping_add(0x1234));
    let backing = Arc::new(CrashableBacking::new().with_tearing(128));
    let mut model = ReferenceBlockModel::new(UNIT as usize, DEVICE_UNITS);
    let mut maybe = Maybe::default();
    let mut stamp: u32 = 0;
    let mut trace = Trace::default();
    let mut engine = try_attach_with(&backing, cache).await.unwrap();

    // With `verbose` the hook only records the operations it is asked about
    // (a permille of 0 never injects).
    if sync_fault_permille > 0 || verbose.is_some() {
        backing.set_fault_hook(Some(sync_fault_hook(
            seed ^ 0xFA17,
            sync_fault_permille,
            trace.faults.clone(),
            verbose,
        )));
    }

    for cycle_index in 0..cycles {
        let cycle = Cycle {
            ops: rng.random_range(8..48),
            power_loss: rng.random_bool(0.7),
        };
        for _ in 0..cycle.ops {
            match rng.random_range(0..100) {
                0..=54 => {
                    let count = rng.random_range(1..=4u64);
                    let first = rng.random_range(0..DEVICE_UNITS - count + 1);
                    let fua = rng.random_bool(0.25);
                    stamp += 1;
                    let data: Vec<u8> = (first..first + count)
                        .flat_map(|u| image(u, stamp))
                        .collect();
                    let result = engine.write(off(first), &data, fua).await;
                    trace.op(format!(
                        "write units {first}..{} stamp {stamp} fua={fua} -> {:?}",
                        first + count,
                        result.as_ref().map(|_| ()).map_err(|e| e.to_string())
                    ));
                    match result {
                        Ok(()) => {
                            for u in first..first + count {
                                if fua {
                                    model.write_fua(u, &image(u, stamp));
                                } else {
                                    model.write(u, &image(u, stamp));
                                }
                            }
                        }
                        Err(e) => {
                            assert!(
                                sync_fault_permille > 0,
                                "seed {seed} cycle {cycle_index}: write failed without faults: {e}"
                            );
                            assert!(
                                matches!(e, CoreError::Io(_) | CoreError::Durability(_)),
                                "seed {seed}: unexpected error class {e}"
                            );
                            for u in first..first + count {
                                maybe.by_unit.entry(u).or_default().insert(image(u, stamp));
                            }
                        }
                    }
                }
                55..=69 => {
                    let result = engine.flush().await;
                    trace.op(format!(
                        "flush -> {:?}",
                        result.as_ref().map(|_| ()).map_err(|e| e.to_string())
                    ));
                    match result {
                        Ok(()) => model.flush(),
                        Err(e) => assert!(
                            sync_fault_permille > 0 && matches!(e, CoreError::Io(_)),
                            "seed {seed}: flush error {e}"
                        ),
                    }
                }
                70..=79 => {
                    let result = engine.checkpoint().await;
                    trace.op(format!(
                        "checkpoint -> {:?}",
                        result.as_ref().map_err(|e| e.to_string())
                    ));
                    if let Err(e) = result {
                        assert!(
                            sync_fault_permille > 0,
                            "seed {seed} cycle {cycle_index}: checkpoint failed without faults: {e}"
                        );
                    }
                }
                _ => {
                    let unit = rng.random_range(0..DEVICE_UNITS);
                    let actual = engine.read(off(unit), UNIT as usize).await.unwrap();
                    if actual != model.read(unit) {
                        // A write whose barrier failed is still journaled
                        // and published (its data may surface), so the live
                        // view may show it; from here on it behaves like an
                        // acknowledged write that the next barrier makes
                        // durable. Anything else is foreign data.
                        let landed = maybe
                            .by_unit
                            .get(&unit)
                            .is_some_and(|set| set.contains(&actual));
                        assert!(
                            landed,
                            "seed {seed} cycle {cycle_index}: live read of unit {unit} is neither \
                             the acknowledged value nor a failed write's data"
                        );
                        trace.op(format!("live read of unit {unit} shows a failed write"));
                        model.write(unit, &actual);
                    }
                }
            }
        }

        // The fault window closes with the workload: recovery itself runs on
        // a healthy device (its own fault tolerance is covered elsewhere).
        backing.set_fault_hook(None);
        drop(engine);
        let what = if cycle.power_loss {
            backing.crash(&mut rng);
            trace.op("power loss".into());
            format!("seed {seed} cycle {cycle_index} (power loss)")
        } else {
            trace.op("restart".into());
            format!("seed {seed} cycle {cycle_index} (restart)")
        };
        engine = match try_attach_with(&backing, cache).await {
            Ok(engine) => engine,
            Err(e) => panic!(
                "{what}: recovery refused the volume: {e}\n{}",
                trace.report()
            ),
        };
        check_all(&engine, &mut model, &mut maybe, &what, &trace.report()).await;

        if sync_fault_permille > 0 || verbose.is_some() {
            backing.set_fault_hook(Some(sync_fault_hook(
                seed ^ (cycle_index as u64 + 1),
                sync_fault_permille,
                trace.faults.clone(),
                verbose,
            )));
        }
    }
}

#[tokio::test]
async fn random_workloads_survive_power_loss_and_restart_cycles() {
    // Failpoints are process-global: every engine in this binary must be
    // serialized against the failpoint-using tests, or a background
    // checkpoint of another test consumes an armed failure.
    let _serial = maki_test_support::failpoints::test_lock();
    for seed in 0..120u64 {
        sweep(seed, 4, 0).await;
    }
}

#[tokio::test]
async fn random_workloads_with_sync_failures_never_show_foreign_data() {
    // Failpoints are process-global: every engine in this binary must be
    // serialized against the failpoint-using tests, or a background
    // checkpoint of another test consumes an armed failure.
    let _serial = maki_test_support::failpoints::test_lock();
    for seed in 0..80u64 {
        sweep(seed, 4, 150).await;
    }
}

/// Restart-then-power-loss with no FLUSH in between is the K-01 shape: the
/// restart's recovery must have made what it accepted durable.
#[tokio::test]
async fn restart_followed_by_power_loss_keeps_recovered_state() {
    // Failpoints are process-global: every engine in this binary must be
    // serialized against the failpoint-using tests, or a background
    // checkpoint of another test consumes an armed failure.
    let _serial = maki_test_support::failpoints::test_lock();
    for seed in 0..80u64 {
        let mut rng = StdRng::seed_from_u64(seed);
        let backing = Arc::new(CrashableBacking::new().with_tearing(128));
        let mut model = ReferenceBlockModel::new(UNIT as usize, DEVICE_UNITS);
        let mut maybe = Maybe::default();
        let engine = attach(&backing).await;
        for stamp in 1..=rng.random_range(4..24u32) {
            let unit = rng.random_range(0..DEVICE_UNITS);
            engine
                .write(off(unit), &image(unit, stamp), false)
                .await
                .unwrap();
            model.write(unit, &image(unit, stamp));
        }
        // Restart: nothing lost, but nothing proven durable either.
        drop(engine);
        let engine = attach(&backing).await;
        check_all(
            &engine,
            &mut model,
            &mut maybe,
            &format!("seed {seed} restart"),
            "",
        )
        .await;
        // Power loss with no writer activity since recovery.
        drop(engine);
        backing.crash(&mut rng);
        let engine = attach(&backing).await;
        check_all(
            &engine,
            &mut model,
            &mut maybe,
            &format!("seed {seed} power loss"),
            "",
        )
        .await;
    }
}

#[tokio::test]
#[ignore = "release gate: long randomized durability sweep"]
async fn phase_r3b_durability_gate_full() {
    // Failpoints are process-global: every engine in this binary must be
    // serialized against the failpoint-using tests, or a background
    // checkpoint of another test consumes an armed failure.
    let _serial = maki_test_support::failpoints::test_lock();
    for seed in 0..1500u64 {
        sweep(seed, 6, 0).await;
    }
    for seed in 0..600u64 {
        sweep(seed, 6, 150).await;
    }
}

/// Minimised from `random_workloads_with_sync_failures_never_show_foreign_data`
/// seed 3. An orphan shard data file (its allocation map's first sync
/// failed, then power was lost) is adopted at open with an in-memory empty
/// map. Creating *another* shard afterwards commits the in-memory catalog —
/// which now names the adopted shard — before the adopted shard's map has
/// ever reached disk. If the checkpoint then fails before allocation
/// persistence and power is lost, the catalog names a shard with no
/// allocation copy and every later attach is refused (K-03's residual: the
/// order was fixed in `persist_allocations` but not in `ensure_shard`).
#[tokio::test]
async fn adopted_shard_is_never_cataloged_by_another_shards_creation() {
    let _serial = maki_test_support::failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let engine = attach(&backing).await;
    // Units are 8 per shard here: unit 0 → shard 0, 8 → 1, 16 → 2, 24 → 3.
    engine.write(off(0), &image(0, 1), false).await.unwrap();
    engine.flush().await.unwrap();
    engine.checkpoint().await.unwrap();

    // Shard 2's allocation map can never be synced: its data file is
    // created, its map stays volatile, the catalog never names it.
    backing.set_fault_hook(Some(Arc::new(|op| match op {
        FaultOp::SyncData { path } if path.contains("shard-00000002.alloc") => {
            Some(io::Error::other("injected sync failure"))
        }
        _ => None,
    })));
    engine.write(off(16), &image(16, 1), false).await.unwrap();
    engine.flush().await.unwrap();
    engine.checkpoint().await.unwrap_err();
    // A lower shard's creation in the next attempt syncs the data
    // directory, making shard 2's data-file dirent durable; shard 2's map
    // still fails.
    engine.write(off(8), &image(8, 1), false).await.unwrap();
    engine.flush().await.unwrap();
    engine.checkpoint().await.unwrap_err();
    backing.set_fault_hook(None);
    drop(engine);
    backing.crash_all_lost();

    // Recovery adopts the orphan. A write to a new, higher shard makes the
    // next checkpoint create shard 3, whose catalog commit names shard 2
    // too; allocation persistence then fails before shard 2's map exists.
    let engine = attach(&backing).await;
    engine.write(off(24), &image(24, 2), false).await.unwrap();
    engine.flush().await.unwrap();
    {
        let _fp = maki_test_support::failpoints::fail_n_times(
            "checkpoint.alloc_store",
            1,
            io::ErrorKind::Other,
            "injected",
        );
        engine.checkpoint().await.unwrap_err();
    }
    drop(engine);
    backing.crash_all_lost();

    let engine = try_attach(&backing)
        .await
        .unwrap_or_else(|e| panic!("attach refused after an interrupted shard creation: {e}"));
    for (unit, stamp) in [(0u64, 1u32), (8, 1), (16, 1), (24, 2)] {
        assert_eq!(
            engine.read(off(unit), UNIT as usize).await.unwrap(),
            image(unit, stamp),
            "unit {unit}"
        );
    }
}

/// Minimised from the same sweep, seed 12. The orphan's allocation map is
/// *readable* after a plain restart (its sync failed, the page cache kept
/// the bytes — K-01), so open loaded it as if it were on disk and nothing
/// ever re-stored it; the next catalog commit named the shard, and the power
/// loss that followed dropped the only copy.
#[tokio::test]
async fn adopted_shards_page_cache_map_is_re_stored_before_it_is_cataloged() {
    let _serial = maki_test_support::failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let engine = attach(&backing).await;
    engine.write(off(0), &image(0, 1), false).await.unwrap();
    engine.flush().await.unwrap();
    engine.checkpoint().await.unwrap();

    backing.set_fault_hook(Some(Arc::new(|op| match op {
        FaultOp::SyncData { path } if path.contains("shard-00000005.alloc") => {
            Some(io::Error::other("injected sync failure"))
        }
        _ => None,
    })));
    engine.write(off(40), &image(40, 1), false).await.unwrap();
    engine.flush().await.unwrap();
    engine.checkpoint().await.unwrap_err();
    engine.write(off(8), &image(8, 1), false).await.unwrap();
    engine.flush().await.unwrap();
    engine.checkpoint().await.unwrap_err();
    backing.set_fault_hook(None);

    // Restart, not power loss: shard 5's volatile map is still readable.
    drop(engine);
    let engine = attach(&backing).await;
    engine.write(off(16), &image(16, 2), false).await.unwrap();
    engine.flush().await.unwrap();
    {
        let _fp = maki_test_support::failpoints::fail_n_times(
            "checkpoint.alloc_store",
            1,
            io::ErrorKind::Other,
            "injected",
        );
        engine.checkpoint().await.unwrap_err();
    }
    drop(engine);
    backing.crash_all_lost();

    let engine = try_attach(&backing)
        .await
        .unwrap_or_else(|e| panic!("attach refused after a restart adopted an orphan: {e}"));
    for (unit, stamp) in [(0u64, 1u32), (8, 1), (16, 2), (40, 1)] {
        assert_eq!(
            engine.read(off(unit), UNIT as usize).await.unwrap(),
            image(unit, stamp),
            "unit {unit}"
        );
    }
}

/// Minimised from `phase_r3b_durability_gate_full` (seed 388, sync faults).
/// A shard's creation failed at its very first step — the sync of the
/// freshly sized data file — and the process then *restarted* rather than
/// losing power (K-01): the page cache still showed the full size the disk
/// never got. The adopted shard was taken at face value, the next checkpoint
/// wrote its slots and cataloged it, and the power loss after that left a
/// data file ending at the last written slot. Read as truncation, that
/// marked every later slot allocated: never-written units read EIO.
#[tokio::test]
async fn adopted_shards_data_file_size_is_re_proven_after_a_failed_sync_and_restart() {
    let _serial = maki_test_support::failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let engine = attach(&backing).await;
    let geometry = superblock().geometry;
    let physical = geometry.units_per_shard() * geometry.slot_size;
    let path = maki_format::layout::shard_data(0);
    engine.write(off(1), &image(1, 1), false).await.unwrap();
    engine.flush().await.unwrap();

    let target = path.clone();
    backing.set_fault_hook(Some(Arc::new(move |op| match op {
        FaultOp::SyncData { path } if *path == target => {
            Some(io::Error::other("injected sync failure"))
        }
        _ => None,
    })));
    engine.checkpoint().await.unwrap_err();
    backing.set_fault_hook(None);

    // Restart, not power loss: the page cache still shows the full size.
    drop(engine);
    let engine = attach(&backing).await;
    assert_eq!(backing.open(&path, false).unwrap().len().unwrap(), physical);
    engine.write(off(3), &image(3, 1), false).await.unwrap();
    engine.flush().await.unwrap();
    engine.checkpoint().await.unwrap();
    drop(engine);
    backing.crash_all_lost();

    let engine = attach(&backing).await;
    assert_eq!(
        backing.open(&path, false).unwrap().len().unwrap(),
        physical,
        "the size was proven again before the shard was written to"
    );
    assert_eq!(engine.read(off(1), UNIT as usize).await.unwrap(), image(1, 1));
    assert_eq!(engine.read(off(3), UNIT as usize).await.unwrap(), image(3, 1));
    assert_eq!(
        engine.read(off(6), UNIT as usize).await.unwrap(),
        vec![0u8; UNIT as usize],
        "a never-written unit of the shard is a hole, not damage"
    );
}

// ---------------------------------------------------------------------------
// Concurrent, partial-unit (read-modify-write) workloads.
//
// The sweeps above write whole units from one task. Real NBD traffic writes
// 512-byte blocks inside 4 KiB crypto units from many callbacks at once, so
// this sweep hands each writer task its own contiguous unit range, lets it
// issue block-aligned sub-unit and multi-unit writes (FUA or not) and live
// reads, while the main task issues FLUSH and checkpoints concurrently, then
// cuts power or restarts and checks every unit against the oracle.

const BIG_UNIT: u32 = 4096;
const BLOCK: u64 = 512;
const WRITERS: u64 = 4;
const UNITS_PER_WRITER: u64 = 12;

fn big_superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xB16),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(
            BLOCK as u32,
            BIG_UNIT,
            512,
            BIG_UNIT + 8,
            DEVICE_UNITS * BIG_UNIT as u64,
            8 * BIG_UNIT as u64,
        )
        .unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

async fn attach_big(backing: &Arc<CrashableBacking>, cache: bool) -> Arc<Engine> {
    if !backing.exists("superblock.a").unwrap() {
        init::create_volume(backing.as_ref(), big_superblock()).unwrap();
    }
    Arc::new(
        Engine::attach(
            backing.clone() as Arc<dyn Backing>,
            Arc::new(FakeCryptoProvider::new(BIG_UNIT)),
            cache_options(BIG_UNIT, cache),
        )
        .await
        .unwrap(),
    )
}

/// What a writer task acknowledged, in order, for the main task's model.
enum Ack {
    Write { unit: u64, data: Vec<u8>, fua: bool },
}

async fn writer_task(
    engine: Arc<Engine>,
    seed: u64,
    first_unit: u64,
    initial: BTreeMap<u64, Vec<u8>>,
    acks: tokio::sync::mpsc::UnboundedSender<Ack>,
) {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut expected = initial;
    let last_unit = first_unit + UNITS_PER_WRITER;
    let unit = BIG_UNIT as u64;
    for step in 0..rng.random_range(10..40u32) {
        if rng.random_bool(0.8) {
            // Block-aligned range inside this task's units, up to 1.5 units.
            let start_unit = rng.random_range(first_unit..last_unit);
            let start = start_unit * unit + rng.random_range(0..unit / BLOCK) * BLOCK;
            let max_len = (last_unit * unit - start).min(unit + unit / 2);
            let len = rng.random_range(1..=max_len / BLOCK) * BLOCK;
            let stamp = (seed as u32).wrapping_mul(1000).wrapping_add(step);
            let data: Vec<u8> = (0..len)
                .map(|i| (stamp.wrapping_mul(0x9E37_79B1) ^ (i as u32)).to_le_bytes()[1])
                .collect();
            let fua = rng.random_bool(0.25);
            engine.write(start, &data, fua).await.unwrap();
            // Compose the acknowledged unit images.
            let first = start / unit;
            let last = (start + len - 1) / unit;
            for u in first..=last {
                let image = expected
                    .entry(u)
                    .or_insert_with(|| vec![0u8; unit as usize]);
                let unit_start = u * unit;
                let from = start.max(unit_start) - unit_start;
                let to = (start + len).min(unit_start + unit) - unit_start;
                let src = start.max(unit_start) - start;
                image[from as usize..to as usize]
                    .copy_from_slice(&data[src as usize..src as usize + (to - from) as usize]);
                let _ = acks.send(Ack::Write {
                    unit: u,
                    data: image.clone(),
                    fua,
                });
            }
        } else {
            // Live read of a block range this task owns: must equal what it
            // acknowledged (nobody else writes these units).
            let u = rng.random_range(first_unit..last_unit);
            let block = rng.random_range(0..unit / BLOCK);
            let got = engine
                .read(u * unit + block * BLOCK, BLOCK as usize)
                .await
                .unwrap();
            let want = expected
                .get(&u)
                .map(|img| img[(block * BLOCK) as usize..((block + 1) * BLOCK) as usize].to_vec())
                .unwrap_or_else(|| vec![0u8; BLOCK as usize]);
            assert_eq!(
                got, want,
                "writer {seed}: live block read of unit {u} block {block}"
            );
        }
        tokio::task::yield_now().await;
    }
}

async fn concurrent_sweep(seed: u64, cycles: usize, cache: bool) {
    let mut rng = StdRng::seed_from_u64(seed ^ 0xC0DE);
    let backing = Arc::new(CrashableBacking::new().with_tearing(256));
    let mut model = ReferenceBlockModel::new(BIG_UNIT as usize, DEVICE_UNITS);
    let mut maybe = Maybe::default();
    let mut engine = attach_big(&backing, cache).await;

    for cycle in 0..cycles {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut tasks = Vec::new();
        for w in 0..WRITERS {
            let first_unit = w * UNITS_PER_WRITER;
            let initial: BTreeMap<u64, Vec<u8>> = (first_unit..first_unit + UNITS_PER_WRITER)
                .map(|u| (u, model.read(u)))
                .collect();
            tasks.push(tokio::spawn(writer_task(
                engine.clone(),
                seed * 100 + cycle as u64 * 10 + w,
                first_unit,
                initial,
                tx.clone(),
            )));
        }
        drop(tx);
        // Barriers race the writers: a FLUSH covers what was acknowledged
        // before it started; whatever is acknowledged afterwards stays
        // pending in the model (the engine may make it durable too, which
        // the oracle allows).
        let apply = |model: &mut ReferenceBlockModel,
                     rx: &mut tokio::sync::mpsc::UnboundedReceiver<Ack>| {
            while let Ok(Ack::Write { unit, data, fua }) = rx.try_recv() {
                if fua {
                    model.write_fua(unit, &data);
                } else {
                    model.write(unit, &data);
                }
            }
        };
        for _ in 0..rng.random_range(1..4) {
            tokio::task::yield_now().await;
            apply(&mut model, &mut rx);
            if rng.random_bool(0.7) {
                engine.flush().await.unwrap();
                model.flush();
            } else {
                engine.checkpoint().await.unwrap();
            }
        }
        for task in tasks {
            task.await.unwrap();
        }
        apply(&mut model, &mut rx);

        drop(engine);
        let what = if rng.random_bool(0.7) {
            backing.crash(&mut rng);
            format!("seed {seed} cycle {cycle} (power loss)")
        } else {
            format!("seed {seed} cycle {cycle} (restart)")
        };
        engine = attach_big(&backing, cache).await;
        let stats = engine.stats().await;
        assert!(
            stats.checkpoint_sequence <= stats.durable_sequence,
            "{what}"
        );
        for unit in 0..DEVICE_UNITS {
            let actual = engine
                .read(unit * BIG_UNIT as u64, BIG_UNIT as usize)
                .await
                .unwrap();
            if let Err(violation) = model.crash_adopt(unit, &actual) {
                panic!("{what}: {violation}");
            }
        }
        maybe.by_unit.clear();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_partial_unit_workloads_survive_power_loss_and_restart() {
    // Failpoints are process-global: every engine in this binary must be
    // serialized against the failpoint-using tests, or a background
    // checkpoint of another test consumes an armed failure.
    let _serial = maki_test_support::failpoints::test_lock();
    for seed in 0..24u64 {
        concurrent_sweep(seed, 3, false).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "release gate: long concurrent partial-unit durability sweep"]
async fn phase_r3b_concurrent_gate_full() {
    // Failpoints are process-global: every engine in this binary must be
    // serialized against the failpoint-using tests, or a background
    // checkpoint of another test consumes an armed failure.
    let _serial = maki_test_support::failpoints::test_lock();
    for seed in 0..300u64 {
        concurrent_sweep(seed, 4, false).await;
    }
    for seed in 0..150u64 {
        concurrent_sweep(seed, 4, true).await;
    }
}

// ---------------------------------------------------------------------------
// The same sweeps with the versioned plaintext cache enabled (a tiny one, so
// eviction and version turnover are constant): a stale or mis-keyed cache
// entry shows up as a live read that disagrees with the acknowledged value.

#[tokio::test]
async fn random_workloads_with_a_plaintext_cache_survive_power_loss_and_restart() {
    // Failpoints are process-global: every engine in this binary must be
    // serialized against the failpoint-using tests, or a background
    // checkpoint of another test consumes an armed failure.
    let _serial = maki_test_support::failpoints::test_lock();
    for seed in 0..60u64 {
        sweep_cached(seed, 4, 0).await;
    }
}

#[tokio::test]
async fn random_workloads_with_a_plaintext_cache_and_sync_failures_never_show_foreign_data() {
    // Failpoints are process-global: every engine in this binary must be
    // serialized against the failpoint-using tests, or a background
    // checkpoint of another test consumes an armed failure.
    let _serial = maki_test_support::failpoints::test_lock();
    for seed in 0..40u64 {
        sweep_cached(seed, 4, 150).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_partial_unit_workloads_with_a_plaintext_cache() {
    // Failpoints are process-global: every engine in this binary must be
    // serialized against the failpoint-using tests, or a background
    // checkpoint of another test consumes an armed failure.
    let _serial = maki_test_support::failpoints::test_lock();
    for seed in 0..12u64 {
        concurrent_sweep(seed, 3, true).await;
    }
}

// ---------------------------------------------------------------------------
// Media damage after a power loss. `review_corruption.rs` damages exactly one
// file of a healthy volume and demands full data; this sweep damages one to
// three files of a volume that just lost power (so A/B redundancy may already
// be down to one copy) and repeats over cycles. The invariant it checks is the
// weakest one that must never break: recovery either refuses the volume with
// an error (never a panic), or every unit reads as an acknowledged value or
// EIO — never foreign data, never zeros for a written unit.

fn damage_candidates(backing: &CrashableBacking) -> Vec<String> {
    let mut out = Vec::new();
    for dir in ["", "data", "journal", "checkpoint"] {
        if let Ok(names) = backing.list(dir) {
            for name in names {
                let path = if dir.is_empty() {
                    name
                } else {
                    format!("{dir}/{name}")
                };
                // Files only: the root listing also names the directories.
                if backing.open(&path, false).is_ok() {
                    out.push(path);
                }
            }
        }
    }
    out.sort();
    out
}

fn damage(backing: &CrashableBacking, path: &str, rng: &mut StdRng) -> String {
    let file = backing.open(path, false).unwrap();
    let len = file.len().unwrap();
    if len == 0 {
        file.write_at(0, &[rng.random::<u8>() | 1]).unwrap();
        file.sync_data().unwrap();
        return format!("{path}: append one byte to empty file");
    }
    let what = match rng.random_range(0..3u32) {
        0 => {
            let n = rng.random_range(1..=8usize).min(len as usize);
            let mut offsets = BTreeSet::new();
            while offsets.len() < n {
                offsets.insert(rng.random_range(0..len));
            }
            for o in &offsets {
                let mut b = [0u8; 1];
                file.read_at(*o, &mut b).unwrap();
                b[0] ^= 1 << rng.random_range(0..8);
                file.write_at(*o, &b).unwrap();
            }
            format!("flip {n} bit(s) at {offsets:?}")
        }
        1 => {
            let keep = rng.random_range(0..len);
            file.set_len(keep).unwrap();
            format!("truncate {len} -> {keep}")
        }
        _ => {
            let start = rng.random_range(0..len);
            let n = (len - start).min(64);
            file.write_at(start, &vec![0u8; n as usize]).unwrap();
            format!("zero {n} bytes at {start}")
        }
    };
    file.sync_data().unwrap();
    format!("{path}: {what}")
}

/// On-disk state around one unit, for a failure report: every file with
/// its length, both catalog and allocation-map generations, the unit's
/// allocation bit in each readable copy and the first bytes of its slot.
fn dump_state(backing: &CrashableBacking, geometry: &Geometry, unit: u64) -> String {
    use maki_format::ab::AbStore;
    use maki_format::allocation::AllocationMap;
    use maki_format::layout;
    use maki_format::catalog::ShardCatalog;
    let mut out = Vec::new();
    for path in damage_candidates(backing) {
        let len = backing.open(&path, false).unwrap().len().unwrap();
        out.push(format!("  {path}: {len} bytes"));
    }
    let catalog = AbStore::new(layout::SHARD_CATALOG_A, layout::SHARD_CATALOG_B);
    out.push(format!(
        "  catalog generations: {:?}",
        catalog.side_generations::<ShardCatalog>(backing)
    ));
    let (shard_idx, in_shard) = geometry.shard_of_unit(unit);
    let alloc = AbStore::new(
        layout::shard_alloc_a(shard_idx),
        layout::shard_alloc_b(shard_idx),
    );
    out.push(format!(
        "  shard {shard_idx} alloc generations: {:?}",
        alloc.side_generations::<AllocationMap>(backing)
    ));
    for path in [
        layout::shard_alloc_a(shard_idx),
        layout::shard_alloc_b(shard_idx),
    ] {
        let bit = backing
            .open(&path, false)
            .ok()
            .and_then(|f| {
                let mut bytes = vec![0u8; f.len().ok()? as usize];
                f.read_at(0, &mut bytes).ok()?;
                AllocationMap::decode(&bytes).ok()
            })
            .map(|m| m.get(in_shard));
        out.push(format!("  {path}: bit for unit {unit} = {bit:?}"));
    }
    if let Ok(data) = backing.open(&layout::shard_data(shard_idx), false) {
        let offset = geometry.slot_offset(in_shard);
        let mut head = [0u8; 16];
        let slot = match data.read_at(offset, &mut head) {
            Ok(()) => format!("{head:02x?}"),
            Err(e) => format!("unreadable: {e}"),
        };
        out.push(format!("  slot of unit {unit} at {offset}: {slot}"));
    }
    out.join("\n")
}

/// Returns whether the volume could still be attached after the damage.
async fn damage_sweep(seed: u64, cycles: usize) -> bool {
    let mut rng = StdRng::seed_from_u64(seed ^ 0xDA3A);
    let backing = Arc::new(CrashableBacking::new().with_tearing(128));
    let geometry = superblock().geometry;
    let mut model = ReferenceBlockModel::new(UNIT as usize, DEVICE_UNITS);
    let mut maybe = Maybe::default();
    let mut stamp: u32 = 0;
    // Every operation, crash and damage, so that a violation reads as a
    // story rather than a seed.
    let mut log: Vec<String> = Vec::new();
    let mut engine = attach(&backing).await;

    for cycle in 0..cycles {
        for _ in 0..rng.random_range(8..40) {
            match rng.random_range(0..100) {
                0..=59 => {
                    let count = rng.random_range(1..=3u64);
                    let first = rng.random_range(0..DEVICE_UNITS - count + 1);
                    let fua = rng.random_bool(0.25);
                    stamp += 1;
                    let data: Vec<u8> = (first..first + count)
                        .flat_map(|u| image(u, stamp))
                        .collect();
                    let tag = format!(
                        "write {first}..{} stamp {stamp}{}",
                        first + count,
                        if fua { " fua" } else { "" }
                    );
                    match engine.write(off(first), &data, fua).await {
                        Ok(()) => {
                            log.push(tag);
                            for u in first..first + count {
                                if fua {
                                    model.write_fua(u, &image(u, stamp));
                                } else {
                                    model.write(u, &image(u, stamp));
                                }
                            }
                        }
                        // A damaged volume may refuse writes (EIO); the data
                        // may or may not have landed.
                        Err(e) => {
                            log.push(format!("{tag} refused: {e}"));
                            for u in first..first + count {
                                maybe.by_unit.entry(u).or_default().insert(image(u, stamp));
                            }
                        }
                    }
                }
                60..=79 => match engine.flush().await {
                    Ok(()) => {
                        log.push("flush".to_string());
                        model.flush();
                    }
                    Err(e) => log.push(format!("flush refused: {e}")),
                },
                _ => match engine.checkpoint().await {
                    Ok(_) => log.push("checkpoint".to_string()),
                    Err(e) => log.push(format!("checkpoint refused: {e}")),
                },
            }
        }

        drop(engine);
        backing.crash(&mut rng);
        log.push(format!("-- power loss, end of cycle {cycle} --"));
        let candidates = damage_candidates(&backing);
        let mut journal_damaged = false;
        for _ in 0..rng.random_range(1..=3usize) {
            let path = candidates[rng.random_range(0..candidates.len())].clone();
            journal_damaged |= path.starts_with("journal/");
            log.push(format!("DAMAGE {}", damage(&backing, &path, &mut rng)));
        }

        // The checker must never panic on damaged input.
        let _ = maki_core::check::deep_check(backing.clone() as Arc<dyn Backing>, 256 << 20);

        engine = match try_attach(&backing).await {
            Ok(engine) => engine,
            Err(_refused) => return false,
        };
        let stats = engine.stats().await;
        assert!(
            stats.checkpoint_sequence <= stats.durable_sequence,
            "seed {seed} cycle {cycle}: checkpoint ran ahead of durability\n{}",
            log.join("\n")
        );
        for unit in 0..DEVICE_UNITS {
            match engine.read(off(unit), UNIT as usize).await {
                Ok(actual) => {
                    if let Err(violation) = model.crash_adopt(unit, &actual) {
                        let landed = maybe
                            .by_unit
                            .get(&unit)
                            .is_some_and(|set| set.contains(&actual));
                        // Documented limitation (S-04): the durable mark is
                        // a plain write and is usually lost in the crash, so
                        // damage inside the final segment's synced records
                        // is truncated as a torn tail and a FLUSH-acknowledged
                        // write can revert to its previous durable value.
                        // Only journal damage may explain a violation here.
                        assert!(
                            landed || journal_damaged,
                            "seed {seed} cycle {cycle}: {violation}\nhistory:\n  {}\nstate:\n{}",
                            log.join("\n  "),
                            dump_state(&backing, &geometry, unit)
                        );
                        model.write_fua(unit, &actual);
                    }
                    maybe.by_unit.remove(&unit);
                }
                Err(CoreError::Corrupt(_)) | Err(CoreError::Io(_)) => {
                    // EIO: the unit keeps its allowed set for later cycles.
                }
                Err(e) => panic!(
                    "seed {seed} cycle {cycle}: unit {unit}: unexpected error class {e}\n{}",
                    log.join("\n")
                ),
            }
        }
    }
    true
}

#[tokio::test]
async fn media_damage_after_power_loss_never_yields_foreign_data() {
    // Failpoints are process-global: every engine in this binary must be
    // serialized against the failpoint-using tests, or a background
    // checkpoint of another test consumes an armed failure.
    let _serial = maki_test_support::failpoints::test_lock();
    let mut attached = 0;
    for seed in 0..80u64 {
        if damage_sweep(seed, 3).await {
            attached += 1;
        }
    }
    assert!(attached > 0, "every damaged volume was refused; the sweep proves nothing");
}

#[tokio::test]
#[ignore = "release gate: long media-damage sweep"]
async fn phase_r3b_media_damage_gate_full() {
    // Failpoints are process-global: every engine in this binary must be
    // serialized against the failpoint-using tests, or a background
    // checkpoint of another test consumes an armed failure.
    let _serial = maki_test_support::failpoints::test_lock();
    for seed in 0..800u64 {
        damage_sweep(seed, 4).await;
    }
}

/// Minimised from `media_damage_after_power_loss_never_yields_foreign_data`
/// seed 16. A checkpointed unit whose newest allocation-map copy is lost
/// *and* whose slot header is damaged (not zeroed — partly overwritten) used
/// to read as zeros: the older map copy does not list it, and the header
/// probe treated any undecodable header as "unwritten". Only an all-zero
/// header is unwritten; anything else on a cleared slot is damage ⇒ EIO
/// (SPEC §12: allocated-but-invalid is never zeros).
#[tokio::test]
async fn damaged_header_on_a_cleared_slot_is_eio_not_zeros() {
    // Failpoints are process-global: every engine in this binary must be
    // serialized against the failpoint-using tests, or a background
    // checkpoint of another test consumes an armed failure.
    let _serial = maki_test_support::failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let engine = attach(&backing).await;
    let geometry = superblock().geometry;
    // Two checkpoints so the shard's allocation map has two generations:
    // the older lists unit 17 only, the newer lists 17 and 19.
    engine.write(off(17), &image(17, 1), true).await.unwrap();
    engine.checkpoint().await.unwrap();
    engine.write(off(19), &image(19, 1), true).await.unwrap();
    engine.checkpoint().await.unwrap();
    // A never-written neighbour stays a genuine hole.
    assert_eq!(
        engine.read(off(21), UNIT as usize).await.unwrap(),
        vec![0u8; UNIT as usize]
    );
    drop(engine);

    let (shard_idx, in_shard) = geometry.shard_of_unit(19);
    let alloc = maki_format::ab::AbStore::new(
        maki_format::layout::shard_alloc_a(shard_idx),
        maki_format::layout::shard_alloc_b(shard_idx),
    );
    let (gen_a, gen_b) = alloc
        .side_generations::<maki_format::allocation::AllocationMap>(backing.as_ref())
        .unwrap();
    let newest = if gen_a >= gen_b {
        maki_format::layout::shard_alloc_a(shard_idx)
    } else {
        maki_format::layout::shard_alloc_b(shard_idx)
    };
    let file = backing.open(&newest, false).unwrap();
    file.set_len(file.len().unwrap() - 1).unwrap();
    file.sync_data().unwrap();
    // Partly overwrite unit 19's slot header: garbage, not a hole.
    let data = backing
        .open(&maki_format::layout::shard_data(shard_idx), false)
        .unwrap();
    data.write_at(geometry.slot_offset(in_shard), &[0u8; 54]).unwrap();
    data.sync_data().unwrap();

    let engine = attach(&backing).await;
    assert_eq!(engine.read(off(17), UNIT as usize).await.unwrap(), image(17, 1));
    assert_eq!(
        engine.read(off(21), UNIT as usize).await.unwrap(),
        vec![0u8; UNIT as usize],
        "a genuine hole still reads as zeros"
    );
    match engine.read(off(19), UNIT as usize).await {
        Ok(actual) => panic!(
            "damaged checkpointed unit read as data: first bytes {:?}",
            &actual[..8]
        ),
        Err(CoreError::Corrupt(_)) | Err(CoreError::Io(_)) => {}
        Err(e) => panic!("unexpected error class {e}"),
    }
}

/// Minimised from the media-damage gate (seed 170). A shard data file is
/// created at its full sparse size before use, so a file that ends before a
/// slot was truncated. A checkpointed unit beyond the truncation point,
/// whose newest allocation copy was lost too, used to read as zeros.
#[tokio::test]
async fn truncated_shard_file_reads_eio_for_units_beyond_its_end_not_zeros() {
    let _serial = maki_test_support::failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let engine = attach(&backing).await;
    let geometry = superblock().geometry;
    engine.write(off(1), &image(1, 1), true).await.unwrap();
    engine.checkpoint().await.unwrap();
    engine.write(off(6), &image(6, 1), true).await.unwrap();
    engine.checkpoint().await.unwrap();
    drop(engine);

    let (shard_idx, in_shard) = geometry.shard_of_unit(6);
    let alloc = maki_format::ab::AbStore::new(
        maki_format::layout::shard_alloc_a(shard_idx),
        maki_format::layout::shard_alloc_b(shard_idx),
    );
    let (gen_a, gen_b) = alloc
        .side_generations::<maki_format::allocation::AllocationMap>(backing.as_ref())
        .unwrap();
    let newest = if gen_a >= gen_b {
        maki_format::layout::shard_alloc_a(shard_idx)
    } else {
        maki_format::layout::shard_alloc_b(shard_idx)
    };
    let file = backing.open(&newest, false).unwrap();
    file.set_len(file.len().unwrap() - 1).unwrap();
    file.sync_data().unwrap();
    let data = backing
        .open(&maki_format::layout::shard_data(shard_idx), false)
        .unwrap();
    data.set_len(geometry.slot_offset(in_shard) - 7).unwrap();
    data.sync_data().unwrap();

    let engine = attach(&backing).await;
    assert_eq!(engine.read(off(1), UNIT as usize).await.unwrap(), image(1, 1));
    match engine.read(off(6), UNIT as usize).await {
        Ok(actual) => panic!(
            "unit beyond a truncated shard file read as data: first bytes {:?}",
            &actual[..8]
        ),
        Err(CoreError::Corrupt(_)) | Err(CoreError::Io(_)) => {}
        Err(e) => panic!("unexpected error class {e}"),
    }
}

/// Minimised from the media-damage gate (seed 58). After a shard data file
/// was truncated, the volume kept running: a checkpoint wrote a *later* slot
/// of the same shard, which grew the file back and zero-filled the slots in
/// between. A checkpointed unit in that range whose newest allocation copy
/// had been lost then read as **zeros** (all-zero header on a cleared bit),
/// although the attach right after the truncation had still reported EIO.
/// The damage must be recorded before the file grows: such slots are marked
/// allocated at open and stay EIO until rewritten, across power loss.
#[tokio::test]
async fn truncation_damage_survives_the_file_growing_back() {
    let _serial = maki_test_support::failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let engine = attach(&backing).await;
    let geometry = superblock().geometry;
    engine.write(off(1), &image(1, 1), true).await.unwrap();
    engine.checkpoint().await.unwrap();
    engine.write(off(5), &image(5, 1), true).await.unwrap();
    engine.checkpoint().await.unwrap();
    drop(engine);

    let (shard_idx, in_shard) = geometry.shard_of_unit(5);
    let alloc = maki_format::ab::AbStore::new(
        maki_format::layout::shard_alloc_a(shard_idx),
        maki_format::layout::shard_alloc_b(shard_idx),
    );
    let (gen_a, gen_b) = alloc
        .side_generations::<maki_format::allocation::AllocationMap>(backing.as_ref())
        .unwrap();
    let newest = if gen_a >= gen_b {
        maki_format::layout::shard_alloc_a(shard_idx)
    } else {
        maki_format::layout::shard_alloc_b(shard_idx)
    };
    let file = backing.open(&newest, false).unwrap();
    file.set_len(file.len().unwrap() - 1).unwrap();
    file.sync_data().unwrap();
    let path = maki_format::layout::shard_data(shard_idx);
    let data = backing.open(&path, false).unwrap();
    // Cut inside slot 4: slots 5..7 are gone entirely.
    data.set_len(geometry.slot_offset(in_shard - 1) + 447).unwrap();
    data.sync_data().unwrap();

    let expect_eio = |unit: u64, result: Result<Vec<u8>, CoreError>, when: &str| match result {
        Ok(actual) => panic!(
            "unit {unit} {when}: read as data, first bytes {:?}",
            &actual[..8]
        ),
        Err(CoreError::Corrupt(_)) | Err(CoreError::Io(_)) => {}
        Err(e) => panic!("unit {unit} {when}: unexpected error class {e}"),
    };

    let engine = attach(&backing).await;
    assert_eq!(engine.read(off(1), UNIT as usize).await.unwrap(), image(1, 1));
    expect_eio(5, engine.read(off(5), UNIT as usize).await, "after the truncation");
    // A later slot of the same shard is checkpointed: the file grows back
    // past unit 5's slot, which is now all zeros.
    engine.write(off(7), &image(7, 1), true).await.unwrap();
    engine.checkpoint().await.unwrap();
    assert_eq!(
        data.len().unwrap(),
        geometry.units_per_shard() * geometry.slot_size,
        "the file is restored to its physical size before the slot write"
    );
    expect_eio(5, engine.read(off(5), UNIT as usize).await, "after the file grew back");
    drop(engine);
    backing.crash_all_lost();

    let engine = attach(&backing).await;
    assert_eq!(engine.read(off(1), UNIT as usize).await.unwrap(), image(1, 1));
    assert_eq!(engine.read(off(7), UNIT as usize).await.unwrap(), image(7, 1));
    expect_eio(5, engine.read(off(5), UNIT as usize).await, "after power loss");
    // Beyond the cut nothing can be told apart from a removed slot: a unit
    // never written there is EIO too, until it is rewritten.
    expect_eio(6, engine.read(off(6), UNIT as usize).await, "after power loss");
    assert_eq!(
        engine.read(off(2), UNIT as usize).await.unwrap(),
        vec![0u8; UNIT as usize],
        "a hole below the cut is still a hole"
    );
    // Rewriting heals the slot.
    engine.write(off(5), &image(5, 2), true).await.unwrap();
    engine.checkpoint().await.unwrap();
    drop(engine);
    let engine = attach(&backing).await;
    assert_eq!(engine.read(off(5), UNIT as usize).await.unwrap(), image(5, 2));
}

/// The flip side of the truncation rule. A shard data file is created and
/// sized before its allocation map is stored and before the catalog names
/// it; a power loss (or a failed sync, then a crash) in that window leaves
/// a zero-length orphan data file with no allocation copy at all. That shard
/// never finished creation and none of its slots was ever written, so
/// adopting it must not turn every unit of the shard into EIO: the size is
/// restored at open, its holes stay holes, and it is usable afterwards.
#[tokio::test]
async fn zero_length_orphan_shard_without_a_map_is_unwritten_not_damaged() {
    let _serial = maki_test_support::failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    // A first attach establishes the key canary, as on any real volume;
    // no write happens, so no shard exists yet.
    drop(attach(&backing).await);
    let path = maki_format::layout::shard_data(0);
    let orphan = backing.open(&path, true).unwrap();
    assert_eq!(orphan.len().unwrap(), 0);
    backing.sync_dir(maki_format::layout::DATA_DIR).unwrap();
    drop(orphan);

    never_finished_shard_reads_as_holes(&backing, &path).await;
}

/// Minimised from `phase_r3b_durability_gate_full` (seed 95, no faults).
/// A shard's creation was interrupted after its empty allocation map was
/// stored but before the data directory was synced: the crash kept the map
/// copy and dropped the never-dir-synced data file. The next attempt
/// re-created the file, and a second crash before its `set_len` was synced
/// left it at zero length — next to the stale, empty allocation copy. Taking
/// that copy as proof of a finished creation classified the file as
/// truncated and marked all eight slots allocated: every unit of the shard
/// read EIO after a plain restart.
#[tokio::test]
async fn zero_length_orphan_shard_with_a_stale_empty_map_is_unwritten_not_damaged() {
    let _serial = maki_test_support::failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    drop(attach(&backing).await);
    let geometry = superblock().geometry;
    let alloc = maki_format::ab::AbStore::new(
        maki_format::layout::shard_alloc_a(0),
        maki_format::layout::shard_alloc_b(0),
    );
    let mut empty = maki_format::allocation::AllocationMap::new(geometry.units_per_shard());
    alloc.store(backing.as_ref(), &mut empty).unwrap();
    let path = maki_format::layout::shard_data(0);
    drop(backing.open(&path, true).unwrap());
    backing.sync_dir(maki_format::layout::DATA_DIR).unwrap();

    never_finished_shard_reads_as_holes(&backing, &path).await;
}

/// Shard 0 exists only as a zero-length orphan data file: every unit reads
/// as zeros, the file is sized before its first slot write, and the shard
/// serves data across a power loss afterwards.
async fn never_finished_shard_reads_as_holes(backing: &Arc<CrashableBacking>, path: &str) {
    let geometry = superblock().geometry;
    let engine = attach(backing).await;
    for unit in [0u64, 3, 7] {
        assert_eq!(
            engine.read(off(unit), UNIT as usize).await.unwrap(),
            vec![0u8; UNIT as usize],
            "unit {unit} of a never-finished shard is a hole"
        );
    }
    engine.write(off(3), &image(3, 1), true).await.unwrap();
    engine.checkpoint().await.unwrap();
    let physical = geometry.units_per_shard() * geometry.slot_size;
    assert_eq!(
        backing.open(path, false).unwrap().len().unwrap(),
        physical,
        "the data file is restored to its sparse size before the first slot write"
    );
    drop(engine);
    backing.crash_all_lost();

    let engine = attach(backing).await;
    assert_eq!(engine.read(off(3), UNIT as usize).await.unwrap(), image(3, 1));
    assert_eq!(
        engine.read(off(5), UNIT as usize).await.unwrap(),
        vec![0u8; UNIT as usize],
        "a never-written unit of the adopted shard still reads as zeros"
    );
}
