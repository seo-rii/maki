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
use maki_core::engine::{AttachError, Engine, EngineOptions};
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
    if !backing.exists("superblock.a").unwrap() {
        init::create_volume(backing.as_ref(), superblock()).unwrap();
    }
    Engine::attach(
        backing.clone() as Arc<dyn Backing>,
        Arc::new(FakeCryptoProvider::new(UNIT)),
        EngineOptions::default(),
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
) {
    let stats = engine.stats().await;
    assert!(
        stats.checkpoint_sequence <= stats.durable_sequence,
        "{what}: checkpoint_sequence {} > durable_sequence {}",
        stats.checkpoint_sequence,
        stats.durable_sequence
    );
    for unit in 0..DEVICE_UNITS {
        let actual = engine.read(off(unit), UNIT as usize).await.unwrap();
        if let Err(violation) = model.crash_adopt(unit, &actual) {
            // An unacknowledged write may or may not have landed; anything
            // else is a durability violation.
            let landed = maybe
                .by_unit
                .get(&unit)
                .is_some_and(|set| set.contains(&actual));
            assert!(landed, "{what}: {violation}");
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
    sweep_verbose(seed, cycles, sync_fault_permille, None).await
}

async fn sweep_verbose(
    seed: u64,
    cycles: usize,
    sync_fault_permille: u32,
    verbose: Option<&'static str>,
) {
    let mut rng = StdRng::seed_from_u64(seed.wrapping_mul(0x9E37_79B9).wrapping_add(0x1234));
    let backing = Arc::new(CrashableBacking::new().with_tearing(128));
    let mut model = ReferenceBlockModel::new(UNIT as usize, DEVICE_UNITS);
    let mut maybe = Maybe::default();
    let mut stamp: u32 = 0;
    let mut trace = Trace::default();
    let mut engine = attach(&backing).await;

    if sync_fault_permille > 0 {
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
        engine = match try_attach(&backing).await {
            Ok(engine) => engine,
            Err(e) => panic!(
                "{what}: recovery refused the volume: {e}\n{}",
                trace.report()
            ),
        };
        check_all(&engine, &mut model, &mut maybe, &what).await;

        if sync_fault_permille > 0 {
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
    for seed in 0..120u64 {
        sweep(seed, 4, 0).await;
    }
}

#[tokio::test]
async fn random_workloads_with_sync_failures_never_show_foreign_data() {
    for seed in 0..80u64 {
        sweep(seed, 4, 150).await;
    }
}

/// Restart-then-power-loss with no FLUSH in between is the K-01 shape: the
/// restart's recovery must have made what it accepted durable.
#[tokio::test]
async fn restart_followed_by_power_loss_keeps_recovered_state() {
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
        )
        .await;
    }
}

#[tokio::test]
#[ignore = "release gate: long randomized durability sweep"]
async fn phase_r3b_durability_gate_full() {
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
