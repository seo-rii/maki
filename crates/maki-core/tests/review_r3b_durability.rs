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

// Every test holds the process-global failpoint lock for its whole body:
// even a sweep that installs no global fault can consume another test's
// injection. Worker tasks remain concurrent within each workload.
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
        engine = match try_attach_with(&backing, cache).await {
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
    let _serial = maki_test_support::failpoints::test_lock();
    for seed in 0..120u64 {
        sweep(seed, 4, 0).await;
    }
}

#[tokio::test]
async fn random_workloads_with_sync_failures_never_show_foreign_data() {
    let _serial = maki_test_support::failpoints::test_lock();
    for seed in 0..80u64 {
        sweep(seed, 4, 150).await;
    }
}

/// Restart-then-power-loss with no FLUSH in between is the K-01 shape: the
/// restart's recovery must have made what it accepted durable.
#[tokio::test]
async fn restart_followed_by_power_loss_keeps_recovered_state() {
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
    let _serial = maki_test_support::failpoints::test_lock();
    for seed in 0..24u64 {
        concurrent_sweep(seed, 3, false).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "release gate: long concurrent partial-unit durability sweep"]
async fn phase_r3b_concurrent_gate_full() {
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
    let _serial = maki_test_support::failpoints::test_lock();
    for seed in 0..60u64 {
        sweep_cached(seed, 4, 0).await;
    }
}

#[tokio::test]
async fn random_workloads_with_a_plaintext_cache_and_sync_failures_never_show_foreign_data() {
    let _serial = maki_test_support::failpoints::test_lock();
    for seed in 0..40u64 {
        sweep_cached(seed, 4, 150).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_partial_unit_workloads_with_a_plaintext_cache() {
    let _serial = maki_test_support::failpoints::test_lock();
    for seed in 0..12u64 {
        concurrent_sweep(seed, 3, true).await;
    }
}
