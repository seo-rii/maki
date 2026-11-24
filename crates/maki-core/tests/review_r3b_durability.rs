//! Review R3 follow-up: randomized multi-cycle durability sweep.
//!
//! The SPEC §54 scenarios (phase 12) fix one sequence and vary the crash.
//! This sweep varies the *sequence* too: seeded random single- and
//! multi-unit writes, FUA, FLUSH, explicit checkpoints, automatic journal
//! rolls (two seeds in three run with a small journal segment) and long
//! unsynced journal tails (the third keeps the default segment, see
//! `segment_for`), then a power loss with torn writes — or a plain
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
use maki_core::engine::{AttachError, CheckpointPolicy, Engine, EngineCacheConfig, EngineOptions};
use maki_core::error::CoreError;
use maki_core::volume::VolumeOptions;
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::journal::{RECORD_HEADER_SIZE, SEGMENT_HEADER_SIZE};
use maki_format::layout;
use maki_format::superblock::Superblock;
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::{CrashableBacking, ReferenceBlockModel};

const UNIT: u32 = 512;
const DEVICE_UNITS: u64 = 48;
/// Tiny shards: eight units each, so a workload spreads over six of them.
const SHARD_BYTES: u64 = 8 * UNIT as u64;

/// A journal segment that holds `records` records of a `unit`-sized write.
fn segment_bytes(unit: u32, records: u64) -> u64 {
    let record = RECORD_HEADER_SIZE as u64 + unit as u64 + 8;
    SEGMENT_HEADER_SIZE as u64 + records * record
}

/// The journal segment a seed's workloads run with.
///
/// A small segment makes a workload roll the journal constantly, not only
/// when a checkpoint is asked for. But a roll seals and syncs the segment it
/// leaves, so with a segment of three records no more than three are ever
/// appended and not yet synced. The default segment is never filled here:
/// its workloads never roll, and their unsynced tail grows to tens of
/// records, which is what a power loss has to cut and what a restart hands
/// to recovery from the page cache alone. A sweep needs both, so the seeds
/// take turns: no rolls and long tails, constant rolls and short tails, and
/// a segment of sixteen records that gives some of each.
fn segment_for(seed: u64, unit: u32) -> u64 {
    match seed % 3 {
        0 => VolumeOptions::default().journal_segment_size,
        1 => segment_bytes(unit, 3),
        _ => segment_bytes(unit, 16),
    }
}

/// Whether `segment_for` gives the seed a segment its workloads fill.
fn rolls_expected(seed: u64) -> bool {
    !seed.is_multiple_of(3)
}

/// A tail of more records than this, appended and not yet synced when the
/// workload ends, is a long one: more than the smallest segment can leave.
const LONG_TAIL: u64 = 3;

/// What a sweep's workloads did to the journal. A sweep that stops doing
/// either still passes, and proves much less, so the tests that run the
/// committed seeds hold their sweep to both.
#[derive(Clone, Copy, Debug, Default)]
struct Journal {
    /// Automatic rolls.
    rolls: u64,
    /// Workloads that ended in a power loss with a long unsynced tail.
    long_tail_power_losses: u64,
    /// Workloads that ended in a restart with a long unsynced tail.
    long_tail_restarts: u64,
    /// The longest unsynced tail a workload ended with, in records.
    longest_tail: u64,
}

impl Journal {
    /// Record how a workload ended: `tail` records appended and not synced.
    fn ended(&mut self, tail: u64, power_loss: bool) {
        if tail > LONG_TAIL {
            if power_loss {
                self.long_tail_power_losses += 1;
            } else {
                self.long_tail_restarts += 1;
            }
        }
        self.longest_tail = self.longest_tail.max(tail);
    }

    /// The sweep rolled the journal and ended workloads with long tails at
    /// least this often.
    fn assert_at_least(&self, rolls: u64, power_losses: u64, restarts: u64) {
        assert!(
            self.rolls >= rolls
                && self.long_tail_power_losses >= power_losses
                && self.long_tail_restarts >= restarts,
            "the sweep no longer covers what it is meant to: {self:?}; expected at least {rolls} \
             rolls, {power_losses} power losses and {restarts} restarts with more than \
             {LONG_TAIL} unsynced records"
        );
    }
}

impl std::ops::AddAssign for Journal {
    fn add_assign(&mut self, other: Self) {
        self.rolls += other.rolls;
        self.long_tail_power_losses += other.long_tail_power_losses;
        self.long_tail_restarts += other.long_tail_restarts;
        self.longest_tail = self.longest_tail.max(other.longest_tail);
    }
}

/// The highest journal segment index on the backing: the active segment's,
/// once a session has appended. A session numbers the segments it creates
/// consecutively and a checkpoint never deletes the active one, so the
/// difference between two readings within a session is the number of
/// automatic rolls in between.
fn newest_segment(backing: &CrashableBacking) -> Option<u64> {
    backing
        .list(layout::JOURNAL_DIR)
        .unwrap_or_default()
        .iter()
        .filter_map(|name| layout::parse_journal_segment(name))
        .max()
}

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
            SHARD_BYTES,
        )
        .unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

/// The scenario tests and the media-damage sweep keep the default journal
/// segment, which no workload here fills: their faults and their damage are
/// placed against a journal of one segment.
async fn try_attach(backing: &Arc<CrashableBacking>) -> Result<Engine, AttachError> {
    try_attach_with(
        backing,
        false,
        VolumeOptions::default().journal_segment_size,
    )
    .await
}

/// A deliberately tiny plaintext cache (a few units) so that hits, misses,
/// evictions and version changes all happen constantly under the sweeps,
/// and a journal segment of `segment` bytes.
fn cache_options(unit: u32, cache: bool, segment: u64) -> EngineOptions {
    EngineOptions {
        cache: cache.then(|| EngineCacheConfig {
            max_bytes: 6 * unit as u64,
            ttl: std::time::Duration::from_secs(3600),
            verify_on_hit: false,
        }),
        checkpoint: CheckpointPolicy {
            emergency_reserve_bytes: 0,
            ..Default::default()
        },
        volume: VolumeOptions {
            journal_segment_size: segment,
        },
        ..EngineOptions::default()
    }
}

async fn try_attach_with(
    backing: &Arc<CrashableBacking>,
    cache: bool,
    segment: u64,
) -> Result<Engine, AttachError> {
    if !backing.exists("superblock.a").unwrap() {
        init::create_volume(backing.as_ref(), superblock()).unwrap();
    }
    Engine::attach(
        backing.process(),
        Arc::new(FakeCryptoProvider::new(UNIT)),
        cache_options(UNIT, cache, segment),
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

/// Values a failed (unacknowledged) write may have left in a unit. Such a
/// write is journaled and published, so it may surface, but only until a
/// later write to the unit supersedes it (TEST-005): a live read must show
/// the newer acknowledged write, and after a crash the older value is
/// acceptable only while that newer write is not yet durable.
#[derive(Default)]
struct Maybe {
    /// What a live read may show instead of the model's value.
    live: BTreeMap<u64, BTreeSet<Vec<u8>>>,
    /// What recovery may show instead of the model's value.
    crash: BTreeMap<u64, BTreeSet<Vec<u8>>>,
    /// Units acknowledged after their last failed write, not yet durable:
    /// the next successful barrier retires their `crash` values.
    superseded: BTreeSet<u64>,
}

impl Maybe {
    fn failed(&mut self, unit: u64, value: Vec<u8>) {
        self.live.entry(unit).or_default().insert(value.clone());
        self.crash.entry(unit).or_default().insert(value);
        self.superseded.remove(&unit);
    }

    fn acknowledged(&mut self, unit: u64, fua: bool) {
        self.live.remove(&unit);
        if fua {
            self.crash.remove(&unit);
            self.superseded.remove(&unit);
        } else if self.crash.contains_key(&unit) {
            self.superseded.insert(unit);
        }
    }

    fn flushed(&mut self) {
        for unit in std::mem::take(&mut self.superseded) {
            self.crash.remove(&unit);
        }
    }

    fn live_may_show(&self, unit: u64, value: &[u8]) -> bool {
        self.live.get(&unit).is_some_and(|set| set.contains(value))
    }

    fn crash_may_show(&self, unit: u64, value: &[u8]) -> bool {
        self.crash.get(&unit).is_some_and(|set| set.contains(value))
    }

    /// Recovery read the unit: what it showed is the new durable state.
    fn settled(&mut self, unit: u64) {
        self.live.remove(&unit);
        self.crash.remove(&unit);
        self.superseded.remove(&unit);
    }
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
            let landed = maybe.crash_may_show(unit, &actual);
            assert!(landed, "{what}: {violation}\n{history}");
            model.write_fua(unit, &actual);
        }
        maybe.settled(unit);
    }
}

/// The sweeps' own oracle (TEST-005): a failed write stops being an
/// acceptable outcome once a newer write to the unit is acknowledged (live)
/// or durable (after a crash), and stays one while no newer write is.
#[test]
fn a_superseded_failed_write_is_no_longer_an_acceptable_outcome() {
    let (failed, newer) = (vec![1u8], vec![2u8]);
    let mut maybe = Maybe::default();
    maybe.failed(7, failed.clone());
    assert!(maybe.live_may_show(7, &failed) && maybe.crash_may_show(7, &failed));
    maybe.acknowledged(7, false);
    assert!(
        !maybe.live_may_show(7, &failed),
        "live view showed a stale write"
    );
    assert!(
        maybe.crash_may_show(7, &failed),
        "the newer write is not durable yet"
    );
    maybe.flushed();
    assert!(
        !maybe.crash_may_show(7, &failed),
        "a FLUSH made the newer write durable"
    );

    let mut maybe = Maybe::default();
    maybe.failed(7, failed.clone());
    maybe.acknowledged(7, true);
    assert!(
        !maybe.crash_may_show(7, &failed),
        "a FUA write is durable at once"
    );

    let mut maybe = Maybe::default();
    maybe.failed(7, failed.clone());
    maybe.acknowledged(7, false);
    maybe.failed(7, newer.clone());
    maybe.flushed();
    assert!(
        maybe.crash_may_show(7, &failed) && maybe.crash_may_show(7, &newer),
        "a failed write after the acknowledged one keeps both possible"
    );
}

struct Cycle {
    ops: usize,
    /// `true` = power loss with torn writes; `false` = plain restart.
    power_loss: bool,
}

/// What a sweep did, for the tests that hold the sweep itself to something.
struct Ran {
    journal: Journal,
    /// Every operation with its result, and every injected fault.
    trace: String,
}

/// One seeded workload → crash/restart → recovery → oracle cycle set.
/// Returns what its workloads did to the journal.
async fn sweep(seed: u64, cycles: usize, sync_fault_permille: u32) -> Journal {
    sweep_verbose(seed, cycles, sync_fault_permille, None, false)
        .await
        .journal
}

async fn sweep_cached(seed: u64, cycles: usize, sync_fault_permille: u32) -> Journal {
    sweep_verbose(seed, cycles, sync_fault_permille, None, true)
        .await
        .journal
}

async fn sweep_verbose(
    seed: u64,
    cycles: usize,
    sync_fault_permille: u32,
    verbose: Option<&'static str>,
    cache: bool,
) -> Ran {
    let mut rng = StdRng::seed_from_u64(seed.wrapping_mul(0x9E37_79B9).wrapping_add(0x1234));
    let backing = Arc::new(CrashableBacking::new().with_tearing(128));
    let mut model = ReferenceBlockModel::new(UNIT as usize, DEVICE_UNITS);
    let mut maybe = Maybe::default();
    let mut stamp: u32 = 0;
    let mut trace = Trace::default();
    let segment = segment_for(seed, UNIT);
    let mut engine = try_attach_with(&backing, cache, segment).await.unwrap();

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

    let mut journal = Journal::default();
    for cycle_index in 0..cycles {
        let cycle = Cycle {
            ops: rng.random_range(8..48),
            power_loss: rng.random_bool(0.7),
        };
        // The session's first segment, read after its first write.
        let mut first_segment = None;
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
                    if first_segment.is_none() {
                        first_segment = newest_segment(&backing);
                    }
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
                                maybe.acknowledged(u, fua);
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
                                maybe.failed(u, image(u, stamp));
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
                        Ok(()) => {
                            model.flush();
                            maybe.flushed();
                        }
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
                        assert!(
                            maybe.live_may_show(unit, &actual),
                            "seed {seed} cycle {cycle_index}: live read of unit {unit} is neither \
                             the acknowledged value nor a failed write newer than it"
                        );
                        trace.op(format!("live read of unit {unit} shows a failed write"));
                        model.write(unit, &actual);
                        maybe.acknowledged(unit, false);
                    }
                }
            }
        }

        // The fault window closes with the workload: recovery itself runs on
        // a healthy device (its own fault tolerance is covered elsewhere).
        backing.set_fault_hook(None);
        if let (Some(first), Some(last)) = (first_segment, newest_segment(&backing)) {
            journal.rolls += last - first;
        }
        let stats = engine.stats().await;
        journal.ended(
            stats.appended_sequence - stats.durable_sequence,
            cycle.power_loss,
        );
        drop(engine);
        let what = if cycle.power_loss {
            backing.crash(&mut rng);
            trace.op("power loss".into());
            format!("seed {seed} cycle {cycle_index} (power loss)")
        } else {
            trace.op("restart".into());
            format!("seed {seed} cycle {cycle_index} (restart)")
        };
        engine = match try_attach_with(&backing, cache, segment).await {
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
    Ran {
        journal,
        trace: trace.report(),
    }
}

/// A seed that fails is only useful if it fails again. The same seed must
/// run the same operations with the same results and meet the same injected
/// faults, in this process and in the next: nothing in the engine may order
/// its backing operations by anything but the workload.
#[tokio::test]
async fn a_sync_fault_sweep_runs_the_same_way_twice_from_one_seed() {
    let _serial = maki_test_support::failpoints::test_lock();
    for seed in 0..24u64 {
        let first = sweep_verbose(seed, 4, 150, None, false).await.trace;
        let second = sweep_verbose(seed, 4, 150, None, false).await.trace;
        if let Some((line, (a, b))) = first
            .lines()
            .zip(second.lines())
            .enumerate()
            .find(|(_, (a, b))| a != b)
        {
            panic!("seed {seed}: two runs differ from line {line}:\n  {a}\n  {b}");
        }
        assert_eq!(first.len(), second.len(), "seed {seed}");
    }
}

#[tokio::test]
async fn random_workloads_survive_power_loss_and_restart_cycles() {
    let _serial = maki_test_support::failpoints::test_lock();
    let mut journal = Journal::default();
    for seed in 0..120u64 {
        let ran = sweep(seed, 4, 0).await;
        assert!(
            ran.rolls > 0 || !rolls_expected(seed),
            "seed {seed}: the workload never rolled the journal"
        );
        journal += ran;
    }
    // Measured: 2052 rolls, 74 power losses and 35 restarts with a long
    // tail, the longest 50 records.
    journal.assert_at_least(1600, 55, 25);
}

#[tokio::test]
async fn random_workloads_with_sync_failures_never_show_foreign_data() {
    let _serial = maki_test_support::failpoints::test_lock();
    let mut journal = Journal::default();
    for seed in 0..80u64 {
        // A failed sync can stop a workload before its first roll, so only
        // the sweep as a whole is held to it.
        journal += sweep(seed, 4, 150).await;
    }
    // Measured: 247 rolls, 88 power losses and 29 restarts with a long
    // tail, the longest 38 records.
    journal.assert_at_least(150, 60, 18);
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
    let _serial = maki_test_support::failpoints::test_lock();
    let mut journal = Journal::default();
    for seed in 0..1500u64 {
        journal += sweep(seed, 6, 0).await;
    }
    // Measured: 40249 rolls, 1443 power losses and 631 restarts with a long
    // tail, the longest 50 records.
    journal.assert_at_least(30000, 1000, 450);
    let mut journal = Journal::default();
    for seed in 0..600u64 {
        journal += sweep(seed, 6, 150).await;
    }
    // Measured: 2738 rolls, 885 power losses and 349 restarts with a long
    // tail, the longest 70 records.
    journal.assert_at_least(1800, 600, 240);
}

/// A failed pre-journal reservation can leave an orphan shard file. Creating
/// another shard must never catalog that orphan without an allocation copy,
/// and the rejected write must remain absent after power loss.
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
    engine
        .write(off(16), &image(16, 1), false)
        .await
        .unwrap_err();
    // A lower shard's creation in the next attempt syncs the data
    // directory, making shard 2's data-file dirent durable; shard 2's map
    // still fails.
    engine.write(off(8), &image(8, 1), false).await.unwrap();
    engine.flush().await.unwrap();
    engine.checkpoint().await.unwrap();
    backing.set_fault_hook(None);
    drop(engine);
    backing.crash_all_lost();

    // Recovery adopts any surviving orphan. A write to a new, higher shard
    // may publish a new catalog, but only after adopted maps are durable.
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
    for (unit, stamp) in [(0u64, 1u32), (8, 1), (24, 2)] {
        assert_eq!(
            engine.read(off(unit), UNIT as usize).await.unwrap(),
            image(unit, stamp),
            "unit {unit}"
        );
    }
    assert_eq!(
        engine.read(off(16), UNIT as usize).await.unwrap(),
        vec![0; UNIT as usize]
    );
}

/// The same orphan rule holds across a plain restart where a failed map sync
/// can remain readable from page cache until the next catalog publication.
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
    engine
        .write(off(40), &image(40, 1), false)
        .await
        .unwrap_err();
    engine.write(off(8), &image(8, 1), false).await.unwrap();
    engine.flush().await.unwrap();
    engine.checkpoint().await.unwrap();
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
    for (unit, stamp) in [(0u64, 1u32), (8, 1), (16, 2)] {
        assert_eq!(
            engine.read(off(unit), UNIT as usize).await.unwrap(),
            image(unit, stamp),
            "unit {unit}"
        );
    }
    assert_eq!(
        engine.read(off(40), UNIT as usize).await.unwrap(),
        vec![0; UNIT as usize]
    );
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
    assert_eq!(
        engine.read(off(1), UNIT as usize).await.unwrap(),
        image(1, 1)
    );
    assert_eq!(
        engine.read(off(3), UNIT as usize).await.unwrap(),
        image(3, 1)
    );
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

async fn attach_big(backing: &Arc<CrashableBacking>, cache: bool, segment: u64) -> Arc<Engine> {
    if !backing.exists("superblock.a").unwrap() {
        init::create_volume(backing.as_ref(), big_superblock()).unwrap();
    }
    Arc::new(
        Engine::attach(
            backing.process(),
            Arc::new(FakeCryptoProvider::new(BIG_UNIT)),
            cache_options(BIG_UNIT, cache, segment),
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

/// Count the journal segments that are created while the returned hook is
/// installed: one when a session first appends, one more for every roll.
fn count_segments_created(backing: &CrashableBacking) -> Arc<std::sync::atomic::AtomicU64> {
    let created = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let counter = created.clone();
    backing.set_fault_hook(Some(Arc::new(move |op: &FaultOp<'_>| {
        if let FaultOp::Open { path, create: true } = op {
            let segment = path
                .strip_prefix(layout::JOURNAL_DIR)
                .and_then(|name| name.strip_prefix('/'))
                .and_then(layout::parse_journal_segment);
            if segment.is_some() {
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        None
    })));
    created
}

async fn concurrent_sweep(seed: u64, cycles: usize, cache: bool) -> Journal {
    let mut rng = StdRng::seed_from_u64(seed ^ 0xC0DE);
    let backing = Arc::new(CrashableBacking::new().with_tearing(256));
    let mut model = ReferenceBlockModel::new(BIG_UNIT as usize, DEVICE_UNITS);
    let segment = segment_for(seed, BIG_UNIT);
    let mut engine = attach_big(&backing, cache, segment).await;
    let mut journal = Journal::default();

    for cycle in 0..cycles {
        let created = count_segments_created(&backing);
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

        backing.set_fault_hook(None);
        journal.rolls += created
            .load(std::sync::atomic::Ordering::Relaxed)
            .saturating_sub(1);
        let stats = engine.stats().await;
        let tail = stats.appended_sequence - stats.durable_sequence;
        drop(engine);
        let power_loss = rng.random_bool(0.7);
        journal.ended(tail, power_loss);
        let what = if power_loss {
            backing.crash(&mut rng);
            format!("seed {seed} cycle {cycle} (power loss)")
        } else {
            format!("seed {seed} cycle {cycle} (restart)")
        };
        engine = attach_big(&backing, cache, segment).await;
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
    }
    journal
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_partial_unit_workloads_survive_power_loss_and_restart() {
    let _serial = maki_test_support::failpoints::test_lock();
    let mut journal = Journal::default();
    for seed in 0..24u64 {
        journal += concurrent_sweep(seed, 3, false).await;
    }
    // Measured: 1173 rolls and, depending on how the writers and the
    // barriers interleave, 12 to 15 power losses and 2 to 10 restarts with
    // a long tail, the longest 19 to 28 records.
    journal.assert_at_least(900, 6, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "release gate: long concurrent partial-unit durability sweep"]
async fn phase_r3b_concurrent_gate_full() {
    let _serial = maki_test_support::failpoints::test_lock();
    let mut journal = Journal::default();
    for seed in 0..300u64 {
        journal += concurrent_sweep(seed, 4, false).await;
    }
    for seed in 0..150u64 {
        journal += concurrent_sweep(seed, 4, true).await;
    }
    // Measured: 29147 rolls, 377 power losses and 134 restarts with a long
    // tail, the longest 43 records; the tails vary from run to run.
    journal.assert_at_least(20000, 250, 80);
}

// ---------------------------------------------------------------------------
// The same sweeps with the versioned plaintext cache enabled (a tiny one, so
// eviction and version turnover are constant): a stale or mis-keyed cache
// entry shows up as a live read that disagrees with the acknowledged value.

#[tokio::test]
async fn random_workloads_with_a_plaintext_cache_survive_power_loss_and_restart() {
    let _serial = maki_test_support::failpoints::test_lock();
    let mut journal = Journal::default();
    for seed in 0..60u64 {
        journal += sweep_cached(seed, 4, 0).await;
    }
    // Measured: 1014 rolls, 39 power losses and 15 restarts with a long
    // tail, the longest 21 records.
    journal.assert_at_least(800, 30, 10);
}

#[tokio::test]
async fn random_workloads_with_a_plaintext_cache_and_sync_failures_never_show_foreign_data() {
    let _serial = maki_test_support::failpoints::test_lock();
    let mut journal = Journal::default();
    for seed in 0..40u64 {
        journal += sweep_cached(seed, 4, 150).await;
    }
    // Measured: 110 rolls, 51 power losses and 11 restarts with a long
    // tail, the longest 38 records.
    journal.assert_at_least(70, 35, 6);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_partial_unit_workloads_with_a_plaintext_cache() {
    let _serial = maki_test_support::failpoints::test_lock();
    let mut journal = Journal::default();
    for seed in 0..12u64 {
        journal += concurrent_sweep(seed, 3, true).await;
    }
    // Measured: 571 rolls, 8 to 10 power losses and at most one restart
    // with a long tail, the longest 16 to 22 records.
    journal.assert_at_least(400, 4, 0);
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
    use maki_format::catalog::ShardCatalog;
    use maki_format::layout;
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
                                maybe.acknowledged(u, fua);
                            }
                        }
                        // A damaged volume may refuse writes (EIO); the data
                        // may or may not have landed.
                        Err(e) => {
                            log.push(format!("{tag} refused: {e}"));
                            for u in first..first + count {
                                maybe.failed(u, image(u, stamp));
                            }
                        }
                    }
                }
                60..=79 => match engine.flush().await {
                    Ok(()) => {
                        log.push("flush".to_string());
                        model.flush();
                        maybe.flushed();
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
                        let landed = maybe.crash_may_show(unit, &actual);
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
                    maybe.settled(unit);
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
    assert!(
        attached > 0,
        "every damaged volume was refused; the sweep proves nothing"
    );
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
    data.write_at(geometry.slot_offset(in_shard), &[0u8; 54])
        .unwrap();
    data.sync_data().unwrap();

    let engine = attach(&backing).await;
    assert_eq!(
        engine.read(off(17), UNIT as usize).await.unwrap(),
        image(17, 1)
    );
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
    assert_eq!(
        engine.read(off(1), UNIT as usize).await.unwrap(),
        image(1, 1)
    );
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
    data.set_len(geometry.slot_offset(in_shard - 1) + 447)
        .unwrap();
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
    assert_eq!(
        engine.read(off(1), UNIT as usize).await.unwrap(),
        image(1, 1)
    );
    expect_eio(
        5,
        engine.read(off(5), UNIT as usize).await,
        "after the truncation",
    );
    // A later slot of the same shard is checkpointed: the file grows back
    // past unit 5's slot, which is now all zeros.
    engine.write(off(7), &image(7, 1), true).await.unwrap();
    engine.checkpoint().await.unwrap();
    assert_eq!(
        data.len().unwrap(),
        geometry.units_per_shard() * geometry.slot_size,
        "the file is restored to its physical size before the slot write"
    );
    expect_eio(
        5,
        engine.read(off(5), UNIT as usize).await,
        "after the file grew back",
    );
    drop(engine);
    backing.crash_all_lost();

    let engine = attach(&backing).await;
    assert_eq!(
        engine.read(off(1), UNIT as usize).await.unwrap(),
        image(1, 1)
    );
    assert_eq!(
        engine.read(off(7), UNIT as usize).await.unwrap(),
        image(7, 1)
    );
    expect_eio(
        5,
        engine.read(off(5), UNIT as usize).await,
        "after power loss",
    );
    // Beyond the cut nothing can be told apart from a removed slot: a unit
    // never written there is EIO too, until it is rewritten.
    expect_eio(
        6,
        engine.read(off(6), UNIT as usize).await,
        "after power loss",
    );
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
    assert_eq!(
        engine.read(off(5), UNIT as usize).await.unwrap(),
        image(5, 2)
    );
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
    assert_eq!(
        engine.read(off(3), UNIT as usize).await.unwrap(),
        image(3, 1)
    );
    assert_eq!(
        engine.read(off(5), UNIT as usize).await.unwrap(),
        vec![0u8; UNIT as usize],
        "a never-written unit of the adopted shard still reads as zeros"
    );
}

/// A repair checkpoint that adopted several shards sizes their data files
/// before the catalog names them, in shard order. The shards are kept in a
/// hash map; in its order, which file a failed sync or a power loss in the
/// middle had reached would differ from one process to the next.
#[tokio::test]
async fn adopted_orphans_are_sized_in_shard_order() {
    let _serial = maki_test_support::failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    drop(attach(&backing).await);
    let orphans = [1u64, 2, 3, 4, 5];
    for shard in orphans {
        drop(backing.open(&layout::shard_data(shard), true).unwrap());
    }
    backing.sync_dir(layout::DATA_DIR).unwrap();

    let engine = attach(&backing).await;
    let sized = Arc::new(Mutex::new(Vec::new()));
    let seen = sized.clone();
    backing.set_fault_hook(Some(Arc::new(move |op: &FaultOp<'_>| {
        if let FaultOp::SetLen { path, len } = op {
            if *len > 0 && path.ends_with(".dat") {
                seen.lock().push(path.to_string());
            }
        }
        None
    })));
    engine.checkpoint().await.unwrap();
    backing.set_fault_hook(None);
    assert_eq!(*sized.lock(), orphans.map(layout::shard_data));
}

/// Minimised from `random_workloads_with_sync_failures_never_show_foreign_data`
/// (seed 29) once checkpoint destinations were reserved at write admission.
/// A shard's creation stopped at its data file's size sync and power was
/// lost: a zero-length orphan with no allocation copy, adopted at the next
/// attach as never finished. A checkpoint with nothing new to apply then
/// persisted the pending repairs — and cataloged the orphan without proving
/// its size first. The next power loss left a *cataloged* zero-length file,
/// which the truncation rule marks allocated: every never-written unit of
/// the shard read EIO. `ensure_shard`'s catalog commit already proved the
/// file through `commit_adopted_maps`; the repair checkpoint's commit is the
/// other one and must do the same.
#[tokio::test]
async fn adopted_orphan_is_sized_before_a_repair_checkpoint_catalogs_it() {
    let _serial = maki_test_support::failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    drop(attach(&backing).await);
    let geometry = superblock().geometry;
    let per_shard = geometry.units_per_shard();
    let shard_idx = 4;
    let path = maki_format::layout::shard_data(shard_idx);
    drop(backing.open(&path, true).unwrap());
    backing.sync_dir(maki_format::layout::DATA_DIR).unwrap();

    // Nothing new is durable: the checkpoint only persists the repairs
    // (the adopted shard's map and the catalog naming it).
    let engine = attach(&backing).await;
    engine.checkpoint().await.unwrap();
    assert_eq!(
        backing.open(&path, false).unwrap().len().unwrap(),
        per_shard * geometry.slot_size,
        "the data file is sized before the catalog names the shard"
    );
    drop(engine);
    backing.crash_all_lost();

    let engine = attach(&backing).await;
    for in_shard in [0, 3, per_shard - 1] {
        let unit = shard_idx * per_shard + in_shard;
        assert_eq!(
            engine.read(off(unit), UNIT as usize).await.unwrap(),
            vec![0u8; UNIT as usize],
            "unit {unit} of a never-written, now cataloged shard is a hole"
        );
    }
    let unit = shard_idx * per_shard + 1;
    engine
        .write(off(unit), &image(unit, 1), true)
        .await
        .unwrap();
    engine.checkpoint().await.unwrap();
    drop(engine);
    backing.crash_all_lost();

    let engine = attach(&backing).await;
    assert_eq!(
        engine.read(off(unit), UNIT as usize).await.unwrap(),
        image(unit, 1)
    );
    assert_eq!(
        engine.read(off(unit + 1), UNIT as usize).await.unwrap(),
        vec![0u8; UNIT as usize],
        "a neighbouring never-written unit still reads as zeros"
    );
}
