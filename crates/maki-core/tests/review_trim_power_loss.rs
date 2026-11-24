//! TEST-006: the randomized power-loss sweeps never issued TRIM, so the
//! ordering of the discard map, hole punching, tombstone records and
//! checkpoints against crashes was only tested after a full FLUSH. This
//! sweep mixes writes and unit-aligned trims (with and without FUA) on a v3
//! discard volume, flushes and checkpoints at random, loses power (with
//! torn writes) or restarts, and holds every unit to the reference model: a
//! trimmed unit reads as zeros exactly like a write of zeros, durable once a
//! FUA or FLUSH covers it. With sync faults, failed operations may or may
//! not have landed until a newer acknowledged one is durable.

#![allow(clippy::await_holding_lock)]

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::Arc;

use parking_lot::Mutex;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use uuid::Uuid;

use maki_backing::Backing;
use maki_core::engine::{AttachError, CheckpointPolicy, Engine, EngineOptions};
use maki_core::volume::VolumeOptions;
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::journal::{RECORD_HEADER_SIZE, SEGMENT_HEADER_SIZE};
use maki_format::layout;
use maki_format::superblock::Superblock;
use maki_test_support::crash_backing::{FaultHook, FaultOp};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::{CrashableBacking, ReferenceBlockModel};

const UNIT: u32 = 512;
const DEVICE_UNITS: u64 = 48;
/// Tiny shards, eight units each: checkpoints and reclamation touch several
/// of them, not only when asked.
const SHARD_BYTES: u64 = 8 * UNIT as u64;

/// A journal segment that holds `records` write records.
fn segment_bytes(records: u64) -> u64 {
    SEGMENT_HEADER_SIZE as u64 + records * (RECORD_HEADER_SIZE as u64 + UNIT as u64 + 8)
}

/// The journal segment a seed's workloads run with.
///
/// A small segment makes a workload roll the journal constantly. But a roll
/// seals and syncs the segment it leaves, so with a segment of three records
/// no more than three are ever appended and not yet synced. The default
/// segment is never filled here: its workloads never roll, and their
/// unsynced tail grows to tens of records, which is what a power loss has to
/// cut and what a restart hands to recovery from the page cache alone. A
/// sweep needs both, so the seeds take turns: no rolls and long tails,
/// constant rolls and short tails, and a segment of sixteen records that
/// gives some of each.
fn segment_for(seed: u64) -> u64 {
    match seed % 3 {
        0 => VolumeOptions::default().journal_segment_size,
        1 => segment_bytes(3),
        _ => segment_bytes(16),
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
        volume_uuid: Uuid::from_u128(0x7417),
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

async fn try_attach(backing: &Arc<CrashableBacking>, segment: u64) -> Result<Engine, AttachError> {
    if !backing.exists("superblock.a").unwrap() {
        init::create_volume_with_discard(backing.as_ref(), superblock()).unwrap();
    }
    Engine::attach(
        backing.process(),
        Arc::new(FakeCryptoProvider::new(UNIT)),
        EngineOptions {
            checkpoint: CheckpointPolicy {
                emergency_reserve_bytes: 0,
                ..Default::default()
            },
            volume: VolumeOptions {
                journal_segment_size: segment,
            },
            ..EngineOptions::default()
        },
    )
    .await
}

fn off(unit: u64) -> u64 {
    unit * UNIT as u64
}

/// Unit-sized content unique to (unit, stamp).
fn image(unit: u64, stamp: u32) -> Vec<u8> {
    let mut v = vec![0u8; UNIT as usize];
    let seed = (unit as u32).wrapping_mul(0x9E37_79B1) ^ stamp.wrapping_mul(0x85EB_CA6B);
    for (i, b) in v.iter_mut().enumerate() {
        *b = (seed.wrapping_add(i as u32).wrapping_mul(0x2545_F491) >> 24) as u8 | 1;
    }
    v
}

fn zeros() -> Vec<u8> {
    vec![0; UNIT as usize]
}

/// What a failed (unacknowledged) write or trim may have left in a unit,
/// until a newer write to the unit supersedes it (see TEST-005).
#[derive(Default)]
struct Maybe {
    live: BTreeMap<u64, BTreeSet<Vec<u8>>>,
    crash: BTreeMap<u64, BTreeSet<Vec<u8>>>,
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
}

fn sync_faults(seed: u64, permille: u32, log: Arc<Mutex<Vec<String>>>) -> FaultHook {
    let rng = Mutex::new(StdRng::seed_from_u64(seed));
    Arc::new(move |op| match op {
        FaultOp::SyncData { .. } | FaultOp::SyncDir { .. }
            if rng.lock().random_range(0..1000) < permille =>
        {
            log.lock().push(format!("INJECTED {op:?}"));
            Some(io::Error::other("injected sync failure"))
        }
        _ => None,
    })
}

/// What a sweep did, for the tests that hold the sweep itself to something.
struct Ran {
    journal: Journal,
    /// Every operation with its result, and every injected fault.
    trace: String,
}

/// Returns what the workloads did to the journal.
async fn sweep(seed: u64, cycles: usize, fault_permille: u32) -> Journal {
    sweep_traced(seed, cycles, fault_permille, true)
        .await
        .journal
}

/// With `worker` the background checkpoint worker reclaims trimmed slots
/// while the workload runs, as it does in the daemon. Its passes and the
/// workload's requests then reach the backing in an order that the two
/// tasks' scheduling decides, so an injected fault does not meet the same
/// operation in every run. Without it the workload is the only source of
/// backing operations.
async fn sweep_traced(seed: u64, cycles: usize, fault_permille: u32, worker: bool) -> Ran {
    let mut rng = StdRng::seed_from_u64(seed.wrapping_mul(0x51_7CC1_B727).wrapping_add(7));
    let backing = Arc::new(CrashableBacking::new().with_tearing(128));
    let mut model = ReferenceBlockModel::new(UNIT as usize, DEVICE_UNITS);
    let mut maybe = Maybe::default();
    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    let mut stamp = 0u32;
    let segment = segment_for(seed);
    let mut engine = try_attach(&backing, segment).await.unwrap();
    if !worker {
        engine.stop_checkpoint_worker().await;
    }
    let history = |log: &Arc<Mutex<Vec<String>>>| log.lock().join("\n  ");

    let mut journal = Journal::default();
    for cycle in 0..cycles {
        if fault_permille > 0 {
            backing.set_fault_hook(Some(sync_faults(
                seed ^ cycle as u64,
                fault_permille,
                log.clone(),
            )));
        }
        // The session's first segment, read after its first write.
        let mut first_segment = None;
        for _ in 0..rng.random_range(8..40) {
            let count = rng.random_range(1..=4u64);
            let first = rng.random_range(0..DEVICE_UNITS - count + 1);
            let fua = rng.random_bool(0.25);
            match rng.random_range(0..100) {
                0..=39 => {
                    stamp += 1;
                    let data: Vec<u8> = (first..first + count)
                        .flat_map(|u| image(u, stamp))
                        .collect();
                    let result = engine.write(off(first), &data, fua).await;
                    if first_segment.is_none() {
                        first_segment = newest_segment(&backing);
                    }
                    log.lock().push(format!(
                        "write {first}..{} stamp {stamp} fua={fua} -> {:?}",
                        first + count,
                        result.as_ref().map_err(|e| e.to_string())
                    ));
                    for u in first..first + count {
                        match &result {
                            Ok(()) if fua => model.write_fua(u, &image(u, stamp)),
                            Ok(()) => model.write(u, &image(u, stamp)),
                            Err(_) => maybe.failed(u, image(u, stamp)),
                        }
                        if result.is_ok() {
                            maybe.acknowledged(u, fua);
                        }
                    }
                    if let Err(e) = result {
                        assert!(
                            fault_permille > 0,
                            "seed {seed}: write failed without faults: {e}"
                        );
                    }
                }
                40..=69 => {
                    let result = engine
                        .trim(off(first), (count * UNIT as u64) as usize, fua)
                        .await;
                    log.lock().push(format!(
                        "trim {first}..{} fua={fua} -> {:?}",
                        first + count,
                        result.as_ref().map_err(|e| e.to_string())
                    ));
                    for u in first..first + count {
                        match &result {
                            Ok(()) if fua => model.write_fua(u, &zeros()),
                            Ok(()) => model.write(u, &zeros()),
                            Err(_) => maybe.failed(u, zeros()),
                        }
                        if result.is_ok() {
                            maybe.acknowledged(u, fua);
                        }
                    }
                    if let Err(e) = result {
                        assert!(
                            fault_permille > 0,
                            "seed {seed}: trim failed without faults: {e}"
                        );
                    }
                }
                70..=79 => {
                    let result = engine.flush().await;
                    log.lock().push(format!(
                        "flush -> {:?}",
                        result.as_ref().map_err(|e| e.to_string())
                    ));
                    match result {
                        Ok(()) => {
                            model.flush();
                            maybe.flushed();
                        }
                        Err(e) => assert!(fault_permille > 0, "seed {seed}: flush failed: {e}"),
                    }
                }
                80..=87 => {
                    let result = engine.checkpoint().await;
                    log.lock().push(format!(
                        "checkpoint -> {:?}",
                        result.as_ref().map_err(|e| e.to_string())
                    ));
                    if let Err(e) = result {
                        assert!(
                            fault_permille > 0,
                            "seed {seed}: checkpoint failed without faults: {e}"
                        );
                    }
                }
                _ => {
                    let unit = rng.random_range(0..DEVICE_UNITS);
                    let actual = engine.read(off(unit), UNIT as usize).await.unwrap();
                    if actual != model.read(unit) {
                        assert!(
                            maybe
                                .live
                                .get(&unit)
                                .is_some_and(|set| set.contains(&actual)),
                            "seed {seed} cycle {cycle}: live read of unit {unit} is neither the \
                             acknowledged value nor a newer failed operation's\n  {}",
                            history(&log)
                        );
                        model.write(unit, &actual);
                        maybe.acknowledged(unit, false);
                    }
                }
            }
        }

        backing.set_fault_hook(None);
        if let (Some(first), Some(last)) = (first_segment, newest_segment(&backing)) {
            journal.rolls += last - first;
        }
        engine.stop_checkpoint_worker().await;
        let stats = engine.stats().await;
        let tail = stats.appended_sequence - stats.durable_sequence;
        drop(engine);
        let power_loss = rng.random_bool(0.7);
        journal.ended(tail, power_loss);
        let what = if power_loss {
            backing.crash(&mut rng);
            log.lock().push("power loss".into());
            format!("seed {seed} cycle {cycle} (power loss)")
        } else {
            log.lock().push("restart".into());
            format!("seed {seed} cycle {cycle} (restart)")
        };
        engine = match try_attach(&backing, segment).await {
            Ok(engine) => engine,
            Err(e) => panic!(
                "{what}: recovery refused the volume: {e}\n  {}",
                history(&log)
            ),
        };
        if !worker {
            engine.stop_checkpoint_worker().await;
        }
        let stats = engine.stats().await;
        assert!(
            stats.checkpoint_sequence <= stats.durable_sequence,
            "{what}: checkpoint ran ahead of durability"
        );
        for unit in 0..DEVICE_UNITS {
            let actual = match engine.read(off(unit), UNIT as usize).await {
                Ok(actual) => actual,
                Err(e) => panic!("{what}: unit {unit}: read failed: {e}\n  {}", history(&log)),
            };
            if let Err(violation) = model.crash_adopt(unit, &actual) {
                assert!(
                    maybe
                        .crash
                        .get(&unit)
                        .is_some_and(|set| set.contains(&actual)),
                    "{what}: {violation}\n  {}",
                    history(&log)
                );
                model.write_fua(unit, &actual);
            }
            maybe.live.remove(&unit);
            maybe.crash.remove(&unit);
            maybe.superseded.remove(&unit);
        }
    }
    Ran {
        journal,
        trace: history(&log),
    }
}

/// A seed that fails is only useful if it fails again. With the workload as
/// the only source of backing operations, the same seed must run the same
/// operations with the same results and meet the same injected faults, in
/// this process and in the next: nothing in the engine may order its backing
/// operations by anything but the workload.
#[tokio::test]
async fn a_sync_fault_sweep_without_the_worker_runs_the_same_way_twice_from_one_seed() {
    let _serial = maki_test_support::failpoints::test_lock();
    for seed in 0..12 {
        let first = sweep_traced(1000 + seed, 6, 120, false).await.trace;
        let second = sweep_traced(1000 + seed, 6, 120, false).await.trace;
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
async fn writes_and_trims_survive_power_loss_and_restart_cycles() {
    let _serial = maki_test_support::failpoints::test_lock();
    let mut journal = Journal::default();
    for seed in 0..24 {
        let ran = sweep(seed, 6, 0).await;
        assert!(
            ran.rolls > 0 || !rolls_expected(seed),
            "seed {seed}: the workload never rolled the journal"
        );
        journal += ran;
    }
    // Measured: 472 rolls, 27 power losses and 16 restarts with a long
    // tail, the longest 21 records.
    journal.assert_at_least(350, 20, 10);
}

#[tokio::test]
async fn writes_and_trims_with_sync_failures_never_show_foreign_data() {
    let _serial = maki_test_support::failpoints::test_lock();
    let mut journal = Journal::default();
    for seed in 0..24 {
        // A failed sync can stop a workload before its first roll, so only
        // the sweep as a whole is held to it.
        journal += sweep(1000 + seed, 6, 120).await;
    }
    // Measured, varying with how the background worker interleaves: 73 to
    // 92 rolls, 32 to 37 power losses and 12 to 15 restarts with a long
    // tail, the longest 41 records.
    journal.assert_at_least(40, 20, 6);
}

#[tokio::test]
#[ignore = "release gate: long randomized trim durability sweep"]
async fn trim_power_loss_gate_full() {
    let _serial = maki_test_support::failpoints::test_lock();
    let mut journal = Journal::default();
    for seed in 0..400 {
        journal += sweep(seed, 10, if seed % 2 == 0 { 0 } else { 120 }).await;
    }
    // Measured: 7253 rolls, 910 power losses and 379 restarts with a long
    // tail, the longest 49 records; the counts vary a little with how the
    // background worker interleaves.
    journal.assert_at_least(5000, 600, 250);
}
