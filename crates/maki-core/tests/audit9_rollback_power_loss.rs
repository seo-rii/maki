//! Audit round 9 (r8-storage): the engine on a LOCAL rollback-protected pair
//! hosted on the executable crash model, with power losses and torn writes.
//!
//! Until #382 an integration test could only host a rollback pair on real
//! directories, where the one crash it can produce is a process restart
//! (round 2's `audit2_sweep_rollback.rs`). `RollbackBacking::create_on` /
//! `open_on` now take caller-supplied backings, so the pair can live on two
//! `CrashableBacking` machines (the backing and the witness directory), and
//! the whole stack above it, where every A/B store is a sequence of manifest
//! commits and #386's "truncate, sync" is one more commit, can lose power.
//!
//! One seeded cycle: a workload (single- and multi-unit writes, FUA, FLUSH,
//! checkpoints, automatic journal rolls, TRIM on a discard volume), optional
//! transient faults on either machine, then a process death followed by a
//! restart, a power loss of both machines with torn writes, or a worst-case
//! power loss; then up to three recoveries that die at a random operation
//! (each followed by the same choice); then a clean recovery. Every unit is
//! compared with `ReferenceBlockModel` after every clean recovery, and what
//! that recovery served is the durable state for the next cycle.
//!
//! `AUDIT9_SEED_START`, `AUDIT9_SEED_COUNT` (default 0 / 40), `AUDIT9_CYCLES`
//! (default 4), `AUDIT9_BUDGET_SECS` (default 240 per mode).
//! `AUDIT9_INDEPENDENT=1` also lets one machine lose power alone.

#![cfg(target_os = "linux")]
#![allow(clippy::await_holding_lock)]

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use uuid::Uuid;

use maki_backing::{Backing, RollbackBacking};
use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
use maki_core::volume::VolumeOptions;
use maki_format::geometry::Geometry;
use maki_format::init::create_in_rollback_backing;
use maki_format::journal::{RECORD_HEADER_SIZE, SEGMENT_HEADER_SIZE};
use maki_format::superblock::Superblock;
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::{CrashableBacking, ReferenceBlockModel};

const UNIT: u32 = 512;
const CAPACITY: u64 = 2 << 20;

#[derive(Clone, Debug)]
struct Cfg {
    device_units: u64,
    units_per_shard: u64,
    records_per_segment: u64,
    discard: bool,
    tear: usize,
}

impl Cfg {
    fn for_seed(seed: u64) -> Self {
        let mut r = StdRng::seed_from_u64(seed ^ 0x0909_B0B0);
        let device_units = r.random_range(8..=40u64);
        Self {
            device_units,
            units_per_shard: [1u64, 3, 8, 16][r.random_range(0..4)].min(device_units),
            records_per_segment: r.random_range(1..=4),
            discard: r.random_bool(0.5),
            tear: [8usize, 64, 512, 4096][r.random_range(0..4)],
        }
    }

    fn superblock(&self) -> Superblock {
        Superblock {
            generation: 0,
            volume_uuid: Uuid::from_u128(0x0A9_B0B0),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(
                UNIT,
                UNIT,
                512,
                UNIT + 8,
                self.device_units * UNIT as u64,
                self.units_per_shard * UNIT as u64,
            )
            .unwrap(),
            format_version: 1,
            created_unix: 0,
        }
    }

    fn options(&self) -> EngineOptions {
        let record = RECORD_HEADER_SIZE as u64 + UNIT as u64 + 8;
        EngineOptions {
            volume: VolumeOptions {
                journal_segment_size: SEGMENT_HEADER_SIZE as u64
                    + self.records_per_segment * record,
            },
            checkpoint: CheckpointPolicy {
                journal_high_watermark_bytes: u64::MAX,
                emergency_reserve_bytes: 0,
                low_space_checkpoint_bytes: 0,
                interval: Duration::from_secs(3600),
                ..Default::default()
            },
            ..EngineOptions::default()
        }
    }
}

/// Fault state shared by both machines' hooks.
#[derive(Default)]
struct Inj {
    /// Every mutation fails (the process is dead).
    dead: AtomicBool,
    /// Mutations left before death; negative = not armed.
    countdown: AtomicI64,
    /// Permille of mutations that fail once (0 = off).
    permille: AtomicI64,
    rng: Mutex<Option<StdRng>>,
    log: Mutex<Vec<String>>,
}

struct Machines {
    root: CrashableBacking,
    witness: CrashableBacking,
    inj: Arc<Inj>,
}

impl Machines {
    fn new(tear: usize) -> Self {
        let machines = Self {
            root: CrashableBacking::new().with_tearing(tear),
            witness: CrashableBacking::new().with_tearing(tear),
            inj: Arc::new(Inj::default()),
        };
        machines.inj.countdown.store(-1, Ordering::SeqCst);
        for (name, machine) in [("root", &machines.root), ("witness", &machines.witness)] {
            let inj = machines.inj.clone();
            machine.set_fault_hook(Some(Arc::new(move |op| {
                let mutating = match op {
                    FaultOp::Open { create, .. } => *create,
                    _ => true,
                };
                if !mutating {
                    return None;
                }
                if inj.dead.load(Ordering::SeqCst) {
                    return Some(io::Error::other("process is dead"));
                }
                let left = inj.countdown.load(Ordering::SeqCst);
                if left >= 0 {
                    if left == 0 {
                        inj.dead.store(true, Ordering::SeqCst);
                        inj.log.lock().push(format!("DEATH at {name} {op:?}"));
                        return Some(io::Error::other("process is dead"));
                    }
                    inj.countdown.store(left - 1, Ordering::SeqCst);
                }
                let permille = inj.permille.load(Ordering::SeqCst);
                if permille > 0 {
                    let hit = inj
                        .rng
                        .lock()
                        .as_mut()
                        .is_some_and(|rng| rng.random_range(0..1000) < permille);
                    if hit {
                        inj.log.lock().push(format!("INJECTED {name} {op:?}"));
                        return Some(io::Error::other("injected failure"));
                    }
                }
                None
            })));
        }
        machines
    }

    fn open(&self) -> io::Result<RollbackBacking> {
        RollbackBacking::open_on(self.root.process(), self.witness.process())
    }

    fn create(&self, cfg: &Cfg) {
        let (root, witness) = (self.root.process(), self.witness.process());
        let (same_root, same_witness) = (root.clone(), witness.clone());
        create_in_rollback_backing(
            || RollbackBacking::create_on(root, witness, CAPACITY),
            || RollbackBacking::open_on(same_root, same_witness),
            CAPACITY,
            cfg.superblock(),
            cfg.discard,
        )
        .map(drop)
        .expect("create the volume");
    }

    /// The process dies: nothing it still holds can change either machine.
    fn kill(&self) {
        self.root.set_lenient_sync_failures(true);
        self.witness.set_lenient_sync_failures(true);
        self.inj.dead.store(true, Ordering::SeqCst);
        self.inj.permille.store(0, Ordering::SeqCst);
    }

    /// A new process may start.
    fn revive(&self) {
        self.inj.dead.store(false, Ordering::SeqCst);
        self.inj.countdown.store(-1, Ordering::SeqCst);
        self.root.set_lenient_sync_failures(false);
        self.witness.set_lenient_sync_failures(false);
    }
}

async fn attach(machines: &Machines, cfg: &Cfg) -> Result<Engine, String> {
    let backing = machines.open().map_err(|e| format!("pair does not open: {e}"))?;
    Engine::attach(
        Arc::new(backing) as Arc<dyn Backing>,
        Arc::new(FakeCryptoProvider::new(UNIT)),
        cfg.options(),
    )
    .await
    .map_err(|e| format!("attach refused: {e}"))
}

fn off(unit: u64) -> u64 {
    unit * UNIT as u64
}

fn image(unit: u64, stamp: u32) -> Vec<u8> {
    let mut v = vec![0u8; UNIT as usize];
    let seed = (unit as u32).wrapping_mul(0x9E37_79B1) ^ stamp.wrapping_mul(0x85EB_CA6B);
    for (i, b) in v.iter_mut().enumerate() {
        *b = (seed.wrapping_add(i as u32).wrapping_mul(0x2545_F491) >> 24) as u8;
    }
    v
}

/// Values an unacknowledged request may have left in a unit.
#[derive(Default)]
struct Maybe {
    values: BTreeMap<u64, BTreeSet<Vec<u8>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Clean,
    Faults,
    RecoveryDeaths,
}

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

async fn run_seed(seed: u64, mode: Mode, cycles: usize) -> Result<(), String> {
    let cfg = Cfg::for_seed(seed);
    let mut rng = StdRng::seed_from_u64(seed.wrapping_mul(0x9E37_79B9).wrapping_add(0x9));
    let machines = Machines::new(cfg.tear);
    *machines.inj.rng.lock() = Some(StdRng::seed_from_u64(seed ^ 0xFA17));
    machines.create(&cfg);
    let independent = std::env::var_os("AUDIT9_INDEPENDENT").is_some();
    let zeros = vec![0u8; UNIT as usize];
    let mut model = ReferenceBlockModel::new(UNIT as usize, cfg.device_units);
    let mut maybe = Maybe::default();
    let mut stamp = 0u32;
    let mut trace: Vec<String> = vec![format!("cfg {cfg:?} mode {mode:?}")];
    let history = |trace: &Vec<String>, machines: &Machines| {
        format!(
            "seed {seed}\n  {}\nfaults:\n  {}",
            trace.join("\n  "),
            machines.inj.log.lock().join("\n  ")
        )
    };
    let mut engine = attach(&machines, &cfg)
        .await
        .map_err(|e| format!("FIRST-ATTACH: {e}\n{}", history(&trace, &machines)))?;

    for cycle in 0..cycles {
        if mode == Mode::Faults {
            machines.inj.permille.store(12, Ordering::SeqCst);
        }
        let ops = rng.random_range(6..40);
        for _ in 0..ops {
            match rng.random_range(0..100) {
                0..=54 => {
                    let count = rng.random_range(1..=4u64).min(cfg.device_units);
                    let first = rng.random_range(0..cfg.device_units - count + 1);
                    let fua = rng.random_bool(0.25);
                    let trim = cfg.discard && rng.random_bool(0.2);
                    stamp += 1;
                    let result = if trim {
                        engine
                            .trim(off(first), (count * UNIT as u64) as usize, fua)
                            .await
                    } else {
                        let data: Vec<u8> = (first..first + count)
                            .flat_map(|u| image(u, stamp))
                            .collect();
                        engine.write(off(first), &data, fua).await
                    };
                    trace.push(format!(
                        "{} units {first}..{} stamp {stamp} fua={fua} -> {:?}",
                        if trim { "trim" } else { "write" },
                        first + count,
                        result.as_ref().map_err(|e| e.to_string())
                    ));
                    for u in first..first + count {
                        let value = if trim { zeros.clone() } else { image(u, stamp) };
                        match &result {
                            Ok(()) if fua => {
                                model.write_fua(u, &value);
                                maybe.values.remove(&u);
                            }
                            Ok(()) => model.write(u, &value),
                            Err(_) => {
                                maybe.values.entry(u).or_default().insert(value);
                            }
                        }
                    }
                    if result.is_err() && mode != Mode::Faults {
                        return Err(format!(
                            "REQUEST-FAILED without faults\n{}",
                            history(&trace, &machines)
                        ));
                    }
                }
                55..=69 => {
                    let result = engine.flush().await;
                    trace.push(format!(
                        "flush -> {:?}",
                        result.as_ref().map_err(|e| e.to_string())
                    ));
                    match result {
                        // A failed write journaled before this barrier may
                        // have become durable with it: `maybe` stays.
                        Ok(()) => model.flush(),
                        Err(_) if mode == Mode::Faults => {}
                        Err(e) => {
                            return Err(format!(
                                "FLUSH-FAILED without faults: {e}\n{}",
                                history(&trace, &machines)
                            ))
                        }
                    }
                }
                70..=79 => {
                    let result = engine.checkpoint().await;
                    trace.push(format!(
                        "checkpoint -> {:?}",
                        result.as_ref().map_err(|e| e.to_string())
                    ));
                    if result.is_err() && mode != Mode::Faults {
                        return Err(format!(
                            "CHECKPOINT-FAILED without faults\n{}",
                            history(&trace, &machines)
                        ));
                    }
                }
                _ => {
                    let unit = rng.random_range(0..cfg.device_units);
                    match engine.read(off(unit), UNIT as usize).await {
                        Ok(actual) => {
                            if actual != model.read(unit)
                                && !maybe.values.get(&unit).is_some_and(|set| set.contains(&actual))
                            {
                                return Err(format!(
                                    "LIVE-READ: unit {unit} is neither the acknowledged value \
                                     nor a failed write\n{}",
                                    history(&trace, &machines)
                                ));
                            }
                        }
                        Err(_) if mode == Mode::Faults => {}
                        Err(e) => {
                            return Err(format!(
                                "READ-FAILED without faults: unit {unit}: {e}\n{}",
                                history(&trace, &machines)
                            ))
                        }
                    }
                }
            }
        }

        // End of the process, then up to three recoveries that die.
        let mut holder = Some(engine);
        let mut interrupted = 0;
        engine = loop {
            machines.kill();
            let crash = rng.random_range(0..100);
            let what = if crash < 30 {
                "restart"
            } else if crash < 80 {
                machines.root.crash(&mut rng);
                machines.witness.crash(&mut rng);
                "power loss"
            } else if independent && crash < 86 {
                machines.root.crash(&mut rng);
                "power loss of the backing machine only"
            } else if independent && crash < 92 {
                machines.witness.crash(&mut rng);
                "power loss of the witness machine only"
            } else {
                machines.root.crash_all_lost();
                machines.witness.crash_all_lost();
                "worst-case power loss"
            };
            // The dead process's tasks must be gone before a new process
            // starts: in this one-thread runtime the engine's worker ends
            // only when it is polled. Nothing it does can reach a machine
            // any more (every mutation fails, or its views are dead).
            if let Some(dead) = holder.take() {
                dead.stop_checkpoint_worker().await;
                drop(dead);
            }
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            machines.revive();
            trace.push(format!("cycle {cycle}: {what}"));
            if mode == Mode::RecoveryDeaths && interrupted < 3 && rng.random_bool(0.6) {
                // This recovery's process dies after `at` mutations (or, if
                // it needs fewer, right after it attached).
                interrupted += 1;
                let at = rng.random_range(0..260);
                machines.inj.countdown.store(at, Ordering::SeqCst);
                let attempt = attach(&machines, &cfg).await;
                trace.push(format!(
                    "recovery dying after {at} mutations -> {:?}",
                    attempt.as_ref().map(|_| ()).map_err(|e| e.clone())
                ));
                holder = attempt.ok();
                continue;
            }
            match attach(&machines, &cfg).await {
                Ok(attached) => break attached,
                Err(e) => {
                    return Err(format!(
                        "RECOVERY after {what}: {e}\n{}",
                        history(&trace, &machines)
                    ))
                }
            }
        };

        // Oracle.
        for unit in 0..cfg.device_units {
            let actual = match engine.read(off(unit), UNIT as usize).await {
                Ok(actual) => actual,
                Err(e) => {
                    return Err(format!(
                        "READ-AFTER-RECOVERY: cycle {cycle} unit {unit}: {e}\n{}",
                        history(&trace, &machines)
                    ))
                }
            };
            if let Err(violation) = model.crash_adopt(unit, &actual) {
                if maybe.values.get(&unit).is_some_and(|set| set.contains(&actual)) {
                    model.write_fua(unit, &actual);
                } else {
                    return Err(format!(
                        "ORACLE: cycle {cycle}: {violation}\n{}",
                        history(&trace, &machines)
                    ));
                }
            }
            maybe.values.remove(&unit);
        }
        trace.push(format!("cycle {cycle}: verified"));
    }
    Ok(())
}

async fn sweep(mode: Mode) {
    let start = env("AUDIT9_SEED_START", 0);
    let count = env("AUDIT9_SEED_COUNT", 40);
    let cycles = env("AUDIT9_CYCLES", 4) as usize;
    let budget = Duration::from_secs(env("AUDIT9_BUDGET_SECS", 240));
    let started = Instant::now();
    let mut failures: Vec<(u64, String)> = Vec::new();
    let mut ran = 0;
    for seed in start..start + count {
        if started.elapsed() > budget {
            break;
        }
        ran += 1;
        if let Err(violation) = run_seed(seed, mode, cycles).await {
            failures.push((seed, violation));
        }
    }
    let mut classes: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for (seed, text) in &failures {
        let class = text.split(':').next().unwrap_or("?").split('\n').next().unwrap().to_string();
        classes.entry(class).or_default().push(*seed);
    }
    println!(
        "AUDIT9-ROLLBACK mode={mode:?} seeds={start}..{} cycles={cycles} failures={} elapsed={:.0}s {classes:?}",
        start + ran,
        failures.len(),
        started.elapsed().as_secs_f64()
    );
    if let Some((seed, text)) = failures.first() {
        panic!(
            "{} of {ran} seeds failed ({classes:?}); first, seed {seed}:\n{text}",
            failures.len()
        );
    }
}

#[tokio::test]
async fn audit9_rollback_pair_survives_power_loss_cycles() {
    let _serial = maki_test_support::failpoints::test_lock();
    sweep(Mode::Clean).await;
}

#[tokio::test]
async fn audit9_rollback_pair_survives_interrupted_recoveries() {
    let _serial = maki_test_support::failpoints::test_lock();
    sweep(Mode::RecoveryDeaths).await;
}

#[tokio::test]
async fn audit9_rollback_pair_with_transient_faults_never_shows_foreign_data() {
    let _serial = maki_test_support::failpoints::test_lock();
    sweep(Mode::Faults).await;
}
