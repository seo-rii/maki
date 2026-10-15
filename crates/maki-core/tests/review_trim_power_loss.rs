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
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_test_support::crash_backing::{FaultHook, FaultOp};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::{CrashableBacking, ReferenceBlockModel};

const UNIT: u32 = 512;
const DEVICE_UNITS: u64 = 48;
/// A tiny journal and shard: rolls, checkpoints and reclamation all happen
/// constantly, not only when asked.
const SHARD_BYTES: u64 = 8 * UNIT as u64;

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

async fn try_attach(backing: &Arc<CrashableBacking>) -> Result<Engine, AttachError> {
    if !backing.exists("superblock.a").unwrap() {
        init::create_volume_with_discard(backing.as_ref(), superblock()).unwrap();
    }
    Engine::attach(
        backing.clone() as Arc<dyn Backing>,
        Arc::new(FakeCryptoProvider::new(UNIT)),
        EngineOptions {
            checkpoint: CheckpointPolicy {
                emergency_reserve_bytes: 0,
                ..Default::default()
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

async fn sweep(seed: u64, cycles: usize, fault_permille: u32) {
    let mut rng = StdRng::seed_from_u64(seed.wrapping_mul(0x51_7CC1_B727).wrapping_add(7));
    let backing = Arc::new(CrashableBacking::new().with_tearing(128));
    let mut model = ReferenceBlockModel::new(UNIT as usize, DEVICE_UNITS);
    let mut maybe = Maybe::default();
    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    let mut stamp = 0u32;
    let mut engine = try_attach(&backing).await.unwrap();
    let history = |log: &Arc<Mutex<Vec<String>>>| log.lock().join("\n  ");

    for cycle in 0..cycles {
        if fault_permille > 0 {
            backing.set_fault_hook(Some(sync_faults(
                seed ^ cycle as u64,
                fault_permille,
                log.clone(),
            )));
        }
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
        engine.stop_checkpoint_worker().await;
        drop(engine);
        let what = if rng.random_bool(0.7) {
            backing.crash(&mut rng);
            log.lock().push("power loss".into());
            format!("seed {seed} cycle {cycle} (power loss)")
        } else {
            log.lock().push("restart".into());
            format!("seed {seed} cycle {cycle} (restart)")
        };
        engine = match try_attach(&backing).await {
            Ok(engine) => engine,
            Err(e) => panic!(
                "{what}: recovery refused the volume: {e}\n  {}",
                history(&log)
            ),
        };
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
}

#[tokio::test]
async fn writes_and_trims_survive_power_loss_and_restart_cycles() {
    let _serial = maki_test_support::failpoints::test_lock();
    for seed in 0..24 {
        sweep(seed, 6, 0).await;
    }
}

#[tokio::test]
async fn writes_and_trims_with_sync_failures_never_show_foreign_data() {
    let _serial = maki_test_support::failpoints::test_lock();
    for seed in 0..24 {
        sweep(1000 + seed, 6, 120).await;
    }
}

#[tokio::test]
#[ignore = "release gate: long randomized trim durability sweep"]
async fn trim_power_loss_gate_full() {
    let _serial = maki_test_support::failpoints::test_lock();
    for seed in 0..400 {
        sweep(seed, 10, if seed % 2 == 0 { 0 } else { 120 }).await;
    }
}
