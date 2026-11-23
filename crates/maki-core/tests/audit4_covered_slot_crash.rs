//! Audit round 4 (storage-review): randomized Volume-level crash sweep aimed
//! at the checkpoint-evidence check added by #194 (`verify_checkpoint_slots`
//! compares slot metadata with the last surviving covered journal record),
//! the bounded replay checkpoint, idle/cleanup checkpoints (#268) and the
//! deep check agreeing with recovery. Small segments make many covered
//! survivors; injected `remove`/`sync_dir`/`sync_data`/`write_at` failures
//! leave checkpoint cleanup pending and syncs uncertain (Linux model);
//! crashes tear any unsynced write. Every crash state must recover without a
//! corruption verdict, the deep check must agree, and every unit must read a
//! value the durability rules allow.

use std::collections::BTreeMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use maki_core::volume::{Volume, VolumeOptions};
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::CrashableBacking;

const UNITS: u64 = 12;
const SEGMENT: u64 = 1600;

#[derive(Default)]
struct Model {
    /// Values that may be the durable value of a unit (None = zeros).
    durable: BTreeMap<u64, Vec<Option<Vec<u8>>>>,
    /// Values written since the last barrier, with whether the append was
    /// acknowledged (a failed operation may or may not have appended).
    pending: BTreeMap<u64, Vec<(Option<Vec<u8>>, bool)>>,
}

impl Model {
    fn write(&mut self, unit: u64, value: Option<Vec<u8>>, certain: bool) {
        self.pending.entry(unit).or_default().push((value, certain));
    }
    fn durable_set(&self, unit: u64) -> Vec<Option<Vec<u8>>> {
        self.durable.get(&unit).cloned().unwrap_or_else(|| vec![None])
    }
    /// Every appended record became durable (FLUSH / FUA success).
    fn barrier(&mut self) {
        for (unit, values) in std::mem::take(&mut self.pending) {
            let mut set = self.durable_set(unit);
            for (value, certain) in values {
                if certain {
                    set = vec![value];
                } else if !set.contains(&value) {
                    set.push(value);
                }
            }
            self.durable.insert(unit, set);
        }
    }
    fn allowed(&self, unit: u64) -> Vec<Option<Vec<u8>>> {
        let mut out = self.durable_set(unit);
        if let Some(values) = self.pending.get(&unit) {
            out.extend(values.iter().map(|(v, _)| v.clone()));
        }
        out
    }
    fn adopt(&mut self, unit: u64, value: Option<Vec<u8>>) {
        self.pending.remove(&unit);
        self.durable.insert(unit, vec![value]);
    }
}

fn geometry() -> Geometry {
    Geometry::compute(512, 512, 512, 520, UNITS * 512, 4 * 512).unwrap()
}

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: SEGMENT,
    }
}

struct Faults {
    rng: Mutex<StdRng>,
    /// Probability in 1/1000.
    rate: AtomicU64,
    /// Process death after this many more mutating operations (0 = off).
    death: AtomicU64,
    /// The process is dead: every operation fails and changes nothing.
    dead: std::sync::atomic::AtomicBool,
}

fn install_faults(backing: &CrashableBacking, faults: Arc<Faults>) {
    backing.set_fault_hook(Some(Arc::new(move |op| {
        if faults.dead.load(Ordering::SeqCst) {
            return Some(io::Error::other("process dead"));
        }
        let mutating = matches!(
            op,
            FaultOp::WriteAt { .. }
                | FaultOp::SetLen { .. }
                | FaultOp::SyncData { .. }
                | FaultOp::SyncDir { .. }
                | FaultOp::Remove { .. }
                | FaultOp::Rename { .. }
                | FaultOp::Open { create: true, .. }
        );
        if mutating {
            let left = faults.death.load(Ordering::SeqCst);
            if left == 1 {
                faults.death.store(0, Ordering::SeqCst);
                faults.dead.store(true, Ordering::SeqCst);
                return Some(io::Error::other("process dead"));
            } else if left > 1 {
                faults.death.store(left - 1, Ordering::SeqCst);
            }
        }
        let rate = faults.rate.load(Ordering::SeqCst);
        if rate == 0 {
            return None;
        }
        let eligible = match op {
            FaultOp::SyncDir { .. } => true,
            FaultOp::SyncData { .. } => true,
            FaultOp::Remove { path } => path.starts_with("journal/"),
            FaultOp::WriteAt { path, .. } => !path.ends_with("durable-mark"),
            FaultOp::SetLen { .. } => true,
            _ => false,
        };
        if eligible && faults.rng.lock().random_range(0..1000) < rate {
            Some(io::Error::other("injected EIO"))
        } else {
            None
        }
    })));
}

fn payload(rng: &mut StdRng) -> Vec<u8> {
    let len = rng.random_range(1..=520usize);
    let byte = rng.random::<u8>() | 1;
    vec![byte; len]
}

fn deep_errors(view: Arc<CrashableBacking>) -> Result<Vec<String>, String> {
    match maki_core::check::deep_check(view, SEGMENT) {
        Ok(report) => Ok(report
            .errors
            .into_iter()
            .filter(|e| !e.contains("key canary"))
            .collect()),
        Err(e) => Err(e.to_string()),
    }
}

fn run_seed(seed: u64, steps: usize, discard: bool, deaths: bool) -> Result<(), String> {
    let mut rng = StdRng::seed_from_u64(seed);
    let base = CrashableBacking::new().with_tearing(512);
    let superblock = Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(0xa4c0_0000 + seed as u128),
        provider_type: "fake".into(),
        crypto_compatibility_id: "covered-slot".into(),
        key_identity: "k".into(),
        geometry: geometry(),
        format_version: 1,
        created_unix: 0,
    };
    if discard {
        init::create_volume_with_discard(&base, superblock).unwrap();
    } else {
        init::create_volume(&base, superblock).unwrap();
    }
    let faults = Arc::new(Faults {
        rng: Mutex::new(StdRng::seed_from_u64(seed ^ 0x5eed)),
        rate: AtomicU64::new(0),
        death: AtomicU64::new(0),
        dead: std::sync::atomic::AtomicBool::new(false),
    });
    install_faults(&base, faults.clone());
    let mut model = Model::default();
    let mut volume = Volume::recover(base.process(), options()).map_err(|e| format!("{e}"))?;
    let mut log = Vec::new();

    for step in 0..steps {
        faults.rate.store(
            if rng.random_bool(0.3) { rng.random_range(5..120) } else { 0 },
            Ordering::SeqCst,
        );
        if deaths && rng.random_bool(0.15) {
            faults.death.store(rng.random_range(1..40), Ordering::SeqCst);
        }
        let choice = if faults.dead.load(Ordering::SeqCst) { 99 } else { rng.random_range(0..100) };
        if choice < 45 {
            let unit = rng.random_range(0..UNITS);
            let data = payload(&mut rng);
            let fua = rng.random_bool(0.2);
            let r = volume.write_ct(unit, &data, fua);
            log.push(format!("{step}: write u{unit} len {} fua {fua} -> {:?}", data.len(), r.as_ref().map(|_| ())));
            model.write(unit, Some(data), r.is_ok());
            if r.is_ok() && fua {
                model.barrier();
            }
        } else if choice < 55 && discard {
            let unit = rng.random_range(0..UNITS);
            let fua = rng.random_bool(0.2);
            let before = volume.journal_appended_sequence();
            let r = volume.discard_ct(unit, fua);
            let appended = volume.journal_appended_sequence() > before;
            log.push(format!(
                "{step}: discard u{unit} fua {fua} appended {appended} -> {:?}",
                r.as_ref().map(|_| ())
            ));
            model.write(unit, None, r.is_ok());
            if r.is_ok() && fua {
                if appended {
                    model.barrier();
                } else {
                    // FUA covers this request only: an already-zero unit
                    // needs no record and no journal sync.
                    model.adopt(unit, None);
                }
            }
        } else if choice < 70 {
            let r = volume.flush();
            log.push(format!("{step}: flush -> {r:?}"));
            if r.is_ok() {
                model.barrier();
            }
        } else if choice < 88 {
            let r = volume.checkpoint();
            log.push(format!("{step}: checkpoint -> {r:?}"));
        } else {
            // Crash or restart, then check and recover.
            faults.rate.store(0, Ordering::SeqCst);
            faults.death.store(0, Ordering::SeqCst);
            let kind = rng.random_range(0..3);
            drop(volume);
            match kind {
                0 => base.crash(&mut rng),
                1 => base.crash_all_lost(),
                _ => {} // plain restart
            }
            faults.dead.store(false, Ordering::SeqCst);
            log.push(format!("{step}: crash kind {kind}"));
            // Interrupted recoveries: die at a random mutation, then crash
            // or restart again.
            for attempt in 0..3 {
                if !deaths || !rng.random_bool(0.4) {
                    break;
                }
                faults.death.store(rng.random_range(1..60), Ordering::SeqCst);
                let r = Volume::recover(base.process(), options());
                faults.death.store(0, Ordering::SeqCst);
                let died = faults.dead.load(Ordering::SeqCst);
                drop(r);
                let kind = rng.random_range(0..3);
                match kind {
                    0 => base.crash(&mut rng),
                    1 => base.crash_all_lost(),
                    _ => {}
                }
                faults.dead.store(false, Ordering::SeqCst);
                log.push(format!("{step}: recovery attempt {attempt} died {died}, crash kind {kind}"));
            }
            let deep = deep_errors(base.process());
            let recovered = Volume::recover(base.process(), options());
            match (&deep, &recovered) {
                (Ok(errors), Ok(_)) if errors.is_empty() => {}
                _ => {
                    return Err(format!(
                        "seed {seed} step {step}: deep check {deep:?}; recovery {:?}\n{}",
                        recovered.as_ref().err(),
                        log.join("\n")
                    ))
                }
            }
            volume = recovered.unwrap();
            for unit in 0..UNITS {
                let got = volume
                    .read_ct(unit)
                    .map_err(|e| format!("seed {seed} step {step}: read u{unit}: {e}\n{}", log.join("\n")))?
                    .map(|(_, data)| data);
                let allowed = model.allowed(unit);
                if !allowed.contains(&got) {
                    return Err(format!(
                        "seed {seed} step {step}: unit {unit} read {:?} not in allowed {:?}\n{}",
                        got.as_ref().map(|d| (d.len(), d[0])),
                        allowed
                            .iter()
                            .map(|v| v.as_ref().map(|d| (d.len(), d[0])))
                            .collect::<Vec<_>>(),
                        log.join("\n")
                    ));
                }
                model.adopt(unit, got);
            }
        }
    }
    drop(volume);
    Ok(())
}

fn sweep(discard: bool, deaths: bool, seeds: std::ops::Range<u64>, steps: usize) {
    let mut failures = Vec::new();
    for seed in seeds {
        if let Err(e) = run_seed(seed, steps, discard, deaths) {
            eprintln!("{e}\n----");
            failures.push(seed);
            if failures.len() >= 3 {
                break;
            }
        }
    }
    assert!(failures.is_empty(), "failing seeds: {failures:?}");
}

#[test]
fn covered_slot_sweep_v3() {
    let n: u64 = std::env::var("AUDIT4_SEEDS").ok().and_then(|s| s.parse().ok()).unwrap_or(150);
    sweep(true, false, 0..n, 160);
}

#[test]
fn covered_slot_sweep_v2() {
    let n: u64 = std::env::var("AUDIT4_SEEDS").ok().and_then(|s| s.parse().ok()).unwrap_or(150);
    sweep(false, false, 10_000..10_000 + n, 160);
}

#[test]
fn covered_slot_death_sweep_v3() {
    let n: u64 = std::env::var("AUDIT4_SEEDS").ok().and_then(|s| s.parse().ok()).unwrap_or(150);
    sweep(true, true, 20_000..20_000 + n, 200);
}

#[test]
fn covered_slot_death_sweep_v2() {
    let n: u64 = std::env::var("AUDIT4_SEEDS").ok().and_then(|s| s.parse().ok()).unwrap_or(150);
    sweep(false, true, 30_000..30_000 + n, 200);
}
