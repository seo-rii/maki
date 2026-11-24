//! Round 9 (r8-storage): verbatim copy of round 8's `audit8_recovery_interrupt.rs` from the dev branch,
//! re-run on the merged tree (1d4c7ea). Only this header was added.
//!
//! Audit (recovery-codecs): randomized journal/recovery sweep that, unlike
//! `review_r3b_durability`, also injects faults *during recovery itself*
//! (fail-stop at a random storage operation, followed by a power loss or a
//! plain restart) and partial journal `write_at`s during the workload.
//!
//! Oracle (conservative): after every successful recovery each unit must
//! hold a value written at or after its newest *durable* version (FUA
//! success for that unit, or a successful FLUSH after the write was
//! acknowledged); anything older or foreign is a durability violation. The
//! final, fault-free recovery must always succeed.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use uuid::Uuid;

use maki_backing::Backing;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::{failpoints, CrashableBacking};

const UNITS: u64 = 24;
/// [interrupted recoveries that failed, that succeeded, failed workload ops]
static STATS: [AtomicU64; 3] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];
/// Profile (tests are serialized by the failpoint lock): 0 = small records
/// and 3000-byte segments, 1 = records up to ~70 KiB (rewrite/scan chunk
/// boundaries) in 200 KB segments, 2 = the minimum segment size (every
/// record rolls).
static PROFILE: AtomicU64 = AtomicU64::new(0);

fn max_ct() -> usize {
    match PROFILE.load(Ordering::SeqCst) {
        1 => 70_016,
        _ => 640,
    }
}

fn geometry() -> Geometry {
    Geometry::compute(512, 512, 512, max_ct() as u32, UNITS * 512, 8 * 512).unwrap()
}

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xA0D1_7EC0),
        provider_type: "fake".into(),
        crypto_compatibility_id: "audit-profile".into(),
        key_identity: "k".into(),
        geometry: geometry(),
        format_version: 1,
        created_unix: 0,
    }
}

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: match PROFILE.load(Ordering::SeqCst) {
            1 => 200_000,
            2 => 1,
            _ => 3000,
        },
    }
}

fn value(unit: u64, stamp: u32, len: usize) -> Vec<u8> {
    let seed = (unit as u32).wrapping_mul(0x9E37_79B1) ^ stamp.wrapping_mul(0x85EB_CA6B);
    (0..len)
        .map(|i| (seed.wrapping_add(i as u32).wrapping_mul(0x2545_F491) >> 24) as u8)
        .collect()
}

/// Per unit: every version ever attempted since the unit was last settled,
/// and the index of the newest version known durable.
struct Oracle {
    versions: Vec<Vec<Option<Vec<u8>>>>,
    floor: Vec<usize>,
    /// Newest acknowledged (successful) version per unit.
    acked: Vec<usize>,
}

impl Oracle {
    fn new() -> Self {
        Self {
            versions: (0..UNITS).map(|_| vec![None]).collect(),
            floor: vec![0; UNITS as usize],
            acked: vec![0; UNITS as usize],
        }
    }
    fn attempt(&mut self, unit: u64, v: Option<Vec<u8>>) -> usize {
        let list = &mut self.versions[unit as usize];
        list.push(v);
        list.len() - 1
    }
    fn ack(&mut self, unit: u64, index: usize, fua: bool) {
        self.acked[unit as usize] = index;
        if fua {
            self.floor[unit as usize] = self.floor[unit as usize].max(index);
        }
    }
    fn flushed(&mut self) {
        for u in 0..UNITS as usize {
            self.floor[u] = self.floor[u].max(self.acked[u]);
        }
    }
    fn check_and_settle(&mut self, unit: u64, actual: Option<Vec<u8>>) -> Result<(), String> {
        let u = unit as usize;
        let ok = self.versions[u][self.floor[u]..]
            .iter()
            .any(|v| *v == actual);
        if !ok {
            let older = self.versions[u][..self.floor[u]]
                .iter()
                .any(|v| *v == actual);
            return Err(format!(
                "unit {unit}: recovered value is {} (floor index {}, {} versions)",
                if older {
                    "OLDER than its newest durable version"
                } else {
                    "foreign"
                },
                self.floor[u],
                self.versions[u].len()
            ));
        }
        self.versions[u] = vec![actual];
        self.floor[u] = 0;
        self.acked[u] = 0;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Mode {
    /// Workload: random sync / dirsync / remove failures and partial
    /// journal writes at `permille`.
    Workload { permille: u32 },
    /// Recovery: fail-stop from operation `at` on (everything fails).
    FailStop { at: u64 },
}

fn hook(
    seed: u64,
    mode: Mode,
    counter: Arc<AtomicU64>,
    log: Arc<Mutex<Vec<String>>>,
) -> maki_test_support::crash_backing::FaultHook {
    let rng = Mutex::new(StdRng::seed_from_u64(seed));
    Arc::new(move |op| {
        let n = counter.fetch_add(1, Ordering::SeqCst);
        match mode {
            Mode::FailStop { at } => {
                if n >= at {
                    if n == at {
                        log.lock().push(format!("FAIL-STOP at op {n}: {op:?}"));
                    }
                    return Some(io::Error::other("fail-stop"));
                }
                None
            }
            Mode::Workload { permille } => {
                let inject = match op {
                    FaultOp::SyncData { .. } | FaultOp::SyncDir { .. } | FaultOp::Remove { .. } => {
                        rng.lock().random_range(0..1000) < permille
                    }
                    FaultOp::WriteAt { .. } | FaultOp::SetLen { .. } | FaultOp::Open { .. } => {
                        rng.lock().random_range(0..1000) < permille / 4
                    }
                    _ => false,
                };
                if inject {
                    log.lock().push(format!("INJECTED {op:?}"));
                    Some(io::Error::other("injected failure"))
                } else {
                    None
                }
            }
        }
    })
}

fn partial_hook(
    seed: u64,
    permille: u32,
    log: Arc<Mutex<Vec<String>>>,
) -> maki_test_support::crash_backing::PartialWriteHook {
    let rng = Mutex::new(StdRng::seed_from_u64(seed));
    Arc::new(move |op| match op {
        // A torn *segment header* that the writer could not durably unlink
        // fails closed by design (review_journal_creation_cleanup.rs,
        // `an_unremoved_invalid_header_still_fails_closed_after_power_loss`),
        // so only record writes are made partial here.
        FaultOp::WriteAt {
            path, len, offset, ..
        } if path.starts_with("journal/seg-") && *len > 1 && *offset > 0 => {
            let mut rng = rng.lock();
            if rng.random_range(0..1000) < permille {
                let keep = rng.random_range(1..*len);
                log.lock().push(format!("PARTIAL {op:?} keep {keep}"));
                Some((keep, io::Error::other("injected partial write")))
            } else {
                None
            }
        }
        _ => None,
    })
}

fn recover(backing: &Arc<CrashableBacking>) -> Result<Volume, String> {
    Volume::recover(backing.process() as Arc<dyn Backing>, options()).map_err(|e| e.to_string())
}

fn sweep(seed: u64, cycles: usize, discard: bool, permille: u32) -> Result<(), String> {
    let mut rng = StdRng::seed_from_u64(seed.wrapping_mul(0x9E37_79B9).wrapping_add(77));
    let backing = Arc::new(CrashableBacking::new().with_tearing(64));
    if discard {
        init::create_volume_with_discard(backing.as_ref(), superblock()).unwrap();
    } else {
        init::create_volume(backing.as_ref(), superblock()).unwrap();
    }
    let log: Arc<Mutex<Vec<String>>> = Arc::default();
    let mut oracle = Oracle::new();
    let mut stamp = 0u32;
    let mut volume = recover(&backing).unwrap();
    let report = |log: &Arc<Mutex<Vec<String>>>| log.lock().join("\n  ");

    for cycle in 0..cycles {
        let counter = Arc::new(AtomicU64::new(0));
        // Half of the cycles end in a fail-stop (a power loss in the middle
        // of whatever storage operation was running) instead of random
        // recoverable faults.
        let mode = if rng.random_bool(0.5) {
            Mode::FailStop {
                at: rng.random_range(0..1500),
            }
        } else {
            Mode::Workload { permille }
        };
        backing.set_fault_hook(Some(hook(
            seed ^ (cycle as u64) << 8,
            mode,
            counter,
            log.clone(),
        )));
        backing.set_partial_write_hook(Some(partial_hook(
            seed ^ 0x5A5A ^ (cycle as u64),
            permille,
            log.clone(),
        )));
        for _ in 0..rng.random_range(6..40) {
            match rng.random_range(0..100) {
                0..=59 => {
                    let unit = rng.random_range(0..UNITS);
                    let fua = rng.random_bool(0.25);
                    stamp += 1;
                    let len = rng.random_range(1..=max_ct());
                    let v = value(unit, stamp, len);
                    let index = oracle.attempt(unit, Some(v.clone()));
                    let r = volume.write_ct(unit, &v, fua);
                    log.lock().push(format!(
                        "write unit {unit} len {len} stamp {stamp} fua {fua} -> {:?}",
                        r.as_ref().map_err(|e| e.to_string())
                    ));
                    if r.is_ok() {
                        oracle.ack(unit, index, fua);
                    } else {
                        STATS[2].fetch_add(1, Ordering::Relaxed);
                    }
                }
                60..=67 if discard => {
                    let unit = rng.random_range(0..UNITS);
                    let fua = rng.random_bool(0.25);
                    let index = oracle.attempt(unit, None);
                    let r = volume.discard_ct(unit, fua);
                    log.lock().push(format!(
                        "discard unit {unit} fua {fua} -> {:?}",
                        r.as_ref().map_err(|e| e.to_string())
                    ));
                    if r.is_ok() {
                        oracle.ack(unit, index, fua);
                    }
                }
                68..=84 => {
                    let r = volume.flush();
                    log.lock().push(format!(
                        "flush -> {:?}",
                        r.as_ref().map_err(|e| e.to_string())
                    ));
                    if r.is_ok() {
                        oracle.flushed();
                    }
                }
                _ => {
                    let r = volume.checkpoint();
                    log.lock().push(format!(
                        "checkpoint -> {:?}",
                        r.as_ref().map_err(|e| e.to_string())
                    ));
                }
            }
        }
        backing.set_fault_hook(None);
        backing.set_partial_write_hook(None);
        drop(volume);
        if rng.random_bool(0.6) {
            backing.crash(&mut rng);
            log.lock().push("power loss".into());
        } else {
            log.lock().push("restart".into());
        }

        // Interrupted recoveries: fail-stop at a random operation, then a
        // power loss or a restart, a few times in a row.
        for attempt in 0..rng.random_range(0..4) {
            let counter = Arc::new(AtomicU64::new(0));
            let at = if rng.random_bool(0.5) {
                rng.random_range(0..60)
            } else {
                rng.random_range(0..600)
            };
            backing.set_fault_hook(Some(hook(0, Mode::FailStop { at }, counter, log.clone())));
            let r = recover(&backing);
            backing.set_fault_hook(None);
            log.lock().push(format!(
                "interrupted recovery {attempt} (fail-stop at {at}) -> {:?}",
                r.as_ref().map(|_| ())
            ));
            if r.is_err() {
                STATS[0].fetch_add(1, Ordering::Relaxed);
            } else {
                STATS[1].fetch_add(1, Ordering::Relaxed);
            }
            drop(r);
            if rng.random_bool(0.5) {
                backing.crash(&mut rng);
                log.lock().push("power loss during recovery".into());
            } else {
                log.lock().push("restart during recovery".into());
            }
        }

        volume = match recover(&backing) {
            Ok(v) => v,
            Err(e) => {
                return Err(format!(
                    "seed {seed} cycle {cycle}: fault-free recovery refused: {e}\n  {}",
                    report(&log)
                ))
            }
        };
        assert!(volume.checkpoint_sequence() <= volume.journal_durable_sequence());
        for unit in 0..UNITS {
            let actual = match volume.read_ct(unit) {
                Ok(v) => v.map(|(_, bytes)| bytes),
                Err(e) => {
                    return Err(format!(
                    "seed {seed} cycle {cycle}: unit {unit} unreadable after recovery: {e}\n  {}",
                    report(&log)
                ))
                }
            };
            if let Err(violation) = oracle.check_and_settle(unit, actual) {
                return Err(format!(
                    "seed {seed} cycle {cycle}: {violation}\n  {}",
                    report(&log)
                ));
            }
        }
        log.lock().push(format!("cycle {cycle} verified"));
    }
    Ok(())
}

fn run(seeds: std::ops::Range<u64>, cycles: usize, discard: bool, permille: u32) {
    run_profile(0, seeds, cycles, discard, permille)
}

fn run_profile(
    profile: u64,
    seeds: std::ops::Range<u64>,
    cycles: usize,
    discard: bool,
    permille: u32,
) {
    let _guard = failpoints::test_lock();
    PROFILE.store(profile, Ordering::SeqCst);
    let mut failures = Vec::new();
    // Audit round 4: AUDIT4_RI_MULT scales the seed count, AUDIT4_RI_OFFSET
    // shifts the seeds (both default to the original ranges).
    let env = |k: &str, d: u64| {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    // Round 8: AUDIT8_SEED_COUNT (seeds per test, overrides the multiplier)
    // and AUDIT8_SEED_START (offset added to the original first seed).
    let len = env(
        "AUDIT8_SEED_COUNT",
        (seeds.end - seeds.start) * env("AUDIT4_RI_MULT", 1),
    );
    let first = seeds.start + env("AUDIT8_SEED_START", env("AUDIT4_RI_OFFSET", 0));
    let seeds = first..first + len;
    for seed in seeds {
        let outcome = std::panic::catch_unwind(|| sweep(seed, cycles, discard, permille));
        match outcome {
            Ok(Ok(())) => {}
            Ok(Err(e)) => failures.push(e),
            Err(panic) => failures.push(format!(
                "seed {seed}: panic: {}",
                panic
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default()
            )),
        }
    }
    eprintln!(
        "stats (profile {profile}, discard {discard}, permille {permille}): interrupted recoveries failed {} / succeeded {}; failed workload writes {}",
        STATS[0].load(Ordering::Relaxed),
        STATS[1].load(Ordering::Relaxed),
        STATS[2].load(Ordering::Relaxed)
    );
    if !failures.is_empty() {
        let shown: Vec<String> = failures
            .iter()
            .take(2)
            .map(|f| f.chars().take(20000).collect())
            .collect();
        panic!(
            "{} failing seed(s); first:\n{}",
            failures.len(),
            shown.join("\n\n=====\n\n")
        );
    }
}

#[test]
fn v2_interrupted_recovery_without_workload_faults() {
    run(0..150, 6, false, 0);
}

#[test]
fn v2_interrupted_recovery_with_workload_faults() {
    run(1000..1150, 6, false, 80);
}

#[test]
fn v3_interrupted_recovery_without_workload_faults() {
    run(2000..2150, 6, true, 0);
}

#[test]
fn v3_interrupted_recovery_with_workload_faults() {
    run(3000..3150, 6, true, 80);
}

#[test]
fn large_records_interrupted_recovery() {
    run_profile(1, 4000..4040, 5, false, 60);
    run_profile(1, 4100..4140, 5, true, 60);
}

#[test]
fn every_record_rolls_interrupted_recovery() {
    run_profile(2, 5000..5100, 5, false, 60);
    run_profile(2, 5100..5200, 5, true, 60);
}

/// Reproduce one seed with its full trace:
/// `AUDIT_SEED=3032 AUDIT_DISCARD=1 AUDIT_PERMILLE=80 cargo test ... -- --ignored single_seed`
#[test]
#[ignore]
fn single_seed() {
    let _guard = failpoints::test_lock();
    let env = |k: &str, d: u64| {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    let seed = env("AUDIT_SEED", 0);
    let discard = env("AUDIT_DISCARD", 0) == 1;
    let permille = env("AUDIT_PERMILLE", 0) as u32;
    let cycles = env("AUDIT_CYCLES", 6) as usize;
    PROFILE.store(env("AUDIT_PROFILE", 0), Ordering::SeqCst);
    if let Err(e) = sweep(seed, cycles, discard, permille) {
        panic!("{e}");
    }
}
