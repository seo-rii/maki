//! Audit sweep (empirical durability hunt). Not part of the maintained
//! suite: an auditor's randomized harness over the engine.
//!
//! What it explores beyond `review_r3b_durability.rs`:
//! - journal segment sizes small enough that automatic rolls happen on
//!   (almost) every append, hard journal limits and overlay bounds small
//!   enough that inline reclaim checkpoints run constantly;
//! - geometries with one unit per shard, a partial last shard, units larger
//!   than the device block (read-modify-write, writes spanning units);
//! - v3 (discard) volumes with TRIM and WRITE_ZEROES mixed into the workload;
//! - a *death* at an arbitrary backing operation in the middle of a request
//!   or of recovery itself (every later backing mutation fails, then power is
//!   lost or the process restarts);
//! - a crash right after a recovery, before any write;
//! - transient failures of every backing mutation (data sync, directory
//!   sync, write, short write, truncate, remove, create), with the Linux
//!   failed-fsync model, and a "heal" check once the faults stop.
//!
//! The oracle is `ReferenceBlockModel` at crypto-unit granularity. A failed
//! request is resolved at once by reading the touched units back (each must
//! show the old or the new image) so the model always knows the exact live
//! image; the request that was in flight when the backing died may surface
//! or not.

#![allow(clippy::await_holding_lock)]
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use uuid::Uuid;

use maki_backing::Backing;
use maki_core::engine::{
    AttachError, CheckpointPolicy, Engine, EngineCacheConfig, EngineLimits, EngineOptions,
};
use maki_core::error::CoreError;
use maki_core::volume::VolumeOptions;
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_test_support::crash_backing::{FaultHook, FaultOp, PartialWriteHook};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::{CrashableBacking, ReferenceBlockModel};

// ---------------------------------------------------------------------------
// Configuration space

#[derive(Clone, Debug)]
pub struct Cfg {
    pub name: &'static str,
    pub block: u32,
    pub unit: u32,
    pub device_units: u64,
    pub units_per_shard: u64,
    /// `VolumeOptions::journal_segment_size` (the writer floors it at 112).
    pub segment_size: u64,
    pub journal_max_bytes: u64,
    pub max_pending_bytes: u64,
    pub max_overlay_bytes: u64,
    pub max_overlay_entries: u64,
    pub max_request_units: u64,
    pub discard: bool,
    /// `Some(verify_on_hit)` enables a tiny plaintext cache.
    pub cache: Option<bool>,
    pub tear: usize,
}

impl Cfg {
    fn record_len(&self) -> u64 {
        32 + self.unit as u64 + 8
    }

    fn superblock(&self) -> Superblock {
        Superblock {
            generation: 0,
            volume_uuid: Uuid::from_u128(0xA0D1_7000 + self.unit as u128),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(
                self.block,
                self.unit,
                512,
                self.unit + 8,
                self.device_units * self.unit as u64,
                self.units_per_shard * self.unit as u64,
            )
            .unwrap(),
            format_version: 1,
            created_unix: 0,
        }
    }

    fn options(&self) -> EngineOptions {
        EngineOptions {
            volume: VolumeOptions {
                journal_segment_size: self.segment_size,
            },
            limits: EngineLimits {
                max_request_bytes: self.max_request_units * self.unit as u64,
                max_overlay_bytes: self.max_overlay_bytes,
                max_overlay_entries: self.max_overlay_entries,
                ..EngineLimits::default()
            },
            cache: self.cache.map(|verify_on_hit| EngineCacheConfig {
                max_bytes: 6 * self.unit as u64,
                ttl: Duration::from_secs(3600),
                verify_on_hit,
            }),
            checkpoint: CheckpointPolicy {
                journal_high_watermark_bytes: u64::MAX,
                journal_max_bytes: self.journal_max_bytes,
                max_pending_bytes: self.max_pending_bytes,
                emergency_reserve_bytes: 0,
                low_space_checkpoint_bytes: 0,
                interval: Duration::from_secs(3600),
            },
            ..EngineOptions::default()
        }
    }
}

const BIG: u64 = 1 << 40;

pub fn cfg(name: &str) -> Cfg {
    let base = Cfg {
        name: "base",
        block: 512,
        unit: 512,
        device_units: 48,
        units_per_shard: 8,
        segment_size: 256 << 20,
        journal_max_bytes: BIG,
        max_pending_bytes: BIG,
        max_overlay_bytes: 0,
        max_overlay_entries: 0,
        max_request_units: 8,
        discard: false,
        cache: None,
        tear: 128,
    };
    let rec = |unit: u64| 32 + unit + 8;
    match name {
        // One record per segment: every append rolls.
        "seg1" => Cfg {
            name: "seg1",
            segment_size: 0,
            ..base
        },
        "seg1-v3" => Cfg {
            name: "seg1-v3",
            segment_size: 0,
            discard: true,
            ..base
        },
        // Three records per segment, a hard limit of about four segments
        // and a pending bound of two records: inline syncs and inline
        // reclaim checkpoints all the time.
        "seg3-tight" => Cfg {
            name: "seg3-tight",
            segment_size: 48 + 3 * rec(512),
            journal_max_bytes: 4 * (48 + 3 * rec(512)),
            max_pending_bytes: 2 * rec(512),
            ..base
        },
        "seg3-tight-v3" => Cfg {
            name: "seg3-tight-v3",
            segment_size: 48 + 3 * rec(512),
            journal_max_bytes: 4 * (48 + 3 * rec(512)),
            max_pending_bytes: 2 * rec(512),
            discard: true,
            ..base
        },
        // 37 units, 5 per shard: the last shard holds 2 units. Unit twice
        // the block size: half-unit writes.
        "odd" => Cfg {
            name: "odd",
            unit: 1024,
            device_units: 37,
            units_per_shard: 5,
            segment_size: 48 + 2 * rec(1024) + 100,
            journal_max_bytes: 6 * (48 + 2 * rec(1024) + 100),
            max_pending_bytes: rec(1024),
            ..base
        },
        "odd-v3" => Cfg {
            name: "odd-v3",
            unit: 1024,
            device_units: 37,
            units_per_shard: 5,
            segment_size: 48 + 2 * rec(1024) + 100,
            journal_max_bytes: 6 * (48 + 2 * rec(1024) + 100),
            max_pending_bytes: rec(1024),
            discard: true,
            ..base
        },
        // One unit per shard: every unit has its own data file, allocation
        // map and (v3) discard map.
        "shard1" => Cfg {
            name: "shard1",
            device_units: 13,
            units_per_shard: 1,
            segment_size: 48 + 2 * rec(512),
            journal_max_bytes: 5 * (48 + 2 * rec(512)),
            ..base
        },
        "shard1-v3" => Cfg {
            name: "shard1-v3",
            device_units: 13,
            units_per_shard: 1,
            segment_size: 48 + 2 * rec(512),
            journal_max_bytes: 5 * (48 + 2 * rec(512)),
            discard: true,
            ..base
        },
        // 4 KiB units over 512-byte blocks, 3 units per shard, 22 units
        // (last shard: 1 unit), tiny overlay bounds.
        "rmw" => Cfg {
            name: "rmw",
            unit: 4096,
            device_units: 22,
            units_per_shard: 3,
            segment_size: 48 + 2 * rec(4096),
            journal_max_bytes: BIG,
            max_overlay_entries: 5,
            max_overlay_bytes: 12 * (4096 + 8),
            max_request_units: 4,
            tear: 512,
            ..base
        },
        "rmw-v3" => Cfg {
            name: "rmw-v3",
            unit: 4096,
            device_units: 22,
            units_per_shard: 3,
            segment_size: 48 + 2 * rec(4096),
            journal_max_bytes: BIG,
            max_overlay_entries: 5,
            max_overlay_bytes: 12 * (4096 + 8),
            max_request_units: 4,
            discard: true,
            tear: 512,
            ..base
        },
        // Plaintext cache variants.
        "seg3-cache-v3" => Cfg {
            name: "seg3-cache-v3",
            segment_size: 48 + 3 * rec(512),
            journal_max_bytes: 4 * (48 + 3 * rec(512)),
            max_pending_bytes: 2 * rec(512),
            discard: true,
            cache: Some(false),
            ..base
        },
        "rmw-cache" => Cfg {
            name: "rmw-cache",
            unit: 4096,
            device_units: 22,
            units_per_shard: 3,
            segment_size: 48 + 2 * rec(4096),
            max_request_units: 4,
            cache: Some(true),
            tear: 512,
            ..base
        },
        // The shape of the existing sweep (no rolls), for comparison.
        "plain" => Cfg {
            name: "plain",
            ..base
        },
        "plain-v3" => Cfg {
            name: "plain-v3",
            discard: true,
            ..base
        },
        other => panic!("unknown cfg {other}"),
    }
}

#[derive(Clone, Debug, Default)]
pub struct Mode {
    pub name: &'static str,
    // Transient faults, permille per backing operation.
    pub sync_data: u32,
    pub sync_dir: u32,
    pub write: u32,
    pub partial: u32,
    pub set_len: u32,
    pub remove: u32,
    pub rename: u32,
    pub create: u32,
    /// Percent of cycles in which the backing dies in the middle of the
    /// workload (never combined with transient faults in the same cycle).
    pub midop_death_pct: u32,
    /// Percent chance (per attempt, up to three) that recovery itself dies.
    pub recovery_death_pct: u32,
    /// Percent chance of crashing again right after a clean recovery.
    pub double_crash_pct: u32,
    /// A plain restart must show every acknowledged write.
    pub strict_restart: bool,
    /// Percent of operations replaced by a "faults stop: FLUSH and
    /// checkpoint must work again" check.
    pub heal_pct: u32,
}

impl Mode {
    fn transient(&self) -> bool {
        self.sync_data
            + self.sync_dir
            + self.write
            + self.partial
            + self.set_len
            + self.remove
            + self.rename
            + self.create
            > 0
    }
}

pub fn mode(name: &str) -> Mode {
    match name {
        "crash" => Mode {
            name: "crash",
            strict_restart: true,
            double_crash_pct: 20,
            ..Mode::default()
        },
        "death" => Mode {
            name: "death",
            strict_restart: true,
            midop_death_pct: 60,
            recovery_death_pct: 45,
            double_crash_pct: 20,
            ..Mode::default()
        },
        "sync" => Mode {
            name: "sync",
            strict_restart: true,
            sync_data: 120,
            sync_dir: 120,
            heal_pct: 4,
            double_crash_pct: 10,
            ..Mode::default()
        },
        "chaos" => Mode {
            name: "chaos",
            strict_restart: true,
            sync_data: 60,
            sync_dir: 60,
            write: 30,
            partial: 30,
            set_len: 30,
            remove: 60,
            rename: 30,
            create: 30,
            heal_pct: 4,
            double_crash_pct: 10,
            ..Mode::default()
        },
        "chaos-death" => Mode {
            name: "chaos-death",
            strict_restart: true,
            sync_data: 60,
            sync_dir: 60,
            write: 30,
            partial: 30,
            set_len: 30,
            remove: 60,
            rename: 30,
            create: 30,
            heal_pct: 4,
            midop_death_pct: 35,
            recovery_death_pct: 35,
            double_crash_pct: 10,
        },
        other => panic!("unknown mode {other}"),
    }
}

// ---------------------------------------------------------------------------
// Fault injection

struct Injector {
    mode: Mode,
    /// Transient faults are live.
    enabled: AtomicBool,
    /// Every backing mutation fails from now on.
    dead: AtomicBool,
    /// Mutations left before death; negative = not armed.
    countdown: AtomicI64,
    mutations: AtomicU64,
    rng: Mutex<StdRng>,
    log: Arc<Mutex<Vec<String>>>,
}

impl Injector {
    fn new(mode: Mode, seed: u64, log: Arc<Mutex<Vec<String>>>) -> Arc<Self> {
        Arc::new(Self {
            mode,
            enabled: AtomicBool::new(false),
            dead: AtomicBool::new(false),
            countdown: AtomicI64::new(-1),
            mutations: AtomicU64::new(0),
            rng: Mutex::new(StdRng::seed_from_u64(seed ^ 0xFA17_FA17)),
            log,
        })
    }

    fn is_dead(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }

    fn arm(&self, mutations: u64) {
        self.countdown.store(mutations as i64, Ordering::SeqCst);
    }

    fn revive(&self) {
        self.countdown.store(-1, Ordering::SeqCst);
        self.dead.store(false, Ordering::SeqCst);
    }

    fn mutations(&self) -> u64 {
        self.mutations.load(Ordering::SeqCst)
    }

    fn hook(self: &Arc<Self>) -> FaultHook {
        let me = self.clone();
        Arc::new(move |op| {
            if matches!(op, FaultOp::Open { create: false, .. }) {
                return None;
            }
            if me.dead.load(Ordering::SeqCst) {
                return Some(io::Error::other("audit: backing is dead"));
            }
            me.mutations.fetch_add(1, Ordering::SeqCst);
            let left = me.countdown.load(Ordering::SeqCst);
            if left >= 0 {
                if left <= 1 {
                    me.dead.store(true, Ordering::SeqCst);
                    me.log.lock().push(format!("      !! DEATH at {op:?}"));
                    return Some(io::Error::other("audit: backing died"));
                }
                me.countdown.store(left - 1, Ordering::SeqCst);
                return None;
            }
            if !me.enabled.load(Ordering::SeqCst) {
                return None;
            }
            let permille = match op {
                FaultOp::SyncData { .. } => me.mode.sync_data,
                FaultOp::SyncDir { .. } => me.mode.sync_dir,
                FaultOp::WriteAt { .. } => me.mode.write,
                FaultOp::SetLen { .. } => me.mode.set_len,
                FaultOp::Remove { .. } => me.mode.remove,
                FaultOp::Rename { .. } => me.mode.rename,
                FaultOp::Open { .. } => me.mode.create,
            };
            if permille > 0 && me.rng.lock().random_range(0..1000) < permille {
                me.log.lock().push(format!("      ! fault {op:?}"));
                return Some(io::Error::other("audit: injected failure"));
            }
            None
        })
    }

    fn partial_hook(self: &Arc<Self>) -> PartialWriteHook {
        let me = self.clone();
        Arc::new(move |op| {
            if me.dead.load(Ordering::SeqCst)
                || me.countdown.load(Ordering::SeqCst) >= 0
                || !me.enabled.load(Ordering::SeqCst)
                || me.mode.partial == 0
            {
                return None;
            }
            let FaultOp::WriteAt { len, .. } = op else {
                return None;
            };
            let mut rng = me.rng.lock();
            if *len > 1 && rng.random_range(0..1000) < me.mode.partial {
                let keep = rng.random_range(0..*len);
                me.log
                    .lock()
                    .push(format!("      ! short write {keep} of {op:?}"));
                return Some((keep, io::Error::other("audit: short write")));
            }
            None
        })
    }
}

// ---------------------------------------------------------------------------
// Statistics

#[derive(Default)]
pub struct Stats {
    counters: Mutex<BTreeMap<String, u64>>,
    notes: Mutex<Vec<String>>,
}

impl Stats {
    fn bump(&self, key: &str) {
        *self.counters.lock().entry(key.to_string()).or_default() += 1;
    }
    fn add(&self, key: &str, n: u64) {
        *self.counters.lock().entry(key.to_string()).or_default() += n;
    }
    fn note(&self, text: String) {
        let mut notes = self.notes.lock();
        if notes.len() < 40 {
            notes.push(text);
        }
    }
    fn get(&self, key: &str) -> u64 {
        self.counters.lock().get(key).copied().unwrap_or(0)
    }
    fn render(&self) -> String {
        let counters = self.counters.lock();
        let mut out: Vec<String> = counters.iter().map(|(k, v)| format!("{k}={v}")).collect();
        out.sort();
        out.join(" ")
    }
}

// ---------------------------------------------------------------------------
// The sweep

fn pattern(stamp: u32, offset: u64, len: usize) -> Vec<u8> {
    (0..len as u64)
        .map(|i| {
            let o = (offset + i) as u32;
            let x = stamp.wrapping_mul(0x9E37_79B1) ^ o.wrapping_mul(0x85EB_CA6B);
            let x = (x ^ (x >> 15)).wrapping_mul(0x2545_F491);
            ((x >> 24) as u8) | 1
        })
        .collect()
}

async fn try_attach(cfg: &Cfg, backing: &Arc<CrashableBacking>) -> Result<Engine, AttachError> {
    Engine::attach(
        backing.clone() as Arc<dyn Backing>,
        Arc::new(FakeCryptoProvider::new(cfg.unit)),
        cfg.options(),
    )
    .await
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Crash {
    PowerLoss,
    AllLost,
    Restart,
}

fn pick_crash(rng: &mut StdRng) -> Crash {
    match rng.random_range(0..100) {
        0..=54 => Crash::PowerLoss,
        55..=69 => Crash::AllLost,
        _ => Crash::Restart,
    }
}

fn apply_crash(kind: Crash, backing: &CrashableBacking, rng: &mut StdRng) {
    match kind {
        Crash::PowerLoss => backing.crash(rng),
        Crash::AllLost => backing.crash_all_lost(),
        Crash::Restart => {}
    }
}

/// The unit images a write of `data` (or zeros) at `offset` produces.
fn images_after_write(
    cfg: &Cfg,
    model: &ReferenceBlockModel,
    offset: u64,
    data: &[u8],
) -> Vec<(u64, Vec<u8>)> {
    let unit = cfg.unit as u64;
    let first = offset / unit;
    let last = (offset + data.len() as u64 - 1) / unit;
    (first..=last)
        .map(|u| {
            let mut image = model.read(u);
            let start = u * unit;
            let from = offset.max(start) - start;
            let to = (offset + data.len() as u64).min(start + unit) - start;
            let src = offset.max(start) - offset;
            image[from as usize..to as usize]
                .copy_from_slice(&data[src as usize..(src + to - from) as usize]);
            (u, image)
        })
        .collect()
}

fn err_text<T>(r: &Result<T, CoreError>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) => format!("ERR {e}"),
    }
}

fn error_class(e: &CoreError) -> &'static str {
    match e {
        CoreError::Io(_) => "io",
        CoreError::Format(_) => "format",
        CoreError::Corrupt(_) => "corrupt",
        CoreError::Durability(_) => "durability",
        CoreError::Invalid(_) => "invalid",
        CoreError::Crypto(_) => "crypto",
    }
}

pub struct Run {
    pub cfg: Cfg,
    pub mode: Mode,
    pub seed: u64,
    pub cycles: usize,
    pub ops_lo: usize,
    pub ops_hi: usize,
    pub verbose: bool,
}

pub async fn run_seed(run: Run, stats: Arc<Stats>) {
    let Run {
        cfg,
        mode,
        seed,
        cycles,
        ops_lo,
        ops_hi,
        verbose,
    } = run;
    let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let say = |text: String| log.lock().push(text);
    let history = || {
        format!(
            "cfg {} mode {} seed {seed}\n  {}",
            cfg.name,
            mode.name,
            log.lock().join("\n  ")
        )
    };
    let mut rng = StdRng::seed_from_u64(seed.wrapping_mul(0x9E37_79B9).wrapping_add(0xA0D1));
    let backing = Arc::new(CrashableBacking::new().with_tearing(cfg.tear));
    if cfg.discard {
        init::create_volume_with_discard(backing.as_ref(), cfg.superblock()).unwrap();
    } else {
        init::create_volume(backing.as_ref(), cfg.superblock()).unwrap();
    }
    let injector = Injector::new(mode.clone(), seed, log.clone());
    backing.set_fault_hook(Some(injector.hook()));
    backing.set_partial_write_hook(Some(injector.partial_hook()));

    let unit = cfg.unit as u64;
    let block = cfg.block as u64;
    let bpu = unit / block;
    let total_blocks = cfg.device_units * bpu;
    let mut model = ReferenceBlockModel::new(cfg.unit as usize, cfg.device_units);
    let zeros = vec![0u8; cfg.unit as usize];
    let mut stamp: u32 = 0;
    let mut engine = match try_attach(&cfg, &backing).await {
        Ok(engine) => engine,
        Err(e) => panic!("ATTACH-FRESH: {e}\n{}", history()),
    };
    engine.stop_checkpoint_worker().await;
    let mut workload_mutations: u64 = 80;
    let mut recovery_mutations: u64 = 30;

    for cycle in 0..cycles {
        let ops = rng.random_range(ops_lo..ops_hi);
        let death_armed = rng.random_range(0..100) < mode.midop_death_pct;
        // What the request in flight at a death may have left behind.
        let mut maybe: BTreeMap<u64, Vec<Vec<u8>>> = BTreeMap::new();
        let transient = mode.transient() && !death_armed;
        if death_armed {
            backing.set_lenient_sync_failures(true);
            let at = rng.random_range(1..=workload_mutations.max(8));
            injector.arm(at);
            say(format!("-- cycle {cycle}: death armed after {at} mutations"));
        } else {
            backing.set_lenient_sync_failures(false);
            injector.enabled.store(transient, Ordering::SeqCst);
            say(format!("-- cycle {cycle}"));
        }
        let mutations_before = injector.mutations();

        for _ in 0..ops {
            stats.bump("ops");
            let roll = rng.random_range(0..100);
            // Resolve a failed request: every touched unit must show its
            // old or its new image; a new one counts as acknowledged-volatile.
            macro_rules! resolve_failure {
                ($what:expr, $error:expr, $images:expr) => {{
                    let error: &CoreError = $error;
                    let images: &Vec<(u64, Vec<u8>)> = $images;
                    stats.bump(&format!("err-{}", error_class(error)));
                    if !matches!(error, CoreError::Io(_) | CoreError::Durability(_)) {
                        stats.note(format!(
                            "cfg {} mode {} seed {seed}: {} failed with class {}: {error}",
                            cfg.name,
                            mode.name,
                            $what,
                            error_class(error)
                        ));
                    }
                    if injector.is_dead() {
                        for (u, image) in images {
                            maybe.entry(*u).or_default().push(image.clone());
                        }
                    } else {
                        assert!(
                            transient,
                            "UNEXPECTED-FAILURE: {} failed without faults: {error}\n{}",
                            $what,
                            history()
                        );
                        let was = injector.enabled.swap(false, Ordering::SeqCst);
                        for (u, image) in images {
                            let actual = match engine.read(u * unit, unit as usize).await {
                                Ok(actual) => actual,
                                Err(e) => panic!(
                                    "LIVE-READ-FAILED: unit {u} after failed {}: {e}\n{}",
                                    $what,
                                    history()
                                ),
                            };
                            if actual == *image {
                                if actual != model.read(*u) {
                                    say(format!("      unit {u}: the failed request is visible"));
                                    model.write(*u, &actual);
                                }
                            } else {
                                assert!(
                                    actual == model.read(*u),
                                    "LIVE-FOREIGN: unit {u} after failed {} is neither old nor new\n{}",
                                    $what,
                                    history()
                                );
                            }
                        }
                        injector.enabled.store(was, Ordering::SeqCst);
                    }
                }};
            }

            if transient && roll < mode.heal_pct as i32 {
                // Faults stop. The engine must be able to flush and
                // checkpoint again without a re-attach.
                injector.enabled.store(false, Ordering::SeqCst);
                let mut attempts = Vec::new();
                let mut healed = false;
                for _ in 0..3 {
                    let r = engine.flush().await;
                    attempts.push(err_text(&r));
                    if r.is_ok() {
                        healed = true;
                        break;
                    }
                }
                say(format!("heal: flush -> {attempts:?}"));
                assert!(healed, "HEAL-FLUSH: FLUSH keeps failing after faults stopped\n{}", history());
                if attempts.len() > 1 {
                    stats.bump("heal-flush-needed-retry");
                    stats.note(format!(
                        "cfg {} mode {} seed {seed}: heal flush attempts {attempts:?}",
                        cfg.name, mode.name
                    ));
                }
                model.flush();
                let mut attempts = Vec::new();
                let mut healed = false;
                for _ in 0..3 {
                    let r = engine.checkpoint().await;
                    attempts.push(err_text(&r));
                    if r.is_ok() {
                        healed = true;
                        break;
                    }
                }
                say(format!("heal: checkpoint -> {attempts:?}"));
                assert!(
                    healed,
                    "HEAL-CHECKPOINT: checkpoint keeps failing after faults stopped\n{}",
                    history()
                );
                if attempts.len() > 1 {
                    stats.bump("heal-checkpoint-needed-retry");
                    stats.note(format!(
                        "cfg {} mode {} seed {seed}: heal checkpoint attempts {attempts:?}",
                        cfg.name, mode.name
                    ));
                }
                let state = engine.state();
                assert!(
                    matches!(state, maki_core::engine::EngineState::Ready),
                    "HEAL-STATE: engine still {state:?} after a clean flush and checkpoint\n{}",
                    history()
                );
                stats.bump("heals");
                injector.enabled.store(true, Ordering::SeqCst);
                continue;
            }

            match roll {
                // WRITE / WRITE_ZEROES
                0..=49 => {
                    let (start, n) = if bpu == 1 || rng.random_bool(0.4) {
                        let count = rng.random_range(1..=cfg.max_request_units.min(4));
                        let first = rng.random_range(0..=cfg.device_units - count);
                        (first * bpu, count * bpu)
                    } else {
                        let max = (cfg.max_request_units * bpu).min(3 * bpu).min(total_blocks);
                        let n = rng.random_range(1..=max);
                        (rng.random_range(0..=total_blocks - n), n)
                    };
                    let (offset, len) = (start * block, (n * block) as usize);
                    let fua = rng.random_bool(0.25);
                    let zero = rng.random_bool(0.1);
                    stamp += 1;
                    let data = if zero {
                        vec![0u8; len]
                    } else {
                        pattern(stamp, offset, len)
                    };
                    let images = images_after_write(&cfg, &model, offset, &data);
                    let result = if zero {
                        engine.write_zeroes(offset, len, fua).await
                    } else {
                        engine.write(offset, &data, fua).await
                    };
                    say(format!(
                        "{} off {offset} len {len} (units {}..={}) stamp {stamp} fua={fua} -> {}",
                        if zero { "zero" } else { "write" },
                        images[0].0,
                        images[images.len() - 1].0,
                        err_text(&result)
                    ));
                    match result {
                        Ok(()) => {
                            for (u, image) in &images {
                                if fua {
                                    model.write_fua(*u, image);
                                } else {
                                    model.write(*u, image);
                                }
                            }
                        }
                        Err(e) => resolve_failure!("write", &e, &images),
                    }
                }
                // TRIM (v3 only; a write otherwise)
                50..=62 if cfg.discard => {
                    let max = (6 * bpu).min(total_blocks);
                    let n = rng.random_range(1..=max);
                    let start = rng.random_range(0..=total_blocks - n);
                    let (offset, len) = (start * block, (n * block) as usize);
                    let fua = rng.random_bool(0.25);
                    let first = offset.div_ceil(unit);
                    let end = (offset + len as u64) / unit;
                    let images: Vec<(u64, Vec<u8>)> =
                        (first..end).map(|u| (u, zeros.clone())).collect();
                    let result = engine.trim(offset, len, fua).await;
                    say(format!(
                        "trim off {offset} len {len} (whole units {first}..{end}) fua={fua} -> {}",
                        err_text(&result)
                    ));
                    match result {
                        Ok(()) => {
                            for (u, image) in &images {
                                if fua {
                                    model.write_fua(*u, image);
                                } else {
                                    model.write(*u, image);
                                }
                            }
                        }
                        Err(e) => resolve_failure!("trim", &e, &images),
                    }
                }
                50..=62 => {
                    let u = rng.random_range(0..cfg.device_units);
                    stamp += 1;
                    let data = pattern(stamp, u * unit, unit as usize);
                    let images = vec![(u, data.clone())];
                    let result = engine.write(u * unit, &data, false).await;
                    say(format!(
                        "write unit {u} stamp {stamp} fua=false -> {}",
                        err_text(&result)
                    ));
                    match result {
                        Ok(()) => model.write(u, &data),
                        Err(e) => resolve_failure!("write", &e, &images),
                    }
                }
                // FLUSH
                63..=75 => {
                    let result = engine.flush().await;
                    say(format!("flush -> {}", err_text(&result)));
                    match result {
                        Ok(()) => model.flush(),
                        Err(e) => resolve_failure!("flush", &e, &Vec::new()),
                    }
                }
                // checkpoint
                76..=86 => {
                    let result = engine.checkpoint().await;
                    say(format!("checkpoint -> {}", err_text(&result)));
                    if let Err(e) = result {
                        resolve_failure!("checkpoint", &e, &Vec::new());
                    }
                }
                // live read of a block range
                _ => {
                    let max = (cfg.max_request_units * bpu).min(2 * bpu).min(total_blocks);
                    let n = rng.random_range(1..=max);
                    let start = rng.random_range(0..=total_blocks - n);
                    let (offset, len) = (start * block, (n * block) as usize);
                    match engine.read(offset, len).await {
                        Ok(actual) => {
                            let mut want = Vec::with_capacity(len);
                            let mut at = offset;
                            while at < offset + len as u64 {
                                let u = at / unit;
                                let from = (at - u * unit) as usize;
                                let to = ((offset + len as u64).min((u + 1) * unit) - u * unit)
                                    as usize;
                                want.extend_from_slice(&model.read(u)[from..to]);
                                at = (u + 1) * unit;
                            }
                            assert!(
                                actual == want,
                                "LIVE-MISMATCH: read off {offset} len {len} differs from the \
                                 acknowledged image\n{}",
                                history()
                            );
                        }
                        Err(e) => {
                            assert!(
                                injector.is_dead(),
                                "LIVE-READ-FAILED: read off {offset} len {len}: {e}\n{}",
                                history()
                            );
                        }
                    }
                }
            }
            if injector.is_dead() {
                break;
            }
        }

        let died = injector.is_dead();
        if !death_armed {
            workload_mutations = (injector.mutations() - mutations_before).max(8);
        }
        injector.enabled.store(false, Ordering::SeqCst);
        if died {
            stats.bump("midop-deaths");
        }
        drop(engine);
        injector.revive();
        backing.set_lenient_sync_failures(false);

        let mut kind = pick_crash(&mut rng);
        apply_crash(kind, &backing, &mut rng);
        say(format!("== {kind:?}"));
        stats.bump("crashes");
        // A restart loses nothing; that only holds while no power loss
        // happens before the state is inspected.
        let mut strict = kind == Crash::Restart && mode.strict_restart;

        let mut attempts = 0;
        while attempts < 3 && rng.random_range(0..100) < mode.recovery_death_pct {
            attempts += 1;
            backing.set_lenient_sync_failures(true);
            let at = rng.random_range(1..=recovery_mutations.max(6) + 4);
            injector.arm(at);
            say(format!("recovery with death armed after {at} mutations"));
            let result = try_attach(&cfg, &backing).await;
            let died = injector.is_dead();
            match result {
                Ok(engine) => {
                    say(format!("   recovery completed (died={died})"));
                    engine.stop_checkpoint_worker().await;
                    drop(engine);
                    stats.bump("recovery-then-crash");
                }
                Err(e) => {
                    say(format!("   recovery failed: {e}"));
                    assert!(
                        died,
                        "ATTACH-REFUSED: recovery failed before the injected death: {e}\n{}",
                        history()
                    );
                    stats.bump("recovery-deaths");
                }
            }
            injector.revive();
            backing.set_lenient_sync_failures(false);
            kind = pick_crash(&mut rng);
            apply_crash(kind, &backing, &mut rng);
            say(format!("== {kind:?}"));
            strict &= kind == Crash::Restart;
        }

        if rng.random_range(0..100) < mode.double_crash_pct {
            match try_attach(&cfg, &backing).await {
                Ok(engine) => {
                    engine.stop_checkpoint_worker().await;
                    drop(engine);
                }
                Err(e) => panic!("ATTACH-REFUSED: {e}\n{}", history()),
            }
            kind = pick_crash(&mut rng);
            apply_crash(kind, &backing, &mut rng);
            say(format!("recovered, then == {kind:?} before any write"));
            strict &= kind == Crash::Restart;
            stats.bump("double-crashes");
        }

        let before = injector.mutations();
        engine = match try_attach(&cfg, &backing).await {
            Ok(engine) => engine,
            Err(e) => panic!("ATTACH-REFUSED: {e}\n{}", history()),
        };
        engine.stop_checkpoint_worker().await;
        recovery_mutations = (injector.mutations() - before).max(6);
        say("recovered".to_string());

        let s = engine.stats().await;
        assert!(
            s.checkpoint_sequence <= s.durable_sequence,
            "CHECKPOINT-AHEAD: checkpoint {} > durable {}\n{}",
            s.checkpoint_sequence,
            s.durable_sequence,
            history()
        );
        for u in 0..cfg.device_units {
            let live_before = model.read(u);
            let actual = match engine.read(u * unit, unit as usize).await {
                Ok(actual) => actual,
                Err(e) => panic!("READ-AFTER-RECOVERY: unit {u}: {e}\n{}", history()),
            };
            let in_flight = maybe.get(&u).is_some_and(|set| set.contains(&actual));
            if strict && actual != live_before && !in_flight {
                panic!(
                    "RESTART-LOSS: unit {u} lost an acknowledged write across a plain restart \
                     (first bytes {:02x?}, wanted {:02x?})\n{}",
                    &actual[..8],
                    &live_before[..8],
                    history()
                );
            }
            if let Err(violation) = model.crash_adopt(u, &actual) {
                assert!(in_flight, "ORACLE: {violation}\n{}", history());
                model.write_fua(u, &actual);
            }
        }
        stats.bump("recoveries-checked");

        // A recovered volume must accept a checkpoint and a flush.
        if rng.random_bool(0.3) {
            if let Err(e) = engine.checkpoint().await {
                panic!("POST-RECOVERY-CHECKPOINT: {e}\n{}", history());
            }
            say("post-recovery checkpoint ok".to_string());
        }
    }
    if verbose {
        println!("{}", history());
    }
}

pub struct Outcome {
    pub seeds_run: u64,
    pub failures: Vec<(u64, String)>,
}

/// Run `seeds` for one configuration and mode (each seed isolated, so one
/// violation does not hide the others), within a wall-clock budget.
pub async fn sweep(
    cfg_name: &str,
    mode_name: &str,
    seeds: std::ops::Range<u64>,
    cycles: usize,
    budget: Duration,
) -> Outcome {
    let stats = Arc::new(Stats::default());
    let started = Instant::now();
    let mut failures = Vec::new();
    let mut seeds_run = 0;
    for seed in seeds.clone() {
        if started.elapsed() > budget {
            break;
        }
        seeds_run += 1;
        let run = Run {
            cfg: cfg(cfg_name),
            mode: mode(mode_name),
            seed,
            cycles,
            ops_lo: 6,
            ops_hi: 40,
            verbose: false,
        };
        let task = tokio::spawn(run_seed(run, stats.clone()));
        if let Err(join) = task.await {
            let text = match join.try_into_panic() {
                Ok(payload) => payload
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_else(|| "non-string panic".into()),
                Err(e) => format!("task cancelled: {e}"),
            };
            failures.push((seed, text));
        }
    }
    println!(
        "AUDIT-SWEEP cfg={cfg_name} mode={mode_name} seeds={}..{} run={seeds_run} cycles={cycles} \
         failures={} elapsed={:.0}s | {}",
        seeds.start,
        seeds.start + seeds_run,
        failures.len(),
        started.elapsed().as_secs_f64(),
        stats.render()
    );
    for note in stats.notes.lock().iter() {
        println!("AUDIT-NOTE {note}");
    }
    let mut classes: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for (seed, text) in &failures {
        let class = text.split(':').next().unwrap_or("?").to_string();
        classes.entry(class).or_default().push(*seed);
    }
    for (class, seeds) in &classes {
        println!("AUDIT-FAIL cfg={cfg_name} mode={mode_name} class={class} seeds={seeds:?}");
    }
    Outcome {
        seeds_run,
        failures,
    }
}

/// Sweep several (cfg, mode) pairs and fail at the end with the first
/// violation of each class.
pub async fn sweep_all(pairs: &[(&str, &str)], seeds: std::ops::Range<u64>, cycles: usize) {
    let per_pair = Duration::from_secs(
        std::env::var("AUDIT_BUDGET_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60),
    );
    let mut report = Vec::new();
    for (cfg_name, mode_name) in pairs {
        let outcome = sweep(cfg_name, mode_name, seeds.clone(), cycles, per_pair).await;
        let mut seen = std::collections::BTreeSet::new();
        for (seed, text) in outcome.failures {
            let class = text.split(':').next().unwrap_or("?").to_string();
            if seen.insert(class) {
                report.push(format!(
                    "cfg {cfg_name} mode {mode_name} seed {seed}:\n{text}"
                ));
            }
        }
    }
    if !report.is_empty() {
        let limit = std::env::var("AUDIT_REPORT_LIMIT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3);
        panic!(
            "{} violation class(es); first {limit}:\n\n{}",
            report.len(),
            report
                .iter()
                .take(limit)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n\n")
        );
    }
}

fn seeds() -> std::ops::Range<u64> {
    let start = std::env::var("AUDIT_SEED_START")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let count: u64 = std::env::var("AUDIT_SEED_COUNT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(40);
    start..start + count
}

const V2: [&str; 5] = ["seg1", "seg3-tight", "odd", "shard1", "rmw"];
const V3: [&str; 5] = ["seg1-v3", "seg3-tight-v3", "odd-v3", "shard1-v3", "rmw-v3"];
const EXTRA: [&str; 4] = ["seg3-cache-v3", "rmw-cache", "plain", "plain-v3"];

fn pairs<'a>(cfgs: &[&'a str], mode: &'a str) -> Vec<(&'a str, &'a str)> {
    cfgs.iter().map(|c| (*c, mode)).collect()
}

#[tokio::test]
async fn audit_crash_v2() {
    sweep_all(&pairs(&V2, "crash"), seeds(), 4).await;
}

#[tokio::test]
async fn audit_crash_v3() {
    sweep_all(&pairs(&V3, "crash"), seeds(), 4).await;
}

#[tokio::test]
async fn audit_crash_extra() {
    sweep_all(&pairs(&EXTRA, "crash"), seeds(), 4).await;
}

#[tokio::test]
async fn audit_death_v2() {
    sweep_all(&pairs(&V2, "death"), seeds(), 4).await;
}

#[tokio::test]
async fn audit_death_v3() {
    sweep_all(&pairs(&V3, "death"), seeds(), 4).await;
}

#[tokio::test]
async fn audit_death_extra() {
    sweep_all(&pairs(&EXTRA, "death"), seeds(), 4).await;
}

#[tokio::test]
async fn audit_sync_v2() {
    sweep_all(&pairs(&V2, "sync"), seeds(), 4).await;
}

#[tokio::test]
async fn audit_sync_v3() {
    sweep_all(&pairs(&V3, "sync"), seeds(), 4).await;
}

#[tokio::test]
async fn audit_sync_extra() {
    sweep_all(&pairs(&EXTRA, "sync"), seeds(), 4).await;
}

#[tokio::test]
async fn audit_chaos_v2() {
    sweep_all(&pairs(&V2, "chaos"), seeds(), 4).await;
}

#[tokio::test]
async fn audit_chaos_v3() {
    sweep_all(&pairs(&V3, "chaos"), seeds(), 4).await;
}

#[tokio::test]
async fn audit_chaos_extra() {
    sweep_all(&pairs(&EXTRA, "chaos"), seeds(), 4).await;
}

#[tokio::test]
async fn audit_chaos_death_v2() {
    sweep_all(&pairs(&V2, "chaos-death"), seeds(), 4).await;
}

#[tokio::test]
async fn audit_chaos_death_v3() {
    sweep_all(&pairs(&V3, "chaos-death"), seeds(), 4).await;
}

/// One seed, chosen by environment, with its full history printed:
/// `AUDIT_CFG=odd-v3 AUDIT_MODE=death AUDIT_SEED=17 [AUDIT_CYCLES=4]`.
#[tokio::test]
async fn audit_one() {
    let Ok(cfg_name) = std::env::var("AUDIT_CFG") else {
        return;
    };
    let mode_name = std::env::var("AUDIT_MODE").unwrap_or_else(|_| "crash".into());
    let seed = std::env::var("AUDIT_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let cycles = std::env::var("AUDIT_CYCLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4);
    let run = Run {
        cfg: cfg(&cfg_name),
        mode: mode(&mode_name),
        seed,
        cycles,
        ops_lo: 6,
        ops_hi: 40,
        verbose: true,
    };
    run_seed(run, Arc::new(Stats::default())).await;
}
