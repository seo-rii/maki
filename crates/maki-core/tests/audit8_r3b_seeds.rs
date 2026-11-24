//! Audit round 8 (long-seeds): the committed randomized durability sweeps of
//! `review_r3b_durability.rs` and `review_trim_power_loss.rs`, with their
//! bodies copied and every parameter they hold fixed turned into a value
//! drawn from the seed. Not part of the maintained suite.
//!
//! What the committed sweeps fix and this driver varies:
//! - geometry: block 512 / unit 512 (4096 in the concurrent sweep), 48 units,
//!   8 units per shard, slot alignment 512, ciphertext = unit + 8;
//! - the journal: `VolumeOptions::default()` (256 MiB segments) and the
//!   default checkpoint policy, so no segment ever fills, no inline reclaim
//!   and no forced sync happens (see `audit8_committed_profile_never_rolls`);
//! - v1 volumes only in r3b (no TRIM), v3 only in the trim sweep, never
//!   WRITE_ZEROES, never a partial-unit write in the sequential sweeps;
//! - tearing at 128 (256) bytes, crash = `crash(rng)` or restart, never
//!   `crash_all_lost`, never a second crash right after recovery;
//! - faults: `fdatasync`/dir-sync failures at 150 (120) permille only, and
//!   never while recovery runs.
//!
//! Seeds: `AUDIT8_SEED_START` (default 0), `AUDIT8_SEED_COUNT` (default 40),
//! `AUDIT8_BUDGET_SECS` (wall-clock cap per test, default none),
//! `AUDIT8_PROFILE` = `committed` | `random` (default) | `tiny` | `rmw` |
//! `big`, `AUDIT8_FAULTS` = permille override, `AUDIT8_CYCLES`,
//! `AUDIT8_FAIL_DIR` (full failure texts are written there),
//! `AUDIT8_ONE=1` prints the parameters and trace of every seed.

#![allow(clippy::await_holding_lock)]
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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

const BIG: u64 = 1 << 40;

// ---------------------------------------------------------------------------
// Parameters

#[derive(Clone, Debug)]
struct P {
    profile: &'static str,
    block: u32,
    unit: u32,
    align: u32,
    /// Provider ciphertext overhead (>= 8) and extra slack in
    /// `max_ciphertext_size` above `unit + overhead`.
    overhead: u32,
    slack: u32,
    device_units: u64,
    shard_units: u64,
    segment_size: u64,
    journal_max: u64,
    max_pending: u64,
    overlay_entries: u64,
    overlay_bytes: u64,
    /// Background worker with a low watermark.
    worker: bool,
    cache: Option<bool>,
    discard: bool,
    tear: Option<usize>,
    /// Sync-fault permille during the workload.
    faults: u32,
    /// Also fail writes, length changes, creations, removals and renames.
    fault_all_ops: bool,
    /// Partial-write permille (a `write_at` persists a prefix, then fails).
    partial: u32,
    /// Keep injecting faults while recovery runs (attach may be refused and
    /// is retried; the last attempt runs on a healthy device).
    recovery_faults: bool,
    p_power: f64,
    p_all_lost: f64,
    /// Second crash right after a successful recovery (K-01 pin).
    p_pin: f64,
    max_write_units: u64,
    ops_lo: usize,
    ops_hi: usize,
    cycles: usize,
}

impl P {
    fn rec(&self) -> u64 {
        // One maximum journal record: header + max_ciphertext_size.
        32 + self.unit as u64 + self.overhead as u64 + self.slack as u64
    }

    /// Exactly what `review_r3b_durability.rs` runs.
    fn committed(cache: bool, faults: u32, cycles: usize) -> Self {
        P {
            profile: "committed",
            block: 512,
            unit: 512,
            align: 512,
            overhead: 8,
            slack: 0,
            device_units: 48,
            shard_units: 8,
            segment_size: 256 << 20,
            journal_max: 4 << 30,
            max_pending: 64 << 20,
            overlay_entries: 0,
            overlay_bytes: 0,
            worker: false,
            cache: cache.then_some(false),
            discard: false,
            tear: Some(128),
            faults,
            fault_all_ops: false,
            partial: 0,
            recovery_faults: false,
            p_power: 0.7,
            p_all_lost: 0.0,
            p_pin: 0.0,
            max_write_units: 4,
            ops_lo: 8,
            ops_hi: 48,
            cycles,
        }
    }

    fn random(profile: &'static str, seed: u64, faults: Option<u32>, cycles: usize) -> Self {
        let mut r = StdRng::seed_from_u64(seed ^ 0xA8_A8_A8_A8);
        let (block, unit): (u32, u32) = match profile {
            "tiny" => (512, 512),
            "rmw" => {
                let block = [512u32, 1024][r.random_range(0..2)];
                (block, block * [2u32, 4, 8, 16][r.random_range(0..4)])
            }
            "big" => {
                let block = [512u32, 4096][r.random_range(0..2)];
                (block, [16384u32, 32768, 65536][r.random_range(0..3)])
            }
            _ => {
                let block = [512u32, 512, 1024, 4096][r.random_range(0..4)];
                (block, block * [1u32, 1, 2, 4, 8][r.random_range(0..5)])
            }
        };
        let align = [512u32, 512, 4096, 65536][r.random_range(0..4)];
        // Below one unit of zero padding: the fake pads with zeros, and a
        // unit of zero plaintext found in the padding is refused as an echo
        // (BUG-105 check) -- an artifact of the fake, not a product path.
        let overhead = [8u32, 8, 9, 16, 28, 264][r.random_range(0..6)];
        let slack = [0u32, 0, 1, 24, 504][r.random_range(0..5)];
        let device_units = match profile {
            "tiny" => r.random_range(1..=5u64),
            "big" => r.random_range(1..=12u64),
            _ => match r.random_range(0..10) {
                0 => 1,
                1 => 2,
                2 => r.random_range(3..=7u64),
                3 => r.random_range(100..=300u64),
                _ => r.random_range(8..=64u64),
            },
        };
        // A shard data file is created at its full sparse size and the
        // in-memory backing holds every byte: keep a shard below 4 MiB.
        let slot = (64 + unit as u64 + overhead as u64 + slack as u64).div_ceil(align as u64)
            * align as u64;
        let shard_cap = ((4u64 << 20) / slot).max(1);
        let shard_units = match r.random_range(0..6) {
            0 => 1,
            1 => device_units,
            2 => device_units + r.random_range(1..=9u64), // one partial shard
            3 => 1 << 16,                                  // far larger than the device
            _ => r.random_range(1..=9u64),
        }
        .min(shard_cap);
        let mut p = P {
            profile,
            block,
            unit,
            align,
            overhead,
            slack,
            device_units,
            shard_units,
            segment_size: 0,
            journal_max: 0,
            max_pending: 0,
            overlay_entries: 0,
            overlay_bytes: 0,
            worker: r.random_bool(0.35),
            cache: match r.random_range(0..3) {
                0 => None,
                1 => Some(false),
                _ => Some(true),
            },
            discard: r.random_bool(0.5),
            tear: match r.random_range(0..8) {
                0 => None,
                1 => Some(1),
                2 => Some(64),
                3 => Some(512),
                4 => Some(4096),
                5 => Some(r.random_range(2..=700usize)),
                _ => Some(128),
            },
            faults: 0,
            fault_all_ops: false,
            partial: 0,
            recovery_faults: false,
            p_power: [0.7f64, 0.7, 0.3, 1.0, 0.0][r.random_range(0..5)],
            p_all_lost: [0.0f64, 0.15, 0.5][r.random_range(0..3)],
            p_pin: [0.0f64, 0.3, 1.0][r.random_range(0..3)],
            max_write_units: r.random_range(1..=6u64).min(device_units),
            ops_lo: 6,
            ops_hi: [24usize, 48, 48, 120][r.random_range(0..4)],
            cycles,
        };
        let rec = p.rec();
        // Journal segment: from "every record rolls" to the committed 256 MiB.
        p.segment_size = match r.random_range(0..8) {
            0 => 112,
            1 => 48 + rec,
            2 => 256 << 20,
            _ => 48 + r.random_range(1..=6u64) * rec + r.random_range(0..rec),
        };
        // A lone request (max_write_units, plus one unit for a misaligned
        // partial write, plus trim chunking) must fit after a full reclaim:
        // the sizing rule of the earlier rounds' harness.
        let lone = (p.max_write_units + 1).max(5);
        p.journal_max = if r.random_bool(0.35) {
            BIG
        } else {
            2 * p.segment_size.max(48 + rec)
                + lone * rec
                + (lone + 2) * 48
                + r.random_range(0..3 * p.segment_size.max(rec))
        };
        p.max_pending = if r.random_bool(0.35) {
            BIG
        } else {
            rec * r.random_range(1..=4u64)
        };
        p.overlay_entries = if r.random_bool(0.55) {
            0
        } else {
            lone + r.random_range(0..8u64)
        };
        p.overlay_bytes = if r.random_bool(0.6) {
            0
        } else {
            2 * lone * (p.unit as u64 + p.overhead as u64)
                + r.random_range(0..6u64) * (p.unit as u64 + p.overhead as u64)
        };
        // Faults.
        let f = faults.unwrap_or_else(|| [0u32, 0, 20, 150, 400][r.random_range(0..5)]);
        p.faults = f;
        if f > 0 {
            p.fault_all_ops = r.random_bool(0.4);
            p.partial = if r.random_bool(0.3) { f / 2 + 1 } else { 0 };
            p.recovery_faults = r.random_bool(0.4);
        }
        p
    }

    fn superblock(&self) -> Superblock {
        Superblock {
            generation: 0,
            volume_uuid: Uuid::from_u128(0xA8_5EED),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(
                self.block,
                self.unit,
                self.align,
                self.unit + self.overhead + self.slack,
                self.device_units * self.unit as u64,
                self.shard_units * self.unit as u64,
            )
            .unwrap_or_else(|e| panic!("HARNESS: geometry {self:?}: {e}")),
            format_version: 1,
            created_unix: 0,
        }
    }

    fn options(&self) -> EngineOptions {
        if self.profile == "committed" {
            // `cache_options` of the committed file, verbatim.
            return EngineOptions {
                cache: self.cache.map(|verify_on_hit| EngineCacheConfig {
                    max_bytes: 6 * self.unit as u64,
                    ttl: Duration::from_secs(3600),
                    verify_on_hit,
                }),
                checkpoint: CheckpointPolicy {
                    emergency_reserve_bytes: 0,
                    ..Default::default()
                },
                ..EngineOptions::default()
            };
        }
        EngineOptions {
            volume: VolumeOptions {
                journal_segment_size: self.segment_size,
            },
            limits: EngineLimits {
                max_overlay_bytes: self.overlay_bytes,
                max_overlay_entries: self.overlay_entries,
                ..EngineLimits::default()
            },
            cache: self.cache.map(|verify_on_hit| EngineCacheConfig {
                max_bytes: 6 * self.unit as u64,
                ttl: Duration::from_secs(3600),
                verify_on_hit,
            }),
            checkpoint: CheckpointPolicy {
                journal_high_watermark_bytes: if self.worker {
                    self.segment_size.max(160)
                } else {
                    u64::MAX
                },
                journal_max_bytes: self.journal_max,
                max_pending_bytes: self.max_pending,
                emergency_reserve_bytes: 0,
                low_space_checkpoint_bytes: 0,
                interval: Duration::from_secs(3600),
            },
            ..EngineOptions::default()
        }
    }

    fn provider(&self) -> Arc<FakeCryptoProvider> {
        Arc::new(FakeCryptoProvider::new(self.unit).with_overhead(self.overhead))
    }
}

// ---------------------------------------------------------------------------
// Coverage counters (what a run actually exercised)

#[derive(Default)]
struct Cov {
    seeds: AtomicU64,
    cycles: AtomicU64,
    ops: AtomicU64,
    writes_ok: AtomicU64,
    writes_failed: AtomicU64,
    partial_writes: AtomicU64,
    trims: AtomicU64,
    zeroes: AtomicU64,
    flushes_ok: AtomicU64,
    flushes_failed: AtomicU64,
    checkpoints_ok: AtomicU64,
    checkpoints_failed: AtomicU64,
    power_losses: AtomicU64,
    all_lost: AtomicU64,
    restarts: AtomicU64,
    pins: AtomicU64,
    attach_retries: AtomicU64,
    live_failed_shown: AtomicU64,
    crash_failed_shown: AtomicU64,
    /// Journal segment files created while a workload operation ran (an
    /// automatic roll), and while recovery/attach ran.
    seg_created_in_ops: AtomicU64,
    seg_created_in_attach: AtomicU64,
    injected: AtomicU64,
    deep_checks: AtomicU64,
    damaged: AtomicU64,
    damage_attached: AtomicU64,
    damage_eio_units: AtomicU64,
    /// Largest `EngineStats::journal_segments` sampled after an operation
    /// (above 1 = a sealed segment exists: the journal rolled).
    max_segments: AtomicU64,
    /// A journal segment was created by a write although an earlier write
    /// of the same attach had already appended to the active segment and no
    /// checkpoint or failure came in between: an automatic roll.
    auto_rolls: AtomicU64,
    /// Power losses sampled by the biased generator.
    biased_losses: AtomicU64,
}

impl Cov {
    fn render(&self) -> String {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        format!(
            "seeds={} cycles={} ops={} writes_ok={} writes_failed={} partial_writes={} trims={} \
             zeroes={} flush_ok={} flush_failed={} ckpt_ok={} ckpt_failed={} power_losses={} \
             all_lost={} restarts={} pins={} attach_retries={} live_failed_shown={} \
             crash_failed_shown={} seg_created_in_ops={} seg_created_in_attach={} injected={} \
             deep_checks={} damaged={} damage_attached={} damage_eio_units={} max_segments={} auto_rolls={} biased_losses={}",
            g(&self.seeds),
            g(&self.cycles),
            g(&self.ops),
            g(&self.writes_ok),
            g(&self.writes_failed),
            g(&self.partial_writes),
            g(&self.trims),
            g(&self.zeroes),
            g(&self.flushes_ok),
            g(&self.flushes_failed),
            g(&self.checkpoints_ok),
            g(&self.checkpoints_failed),
            g(&self.power_losses),
            g(&self.all_lost),
            g(&self.restarts),
            g(&self.pins),
            g(&self.attach_retries),
            g(&self.live_failed_shown),
            g(&self.crash_failed_shown),
            g(&self.seg_created_in_ops),
            g(&self.seg_created_in_attach),
            g(&self.injected),
            g(&self.deep_checks),
            g(&self.damaged),
            g(&self.damage_attached),
            g(&self.damage_eio_units),
            g(&self.max_segments),
            g(&self.auto_rolls),
            g(&self.biased_losses),
        )
    }
}

fn bump(a: &AtomicU64) {
    a.fetch_add(1, Ordering::Relaxed);
}

/// 0 = attach/recovery, 1 = workload operation.
static PHASE: AtomicUsize = AtomicUsize::new(0);

/// Panic messages recorded by the driver's hook while a seed runs.
static PANICS: Mutex<Vec<String>> = Mutex::new(Vec::new());

// ---------------------------------------------------------------------------
// Trace, faults (copied from the committed sweep, extended)

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

/// The committed sweep's sync-fault hook; with `all_ops` it also fails the
/// other mutating operations. It always counts journal segment creations.
fn fault_hook(
    seed: u64,
    permille: u32,
    all_ops: bool,
    faults: Arc<Mutex<Vec<String>>>,
    cov: Arc<Cov>,
) -> FaultHook {
    let fault_rng = Mutex::new(StdRng::seed_from_u64(seed));
    Arc::new(move |op| {
        if let FaultOp::Open { path, create: true } = op {
            if path.starts_with("journal/seg-") {
                if PHASE.load(Ordering::Relaxed) == 1 {
                    bump(&cov.seg_created_in_ops);
                } else {
                    bump(&cov.seg_created_in_attach);
                }
            }
        }
        if permille == 0 {
            return None;
        }
        let eligible = match op {
            FaultOp::SyncData { .. } | FaultOp::SyncDir { .. } => true,
            FaultOp::Open { create, .. } => all_ops && *create,
            FaultOp::WriteAt { .. }
            | FaultOp::SetLen { .. }
            | FaultOp::Remove { .. }
            | FaultOp::Rename { .. } => all_ops,
        };
        if eligible && fault_rng.lock().random_range(0..1000) < permille {
            faults.lock().push(format!("INJECTED {op:?}"));
            bump(&cov.injected);
            Some(io::Error::other("injected failure"))
        } else {
            None
        }
    })
}

fn partial_hook(seed: u64, permille: u32, faults: Arc<Mutex<Vec<String>>>) -> PartialWriteHook {
    let rng = Mutex::new(StdRng::seed_from_u64(seed ^ 0x9A27));
    Arc::new(move |op| match op {
        FaultOp::WriteAt { len, .. } if *len > 1 => {
            let mut rng = rng.lock();
            if rng.random_range(0..1000) < permille {
                let keep = rng.random_range(1..*len);
                faults.lock().push(format!("PARTIAL {op:?} keep {keep}"));
                Some((keep, io::Error::other("injected partial write")))
            } else {
                None
            }
        }
        _ => None,
    })
}

fn install_faults(
    p: &P,
    backing: &CrashableBacking,
    seed: u64,
    faults: &Arc<Mutex<Vec<String>>>,
    cov: &Arc<Cov>,
    enabled: bool,
) {
    let permille = if enabled { p.faults } else { 0 };
    backing.set_fault_hook(Some(fault_hook(
        seed,
        permille,
        p.fault_all_ops,
        faults.clone(),
        cov.clone(),
    )));
    backing.set_partial_write_hook(if enabled && p.partial > 0 {
        Some(partial_hook(seed, p.partial, faults.clone()))
    } else {
        None
    });
}


/// Round 8: a crash generator for `CrashableBacking::crash`, whose own
/// sampling keeps every volatile operation with probability one half and
/// tears a kept write with probability three tenths, independently. With
/// dozens of operations pending that never produces the states next to
/// "everything reached the disk" or "nothing did". `crash` decides with
/// `random_bool(0.5)` (keep) and `random_bool(0.3)` (tear), i.e. by
/// comparing one `u64` draw with 2^63 and with 0.3 * 2^64, so a draw from
/// [0, 0.3 * 2^64) says "keep, torn", one from [0.3 * 2^64, 2^63) "keep,
/// whole" and one above 2^63 "lost". This generator picks the range with
/// the given probabilities and a uniform value inside it.
struct Biased {
    inner: StdRng,
    keep_torn: f64,
    keep_whole: f64,
}

impl Biased {
    /// One of four biased crash kinds: nearly everything kept, nearly
    /// everything lost, nearly everything kept but half of it torn, and
    /// everything kept untorn.
    fn pick(rng: &mut StdRng) -> (Self, &'static str) {
        let (keep_torn, keep_whole, name) = match rng.random_range(0..4u32) {
            0 => (0.05, 0.90, "mostly kept"),
            1 => (0.02, 0.05, "mostly lost"),
            2 => (0.50, 0.45, "mostly kept, half torn"),
            _ => (0.0, 1.0, "everything kept"),
        };
        (
            Self {
                inner: StdRng::seed_from_u64(rng.random()),
                keep_torn,
                keep_whole,
            },
            name,
        )
    }
}

impl rand::RngCore for Biased {
    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }
    fn next_u64(&mut self) -> u64 {
        const TEAR: f64 = 0.3 * 18_446_744_073_709_551_616.0;
        const HALF: f64 = 0.5 * 18_446_744_073_709_551_616.0;
        let pick: f64 = self.inner.random();
        let frac: f64 = self.inner.random();
        let (lo, hi) = if pick < self.keep_torn {
            (0.0, TEAR)
        } else if pick < self.keep_torn + self.keep_whole {
            (TEAR + 2048.0, HALF - 2048.0)
        } else {
            (HALF + 2048.0, 18_446_744_073_709_547_520.0)
        };
        (lo + frac * (hi - lo)) as u64
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand::RngCore::fill_bytes(&mut self.inner, dest)
    }
}

/// A power loss of a non-committed profile: half use the model's own
/// sampling (from the main generator, as the committed sweeps do), half one
/// of the biased kinds.
fn sampled_crash(p: &P, backing: &CrashableBacking, rng: &mut StdRng, cov: &Cov) -> &'static str {
    if p.profile != "committed" && rng.random_bool(0.5) {
        let (mut biased, name) = Biased::pick(rng);
        backing.crash(&mut biased);
        bump(&cov.biased_losses);
        name
    } else {
        backing.crash(rng);
        "sampled"
    }
}

// ---------------------------------------------------------------------------
// Oracle helpers (copied)

/// Unit-sized content unique to (unit, stamp); never all zeros.
fn image(p: &P, unit: u64, stamp: u32) -> Vec<u8> {
    let mut v = vec![0u8; p.unit as usize];
    let seed = (unit as u32).wrapping_mul(0x9E37_79B1) ^ stamp.wrapping_mul(0x85EB_CA6B);
    for (i, b) in v.iter_mut().enumerate() {
        *b = (seed.wrapping_add(i as u32).wrapping_mul(0x2545_F491) >> 24) as u8;
    }
    v[0] |= 1;
    v
}

/// Values a failed (unacknowledged) write may have left in a unit (TEST-005).
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

    fn live_may_show(&self, unit: u64, value: &[u8]) -> bool {
        self.live.get(&unit).is_some_and(|set| set.contains(value))
    }

    fn crash_may_show(&self, unit: u64, value: &[u8]) -> bool {
        self.crash.get(&unit).is_some_and(|set| set.contains(value))
    }

    fn settled(&mut self, unit: u64) {
        self.live.remove(&unit);
        self.crash.remove(&unit);
        self.superseded.remove(&unit);
    }
}

async fn try_attach(p: &P, backing: &Arc<CrashableBacking>) -> Result<Engine, AttachError> {
    if !backing.exists("superblock.a").unwrap() {
        if p.discard {
            init::create_volume_with_discard(backing.as_ref(), p.superblock()).unwrap();
        } else {
            init::create_volume(backing.as_ref(), p.superblock()).unwrap();
        }
    }
    Engine::attach(backing.process(), p.provider(), p.options()).await
}

/// Compare every unit after a recovery against the oracle and adopt what was
/// observed as the new durable state (the committed `check_all`).
async fn check_all(
    p: &P,
    engine: &Engine,
    model: &mut ReferenceBlockModel,
    maybe: &mut Maybe,
    what: &str,
    trace: &Trace,
    cov: &Cov,
) {
    let stats = engine.stats().await;
    assert!(
        stats.checkpoint_sequence <= stats.durable_sequence,
        "CKPT-AHEAD: {what}: checkpoint_sequence {} > durable_sequence {}\n{}",
        stats.checkpoint_sequence,
        stats.durable_sequence,
        trace.report()
    );
    for unit in 0..p.device_units {
        let actual = match engine
            .read(unit * p.unit as u64, p.unit as usize)
            .await
        {
            Ok(actual) => actual,
            Err(e) => panic!(
                "READ-AFTER-RECOVERY: {what}: unit {unit}: read failed: {e}\n{}",
                trace.report()
            ),
        };
        if let Err(violation) = model.crash_adopt(unit, &actual) {
            let landed = maybe.crash_may_show(unit, &actual);
            assert!(landed, "ORACLE: {what}: {violation}\n{}", trace.report());
            bump(&cov.crash_failed_shown);
            model.write_fua(unit, &actual);
        }
        maybe.settled(unit);
    }
}

/// Resolve a unit's live value before a partial (read-modify-write) write:
/// after a failed write the base image is one of two values.
async fn resolve_live(
    p: &P,
    engine: &Engine,
    model: &mut ReferenceBlockModel,
    maybe: &mut Maybe,
    unit: u64,
    what: &str,
    trace: &mut Trace,
    cov: &Cov,
) -> Vec<u8> {
    let actual = engine
        .read(unit * p.unit as u64, p.unit as usize)
        .await
        .unwrap_or_else(|e| panic!("LIVE-READ: {what}: unit {unit}: {e}\n{}", trace.report()));
    if actual != model.read(unit) {
        assert!(
            maybe.live_may_show(unit, &actual),
            "LIVE: {what}: live read of unit {unit} is neither the acknowledged value nor a \
             failed write newer than it\n{}",
            trace.report()
        );
        bump(&cov.live_failed_shown);
        trace.op(format!("live read of unit {unit} shows a failed write"));
        model.write(unit, &actual);
        maybe.acknowledged(unit, false);
    }
    actual
}

fn err_text<T>(r: &Result<T, CoreError>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) => format!("ERR {e}"),
    }
}

// ---------------------------------------------------------------------------
// Sequential sweep (review_r3b_durability.rs `sweep_verbose`, plus TRIM,
// WRITE_ZEROES and partial-unit writes)

async fn recover(
    p: &P,
    backing: &Arc<CrashableBacking>,
    seed: u64,
    cycle: usize,
    what: &str,
    trace: &mut Trace,
    cov: &Arc<Cov>,
) -> Engine {
    PHASE.store(0, Ordering::Relaxed);
    if p.faults > 0 && p.recovery_faults {
        // Up to three attempts on a faulty device; each refusal is a restart.
        for attempt in 0..3u64 {
            install_faults(
                p,
                backing,
                seed ^ 0xEC0 ^ ((cycle as u64) << 8) ^ attempt,
                &trace.faults,
                cov,
                true,
            );
            match try_attach(p, backing).await {
                Ok(engine) => {
                    install_faults(p, backing, 0, &trace.faults, cov, false);
                    trace.op(format!("recovery attempt {attempt} succeeded under faults"));
                    return engine;
                }
                Err(e) => {
                    bump(&cov.attach_retries);
                    trace.op(format!("recovery attempt {attempt} refused under faults: {e}"));
                }
            }
        }
    }
    install_faults(p, backing, 0, &trace.faults, cov, false);
    match try_attach(p, backing).await {
        Ok(engine) => engine,
        Err(e) => panic!(
            "ATTACH-REFUSED: {what}: recovery refused the volume: {e}\n{}",
            trace.report()
        ),
    }
}

async fn seq_sweep(seed: u64, p: P, cov: Arc<Cov>, verbose: bool) {
    let mut rng = StdRng::seed_from_u64(seed.wrapping_mul(0x9E37_79B9).wrapping_add(0x1234));
    let backing = Arc::new(match p.tear {
        Some(t) => CrashableBacking::new().with_tearing(t),
        None => CrashableBacking::new(),
    });
    let mut model = ReferenceBlockModel::new(p.unit as usize, p.device_units);
    let mut maybe = Maybe::default();
    let mut stamp: u32 = 0;
    let mut trace = Trace::default();
    trace.op(format!("params {p:?}"));
    let unit = p.unit as u64;
    let blocks_per_unit = (p.unit / p.block) as u64;
    let zeros = vec![0u8; p.unit as usize];

    PHASE.store(0, Ordering::Relaxed);
    install_faults(&p, &backing, 0, &trace.faults, &cov, false);
    let mut engine = try_attach(&p, &backing)
        .await
        .unwrap_or_else(|e| panic!("FIRST-ATTACH: seed {seed}: {e}\n{}", trace.report()));
    install_faults(&p, &backing, seed ^ 0xFA17, &trace.faults, &cov, true);

    for cycle_index in 0..p.cycles {
        bump(&cov.cycles);
        // An append succeeded since the last attach, checkpoint or failure.
        let mut active = false;
        let ops = rng.random_range(p.ops_lo..p.ops_hi);
        let power_loss = rng.random_bool(p.p_power);
        let faulty = p.faults > 0;
        PHASE.store(1, Ordering::Relaxed);
        for op_index in 0..ops {
            bump(&cov.ops);
            if p.profile == "committed" || op_index % 4 == 3 {
                let segments = engine.stats().await.journal_segments as u64;
                cov.max_segments.fetch_max(segments, Ordering::Relaxed);
            }
            let what = format!("seed {seed} cycle {cycle_index}");
            let created_before = cov.seg_created_in_ops.load(Ordering::Relaxed);
            let failed_before = cov.writes_failed.load(Ordering::Relaxed)
                + cov.flushes_failed.load(Ordering::Relaxed);
            let was_active = active;
            let roll = rng.random_range(0..100);
            // The committed mix is 55 write / 15 flush / 10 checkpoint / 20
            // read; the extra operation kinds take part of the write share.
            let kind = match roll {
                0..=54 => {
                    if p.profile == "committed" {
                        0
                    } else {
                        match rng.random_range(0..10) {
                            0..=1 if p.discard => 1,          // trim
                            2 => 2,                           // write_zeroes
                            3..=5 if blocks_per_unit > 1 => 3, // partial write
                            _ => 0,
                        }
                    }
                }
                55..=69 => 4,
                70..=79 => 5,
                _ => 6,
            };
            match kind {
                0 | 1 | 2 => {
                    let count = rng.random_range(1..=p.max_write_units);
                    let first = rng.random_range(0..p.device_units - count + 1);
                    let fua = rng.random_bool(0.25);
                    stamp += 1;
                    let images: Vec<Vec<u8>> = (first..first + count)
                        .map(|u| {
                            if kind == 0 {
                                image(&p, u, stamp)
                            } else {
                                zeros.clone()
                            }
                        })
                        .collect();
                    let result = match kind {
                        0 => {
                            let data: Vec<u8> = images.iter().flatten().copied().collect();
                            engine.write(first * unit, &data, fua).await
                        }
                        1 => {
                            bump(&cov.trims);
                            engine
                                .trim(first * unit, (count * unit) as usize, fua)
                                .await
                        }
                        _ => {
                            bump(&cov.zeroes);
                            engine
                                .write_zeroes(first * unit, (count * unit) as usize, fua)
                                .await
                        }
                    };
                    trace.op(format!(
                        "{} units {first}..{} stamp {stamp} fua={fua} -> {}",
                        ["write", "trim", "write_zeroes"][kind],
                        first + count,
                        err_text(&result)
                    ));
                    match result {
                        Ok(()) => {
                            bump(&cov.writes_ok);
                            for (i, u) in (first..first + count).enumerate() {
                                if fua {
                                    model.write_fua(u, &images[i]);
                                } else {
                                    model.write(u, &images[i]);
                                }
                                maybe.acknowledged(u, fua);
                            }
                        }
                        Err(e) => {
                            bump(&cov.writes_failed);
                            assert!(
                                faulty,
                                "WRITE-FAILED: {what}: write failed without faults: {e}\n{}",
                                trace.report()
                            );
                            if !p.fault_all_ops && p.partial == 0 {
                                assert!(
                                    matches!(
                                        e,
                                        CoreError::Io(_)
                                            | CoreError::Durability(_)
                                            | CoreError::Format(maki_format::FormatError::Io(_))
                                    ),
                                    "ERROR-CLASS: seed {seed}: unexpected error class {e}\n{}",
                                    trace.report()
                                );
                            }
                            for (i, u) in (first..first + count).enumerate() {
                                maybe.failed(u, images[i].clone());
                            }
                        }
                    }
                }
                3 => {
                    // Block-aligned range inside up to two units.
                    bump(&cov.partial_writes);
                    let start_unit = rng.random_range(0..p.device_units);
                    let start_block = rng.random_range(0..blocks_per_unit);
                    let device_blocks = p.device_units * blocks_per_unit;
                    let start = start_unit * blocks_per_unit + start_block;
                    let max_blocks = (device_blocks - start).min(blocks_per_unit + blocks_per_unit / 2);
                    let blocks = rng.random_range(1..=max_blocks);
                    let offset = start * p.block as u64;
                    let len = blocks * p.block as u64;
                    let fua = rng.random_bool(0.25);
                    stamp += 1;
                    let data: Vec<u8> = (0..len)
                        .map(|i| (stamp.wrapping_mul(0x9E37_79B1) ^ (i as u32)).to_le_bytes()[1] | 1)
                        .collect();
                    let first = offset / unit;
                    let last = (offset + len - 1) / unit;
                    let mut images = Vec::new();
                    for u in first..=last {
                        let mut img = resolve_live(
                            &p, &engine, &mut model, &mut maybe, u, &what, &mut trace, &cov,
                        )
                        .await;
                        let unit_start = u * unit;
                        let from = offset.max(unit_start) - unit_start;
                        let to = (offset + len).min(unit_start + unit) - unit_start;
                        let src = offset.max(unit_start) - offset;
                        img[from as usize..to as usize]
                            .copy_from_slice(&data[src as usize..(src + to - from) as usize]);
                        images.push(img);
                    }
                    let result = engine.write(offset, &data, fua).await;
                    trace.op(format!(
                        "partial write offset {offset} len {len} (units {first}..={last}) stamp \
                         {stamp} fua={fua} -> {}",
                        err_text(&result)
                    ));
                    match result {
                        Ok(()) => {
                            bump(&cov.writes_ok);
                            for (i, u) in (first..=last).enumerate() {
                                if fua {
                                    model.write_fua(u, &images[i]);
                                } else {
                                    model.write(u, &images[i]);
                                }
                                maybe.acknowledged(u, fua);
                            }
                        }
                        Err(e) => {
                            bump(&cov.writes_failed);
                            assert!(
                                faulty,
                                "WRITE-FAILED: {what}: partial write failed without faults: {e}\n{}",
                                trace.report()
                            );
                            for (i, u) in (first..=last).enumerate() {
                                maybe.failed(u, images[i].clone());
                            }
                        }
                    }
                }
                4 => {
                    let result = engine.flush().await;
                    trace.op(format!("flush -> {}", err_text(&result)));
                    match result {
                        Ok(()) => {
                            bump(&cov.flushes_ok);
                            model.flush();
                            maybe.flushed();
                        }
                        Err(e) => {
                            bump(&cov.flushes_failed);
                            assert!(
                                faulty,
                                "FLUSH-FAILED: {what}: flush failed without faults: {e}\n{}",
                                trace.report()
                            );
                        }
                    }
                }
                5 => {
                    let result = engine.checkpoint().await;
                    trace.op(format!("checkpoint -> {}", err_text(&result)));
                    match result {
                        Ok(_) => bump(&cov.checkpoints_ok),
                        Err(e) => {
                            bump(&cov.checkpoints_failed);
                            assert!(
                                faulty,
                                "CHECKPOINT-FAILED: {what}: checkpoint failed without faults: \
                                 {e}\n{}",
                                trace.report()
                            );
                        }
                    }
                }
                _ => {
                    let u = rng.random_range(0..p.device_units);
                    resolve_live(
                        &p, &engine, &mut model, &mut maybe, u, &what, &mut trace, &cov,
                    )
                    .await;
                }
            }
            let failed_after = cov.writes_failed.load(Ordering::Relaxed)
                + cov.flushes_failed.load(Ordering::Relaxed);
            if kind == 5 || failed_after != failed_before {
                active = false;
            } else if kind <= 3 {
                if was_active && cov.seg_created_in_ops.load(Ordering::Relaxed) != created_before {
                    bump(&cov.auto_rolls);
                }
                active = true;
            }
        }

        // End of cycle: restart, power loss, or worst-case power loss.
        let mut old = Some(engine);
        let what = if power_loss {
            let all_lost = p.p_all_lost > 0.0 && rng.random_bool(p.p_all_lost);
            // Half of the power losses hit a live engine (its worker and
            // handles die with the process view); the committed sweep always
            // drops the engine first.
            let live = p.profile != "committed" && rng.random_bool(0.5);
            if !live {
                if let Some(engine) = old.take() {
                    if p.profile != "committed" {
                        engine.stop_checkpoint_worker().await;
                    }
                    drop(engine);
                }
            }
            install_faults(&p, &backing, 0, &trace.faults, &cov, false);
            if all_lost {
                bump(&cov.all_lost);
                backing.crash_all_lost();
                trace.op(format!("power loss (everything volatile lost, live={live})"));
            } else {
                bump(&cov.power_losses);
                let kind = sampled_crash(&p, &backing, &mut rng, &cov);
                trace.op(format!("power loss ({kind}, live={live})"));
            }
            format!("seed {seed} cycle {cycle_index} (power loss)")
        } else {
            bump(&cov.restarts);
            install_faults(&p, &backing, 0, &trace.faults, &cov, false);
            if let Some(engine) = old.take() {
                if p.profile != "committed" {
                    engine.stop_checkpoint_worker().await;
                }
                drop(engine);
            }
            trace.op("restart".into());
            format!("seed {seed} cycle {cycle_index} (restart)")
        };
        drop(old);
        // The previous engine (if a live power loss left it) is gone before
        // the next process starts.
        engine = recover(&p, &backing, seed, cycle_index, &what, &mut trace, &cov).await;
        check_all(&p, &engine, &mut model, &mut maybe, &what, &trace, &cov).await;

        // K-01 pin: whatever a recovery served must survive a power loss
        // right after it, with no writer activity in between.
        if p.p_pin > 0.0 && rng.random_bool(p.p_pin) {
            bump(&cov.pins);
            engine.stop_checkpoint_worker().await;
            drop(engine);
            let kind = if rng.random_bool(0.5) {
                backing.crash_all_lost();
                "everything volatile lost"
            } else {
                sampled_crash(&p, &backing, &mut rng, &cov)
            };
            trace.op(format!("pin: power loss right after recovery ({kind})"));
            let what = format!("seed {seed} cycle {cycle_index} (pin after recovery, {kind})");
            PHASE.store(0, Ordering::Relaxed);
            engine = match try_attach(&p, &backing).await {
                Ok(engine) => engine,
                Err(e) => panic!(
                    "ATTACH-REFUSED: {what}: recovery refused the volume: {e}\n{}",
                    trace.report()
                ),
            };
            check_all(&p, &engine, &mut model, &mut maybe, &what, &trace, &cov).await;
        }

        install_faults(
            &p,
            &backing,
            seed ^ (cycle_index as u64 + 1),
            &trace.faults,
            &cov,
            true,
        );
    }
    install_faults(&p, &backing, 0, &trace.faults, &cov, false);
    engine.stop_checkpoint_worker().await;
    drop(engine);
    if verbose {
        println!("seed {seed}: clean\n{}", trace.report());
    }
}

// ---------------------------------------------------------------------------
// Concurrent partial-unit sweep (review_r3b_durability.rs `concurrent_sweep`)

enum Ack {
    Write { unit: u64, data: Vec<u8>, fua: bool },
}

#[derive(Clone)]
struct ConcP {
    p: P,
    writers: u64,
    units_per_writer: u64,
}

async fn writer_task(
    engine: Arc<Engine>,
    cp: ConcP,
    seed: u64,
    first_unit: u64,
    initial: BTreeMap<u64, Vec<u8>>,
    acks: tokio::sync::mpsc::UnboundedSender<Ack>,
) {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut expected = initial;
    let last_unit = first_unit + cp.units_per_writer;
    let unit = cp.p.unit as u64;
    let block = cp.p.block as u64;
    for step in 0..rng.random_range(10..40u32) {
        let roll = rng.random_range(0..100);
        if roll < 70 || (roll < 80 && !cp.p.discard) {
            // Block-aligned range inside this task's units, up to 1.5 units.
            let start_unit = rng.random_range(first_unit..last_unit);
            let start = start_unit * unit + rng.random_range(0..unit / block) * block;
            let max_len = (last_unit * unit - start).min(unit + unit / 2);
            let len = rng.random_range(1..=max_len / block) * block;
            let stamp = (seed as u32).wrapping_mul(1000).wrapping_add(step);
            let data: Vec<u8> = (0..len)
                .map(|i| (stamp.wrapping_mul(0x9E37_79B1) ^ (i as u32)).to_le_bytes()[1])
                .collect();
            let fua = rng.random_bool(0.25);
            engine.write(start, &data, fua).await.unwrap();
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
        } else if roll < 80 {
            // TRIM of whole units this task owns (v3 volumes).
            let count = rng.random_range(1..=cp.units_per_writer.min(3));
            let first = rng.random_range(first_unit..=last_unit - count);
            let fua = rng.random_bool(0.25);
            engine
                .trim(first * unit, (count * unit) as usize, fua)
                .await
                .unwrap();
            for u in first..first + count {
                let z = vec![0u8; unit as usize];
                expected.insert(u, z.clone());
                let _ = acks.send(Ack::Write {
                    unit: u,
                    data: z,
                    fua,
                });
            }
        } else {
            let u = rng.random_range(first_unit..last_unit);
            let b = rng.random_range(0..unit / block);
            let got = engine
                .read(u * unit + b * block, block as usize)
                .await
                .unwrap();
            let want = expected
                .get(&u)
                .map(|img| img[(b * block) as usize..((b + 1) * block) as usize].to_vec())
                .unwrap_or_else(|| vec![0u8; block as usize]);
            assert_eq!(
                got, want,
                "LIVE: writer {seed}: live block read of unit {u} block {b}"
            );
        }
        tokio::task::yield_now().await;
    }
}

async fn concurrent_sweep(seed: u64, cp: ConcP, cov: Arc<Cov>) {
    let p = cp.p.clone();
    let mut rng = StdRng::seed_from_u64(seed ^ 0xC0DE);
    let backing = Arc::new(match p.tear {
        Some(t) => CrashableBacking::new().with_tearing(t),
        None => CrashableBacking::new(),
    });
    let mut model = ReferenceBlockModel::new(p.unit as usize, p.device_units);
    let faults = Arc::new(Mutex::new(Vec::new()));
    install_faults(&p, &backing, 0, &faults, &cov, false);
    PHASE.store(0, Ordering::Relaxed);
    let mut engine = Arc::new(try_attach(&p, &backing).await.unwrap());

    for cycle in 0..p.cycles {
        bump(&cov.cycles);
        PHASE.store(1, Ordering::Relaxed);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut tasks = Vec::new();
        for w in 0..cp.writers {
            let first_unit = w * cp.units_per_writer;
            let initial: BTreeMap<u64, Vec<u8>> = (first_unit..first_unit + cp.units_per_writer)
                .map(|u| (u, model.read(u)))
                .collect();
            tasks.push(tokio::spawn(writer_task(
                engine.clone(),
                cp.clone(),
                seed * 100 + cycle as u64 * 10 + w,
                first_unit,
                initial,
                tx.clone(),
            )));
        }
        drop(tx);
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
                bump(&cov.flushes_ok);
                model.flush();
            } else {
                engine.checkpoint().await.unwrap();
                bump(&cov.checkpoints_ok);
            }
        }
        for task in tasks {
            if let Err(e) = task.await {
                match e.try_into_panic() {
                    Ok(payload) => std::panic::resume_unwind(payload),
                    Err(e) => panic!("writer task: {e}"),
                }
            }
        }
        apply(&mut model, &mut rx);

        engine.stop_checkpoint_worker().await;
        drop(engine);
        let what = if rng.random_bool(p.p_power) {
            if p.p_all_lost > 0.0 && rng.random_bool(p.p_all_lost) {
                bump(&cov.all_lost);
                backing.crash_all_lost();
            } else {
                bump(&cov.power_losses);
                sampled_crash(&p, &backing, &mut rng, &cov);
            }
            format!("seed {seed} cycle {cycle} (power loss) {p:?}")
        } else {
            bump(&cov.restarts);
            format!("seed {seed} cycle {cycle} (restart) {p:?}")
        };
        PHASE.store(0, Ordering::Relaxed);
        engine = Arc::new(
            try_attach(&p, &backing)
                .await
                .unwrap_or_else(|e| panic!("ATTACH-REFUSED: {what}: {e}")),
        );
        let stats = engine.stats().await;
        assert!(
            stats.checkpoint_sequence <= stats.durable_sequence,
            "CKPT-AHEAD: {what}"
        );
        for unit in 0..p.device_units {
            let actual = engine
                .read(unit * p.unit as u64, p.unit as usize)
                .await
                .unwrap_or_else(|e| panic!("READ-AFTER-RECOVERY: {what}: unit {unit}: {e}"));
            if let Err(violation) = model.crash_adopt(unit, &actual) {
                panic!("ORACLE: {what}: {violation}");
            }
        }
    }
    engine.stop_checkpoint_worker().await;
}

// ---------------------------------------------------------------------------
// Media damage after a power loss (review_r3b_durability.rs `damage_sweep`)

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

/// Returns whether the volume could still be attached after the damage.
async fn damage_sweep(seed: u64, p: P, cov: Arc<Cov>) -> bool {
    let mut rng = StdRng::seed_from_u64(seed ^ 0xDA3A);
    let backing = Arc::new(match p.tear {
        Some(t) => CrashableBacking::new().with_tearing(t),
        None => CrashableBacking::new(),
    });
    let mut model = ReferenceBlockModel::new(p.unit as usize, p.device_units);
    let mut maybe = Maybe::default();
    let mut stamp: u32 = 0;
    let mut log: Vec<String> = vec![format!("params {p:?}")];
    let unit = p.unit as u64;
    let zeros = vec![0u8; p.unit as usize];
    let faults = Arc::new(Mutex::new(Vec::new()));
    install_faults(&p, &backing, 0, &faults, &cov, false);
    PHASE.store(0, Ordering::Relaxed);
    let mut engine = try_attach(&p, &backing).await.unwrap();

    for cycle in 0..p.cycles {
        bump(&cov.cycles);
        PHASE.store(1, Ordering::Relaxed);
        for _ in 0..rng.random_range(8..40) {
            bump(&cov.ops);
            match rng.random_range(0..100) {
                0..=59 => {
                    let count = rng.random_range(1..=3u64.min(p.device_units));
                    let first = rng.random_range(0..p.device_units - count + 1);
                    let fua = rng.random_bool(0.25);
                    let trim = p.profile != "committed" && p.discard && rng.random_bool(0.25);
                    stamp += 1;
                    let images: Vec<Vec<u8>> = (first..first + count)
                        .map(|u| if trim { zeros.clone() } else { image(&p, u, stamp) })
                        .collect();
                    let tag = format!(
                        "{} {first}..{} stamp {stamp}{}",
                        if trim { "trim" } else { "write" },
                        first + count,
                        if fua { " fua" } else { "" }
                    );
                    let result = if trim {
                        engine.trim(first * unit, (count * unit) as usize, fua).await
                    } else {
                        let data: Vec<u8> = images.iter().flatten().copied().collect();
                        engine.write(first * unit, &data, fua).await
                    };
                    match result {
                        Ok(()) => {
                            log.push(tag);
                            for (i, u) in (first..first + count).enumerate() {
                                if fua {
                                    model.write_fua(u, &images[i]);
                                } else {
                                    model.write(u, &images[i]);
                                }
                                maybe.acknowledged(u, fua);
                            }
                        }
                        Err(e) => {
                            log.push(format!("{tag} refused: {e}"));
                            for (i, u) in (first..first + count).enumerate() {
                                maybe.failed(u, images[i].clone());
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

        engine.stop_checkpoint_worker().await;
        drop(engine);
        let kind = sampled_crash(&p, &backing, &mut rng, &cov);
        bump(&cov.power_losses);
        log.push(format!("-- power loss ({kind}), end of cycle {cycle} --"));
        let candidates = damage_candidates(&backing);
        let mut journal_damaged = false;
        let mut discard_damaged = false;
        for _ in 0..rng.random_range(1..=3usize) {
            let path = candidates[rng.random_range(0..candidates.len())].clone();
            journal_damaged |= path.starts_with("journal/");
            discard_damaged |= path.contains(".discard.");
            bump(&cov.damaged);
            log.push(format!("DAMAGE {}", damage(&backing, &path, &mut rng)));
        }

        // The checker must never panic on damaged input.
        bump(&cov.deep_checks);
        let _ = maki_core::check::deep_check(
            backing.process() as Arc<dyn Backing>,
            p.options().volume.journal_segment_size,
        );

        PHASE.store(0, Ordering::Relaxed);
        engine = match try_attach(&p, &backing).await {
            Ok(engine) => engine,
            Err(_refused) => return false,
        };
        bump(&cov.damage_attached);
        let stats = engine.stats().await;
        assert!(
            stats.checkpoint_sequence <= stats.durable_sequence,
            "CKPT-AHEAD: seed {seed} cycle {cycle}: checkpoint ran ahead of durability\n{}",
            log.join("\n")
        );
        for u in 0..p.device_units {
            match engine.read(u * unit, p.unit as usize).await {
                Ok(actual) => {
                    if let Err(violation) = model.crash_adopt(u, &actual) {
                        let landed = maybe.crash_may_show(u, &actual);
                        // S-04 (documented): journal damage may revert a
                        // FLUSH-acknowledged write to its previous durable
                        // value. A violation with only a discard map damaged
                        // is reported under its own class for triage.
                        assert!(
                            landed || journal_damaged,
                            "{}: seed {seed} cycle {cycle}: {violation}\nhistory:\n  {}",
                            if discard_damaged {
                                "DAMAGE-ORACLE-DISCARD"
                            } else {
                                "DAMAGE-ORACLE"
                            },
                            log.join("\n  "),
                        );
                        model.write_fua(u, &actual);
                    }
                    maybe.settled(u);
                }
                Err(CoreError::Corrupt(_)) | Err(CoreError::Io(_)) => {
                    bump(&cov.damage_eio_units);
                }
                Err(e) => panic!(
                    "ERROR-CLASS: seed {seed} cycle {cycle}: unit {u}: unexpected error class \
                     {e}\n{}",
                    log.join("\n")
                ),
            }
        }
    }
    engine.stop_checkpoint_worker().await;
    true
}

// ---------------------------------------------------------------------------
// Driver

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

fn seeds() -> std::ops::Range<u64> {
    let start = env_u64("AUDIT8_SEED_START").unwrap_or(0);
    let count = env_u64("AUDIT8_SEED_COUNT").unwrap_or(40);
    start..start + count
}

fn profile() -> &'static str {
    match std::env::var("AUDIT8_PROFILE").as_deref() {
        Ok("committed") => "committed",
        Ok("tiny") => "tiny",
        Ok("rmw") => "rmw",
        Ok("big") => "big",
        _ => "random",
    }
}

fn params(seed: u64, default_cycles: usize, faults_default: Option<u32>) -> P {
    let cycles = env_u64("AUDIT8_CYCLES").unwrap_or(default_cycles as u64) as usize;
    let faults = env_u64("AUDIT8_FAULTS").map(|f| f as u32).or(faults_default);
    match profile() {
        "committed" => {
            let mut p = P::committed(
                std::env::var_os("AUDIT8_CACHE").is_some(),
                faults.unwrap_or(0),
                cycles,
            );
            // The one deviation the committed profile allows, for the
            // reproducibility probe (T2): units per shard (48 = one shard).
            if let Some(shard_units) = env_u64("AUDIT8_SHARD_UNITS") {
                p.shard_units = shard_units;
            }
            p
        }
        other => P::random(other, seed, faults, cycles),
    }
}

fn panic_text(e: tokio::task::JoinError) -> String {
    match e.try_into_panic() {
        Ok(payload) => payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "non-string panic".into()),
        Err(e) => format!("task cancelled: {e}"),
    }
}

/// Run one closure per seed (each isolated), stop at the wall-clock budget,
/// print coverage and fail at the end with every violation class.
async fn drive<F, Fut>(name: &str, cov: Arc<Cov>, run: F)
where
    F: Fn(u64) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let budget = env_u64("AUDIT8_BUDGET_SECS").map(Duration::from_secs);
    let started = Instant::now();
    let range = seeds();
    let mut failures: Vec<(u64, String)> = Vec::new();
    let mut last = range.start;
    // A panic in a seed is recorded, not printed with its whole history.
    let quiet = std::env::var_os("AUDIT8_ONE").is_none();
    if quiet {
        // Record every panic (message and location) instead of printing it:
        // a panic in an engine worker thread must not go unnoticed.
        std::panic::set_hook(Box::new(|info| {
            let mut log = PANICS.lock();
            if log.len() < 64 {
                log.push(info.to_string());
            }
        }));
    }
    for seed in range.clone() {
        if budget.is_some_and(|b| started.elapsed() > b) {
            break;
        }
        last = seed + 1;
        bump(&cov.seeds);
        PANICS.lock().clear();
        let outcome = tokio::spawn(run(seed)).await;
        let panics: Vec<String> = std::mem::take(&mut *PANICS.lock());
        let outcome = match outcome {
            Err(e) => Err(format!(
                "{}\nrecorded panics:\n  {}",
                panic_text(e),
                panics.join("\n  ")
            )),
            // A panic somewhere (a background thread) that the seed survived.
            Ok(()) if !panics.is_empty() => Err(format!(
                "SILENT-PANIC: seed {seed} passed but a thread panicked:\n  {}",
                panics.join("\n  ")
            )),
            Ok(()) => Ok(()),
        };
        if let Err(text) = outcome {
            let class = text.split(':').next().unwrap_or("?").to_string();
            println!(
                "AUDIT8-FAIL test={name} profile={} seed={seed} class={class}",
                profile()
            );
            if let Ok(dir) = std::env::var("AUDIT8_FAIL_DIR") {
                let _ = std::fs::create_dir_all(&dir);
                let _ = std::fs::write(
                    format!("{dir}/{name}-{}-{seed}.txt", profile()),
                    &text,
                );
            }
            failures.push((seed, text));
        }
    }
    if quiet {
        let _ = std::panic::take_hook();
    }
    println!(
        "AUDIT8-SWEEP test={name} profile={} seeds={}..{} failures={} elapsed={:.0}s | {}",
        profile(),
        range.start,
        last,
        failures.len(),
        started.elapsed().as_secs_f64(),
        cov.render()
    );
    if !failures.is_empty() {
        let mut classes: BTreeMap<String, Vec<u64>> = BTreeMap::new();
        for (seed, text) in &failures {
            classes
                .entry(text.split(':').next().unwrap_or("?").to_string())
                .or_default()
                .push(*seed);
        }
        let first = &failures[0];
        panic!(
            "{} failing seed(s) by class: {classes:?}\nfirst (seed {}):\n{}",
            failures.len(),
            first.0,
            first.1.chars().take(6000).collect::<String>()
        );
    }
}

/// Sequential sweep, fault-free and with faults (the seed decides unless
/// `AUDIT8_FAULTS` is set).
#[tokio::test]
async fn audit8_r3b_seq() {
    let cov = Arc::new(Cov::default());
    let verbose = std::env::var_os("AUDIT8_ONE").is_some();
    let c = cov.clone();
    drive("r3b_seq", cov, move |seed| {
        let p = params(seed, 6, None);
        seq_sweep(seed, p, c.clone(), verbose)
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit8_r3b_concurrent() {
    let cov = Arc::new(Cov::default());
    let c = cov.clone();
    drive("r3b_concurrent", cov, move |seed| {
        let cp = if profile() == "committed" {
            let mut p = P::committed(std::env::var_os("AUDIT8_CACHE").is_some(), 0, 4);
            p.unit = 4096;
            p.tear = Some(256);
            ConcP {
                p,
                writers: 4,
                units_per_writer: 12,
            }
        } else {
            let mut r = StdRng::seed_from_u64(seed ^ 0xC0_4C);
            let mut p = params(seed, 4, Some(0));
            p.faults = 0;
            p.fault_all_ops = false;
            p.partial = 0;
            p.recovery_faults = false;
            let writers = r.random_range(1..=6u64);
            let units_per_writer = r.random_range(1..=12u64);
            p.device_units = writers * units_per_writer + r.random_range(0..3u64);
            p.max_write_units = 2;
            // Every writer may hold a request of up to two units (three
            // records with a misaligned start, or a three-unit trim) at once:
            // size the bounds so that all of them fit after a full reclaim.
            let rec = p.rec();
            let req = 4 * writers;
            if p.journal_max != BIG {
                p.journal_max = 2 * p.segment_size.max(48 + rec)
                    + req * rec
                    + (req + 2) * 48
                    + r.random_range(0..3 * p.segment_size.max(rec));
            }
            if p.overlay_entries != 0 {
                p.overlay_entries = req + r.random_range(0..8u64);
            }
            if p.overlay_bytes != 0 {
                p.overlay_bytes = 2 * req * (p.unit as u64 + p.overhead as u64)
                    + r.random_range(0..6u64) * (p.unit as u64 + p.overhead as u64);
            }
            ConcP {
                p,
                writers,
                units_per_writer,
            }
        };
        concurrent_sweep(seed, cp, c.clone())
    })
    .await;
}

#[tokio::test]
async fn audit8_r3b_damage() {
    let cov = Arc::new(Cov::default());
    let c = cov.clone();
    drive("r3b_damage", cov, move |seed| {
        let mut p = params(seed, 4, Some(0));
        p.faults = 0;
        p.fault_all_ops = false;
        p.partial = 0;
        p.recovery_faults = false;
        let c = c.clone();
        async move {
            damage_sweep(seed, p, c).await;
        }
    })
    .await;
}

/// Control: the committed profile over the committed default seed ranges must
/// pass (the copy is faithful), and it shows what those sweeps never do: no
/// journal segment is ever created by a workload operation.
#[tokio::test]
async fn audit8_committed_profile_never_rolls() {
    let cov = Arc::new(Cov::default());
    for seed in 0..120u64 {
        seq_sweep(seed, P::committed(false, 0, 4), cov.clone(), false).await;
    }
    println!("AUDIT8-CONTROL committed profile, no faults: {}", cov.render());
    let rolls = cov.auto_rolls.load(Ordering::Relaxed);
    let faulty = Arc::new(Cov::default());
    for seed in 0..80u64 {
        seq_sweep(seed, P::committed(false, 150, 4), faulty.clone(), false).await;
    }
    println!("AUDIT8-CONTROL committed profile, 150 permille sync faults: {}", faulty.render());
    // The same loop with the journal segment sized for three records.
    let small = Arc::new(Cov::default());
    for seed in 0..120u64 {
        let mut p = P::committed(false, 0, 4);
        p.profile = "committed-small-segment";
        p.segment_size = 48 + 3 * p.rec();
        seq_sweep(seed, p, small.clone(), false).await;
    }
    println!("AUDIT8-CONTROL 3-record segments, no faults: {}", small.render());
    assert!(small.auto_rolls.load(Ordering::Relaxed) > 0, "the roll counter never fires");
    assert_eq!(
        rolls, 0,
        "the committed profile rolled the journal inside a write after all"
    );
}
