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
    /// Keep the background checkpoint worker running (with a low journal
    /// watermark, so it wakes constantly) instead of stopping it.
    pub worker: bool,
    /// Above 1: some operations are issued as a batch of up to this many
    /// concurrent requests on disjoint units (plus FLUSH/checkpoint).
    pub concurrency: usize,
    /// Simulated backing free space changes before every operation, with an
    /// emergency reserve and checkpoint headroom enabled: some writes are
    /// refused with ENOSPC (side-effect free) and the worker checkpoints on
    /// low space and on refusals.
    pub space: bool,
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
                journal_high_watermark_bytes: if self.worker {
                    self.segment_size.max(160)
                } else {
                    u64::MAX
                },
                journal_max_bytes: self.journal_max_bytes,
                max_pending_bytes: self.max_pending_bytes,
                emergency_reserve_bytes: if self.space {
                    4 * self.unit as u64
                } else {
                    0
                },
                low_space_checkpoint_bytes: if self.space {
                    3 * self.unit as u64
                } else {
                    0
                },
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
        worker: false,
        concurrency: 1,
        space: false,
    };
    let rec = |unit: u64| 32 + unit + 8;
    match name {
        // ---- configurations added by the second auditor ----
        // 4 KiB blocks and units (no RMW), two records per segment, v3.
        "blk4k-v3" => Cfg {
            name: "blk4k-v3",
            block: 4096,
            unit: 4096,
            device_units: 24,
            units_per_shard: 4,
            segment_size: 48 + 2 * rec(4096),
            journal_max_bytes: 5 * (48 + 2 * rec(4096)),
            max_pending_bytes: rec(4096),
            max_request_units: 4,
            discard: true,
            tear: 512,
            ..base
        },
        // 16 KiB units over 4 KiB blocks (quarter-unit writes), 2 units per
        // shard, 11 units (partial last shard), tiny overlay.
        "u16k" => Cfg {
            name: "u16k",
            block: 4096,
            unit: 16384,
            device_units: 11,
            units_per_shard: 2,
            segment_size: 48 + 2 * rec(16384),
            journal_max_bytes: 4 * (48 + 2 * rec(16384)),
            max_pending_bytes: rec(16384),
            max_overlay_entries: 4,
            max_request_units: 3,
            tear: 4096,
            ..base
        },
        "u16k-v3" => Cfg {
            name: "u16k-v3",
            block: 4096,
            unit: 16384,
            device_units: 11,
            units_per_shard: 2,
            segment_size: 48 + 2 * rec(16384),
            journal_max_bytes: 4 * (48 + 2 * rec(16384)),
            max_pending_bytes: rec(16384),
            max_overlay_entries: 4,
            max_request_units: 3,
            discard: true,
            tear: 4096,
            ..base
        },
        // The smallest legal pending bound (exactly one record: every
        // second record of a request syncs inline), small hard limit, small
        // overlay, verify-on-hit cache, v3.
        "pend1-v3" => Cfg {
            name: "pend1-v3",
            segment_size: 48 + 5 * rec(512),
            journal_max_bytes: 3 * (48 + 5 * rec(512)),
            max_pending_bytes: rec(512),
            max_overlay_entries: 6,
            max_overlay_bytes: 10 * (512 + 8),
            discard: true,
            cache: Some(true),
            ..base
        },
        // Background checkpoint worker left running (sequential requests).
        "seg3-worker-v3" => Cfg {
            name: "seg3-worker-v3",
            segment_size: 48 + 3 * rec(512),
            journal_max_bytes: 4 * (48 + 3 * rec(512)),
            max_pending_bytes: 2 * rec(512),
            max_overlay_entries: 8,
            discard: true,
            worker: true,
            ..base
        },
        "rmw-worker" => Cfg {
            name: "rmw-worker",
            unit: 4096,
            device_units: 22,
            units_per_shard: 3,
            segment_size: 48 + 2 * rec(4096),
            max_overlay_entries: 5,
            max_overlay_bytes: 12 * (4096 + 8),
            max_request_units: 4,
            tear: 512,
            worker: true,
            ..base
        },
        // Concurrent request batches on disjoint units, worker running.
        "conc-v3" => Cfg {
            name: "conc-v3",
            segment_size: 48 + 3 * rec(512),
            journal_max_bytes: 4 * (48 + 3 * rec(512)),
            max_pending_bytes: 2 * rec(512),
            max_overlay_entries: 10,
            discard: true,
            worker: true,
            concurrency: 4,
            ..base
        },
        "conc-v2" => Cfg {
            name: "conc-v2",
            segment_size: 48 + 3 * rec(512),
            journal_max_bytes: 4 * (48 + 3 * rec(512)),
            max_pending_bytes: 2 * rec(512),
            max_overlay_entries: 10,
            worker: true,
            concurrency: 4,
            ..base
        },
        "conc-rmw-v3" => Cfg {
            name: "conc-rmw-v3",
            unit: 4096,
            device_units: 22,
            units_per_shard: 3,
            segment_size: 48 + 2 * rec(4096),
            max_overlay_entries: 6,
            max_overlay_bytes: 14 * (4096 + 8),
            max_request_units: 4,
            discard: true,
            tear: 512,
            worker: true,
            concurrency: 3,
            ..base
        },
        "conc-shard1-v3" => Cfg {
            name: "conc-shard1-v3",
            device_units: 13,
            units_per_shard: 1,
            segment_size: 48 + 2 * rec(512),
            journal_max_bytes: 5 * (48 + 2 * rec(512)),
            discard: true,
            cache: Some(false),
            worker: true,
            concurrency: 4,
            ..base
        },
        // Free-space admission (emergency reserve + checkpoint headroom).
        "space-v3" => Cfg {
            name: "space-v3",
            segment_size: 48 + 3 * rec(512),
            journal_max_bytes: 4 * (48 + 3 * rec(512)),
            max_pending_bytes: 2 * rec(512),
            discard: true,
            worker: true,
            space: true,
            ..base
        },
        "space-rmw" => Cfg {
            name: "space-rmw",
            unit: 4096,
            device_units: 22,
            units_per_shard: 3,
            segment_size: 48 + 2 * rec(4096),
            max_overlay_entries: 5,
            max_request_units: 4,
            tear: 512,
            space: true,
            ..base
        },
        "space-conc-v3" => Cfg {
            name: "space-conc-v3",
            segment_size: 48 + 3 * rec(512),
            journal_max_bytes: 4 * (48 + 3 * rec(512)),
            max_pending_bytes: 2 * rec(512),
            max_overlay_entries: 10,
            discard: true,
            worker: true,
            concurrency: 4,
            space: true,
            ..base
        },
        // Concurrency without the worker: only foreground races.
        "conc-noworker-v3" => Cfg {
            name: "conc-noworker-v3",
            segment_size: 48 + 3 * rec(512),
            journal_max_bytes: 4 * (48 + 3 * rec(512)),
            max_pending_bytes: 2 * rec(512),
            max_overlay_entries: 10,
            discard: true,
            concurrency: 4,
            ..base
        },
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

/// `random`/`random-v3`/`random-any`: a geometry and limit set drawn from
/// the seed (edge shapes: one shard, one-unit shards, partial last shard,
/// up to 8 blocks per unit, one to six records per segment, the smallest
/// legal pending bound, tight overlay bounds, worker and concurrency on or
/// off). Every limit is kept large enough that a lone request always fits.
pub fn cfg_for(name: &str, seed: u64) -> Cfg {
    if !name.starts_with("random") {
        return cfg(name);
    }
    let mut r = StdRng::seed_from_u64(seed ^ 0x6E0_6E0);
    let block: u32 = if r.random_bool(0.75) { 512 } else { 4096 };
    let unit = block * [1u32, 1, 2, 4, 8][r.random_range(0..5)];
    let device_units = r.random_range(2..=40u64);
    let units_per_shard = match r.random_range(0..4) {
        0 => 1,
        1 => device_units, // a single shard
        _ => r.random_range(1..=9u64),
    };
    let rec = 32 + unit as u64 + 8;
    let per_segment = r.random_range(1..=6u64);
    let segment_size = 48 + per_segment * rec + r.random_range(0..rec);
    let max_request_units = r.random_range(1..=6u64).min(device_units);
    let concurrency = if r.random_bool(0.35) {
        r.random_range(2..=4usize)
    } else {
        1
    };
    let worker = r.random_bool(0.4);
    // An unaligned request of max_request_bytes touches one extra unit.
    let request_records = (max_request_units + 1) * concurrency as u64;
    let journal_max_bytes = if r.random_bool(0.3) {
        BIG
    } else {
        2 * segment_size
            + request_records * rec
            + (request_records + 2) * 48
            + r.random_range(0..3 * segment_size)
    };
    let max_pending_bytes = if r.random_bool(0.3) {
        BIG
    } else {
        rec * r.random_range(1..=4u64)
    };
    let max_overlay_entries = if r.random_bool(0.5) {
        0
    } else {
        request_records + r.random_range(0..8u64)
    };
    let max_overlay_bytes = if r.random_bool(0.6) {
        0
    } else {
        2 * request_records * (unit as u64 + 8) + r.random_range(0..6u64) * (unit as u64 + 8)
    };
    let discard = match name {
        "random-v3" => true,
        "random" => false,
        _ => r.random_bool(0.5),
    };
    let cache = match r.random_range(0..3) {
        0 => None,
        1 => Some(false),
        _ => Some(true),
    };
    let tear = [128usize, 512, 4096][r.random_range(0..3)].min(unit as usize);
    Cfg {
        name: match name {
            "random-v3" => "random-v3",
            "random" => "random",
            _ => "random-any",
        },
        block,
        unit,
        device_units,
        units_per_shard,
        segment_size,
        journal_max_bytes,
        max_pending_bytes,
        max_overlay_bytes,
        max_overlay_entries,
        max_request_units,
        discard,
        cache,
        tear,
        worker,
        concurrency,
        space: false,
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
    /// Percent chance (per attempt, up to three) that recovery runs with
    /// the transient faults above live, Linux failed-fsync model (a failed
    /// recovery is followed by a restart or power loss and another try).
    pub recovery_fault_pct: u32,
    /// The transient faults apply to recovery only, never to the workload.
    pub recovery_only: bool,
    /// Percent chance per cycle of media damage to one or two non-journal
    /// files after the crash; the seed ends after checking that cycle.
    pub damage_pct: u32,
    /// Permille of successful syncs (file or directory) reported as failed
    /// after they persisted everything (see `Lying`).
    pub lying_sync: u32,
}

impl Mode {
    fn transient(&self) -> bool {
        !self.recovery_only && self.any_faults()
    }

    fn any_faults(&self) -> bool {
        self.sync_data
            + self.lying_sync
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
            ..Mode::default()
        },
        // Clean workload; recovery itself sees transient faults with the
        // Linux failed-fsync model, then restarts or loses power, and tries
        // again (the death modes use lenient sync failures).
        "rfault" => Mode {
            name: "rfault",
            strict_restart: true,
            sync_data: 120,
            sync_dir: 120,
            write: 40,
            partial: 40,
            set_len: 40,
            remove: 60,
            rename: 40,
            create: 40,
            recovery_fault_pct: 70,
            recovery_only: true,
            double_crash_pct: 15,
            ..Mode::default()
        },
        // Faulty workload and faulty recovery.
        "chaos-rfault" => Mode {
            name: "chaos-rfault",
            strict_restart: true,
            sync_data: 80,
            sync_dir: 80,
            write: 30,
            partial: 30,
            set_len: 30,
            remove: 60,
            rename: 30,
            create: 30,
            heal_pct: 4,
            recovery_fault_pct: 60,
            double_crash_pct: 10,
            ..Mode::default()
        },
        // Crash-only workload, then media damage outside the journal.
        "damage" => Mode {
            name: "damage",
            double_crash_pct: 10,
            damage_pct: 30,
            ..Mode::default()
        },
        "death-damage" => Mode {
            name: "death-damage",
            midop_death_pct: 50,
            recovery_death_pct: 30,
            double_crash_pct: 10,
            damage_pct: 30,
            ..Mode::default()
        },
        "lying" => Mode {
            name: "lying",
            strict_restart: true,
            lying_sync: 120,
            heal_pct: 4,
            double_crash_pct: 10,
            ..Mode::default()
        },
        "chaos-lying" => Mode {
            name: "chaos-lying",
            strict_restart: true,
            sync_data: 50,
            sync_dir: 50,
            lying_sync: 80,
            write: 25,
            partial: 25,
            set_len: 25,
            remove: 50,
            rename: 25,
            create: 25,
            heal_pct: 4,
            recovery_fault_pct: 50,
            double_crash_pct: 10,
            ..Mode::default()
        },
        "rfault-lying" => Mode {
            name: "rfault-lying",
            strict_restart: true,
            sync_data: 100,
            sync_dir: 100,
            lying_sync: 100,
            recovery_fault_pct: 80,
            recovery_only: true,
            double_crash_pct: 15,
            ..Mode::default()
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
    /// Mutations left before one single transient fault; negative = off.
    single: AtomicI64,
    /// The single fault chose to be a short write of this `write_at`.
    single_partial: AtomicBool,
    /// The single fault chose to be a lying sync (persist, then fail).
    lie_next: AtomicBool,
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
            single: AtomicI64::new(-1),
            single_partial: AtomicBool::new(false),
            lie_next: AtomicBool::new(false),
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

    /// One transient fault after `mutations` more mutations (Linux model).
    fn arm_single(&self, mutations: u64) {
        self.single.store(mutations as i64, Ordering::SeqCst);
    }

    fn disarm_single(&self) {
        self.single.store(-1, Ordering::SeqCst);
        self.single_partial.store(false, Ordering::SeqCst);
        self.lie_next.store(false, Ordering::SeqCst);
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
            let single = me.single.load(Ordering::SeqCst);
            if single >= 0 {
                if single <= 1 {
                    me.single.store(-1, Ordering::SeqCst);
                    if let FaultOp::WriteAt { len, .. } = op {
                        if *len > 1 && me.rng.lock().random_bool(0.5) {
                            me.single_partial.store(true, Ordering::SeqCst);
                            return None;
                        }
                    }
                    if matches!(op, FaultOp::SyncData { .. } | FaultOp::SyncDir { .. })
                        && me.mode.lying_sync > 0
                        && me.rng.lock().random_bool(0.5)
                    {
                        me.lie_next.store(true, Ordering::SeqCst);
                        return None;
                    }
                    me.log.lock().push(format!("      !! SINGLE fault {op:?}"));
                    return Some(io::Error::other("audit: single injected failure"));
                }
                me.single.store(single - 1, Ordering::SeqCst);
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
            if me.single_partial.swap(false, Ordering::SeqCst) {
                if let FaultOp::WriteAt { len, .. } = op {
                    let keep = me.rng.lock().random_range(0..*len);
                    me.log
                        .lock()
                        .push(format!("      !! SINGLE short write {keep} of {op:?}"));
                    return Some((keep, io::Error::other("audit: single short write")));
                }
            }
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
// Offline deep check, run on the crashed (not yet recovered) volume: it must
// be read-only, and it promises that "anything that would refuse attach or
// return EIO at runtime is reported here, and nothing the runtime accepts is
// reported as an error" (crates/maki-core/src/check.rs). `None` = the check
// was inconclusive (an I/O error).

fn run_deep_check(
    cfg: &Cfg,
    backing: &Arc<CrashableBacking>,
    injector: &Injector,
) -> Result<Option<maki_format::checker::CheckReport>, String> {
    let before = injector.mutations();
    let result = maki_core::check::deep_check(backing.clone() as Arc<dyn Backing>, cfg.segment_size);
    let after = injector.mutations();
    if after != before {
        return Err(format!(
            "CHECK-MUTATED: the offline deep check performed {} backing mutation(s)",
            after - before
        ));
    }
    Ok(result.ok())
}

// ---------------------------------------------------------------------------
// Media damage (outside the journal directory)

fn damage_candidates(backing: &CrashableBacking) -> Vec<String> {
    let mut out = Vec::new();
    for dir in ["", "data", "checkpoint"] {
        if let Ok(names) = backing.list(dir) {
            for name in names {
                let path = if dir.is_empty() {
                    name
                } else {
                    format!("{dir}/{name}")
                };
                if path.starts_with("journal") || path == "volume.lock" {
                    continue;
                }
                if backing.open(&path, false).is_ok() {
                    out.push(path);
                }
            }
        }
    }
    out.sort();
    out
}

fn damage_file(backing: &CrashableBacking, path: &str, rng: &mut StdRng) -> String {
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
            let mut offsets = std::collections::BTreeSet::new();
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

/// Finding 1 of this audit (see `audit_sweep_regressions.rs`): a torn
/// header of a never-completed segment refuses attach. Recognised so that a
/// sweep keeps looking for other classes; counted as `known-torn-header`.
fn known_torn_header(error: &str, log: &[String]) -> bool {
    // AUDIT_STRICT_KNOWN=1 reports the known class as a failure again.
    std::env::var_os("AUDIT_STRICT_KNOWN").is_none()
        && error.contains("invalid header")
        && log.iter().any(|l| {
            l.contains("short write")
                && l.contains("journal/seg-")
                && l.contains("offset: 0, len: 48")
        })
}

// ---------------------------------------------------------------------------
// Coverage of rare engine paths: count WARN/ERROR tracing events by message
// shape (digits folded), printed after every sweep.

static TRACE_COUNTS: std::sync::OnceLock<Arc<Mutex<BTreeMap<String, u64>>>> =
    std::sync::OnceLock::new();

struct TraceCounter(Arc<Mutex<BTreeMap<String, u64>>>);

struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for TraceCounter {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        let level = *event.metadata().level();
        if level != tracing::Level::WARN && level != tracing::Level::ERROR {
            return;
        }
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        let mut key = String::new();
        let mut in_digits = false;
        for c in visitor.0.chars() {
            if c.is_ascii_digit() {
                if !in_digits {
                    key.push('#');
                }
                in_digits = true;
            } else {
                in_digits = false;
                key.push(c);
            }
        }
        key.truncate(110);
        *self.0.lock().entry(format!("{level} {key}")).or_default() += 1;
    }
}

fn trace_counts() -> Arc<Mutex<BTreeMap<String, u64>>> {
    TRACE_COUNTS
        .get_or_init(|| {
            use tracing_subscriber::layer::SubscriberExt;
            let counts = Arc::new(Mutex::new(BTreeMap::new()));
            let subscriber =
                tracing_subscriber::registry().with(TraceCounter(counts.clone()));
            let _ = tracing::subscriber::set_global_default(subscriber);
            counts
        })
        .clone()
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

async fn try_attach(cfg: &Cfg, backing: &Arc<dyn Backing>) -> Result<Engine, AttachError> {
    Engine::attach(
        backing.clone(),
        Arc::new(FakeCryptoProvider::new(cfg.unit)),
        cfg.options(),
    )
    .await
}

// ---------------------------------------------------------------------------
// A "lying" sync: the inner `fdatasync`/directory sync really happens and
// persists everything, and then an error is reported anyway (Linux reports a
// writeback error even when most or all pages reached the disk). The engine
// must never rely on the bytes of a failed barrier being absent.

struct Lying {
    inner: Arc<CrashableBacking>,
    injector: Arc<Injector>,
}

struct LyingFile {
    inner: Arc<dyn maki_backing::BackingFile>,
    path: String,
    injector: Arc<Injector>,
}

impl Injector {
    fn lie(&self, what: &str) -> bool {
        if self.lie_next.swap(false, Ordering::SeqCst) {
            self.log.lock().push(format!("      !! SINGLE lying sync of {what}"));
            return true;
        }
        if self.dead.load(Ordering::SeqCst)
            || self.countdown.load(Ordering::SeqCst) >= 0
            || !self.enabled.load(Ordering::SeqCst)
            || self.mode.lying_sync == 0
        {
            return false;
        }
        if self.rng.lock().random_range(0..1000) < self.mode.lying_sync {
            self.log.lock().push(format!("      ! lying sync of {what}"));
            return true;
        }
        false
    }
}

impl maki_backing::BackingFile for LyingFile {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.inner.read_at(offset, buf)
    }
    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.inner.write_at(offset, data)
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.inner.set_len(len)
    }
    fn allocate_range(&self, offset: u64, len: u64) -> io::Result<()> {
        self.inner.allocate_range(offset, len)
    }
    fn punch_hole(&self, offset: u64, len: u64) -> io::Result<()> {
        self.inner.punch_hole(offset, len)
    }
    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }
    fn sync_data(&self) -> io::Result<()> {
        self.inner.sync_data()?;
        if self.injector.lie(&self.path) {
            return Err(io::Error::other("audit: sync persisted but reported failure"));
        }
        Ok(())
    }
    fn sync_all(&self) -> io::Result<()> {
        self.inner.sync_all()?;
        if self.injector.lie(&self.path) {
            return Err(io::Error::other("audit: sync persisted but reported failure"));
        }
        Ok(())
    }
}

impl Backing for Lying {
    fn check_freshness(&self) -> io::Result<()> {
        self.inner.check_freshness()
    }
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn maki_backing::BackingFile>> {
        let inner = self.inner.open(path, create)?;
        Ok(Arc::new(LyingFile {
            inner,
            path: path.to_string(),
            injector: self.injector.clone(),
        }))
    }
    fn exists(&self, path: &str) -> io::Result<bool> {
        self.inner.exists(path)
    }
    fn remove(&self, path: &str) -> io::Result<()> {
        self.inner.remove(path)
    }
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        self.inner.rename(from, to)
    }
    fn create_dir_all(&self, path: &str) -> io::Result<()> {
        self.inner.create_dir_all(path)
    }
    fn list(&self, dir: &str) -> io::Result<Vec<String>> {
        self.inner.list(dir)
    }
    fn sync_dir(&self, dir: &str) -> io::Result<()> {
        self.inner.sync_dir(dir)?;
        if self.injector.lie(&format!("dir {dir:?}")) {
            return Err(io::Error::other("audit: dir sync persisted but reported failure"));
        }
        Ok(())
    }
    fn try_lock(&self, path: &str) -> io::Result<Box<dyn maki_backing::VolumeLock>> {
        self.inner.try_lock(path)
    }
    fn free_bytes(&self) -> io::Result<Option<u64>> {
        self.inner.free_bytes()
    }
}

/// The durability oracle plus a journal-order *prefix* oracle. The engine
/// journals every request in one sequence (records in ascending unit order)
/// and recovery keeps a prefix of that sequence, so after any crash of a
/// sequential workload the volume must equal "the cycle's starting image
/// with the first S journaled writes applied", for some S at or beyond the
/// last write a FUA/FLUSH made durable. The per-unit oracle alone accepts a
/// later write surviving while an earlier one to another unit is lost (a
/// hole in the replayed journal, the M-007 class).
struct Tracked {
    inner: ReferenceBlockModel,
    prefix: bool,
    baseline: Vec<Vec<u8>>,
    log: Vec<(u64, Vec<u8>)>,
    durable_upto: i64,
}

impl Tracked {
    fn new(unit: usize, units: u64, prefix: bool) -> Self {
        Self {
            inner: ReferenceBlockModel::new(unit, units),
            prefix,
            baseline: (0..units).map(|_| vec![0u8; unit]).collect(),
            log: Vec::new(),
            durable_upto: -1,
        }
    }
    fn write(&mut self, unit: u64, data: &[u8]) {
        self.inner.write(unit, data);
        self.log.push((unit, data.to_vec()));
    }
    fn write_fua(&mut self, unit: u64, data: &[u8]) {
        self.inner.write_fua(unit, data);
        self.log.push((unit, data.to_vec()));
        self.durable_upto = self.log.len() as i64 - 1;
    }
    fn flush(&mut self) {
        self.inner.flush();
        self.durable_upto = self.log.len() as i64 - 1;
    }
    fn read(&self, unit: u64) -> Vec<u8> {
        self.inner.read(unit)
    }
    fn crash_adopt(
        &mut self,
        unit: u64,
        actual: &[u8],
    ) -> Result<(), maki_test_support::model::OracleViolation> {
        self.inner.crash_adopt(unit, actual)
    }
    /// Adopt a post-crash value (an in-flight request's) without logging it.
    fn adopt(&mut self, unit: u64, actual: &[u8]) {
        self.inner.write_fua(unit, actual);
    }
    /// The request in flight at a death: its records follow every
    /// completed one, so they may extend the prefix.
    fn in_flight(&mut self, unit: u64, image: &[u8]) {
        self.log.push((unit, image.to_vec()));
    }
    fn start_cycle(&mut self) {
        let units = self.inner.num_units();
        self.baseline = (0..units).map(|u| self.inner.read(u)).collect();
        self.log.clear();
        self.durable_upto = -1;
    }
    fn check_prefix(&self, observed: &[Vec<u8>]) -> Result<(), String> {
        if !self.prefix {
            return Ok(());
        }
        let mut predicted = self.baseline.clone();
        for (unit, image) in self.log.iter().take((self.durable_upto + 1) as usize) {
            predicted[*unit as usize] = image.clone();
        }
        let mut mismatched: usize = (0..observed.len())
            .filter(|&u| predicted[u] != observed[u])
            .count();
        let mut best = (mismatched, self.durable_upto);
        let mut s = self.durable_upto;
        loop {
            if mismatched == 0 {
                return Ok(());
            }
            s += 1;
            if s >= self.log.len() as i64 {
                break;
            }
            let (unit, image) = &self.log[s as usize];
            let u = *unit as usize;
            let before = predicted[u] != observed[u];
            predicted[u] = image.clone();
            let after = predicted[u] != observed[u];
            mismatched = mismatched + usize::from(after) - usize::from(before);
            if mismatched < best.0 {
                best = (mismatched, s);
            }
        }
        // Report the closest prefix.
        let mut closest = self.baseline.clone();
        for (unit, image) in self.log.iter().take((best.1 + 1) as usize) {
            closest[*unit as usize] = image.clone();
        }
        let units: Vec<u64> = (0..observed.len())
            .filter(|&u| closest[u] != observed[u])
            .map(|u| u as u64)
            .collect();
        let entry_of = |u: u64, value: &Vec<u8>| -> String {
            if *value == self.baseline[u as usize] {
                return "cycle baseline".to_string();
            }
            self.log
                .iter()
                .enumerate()
                .filter(|(_, (lu, img))| *lu == u && img == value)
                .map(|(i, _)| format!("log#{i}"))
                .collect::<Vec<_>>()
                .join("/")
        };
        let detail: Vec<String> = units
            .iter()
            .map(|&u| {
                format!(
                    "unit {u}: observed {} vs prefix {}",
                    entry_of(u, &observed[u as usize]),
                    entry_of(u, &closest[u as usize])
                )
            })
            .collect();
        Err(format!(
            "no journal prefix explains the recovered volume: {} journaled writes this cycle \
             (durable through #{}), closest prefix #{} still differs at {}",
            self.log.len(),
            self.durable_upto,
            best.1,
            detail.join("; ")
        ))
    }
}

/// One member of a concurrent request batch.
enum BatchOp {
    Flush,
    Checkpoint,
    Read {
        offset: u64,
        len: usize,
        want: Vec<u8>,
    },
    Trim {
        offset: u64,
        len: usize,
        fua: bool,
        images: Vec<(u64, Vec<u8>)>,
    },
    Write {
        offset: u64,
        data: Vec<u8>,
        fua: bool,
        zero: bool,
        images: Vec<(u64, Vec<u8>)>,
    },
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
    model: &Tracked,
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
    let raw = backing.clone();
    let backing: Arc<dyn Backing> = Arc::new(Lying {
        inner: raw.clone(),
        injector: injector.clone(),
    });

    let unit = cfg.unit as u64;
    let block = cfg.block as u64;
    let bpu = unit / block;
    let total_blocks = cfg.device_units * bpu;
    let mut model = Tracked::new(cfg.unit as usize, cfg.device_units, cfg.concurrency == 1);
    let zeros = vec![0u8; cfg.unit as usize];
    let mut stamp: u32 = 0;
    // The first attach of a pristine volume establishes the key canary and
    // the first recovery metadata: interrupt it too (a death or a single
    // Linux-model fault), then crash, before the real first attach.
    if (mode.recovery_death_pct > 0 || mode.recovery_fault_pct > 0) && rng.random_bool(0.5) {
        let at = rng.random_range(1..=40u64);
        let death = mode.recovery_death_pct > 0 && rng.random_bool(0.5);
        if death {
            raw.set_lenient_sync_failures(true);
            injector.arm(at);
        } else {
            injector.arm_single(at);
        }
        say(format!(
            "first attach with {} after {at} mutations",
            if death { "death" } else { "one fault" }
        ));
        match try_attach(&cfg, &backing).await {
            Ok(engine) => {
                engine.stop_checkpoint_worker().await;
                drop(engine);
                say("   first attach completed".to_string());
            }
            Err(e) => say(format!("   first attach failed: {e}")),
        }
        injector.revive();
        injector.disarm_single();
        raw.set_lenient_sync_failures(false);
        let kind = pick_crash(&mut rng);
        apply_crash(kind, &raw, &mut rng);
        say(format!("== {kind:?}"));
        stats.bump("first-attach-interrupted");
    }
    let mut engine = match try_attach(&cfg, &backing).await {
        Ok(engine) => engine,
        Err(e) => panic!("ATTACH-FRESH: {e}\n{}", history()),
    };
    if !cfg.worker {
        engine.stop_checkpoint_worker().await;
    }
    let mut workload_mutations: u64 = 80;
    let mut recovery_mutations: u64 = 30;

    for cycle in 0..cycles {
        model.start_cycle();
        let ops = rng.random_range(ops_lo..ops_hi);
        let death_armed = rng.random_range(0..100) < mode.midop_death_pct;
        // What the request in flight at a death may have left behind.
        let mut maybe: BTreeMap<u64, Vec<Vec<u8>>> = BTreeMap::new();
        let transient = mode.transient() && !death_armed;
        if death_armed {
            raw.set_lenient_sync_failures(true);
            let at = rng.random_range(1..=workload_mutations.max(8));
            injector.arm(at);
            say(format!("-- cycle {cycle}: death armed after {at} mutations"));
        } else {
            raw.set_lenient_sync_failures(false);
            injector.enabled.store(transient, Ordering::SeqCst);
            say(format!("-- cycle {cycle}"));
        }
        let mutations_before = injector.mutations();

        for _ in 0..ops {
            stats.bump("ops");
            if cfg.space {
                // Around the admission threshold: reserve + headroom + one or
                // two records' footprint.
                let need = 7 * unit + 2 * cfg.record_len();
                let free = match rng.random_range(0..10) {
                    0 => None,
                    1..=3 => Some(rng.random_range(0..need)),
                    _ => Some(rng.random_range(need..4 * need)),
                };
                raw.set_free_bytes(free);
            }
            let roll = rng.random_range(0..100);
            // Resolve a failed request: every touched unit must show its
            // old or its new image; a new one counts as acknowledged-volatile.
            macro_rules! resolve_failure {
                ($what:expr, $error:expr, $images:expr) => {{
                    let error: &CoreError = $error;
                    let images: &Vec<(u64, Vec<u8>)> = $images;
                    stats.bump(&format!("err-{}", error_class(error)));
                    if !matches!(
                        error,
                        CoreError::Io(_)
                            | CoreError::Durability(_)
                            | CoreError::Format(maki_format::FormatError::Io(_))
                    ) {
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
                            model.in_flight(*u, image);
                        }
                    } else {
                        assert!(
                            transient || cfg.space,
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

            if cfg.concurrency > 1 && rng.random_range(0..100) < 40 {
                // A batch of concurrent requests on disjoint units, maybe
                // with a FLUSH and/or a checkpoint racing them.
                let mut used: std::collections::BTreeSet<u64> = Default::default();
                let mut batch: Vec<BatchOp> = Vec::new();
                let width = rng.random_range(2..=cfg.concurrency);
                for _ in 0..width {
                    let kind = rng.random_range(0..100);
                    if kind < 12 {
                        batch.push(BatchOp::Flush);
                        continue;
                    }
                    if kind < 20 {
                        batch.push(BatchOp::Checkpoint);
                        continue;
                    }
                    // Pick a unit range not touched by another member.
                    let mut picked = None;
                    for _ in 0..8 {
                        let count = rng.random_range(1..=cfg.max_request_units.min(3));
                        let first = rng.random_range(0..=cfg.device_units - count);
                        if (first..first + count).all(|u| !used.contains(&u)) {
                            picked = Some((first, count));
                            break;
                        }
                    }
                    let Some((first, count)) = picked else {
                        continue;
                    };
                    used.extend(first..first + count);
                    // Block range inside the picked units (partial edges ok).
                    let span = count * bpu;
                    let (start, n) = if bpu > 1 && rng.random_bool(0.5) {
                        let n = rng.random_range(1..=span);
                        (first * bpu + rng.random_range(0..=span - n), n)
                    } else {
                        (first * bpu, span)
                    };
                    let (offset, len) = (start * block, (n * block) as usize);
                    let fua = rng.random_bool(0.25);
                    if kind < 40 {
                        let mut want = Vec::with_capacity(len);
                        let mut at = offset;
                        while at < offset + len as u64 {
                            let u = at / unit;
                            let from = (at - u * unit) as usize;
                            let to =
                                ((offset + len as u64).min((u + 1) * unit) - u * unit) as usize;
                            want.extend_from_slice(&model.read(u)[from..to]);
                            at = (u + 1) * unit;
                        }
                        batch.push(BatchOp::Read { offset, len, want });
                    } else if kind < 55 && cfg.discard {
                        let first_whole = offset.div_ceil(unit);
                        let end = (offset + len as u64) / unit;
                        let images = (first_whole..end).map(|u| (u, zeros.clone())).collect();
                        batch.push(BatchOp::Trim {
                            offset,
                            len,
                            fua,
                            images,
                        });
                    } else {
                        let zero = rng.random_bool(0.1);
                        stamp += 1;
                        let data = if zero {
                            vec![0u8; len]
                        } else {
                            pattern(stamp, offset, len)
                        };
                        let images = images_after_write(&cfg, &model, offset, &data);
                        batch.push(BatchOp::Write {
                            offset,
                            data,
                            fua,
                            zero,
                            images,
                        });
                    }
                }
                let mut handles = Vec::new();
                for op in &batch {
                    let engine = engine.clone();
                    handles.push(match op {
                        BatchOp::Flush => tokio::spawn(async move {
                            engine.flush().await.map(|_| None)
                        }),
                        BatchOp::Checkpoint => tokio::spawn(async move {
                            engine.checkpoint().await.map(|_| None)
                        }),
                        BatchOp::Read { offset, len, .. } => {
                            let (offset, len) = (*offset, *len);
                            tokio::spawn(async move { engine.read(offset, len).await.map(Some) })
                        }
                        BatchOp::Trim {
                            offset, len, fua, ..
                        } => {
                            let (offset, len, fua) = (*offset, *len, *fua);
                            tokio::spawn(async move {
                                engine.trim(offset, len, fua).await.map(|_| None)
                            })
                        }
                        BatchOp::Write {
                            offset,
                            data,
                            fua,
                            zero,
                            ..
                        } => {
                            let (offset, data, fua, zero) = (*offset, data.clone(), *fua, *zero);
                            tokio::spawn(async move {
                                if zero {
                                    engine.write_zeroes(offset, data.len(), fua).await
                                } else {
                                    engine.write(offset, &data, fua).await
                                }
                                .map(|_| None)
                            })
                        }
                    });
                }
                let mut results = Vec::new();
                for handle in handles {
                    results.push(handle.await.expect("batch member panicked"));
                }
                // A FLUSH in the batch covers only what was acknowledged
                // before the batch began.
                let flushed = batch
                    .iter()
                    .zip(&results)
                    .any(|(op, r)| matches!(op, BatchOp::Flush) && r.is_ok());
                if flushed {
                    model.flush();
                }
                let mut summary = Vec::new();
                let mut failed: Vec<(String, CoreError, Vec<(u64, Vec<u8>)>)> = Vec::new();
                for (op, result) in batch.into_iter().zip(results) {
                    let verdict = match &result {
                        Ok(_) => "ok".to_string(),
                        Err(e) => format!("ERR {e}"),
                    };
                    match op {
                        BatchOp::Flush => {
                            summary.push(format!("flush -> {verdict}"));
                            if let Err(e) = result {
                                failed.push(("flush".into(), e, Vec::new()));
                            }
                        }
                        BatchOp::Checkpoint => {
                            summary.push(format!("checkpoint -> {verdict}"));
                            if let Err(e) = result {
                                failed.push(("checkpoint".into(), e, Vec::new()));
                            }
                        }
                        BatchOp::Read { offset, len, want } => {
                            summary.push(format!("read off {offset} len {len} -> {verdict}"));
                            match result {
                                Ok(Some(actual)) => assert!(
                                    actual == want,
                                    "LIVE-MISMATCH: batch read off {offset} len {len} differs \
                                     from the acknowledged image\n{}",
                                    history()
                                ),
                                Ok(None) => unreachable!(),
                                Err(e) => assert!(
                                    injector.is_dead(),
                                    "LIVE-READ-FAILED: batch read off {offset} len {len}: {e}\n{}",
                                    history()
                                ),
                            }
                        }
                        BatchOp::Trim {
                            offset,
                            len,
                            fua,
                            images,
                        } => {
                            summary.push(format!(
                                "trim off {offset} len {len} fua={fua} -> {verdict}"
                            ));
                            match result {
                                Ok(_) => {
                                    for (u, image) in &images {
                                        if fua {
                                            model.write_fua(*u, image);
                                        } else {
                                            model.write(*u, image);
                                        }
                                    }
                                }
                                Err(e) => failed.push(("trim".into(), e, images)),
                            }
                        }
                        BatchOp::Write {
                            offset,
                            data,
                            fua,
                            zero,
                            images,
                        } => {
                            summary.push(format!(
                                "{} off {offset} len {} (units {}..={}) fua={fua} -> {verdict}",
                                if zero { "zero" } else { "write" },
                                data.len(),
                                images[0].0,
                                images[images.len() - 1].0,
                            ));
                            match result {
                                Ok(_) => {
                                    for (u, image) in &images {
                                        if fua {
                                            model.write_fua(*u, image);
                                        } else {
                                            model.write(*u, image);
                                        }
                                    }
                                }
                                Err(e) => failed.push(("write".into(), e, images)),
                            }
                        }
                    }
                }
                say(format!("batch [{}]", summary.join(" | ")));
                stats.bump("batches");
                for (what, error, images) in failed {
                    resolve_failure!(what, &error, &images);
                }
                if injector.is_dead() {
                    break;
                }
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
        // A running worker pass holds the volume (and its lock); the
        // process "dies" once it has finished (the backing may be dead).
        engine.stop_checkpoint_worker().await;
        drop(engine);
        injector.revive();
        raw.set_lenient_sync_failures(false);

        let mut kind = pick_crash(&mut rng);
        apply_crash(kind, &raw, &mut rng);
        say(format!("== {kind:?}"));
        stats.bump("crashes");
        // A restart loses nothing; that only holds while no power loss
        // happens before the state is inspected.
        let mut strict = kind == Crash::Restart && mode.strict_restart;

        let mut attempts = 0;
        while attempts < 3 && rng.random_range(0..100) < mode.recovery_death_pct {
            attempts += 1;
            raw.set_lenient_sync_failures(true);
            let at = rng.random_range(1..=recovery_mutations.max(6) + 4);
            injector.arm(at);
            say(format!("recovery with death armed after {at} mutations"));
            let result = try_attach(&cfg, &backing).await;
            let died = injector.is_dead();
            match result {
                Ok(engine) => {
                    say(format!("   recovery completed (died={died})"));
                    if died {
                        // Some mutation failed and attach still succeeded:
                        // which step tolerates a failure?
                        let death = log
                            .lock()
                            .iter()
                            .rev()
                            .find(|l| l.contains("DEATH"))
                            .cloned()
                            .unwrap_or_default();
                        stats.bump("recovery-ok-despite-death");
                        stats.note(format!(
                            "cfg {} mode {} seed {seed}: attach succeeded after death: {}",
                            cfg.name,
                            mode.name,
                            death.trim()
                        ));
                    }
                    engine.stop_checkpoint_worker().await;
                    drop(engine);
                    stats.bump("recovery-then-crash");
                }
                Err(e) => {
                    say(format!("   recovery failed: {e}"));
                    if !died && known_torn_header(&e.to_string(), &log.lock()) {
                        stats.bump("known-torn-header");
                        return;
                    }
                    assert!(
                        died,
                        "ATTACH-REFUSED: recovery failed before the injected death: {e}\n{}",
                        history()
                    );
                    stats.bump("recovery-deaths");
                }
            }
            injector.revive();
            raw.set_lenient_sync_failures(false);
            kind = pick_crash(&mut rng);
            apply_crash(kind, &raw, &mut rng);
            say(format!("== {kind:?}"));
            strict &= kind == Crash::Restart;
        }

        // Recovery under transient faults (Linux failed-fsync model).
        let mut attempts = 0;
        while mode.any_faults()
            && attempts < 3
            && rng.random_range(0..100) < mode.recovery_fault_pct
        {
            attempts += 1;
            raw.set_lenient_sync_failures(false);
            // One transient fault at a uniformly chosen mutation of the
            // recovery (it may land after recovery, in attach, or never).
            let at = rng.random_range(1..=recovery_mutations.max(6) + 2);
            say(format!("recovery with one transient fault after {at} mutations"));
            injector.arm_single(at);
            let result = try_attach(&cfg, &backing).await;
            let fired = injector.single.load(Ordering::SeqCst) < 0;
            injector.disarm_single();
            match result {
                Ok(engine) => {
                    say(format!("   faulty recovery completed (fault fired={fired})"));
                    if fired {
                        stats.bump("faulty-recovery-ok-after-fault");
                        let fault = log
                            .lock()
                            .iter()
                            .rev()
                            .find(|l| l.contains("SINGLE"))
                            .cloned()
                            .unwrap_or_default();
                        stats.note(format!(
                            "cfg {} mode {} seed {seed}: attach succeeded after a fault: {}",
                            cfg.name,
                            mode.name,
                            fault.trim()
                        ));
                    }
                    stats.bump("faulty-recovery-ok");
                    engine.stop_checkpoint_worker().await;
                    // Sometimes write a little through the faulty-recovered
                    // engine before crashing: it must be as good as any.
                    drop(engine);
                }
                Err(e) => {
                    say(format!("   faulty recovery failed: {e}"));
                    stats.bump("faulty-recovery-failed");
                }
            }
            kind = pick_crash(&mut rng);
            apply_crash(kind, &raw, &mut rng);
            say(format!("== {kind:?}"));
            strict &= kind == Crash::Restart;
        }

        if rng.random_range(0..100) < mode.double_crash_pct {
            match try_attach(&cfg, &backing).await {
                Ok(engine) => {
                    engine.stop_checkpoint_worker().await;
                    drop(engine);
                }
                Err(e) if known_torn_header(&e.to_string(), &log.lock()) => {
                    stats.bump("known-torn-header");
                    return;
                }
                Err(e) => panic!("ATTACH-REFUSED: {e}\n{}", history()),
            }
            kind = pick_crash(&mut rng);
            apply_crash(kind, &raw, &mut rng);
            say(format!("recovered, then == {kind:?} before any write"));
            strict &= kind == Crash::Restart;
            stats.bump("double-crashes");
        }

        if rng.random_range(0..100) < mode.damage_pct {
            // Media damage to one or two non-journal files after the crash
            // (journal damage can legitimately revert a FLUSHed write, S-04).
            // Recovery may refuse; otherwise every unit must read as an
            // allowed value or fail with EIO, never foreign data or zeros
            // for a written unit. The seed ends here.
            let candidates = damage_candidates(&raw);
            for _ in 0..rng.random_range(1..=2usize) {
                let path = candidates[rng.random_range(0..candidates.len())].clone();
                say(format!("DAMAGE {}", damage_file(&raw, &path, &mut rng)));
            }
            stats.bump("damaged");
            let report = match run_deep_check(&cfg, &raw, &injector) {
                Ok(report) => report,
                Err(text) => panic!("{text}\n{}", history()),
            };
            if let Some(report) = &report {
                say(format!("deep check: errors {:?} warnings {:?}", report.errors, report.warnings));
            }
            let check_clean = report.as_ref().map(|r| r.errors.is_empty());
            let engine = match try_attach(&cfg, &backing).await {
                Ok(engine) => engine,
                Err(e) => {
                    say(format!("damaged volume refused: {e}"));
                    stats.bump("damage-refused");
                    if check_clean == Some(true) {
                        panic!(
                            "CHECK-FALSE-NEGATIVE: deep check reported no error but attach was \
                             refused: {e}\n{}",
                            history()
                        );
                    }
                    return;
                }
            };
            engine.stop_checkpoint_worker().await;
            let s = engine.stats().await;
            assert!(
                s.checkpoint_sequence <= s.durable_sequence,
                "CHECKPOINT-AHEAD (damaged): checkpoint {} > durable {}\n{}",
                s.checkpoint_sequence,
                s.durable_sequence,
                history()
            );
            let mut eio_units = 0u64;
            for u in 0..cfg.device_units {
                match engine.read(u * unit, unit as usize).await {
                    Ok(actual) => {
                        let in_flight = maybe.get(&u).is_some_and(|set| set.contains(&actual));
                        if let Err(violation) = model.crash_adopt(u, &actual) {
                            assert!(
                                in_flight,
                                "DAMAGE-ORACLE: {violation} (wanted one of the allowed \
                                 values or EIO)\n{}",
                                history()
                            );
                        }
                    }
                    Err(e @ (CoreError::Corrupt(_) | CoreError::Io(_))) => {
                        stats.bump("damage-eio-units");
                        if check_clean == Some(true) {
                            panic!(
                                "CHECK-FALSE-NEGATIVE: deep check reported no error but unit {u} \
                                 reads EIO after attach: {e}\n{}",
                                history()
                            );
                        }
                        eio_units += 1;
                    }
                    Err(e) => panic!(
                        "DAMAGE-ERROR-CLASS: unit {u}: unexpected error class {e}\n{}",
                        history()
                    ),
                }
            }
            if check_clean == Some(false) && eio_units == 0 {
                stats.bump("check-error-but-runtime-clean");
                stats.note(format!(
                    "cfg {} mode {} seed {seed}: deep check errors {:?} on a volume that attached \
                     with every unit readable",
                    cfg.name,
                    mode.name,
                    report.as_ref().map(|r| r.errors.clone()).unwrap_or_default()
                ));
            }
            stats.bump("damage-attached");
            return;
        }

        if rng.random_range(0..100) < 35 {
            match run_deep_check(&cfg, &raw, &injector) {
                Err(text) => panic!("{text}\n{}", history()),
                Ok(None) => stats.bump("check-inconclusive"),
                Ok(Some(report)) => {
                    stats.bump("checks");
                    if report.errors.len() == 1
                        && known_torn_header(&report.errors[0], &log.lock())
                    {
                        stats.bump("known-torn-header");
                        return;
                    }
                    if !report.errors.is_empty() {
                        panic!(
                            "CHECK-FALSE-POSITIVE: deep check reports errors {:?} on a \
                             crash-consistent volume (no damage injected)\n{}",
                            report.errors,
                            history()
                        );
                    }
                }
            }
        }

        let before = injector.mutations();
        engine = match try_attach(&cfg, &backing).await {
            Ok(engine) => engine,
            Err(e) if known_torn_header(&e.to_string(), &log.lock()) => {
                stats.bump("known-torn-header");
                return;
            }
            Err(e) => panic!("ATTACH-REFUSED: {e}\n{}", history()),
        };
        if !cfg.worker {
            engine.stop_checkpoint_worker().await;
        }
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
        let mut observed: Vec<Vec<u8>> = Vec::with_capacity(cfg.device_units as usize);
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
            observed.push(actual.clone());
            if let Err(violation) = model.crash_adopt(u, &actual) {
                assert!(in_flight, "ORACLE: {violation}\n{}", history());
                model.adopt(u, &actual);
            }
        }
        if let Err(text) = model.check_prefix(&observed) {
            panic!("PREFIX-VIOLATION: {text}\n{}", history());
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
    let traces = trace_counts();
    traces.lock().clear();
    let started = Instant::now();
    let mut failures = Vec::new();
    let mut seeds_run = 0;
    for seed in seeds.clone() {
        if started.elapsed() > budget {
            break;
        }
        seeds_run += 1;
        let run = Run {
            cfg: cfg_for(cfg_name, seed),
            mode: mode(mode_name),
            seed,
            cycles: env_or("AUDIT_CYCLES", cycles as u64) as usize,
            ops_lo: env_or("AUDIT_OPS_LO", 6) as usize,
            ops_hi: env_or("AUDIT_OPS_HI", 40) as usize,
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
        "AUDIT-SWEEP cfg={cfg_name} mode={mode_name} seeds={}..{} run={seeds_run} cycles={} ops={}..{} \
         failures={} elapsed={:.0}s | {}",
        seeds.start,
        seeds.start + seeds_run,
        env_or("AUDIT_CYCLES", cycles as u64),
        env_or("AUDIT_OPS_LO", 6),
        env_or("AUDIT_OPS_HI", 40),
        failures.len(),
        started.elapsed().as_secs_f64(),
        stats.render()
    );
    for note in stats.notes.lock().iter() {
        println!("AUDIT-NOTE {note}");
    }
    for (event, count) in traces.lock().iter() {
        println!("AUDIT-TRACE cfg={cfg_name} mode={mode_name} {count:>6} {event}");
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

fn env_or(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
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

// ---- second auditor: new geometries, worker, concurrency, faulty recovery

const NEWGEO: [&str; 4] = ["blk4k-v3", "u16k", "u16k-v3", "pend1-v3"];
const WORKER: [&str; 2] = ["seg3-worker-v3", "rmw-worker"];
const CONC: [&str; 5] = [
    "conc-v3",
    "conc-v2",
    "conc-rmw-v3",
    "conc-shard1-v3",
    "conc-noworker-v3",
];

fn all_pairs<'a>(cfgs: &[&'a str], modes: &[&'a str]) -> Vec<(&'a str, &'a str)> {
    modes
        .iter()
        .flat_map(|m| cfgs.iter().map(move |c| (*c, *m)))
        .collect()
}

fn pairs_from_env(default: Vec<(&'static str, &'static str)>) -> Vec<(String, String)> {
    match std::env::var("AUDIT_PAIRS") {
        // "cfg:mode,cfg:mode"
        Ok(spec) => spec
            .split(',')
            .filter(|p| !p.is_empty())
            .map(|p| {
                let (c, m) = p.split_once(':').expect("cfg:mode");
                (c.to_string(), m.to_string())
            })
            .collect(),
        Err(_) => default
            .into_iter()
            .map(|(c, m)| (c.to_string(), m.to_string()))
            .collect(),
    }
}

async fn sweep_owned(pairs: Vec<(String, String)>, seeds: std::ops::Range<u64>, cycles: usize) {
    let refs: Vec<(&str, &str)> = pairs.iter().map(|(c, m)| (c.as_str(), m.as_str())).collect();
    sweep_all(&refs, seeds, cycles).await;
}

#[tokio::test]
async fn audit2_newgeo_crash_death() {
    sweep_owned(
        pairs_from_env(all_pairs(&NEWGEO, &["crash", "death"])),
        seeds(),
        4,
    )
    .await;
}

#[tokio::test]
async fn audit2_newgeo_faults() {
    sweep_owned(
        pairs_from_env(all_pairs(&NEWGEO, &["chaos", "chaos-death"])),
        seeds(),
        4,
    )
    .await;
}

#[tokio::test]
async fn audit2_rfault() {
    let mut cfgs: Vec<&str> = V2.to_vec();
    cfgs.extend(V3);
    cfgs.extend(NEWGEO);
    sweep_owned(pairs_from_env(all_pairs(&cfgs, &["rfault"])), seeds(), 4).await;
}

#[tokio::test]
async fn audit2_chaos_rfault() {
    let mut cfgs: Vec<&str> = V3.to_vec();
    cfgs.extend(["blk4k-v3", "u16k", "pend1-v3"]);
    sweep_owned(
        pairs_from_env(all_pairs(&cfgs, &["chaos-rfault"])),
        seeds(),
        4,
    )
    .await;
}

#[tokio::test]
async fn audit2_lying() {
    let mut cfgs: Vec<&str> = V2.to_vec();
    cfgs.extend(V3);
    cfgs.extend(NEWGEO);
    sweep_owned(
        pairs_from_env(all_pairs(&cfgs, &["lying", "chaos-lying", "rfault-lying"])),
        seeds(),
        4,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit2_conc_lying() {
    sweep_owned(
        pairs_from_env(all_pairs(&CONC, &["lying", "chaos-lying"])),
        seeds(),
        4,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit2_random_geometry() {
    sweep_owned(
        pairs_from_env(all_pairs(
            &["random-any"],
            &["crash", "death", "sync", "chaos", "chaos-death", "lying", "rfault", "damage"],
        )),
        seeds(),
        4,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit2_space() {
    sweep_owned(
        pairs_from_env(all_pairs(
            &["space-v3", "space-rmw", "space-conc-v3"],
            &["crash", "death", "chaos", "lying"],
        )),
        seeds(),
        4,
    )
    .await;
}

#[tokio::test]
async fn audit2_damage() {
    let mut cfgs: Vec<&str> = V2.to_vec();
    cfgs.extend(V3);
    cfgs.extend(NEWGEO);
    cfgs.extend(["seg3-cache-v3", "rmw-cache", "plain", "plain-v3"]);
    sweep_owned(
        pairs_from_env(all_pairs(&cfgs, &["damage", "death-damage"])),
        seeds(),
        4,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit2_worker() {
    sweep_owned(
        pairs_from_env(all_pairs(&WORKER, &["crash", "death", "chaos", "chaos-death"])),
        seeds(),
        4,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit2_conc_clean() {
    sweep_owned(
        pairs_from_env(all_pairs(&CONC, &["crash", "death"])),
        seeds(),
        4,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit2_conc_faults() {
    sweep_owned(
        pairs_from_env(all_pairs(&CONC, &["sync", "chaos", "chaos-death"])),
        seeds(),
        4,
    )
    .await;
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
        cfg: cfg_for(&cfg_name, seed),
        mode: mode(&mode_name),
        seed,
        cycles,
        ops_lo: env_or("AUDIT_OPS_LO", 6) as usize,
        ops_hi: env_or("AUDIT_OPS_HI", 40) as usize,
        verbose: true,
    };
    run_seed(run, Arc::new(Stats::default())).await;
}

/// The prefix oracle is not vacuous: a later write surviving an earlier lost
/// one (a hole in the replayed journal) is refused; every prefix is accepted.
#[test]
fn audit_prefix_oracle_refuses_holes() {
    let (a, b, z) = (vec![1u8; 4], vec![2u8; 4], vec![0u8; 4]);
    let mut model = Tracked::new(4, 2, true);
    model.start_cycle();
    model.write(0, &a);
    model.write(1, &b);
    assert!(model.check_prefix(&[z.clone(), z.clone()]).is_ok());
    assert!(model.check_prefix(&[a.clone(), z.clone()]).is_ok());
    assert!(model.check_prefix(&[a.clone(), b.clone()]).is_ok());
    assert!(model.check_prefix(&[z.clone(), b.clone()]).is_err());
    model.flush();
    assert!(model.check_prefix(&[a.clone(), z.clone()]).is_err());
    assert!(model.check_prefix(&[a.clone(), b.clone()]).is_ok());
}
