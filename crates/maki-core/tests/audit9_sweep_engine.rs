//! Audit round 9 copy of round 8's `audit8_sweep_engine.rs` (itself round 2's
//! sweep), with the `r9-ab*` geometries and the `ab-*` fault modes added.
//!
//! Audit round 2 sweep (empirical durability hunt). Not part of the
//! maintained suite: an auditor's randomized harness over the engine,
//! adapted from round 1's `audit_sweep_engine.rs` to the stricter crash
//! model of #165 and extended to what round 1 did not cover:
//!
//! - every "process" (an attach and the workload on its engine) runs in its
//!   own tokio runtime; a process death makes every later backing mutation
//!   fail (a sync that "fails" this way never ran) and then shuts the runtime
//!   down, so detached storage/publish/checkpoint tasks die with it exactly
//!   where they are, and a plain restart never races a leftover task;
//! - request futures (writes, WRITE_ZEROES, TRIMs, FLUSH, checkpoint, reads)
//!   are dropped at a random await point (after N pending polls or a short
//!   timeout). A cancelled request's detached storage may still land: it is
//!   settled (every admission permit returned) and then resolved per unit
//!   (old or new image, never anything else), or it is left in flight into
//!   the next process death;
//! - interrupted-recovery chains: up to N recoveries in a row, each killed
//!   by a death at a random mutation or one Linux-model transient fault,
//!   each followed by a restart, a power loss or a worst-case power loss;
//! - every *successful* attach pins what it serves: all units are read and
//!   adopted as durable, so any later crash must show exactly that state
//!   (SPEC §27: nothing recovery accepts may stay unsynced once the writer
//!   resumes). Round 1 only checked the final attach against the allowed set;
//! - tight journal/overlay bounds with up to six concurrent writers, so the
//!   #168 reclaim gate is taken constantly, mixed with cancellations, faults
//!   and crashes; a write refused with ENOSPC without faults is a failure.
//!
//! The oracle is `ReferenceBlockModel` at crypto-unit granularity, plus a
//! journal-prefix oracle for sequential workloads.

#![allow(clippy::await_holding_lock)]
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
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
// Processes and cancellation

/// One process: a runtime of its own. Everything the engine spawns lives in
/// it, so killing it stops every detached task.
pub struct Proc {
    rt: Option<tokio::runtime::Runtime>,
}

impl Proc {
    pub fn new() -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("process runtime");
        Self { rt: Some(rt) }
    }

    fn handle(&self) -> tokio::runtime::Handle {
        self.rt.as_ref().expect("live process").handle().clone()
    }

    /// Run `fut` inside the process; a panic in it is re-raised here.
    pub async fn run<T: Send + 'static>(&self, fut: impl Future<Output = T> + Send + 'static) -> T {
        match self.handle().spawn(fut).await {
            Ok(v) => v,
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(e) => panic!("PROCESS-TASK: {e}"),
        }
    }

    /// The process dies. The caller has already made every backing
    /// mutation fail; running storage closures finish (failing), every task
    /// stops at its next await.
    pub fn kill(mut self) {
        let rt = self.rt.take().expect("live process");
        std::thread::spawn(move || rt.shutdown_timeout(Duration::from_secs(60)))
            .join()
            .expect("runtime shutdown");
    }
}

impl Default for Proc {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

/// Where a cancelled request future is dropped.
#[derive(Clone, Copy, Debug)]
pub enum Cut {
    /// After it returned `Pending` this many times (an await point).
    Polls(u32),
    /// After this many microseconds of wall time.
    Micros(u64),
}

struct CancelAfterPolls<F> {
    inner: Option<Pin<Box<F>>>,
    left: u32,
}

impl<F: Future> Future for CancelAfterPolls<F> {
    type Output = Option<F::Output>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        let fut = this.inner.as_mut().expect("polled after completion");
        match fut.as_mut().poll(cx) {
            Poll::Ready(v) => {
                this.inner = None;
                Poll::Ready(Some(v))
            }
            Poll::Pending => {
                this.left = this.left.saturating_sub(1);
                if this.left == 0 {
                    // Drop the request future right here, at its await point.
                    this.inner = None;
                    Poll::Ready(None)
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

/// `None` = the request future was dropped before it completed.
pub async fn cancellable<F: Future>(fut: F, cut: Option<Cut>) -> Option<F::Output> {
    match cut {
        None => Some(fut.await),
        Some(Cut::Polls(n)) => {
            CancelAfterPolls {
                inner: Some(Box::pin(fut)),
                left: n.max(1),
            }
            .await
        }
        Some(Cut::Micros(us)) => tokio::time::timeout(Duration::from_micros(us), fut)
            .await
            .ok(),
    }
}

fn pick_cut(rng: &mut StdRng) -> Cut {
    if rng.random_bool(0.75) {
        Cut::Polls(rng.random_range(1..=14))
    } else {
        Cut::Micros(rng.random_range(0..3000))
    }
}

/// Wait until no request holds an admission permit (a cancelled request's
/// detached storage has finished). `Err` = it never did.
async fn settle(proc: &Proc, engine: &Engine) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let e = engine.clone();
        let s = proc.run(async move { e.stats().await }).await;
        if s.admission_slots == 0 && s.plaintext_bytes_in_flight == 0 && s.active_requests == 0 {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(format!(
                "SETTLE-HANG: 30 s after a cancellation admission_slots={} plaintext_bytes={} \
                 active_requests={} state={:?}",
                s.admission_slots, s.plaintext_bytes_in_flight, s.active_requests, s.state
            ));
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

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
    /// Round 8: slot alignment (earlier rounds: always 512) and slack in
    /// `max_ciphertext_size` above the provider's `unit + 8` (always 0).
    pub align: u32,
    pub slack: u32,
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
                self.align,
                self.unit + 8 + self.slack,
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
                emergency_reserve_bytes: if self.space { 4 * self.unit as u64 } else { 0 },
                low_space_checkpoint_bytes: if self.space { 3 * self.unit as u64 } else { 0 },
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
        align: 512,
        slack: 0,
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
        // ---- round 2: the #168 reclaim gate. Tiny journal/overlay bounds,
        // up to six concurrent writers: nearly every batch member is over a
        // bound and reclaims or queues. A lone request of up to four units
        // always fits after a full reclaim.
        "gate-v3" => Cfg {
            name: "gate-v3",
            device_units: 64,
            segment_size: 48 + 2 * rec(512),
            journal_max_bytes: 4 * (48 + 2 * rec(512)),
            max_pending_bytes: 2 * rec(512),
            max_overlay_entries: 6,
            discard: true,
            worker: true,
            concurrency: 6,
            ..base
        },
        "gate-noworker-v3" => Cfg {
            name: "gate-noworker-v3",
            device_units: 64,
            segment_size: 48 + 2 * rec(512),
            journal_max_bytes: 4 * (48 + 2 * rec(512)),
            max_pending_bytes: 2 * rec(512),
            max_overlay_entries: 6,
            discard: true,
            concurrency: 6,
            ..base
        },
        "gate-ovlbytes-v3" => Cfg {
            name: "gate-ovlbytes-v3",
            device_units: 64,
            segment_size: 48 + 4 * rec(512),
            journal_max_bytes: BIG,
            max_overlay_bytes: 2 * 5 * (512 + 8),
            discard: true,
            worker: true,
            concurrency: 6,
            ..base
        },
        "gate-journal-v2" => Cfg {
            name: "gate-journal-v2",
            device_units: 64,
            segment_size: 48 + rec(512),
            journal_max_bytes: 6 * (48 + rec(512)),
            max_pending_bytes: rec(512),
            concurrency: 6,
            worker: true,
            ..base
        },
        "gate-rmw-v3" => Cfg {
            name: "gate-rmw-v3",
            unit: 4096,
            device_units: 40,
            units_per_shard: 3,
            segment_size: 48 + 2 * rec(4096),
            journal_max_bytes: 4 * (48 + 2 * rec(4096)),
            max_pending_bytes: 2 * rec(4096),
            max_overlay_entries: 5,
            max_overlay_bytes: 10 * (4096 + 8),
            max_request_units: 4,
            discard: true,
            tear: 512,
            worker: true,
            concurrency: 5,
            ..base
        },
        "gate-shard1-v3" => Cfg {
            name: "gate-shard1-v3",
            device_units: 24,
            units_per_shard: 1,
            segment_size: 48 + 2 * rec(512),
            journal_max_bytes: 4 * (48 + 2 * rec(512)),
            max_pending_bytes: 2 * rec(512),
            max_overlay_entries: 6,
            discard: true,
            cache: Some(false),
            worker: true,
            concurrency: 5,
            ..base
        },
        "gate-space-v3" => Cfg {
            name: "gate-space-v3",
            device_units: 64,
            segment_size: 48 + 2 * rec(512),
            journal_max_bytes: 4 * (48 + 2 * rec(512)),
            max_pending_bytes: 2 * rec(512),
            max_overlay_entries: 6,
            discard: true,
            worker: true,
            concurrency: 5,
            space: true,
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
    // Round 8: `r8-any` / `r8-gate` start from the round-2 random geometry
    // and push what it keeps fixed or narrow: slot alignment, ciphertext
    // slack, tear granularity (down to one byte, odd sizes, none below a
    // megabyte), one-unit and several-hundred-unit devices.
    // Round 9: `r9-ab` / `r9-ab-gate` take the round-8 geometry and force a
    // tearing unit far below every A/B record (checkpoint state 32 bytes,
    // durable proof 64, maps and catalog about 40), so a cut store leaves a
    // genuine mixture in the side and the next store meets "exists but does
    // not decode" (the emptying of #386) constantly; and a journal segment
    // of at most three records so that every workload rolls.
    if name.starts_with("r9-") {
        let gate = name == "r9-ab-gate";
        let mut c = cfg_for(if gate { "r8-gate" } else { "r8-any" }, seed ^ 0x0909_0909);
        let mut r = StdRng::seed_from_u64(seed ^ 0x9A9A_9A9A);
        c.name = if gate { "r9-ab-gate" } else { "r9-ab" };
        c.tear = [1usize, 3, 4, 8, 13, 16, 24][r.random_range(0..7)];
        return c;
    }
    if name.starts_with("r8-") {
        let gate = name == "r8-gate";
        let mut c = cfg_for(if gate { "random-gate" } else { "random-any" }, seed ^ 0x5EED_0008);
        let mut r = StdRng::seed_from_u64(seed ^ 0xA8A8_A8A8);
        c.name = if gate { "r8-gate" } else { "r8-any" };
        c.align = [512u32, 512, 4096, 4096, 65536][r.random_range(0..5)];
        c.slack = [0u32, 0, 1, 24, 504][r.random_range(0..5)];
        c.tear = [1usize, 7, 64, 128, 512, 4096, 1 << 20][r.random_range(0..7)];
        if c.concurrency == 1 && r.random_bool(0.2) {
            c.device_units = r.random_range(1..=3u64);
            c.max_request_units = c.max_request_units.min(c.device_units);
        } else if r.random_bool(0.25) {
            c.device_units *= r.random_range(4..=8u64);
        }
        if r.random_bool(0.3) {
            c.units_per_shard = c.device_units + r.random_range(0..=5u64);
        }
        // The in-memory backing holds a shard file at its full sparse size.
        let slot = (64 + c.unit as u64 + 8 + c.slack as u64).div_ceil(c.align as u64) * c.align as u64;
        c.units_per_shard = c.units_per_shard.clamp(1, ((4u64 << 20) / slot).max(1));
        // `max_pending_bytes` must hold one maximum record (with the slack).
        if c.max_pending_bytes != BIG {
            c.max_pending_bytes += 4 * c.slack as u64;
        }
        return c;
    }
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
    let gate = name == "random-gate";
    // A lone request (at most four units in a batch member or a sequential
    // write, plus one for misalignment) must fit after a full reclaim.
    // Trims journal chunks of up to max_request_units tombstones.
    let lone = max_request_units.max(4) + 1;

    let concurrency = if gate {
        r.random_range(3..=6usize)
    } else if r.random_bool(0.35) {
        r.random_range(2..=4usize)
    } else {
        1
    };
    let worker = r.random_bool(if gate { 0.6 } else { 0.4 });
    // An unaligned request of max_request_bytes touches one extra unit.
    let request_records = (max_request_units + 1) * concurrency as u64;
    let journal_max_bytes = if !gate && r.random_bool(0.3) {
        BIG
    } else if gate {
        2 * segment_size + lone * rec + (lone + 2) * 48 + r.random_range(0..segment_size)
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
    } else if gate {
        lone + r.random_range(0..3u64)
    } else {
        request_records + r.random_range(0..8u64)
    };
    let max_overlay_bytes = if r.random_bool(0.6) {
        0
    } else if gate {
        2 * lone * (unit as u64 + 8) + r.random_range(0..3u64) * (unit as u64 + 8)
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
            "random-gate" => "random-gate",
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
        align: 512,
        slack: 0,
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
    /// Harness self-test: permille of file syncs that report success
    /// without syncing (a broken backing). Every seed should then fail.
    pub skip_sync: u32,
    /// Comma-separated path substrings: when set, transient faults apply
    /// only to operations on matching paths (directories by name).
    pub fault_paths: &'static str,
    /// Damage both copies of one A/B pair (canary, superblock, checkpoint
    /// state, allocation/discard map, catalog) instead of random files.
    pub damage_pairs: bool,
    /// Round 9: damage aimed at one shard instead of random files: its data
    /// file is truncated and the newest copy of its allocation map is
    /// damaged (what the S-01 residual rules are about), and sometimes the
    /// newest catalog copy too.
    pub damage_shard: bool,
    /// Percent of requests (sequential and batch members) whose future is
    /// dropped at a random await point.
    pub cancel_pct: u32,
    /// Above 0: replace round 1's recovery loops by one chain of up to this
    /// many interrupted recoveries (death or one Linux-model fault, chosen
    /// per step), each followed by a restart or power loss.
    pub chain: u32,
    /// Above 0: percent of crashes that are plain restarts (the rest power
    /// losses, a quarter of them worst case).
    pub restart_pct: u32,
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

/// Path substrings of every A/B record of a volume.
const AB_PATHS: &str = ".alloc.,.discard.,catalog,state.,durable-proof,superblock,canary";

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
        // ---- round 2 modes ----
        "cancel" => Mode {
            name: "cancel",
            strict_restart: true,
            cancel_pct: 30,
            double_crash_pct: 15,
            ..Mode::default()
        },
        "cancel-death" => Mode {
            name: "cancel-death",
            strict_restart: true,
            cancel_pct: 25,
            midop_death_pct: 50,
            recovery_death_pct: 40,
            double_crash_pct: 15,
            ..Mode::default()
        },
        "cancel-sync" => Mode {
            name: "cancel-sync",
            strict_restart: true,
            cancel_pct: 25,
            sync_data: 100,
            sync_dir: 100,
            heal_pct: 4,
            double_crash_pct: 10,
            ..Mode::default()
        },
        "cancel-chaos" => Mode {
            name: "cancel-chaos",
            strict_restart: true,
            cancel_pct: 25,
            sync_data: 60,
            sync_dir: 60,
            write: 30,
            partial: 30,
            set_len: 30,
            remove: 60,
            rename: 30,
            create: 30,
            heal_pct: 4,
            recovery_fault_pct: 40,
            double_crash_pct: 10,
            ..Mode::default()
        },
        "cancel-lying" => Mode {
            name: "cancel-lying",
            strict_restart: true,
            cancel_pct: 25,
            sync_data: 40,
            sync_dir: 40,
            lying_sync: 80,
            heal_pct: 4,
            double_crash_pct: 10,
            ..Mode::default()
        },
        // Interrupted-recovery chains (death or one Linux-model fault per
        // step), restart-heavy or power-loss-heavy.
        "rchain" => Mode {
            name: "rchain",
            strict_restart: true,
            sync_data: 120,
            sync_dir: 120,
            write: 40,
            partial: 40,
            set_len: 40,
            remove: 60,
            rename: 40,
            create: 40,
            recovery_only: true,
            chain: 6,
            restart_pct: 50,
            double_crash_pct: 25,
            ..Mode::default()
        },
        "rchain-restart" => Mode {
            name: "rchain-restart",
            strict_restart: true,
            sync_data: 120,
            sync_dir: 120,
            write: 40,
            partial: 40,
            set_len: 40,
            remove: 60,
            rename: 40,
            create: 40,
            recovery_only: true,
            chain: 6,
            restart_pct: 85,
            double_crash_pct: 25,
            ..Mode::default()
        },
        "rchain-death" => Mode {
            name: "rchain-death",
            strict_restart: true,
            sync_data: 100,
            sync_dir: 100,
            write: 30,
            partial: 30,
            remove: 50,
            recovery_only: true,
            midop_death_pct: 50,
            chain: 6,
            restart_pct: 60,
            double_crash_pct: 20,
            cancel_pct: 15,
            ..Mode::default()
        },
        "rchain-chaos" => Mode {
            name: "rchain-chaos",
            strict_restart: true,
            sync_data: 60,
            sync_dir: 60,
            write: 25,
            partial: 25,
            set_len: 25,
            remove: 50,
            rename: 25,
            create: 25,
            lying_sync: 40,
            heal_pct: 4,
            chain: 5,
            restart_pct: 50,
            double_crash_pct: 15,
            cancel_pct: 15,
            ..Mode::default()
        },
        "selftest-skipsync" => Mode {
            name: "selftest-skipsync",
            strict_restart: true,
            skip_sync: 300,
            cancel_pct: 20,
            double_crash_pct: 30,
            ..Mode::default()
        },
        // Targeted, high-rate sync faults on one class of files, with heals
        // (faults stop, FLUSH + checkpoint must work) and power losses.
        "slot-sync" => Mode {
            name: "slot-sync",
            strict_restart: true,
            sync_data: 350,
            write: 40,
            partial: 40,
            fault_paths: ".dat",
            heal_pct: 8,
            cancel_pct: 10,
            recovery_fault_pct: 40,
            double_crash_pct: 30,
            ..Mode::default()
        },
        "meta-sync" => Mode {
            name: "meta-sync",
            strict_restart: true,
            sync_data: 300,
            sync_dir: 300,
            write: 40,
            partial: 40,
            rename: 60,
            remove: 60,
            create: 40,
            fault_paths: ".alloc.,.discard.,catalog,checkpoint,data",
            heal_pct: 8,
            cancel_pct: 10,
            recovery_fault_pct: 40,
            double_crash_pct: 30,
            ..Mode::default()
        },
        "journal-sync" => Mode {
            name: "journal-sync",
            strict_restart: true,
            sync_data: 300,
            sync_dir: 300,
            write: 40,
            partial: 40,
            set_len: 60,
            remove: 60,
            create: 40,
            fault_paths: "journal",
            heal_pct: 8,
            cancel_pct: 10,
            recovery_fault_pct: 40,
            double_crash_pct: 30,
            ..Mode::default()
        },
        "slot-lying" => Mode {
            name: "slot-lying",
            strict_restart: true,
            sync_data: 200,
            lying_sync: 300,
            fault_paths: ".dat,.alloc.,.discard.,checkpoint",
            heal_pct: 8,
            cancel_pct: 10,
            double_crash_pct: 30,
            ..Mode::default()
        },
        "damage-pairs" => Mode {
            name: "damage-pairs",
            double_crash_pct: 10,
            damage_pct: 35,
            damage_pairs: true,
            ..Mode::default()
        },
        "death-damage-pairs" => Mode {
            name: "death-damage-pairs",
            midop_death_pct: 50,
            recovery_death_pct: 30,
            double_crash_pct: 10,
            damage_pct: 35,
            damage_pairs: true,
            cancel_pct: 10,
            ..Mode::default()
        },
        // Round 9: transient faults on the A/B records only (every kind the
        // new truncate / fdatasync / write sequence can meet: a failed
        // truncation, a failed or partial write as on a full filesystem, a
        // failed sync of either), in the workload and in recovery.
        "ab-fault" => Mode {
            name: "ab-fault",
            strict_restart: true,
            sync_data: 220,
            sync_dir: 60,
            write: 90,
            partial: 90,
            set_len: 120,
            create: 40,
            fault_paths: AB_PATHS,
            heal_pct: 8,
            cancel_pct: 5,
            recovery_fault_pct: 60,
            double_crash_pct: 30,
            ..Mode::default()
        },
        // The same faults in chains of interrupted recoveries only.
        "ab-rchain" => Mode {
            name: "ab-rchain",
            strict_restart: true,
            sync_data: 220,
            sync_dir: 60,
            write: 90,
            partial: 90,
            set_len: 120,
            create: 40,
            fault_paths: AB_PATHS,
            recovery_only: true,
            chain: 6,
            restart_pct: 50,
            double_crash_pct: 25,
            ..Mode::default()
        },
        // Faulty workload and chains of faulty recoveries, A/B records only.
        "ab-chain-chaos" => Mode {
            name: "ab-chain-chaos",
            strict_restart: true,
            sync_data: 160,
            sync_dir: 40,
            write: 60,
            partial: 60,
            set_len: 80,
            create: 30,
            fault_paths: AB_PATHS,
            heal_pct: 6,
            chain: 5,
            restart_pct: 50,
            double_crash_pct: 20,
            cancel_pct: 10,
            ..Mode::default()
        },
        // Round 9: metadata sync faults and restarts (so that recovery
        // accepts copies that were never durable), then damage aimed at one
        // shard.
        "sync-damage-shard" => Mode {
            name: "sync-damage-shard",
            sync_data: 200,
            sync_dir: 100,
            fault_paths: ".alloc.,.discard.,catalog",
            restart_pct: 60,
            double_crash_pct: 30,
            damage_pct: 45,
            damage_shard: true,
            ..Mode::default()
        },
        "sync-damage-shard2" => Mode {
            name: "sync-damage-shard2",
            sync_data: 200,
            sync_dir: 100,
            fault_paths: ".alloc.,.discard.,catalog",
            restart_pct: 60,
            double_crash_pct: 30,
            damage_pct: 45,
            damage_shard: true,
            ..Mode::default()
        },
        "damage-shard2" => Mode {
            name: "damage-shard2",
            double_crash_pct: 20,
            damage_pct: 45,
            damage_shard: true,
            ..Mode::default()
        },
        "damage-shard" => Mode {
            name: "damage-shard",
            double_crash_pct: 20,
            damage_pct: 45,
            damage_shard: true,
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

    /// A process death: every later mutation fails, silently.
    fn kill(&self) {
        self.countdown.store(-1, Ordering::SeqCst);
        self.single.store(-1, Ordering::SeqCst);
        self.dead.store(true, Ordering::SeqCst);
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
            if !me.mode.fault_paths.is_empty() {
                let path = match op {
                    FaultOp::Open { path, .. }
                    | FaultOp::WriteAt { path, .. }
                    | FaultOp::SetLen { path, .. }
                    | FaultOp::SyncData { path }
                    | FaultOp::Remove { path } => *path,
                    FaultOp::SyncDir { dir } => *dir,
                    FaultOp::Rename { from, .. } => *from,
                };
                if !me.mode.fault_paths.split(',').any(|p| path.contains(p)) {
                    return None;
                }
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
            let FaultOp::WriteAt { len, path, .. } = op else {
                return None;
            };
            if !me.mode.fault_paths.is_empty()
                && !me.mode.fault_paths.split(',').any(|p| path.contains(p))
            {
                return None;
            }
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
    let result =
        maki_core::check::deep_check(backing.process() as Arc<dyn Backing>, cfg.segment_size);
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
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
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
            let subscriber = tracing_subscriber::registry().with(TraceCounter(counts.clone()));
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
    fn skip_sync(&self) -> bool {
        self.mode.skip_sync > 0
            && !self.dead.load(Ordering::SeqCst)
            && self.rng.lock().random_range(0..1000) < self.mode.skip_sync
    }

    fn lie(&self, what: &str) -> bool {
        if self.lie_next.swap(false, Ordering::SeqCst) {
            self.log
                .lock()
                .push(format!("      !! SINGLE lying sync of {what}"));
            return true;
        }
        if self.dead.load(Ordering::SeqCst)
            || self.countdown.load(Ordering::SeqCst) >= 0
            || !self.enabled.load(Ordering::SeqCst)
            || self.mode.lying_sync == 0
        {
            return false;
        }
        if !self.mode.fault_paths.is_empty()
            && !self.mode.fault_paths.split(',').any(|p| what.contains(p))
        {
            return false;
        }
        if self.rng.lock().random_range(0..1000) < self.mode.lying_sync {
            self.log
                .lock()
                .push(format!("      ! lying sync of {what}"));
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
        if self.injector.skip_sync() {
            // Harness self-test only: a sync that reports success without
            // syncing. The oracle must catch the resulting loss.
            return Ok(());
        }
        self.inner.sync_data()?;
        if self.injector.lie(&self.path) {
            return Err(io::Error::other(
                "audit: sync persisted but reported failure",
            ));
        }
        Ok(())
    }
    fn sync_all(&self) -> io::Result<()> {
        self.inner.sync_all()?;
        if self.injector.lie(&self.path) {
            return Err(io::Error::other(
                "audit: sync persisted but reported failure",
            ));
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
            return Err(io::Error::other(
                "audit: dir sync persisted but reported failure",
            ));
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
    /// A whole-unit read racing another member's write or trim: each unit
    /// must show its old or its new image, never a mix.
    RaceRead {
        first: u64,
        count: u64,
        allowed: Vec<(Vec<u8>, Vec<u8>)>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Crash {
    PowerLoss,
    AllLost,
    Restart,
}

fn pick_crash(rng: &mut StdRng, mode: &Mode) -> Crash {
    if mode.restart_pct > 0 {
        if rng.random_range(0..100) < mode.restart_pct {
            return Crash::Restart;
        }
        return if rng.random_bool(0.75) {
            Crash::PowerLoss
        } else {
            Crash::AllLost
        };
    }
    match rng.random_range(0..100) {
        0..=54 => Crash::PowerLoss,
        55..=69 => Crash::AllLost,
        _ => Crash::Restart,
    }
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

fn apply_crash(kind: Crash, backing: &CrashableBacking, rng: &mut StdRng) {
    match kind {
        // Round 8: half of the sampled power losses use a biased generator
        // (see `Biased`); the rest sample as rounds 1-4 did.
        Crash::PowerLoss => {
            if rng.random_bool(0.5) {
                let (mut biased, _) = Biased::pick(rng);
                backing.crash(&mut biased);
            } else {
                backing.crash(rng);
            }
        }
        Crash::AllLost => backing.crash_all_lost(),
        Crash::Restart => {}
    }
}

/// The unit images a write of `data` (or zeros) at `offset` produces.
fn images_after_write(cfg: &Cfg, model: &Tracked, offset: u64, data: &[u8]) -> Vec<(u64, Vec<u8>)> {
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

/// Every process of the code under test starts on its own
/// `CrashableBacking::process()` view (wrapped by the lying-sync layer), so
/// a power loss kills its handles and namespace access.
#[derive(Clone)]
struct Views {
    raw: Arc<CrashableBacking>,
    injector: Arc<Injector>,
}

impl Views {
    fn view(&self) -> Arc<dyn Backing> {
        Arc::new(Lying {
            inner: self.raw.process(),
            injector: self.injector.clone(),
        })
    }
}

async fn try_attach(
    proc: &Proc,
    cfg: &Cfg,
    backing: &Views,
) -> Result<Engine, AttachError> {
    let (backing, unit, options) = (backing.view(), cfg.unit, cfg.options());
    proc.run(async move {
        Engine::attach(backing, Arc::new(FakeCryptoProvider::new(unit)), options).await
    })
    .await
}

async fn stop_worker(proc: &Proc, engine: &Engine) {
    let e = engine.clone();
    proc.run(async move { e.stop_checkpoint_worker().await })
        .await;
}

async fn read_on(
    proc: &Proc,
    engine: &Engine,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>, CoreError> {
    let e = engine.clone();
    proc.run(async move { e.read(offset, len).await }).await
}

/// One request of the sequential workload.
#[derive(Clone)]
enum Req {
    Write {
        offset: u64,
        data: Vec<u8>,
        fua: bool,
    },
    Zero {
        offset: u64,
        len: usize,
        fua: bool,
    },
    Trim {
        offset: u64,
        len: usize,
        fua: bool,
    },
    Flush,
    Checkpoint,
    Read {
        offset: u64,
        len: usize,
    },
}

/// Issue `req` in the process, maybe cancelled. `None` = cancelled.
async fn issue(
    proc: &Proc,
    engine: &Engine,
    req: Req,
    cut: Option<Cut>,
) -> Option<Result<Option<Vec<u8>>, CoreError>> {
    let e = engine.clone();
    proc.run(async move {
        let fut = async {
            match req {
                Req::Write { offset, data, fua } => e.write(offset, &data, fua).await.map(|_| None),
                Req::Zero { offset, len, fua } => {
                    e.write_zeroes(offset, len, fua).await.map(|_| None)
                }
                Req::Trim { offset, len, fua } => e.trim(offset, len, fua).await.map(|_| None),
                Req::Flush => e.flush().await.map(|_| None),
                Req::Checkpoint => e.checkpoint().await.map(|_| None),
                Req::Read { offset, len } => e.read(offset, len).await.map(Some),
            }
        };
        cancellable(fut, cut).await
    })
    .await
}

/// A configured memory or disk bound that does not hold.
fn bound_violation(cfg: &Cfg, s: &maki_core::engine::EngineStats) -> Option<String> {
    if cfg.max_overlay_bytes > 0 && s.overlay_bytes > cfg.max_overlay_bytes {
        return Some(format!(
            "OVERLAY-BYTES-BOUND: overlay holds {} bytes > max_overlay_bytes {}",
            s.overlay_bytes, cfg.max_overlay_bytes
        ));
    }
    if cfg.max_overlay_entries > 0 && s.overlay_units as u64 > cfg.max_overlay_entries {
        return Some(format!(
            "OVERLAY-ENTRIES-BOUND: overlay holds {} units > max_overlay_entries {}",
            s.overlay_units, cfg.max_overlay_entries
        ));
    }
    if s.journal_total_bytes > cfg.journal_max_bytes {
        return Some(format!(
            "JOURNAL-BOUND: journal holds {} bytes on disk > journal_max_bytes {}",
            s.journal_total_bytes, cfg.journal_max_bytes
        ));
    }
    if s.checkpoint_sequence > s.durable_sequence {
        return Some(format!(
            "CHECKPOINT-AHEAD (live): checkpoint {} > durable {}",
            s.checkpoint_sequence, s.durable_sequence
        ));
    }
    None
}

/// What a cycle-ending process death does.
struct World {
    raw: Arc<CrashableBacking>,
    backing: Views,
    injector: Arc<Injector>,
}

impl World {
    /// The process dies: from now on no mutation reaches the backing (a sync
    /// that fails this way never ran), then its runtime stops.
    fn kill(&self, proc: Proc, engine: Option<Engine>) {
        self.raw.set_lenient_sync_failures(true);
        self.injector.kill();
        drop(engine);
        proc.kill();
        self.injector.revive();
        self.injector.disarm_single();
        self.raw.set_lenient_sync_failures(false);
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

/// Read every unit through a freshly attached engine and check it against
/// the model; then pin it: whatever a successful attach serves must be
/// durable, so it becomes the only allowed value until the next write.
#[allow(clippy::too_many_arguments)]
async fn observe_and_pin(
    proc: &Proc,
    engine: &Engine,
    cfg: &Cfg,
    model: &mut Tracked,
    maybe: &mut BTreeMap<u64, Vec<Vec<u8>>>,
    strict: bool,
    what: &str,
) -> Result<(), String> {
    let unit = cfg.unit as u64;
    let e = engine.clone();
    let s = proc.run(async move { e.stats().await }).await;
    if s.checkpoint_sequence > s.durable_sequence {
        return Err(format!(
            "CHECKPOINT-AHEAD ({what}): checkpoint {} > durable {}",
            s.checkpoint_sequence, s.durable_sequence
        ));
    }
    let mut observed: Vec<Vec<u8>> = Vec::with_capacity(cfg.device_units as usize);
    for u in 0..cfg.device_units {
        let live_before = model.read(u);
        let actual = match read_on(proc, engine, u * unit, unit as usize).await {
            Ok(actual) => actual,
            Err(e) => return Err(format!("READ-AFTER-RECOVERY ({what}): unit {u}: {e}")),
        };
        let in_flight = maybe.get(&u).is_some_and(|set| set.contains(&actual));
        if strict && actual != live_before && !in_flight {
            return Err(format!(
                "RESTART-LOSS ({what}): unit {u} lost an acknowledged write across plain \
                 restarts (first bytes {:02x?}, wanted {:02x?})",
                &actual[..8],
                &live_before[..8]
            ));
        }
        observed.push(actual.clone());
        if let Err(violation) = model.crash_adopt(u, &actual) {
            if !in_flight {
                return Err(format!("ORACLE ({what}): {violation}"));
            }
            model.adopt(u, &actual);
        }
    }
    model
        .check_prefix(&observed)
        .map_err(|text| format!("PREFIX-VIOLATION ({what}): {text}"))?;
    // Pinned: the served state is now the durable baseline.
    model.start_cycle();
    maybe.clear();
    Ok(())
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
        let lines = log.lock();
        let skip = lines.len().saturating_sub(400);
        format!(
            "cfg {} mode {} seed {seed}\n  {}{}",
            cfg.name,
            mode.name,
            if skip > 0 {
                format!("[{skip} earlier lines]\n  ")
            } else {
                String::new()
            },
            lines[skip..].join("\n  ")
        )
    };
    let mut rng = StdRng::seed_from_u64(seed.wrapping_mul(0x9E37_79B9).wrapping_add(0xA0D2));
    let raw = Arc::new(CrashableBacking::new().with_tearing(cfg.tear));
    if cfg.discard {
        init::create_volume_with_discard(raw.as_ref(), cfg.superblock()).unwrap();
    } else {
        init::create_volume(raw.as_ref(), cfg.superblock()).unwrap();
    }
    let injector = Injector::new(mode.clone(), seed, log.clone());
    raw.set_fault_hook(Some(injector.hook()));
    raw.set_partial_write_hook(Some(injector.partial_hook()));
    let backing = Views {
        raw: raw.clone(),
        injector: injector.clone(),
    };
    let world = World {
        raw: raw.clone(),
        backing: backing.clone(),
        injector: injector.clone(),
    };

    let unit = cfg.unit as u64;
    let block = cfg.block as u64;
    let bpu = unit / block;
    let total_blocks = cfg.device_units * bpu;
    let mut model = Tracked::new(cfg.unit as usize, cfg.device_units, cfg.concurrency == 1);
    let zeros = vec![0u8; cfg.unit as usize];
    let mut stamp: u32 = 0;
    let cancel_on = mode.cancel_pct > 0;

    // The first attach of a pristine volume establishes the key canary and
    // the first recovery metadata: interrupt it too, then crash.
    if (mode.recovery_death_pct > 0 || mode.recovery_fault_pct > 0 || mode.chain > 0)
        && rng.random_bool(0.5)
    {
        let at = rng.random_range(1..=40u64);
        let death = rng.random_bool(0.5);
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
        let proc = Proc::new();
        let engine = match try_attach(&proc, &cfg, &backing).await {
            Ok(engine) => {
                say("   first attach completed".to_string());
                Some(engine)
            }
            Err(e) => {
                say(format!("   first attach failed: {e}"));
                None
            }
        };
        world.kill(proc, engine);
        let kind = pick_crash(&mut rng, &mode);
        apply_crash(kind, &raw, &mut rng);
        say(format!("== {kind:?}"));
        stats.bump("first-attach-interrupted");
    }
    let mut proc = Proc::new();
    let mut engine = match try_attach(&proc, &cfg, &backing).await {
        Ok(engine) => engine,
        Err(e) => panic!("ATTACH-FRESH: {e}\n{}", history()),
    };
    if !cfg.worker {
        stop_worker(&proc, &engine).await;
    }
    let mut workload_mutations: u64 = 80;
    let mut recovery_mutations: u64 = 30;

    for cycle in 0..cycles {
        model.start_cycle();
        let ops = rng.random_range(ops_lo..ops_hi);
        let death_armed = rng.random_range(0..100) < mode.midop_death_pct;
        // What a request in flight at a death (or left cancelled and
        // unsettled into the process death) may have left behind.
        let mut maybe: BTreeMap<u64, Vec<Vec<u8>>> = BTreeMap::new();
        let transient = mode.transient() && !death_armed;
        if death_armed {
            raw.set_lenient_sync_failures(true);
            let at = rng.random_range(1..=workload_mutations.max(8));
            injector.arm(at);
            say(format!(
                "-- cycle {cycle}: death armed after {at} mutations"
            ));
        } else {
            raw.set_lenient_sync_failures(false);
            injector.enabled.store(transient, Ordering::SeqCst);
            say(format!("-- cycle {cycle}"));
        }
        let mutations_before = injector.mutations();
        // A cancelled request left unsettled ends the cycle at once.
        let mut end_cycle = false;

        for _ in 0..ops {
            stats.bump("ops");
            // Audit round 4: the configured bounds hold between requests.
            if rng.random_bool(0.25) && !injector.is_dead() {
                let e = engine.clone();
                let s = proc.run(async move { e.stats().await }).await;
                stats.bump("bound-samples");
                if let Some(v) = bound_violation(&cfg, &s) {
                    panic!("{v}\n{}", history());
                }
            }
            if cfg.space {
                let need = 7 * unit + 2 * cfg.record_len();
                let free = match rng.random_range(0..10) {
                    0 => None,
                    1..=3 => Some(rng.random_range(0..need)),
                    _ => Some(rng.random_range(need..4 * need)),
                };
                raw.set_free_bytes(free);
            }
            let roll = rng.random_range(0..100);
            // Resolve a failed or cancelled-and-settled request: every
            // touched unit must show its old or its new image; a new one
            // counts as acknowledged-volatile.
            macro_rules! resolve_units {
                ($what:expr, $images:expr, $allow_without_faults:expr) => {{
                    let images: &Vec<(u64, Vec<u8>)> = $images;
                    if injector.is_dead() {
                        for (u, image) in images {
                            maybe.entry(*u).or_default().push(image.clone());
                            model.in_flight(*u, image);
                        }
                    } else {
                        assert!(
                            $allow_without_faults || transient || cfg.space,
                            "UNEXPECTED-FAILURE: {} failed without faults\n{}",
                            $what,
                            history()
                        );
                        let was = injector.enabled.swap(false, Ordering::SeqCst);
                        for (u, image) in images {
                            let actual =
                                match read_on(&proc, &engine, u * unit, unit as usize).await {
                                    Ok(actual) => actual,
                                    Err(e) => panic!(
                                        "LIVE-READ-FAILED: unit {u} after {}: {e}\n{}",
                                        $what,
                                        history()
                                    ),
                                };
                            if actual == *image {
                                if actual != model.read(*u) {
                                    stats.bump(&format!("visible-{}", $what).replace(' ', "-"));
                                    say(format!(
                                        "      unit {u}: the {} request is visible",
                                        $what
                                    ));
                                    model.write(*u, &actual);
                                }
                            } else {
                                assert!(
                                    actual == model.read(*u),
                                    "LIVE-FOREIGN: unit {u} after {} is neither old nor new\n{}",
                                    $what,
                                    history()
                                );
                            }
                        }
                        injector.enabled.store(was, Ordering::SeqCst);
                    }
                }};
            }
            macro_rules! resolve_failure {
                ($what:expr, $error:expr, $images:expr) => {{
                    let error: &CoreError = $error;
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
                    if !injector.is_dead() && !(transient || cfg.space) {
                        panic!(
                            "UNEXPECTED-FAILURE: {} failed without faults: {error}\n{}",
                            $what,
                            history()
                        );
                    }
                    resolve_units!(format!("failed {}", $what), $images, false);
                }};
            }
            // A cancelled request: settle its detached storage (or leave it
            // in flight into the process death), then resolve it.
            macro_rules! resolve_cancel {
                ($what:expr, $images:expr) => {{
                    let images: &Vec<(u64, Vec<u8>)> = $images;
                    stats.bump(&format!("cancelled-{}", $what));
                    if !images.is_empty() && rng.random_range(0..100) < 15 {
                        say("      (left in flight into the process death)".to_string());
                        stats.bump("cancel-unsettled");
                        for (u, image) in images {
                            maybe.entry(*u).or_default().push(image.clone());
                            model.in_flight(*u, image);
                        }
                        end_cycle = true;
                    } else {
                        let was = injector.enabled.load(Ordering::SeqCst);
                        if let Err(text) = settle(&proc, &engine).await {
                            panic!("{text}\n{}", history());
                        }
                        injector.enabled.store(was, Ordering::SeqCst);
                        resolve_units!(format!("cancelled {}", $what), images, true);
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
                    let r = issue(&proc, &engine, Req::Flush, None).await.unwrap();
                    attempts.push(err_text(&r));
                    if r.is_ok() {
                        healed = true;
                        break;
                    }
                }
                say(format!("heal: flush -> {attempts:?}"));
                assert!(
                    healed,
                    "HEAL-FLUSH: FLUSH keeps failing after faults stopped\n{}",
                    history()
                );
                model.flush();
                let mut attempts = Vec::new();
                let mut healed = false;
                for _ in 0..3 {
                    let r = issue(&proc, &engine, Req::Checkpoint, None).await.unwrap();
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

            if cfg.concurrency > 1 && rng.random_range(0..100) < 45 {
                // A batch of concurrent requests on disjoint units, maybe
                // with a FLUSH and/or a checkpoint racing them, some members
                // cancelled at a random await point.
                let mut used: std::collections::BTreeSet<u64> = Default::default();
                let mut batch: Vec<BatchOp> = Vec::new();
                let width = rng.random_range(2..=cfg.concurrency);
                for _ in 0..width {
                    let kind = rng.random_range(0..100);
                    if kind < 10 {
                        batch.push(BatchOp::Flush);
                        continue;
                    }
                    if kind < 16 {
                        batch.push(BatchOp::Checkpoint);
                        continue;
                    }
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
                    let span = count * bpu;
                    let (start, n) = if bpu > 1 && rng.random_bool(0.5) {
                        let n = rng.random_range(1..=span);
                        (first * bpu + rng.random_range(0..=span - n), n)
                    } else {
                        (first * bpu, span)
                    };
                    let (offset, len) = (start * block, (n * block) as usize);
                    let fua = rng.random_bool(0.25);
                    if kind < 32 {
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
                    } else if kind < 47 && cfg.discard {
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
                // Sometimes race a whole-unit read against one member's
                // write or trim (old or new per unit, never a mix).
                if rng.random_bool(0.35) {
                    let targets: Vec<Vec<(u64, Vec<u8>)>> = batch
                        .iter()
                        .filter_map(|op| match op {
                            BatchOp::Write { images, .. } | BatchOp::Trim { images, .. }
                                if !images.is_empty() =>
                            {
                                Some(images.clone())
                            }
                            _ => None,
                        })
                        .collect();
                    if !targets.is_empty() {
                        let images = &targets[rng.random_range(0..targets.len())];
                        let first = images[0].0;
                        let count = images.len() as u64;
                        let allowed = images
                            .iter()
                            .map(|(u, image)| (model.read(*u), image.clone()))
                            .collect();
                        batch.push(BatchOp::RaceRead {
                            first,
                            count,
                            allowed,
                        });
                    }
                }
                let cuts: Vec<Option<Cut>> = batch
                    .iter()
                    .map(|_| {
                        (cancel_on && rng.random_range(0..100) < mode.cancel_pct)
                            .then(|| pick_cut(&mut rng))
                    })
                    .collect();
                let mut handles = Vec::new();
                for (op, cut) in batch.iter().zip(&cuts) {
                    let req = match op {
                        BatchOp::Flush => Req::Flush,
                        BatchOp::Checkpoint => Req::Checkpoint,
                        BatchOp::Read { offset, len, .. } => Req::Read {
                            offset: *offset,
                            len: *len,
                        },
                        BatchOp::RaceRead { first, count, .. } => Req::Read {
                            offset: first * unit,
                            len: (count * unit) as usize,
                        },
                        BatchOp::Trim {
                            offset, len, fua, ..
                        } => Req::Trim {
                            offset: *offset,
                            len: *len,
                            fua: *fua,
                        },
                        BatchOp::Write {
                            offset,
                            data,
                            fua,
                            zero,
                            ..
                        } => {
                            if *zero {
                                Req::Zero {
                                    offset: *offset,
                                    len: data.len(),
                                    fua: *fua,
                                }
                            } else {
                                Req::Write {
                                    offset: *offset,
                                    data: data.clone(),
                                    fua: *fua,
                                }
                            }
                        }
                    };
                    let e = engine.clone();
                    let cut = *cut;
                    handles.push(proc.handle().spawn(async move {
                        let fut = async {
                            match req {
                                Req::Write { offset, data, fua } => {
                                    e.write(offset, &data, fua).await.map(|_| None)
                                }
                                Req::Zero { offset, len, fua } => {
                                    e.write_zeroes(offset, len, fua).await.map(|_| None)
                                }
                                Req::Trim { offset, len, fua } => {
                                    e.trim(offset, len, fua).await.map(|_| None)
                                }
                                Req::Flush => e.flush().await.map(|_| None),
                                Req::Checkpoint => e.checkpoint().await.map(|_| None),
                                Req::Read { offset, len } => e.read(offset, len).await.map(Some),
                            }
                        };
                        cancellable(fut, cut).await
                    }));
                }
                let mut results = Vec::new();
                let deadline = Instant::now() + Duration::from_secs(60);
                for handle in handles {
                    let left = deadline.saturating_duration_since(Instant::now());
                    match tokio::time::timeout(left, handle).await {
                        Ok(joined) => results.push(joined.expect("batch member panicked")),
                        Err(_) => panic!(
                            "BATCH-HANG: a batch member did not finish within 60 s\n{}",
                            history()
                        ),
                    }
                }
                // A FLUSH in the batch covers only what was acknowledged
                // before the batch began.
                let flushed = batch
                    .iter()
                    .zip(&results)
                    .any(|(op, r)| matches!(op, BatchOp::Flush) && matches!(r, Some(Ok(_))));
                if flushed {
                    model.flush();
                }
                let any_cancelled = results.iter().any(Option::is_none);
                if any_cancelled {
                    // Every detached member must finish before the units are
                    // resolved (they hold their unit locks until then).
                    let was = injector.enabled.load(Ordering::SeqCst);
                    if let Err(text) = settle(&proc, &engine).await {
                        panic!("{text}\n{}", history());
                    }
                    injector.enabled.store(was, Ordering::SeqCst);
                }
                let mut summary = Vec::new();
                let mut failed: Vec<(String, Option<CoreError>, Vec<(u64, Vec<u8>)>)> = Vec::new();
                for (op, result) in batch.into_iter().zip(results) {
                    let verdict = match &result {
                        None => "CANCELLED".to_string(),
                        Some(Ok(_)) => "ok".to_string(),
                        Some(Err(e)) => format!("ERR {e}"),
                    };
                    match op {
                        BatchOp::Flush => {
                            summary.push(format!("flush -> {verdict}"));
                            match result {
                                Some(Err(e)) => failed.push(("flush".into(), Some(e), Vec::new())),
                                None => stats.bump("cancelled-flush"),
                                _ => {}
                            }
                        }
                        BatchOp::Checkpoint => {
                            summary.push(format!("checkpoint -> {verdict}"));
                            match result {
                                Some(Err(e)) => {
                                    failed.push(("checkpoint".into(), Some(e), Vec::new()))
                                }
                                None => stats.bump("cancelled-checkpoint"),
                                _ => {}
                            }
                        }
                        BatchOp::Read { offset, len, want } => {
                            summary.push(format!("read off {offset} len {len} -> {verdict}"));
                            match result {
                                Some(Ok(Some(actual))) => assert!(
                                    actual == want,
                                    "LIVE-MISMATCH: batch read off {offset} len {len} differs \
                                     from the acknowledged image\n{}",
                                    history()
                                ),
                                Some(Ok(None)) => unreachable!(),
                                Some(Err(e)) => assert!(
                                    injector.is_dead(),
                                    "LIVE-READ-FAILED: batch read off {offset} len {len}: {e}\n{}",
                                    history()
                                ),
                                None => stats.bump("cancelled-read"),
                            }
                        }
                        BatchOp::RaceRead {
                            first,
                            count,
                            allowed,
                        } => {
                            summary.push(format!("race-read units {first}+{count} -> {verdict}"));
                            match result {
                                Some(Ok(Some(actual))) => {
                                    for (i, (old, new)) in allowed.iter().enumerate() {
                                        let got = &actual
                                            [i * unit as usize..(i + 1) * unit as usize];
                                        assert!(
                                            got == old.as_slice() || got == new.as_slice(),
                                            "RACE-READ-TORN: unit {} read while being written \
                                             is neither its old nor its new image\n{}",
                                            first + i as u64,
                                            history()
                                        );
                                    }
                                    stats.bump("race-reads");
                                }
                                Some(Ok(None)) => unreachable!(),
                                Some(Err(e)) => assert!(
                                    injector.is_dead(),
                                    "LIVE-READ-FAILED: racing read of units {first}+{count}: {e}\n{}",
                                    history()
                                ),
                                None => stats.bump("cancelled-read"),
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
                                Some(Ok(_)) => {
                                    for (u, image) in &images {
                                        if fua {
                                            model.write_fua(*u, image);
                                        } else {
                                            model.write(*u, image);
                                        }
                                    }
                                }
                                Some(Err(e)) => failed.push(("trim".into(), Some(e), images)),
                                None => failed.push(("trim".into(), None, images)),
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
                                Some(Ok(_)) => {
                                    for (u, image) in &images {
                                        if fua {
                                            model.write_fua(*u, image);
                                        } else {
                                            model.write(*u, image);
                                        }
                                    }
                                }
                                Some(Err(e)) => failed.push(("write".into(), Some(e), images)),
                                None => failed.push(("write".into(), None, images)),
                            }
                        }
                    }
                }
                say(format!("batch [{}]", summary.join(" | ")));
                stats.bump("batches");
                for (what, error, images) in failed {
                    match error {
                        Some(error) => resolve_failure!(what, &error, &images),
                        None => {
                            stats.bump(&format!("cancelled-{what}"));
                            resolve_units!(format!("cancelled {what}"), &images, true);
                        }
                    }
                }
                if injector.is_dead() {
                    break;
                }
                continue;
            }

            let cut = (cancel_on && rng.random_range(0..100) < mode.cancel_pct)
                .then(|| pick_cut(&mut rng));
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
                    let req = if zero {
                        Req::Zero { offset, len, fua }
                    } else {
                        Req::Write {
                            offset,
                            data: data.clone(),
                            fua,
                        }
                    };
                    let result = issue(&proc, &engine, req, cut).await;
                    say(format!(
                        "{} off {offset} len {len} (units {}..={}) stamp {stamp} fua={fua} cut={cut:?} -> {}",
                        if zero { "zero" } else { "write" },
                        images[0].0,
                        images[images.len() - 1].0,
                        match &result {
                            None => "CANCELLED".to_string(),
                            Some(r) => err_text(r),
                        }
                    ));
                    match result {
                        Some(Ok(_)) => {
                            for (u, image) in &images {
                                if fua {
                                    model.write_fua(*u, image);
                                } else {
                                    model.write(*u, image);
                                }
                            }
                        }
                        Some(Err(e)) => resolve_failure!("write", &e, &images),
                        None => resolve_cancel!("write", &images),
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
                    let result = issue(&proc, &engine, Req::Trim { offset, len, fua }, cut).await;
                    say(format!(
                        "trim off {offset} len {len} (whole units {first}..{end}) fua={fua} cut={cut:?} -> {}",
                        match &result {
                            None => "CANCELLED".to_string(),
                            Some(r) => err_text(r),
                        }
                    ));
                    match result {
                        Some(Ok(_)) => {
                            for (u, image) in &images {
                                if fua {
                                    model.write_fua(*u, image);
                                } else {
                                    model.write(*u, image);
                                }
                            }
                        }
                        Some(Err(e)) => resolve_failure!("trim", &e, &images),
                        None => resolve_cancel!("trim", &images),
                    }
                }
                50..=62 => {
                    let u = rng.random_range(0..cfg.device_units);
                    stamp += 1;
                    let data = pattern(stamp, u * unit, unit as usize);
                    let images = vec![(u, data.clone())];
                    let result = issue(
                        &proc,
                        &engine,
                        Req::Write {
                            offset: u * unit,
                            data: data.clone(),
                            fua: false,
                        },
                        cut,
                    )
                    .await;
                    say(format!(
                        "write unit {u} stamp {stamp} fua=false cut={cut:?} -> {}",
                        match &result {
                            None => "CANCELLED".to_string(),
                            Some(r) => err_text(r),
                        }
                    ));
                    match result {
                        Some(Ok(_)) => model.write(u, &data),
                        Some(Err(e)) => resolve_failure!("write", &e, &images),
                        None => resolve_cancel!("write", &images),
                    }
                }
                // FLUSH
                63..=75 => {
                    let result = issue(&proc, &engine, Req::Flush, cut).await;
                    say(format!(
                        "flush cut={cut:?} -> {}",
                        match &result {
                            None => "CANCELLED".to_string(),
                            Some(r) => err_text(r),
                        }
                    ));
                    match result {
                        Some(Ok(_)) => model.flush(),
                        Some(Err(e)) => resolve_failure!("flush", &e, &Vec::new()),
                        None => resolve_cancel!("flush", &Vec::new()),
                    }
                }
                // checkpoint
                76..=86 => {
                    let result = issue(&proc, &engine, Req::Checkpoint, cut).await;
                    say(format!(
                        "checkpoint cut={cut:?} -> {}",
                        match &result {
                            None => "CANCELLED".to_string(),
                            Some(r) => err_text(r),
                        }
                    ));
                    match result {
                        Some(Ok(_)) => {}
                        Some(Err(e)) => resolve_failure!("checkpoint", &e, &Vec::new()),
                        None => resolve_cancel!("checkpoint", &Vec::new()),
                    }
                }
                // live read of a block range
                _ => {
                    let max = (cfg.max_request_units * bpu).min(2 * bpu).min(total_blocks);
                    let n = rng.random_range(1..=max);
                    let start = rng.random_range(0..=total_blocks - n);
                    let (offset, len) = (start * block, (n * block) as usize);
                    match issue(&proc, &engine, Req::Read { offset, len }, cut).await {
                        Some(Ok(Some(actual))) => {
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
                            assert!(
                                actual == want,
                                "LIVE-MISMATCH: read off {offset} len {len} differs from the \
                                 acknowledged image\n{}",
                                history()
                            );
                        }
                        Some(Ok(None)) => unreachable!(),
                        Some(Err(e)) => {
                            assert!(
                                injector.is_dead(),
                                "LIVE-READ-FAILED: read off {offset} len {len}: {e}\n{}",
                                history()
                            );
                        }
                        None => resolve_cancel!("read", &Vec::new()),
                    }
                }
            }
            if injector.is_dead() || end_cycle {
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
        // The process dies wherever its tasks are (worker passes, detached
        // storage of cancelled requests).
        if !end_cycle && !died && rng.random_bool(0.2) {
            let e = engine.clone();
            let s = proc.run(async move { e.stats().await }).await;
            stats.add("engine-checkpoints-sampled", s.checkpoints_total);
            stats.add(
                "engine-checkpoint-failures-sampled",
                s.checkpoint_failures_total,
            );
        }
        if !end_cycle && !died && rng.random_bool(0.3) {
            // A graceful detach first: the worker finishes its pass.
            stop_worker(&proc, &engine).await;
            stats.bump("graceful-stops");
        }
        world.kill(proc, Some(engine));

        let mut kind = pick_crash(&mut rng, &mode);
        apply_crash(kind, &raw, &mut rng);
        say(format!("== {kind:?}"));
        stats.bump("crashes");
        // A restart loses nothing; that only holds while no power loss
        // happens before the state is inspected.
        let mut strict = kind == Crash::Restart && mode.strict_restart;

        if mode.chain > 0 {
            // A chain of interrupted recoveries.
            let steps = rng.random_range(0..=mode.chain);
            for step in 0..steps {
                let death = rng.random_bool(0.5);
                let at = rng.random_range(1..=recovery_mutations.max(6) + 4);
                if death {
                    raw.set_lenient_sync_failures(true);
                    injector.arm(at);
                } else {
                    raw.set_lenient_sync_failures(false);
                    injector.arm_single(at);
                }
                say(format!(
                    "chain step {step}: recovery with {} after {at} mutations",
                    if death {
                        "death"
                    } else {
                        "one Linux-model fault"
                    }
                ));
                let p = Proc::new();
                let result = try_attach(&p, &cfg, &backing).await;
                let died = injector.is_dead();
                let fired = death && died || !death && injector.single.load(Ordering::SeqCst) < 0;
                match result {
                    Ok(engine) => {
                        say(format!(
                            "   recovery completed (interruption fired={fired})"
                        ));
                        stats.bump(if fired {
                            "chain-ok-after-interruption"
                        } else {
                            "chain-ok-clean"
                        });
                        if fired {
                            let line = log
                                .lock()
                                .iter()
                                .rev()
                                .find(|l| l.contains("DEATH") || l.contains("SINGLE"))
                                .cloned()
                                .unwrap_or_default();
                            stats.note(format!(
                                "cfg {} mode {} seed {seed}: attach succeeded after {}",
                                cfg.name,
                                mode.name,
                                line.trim()
                            ));
                        }
                        // Interruptions off for the observation and the
                        // post-recovery write; a death that already fired
                        // (in the worker, after attach) skips both.
                        injector.disarm_single();
                        if !injector.is_dead() {
                            injector.revive();
                            raw.set_lenient_sync_failures(false);
                            if !cfg.worker {
                                stop_worker(&p, &engine).await;
                            }
                            if let Err(text) = observe_and_pin(
                                &p,
                                &engine,
                                &cfg,
                                &mut model,
                                &mut maybe,
                                strict,
                                &format!("chain step {step}"),
                            )
                            .await
                            {
                                panic!("{text}\n{}", history());
                            }
                            stats.bump("chain-pinned");
                            // Sometimes write through the recovered engine:
                            // its barriers must be as good as any.
                            if rng.random_bool(0.4) {
                                if cfg.space {
                                    raw.set_free_bytes(Some(1 << 30));
                                }
                                let u = rng.random_range(0..cfg.device_units);
                                stamp += 1;
                                let data = pattern(stamp, u * unit, unit as usize);
                                let fua = rng.random_bool(0.5);
                                let r = issue(
                                    &p,
                                    &engine,
                                    Req::Write {
                                        offset: u * unit,
                                        data: data.clone(),
                                        fua,
                                    },
                                    None,
                                )
                                .await
                                .unwrap();
                                let r = match (r, fua) {
                                    (Ok(_), false) => {
                                        issue(&p, &engine, Req::Flush, None).await.unwrap()
                                    }
                                    (r, _) => r,
                                };
                                say(format!(
                                    "   post-recovery write unit {u} stamp {stamp} fua={fua} (+flush) -> {}",
                                    err_text(&r)
                                ));
                                match r {
                                    Ok(_) => model.write_fua(u, &data),
                                    Err(e) => panic!(
                                        "POST-RECOVERY-WRITE: a write/flush through a recovered \
                                         engine failed without faults: {e}\n{}",
                                        history()
                                    ),
                                }
                            }
                        }
                        world.kill(p, Some(engine));
                    }
                    Err(e) => {
                        say(format!("   recovery failed: {e}"));
                        if !fired {
                            panic!(
                                "ATTACH-REFUSED: recovery failed before its injected interruption: \
                                 {e}\n{}",
                                history()
                            );
                        }
                        stats.bump("chain-interrupted");
                        world.kill(p, None);
                    }
                }
                kind = pick_crash(&mut rng, &mode);
                apply_crash(kind, &raw, &mut rng);
                say(format!("== {kind:?}"));
                strict &= kind == Crash::Restart;
                stats.bump("chain-steps");
            }
        } else {
            let mut attempts = 0;
            while attempts < 3 && rng.random_range(0..100) < mode.recovery_death_pct {
                attempts += 1;
                raw.set_lenient_sync_failures(true);
                let at = rng.random_range(1..=recovery_mutations.max(6) + 4);
                injector.arm(at);
                say(format!("recovery with death armed after {at} mutations"));
                let p = Proc::new();
                let result = try_attach(&p, &cfg, &backing).await;
                let died = injector.is_dead();
                match result {
                    Ok(engine) => {
                        say(format!("   recovery completed (died={died})"));
                        if died {
                            stats.bump("recovery-ok-despite-death");
                        }
                        stats.bump("recovery-then-crash");
                        world.kill(p, Some(engine));
                    }
                    Err(e) => {
                        say(format!("   recovery failed: {e}"));
                        assert!(
                            died,
                            "ATTACH-REFUSED: recovery failed before the injected death: {e}\n{}",
                            history()
                        );
                        stats.bump("recovery-deaths");
                        world.kill(p, None);
                    }
                }
                kind = pick_crash(&mut rng, &mode);
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
                let at = rng.random_range(1..=recovery_mutations.max(6) + 2);
                say(format!(
                    "recovery with one transient fault after {at} mutations"
                ));
                injector.arm_single(at);
                let p = Proc::new();
                let result = try_attach(&p, &cfg, &backing).await;
                let fired = injector.single.load(Ordering::SeqCst) < 0;
                injector.disarm_single();
                match result {
                    Ok(engine) => {
                        say(format!(
                            "   faulty recovery completed (fault fired={fired})"
                        ));
                        stats.bump("faulty-recovery-ok");
                        if fired {
                            stats.bump("faulty-recovery-ok-after-fault");
                        }
                        world.kill(p, Some(engine));
                    }
                    Err(e) => {
                        say(format!("   faulty recovery failed: {e}"));
                        if !fired {
                            panic!(
                                "ATTACH-REFUSED: recovery failed before its injected fault: {e}\n{}",
                                history()
                            );
                        }
                        stats.bump("faulty-recovery-failed");
                        world.kill(p, None);
                    }
                }
                kind = pick_crash(&mut rng, &mode);
                apply_crash(kind, &raw, &mut rng);
                say(format!("== {kind:?}"));
                strict &= kind == Crash::Restart;
            }
        }

        if rng.random_range(0..100) < mode.double_crash_pct {
            // Recover, pin what the engine serves, then crash before any
            // write: the next recovery must serve exactly the same.
            let p = Proc::new();
            match try_attach(&p, &cfg, &backing).await {
                Ok(engine) => {
                    if !cfg.worker {
                        stop_worker(&p, &engine).await;
                    }
                    if let Err(text) = observe_and_pin(
                        &p,
                        &engine,
                        &cfg,
                        &mut model,
                        &mut maybe,
                        strict,
                        "double crash",
                    )
                    .await
                    {
                        panic!("{text}\n{}", history());
                    }
                    world.kill(p, Some(engine));
                }
                Err(e) => panic!("ATTACH-REFUSED: {e}\n{}", history()),
            }
            kind = pick_crash(&mut rng, &mode);
            apply_crash(kind, &raw, &mut rng);
            say(format!(
                "recovered and pinned, then == {kind:?} before any write"
            ));
            strict &= kind == Crash::Restart;
            stats.bump("double-crashes");
        }

        if rng.random_range(0..100) < mode.damage_pct {
            let candidates = damage_candidates(&raw);
            let pairs: Vec<String> = candidates
                .iter()
                .filter(|p| {
                    p.ends_with(".a") && candidates.contains(&format!("{}b", &p[..p.len() - 1]))
                })
                .cloned()
                .collect();
            let shards: Vec<String> = candidates
                .iter()
                .filter(|p| p.ends_with(".dat"))
                .cloned()
                .collect();
            if mode.damage_shard && !shards.is_empty() {
                let dat = shards[rng.random_range(0..shards.len())].clone();
                let stem = dat.trim_end_matches(".dat").to_string();
                let file = raw.open(&dat, false).unwrap();
                let len = file.len().unwrap();
                if len > 0 {
                    let keep = rng.random_range(0..len);
                    file.set_len(keep).unwrap();
                    file.sync_data().unwrap();
                    say(format!("DAMAGE {dat}: truncate {len} -> {keep}"));
                }
                drop(file);
                // The newest valid copy of a pair, by its raw generation.
                let newest = |a: String, b: String| -> Option<String> {
                    let generation = |path: &str| -> Option<u64> {
                        let file = raw.open(path, false).ok()?;
                        let len = file.len().ok()?;
                        let mut bytes = vec![0u8; len as usize];
                        file.read_at(0, &mut bytes).ok()?;
                        (len >= 24
                            && crc32fast::hash(&bytes[..len as usize - 4]).to_le_bytes()
                                == bytes[len as usize - 4..])
                            .then(|| u64::from_le_bytes(bytes[12..20].try_into().unwrap()))
                    };
                    match (generation(&a), generation(&b)) {
                        (Some(ga), Some(gb)) => Some(if ga >= gb { a } else { b }),
                        (Some(_), None) => Some(a),
                        (None, Some(_)) => Some(b),
                        (None, None) => None,
                    }
                };
                if let Some(path) = newest(format!("{stem}.alloc.a"), format!("{stem}.alloc.b")) {
                    say(format!("DAMAGE {}", damage_file(&raw, &path, &mut rng)));
                }
                // The `*2` modes damage two files only, as the maintained
                // media-damage sweep does.
                if !mode.name.ends_with('2') && rng.random_bool(0.3) {
                    if let Some(path) =
                        newest("shard-catalog.a".to_string(), "shard-catalog.b".to_string())
                    {
                        say(format!("DAMAGE {}", damage_file(&raw, &path, &mut rng)));
                    }
                }
                stats.bump("damaged-shard");
            } else if mode.damage_pairs && !pairs.is_empty() {
                let a = pairs[rng.random_range(0..pairs.len())].clone();
                let b = format!("{}b", &a[..a.len() - 1]);
                say(format!("DAMAGE {}", damage_file(&raw, &a, &mut rng)));
                say(format!("DAMAGE {}", damage_file(&raw, &b, &mut rng)));
                stats.bump(&format!(
                    "damaged-pair-{}",
                    a.trim_start_matches("data/")
                        .trim_start_matches("checkpoint/")
                        .split(['-', '.'])
                        .find(|s| !s.is_empty()
                            && !s.chars().all(|c| c.is_ascii_digit())
                            && *s != "shard")
                        .unwrap_or("?")
                ));
            } else {
                for _ in 0..rng.random_range(1..=2usize) {
                    let path = candidates[rng.random_range(0..candidates.len())].clone();
                    say(format!("DAMAGE {}", damage_file(&raw, &path, &mut rng)));
                }
            }
            stats.bump("damaged");
            let report = match run_deep_check(&cfg, &raw, &injector) {
                Ok(report) => report,
                Err(text) => panic!("{text}\n{}", history()),
            };
            let check_clean = report.as_ref().map(|r| r.errors.is_empty());
            let p = Proc::new();
            let engine = match try_attach(&p, &cfg, &backing).await {
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
                    world.kill(p, None);
                    return;
                }
            };
            stop_worker(&p, &engine).await;
            let mut eio_units = 0u64;
            for u in 0..cfg.device_units {
                match read_on(&p, &engine, u * unit, unit as usize).await {
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
                let damage: Vec<String> = log
                    .lock()
                    .iter()
                    .filter(|l| l.contains("DAMAGE"))
                    .map(|l| l.trim().to_string())
                    .collect();
                stats.note(format!(
                    "cfg {} mode {} seed {seed}: deep check errors {:?} but attach + every unit read fine; {}",
                    cfg.name,
                    mode.name,
                    report.as_ref().map(|r| r.errors.clone()).unwrap_or_default(),
                    damage.join("; ")
                ));
            }
            stats.bump("damage-attached");
            world.kill(p, Some(engine));
            return;
        }

        if rng.random_range(0..100) < 35 {
            match run_deep_check(&cfg, &raw, &injector) {
                Err(text) => panic!("{text}\n{}", history()),
                Ok(None) => stats.bump("check-inconclusive"),
                Ok(Some(report)) => {
                    stats.bump("checks");
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
        proc = Proc::new();
        if cancel_on && rng.random_range(0..100) < 20 {
            // The attach future itself is dropped at a random await point;
            // its blocking recovery may still run. A retry in the same
            // process must succeed once that storage work has finished.
            let cut = pick_cut(&mut rng);
            let (b, u, o) = (backing.view(), cfg.unit, cfg.options());
            let first = proc
                .run(async move {
                    cancellable(
                        Engine::attach(b, Arc::new(FakeCryptoProvider::new(u)), o),
                        Some(cut),
                    )
                    .await
                })
                .await;
            say(format!(
                "attach cancelled at {cut:?}: {}",
                match &first {
                    None => "CANCELLED".to_string(),
                    Some(Ok(_)) => "completed".to_string(),
                    Some(Err(e)) => format!("ERR {e}"),
                }
            ));
            match first {
                Some(Err(e)) => panic!("ATTACH-REFUSED: {e}\n{}", history()),
                Some(Ok(engine)) => {
                    // Completed before the cut: a second process-local engine
                    // must not coexist; drop it before the retry. (Round 4:
                    // stop its worker first, so the volume lock is released
                    // now rather than when a running worker pass ends.)
                    stop_worker(&proc, &engine).await;
                    drop(engine);
                    stats.bump("attach-cut-too-late");
                }
                None => stats.bump("attach-cancelled"),
            }
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                tokio::time::sleep(Duration::from_millis(1)).await;
                match try_attach(&proc, &cfg, &backing).await {
                    Ok(engine) => {
                        // Hand it to the normal path below.
                        stop_worker(&proc, &engine).await;
                        drop(engine);
                        break;
                    }
                    Err(e) if e.to_string().contains("ALREADY_ATTACHED") => {
                        if Instant::now() > deadline {
                            panic!(
                                "ATTACH-AFTER-CANCEL: the volume stayed locked 30 s after a \
                                 cancelled attach: {e}\n{}",
                                history()
                            );
                        }
                    }
                    Err(e) => panic!(
                        "ATTACH-REFUSED (after cancelled attach): {e}\n{}",
                        history()
                    ),
                }
            }
            // The dropped engines' workers must be gone before the real
            // attach (their volume lock is released when the last owner goes).
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                match try_attach(&proc, &cfg, &backing).await {
                    Ok(engine) => {
                        stop_worker(&proc, &engine).await;
                        drop(engine);
                        break;
                    }
                    Err(e)
                        if Instant::now() < deadline
                            && e.to_string().contains("ALREADY_ATTACHED") =>
                    {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                    Err(e) => panic!("ATTACH-AFTER-CANCEL: {e}\n{}", history()),
                }
            }
        }
        engine = match try_attach(&proc, &cfg, &backing).await {
            Ok(engine) => engine,
            Err(e) => panic!("ATTACH-REFUSED: {e}\n{}", history()),
        };
        if !cfg.worker {
            stop_worker(&proc, &engine).await;
        }
        recovery_mutations = (injector.mutations() - before).max(6);
        say("recovered".to_string());
        if let Err(text) = observe_and_pin(
            &proc,
            &engine,
            &cfg,
            &mut model,
            &mut maybe,
            strict,
            "cycle end",
        )
        .await
        {
            panic!("{text}\n{}", history());
        }
        stats.bump("recoveries-checked");

        // A recovered volume must accept a checkpoint and a flush.
        if rng.random_bool(0.3) {
            if let Some(Err(e)) = issue(&proc, &engine, Req::Checkpoint, None).await {
                panic!("POST-RECOVERY-CHECKPOINT: {e}\n{}", history());
            }
            say("post-recovery checkpoint ok".to_string());
        }
    }
    world.kill(proc, Some(engine));
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
    if std::env::var_os("AUDIT_TRACES").is_some() {
        for (event, count) in traces.lock().iter() {
            println!("AUDIT-TRACE cfg={cfg_name} mode={mode_name} {count:>6} {event}");
        }
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
            .unwrap_or(30),
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
    // Round 8: `AUDIT8_SEED_START` / `AUDIT8_SEED_COUNT` (the round-1..4
    // names still work).
    let start = std::env::var("AUDIT8_SEED_START")
        .or_else(|_| std::env::var("AUDIT_SEED_START"))
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let count: u64 = std::env::var("AUDIT8_SEED_COUNT")
        .or_else(|_| std::env::var("AUDIT_SEED_COUNT"))
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(40);
    start..start + count
}

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
    let refs: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(c, m)| (c.as_str(), m.as_str()))
        .collect();
    sweep_all(&refs, seeds, cycles).await;
}

const SEQ: [&str; 6] = [
    "seg1-v3",
    "seg3-tight-v3",
    "odd-v3",
    "shard1-v3",
    "rmw-v3",
    "pend1-v3",
];
const CONC: [&str; 5] = [
    "conc-v3",
    "conc-v2",
    "conc-rmw-v3",
    "conc-shard1-v3",
    "conc-noworker-v3",
];
const GATE: [&str; 7] = [
    "gate-v3",
    "gate-noworker-v3",
    "gate-ovlbytes-v3",
    "gate-journal-v2",
    "gate-rmw-v3",
    "gate-shard1-v3",
    "gate-space-v3",
];

/// Item 1: cancelled requests, sequential and concurrent, mixed with
/// crashes, deaths and faults.
#[tokio::test]
async fn audit2_cancel_sequential() {
    sweep_owned(
        pairs_from_env(all_pairs(
            &SEQ,
            &[
                "cancel",
                "cancel-death",
                "cancel-sync",
                "cancel-chaos",
                "cancel-lying",
            ],
        )),
        seeds(),
        4,
    )
    .await;
}

#[tokio::test]
async fn audit2_cancel_concurrent() {
    sweep_owned(
        pairs_from_env(all_pairs(
            &CONC,
            &["cancel", "cancel-death", "cancel-chaos", "cancel-lying"],
        )),
        seeds(),
        4,
    )
    .await;
}

/// Item 2: interrupted-recovery chains with restarts and power losses.
#[tokio::test]
async fn audit2_recovery_chains() {
    let mut cfgs: Vec<&str> = SEQ.to_vec();
    cfgs.extend(["conc-v3", "seg3-worker-v3", "blk4k-v3", "u16k-v3"]);
    sweep_owned(
        pairs_from_env(all_pairs(
            &cfgs,
            &["rchain", "rchain-restart", "rchain-death", "rchain-chaos"],
        )),
        seeds(),
        4,
    )
    .await;
}

/// Item 4: the reclaim gate under concurrency, cancellation, faults, crashes.
#[tokio::test]
async fn audit2_reclaim_gate() {
    sweep_owned(
        pairs_from_env(all_pairs(
            &GATE,
            &[
                "crash",
                "cancel",
                "cancel-death",
                "cancel-chaos",
                "rchain-death",
            ],
        )),
        seeds(),
        4,
    )
    .await;
}

#[tokio::test]
async fn audit2_random() {
    sweep_owned(
        pairs_from_env(all_pairs(
            &["random-any", "random-gate"],
            &[
                "cancel",
                "cancel-death",
                "cancel-chaos",
                "cancel-lying",
                "rchain",
                "rchain-death",
                "rchain-chaos",
                "death-damage",
            ],
        )),
        seeds(),
        4,
    )
    .await;
}

/// Targeted high-rate sync faults on one class of files.
#[tokio::test]
async fn audit2_targeted_sync() {
    sweep_owned(
        pairs_from_env(all_pairs(
            &[
                "seg3-tight-v3",
                "rmw-v3",
                "shard1-v3",
                "conc-v3",
                "gate-v3",
                "odd-v3",
            ],
            &["slot-sync", "meta-sync", "journal-sync", "slot-lying"],
        )),
        seeds(),
        4,
    )
    .await;
}

/// Media damage to both copies of an A/B pair: the deep check must agree
/// with attach and the read path.
#[tokio::test]
async fn audit2_damage_pairs() {
    sweep_owned(
        pairs_from_env(all_pairs(
            &[
                "seg3-tight-v3",
                "rmw-v3",
                "shard1-v3",
                "odd-v3",
                "conc-v3",
                "random-any",
            ],
            &["damage-pairs", "death-damage-pairs"],
        )),
        seeds(),
        4,
    )
    .await;
}

/// Round 1's modes on the new process model (regression of the harness).
#[tokio::test]
async fn audit2_round1_modes() {
    sweep_owned(
        pairs_from_env(all_pairs(
            &["seg3-tight-v3", "rmw-v3", "conc-v3", "pend1-v3"],
            &[
                "crash",
                "death",
                "chaos-death",
                "chaos-rfault",
                "lying",
                "damage",
            ],
        )),
        seeds(),
        4,
    )
    .await;
}

/// Round 8: the widened random geometry under every mode family.
#[tokio::test]
async fn audit8_r8_geometry() {
    sweep_owned(
        pairs_from_env(all_pairs(
            &["r8-any", "r8-gate"],
            &[
                "crash",
                "cancel",
                "cancel-death",
                "cancel-chaos",
                "cancel-lying",
                "rchain",
                "rchain-death",
                "rchain-chaos",
                "chaos-rfault",
                "death-damage",
                "damage-pairs",
                "slot-sync",
                "meta-sync",
                "journal-sync",
            ],
        )),
        seeds(),
        4,
    )
    .await;
}

/// Round 9: tearing units below every A/B record, under the round-8 mode
/// families that end in recovery, and under faults on the A/B records only.
#[tokio::test]
async fn audit9_ab_geometry() {
    sweep_owned(
        pairs_from_env(all_pairs(
            &["r9-ab", "r9-ab-gate"],
            &[
                "crash",
                "rchain",
                "rchain-chaos",
                "chaos-rfault",
                "meta-sync",
                "ab-fault",
                "ab-rchain",
                "ab-chain-chaos",
            ],
        )),
        seeds(),
        4,
    )
    .await;
}

/// Round 9: damage aimed at one shard (data file tail + newest allocation
/// copy, sometimes the newest catalog copy), with and without a history of
/// metadata sync faults and restarts.
#[tokio::test]
async fn audit9_shard_damage() {
    sweep_owned(
        pairs_from_env(all_pairs(
            &["r8-any", "seg3-tight", "odd", "shard1", "plain"],
            &["sync-damage-shard", "damage-shard"],
        )),
        seeds(),
        4,
    )
    .await;
}

/// One seed, chosen by environment, with its full history printed:
/// `AUDIT_CFG=odd-v3 AUDIT_MODE=cancel AUDIT_SEED=17 [AUDIT_CYCLES=4]`.
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

/// The cancellation wrapper drops a request at an await point and the
/// detached storage still lands (the oracle must allow both outcomes).
#[test]
fn audit_cancel_wrapper_drops_at_await_point() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let r = cancellable(
            async {
                tokio::task::yield_now().await;
                1
            },
            Some(Cut::Polls(1)),
        )
        .await;
        assert_eq!(r, None);
        let r = cancellable(async { 2 }, Some(Cut::Polls(1))).await;
        assert_eq!(r, Some(2));
    });
}
