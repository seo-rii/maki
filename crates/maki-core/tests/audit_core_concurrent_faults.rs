//! Audit (core write path): the live model of `audit_core_live_model.rs`
//! with transient backing faults injected *concurrently* with the workload
//! and background checkpoints: failed shard data syncs (Linux model: dirty
//! pages marked clean), failed journal syncs, directory syncs and metadata
//! writes. A failed request leaves its units uncertain (old or new). After the
//! faults stop, the engine must heal (FLUSH + checkpoint succeed), the live
//! image must match the model, and a power loss after that FLUSH must
//! reproduce the live image exactly.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use maki_core::engine::{CheckpointPolicy, Engine, EngineCacheConfig, EngineLimits, EngineOptions};
use maki_core::volume::VolumeOptions;
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::{CrashableBacking, FakeCryptoProvider};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const UNIT: usize = 1024;
const UNITS: usize = 64;
const TASKS: usize = 4;
const PER_TASK: usize = UNITS / TASKS;

fn options(verify_on_hit: bool, cache: bool) -> EngineOptions {
    EngineOptions {
        volume: VolumeOptions {
            journal_segment_size: 4096,
        },
        limits: EngineLimits {
            max_active_callbacks: 64,
            max_plaintext_bytes: 1 << 20,
            max_request_bytes: 8 * 1024,
            max_overlay_bytes: 48_000,
            max_overlay_entries: 24,
        },
        cache: cache.then_some(EngineCacheConfig {
            max_bytes: 6 * 1024,
            ttl: Duration::from_secs(3600),
            verify_on_hit,
        }),
        checkpoint: CheckpointPolicy {
            journal_high_watermark_bytes: 10 * 1024,
            journal_max_bytes: 20 * 1024,
            max_pending_bytes: 4096,
            emergency_reserve_bytes: 0,
            low_space_checkpoint_bytes: 0,
            interval: Duration::from_secs(3600),
        },
        ..Default::default()
    }
}

fn create(backing: &CrashableBacking) {
    init::create_volume_with_discard(
        backing,
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xa0d1_7001),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, UNIT as u32, 512, UNIT as u32 + 8, (UNITS * UNIT) as u64, 8 * 1024)
                .unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
}

async fn attach(backing: &Arc<CrashableBacking>, verify_on_hit: bool, cache: bool) -> Engine {
    Engine::attach(
        backing.clone(),
        Arc::new(FakeCryptoProvider::new(UNIT as u32)),
        options(verify_on_hit, cache),
    )
    .await
    .unwrap()
}

/// Completes after being polled `n` times (a cancellation point that does
/// not depend on wall-clock time).
struct YieldN(usize);
impl Future for YieldN {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 == 0 {
            Poll::Ready(())
        } else {
            self.0 -= 1;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// Run `op`, cancelling it after `cancel_after` polls of the timer when set.
/// Returns `None` if cancelled.
async fn maybe_cancel<T>(op: impl Future<Output = T>, cancel_after: Option<usize>) -> Option<T> {
    match cancel_after {
        None => Some(op.await),
        Some(n) => {
            tokio::select! {
                biased;
                r = op => Some(r),
                _ = YieldN(n) => None,
            }
        }
    }
}

/// Candidate contents per unit.
#[derive(Clone)]
struct Model {
    units: Vec<HashSet<Vec<u8>>>,
}

impl Model {
    fn new() -> Self {
        Self {
            units: (0..UNITS)
                .map(|_| HashSet::from([vec![0u8; UNIT]]))
                .collect(),
        }
    }

    /// Apply a byte-range update to the candidate set of every touched unit.
    /// `uncertain`: keep the old candidates as well (cancelled or failed op).
    fn apply(&mut self, offset: usize, f: impl Fn(usize, &mut [u8]), len: usize, uncertain: bool) {
        let first = offset / UNIT;
        let last = (offset + len - 1) / UNIT;
        for unit in first..=last {
            let start = unit * UNIT;
            let from = offset.max(start) - start;
            let to = (offset + len).min(start + UNIT) - start;
            let mut next = HashSet::new();
            for old in &self.units[unit] {
                let mut new = old.clone();
                f(start, &mut new[from..to]);
                if uncertain {
                    next.insert(old.clone());
                }
                next.insert(new);
            }
            assert!(next.len() <= 64, "model candidate explosion");
            self.units[unit] = next;
        }
    }

    fn check(&self, offset: usize, data: &[u8], what: &str) {
        let first = offset / UNIT;
        let last = (offset + data.len() - 1) / UNIT;
        for unit in first..=last {
            let start = unit * UNIT;
            let from = offset.max(start) - start;
            let to = (offset + data.len()).min(start + UNIT) - start;
            let got = &data[start + from - offset..start + to - offset];
            assert!(
                self.units[unit].iter().any(|c| &c[from..to] == got),
                "{what}: unit {unit} bytes {from}..{to} match no allowed candidate \
                 (first byte {:#x}, {} candidates)",
                got[0],
                self.units[unit].len()
            );
        }
    }
}

async fn writer(engine: Engine, task: usize, seed: u64, ops: usize) -> Model {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut model = Model::new();
    let base_unit = task * PER_TASK;
    for step in 0..ops {
        let first = base_unit + rng.random_range(0..PER_TASK);
        let max_end = (base_unit + PER_TASK).min(first + 8);
        let end_unit = rng.random_range(first + 1..=max_end);
        // Block-granular offsets inside the chosen unit range.
        let mut offset = first * UNIT + 512 * rng.random_range(0..2usize);
        let mut end = end_unit * UNIT - 512 * rng.random_range(0..2usize);
        if end <= offset {
            offset = first * UNIT;
            end = end_unit * UNIT;
        }
        let len = end - offset;
        let fua = rng.random_bool(0.2);
        let cancel = rng.random_bool(0.15).then(|| rng.random_range(0..40usize));
        let what = format!("task {task} step {step}");
        match rng.random_range(0..10u32) {
            0..=3 => {
                let byte = (step as u8).wrapping_mul(7).wrapping_add(task as u8 * 61) | 1;
                let data = vec![byte; len];
                let r = maybe_cancel(engine.write(offset as u64, &data, fua), cancel).await;
                match r {
                    Some(Ok(())) => model.apply(offset, |_, d| d.fill(byte), len, false),
                    Some(Err(_)) | None => model.apply(offset, |_, d| d.fill(byte), len, true),
                }
            }
            4 => {
                let r = maybe_cancel(engine.write_zeroes(offset as u64, len, fua), cancel).await;
                match r {
                    Some(Ok(())) => model.apply(offset, |_, d| d.fill(0), len, false),
                    Some(Err(_)) | None => model.apply(offset, |_, d| d.fill(0), len, true),
                }
            }
            5..=6 => {
                // Trim zeroes whole units only.
                let r = maybe_cancel(engine.trim(offset as u64, len, fua), cancel).await;
                let wf = offset.div_ceil(UNIT);
                let we = (offset + len) / UNIT;
                if wf < we {
                    let (o, l) = (wf * UNIT, (we - wf) * UNIT);
                    match r {
                        Some(Ok(())) => model.apply(o, |_, d| d.fill(0), l, false),
                        Some(Err(_)) | None => model.apply(o, |_, d| d.fill(0), l, true),
                    }
                }
            }
            _ => {
                if let Some(r) = maybe_cancel(engine.read(offset as u64, len), cancel).await {
                    let data = r.unwrap_or_else(|e| panic!("{what}: read failed: {e}"));
                    model.check(offset, &data, &what);
                }
            }
        }
        if step % 16 == 0 {
            tokio::task::yield_now().await;
        }
    }
    model
}

async fn read_all(engine: &Engine) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in 0..(UNITS * UNIT) / 8192 {
        out.extend(engine.read((chunk * 8192) as u64, 8192).await.unwrap());
    }
    out
}

async fn quiesce(engine: &Engine) {
    for _ in 0..200_000 {
        let s = engine.stats().await;
        if s.admission_slots == 0 && s.plaintext_bytes_in_flight == 0 && s.active_requests == 0 {
            return;
        }
        tokio::task::yield_now().await;
    }
    let s = engine.stats().await;
    panic!(
        "engine never became quiescent: slots {} bytes {} active {}",
        s.admission_slots, s.plaintext_bytes_in_flight, s.active_requests
    );
}

async fn run(seed: u64, verify_on_hit: bool, cache: bool) {
    let backing = Arc::new(CrashableBacking::new());
    create(&backing);
    let engine = attach(&backing, verify_on_hit, cache).await;
    let faults_on = Arc::new(AtomicBool::new(true));
    let counter = Arc::new(AtomicU64::new(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1));
    let injected = Arc::new(AtomicU64::new(0));
    {
        let faults_on = faults_on.clone();
        let counter = counter.clone();
        let injected = injected.clone();
        backing.set_fault_hook(Some(Arc::new(move |op| {
            if !faults_on.load(Ordering::SeqCst) {
                return None;
            }
            // xorshift for a cheap shared pseudo-random stream
            let mut x = counter.load(Ordering::Relaxed);
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            counter.store(x, Ordering::Relaxed);
            let roll = x % 1000;
            let hit = match op {
                FaultOp::SyncData { path } if path.ends_with(".dat") => roll < 60,
                FaultOp::SyncData { path } if path.starts_with("journal/") => roll < 30,
                FaultOp::SyncData { .. } => roll < 20,
                FaultOp::SyncDir { .. } => roll < 20,
                FaultOp::WriteAt { path, .. } if !path.ends_with(".dat") && !path.starts_with("journal/") => roll < 15,
                _ => false,
            };
            if hit {
                injected.fetch_add(1, Ordering::Relaxed);
                Some(std::io::Error::other("audit transient fault"))
            } else {
                None
            }
        })));
    }

    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let bg = {
        let engine = engine.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            let mut rng = StdRng::seed_from_u64(seed ^ 0xb6);
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                match rng.random_range(0..4u32) {
                    0 => {
                        let _ = engine.flush().await;
                    }
                    1 => {
                        let _ = engine.checkpoint().await;
                    }
                    _ => {
                        let _ = engine.stats().await;
                    }
                }
                tokio::task::yield_now().await;
            }
        })
    };
    let mut handles = Vec::new();
    for task in 0..TASKS {
        handles.push(tokio::spawn(writer(
            engine.clone(),
            task,
            seed.wrapping_mul(1000) + task as u64,
            300,
        )));
    }
    let mut models = Vec::new();
    for h in handles {
        models.push(h.await.expect("writer task"));
    }
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    bg.await.unwrap();
    quiesce(&engine).await;
    faults_on.store(false, Ordering::SeqCst);
    eprintln!("seed {seed}: injected {} faults", injected.load(Ordering::Relaxed));

    // Merge the disjoint per-task models.
    let mut model = Model::new();
    for (task, m) in models.into_iter().enumerate() {
        for unit in task * PER_TASK..(task + 1) * PER_TASK {
            model.units[unit] = m.units[unit].clone();
        }
    }
    let final_view = read_all(&engine).await;
    model.check(0, &final_view, &format!("seed {seed}: final read"));
    // A second read (cache path) must agree with the first.
    assert_eq!(read_all(&engine).await, final_view);
    engine.flush().await.expect("FLUSH must heal once faults stop");
    engine.checkpoint().await.expect("checkpoint must heal once faults stop");
    assert_eq!(engine.state(), maki_core::engine::EngineState::Ready);
    let st = engine.stats().await;
    eprintln!(
        "seed {seed}: appended {} checkpoints {} cache hits {} misses {} cancelled {} errors {}",
        st.appended_sequence,
        st.checkpoints_total,
        st.cache_hits,
        st.cache_misses,
        st.requests_cancelled_total,
        st.requests_error_total
    );
    assert!(st.checkpoint_sequence <= st.durable_sequence);
    engine.stop_checkpoint_worker().await;
    drop(engine);

    // Restart (page cache kept).
    let engine = attach(&backing, verify_on_hit, cache).await;
    assert!(
        read_all(&engine).await == final_view,
        "seed {seed}: restart changed the flushed contents"
    );
    // Power loss after the FLUSH/checkpoint above.
    engine.stop_checkpoint_worker().await;
    drop(engine);
    backing.crash(&mut StdRng::seed_from_u64(seed));
    let engine = attach(&backing, verify_on_hit, cache).await;
    assert!(
        read_all(&engine).await == final_view,
        "seed {seed}: power loss changed the flushed contents"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn audit_faults_cache_no_verify() {
    for seed in 0..6 {
        run(seed, false, true).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn audit_faults_cache_verify() {
    for seed in 100..104 {
        run(seed, true, true).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn audit_faults_no_cache() {
    for seed in 200..204 {
        run(seed, false, false).await;
    }
}
