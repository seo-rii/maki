//! Audit (core write path): concurrent writers, trims and background
//! FLUSH/checkpoints, then the backing *dies* at a random operation (every
//! later backing call fails), followed by a power loss with torn writes.
//! Each unit belongs to one writer task, so its operations have a known
//! order; whole-unit writes carry a unique id, so recovered contents name the
//! write they came from. After recovery every unit must hold the content of
//! the last write acknowledged durable (FUA, or acknowledged before a FLUSH
//! that then succeeded) or of a later operation on that unit.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use maki_core::engine::{CheckpointPolicy, Engine, EngineLimits, EngineOptions};
use maki_core::volume::VolumeOptions;
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::{CrashableBacking, FakeCryptoProvider};

const UNIT: usize = 1024;
const UNITS: usize = 48;
const TASKS: usize = 4;
const PER_TASK: usize = UNITS / TASKS;

fn options() -> EngineOptions {
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
            volume_uuid: uuid::Uuid::from_u128(0xa0d1_9015),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(
                512,
                UNIT as u32,
                512,
                UNIT as u32 + 8,
                (UNITS * UNIT) as u64,
                8 * 1024,
            )
            .unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
}

fn content(id: u32) -> Vec<u8> {
    if id == 0 {
        return vec![0; UNIT];
    }
    let mut v = Vec::with_capacity(UNIT);
    while v.len() < UNIT {
        v.extend_from_slice(&id.to_le_bytes());
    }
    v
}

/// Per-unit operation history (ids in issue order; 0 = zeros) plus the
/// index of the last acknowledged entry and of the durability floor.
#[derive(Default, Clone)]
struct Hist {
    ids: Vec<u32>,
    acked: usize,
    durable: usize,
}

struct Shared {
    units: Mutex<Vec<Hist>>,
    next_id: AtomicU64,
}

impl Shared {
    fn begin(&self, units: std::ops::Range<usize>, zero: bool) -> (u32, Vec<usize>) {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst) as u32;
        let mut h = self.units.lock();
        let idx = units
            .map(|u| {
                h[u].ids.push(if zero { 0 } else { id });
                h[u].ids.len() - 1
            })
            .collect();
        (id, idx)
    }

    fn ack(&self, first: usize, idx: &[usize], fua: bool) {
        let mut h = self.units.lock();
        for (k, i) in idx.iter().enumerate() {
            let u = &mut h[first + k];
            u.acked = u.acked.max(*i);
            if fua {
                u.durable = u.durable.max(*i);
            }
        }
    }
}

async fn writer(engine: Engine, shared: Arc<Shared>, task: usize, seed: u64, ops: usize) {
    let mut rng = StdRng::seed_from_u64(seed);
    for _ in 0..ops {
        let base = task * PER_TASK;
        let first = base + rng.random_range(0..PER_TASK);
        let end = (first + rng.random_range(1..=8usize)).min(base + PER_TASK);
        let fua = rng.random_bool(0.25);
        let trim = rng.random_bool(0.25);
        let (id, idx) = shared.begin(first..end, trim);
        let offset = (first * UNIT) as u64;
        let len = (end - first) * UNIT;
        let result = if trim {
            engine.trim(offset, len, fua).await
        } else {
            let mut data = Vec::with_capacity(len);
            for _ in first..end {
                data.extend(content(id));
            }
            engine.write(offset, &data, fua).await
        };
        if result.is_ok() {
            shared.ack(first, &idx, fua);
        }
        if rng.random_bool(0.1) {
            tokio::task::yield_now().await;
        }
    }
}

async fn run(seed: u64) -> (u64, u64) {
    let backing = Arc::new(CrashableBacking::new().with_tearing(512));
    create(&backing);
    let engine = Engine::attach(
        backing.clone(),
        Arc::new(FakeCryptoProvider::new(UNIT as u32)),
        options(),
    )
    .await
    .unwrap();

    let mut rng = StdRng::seed_from_u64(seed);
    let death_at = rng.random_range(200..4000u64);
    let ops = Arc::new(AtomicU64::new(0));
    let dead = Arc::new(AtomicBool::new(false));
    {
        let ops = ops.clone();
        let dead = dead.clone();
        backing.set_fault_hook(Some(Arc::new(move |_op| {
            if dead.load(Ordering::SeqCst) || ops.fetch_add(1, Ordering::SeqCst) >= death_at {
                dead.store(true, Ordering::SeqCst);
                Some(std::io::Error::other("audit: backing died"))
            } else {
                None
            }
        })));
    }

    let shared = Arc::new(Shared {
        units: Mutex::new(
            (0..UNITS)
                .map(|_| Hist {
                    ids: vec![0],
                    acked: 0,
                    durable: 0,
                })
                .collect(),
        ),
        next_id: AtomicU64::new(1),
    });
    let stop = Arc::new(AtomicBool::new(false));
    let bg = {
        let engine = engine.clone();
        let shared = shared.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            let mut rng = StdRng::seed_from_u64(seed ^ 0x77);
            while !stop.load(Ordering::SeqCst) {
                if rng.random_bool(0.5) {
                    let snapshot: Vec<usize> =
                        shared.units.lock().iter().map(|h| h.acked).collect();
                    if engine.flush().await.is_ok() {
                        let mut h = shared.units.lock();
                        for (u, acked) in snapshot.into_iter().enumerate() {
                            h[u].durable = h[u].durable.max(acked);
                        }
                    }
                } else {
                    let _ = engine.checkpoint().await;
                }
                tokio::task::yield_now().await;
            }
        })
    };
    let mut handles = Vec::new();
    for task in 0..TASKS {
        handles.push(tokio::spawn(writer(
            engine.clone(),
            shared.clone(),
            task,
            seed * 100 + task as u64,
            250,
        )));
    }
    for h in handles {
        h.await.unwrap();
    }
    stop.store(true, Ordering::SeqCst);
    bg.await.unwrap();
    engine.stop_checkpoint_worker().await;
    // Let detached storage work finish before the power loss.
    for _ in 0..100_000 {
        let s = engine.stats().await;
        if s.admission_slots == 0 && s.active_requests == 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    drop(engine);
    let died = dead.load(Ordering::SeqCst);
    backing.set_fault_hook(None);
    backing.crash(&mut StdRng::seed_from_u64(seed ^ 0xc4a5));

    let engine = Engine::attach(
        backing.clone(),
        Arc::new(FakeCryptoProvider::new(UNIT as u32)),
        options(),
    )
    .await
    .unwrap_or_else(|e| panic!("seed {seed}: recovery after power loss failed: {e}"));
    let h = shared.units.lock().clone();
    let mut durable_units = 0;
    for unit in 0..UNITS {
        let got = engine
            .read((unit * UNIT) as u64, UNIT)
            .await
            .unwrap_or_else(|e| panic!("seed {seed}: unit {unit} unreadable: {e}"));
        let hist = &h[unit];
        let allowed: Vec<u32> = hist.ids[hist.durable..].to_vec();
        let ok = allowed.iter().any(|id| content(*id) == got);
        if hist.durable > 0 {
            durable_units += 1;
        }
        assert!(
            ok,
            "seed {seed} (died={died}, death_at={death_at}): unit {unit} holds {:?}, \
             allowed ids {:?} (durable index {}, history {:?})",
            &got[..4],
            allowed,
            hist.durable,
            hist.ids
        );
    }
    engine.stop_checkpoint_worker().await;
    (death_at, durable_units)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn audit_concurrent_death_then_power_loss() {
    for seed in 0..40 {
        let (death_at, durable) = run(seed).await;
        eprintln!("seed {seed}: death at op {death_at}, {durable} units with a durable floor");
    }
}
