//! Audit round 3 (PR #176 `fix/worker-sync-failure-20261117`): the worker now
//! checkpoints durable records after a failed journal sync for every trigger
//! (watermark, low space, interval, overlay watermark, refusal), and the size
//! trigger requires a sealed segment. Stress that with concurrent writers
//! (FUA and FLUSH), journal syncs that fail at random, a clock driven past the
//! interval, low free space and a small overlay bound, then lose power and
//! check that every acknowledged write survives (oracle per unit; each unit
//! has one writer).

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use maki_core::engine::{CheckpointPolicy, Engine, EngineLimits, EngineOptions};
use maki_core::volume::VolumeOptions;
use maki_crypto::Clock;
use maki_format::{geometry::Geometry, init, layout, superblock::Superblock};
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::{CrashableBacking, FakeCryptoProvider, ManualClock};

const UNIT: u64 = 1024;
const WRITERS: u64 = 3;
const UNITS_PER_WRITER: u64 = 6;
const INTERVAL: Duration = Duration::from_secs(30);

fn superblock(seed: u64) -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(0xa3_5715 + seed as u128),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, UNIT as u32, 512, UNIT as u32 + 8, 64 * UNIT, 16 * UNIT)
            .unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn options(clock: Arc<ManualClock>) -> EngineOptions {
    EngineOptions {
        volume: VolumeOptions {
            // Three records per segment: rolls are frequent.
            journal_segment_size: 4096,
        },
        checkpoint: CheckpointPolicy {
            // Below one segment: exercises the sealed-segment requirement.
            journal_high_watermark_bytes: 2048,
            journal_max_bytes: 1 << 20,
            max_pending_bytes: 1 << 20,
            emergency_reserve_bytes: 0,
            low_space_checkpoint_bytes: 1 << 20,
            interval: INTERVAL,
        },
        limits: EngineLimits {
            max_overlay_entries: 8,
            ..EngineLimits::default()
        },
        clock: Some(clock as Arc<dyn Clock>),
        ..Default::default()
    }
}

#[derive(Default, Clone)]
struct History {
    values: Vec<u8>,
    acked: Option<usize>,
}

fn is_segment(path: &str) -> bool {
    path.strip_prefix("journal/")
        .and_then(layout::parse_journal_segment)
        .is_some()
}

async fn run(seed: u64) -> Result<(), String> {
    let backing = Arc::new(CrashableBacking::new().with_tearing(64));
    init::create_volume(backing.as_ref(), superblock(seed)).unwrap();
    let failing = Arc::new(AtomicBool::new(false));
    let counter = Arc::new(AtomicU64::new(seed.wrapping_mul(0x9E37_79B9)));
    {
        let failing = failing.clone();
        let counter = counter.clone();
        backing.set_fault_hook(Some(Arc::new(move |op: &FaultOp<'_>| match op {
            FaultOp::SyncData { path } if is_segment(path) && failing.load(Ordering::SeqCst) => {
                let n = counter.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::SeqCst);
                (n.rotate_left(29) % 3 != 0).then(|| io::Error::other("injected sync failure"))
            }
            _ => None,
        })));
    }
    let clock = Arc::new(ManualClock::new());
    let engine = Arc::new(
        Engine::attach(
            backing.clone(),
            Arc::new(FakeCryptoProvider::new(UNIT as u32)),
            options(clock.clone()),
        )
        .await
        .map_err(|e| format!("seed {seed}: attach: {e}"))?,
    );
    let histories: Arc<Mutex<Vec<History>>> = Arc::new(Mutex::new(vec![
        History::default();
        (WRITERS * UNITS_PER_WRITER)
            as usize
    ]));
    let stop = Arc::new(AtomicBool::new(false));

    // Driver: toggles failing syncs, moves the clock past the interval, and
    // flips the reported free space around the low-space reserve.
    let driver = {
        let clock = clock.clone();
        let failing = failing.clone();
        let backing = backing.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            let mut rng = StdRng::seed_from_u64(seed ^ 0xd51e);
            while !stop.load(Ordering::SeqCst) {
                failing.store(rng.random_bool(0.6), Ordering::SeqCst);
                backing.set_free_bytes(Some(if rng.random_bool(0.3) { 1024 } else { 1 << 30 }));
                clock.advance(INTERVAL + Duration::from_secs(1));
                for _ in 0..rng.random_range(1..20) {
                    tokio::task::yield_now().await;
                }
            }
        })
    };

    let mut writers = Vec::new();
    for w in 0..WRITERS {
        let engine = engine.clone();
        let histories = histories.clone();
        writers.push(tokio::spawn(async move {
            let mut rng = StdRng::seed_from_u64(seed * 31 + w);
            let mut completed: Vec<(usize, usize)> = Vec::new();
            let mut value = (w as u8) * 80 + 1;
            for _ in 0..120 {
                let unit = (w * UNITS_PER_WRITER + rng.random_range(0..UNITS_PER_WRITER)) as usize;
                if rng.random_bool(0.75) {
                    value = value.wrapping_add(1).max(1);
                    let fua = rng.random_bool(0.3);
                    let index = {
                        let mut h = histories.lock().unwrap();
                        h[unit].values.push(value);
                        h[unit].values.len() - 1
                    };
                    let result = engine
                        .write(unit as u64 * UNIT, &vec![value; UNIT as usize], fua)
                        .await;
                    if result.is_ok() {
                        if fua {
                            let mut h = histories.lock().unwrap();
                            if h[unit].acked.is_none_or(|a| a < index) {
                                h[unit].acked = Some(index);
                            }
                        } else {
                            completed.push((unit, index));
                        }
                    }
                } else if engine.flush().await.is_ok() {
                    let mut h = histories.lock().unwrap();
                    for (unit, index) in completed.drain(..) {
                        if h[unit].acked.is_none_or(|a| a < index) {
                            h[unit].acked = Some(index);
                        }
                    }
                }
                tokio::task::yield_now().await;
            }
        }));
    }
    for writer in writers {
        writer.await.unwrap();
    }
    stop.store(true, Ordering::SeqCst);
    driver.await.unwrap();
    let stats = engine.stats().await;
    if std::env::var("AUDIT3_STATS").is_ok() {
        eprintln!(
            "seed {seed}: appended {} durable {} checkpoint {} checkpoints {} ckpt_failures {} \
             segments {} state {:?}",
            stats.appended_sequence,
            stats.durable_sequence,
            stats.checkpoint_sequence,
            stats.checkpoints_total,
            stats.checkpoint_failures_total,
            stats.journal_segments,
            stats.state
        );
    }
    engine.stop_checkpoint_worker().await;
    drop(engine);
    backing.set_fault_hook(None);
    if seed % 2 == 0 {
        backing.crash_all_lost();
    } else {
        backing.crash(&mut StdRng::seed_from_u64(seed ^ 0xc7a5));
    }

    let clock = Arc::new(ManualClock::new());
    let engine = Engine::attach(
        backing.clone(),
        Arc::new(FakeCryptoProvider::new(UNIT as u32)),
        options(clock),
    )
    .await
    .map_err(|e| format!("seed {seed}: re-attach after power loss: {e} (stats {stats:?})"))?;
    let histories = histories.lock().unwrap().clone();
    for (unit, history) in histories.iter().enumerate() {
        let data = engine
            .read(unit as u64 * UNIT, UNIT as usize)
            .await
            .map_err(|e| format!("seed {seed}: unit {unit}: read {e}"))?;
        let got = data[0];
        if data.iter().any(|b| *b != got) {
            return Err(format!("seed {seed}: unit {unit}: torn unit"));
        }
        let ok = match history.acked {
            None => got == 0 || history.values.contains(&got),
            Some(a) => history.values[a..].contains(&got),
        };
        if !ok {
            return Err(format!(
                "seed {seed}: unit {unit}: lost acknowledged write: got {got}, acked {:?}, \
                 history {:?} (stats before crash {stats:?})",
                history.acked.map(|a| history.values[a]),
                history.values
            ));
        }
    }
    engine.stop_checkpoint_worker().await;
    Ok(())
}

#[test]
fn worker_checkpoints_after_failed_syncs_never_lose_acknowledged_writes() {
    let seeds: u64 = std::env::var("AUDIT3_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    let mut failures = Vec::new();
    for seed in 0..seeds {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(3)
            .enable_all()
            .build()
            .unwrap();
        if let Err(e) = runtime.block_on(run(seed)) {
            failures.push(e);
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
