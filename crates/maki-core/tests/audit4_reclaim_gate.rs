//! Audit (round 2, durability-pr-review): adversarial probes of the inline
//! reclaim FIFO gate (#168).
//!
//! Mixed workload on a v3 (discard) volume with every bound at its validated
//! minimum (journal hard limit, overlay bytes, overlay entries) and the
//! emergency-reserve admission path enabled: maximal misaligned writes,
//! writes into a region shared by every writer (unit-lock contention while
//! queued), discards, WRITE_ZEROES, FLUSH, FUA, and callers cancelled at a
//! random await point. Nothing is injected, so no request may fail with
//! ENOSPC and nothing may hang. A real-time timeout is only a hang detector.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use maki_core::engine::{CheckpointPolicy, Engine, EngineLimits, EngineOptions};
use maki_core::volume::VolumeOptions;
use maki_format::{geometry::Geometry, init, journal, superblock::Superblock};
use maki_test_support::{CrashableBacking, FakeCryptoProvider};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const UNIT: u64 = 1024;
const MAX_CT: u64 = UNIT + 8;
const BLOCK: u64 = 512;
const MAX_IO: u64 = 8 * UNIT;
const UNITS_PER_WRITER: u64 = 12;
const SHARED_UNITS: u64 = 12;
const SEGMENT: u64 = 4096;
const WRITERS: u64 = 8;
const OPS: u64 = 80;

fn units_per_request() -> u64 {
    MAX_IO.div_ceil(UNIT) + 1
}

fn minimum_journal_bytes() -> u64 {
    journal::minimum_journal_limit(
        SEGMENT,
        journal::max_record_len(MAX_CT as u32),
        units_per_request(),
    )
    .unwrap()
}

async fn engine(seed: u64, discard: bool, entries: bool, reserve: bool) -> (Engine, Arc<CrashableBacking>) {
    let backing = Arc::new(CrashableBacking::new());
    backing.set_free_bytes(Some(1 << 40));
    let superblock = Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(0xA2D1_0000 + seed as u128),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(
            BLOCK as u32,
            UNIT as u32,
            512,
            MAX_CT as u32,
            (WRITERS * UNITS_PER_WRITER + SHARED_UNITS) * UNIT,
            8 * UNIT,
        )
        .unwrap(),
        format_version: 1,
        created_unix: 0,
    };
    if discard {
        init::create_volume_with_discard(backing.as_ref(), superblock).unwrap();
    } else {
        init::create_volume(backing.as_ref(), superblock).unwrap();
    }
    let journal_max = minimum_journal_bytes();
    let engine = Engine::attach(
        backing.process(),
        Arc::new(FakeCryptoProvider::new(UNIT as u32)),
        EngineOptions {
            volume: VolumeOptions {
                journal_segment_size: SEGMENT,
            },
            limits: EngineLimits {
                max_active_callbacks: 64,
                max_plaintext_bytes: 1 << 20,
                max_request_bytes: MAX_IO,
                max_overlay_bytes: 2 * units_per_request() * MAX_CT,
                max_overlay_entries: if entries { units_per_request() } else { 0 },
            },
            checkpoint: CheckpointPolicy {
                journal_high_watermark_bytes: journal_max / 2,
                journal_max_bytes: journal_max,
                max_pending_bytes: 4096,
                emergency_reserve_bytes: if reserve { 1 << 20 } else { 0 },
                low_space_checkpoint_bytes: if reserve { 1 << 20 } else { 0 },
                interval: Duration::from_secs(3600),
            },
            ..Default::default()
        },
    )
    .await
    .unwrap();
    (engine, backing)
}

#[derive(Default)]
struct Tally {
    ok: AtomicU64,
    cancelled: AtomicU64,
}

async fn run_workload(seed: u64, discard: bool, entries: bool, reserve: bool) -> Vec<String> {
    let (engine, _backing) = engine(seed, discard, entries, reserve).await;
    let tally = Arc::new(Tally::default());
    let mut handles = Vec::new();
    for writer in 0..WRITERS {
        let engine = engine.clone();
        let tally = tally.clone();
        handles.push(tokio::spawn(async move {
            let mut rng = StdRng::seed_from_u64(seed * 1000 + writer);
            let mut failures = Vec::new();
            let own = writer * UNITS_PER_WRITER * UNIT;
            let shared = WRITERS * UNITS_PER_WRITER * UNIT;
            for op in 0..OPS {
                let kind = rng.random_range(0..10u32);
                let fua = rng.random_bool(0.2);
                let cancel_after = if rng.random_bool(0.25) {
                    Some(rng.random_range(0..6u32))
                } else {
                    None
                };
                let e = engine.clone();
                let stamp = (writer * OPS + op) as u8 | 1;
                let label = format!("writer {writer} op {op} kind {kind} fua {fua}");
                let task = match kind {
                    0..=3 => tokio::spawn(async move {
                        e.write(own + BLOCK, &vec![stamp; MAX_IO as usize], fua).await
                    }),
                    4 | 5 => {
                        let off = shared + rng.random_range(0..4u64) * BLOCK;
                        tokio::spawn(async move {
                            e.write(off, &vec![stamp; MAX_IO as usize], fua).await
                        })
                    }
                    6 if discard => tokio::spawn(async move {
                        e.trim(own, (UNITS_PER_WRITER * UNIT) as usize, fua).await
                    }),
                    7 => tokio::spawn(async move {
                        e.write_zeroes(own + BLOCK, MAX_IO as usize, fua).await
                    }),
                    8 => tokio::spawn(async move { e.flush().await }),
                    _ => tokio::spawn(async move {
                        e.write(own, &vec![stamp; UNIT as usize], fua).await
                    }),
                };
                match cancel_after {
                    Some(polls) => {
                        for _ in 0..polls {
                            tokio::task::yield_now().await;
                        }
                        task.abort();
                        match task.await {
                            Ok(Ok(())) => {
                                tally.ok.fetch_add(1, Ordering::Relaxed);
                            }
                            Ok(Err(error)) => failures.push(format!("{label} (cancel): {error}")),
                            Err(_) => {
                                tally.cancelled.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    None => match task.await.unwrap() {
                        Ok(()) => {
                            tally.ok.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(error) => failures.push(format!("{label}: {error}")),
                    },
                }
            }
            failures
        }));
    }
    let mut failures = Vec::new();
    for handle in handles {
        failures.extend(handle.await.unwrap());
    }
    // Drain: every detached publish task must finish and leave the gate
    // free; a later write and FLUSH must not queue forever.
    engine
        .write(0, &vec![0x5a; MAX_IO as usize], true)
        .await
        .map_err(|e| failures.push(format!("final write: {e}")))
        .ok();
    engine
        .flush()
        .await
        .map_err(|e| failures.push(format!("final flush: {e}")))
        .ok();
    let stats = engine.stats().await;
    if stats.journal_total_bytes > minimum_journal_bytes() {
        failures.push(format!(
            "journal {} over its limit {}",
            stats.journal_total_bytes,
            minimum_journal_bytes()
        ));
    }
    if stats.overlay_bytes > 2 * units_per_request() * MAX_CT {
        failures.push(format!("overlay {} over its limit", stats.overlay_bytes));
    }
    eprintln!(
        "seed {seed} discard {discard} entries {entries} reserve {reserve}: ok {} cancelled {} \
         checkpoints {} active_requests {}",
        tally.ok.load(Ordering::Relaxed),
        tally.cancelled.load(Ordering::Relaxed),
        stats.checkpoints_total,
        stats.active_requests
    );
    engine.stop_checkpoint_worker().await;
    failures
}

async fn sweep(discard: bool, entries: bool, reserve: bool) {
    let mut failures = Vec::new();
    for seed in 0..3 {
        let outcome = tokio::time::timeout(
            Duration::from_secs(240),
            run_workload(seed, discard, entries, reserve),
        )
        .await;
        match outcome {
            Ok(f) => failures.extend(f),
            Err(_) => failures.push(format!("seed {seed}: workload hung (no progress in 240 s)")),
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures with nothing injected; first: {}",
        failures.len(),
        failures[0]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v3_mixed_workload_at_minimum_bounds_never_enospc_or_hangs() {
    sweep(true, true, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v2_mixed_workload_at_minimum_bounds_never_enospc_or_hangs() {
    sweep(false, false, false).await;
}

/// Transient writeback failures (random failed data syncs) while writers
/// reclaim inline: requests may fail with EIO, but once the faults stop no
/// gate, ticket or admission permit may be left behind: a FUA write and a
/// FLUSH must succeed and nothing may hang.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transient_sync_failures_during_inline_reclaim_leave_no_stuck_gate() {
    use maki_test_support::crash_backing::FaultOp;
    use std::sync::atomic::AtomicBool;
    for seed in 0..3u64 {
        let outcome = tokio::time::timeout(Duration::from_secs(240), async {
            let (engine, backing) = engine(100 + seed, true, true, false).await;
            let faulty = Arc::new(AtomicBool::new(true));
            let counter = Arc::new(AtomicU64::new(seed));
            let (f, c) = (faulty.clone(), counter.clone());
            backing.set_fault_hook(Some(Arc::new(move |op: &FaultOp<'_>| {
                let n = c.fetch_add(1, Ordering::SeqCst);
                (f.load(Ordering::SeqCst)
                    && matches!(op, FaultOp::SyncData { .. })
                    && n.wrapping_mul(0x9E37_79B9) % 61 == 0)
                    .then(|| std::io::Error::other("injected writeback EIO"))
            })));
            let mut handles = Vec::new();
            for writer in 0..WRITERS {
                let engine = engine.clone();
                handles.push(tokio::spawn(async move {
                    let own = writer * UNITS_PER_WRITER * UNIT;
                    let mut errors = 0u64;
                    for op in 0..40u64 {
                        let data = vec![(op as u8) | 1; MAX_IO as usize];
                        let r = match op % 4 {
                            0 => engine.trim(own, (UNITS_PER_WRITER * UNIT) as usize, false).await,
                            1 => engine.write(own + BLOCK, &data, true).await,
                            _ => engine.write(own + BLOCK, &data, false).await,
                        };
                        if let Err(e) = r {
                            errors += 1;
                            if errors <= 2 && writer == 0 {
                                eprintln!("  writer 0 op {op}: {e}");
                            }
                        }
                    }
                    errors
                }));
            }
            let mut errors = 0;
            for h in handles {
                errors += h.await.unwrap();
            }
            faulty.store(false, Ordering::SeqCst);
            let mut tail = Vec::new();
            for attempt in 0..3 {
                match engine.flush().await {
                    Ok(()) => break,
                    Err(e) => tail.push(format!("flush attempt {attempt}: {e}")),
                }
            }
            let write = engine.write(0, &vec![0x77; MAX_IO as usize], true).await;
            let flush = engine.flush().await;
            let state = engine.state();
            engine.stop_checkpoint_worker().await;
            (errors, tail, write.map_err(|e| e.to_string()), flush.map_err(|e| e.to_string()), state)
        })
        .await;
        let (errors, tail, write, flush, state) =
            outcome.unwrap_or_else(|_| panic!("seed {seed}: hung after transient sync failures"));
        eprintln!("seed {seed}: {errors} failed requests while faulty; {tail:?}; state {state:?}");
        assert!(write.is_ok(), "seed {seed}: FUA write after faults stopped: {write:?}");
        assert!(flush.is_ok(), "seed {seed}: FLUSH after faults stopped: {flush:?}");
    }
}
