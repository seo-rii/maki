//! Randomized engine stress with a per-unit oracle.
//!
//! Suite 1 drives concurrent writers and readers through a small-journal
//! engine (inline and background checkpoints firing constantly) while a
//! chaos task injects provider faults, then crashes the backing and
//! recovers. The oracle records every issued, acknowledged, and durable
//! stamp per unit; reads must never return a torn unit or a stamp that was
//! never issued, and recovery must return every FUA/flush-acknowledged
//! stamp or a newer acknowledged one.
//!
//! Suite 2 sweeps every persistence failpoint through the *engine* (admission,
//! background worker, degraded state) instead of the bare volume: while a
//! failpoint fails I/O, writes keep being issued; once it clears, the engine
//! must recover to `Ready`, acknowledge again, and after a crash return
//! exactly the acknowledged data.
//!
//! In debug builds every mutation also runs the overlay, journal, and volume
//! sanitizers (`check_invariants`), so accounting drift surfaces here first.

#![allow(clippy::await_holding_lock)]

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use uuid::Uuid;

use maki_backing::Backing;
use maki_core::engine::{CheckpointPolicy, Engine, EngineCacheConfig, EngineOptions, EngineState};
use maki_core::error::CoreError;
use maki_core::volume::VolumeOptions;
use maki_crypto::{CryptoError, CryptoProvider};
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_test_support::failpoints;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::CrashableBacking;

const BLOCK: u32 = 512;
const UNIT: u32 = 1024;
const UNITS: u64 = 256;
const DEVICE_SIZE: u64 = UNITS * UNIT as u64;
const SEGMENT: u64 = 16 << 10;
const WRITERS: u64 = 4;
const UNITS_PER_WRITER: u64 = UNITS / WRITERS;
const ROUNDS: u16 = 300;

fn geometry() -> Geometry {
    Geometry::compute(BLOCK, UNIT, 512, UNIT + 8, DEVICE_SIZE, 64 * UNIT as u64).unwrap()
}

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0x57E55),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: geometry(),
        format_version: 1,
        created_unix: 0,
    }
}

fn provider() -> Arc<FakeCryptoProvider> {
    Arc::new(FakeCryptoProvider::new(UNIT))
}

fn options() -> EngineOptions {
    EngineOptions {
        volume: VolumeOptions {
            journal_segment_size: SEGMENT,
        },
        cache: Some(EngineCacheConfig {
            max_bytes: 32 * UNIT as u64,
            ttl: Duration::from_secs(5),
        }),
        checkpoint: CheckpointPolicy {
            journal_high_watermark_bytes: 3 * SEGMENT,
            journal_max_bytes: 8 * SEGMENT,
            max_pending_bytes: SEGMENT / 2,
            emergency_reserve_bytes: 0,
            low_space_checkpoint_bytes: 0,
            interval: Duration::from_millis(15),
        },
        ..Default::default()
    }
}

fn fresh() -> Arc<CrashableBacking> {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    backing
}

async fn attach(backing: &Arc<CrashableBacking>, provider: Arc<dyn CryptoProvider>) -> Arc<Engine> {
    Arc::new(
        Engine::attach(backing.clone() as Arc<dyn Backing>, provider, options())
            .await
            .expect("attach"),
    )
}

/// 16-bit stamp: writer in the top nibble, round in the low 12 bits, so
/// rounds compare within one writer (each unit has exactly one writer).
fn stamp(writer: u64, round: u16) -> u16 {
    assert!(writer < 16 && round < 4096);
    ((writer as u16) << 12) | round
}

fn round_of(stamp: u16) -> u16 {
    stamp & 0x0FFF
}

fn stamp_bytes(stamp: u16, units: usize) -> Vec<u8> {
    stamp
        .to_be_bytes()
        .iter()
        .copied()
        .cycle()
        .take(UNIT as usize * units)
        .collect()
}

/// Decode a unit; panics on a torn unit (mixed stamps).
fn decode_stamp(unit: u64, buf: &[u8]) -> u16 {
    assert_eq!(buf.len(), UNIT as usize);
    let first = u16::from_be_bytes([buf[0], buf[1]]);
    for pair in buf.chunks(2) {
        let s = u16::from_be_bytes([pair[0], pair[1]]);
        assert_eq!(
            s, first,
            "unit {unit}: torn read ({first:#06x} vs {s:#06x})"
        );
    }
    first
}

fn tolerated(e: &CoreError) -> bool {
    match e {
        CoreError::Crypto(c) => c.is_retryable(),
        CoreError::Io(io) => {
            io.kind() == io::ErrorKind::StorageFull || io.raw_os_error() == Some(28)
        }
        _ => false,
    }
}

#[derive(Default, Debug)]
struct UnitTrack {
    issued: BTreeSet<u16>,
    acked: Option<u16>,
    durable: Option<u16>,
    /// Writes that returned an error: not applied unless the error came
    /// after journaling, so "maybe applied" for the oracle.
    unconfirmed: BTreeSet<u16>,
}

type Oracle = Arc<Mutex<BTreeMap<u64, UnitTrack>>>;

async fn read_unit(engine: &Engine, unit: u64) -> Result<u16, CoreError> {
    let buf = engine.read(unit * UNIT as u64, UNIT as usize).await?;
    Ok(decode_stamp(unit, &buf))
}

async fn check_stats(engine: &Engine) {
    let s = engine.stats().await;
    assert!(
        s.checkpoint_sequence <= s.durable_sequence && s.durable_sequence <= s.appended_sequence,
        "sequence order violated: {s:?}"
    );
    let policy = options().checkpoint;
    assert!(
        s.journal_total_bytes <= policy.journal_max_bytes + SEGMENT,
        "journal exceeded its cap: {s:?}"
    );
    assert!(
        s.overlay_bytes <= 2 * (policy.journal_max_bytes + 2 * SEGMENT),
        "overlay unbounded: {s:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_engine_stress_with_faults_checkpoints_and_crash() {
    let _serial = failpoints::test_lock();
    let backing = fresh();
    let fake = provider();
    let engine = attach(&backing, fake.clone()).await;
    let oracle: Oracle = Arc::new(Mutex::new(BTreeMap::new()));

    let stop = Arc::new(AtomicBool::new(false));
    let chaos = {
        let fake = fake.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            let mut rng = StdRng::seed_from_u64(0xC4A05);
            while !stop.load(Ordering::SeqCst) {
                if fake.queued_failures() < 2 {
                    let e = if rng.random_bool(0.7) {
                        CryptoError::Retryable("chaos".into())
                    } else {
                        CryptoError::Throttled("chaos".into())
                    };
                    fake.fail_next([e]);
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
    };

    let mut writers = Vec::new();
    for w in 0..WRITERS {
        let engine = engine.clone();
        let oracle = oracle.clone();
        writers.push(tokio::spawn(async move {
            let mut rng = StdRng::seed_from_u64(0xA0 + w);
            let base = w * UNITS_PER_WRITER;
            let (mut ok, mut failed, mut flushes) = (0u32, 0u32, 0u32);
            for round in 1..=ROUNDS {
                let n = if rng.random_bool(0.2) { 2 } else { 1 };
                let unit = base + rng.random_range(0..UNITS_PER_WRITER - n + 1);
                let s = stamp(w, round);
                {
                    let mut o = oracle.lock().unwrap();
                    for u in unit..unit + n {
                        o.entry(u).or_default().issued.insert(s);
                    }
                }
                let fua = rng.random_bool(0.3);
                let data = stamp_bytes(s, n as usize);
                match engine.write(unit * UNIT as u64, &data, fua).await {
                    Ok(()) => {
                        ok += 1;
                        let mut o = oracle.lock().unwrap();
                        for u in unit..unit + n {
                            let t = o.entry(u).or_default();
                            t.acked = Some(s);
                            if fua {
                                t.durable = Some(s);
                            }
                        }
                    }
                    Err(e) => {
                        assert!(tolerated(&e), "writer {w}: unexpected error {e}");
                        failed += 1;
                        let mut o = oracle.lock().unwrap();
                        for u in unit..unit + n {
                            o.entry(u).or_default().unconfirmed.insert(s);
                        }
                    }
                }
                if rng.random_bool(0.05) {
                    match engine.flush().await {
                        Ok(()) => {
                            flushes += 1;
                            let mut o = oracle.lock().unwrap();
                            for u in base..base + UNITS_PER_WRITER {
                                if let Some(t) = o.get_mut(&u) {
                                    if t.acked.is_some() {
                                        t.durable = t.acked;
                                    }
                                }
                            }
                        }
                        Err(e) => assert!(tolerated(&e), "writer {w}: flush error {e}"),
                    }
                }
                if rng.random_bool(0.1) {
                    tokio::task::yield_now().await;
                }
            }
            (ok, failed, flushes)
        }));
    }

    let writers_done = Arc::new(AtomicBool::new(false));
    let mut readers = Vec::new();
    for r in 0..2u64 {
        let engine = engine.clone();
        let oracle = oracle.clone();
        let done = writers_done.clone();
        readers.push(tokio::spawn(async move {
            let mut rng = StdRng::seed_from_u64(0xB0 + r);
            let mut reads = 0u32;
            while !done.load(Ordering::SeqCst) {
                let unit = rng.random_range(0..UNITS);
                match read_unit(&engine, unit).await {
                    Ok(0) => {}
                    Ok(s) => {
                        let o = oracle.lock().unwrap();
                        let issued = o.get(&unit).map(|t| t.issued.contains(&s)).unwrap_or(false);
                        assert!(
                            issued,
                            "unit {unit}: read stamp {s:#06x} that was never issued"
                        );
                    }
                    Err(e) => assert!(tolerated(&e), "reader {r}: unexpected error {e}"),
                }
                reads += 1;
                if reads.is_multiple_of(32) {
                    check_stats(&engine).await;
                    tokio::task::yield_now().await;
                }
            }
            reads
        }));
    }

    let mut totals = (0u32, 0u32, 0u32);
    for w in writers {
        let (ok, failed, flushes) = tokio::time::timeout(Duration::from_secs(120), w)
            .await
            .expect("writer hung")
            .unwrap();
        totals.0 += ok;
        totals.1 += failed;
        totals.2 += flushes;
    }
    writers_done.store(true, Ordering::SeqCst);
    for r in readers {
        tokio::time::timeout(Duration::from_secs(30), r)
            .await
            .expect("reader hung")
            .unwrap();
    }
    stop.store(true, Ordering::SeqCst);
    chaos.await.unwrap();
    assert!(
        totals.0 > 0 && totals.1 > 0,
        "faults never fired: {totals:?}"
    );

    // Live view equals the oracle once writers are quiescent.
    let mut rng = StdRng::seed_from_u64(0xF1A5);
    for unit in 0..UNITS {
        let s = loop {
            match read_unit(&engine, unit).await {
                Ok(s) => break s,
                Err(e) => assert!(tolerated(&e), "{e}"),
            }
        };
        let o = oracle.lock().unwrap();
        match o.get(&unit) {
            None => assert_eq!(s, 0, "unit {unit}: never written but reads {s:#06x}"),
            Some(t) => {
                let expected = t.acked.unwrap_or(0);
                assert!(
                    s == expected || t.unconfirmed.contains(&s),
                    "unit {unit}: live {s:#06x}, acked {expected:#06x}, maybe {:?}",
                    t.unconfirmed
                );
            }
        }
    }
    // The worker recovered from every transient fault.
    let mut ready = false;
    for _ in 0..200 {
        if engine.state() == EngineState::Ready {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let stats = engine.stats().await;
    assert!(ready, "engine stuck degraded: {stats:?}");
    assert!(
        stats.checkpoints_total > 0,
        "checkpoints never ran: {stats:?}"
    );
    check_stats(&engine).await;

    // Crash (independent survival per pending op) and recover.
    drop(engine);
    tokio::time::sleep(Duration::from_millis(100)).await;
    backing.crash(&mut rng);
    let engine = attach(&backing, provider()).await;
    let o = oracle.lock().unwrap();
    for unit in 0..UNITS {
        let s = read_unit(&engine, unit).await.unwrap();
        let Some(t) = o.get(&unit) else {
            assert_eq!(s, 0, "unit {unit}: never written but recovered {s:#06x}");
            continue;
        };
        if s != 0 {
            assert!(
                t.acked == Some(s) || t.issued.contains(&s),
                "unit {unit}: recovered {s:#06x} never issued"
            );
        }
        if let Some(d) = t.durable {
            assert!(
                s != 0 && round_of(s) >= round_of(d),
                "unit {unit}: durable {d:#06x} lost, recovered {s:#06x}"
            );
        }
    }
}

const FAILPOINTS: &[&str] = &[
    "journal.append.write",
    "journal.sync",
    "journal.segment.create",
    "journal.segment.header_sync",
    "journal.segment.dirsync",
    "checkpoint.slot_write",
    "checkpoint.shard_sync",
    "checkpoint.alloc_store",
    "checkpoint.alloc_dirsync",
    "checkpoint.state_store",
    "checkpoint.segment_delete",
    "checkpoint.dirsync",
    "store.shard_create",
    "store.shard_dirsync",
    "store.catalog_store",
];

#[test]
fn engine_failpoint_sweep_preserves_acknowledged_data() {
    let _serial = failpoints::test_lock();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for (i, name) in FAILPOINTS.iter().enumerate() {
        rt.block_on(sweep_one(name, i as u64));
    }
}

/// One random single-unit write; `true` when acknowledged. Errors must be
/// I/O or durability failures (the failpoint's), never anything else.
#[allow(clippy::too_many_arguments)]
async fn sweep_write(
    name: &str,
    engine: &Engine,
    rng: &mut StdRng,
    round: u16,
    acked: &mut BTreeMap<u64, u16>,
    durable: &mut BTreeMap<u64, u16>,
    maybe: &mut BTreeMap<u64, BTreeSet<u16>>,
) -> bool {
    let unit = rng.random_range(0..UNITS);
    let fua = rng.random_bool(0.4);
    let s = stamp(1, round);
    match engine
        .write(unit * UNIT as u64, &stamp_bytes(s, 1), fua)
        .await
    {
        Ok(()) => {
            acked.insert(unit, s);
            if fua {
                durable.insert(unit, s);
            }
            true
        }
        Err(e) => {
            assert!(
                matches!(e, CoreError::Io(_) | CoreError::Durability(_)),
                "{name}: unexpected error class {e}"
            );
            maybe.entry(unit).or_default().insert(s);
            false
        }
    }
}

async fn sweep_one(name: &str, seed: u64) {
    let backing = fresh();
    let engine = attach(&backing, provider()).await;
    let mut rng = StdRng::seed_from_u64(0x5EED + seed);
    let mut acked: BTreeMap<u64, u16> = BTreeMap::new();
    let mut durable: BTreeMap<u64, u16> = BTreeMap::new();
    let mut maybe: BTreeMap<u64, BTreeSet<u16>> = BTreeMap::new();
    let mut round: u16 = 0;

    // Healthy prologue.
    for _ in 0..40 {
        round += 1;
        let ok = sweep_write(
            name,
            &engine,
            &mut rng,
            round,
            &mut acked,
            &mut durable,
            &mut maybe,
        )
        .await;
        assert!(ok, "{name}: healthy write failed");
    }

    // Fault window: the failpoint fails its next three hits.
    let mut failures = 0u32;
    {
        let _fp = failpoints::fail_n_times(name, 3, io::ErrorKind::Other, "sweep");
        for _ in 0..60 {
            round += 1;
            if !sweep_write(
                name,
                &engine,
                &mut rng,
                round,
                &mut acked,
                &mut durable,
                &mut maybe,
            )
            .await
            {
                failures += 1;
            }
            if round.is_multiple_of(10) {
                match engine.flush().await {
                    Ok(()) => {
                        for (u, s) in &acked {
                            durable.insert(*u, *s);
                        }
                    }
                    Err(e) => {
                        failures += 1;
                        assert!(matches!(e, CoreError::Io(_)), "{name}: flush error {e}");
                    }
                }
            }
            if round.is_multiple_of(25) {
                let _ = engine.checkpoint().await;
            }
        }
    }

    // Recovery: everything must work again and the engine must be Ready.
    engine
        .flush()
        .await
        .unwrap_or_else(|e| panic!("{name}: flush after fault window failed: {e}"));
    for (u, s) in &acked {
        durable.insert(*u, *s);
    }
    for _ in 0..20 {
        round += 1;
        let ok = sweep_write(
            name,
            &engine,
            &mut rng,
            round,
            &mut acked,
            &mut durable,
            &mut maybe,
        )
        .await;
        assert!(ok, "{name}: write after fault window failed");
    }
    engine
        .flush()
        .await
        .unwrap_or_else(|e| panic!("{name}: final flush failed: {e}"));
    for (u, s) in &acked {
        durable.insert(*u, *s);
    }
    engine
        .checkpoint()
        .await
        .unwrap_or_else(|e| panic!("{name}: checkpoint after fault window failed: {e}"));
    assert_eq!(
        engine.state(),
        EngineState::Ready,
        "{name}: not ready after recovery"
    );
    let stats = engine.stats().await;
    assert!(
        stats.checkpoint_sequence <= stats.durable_sequence,
        "{name}: {stats:?}"
    );
    let _ = failures;

    // Live view.
    for unit in 0..UNITS {
        let s = read_unit(&engine, unit).await.unwrap();
        let expected = acked.get(&unit).copied().unwrap_or(0);
        let tolerated = maybe.get(&unit).map(|m| m.contains(&s)).unwrap_or(false);
        assert!(
            s == expected || tolerated,
            "{name}: unit {unit} live {s:#06x} expected {expected:#06x}"
        );
    }

    // Crash + recover: every durable stamp (or a newer acknowledged one).
    drop(engine);
    tokio::time::sleep(Duration::from_millis(60)).await;
    backing.crash(&mut rng);
    let engine = attach(&backing, provider()).await;
    for unit in 0..UNITS {
        let s = read_unit(&engine, unit).await.unwrap();
        let tolerated = maybe.get(&unit).map(|m| m.contains(&s)).unwrap_or(false);
        match durable.get(&unit) {
            Some(d) => assert!(
                s == *d || (tolerated && round_of(s) > round_of(*d)),
                "{name}: unit {unit} durable {d:#06x} lost, recovered {s:#06x}"
            ),
            None => assert!(
                s == 0 || tolerated,
                "{name}: unit {unit} recovered {s:#06x} that was never acknowledged"
            ),
        }
    }
    assert_eq!(
        engine.state(),
        EngineState::Ready,
        "{name}: degraded after recovery"
    );
}
