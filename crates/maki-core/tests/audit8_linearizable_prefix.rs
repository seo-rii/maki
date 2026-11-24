//! Audit round 4 (secrets-memory-cache): the round-3 linearizability
//! harness (`audit3_linearizable.rs` on the audit branch), re-run with the
//! `RandomPrefixProvider` between the engine and the provider, so decrypted
//! units carry spare capacity and exercise the padded read-unit cache policy
//! of #296 (compaction, duplicate-on-insert), the capacity charge of #286 and
//! the header-reuse read path of #249 under overlapping concurrent requests,
//! cache resizes, TTL expiry and cancellation. Oracle unchanged: no stale or
//! never-written image may be read.
//!
//! Audit round 3 (engine-concurrency): are concurrent, *overlapping* block
//! requests linearizable?
//!
//! Earlier sweeps gave every unit to one writer. Here several tasks issue
//! overlapping sub-unit (RMW) writes, writes spanning unit boundaries,
//! WRITE_ZEROES, TRIM, reads, FLUSH, checkpoints and cache resizes against
//! a tiny device (6 units of 4 sectors), on a multi-threaded runtime, with
//! a provider that yields at random points (widening the RMW, encrypt and
//! decrypt-then-cache windows) and with random cancellation of callers.
//!
//! Oracle: every sector written by a write carries `(write id, sector)`, so
//! a read names the write each sector came from. A round is accepted only
//! if there is ONE serial order of its operations that respects real time
//! (an operation that completed before another started precedes it) in
//! which every read returns exactly the state at its linearization point
//! and the device afterwards equals the state after all of them.
//! Successful operations are applied whole; cancelled ones whole or not at
//! all (their publication is detached, so they may land at any time up to
//! quiescence). Bytes that match no write ("never-written image") fail.
//! After each round the engine must be quiescent: no admission slot or
//! plaintext byte still charged, no active callback (no leak, no deadlock).

use std::collections::HashSet;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use maki_core::engine::{CheckpointPolicy, Engine, EngineCacheConfig, EngineLimits, EngineOptions};
use maki_core::volume::VolumeOptions;
use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit,
};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::{CrashableBacking, FakeCryptoProvider, ManualClock};

const BLOCK: usize = 512;
const UNIT: usize = 2048;
const SPU: usize = UNIT / BLOCK;
const UNITS: usize = 6;
const SECTORS: usize = UNITS * SPU;
const MAX_REQ: usize = 8192;
const PREFIX: usize = 32;
const WIRE: usize = UNIT + PREFIX;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Val {
    Zero,
    Tag(u32),
}

type Image = [Val; SECTORS];

fn sector_bytes(v: Val, s: usize) -> Vec<u8> {
    match v {
        Val::Zero => vec![0; BLOCK],
        Val::Tag(id) => {
            let mut b = vec![0u8; BLOCK];
            for (i, chunk) in b.chunks_mut(8).enumerate() {
                chunk[..4].copy_from_slice(&id.to_le_bytes());
                chunk[4..].copy_from_slice(&((s as u32) | ((i as u32) << 16)).to_le_bytes());
            }
            b
        }
    }
}

fn decode(bytes: &[u8], first: usize) -> Result<Vec<Val>, String> {
    bytes
        .chunks(BLOCK)
        .enumerate()
        .map(|(k, c)| {
            let s = first + k;
            if c.iter().all(|&b| b == 0) {
                return Ok(Val::Zero);
            }
            let id = u32::from_le_bytes(c[..4].try_into().unwrap());
            if id != 0 && c == sector_bytes(Val::Tag(id), s).as_slice() {
                Ok(Val::Tag(id))
            } else {
                Err(format!(
                    "sector {s}: bytes match no write (first word {id:#x}) — never-written image"
                ))
            }
        })
        .collect()
}

// ---------------------------------------------------------------- provider

/// Delegates to the fake provider, yielding a pseudo-random number of times
/// before and after each call.
struct Jitter {
    inner: Arc<FakeCryptoProvider>,
    state: AtomicU64,
    max_yields: u64,
}

impl Jitter {
    fn next(&self) -> u64 {
        let mut x = self
            .state
            .fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed)
            .wrapping_add(0x9e37_79b9_7f4a_7c15);
        x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        x ^ (x >> 31)
    }

    async fn pause(&self) {
        if self.max_yields == 0 {
            return;
        }
        let n = self.next() % self.max_yields;
        for _ in 0..n {
            tokio::task::yield_now().await;
        }
        if self.next() % 8 == 0 {
            std::thread::yield_now();
        }
    }
}

#[async_trait]
impl CryptoProvider for Jitter {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.inner.capabilities().await
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.pause().await;
        let out = self.inner.encrypt_batch(context, items).await;
        self.pause().await;
        out
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.pause().await;
        let out = self.inner.decrypt_batch(context, items).await;
        self.pause().await;
        out
    }
}

// ---------------------------------------------------------------- history

#[derive(Clone, Debug)]
enum Kind {
    Write { first: usize, len: usize, fua: bool },
    Zero { first: usize, len: usize, fua: bool },
    Trim { first: usize, len: usize, fua: bool },
    Read { first: usize, len: usize },
    Flush,
    Checkpoint,
    Resize(u64),
}

#[derive(Clone, Debug)]
enum Outcome {
    Ok,
    Err(String),
    Cancelled,
}

#[derive(Clone, Debug)]
struct Rec {
    id: u32,
    task: usize,
    kind: Kind,
    start: u64,
    end: u64,
    outcome: Outcome,
    read: Option<Vec<Val>>,
}

/// Per-unit effects (ascending units) of a write-like operation.
fn effects(id: u32, kind: &Kind) -> Option<Vec<Vec<(usize, Val)>>> {
    let (sectors, val): (Vec<usize>, Val) = match *kind {
        Kind::Write { first, len, .. } => ((first..first + len).collect(), Val::Tag(id)),
        Kind::Zero { first, len, .. } => ((first..first + len).collect(), Val::Zero),
        Kind::Trim { first, len, .. } => {
            let mut s = Vec::new();
            for u in 0..UNITS {
                if u * SPU >= first && (u + 1) * SPU <= first + len {
                    s.extend(u * SPU..(u + 1) * SPU);
                }
            }
            (s, Val::Zero)
        }
        _ => return None,
    };
    let mut units: Vec<Vec<(usize, Val)>> = Vec::new();
    let mut last = usize::MAX;
    for s in sectors {
        if s / SPU != last {
            units.push(Vec::new());
            last = s / SPU;
        }
        units.last_mut().unwrap().push((s, val));
    }
    Some(units)
}

enum E {
    Op {
        units: Vec<Vec<(usize, Val)>>,
        mandatory: bool,
    },
    Read {
        first: usize,
        img: Vec<Val>,
    },
}

struct Elem {
    start: u64,
    end: u64,
    e: E,
}

struct Search<'a> {
    elems: &'a [Elem],
    preds: Vec<u32>,
    final_img: &'a Image,
    memo: HashSet<(u32, Image)>,
}

impl Search<'_> {
    fn dfs(&mut self, done: u32, img: Image) -> bool {
        let n = self.elems.len();
        if done == (1u32 << n) - 1 {
            return img == *self.final_img;
        }
        if !self.memo.insert((done, img)) {
            return false;
        }
        for i in 0..n {
            if done & (1 << i) != 0 || self.preds[i] & !done != 0 {
                continue;
            }
            match &self.elems[i].e {
                E::Read { first, img: r } => {
                    if img[*first..*first + r.len()] == r[..] && self.dfs(done | 1 << i, img) {
                        return true;
                    }
                }
                E::Op { units, mandatory } => {
                    let choices: &[bool] = if *mandatory { &[true] } else { &[true, false] };
                    for &apply in choices {
                        let mut s = img;
                        if apply {
                            for unit in units {
                                for &(sec, v) in unit {
                                    s[sec] = v;
                                }
                            }
                        }
                        if self.dfs(done | 1 << i, s) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
}

/// `Ok` when one real-time-respecting serial order explains every read and
/// the final image.
fn linearizable(base: &Image, recs: &[Rec], final_img: &Image) -> Result<(), String> {
    let mut elems = Vec::new();
    for r in recs {
        let mandatory = match &r.outcome {
            Outcome::Ok => true,
            Outcome::Cancelled => false,
            Outcome::Err(e) => return Err(format!("op {} {:?} failed: {e}", r.id, r.kind)),
        };
        if let Some(units) = effects(r.id, &r.kind) {
            if units.is_empty() {
                continue;
            }
            elems.push(Elem {
                start: r.start,
                end: r.end,
                e: E::Op { units, mandatory },
            });
        } else if let (Kind::Read { first, .. }, Some(img)) = (&r.kind, &r.read) {
            elems.push(Elem {
                start: r.start,
                end: r.end,
                e: E::Read {
                    first: *first,
                    img: img.clone(),
                },
            });
        }
    }
    assert!(elems.len() < 31);
    let preds = elems
        .iter()
        .map(|a| {
            elems
                .iter()
                .enumerate()
                .filter(|(_, b)| b.end < a.start)
                .fold(0u32, |m, (j, _)| m | 1 << j)
        })
        .collect();
    let mut search = Search {
        elems: &elems,
        preds,
        final_img,
        memo: HashSet::new(),
    };
    if search.dfs(0, *base) {
        Ok(())
    } else {
        Err("no serial order explains the reads and the final image".into())
    }
}

// ---------------------------------------------------------------- engine

#[derive(Clone, Copy, Debug)]
struct Config {
    cache: u8, // 0 off, 1 read, 2 read + verify_on_hit
    cache_bytes: u64,
    callbacks: u32,
    plaintext: u64,
    batch_items: u32,
    watermark: u64,
    journal_max: u64,
    pending: u64,
    overlay_bytes: u64,
    overlay_entries: u64,
    max_yields: u64,
    cancel_pct: u32,
    /// Drive the engine clock by hand during rounds: worker interval
    /// checkpoints and cache TTL expiry race the workload.
    manual_clock: bool,
    /// v3 discard volume (TRIM supported); otherwise a plain volume where
    /// TRIM requests are issued as WRITE_ZEROES.
    discard: bool,
    /// Put the cross-request coalescing `BatchScheduler` (the remote
    /// provider path) between the engine and the provider.
    scheduler: bool,
}

impl Config {
    fn random(rng: &mut StdRng) -> Self {
        Self {
            cache: rng.random_range(0..3),
            cache_bytes: [UNIT as u64, WIRE as u64, 3 * UNIT as u64 + 40, 1 << 20]
                [rng.random_range(0..4)],
            callbacks: [2, 3, 64][rng.random_range(0..3)],
            plaintext: [10_240, 24_576, 1 << 20][rng.random_range(0..3)],
            batch_items: [1, 2, 64][rng.random_range(0..3)],
            watermark: [12 << 10, 24 << 10, 1 << 30][rng.random_range(0..3)],
            journal_max: [48 << 10, 1 << 31][rng.random_range(0..2)],
            pending: [4096, 1 << 20][rng.random_range(0..2)],
            overlay_bytes: [0, 40_000][rng.random_range(0..2)],
            overlay_entries: [0, 8][rng.random_range(0..2)],
            max_yields: [0, 4, 24][rng.random_range(0..3)],
            cancel_pct: [0, 10, 25][rng.random_range(0..3)],
            manual_clock: rng.random_bool(0.5),
            discard: rng.random_bool(0.75),
            scheduler: rng.random_bool(0.4),
        }
    }
}

async fn provider(cfg: &Config, seed: u64) -> Arc<dyn CryptoProvider> {
    let fake =
        Arc::new(FakeCryptoProvider::new(WIRE as u32).with_max_batch(cfg.batch_items, 1 << 20));
    let jitter = Arc::new(Jitter {
        inner: fake,
        state: AtomicU64::new(seed),
        max_yields: cfg.max_yields,
    });
    let jitter: Arc<dyn CryptoProvider> = Arc::new(
        maki_crypto::RandomPrefixProvider::new(
            jitter,
            UNIT as u32,
            PREFIX as u32,
            "audit4-prefix-v1".into(),
        )
        .await
        .unwrap(),
    );
    if !cfg.scheduler {
        return jitter;
    }
    let max_items = cfg.batch_items as usize;
    let scheduler = Arc::new(maki_crypto::scheduler::BatchScheduler::with_unit_size(
        jitter,
        maki_crypto::scheduler::SchedulerConfig {
            target_items: max_items.min(4),
            target_bytes: 1 << 20,
            max_items,
            max_bytes: 1 << 20,
            max_wait: Duration::from_micros(200),
            max_pending_items: 4096,
            max_pending_plaintext_bytes: 1 << 20,
            max_pending_ciphertext_bytes: 1 << 20,
            max_inflight_batches: 4,
        },
        Arc::new(maki_crypto::SystemClock::new()),
        UNIT as u32,
    ));
    SCHEDULERS.lock().push(scheduler.stats());
    scheduler
}

/// Stats of every scheduler built (coverage: were requests coalesced?).
static SCHEDULERS: parking_lot::Mutex<Vec<Arc<maki_crypto::scheduler::SchedulerStats>>> =
    parking_lot::Mutex::new(Vec::new());

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(0xa3_11_0e_a7),
        provider_type: "fake".into(),
        crypto_compatibility_id: "audit4-prefix-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(
            BLOCK as u32,
            UNIT as u32,
            512,
            WIRE as u32 + 8,
            (UNITS * UNIT) as u64,
            4 * UNIT as u64,
        )
        .unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn options(cfg: &Config, clock: Option<Arc<ManualClock>>) -> EngineOptions {
    EngineOptions {
        volume: VolumeOptions {
            journal_segment_size: 8192,
        },
        limits: EngineLimits {
            max_active_callbacks: cfg.callbacks,
            max_plaintext_bytes: cfg.plaintext,
            max_request_bytes: MAX_REQ as u64,
            max_overlay_bytes: cfg.overlay_bytes,
            max_overlay_entries: cfg.overlay_entries,
        },
        cache: (cfg.cache > 0).then(|| EngineCacheConfig {
            max_bytes: cfg.cache_bytes,
            ttl: Duration::from_secs(if clock.is_some() { 3 } else { 3600 }),
            verify_on_hit: cfg.cache == 2,
        }),
        identity: None,
        checkpoint: CheckpointPolicy {
            journal_high_watermark_bytes: cfg.watermark,
            journal_max_bytes: cfg.journal_max,
            max_pending_bytes: cfg.pending,
            emergency_reserve_bytes: 0,
            low_space_checkpoint_bytes: 0,
            interval: Duration::from_secs(if clock.is_some() { 5 } else { 3600 }),
        },
        clock: clock.map(|c| c as Arc<dyn maki_crypto::Clock>),
    }
}

async fn yields(n: usize) {
    for _ in 0..n {
        tokio::task::yield_now().await;
    }
}

/// Run `fut`, dropping it after `polls` yields of a racing timer if set.
async fn maybe_cancel<T>(fut: impl Future<Output = T>, polls: Option<usize>) -> Option<T> {
    match polls {
        None => Some(fut.await),
        Some(n) => {
            tokio::pin!(fut);
            tokio::select! {
                biased;
                r = &mut fut => Some(r),
                _ = yields(n) => None,
            }
        }
    }
}

fn random_range(rng: &mut StdRng) -> (usize, usize) {
    let first = rng.random_range(0..SECTORS);
    let max = (SECTORS - first).min(MAX_REQ / BLOCK);
    // Favour short, overlapping requests; sometimes whole units.
    if rng.random_bool(0.3) {
        let u = first / SPU;
        return (
            u * SPU,
            (rng.random_range(1..=2) * SPU).min(SECTORS - u * SPU),
        );
    }
    let cap = if rng.random_bool(0.7) { 3 } else { max };
    (first, rng.random_range(1..=max.min(cap)))
}

fn random_kind(rng: &mut StdRng, cache: bool) -> Kind {
    let p = rng.random_range(0..100);
    let (first, len) = random_range(rng);
    let fua = rng.random_bool(0.25);
    match p {
        0..=37 => Kind::Write { first, len, fua },
        38..=45 => Kind::Zero { first, len, fua },
        46..=58 => Kind::Trim { first, len, fua },
        59..=86 => Kind::Read { first, len },
        87..=92 => Kind::Flush,
        93..=95 => Kind::Checkpoint,
        _ if cache => Kind::Resize(
            [0, UNIT as u64, WIRE as u64, 3 * UNIT as u64 + 40, 1 << 20][rng.random_range(0..5)],
        ),
        _ => Kind::Flush,
    }
}

async fn execute(
    engine: &Engine,
    id: u32,
    kind: &Kind,
    cancel: Option<usize>,
) -> (Outcome, Option<Vec<Val>>) {
    let off = |s: usize| (s * BLOCK) as u64;
    let res: Option<Result<Option<Vec<Val>>, String>> = match *kind {
        Kind::Write { first, len, fua } => {
            let mut data = Vec::with_capacity(len * BLOCK);
            for s in first..first + len {
                data.extend(sector_bytes(Val::Tag(id), s));
            }
            maybe_cancel(engine.write(off(first), &data, fua), cancel)
                .await
                .map(|r| r.map(|_| None).map_err(|e| e.to_string()))
        }
        Kind::Zero { first, len, fua } => {
            maybe_cancel(engine.write_zeroes(off(first), len * BLOCK, fua), cancel)
                .await
                .map(|r| r.map(|_| None).map_err(|e| e.to_string()))
        }
        Kind::Trim { first, len, fua } => {
            maybe_cancel(engine.trim(off(first), len * BLOCK, fua), cancel)
                .await
                .map(|r| r.map(|_| None).map_err(|e| e.to_string()))
        }
        Kind::Read { first, len } => maybe_cancel(engine.read(off(first), len * BLOCK), cancel)
            .await
            .map(|r| match r {
                Ok(bytes) => decode(&bytes, first).map(Some),
                Err(e) => Err(e.to_string()),
            }),
        Kind::Flush => Some(
            engine
                .flush()
                .await
                .map(|_| None)
                .map_err(|e| e.to_string()),
        ),
        Kind::Checkpoint => Some(
            engine
                .checkpoint()
                .await
                .map(|_| None)
                .map_err(|e| e.to_string()),
        ),
        Kind::Resize(bytes) => {
            engine.resize_cache(bytes);
            Some(Ok(None))
        }
    };
    match res {
        None => (Outcome::Cancelled, None),
        Some(Ok(read)) => (Outcome::Ok, read),
        Some(Err(e)) => (Outcome::Err(e), None),
    }
}

/// Wait until no callback, admission slot or plaintext byte is held.
async fn quiesce(engine: &Engine) -> Result<(), String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let s = engine.stats().await;
        if s.admission_slots == 0 && s.active_requests == 0 && s.plaintext_bytes_in_flight == 0 {
            return Ok(());
        }
        if std::time::Instant::now() > deadline {
            return Err(format!(
                "engine not quiescent 30 s after the round: {} admission slots, {} active \
                 requests, {} plaintext bytes still charged",
                s.admission_slots, s.active_requests, s.plaintext_bytes_in_flight
            ));
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

async fn run_round(
    engine: &Engine,
    rng: &mut StdRng,
    next_id: &mut u32,
    ticks: &Arc<AtomicU64>,
    cfg: &Config,
    clock: Option<&Arc<ManualClock>>,
) -> Vec<Rec> {
    let tasks = rng.random_range(2..=4);
    let mut handles = Vec::new();
    let ticker = clock.map(|clock| {
        let clock = clock.clone();
        let steps: Vec<(usize, u64)> = (0..rng.random_range(1..=4))
            .map(|_| (rng.random_range(0..30usize), rng.random_range(0..2500u64)))
            .collect();
        tokio::spawn(async move {
            for (delay, ms) in steps {
                yields(delay).await;
                clock.advance(Duration::from_millis(ms));
            }
        })
    });
    let mut budget = 9usize;
    for task in 0..tasks {
        let n = rng.random_range(1..=3).min(budget).max(1);
        budget = budget.saturating_sub(n);
        let mut plan = Vec::new();
        for _ in 0..n {
            let kind = match random_kind(rng, cfg.cache > 0) {
                Kind::Trim { first, len, fua } if !cfg.discard => Kind::Zero { first, len, fua },
                kind => kind,
            };
            let cancel = (matches!(
                kind,
                Kind::Write { .. } | Kind::Zero { .. } | Kind::Trim { .. } | Kind::Read { .. }
            ) && rng.random_range(0..100) < cfg.cancel_pct)
                .then(|| rng.random_range(0..40));
            plan.push((*next_id, kind, cancel, rng.random_range(0..20usize)));
            *next_id += 1;
        }
        let engine = engine.clone();
        let ticks = ticks.clone();
        handles.push(tokio::spawn(async move {
            let mut recs = Vec::new();
            for (id, kind, cancel, delay) in plan {
                yields(delay).await;
                let start = ticks.fetch_add(1, Ordering::SeqCst);
                let (outcome, read) = execute(&engine, id, &kind, cancel).await;
                let end = match outcome {
                    Outcome::Cancelled => u64::MAX,
                    _ => ticks.fetch_add(1, Ordering::SeqCst),
                };
                recs.push(Rec {
                    id,
                    task,
                    kind,
                    start,
                    end,
                    outcome,
                    read,
                });
            }
            recs
        }));
    }
    let mut recs = Vec::new();
    for h in handles {
        recs.extend(h.await.expect("task panicked"));
    }
    if let Some(t) = ticker {
        t.await.expect("ticker panicked");
    }
    recs
}

async fn read_all(engine: &Engine) -> Result<Image, String> {
    // Quiescent: reading in request-sized pieces is still one snapshot.
    let mut vals = Vec::new();
    for first in (0..SECTORS).step_by(MAX_REQ / BLOCK) {
        let len = (SECTORS - first).min(MAX_REQ / BLOCK);
        let bytes = engine
            .read((first * BLOCK) as u64, len * BLOCK)
            .await
            .map_err(|e| e.to_string())?;
        vals.extend(decode(&bytes, first)?);
    }
    Ok(vals.try_into().unwrap())
}

async fn run_seed(seed: u64, rounds: usize) -> Result<(), String> {
    let mut rng = StdRng::seed_from_u64(seed);
    let cfg = Config::random(&mut rng);
    let backing = Arc::new(CrashableBacking::new());
    if cfg.discard {
        init::create_volume_with_discard(backing.as_ref(), superblock()).unwrap();
    } else {
        init::create_volume(backing.as_ref(), superblock()).unwrap();
    }
    let provider = provider(&cfg, seed).await;
    let clock = cfg.manual_clock.then(|| Arc::new(ManualClock::new()));
    let engine = Engine::attach(backing.clone(), provider, options(&cfg, clock.clone()))
        .await
        .map_err(|e| format!("attach: {e}"))?;
    let ticks = Arc::new(AtomicU64::new(1));
    let mut next_id = 1u32;
    let mut base = [Val::Zero; SECTORS];
    for round in 0..rounds {
        let recs = tokio::time::timeout(
            Duration::from_secs(60),
            run_round(
                &engine,
                &mut rng,
                &mut next_id,
                &ticks,
                &cfg,
                clock.as_ref(),
            ),
        )
        .await
        .map_err(|_| {
            format!(
                "seed {seed} round {round}: round did not finish in 60 s (deadlock?) cfg {cfg:?}"
            )
        })?;
        quiesce(&engine)
            .await
            .map_err(|e| format!("seed {seed} round {round}: {e} cfg {cfg:?}"))?;
        let final_img = read_all(&engine)
            .await
            .map_err(|e| format!("seed {seed} round {round}: final read: {e}"))?;
        // A second read (cache hit path when enabled) must agree.
        let again = read_all(&engine)
            .await
            .map_err(|e| format!("seed {seed} round {round}: re-read: {e}"))?;
        if again != final_img {
            return Err(format!(
                "seed {seed} round {round}: two quiescent reads disagree"
            ));
        }
        if let Err(why) = linearizable(&base, &recs, &final_img) {
            let mut dump = format!(
                "seed {seed} round {round}: {why}\ncfg {cfg:?}\nbase  {:?}\nfinal {:?}\n",
                base, final_img
            );
            let mut sorted = recs.clone();
            sorted.sort_by_key(|r| r.start);
            for r in sorted {
                dump.push_str(&format!(
                    "  op {:>3} task {} [{:>4},{:>4}] {:?} {:?} {:?}\n",
                    r.id,
                    r.task,
                    r.start,
                    if r.end == u64::MAX { 0 } else { r.end },
                    r.kind,
                    r.outcome,
                    r.read
                ));
            }
            return Err(dump);
        }
        coverage(&recs);
        base = final_img;
    }
    engine.stop_checkpoint_worker().await;
    let st = engine.stats().await;
    COV[6].fetch_add(st.cache_hits, Ordering::Relaxed);
    COV[7].fetch_add(st.checkpoints_total, Ordering::Relaxed);
    let stats = engine.stats().await;
    if stats.requests_error_total != 0 {
        return Err(format!(
            "seed {seed}: {} requests failed",
            stats.requests_error_total
        ));
    }
    Ok(())
}

/// Coverage counters: [0] concurrent write pairs sharing a unit, [1] sharing
/// a sector, [2] concurrent read/write pairs sharing a unit, [3] cancelled
/// ops, [4] write-like ops, [5] reads, [6] cache hits, [7] checkpoints.
static COV: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];

fn sectors_of(r: &Rec) -> Vec<usize> {
    match r.kind {
        Kind::Write { first, len, .. }
        | Kind::Zero { first, len, .. }
        | Kind::Trim { first, len, .. }
        | Kind::Read { first, len } => (first..first + len).collect(),
        _ => Vec::new(),
    }
}

fn coverage(recs: &[Rec]) {
    let is_w = |r: &Rec| {
        matches!(
            r.kind,
            Kind::Write { .. } | Kind::Zero { .. } | Kind::Trim { .. }
        )
    };
    let is_r = |r: &Rec| matches!(r.kind, Kind::Read { .. });
    for (i, a) in recs.iter().enumerate() {
        if matches!(a.outcome, Outcome::Cancelled) {
            COV[3].fetch_add(1, Ordering::Relaxed);
        }
        if is_w(a) {
            COV[4].fetch_add(1, Ordering::Relaxed);
        }
        if is_r(a) {
            COV[5].fetch_add(1, Ordering::Relaxed);
        }
        for b in &recs[i + 1..] {
            if !(a.start < b.end && b.start < a.end) {
                continue;
            }
            let sa = sectors_of(a);
            let sb = sectors_of(b);
            let unit = sa.iter().any(|x| sb.iter().any(|y| x / SPU == y / SPU));
            let sector = sa.iter().any(|x| sb.contains(x));
            if is_w(a) && is_w(b) {
                if unit {
                    COV[0].fetch_add(1, Ordering::Relaxed);
                }
                if sector {
                    COV[1].fetch_add(1, Ordering::Relaxed);
                }
            } else if (is_w(a) && is_r(b)) || (is_r(a) && is_w(b)) {
                if unit {
                    COV[2].fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

fn seeds() -> std::ops::Range<u64> {
    let first: u64 = std::env::var("AUDIT8_SEED_START")
        .or_else(|_| std::env::var("AUDIT4_SEED_FIRST"))
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let count: u64 = std::env::var("AUDIT8_SEED_COUNT")
        .or_else(|_| std::env::var("AUDIT4_SEEDS"))
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(24);
    first..first + count
}

fn rounds() -> usize {
    std::env::var("AUDIT4_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(40)
}

#[test]
fn overlapping_concurrent_requests_are_linearizable() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(std::env::var("AUDIT8_WORKERS").ok().and_then(|v| v.parse().ok()).unwrap_or(2))
        .enable_all()
        .build()
        .unwrap();
    let mut failures = Vec::new();
    let range = seeds();
    let total = range.end - range.start;
    for seed in range {
        if let Err(e) = rt.block_on(run_seed(seed, rounds())) {
            eprintln!("{e}");
            failures.push(seed);
        }
    }
    eprintln!(
        "linearizability: {} of {total} seeds failed ({} rounds each): {failures:?}",
        failures.len(),
        rounds()
    );
    let c: Vec<u64> = COV.iter().map(|c| c.load(Ordering::Relaxed)).collect();
    eprintln!(
        "coverage: concurrent write pairs sharing a unit {}, sharing a sector {}, concurrent \
         read/write pairs sharing a unit {}, cancelled {}, write-like ops {}, reads {}, cache \
         hits {}, checkpoints {}",
        c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]
    );
    let schedulers = SCHEDULERS.lock();
    eprintln!(
        "scheduler: {} seeds, {} batches, {} coalesced across requests",
        schedulers.len(),
        schedulers.iter().map(|s| s.batches_total()).sum::<u64>(),
        schedulers
            .iter()
            .map(|s| s.coalesced_batches_total())
            .sum::<u64>()
    );
    assert!(failures.is_empty(), "failing seeds: {failures:?}");
}

/// The oracle itself must reject a lost update and a torn unit.
#[test]
fn oracle_rejects_lost_update_and_torn_unit() {
    let base = [Val::Zero; SECTORS];
    let w = |id: u32, first: usize, len: usize, start: u64, end: u64| Rec {
        id,
        task: 0,
        kind: Kind::Write {
            first,
            len,
            fua: false,
        },
        start,
        end,
        outcome: Outcome::Ok,
        read: None,
    };
    // Two concurrent sub-unit writes to different sectors of unit 0: both
    // must survive.
    let recs = vec![w(1, 0, 1, 1, 4), w(2, 1, 1, 2, 3)];
    let mut lost = base;
    lost[1] = Val::Tag(2);
    assert!(linearizable(&base, &recs, &lost).is_err());
    let mut good = lost;
    good[0] = Val::Tag(1);
    assert!(linearizable(&base, &recs, &good).is_ok());
    // Two concurrent writes of the same two sectors cannot interleave.
    let recs = vec![w(1, 0, 2, 1, 4), w(2, 0, 2, 2, 3)];
    let mut torn = base;
    torn[0] = Val::Tag(1);
    torn[1] = Val::Tag(2);
    assert!(linearizable(&base, &recs, &torn).is_err());
    // Real time: a write that finished before another started is older.
    let recs = vec![w(1, 0, 1, 1, 2), w(2, 0, 1, 3, 4)];
    let mut stale = base;
    stale[0] = Val::Tag(1);
    assert!(linearizable(&base, &recs, &stale).is_err());
}
