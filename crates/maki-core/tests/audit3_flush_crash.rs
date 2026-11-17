//! Audit round 3 (engine-concurrency): FLUSH/FUA durability of concurrent,
//! overlapping requests across power loss.
//!
//! The workload of `audit3_linearizable.rs` (overlapping sub-unit and
//! multi-unit writes, WRITE_ZEROES, TRIM, reads, FLUSH, FUA, checkpoints,
//! cache resizes, cancelled callers, small journal/overlay bounds so the
//! worker and inline reclaim checkpoint mid-round) runs while the backing
//! *dies* at a random mutating operation (every later one fails, like a
//! power cut seen from the process), or not at all; then a torn power loss
//! (`CrashableBacking::with_tearing`, every unsynced write kept, lost or
//! torn) and recovery.
//!
//! Oracle: there must be ONE serial order of the round's operations that
//! respects real time, explains every successful live read and the live
//! device just before the power loss, and of which the recovered device
//! is a prefix — cut at any record (a request's units are appended in
//! ascending order) — that contains every durable operation: a write, zero
//! or trim acknowledged with FUA, or acknowledged before a successful FLUSH
//! (or FUA trim covering no whole unit, which is a FLUSH) was *issued*.
//! Failed and cancelled operations may be applied for any prefix of their
//! units, or not at all. NBD itself only requires the durable operations;
//! the prefix requirement is what the journal design promises and is
//! reported separately when it is the only thing violated.

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
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::{CrashableBacking, FakeCryptoProvider};

const BLOCK: usize = 512;
const UNIT: usize = 2048;
const SPU: usize = UNIT / BLOCK;
const UNITS: usize = 6;
const SECTORS: usize = UNITS * SPU;
const MAX_REQ: usize = 8192;

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
#[allow(dead_code)] // the error text is only shown in failure dumps
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
    /// Live device just before the power loss, if it could be read.
    final_img: Option<&'a Image>,
    recovered: &'a Image,
    durable: u32,
    memo: HashSet<(u32, Image, bool)>,
}

impl Search<'_> {
    fn cut_ok(&self, done: u32, img: &Image) -> bool {
        img == self.recovered && self.durable & !done == 0
    }

    fn dfs(&mut self, done: u32, img: Image, mut cut: bool) -> bool {
        if !cut && self.cut_ok(done, &img) {
            cut = true;
        }
        let n = self.elems.len();
        if done == (1u32 << n) - 1 {
            return cut && self.final_img.is_none_or(|f| *f == img);
        }
        if !self.memo.insert((done, img, cut)) {
            return false;
        }
        for i in 0..n {
            if done & (1 << i) != 0 || self.preds[i] & !done != 0 {
                continue;
            }
            match &self.elems[i].e {
                E::Read { first, img: r } => {
                    if img[*first..*first + r.len()] == r[..] && self.dfs(done | 1 << i, img, cut) {
                        return true;
                    }
                }
                E::Op { units, mandatory } => {
                    let lo = if *mandatory { units.len() } else { 0 };
                    for j in (lo..=units.len()).rev() {
                        let mut s = img;
                        let mut c = cut;
                        for (k, unit) in units.iter().enumerate().take(j) {
                            if k > 0 && !c && self.cut_ok(done, &s) {
                                c = true;
                            }
                            for &(sec, v) in unit {
                                s[sec] = v;
                            }
                        }
                        if self.dfs(done | 1 << i, s, c) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
}

/// NBD-only check (no prefix requirement): each sector of the recovered
/// device holds the value of the base or of a write covering it that is
/// not followed, in a real-time-compatible way, by a durable write of that
/// sector that must precede... approximated per sector: the recovered
/// value must come from the base or an operation covering the sector, and
/// no durable operation covering the sector may have *finished before* the
/// operation that wrote the recovered value started.
fn nbd_durable_ok(
    base: &Image,
    recs: &[Rec],
    durable_ids: &HashSet<u32>,
    recovered: &Image,
) -> Result<(), String> {
    for s in 0..SECTORS {
        let writers: Vec<&Rec> = recs
            .iter()
            .filter(|r| {
                effects(r.id, &r.kind).is_some_and(|u| u.iter().flatten().any(|(sec, _)| *sec == s))
            })
            .collect();
        // Candidate sources of the recovered value.
        let sources: Vec<Option<&Rec>> = std::iter::once(None)
            .chain(writers.iter().map(|r| Some(*r)))
            .filter(|src| {
                let v = match src {
                    None => base[s],
                    Some(r) => {
                        effects(r.id, &r.kind)
                            .unwrap()
                            .iter()
                            .flatten()
                            .find(|(sec, _)| *sec == s)
                            .unwrap()
                            .1
                    }
                };
                v == recovered[s]
            })
            .collect();
        let ok = sources.iter().any(|src| {
            writers
                .iter()
                .filter(|d| durable_ids.contains(&d.id))
                .all(|d| match src {
                    // The base survives only if no durable write covers s.
                    None => false,
                    // A durable write d is superseded only by a write that did
                    // not finish before d started (d < src possible) — i.e.
                    // src must not have finished before d started, and src is
                    // d itself or not provably older.
                    Some(src) => src.id == d.id || src.end >= d.start,
                })
        });
        if !ok {
            return Err(format!(
                "sector {s}: recovered {:?}, but durable writes {:?} cover it",
                recovered[s],
                writers
                    .iter()
                    .filter(|d| durable_ids.contains(&d.id))
                    .map(|d| d.id)
                    .collect::<Vec<_>>()
            ));
        }
    }
    Ok(())
}

/// Ops durable at the power loss: FUA-acknowledged, or acknowledged before
/// a successful FLUSH was issued.
fn durable_ids(recs: &[Rec]) -> HashSet<u32> {
    let flushes: Vec<u64> = recs
        .iter()
        .filter(|r| matches!(r.outcome, Outcome::Ok))
        .filter(|r| match r.kind {
            Kind::Flush => true,
            Kind::Trim { fua: true, .. } => effects(r.id, &r.kind).unwrap().is_empty(),
            _ => false,
        })
        .map(|r| r.start)
        .collect();
    recs.iter()
        .filter(|r| matches!(r.outcome, Outcome::Ok))
        .filter(|r| effects(r.id, &r.kind).is_some_and(|u| !u.is_empty()))
        .filter(|r| {
            let fua = match r.kind {
                Kind::Write { fua, .. } | Kind::Zero { fua, .. } | Kind::Trim { fua, .. } => fua,
                _ => false,
            };
            fua || flushes.iter().any(|f| r.end < *f)
        })
        .map(|r| r.id)
        .collect()
}

fn crash_consistent(
    base: &Image,
    recs: &[Rec],
    final_img: Option<&Image>,
    recovered: &Image,
) -> Result<(), String> {
    let durable_set = durable_ids(recs);
    let mut elems = Vec::new();
    let mut durable = 0u32;
    for r in recs {
        let mandatory = matches!(r.outcome, Outcome::Ok);
        if let Some(units) = effects(r.id, &r.kind) {
            if units.is_empty() {
                continue;
            }
            if durable_set.contains(&r.id) {
                durable |= 1 << elems.len();
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
        recovered,
        durable,
        memo: HashSet::new(),
    };
    if search.dfs(0, *base, false) {
        return Ok(());
    }
    match nbd_durable_ok(base, recs, &durable_set, recovered) {
        Ok(()) => Err(
            "NOT a prefix of any serial order (journal design), though every durable \
                       write survives (NBD-legal)"
                .into(),
        ),
        Err(e) => Err(format!("DURABILITY VIOLATION: {e}")),
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
            cache_bytes: [UNIT as u64, 3 * UNIT as u64, 1 << 20][rng.random_range(0..3)],
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
            discard: rng.random_bool(0.75),
            scheduler: rng.random_bool(0.4),
        }
    }
}

fn provider(cfg: &Config, seed: u64) -> Arc<dyn CryptoProvider> {
    let fake =
        Arc::new(FakeCryptoProvider::new(UNIT as u32).with_max_batch(cfg.batch_items, 1 << 20));
    let jitter = Arc::new(Jitter {
        inner: fake,
        state: AtomicU64::new(seed),
        max_yields: cfg.max_yields,
    });
    if !cfg.scheduler {
        return jitter;
    }
    let max_items = cfg.batch_items as usize;
    Arc::new(maki_crypto::scheduler::BatchScheduler::with_unit_size(
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
    ))
}

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(0xa3_11_0e_a7),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(
            BLOCK as u32,
            UNIT as u32,
            512,
            UNIT as u32 + 8,
            (UNITS * UNIT) as u64,
            4 * UNIT as u64,
        )
        .unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn options(cfg: &Config) -> EngineOptions {
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
            ttl: Duration::from_secs(3600),
            verify_on_hit: cfg.cache == 2,
        }),
        identity: None,
        checkpoint: CheckpointPolicy {
            journal_high_watermark_bytes: cfg.watermark,
            journal_max_bytes: cfg.journal_max,
            max_pending_bytes: cfg.pending,
            emergency_reserve_bytes: 0,
            low_space_checkpoint_bytes: 0,
            interval: Duration::from_secs(3600),
        },
        clock: None,
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
        _ if cache => {
            Kind::Resize([0, UNIT as u64, 3 * UNIT as u64, 1 << 20][rng.random_range(0..4)])
        }
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
) -> Vec<Rec> {
    let tasks = rng.random_range(2..=4);
    let mut handles = Vec::new();
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

/// Fail every mutating backing operation after `ops` of them, and before
/// that fail each one transiently with probability `flaky_permille`/1000
/// (a write may then persist a prefix); returns the counter of operations.
fn die_after(
    backing: &CrashableBacking,
    ops: Option<u64>,
    flaky_permille: u64,
    seed: u64,
) -> Arc<AtomicU64> {
    let count = Arc::new(AtomicU64::new(0));
    let seen = count.clone();
    let limit = ops.unwrap_or(u64::MAX);
    let roll = Arc::new(move |n: u64| {
        let mut x = seed ^ n.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        (x ^ (x >> 31)) % 1000
    });
    let partial_roll = roll.clone();
    let partial_count = Arc::new(AtomicU64::new(0));
    backing.set_fault_hook(Some(Arc::new(move |_op| {
        let n = count.fetch_add(1, Ordering::SeqCst);
        if n >= limit {
            Some(std::io::Error::other("audit3: backing died (power cut)"))
        } else if roll(n) < flaky_permille {
            Some(std::io::Error::other("audit3: transient I/O error"))
        } else {
            None
        }
    })));
    backing.set_partial_write_hook((flaky_permille > 0).then(|| {
        Arc::new(move |op: &FaultOp<'_>| {
            let n = partial_count.fetch_add(1, Ordering::SeqCst);
            match op {
                FaultOp::WriteAt { len, .. }
                    if *len > 1 && partial_roll(n ^ 0x5a5a) < flaky_permille / 2 =>
                {
                    Some((len / 2, std::io::Error::other("audit3: partial write")))
                }
                _ => None,
            }
        }) as maki_test_support::crash_backing::PartialWriteHook
    }));
    seen
}

fn dump(recs: &[Rec]) -> String {
    let mut sorted = recs.to_vec();
    sorted.sort_by_key(|r| r.start);
    let mut out = String::new();
    for r in sorted {
        out.push_str(&format!(
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
    out
}

/// Coverage: [0] crash rounds, [1] with a mid-round death that fired, [2]
/// durable ops, [3] durable ops whose unit had a later non-durable
/// overwrite in the same round, [4] rounds where recovery returned
/// something other than the live image, [5] recoveries, [6] mutating
/// backing ops in rounds without death, [7] ops failed by the death.
/// [8] rounds with transient faults, [9] rounds ending in a process restart
/// instead of a power loss.
/// [10] flaky rounds healed in place (no crash) before the next cycle.
static COV: [AtomicU64; 11] = [const { AtomicU64::new(0) }; 11];

async fn attach(
    backing: &Arc<CrashableBacking>,
    cfg: &Config,
    seed: u64,
) -> Result<Engine, String> {
    let provider = provider(cfg, seed);
    Engine::attach(backing.clone(), provider, options(cfg))
        .await
        .map_err(|e| format!("attach: {e}"))
}

async fn run_seed(seed: u64, cycles: usize) -> Result<(), String> {
    let mut rng = StdRng::seed_from_u64(seed);
    let cfg = Config::random(&mut rng);
    let backing = Arc::new(CrashableBacking::new().with_tearing(512));
    if cfg.discard {
        init::create_volume_with_discard(backing.as_ref(), superblock()).unwrap();
    } else {
        init::create_volume(backing.as_ref(), superblock()).unwrap();
    }
    let mut engine = attach(&backing, &cfg, seed).await?;
    let ticks = Arc::new(AtomicU64::new(1));
    let mut next_id = 1u32;
    let mut base = [Val::Zero; SECTORS];
    for cycle in 0..cycles {
        let tag = format!("seed {seed} cycle {cycle}");
        // A live warm-up round leaves overlay/journal/cache state behind.
        if rng.random_bool(0.5) {
            let recs = tokio::time::timeout(
                Duration::from_secs(60),
                run_round(&engine, &mut rng, &mut next_id, &ticks, &cfg),
            )
            .await
            .map_err(|_| format!("{tag}: warm-up round stuck"))?;
            quiesce(&engine).await.map_err(|e| format!("{tag}: {e}"))?;
            if let Some(r) = recs.iter().find(|r| matches!(r.outcome, Outcome::Err(_))) {
                return Err(format!("{tag}: warm-up op failed without faults: {r:?}"));
            }
        }
        // The crash round starts from a durable, known device.
        engine
            .flush()
            .await
            .map_err(|e| format!("{tag}: base flush: {e}"))?;
        base = read_all(&engine)
            .await
            .map_err(|e| format!("{tag}: base read: {e}"))?;

        let death = rng
            .random_bool(0.7)
            .then(|| rng.random_range(0..DEATH_RANGE));
        let flaky = [0, 0, 20, 50][rng.random_range(0..4)];
        let restart = rng.random_bool(0.3);
        COV[0].fetch_add(1, Ordering::Relaxed);
        if flaky > 0 {
            COV[8].fetch_add(1, Ordering::Relaxed);
        }
        if restart {
            COV[9].fetch_add(1, Ordering::Relaxed);
        }
        let seen = die_after(&backing, death, flaky, seed.wrapping_mul(31) ^ cycle as u64);
        let recs = tokio::time::timeout(
            Duration::from_secs(60),
            run_round(&engine, &mut rng, &mut next_id, &ticks, &cfg),
        )
        .await
        .map_err(|_| format!("{tag}: crash round stuck (deadlock?) cfg {cfg:?}"))?;
        quiesce(&engine).await.map_err(|e| format!("{tag}: {e}"))?;
        if death.is_none() && flaky == 0 {
            if let Some(r) = recs.iter().find(|r| matches!(r.outcome, Outcome::Err(_))) {
                return Err(format!("{tag}: op failed without faults: {r:?}"));
            }
        }
        let seen = seen.load(Ordering::SeqCst);
        match death {
            Some(limit) if seen > limit => {
                COV[1].fetch_add(1, Ordering::Relaxed);
            }
            None => {
                COV[6].fetch_add(seen, Ordering::Relaxed);
            }
            _ => {}
        }
        COV[7].fetch_add(
            recs.iter()
                .filter(|r| matches!(r.outcome, Outcome::Err(_)))
                .count() as u64,
            Ordering::Relaxed,
        );
        // Reads are not hooked: the live (page-cache) device just before the
        // power loss.
        let live = read_all(&engine).await.ok();
        // Healing: the faults stop and the same engine keeps serving (its
        // failed syncs and checkpoints must be retried and rewritten); the
        // next cycle's base FLUSH and crash round then check that whatever
        // it acknowledges after healing is really durable.
        if flaky > 0 && death.is_none() && rng.random_bool(0.4) {
            backing.set_fault_hook(None);
            backing.set_partial_write_hook(None);
            COV[10].fetch_add(1, Ordering::Relaxed);
            let live = live.ok_or_else(|| format!("{tag}: live read failed after healing"))?;
            if let Err(why) = crash_consistent(&base, &recs, Some(&live), &live) {
                return Err(format!(
                    "{tag}: live state after transient faults: {why}\ncfg {cfg:?}\nbase {base:?}\nlive {live:?}\n{}",
                    dump(&recs)
                ));
            }
            continue;
        }
        engine.stop_checkpoint_worker().await;
        drop(engine);
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        backing.set_fault_hook(None);
        backing.set_partial_write_hook(None);
        if !restart {
            backing.crash(&mut rng);
        }
        COV[5].fetch_add(1, Ordering::Relaxed);
        engine = attach(&backing, &cfg, seed ^ cycle as u64)
            .await
            .map_err(|e| {
                format!(
                    "{tag}: RECOVERY FAILED after power loss: {e}\ncfg {cfg:?}\n{}",
                    dump(&recs)
                )
            })?;
        let recovered = read_all(&engine)
            .await
            .map_err(|e| format!("{tag}: read after recovery: {e}\n{}", dump(&recs)))?;
        if read_all(&engine).await.ok() != Some(recovered) {
            return Err(format!("{tag}: two reads after recovery disagree"));
        }
        let durable = durable_ids(&recs);
        COV[2].fetch_add(durable.len() as u64, Ordering::Relaxed);
        if live != Some(recovered) {
            COV[4].fetch_add(1, Ordering::Relaxed);
        }
        for d in recs.iter().filter(|r| durable.contains(&r.id)) {
            let du: Vec<usize> = effects(d.id, &d.kind)
                .unwrap()
                .iter()
                .map(|u| u[0].0 / SPU)
                .collect();
            if recs.iter().any(|w| {
                w.start > d.end
                    && !durable.contains(&w.id)
                    && effects(w.id, &w.kind)
                        .is_some_and(|u| u.iter().any(|u| du.contains(&(u[0].0 / SPU))))
            }) {
                COV[3].fetch_add(1, Ordering::Relaxed);
            }
        }
        if let Err(why) = crash_consistent(&base, &recs, live.as_ref(), &recovered) {
            return Err(format!(
                "{tag}: {why}\ncfg {cfg:?} death after {death:?} mutating ops\nbase      {base:?}\nlive      {live:?}\nrecovered {recovered:?}\n{}",
                dump(&recs)
            ));
        }
        base = recovered;
    }
    let _ = base;
    engine.stop_checkpoint_worker().await;
    Ok(())
}

const DEATH_RANGE: u64 = 180;

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[test]
fn acknowledged_durable_requests_survive_power_loss_under_overlap() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let first = env("AUDIT3_SEED_FIRST", 0);
    let count = env("AUDIT3_SEEDS", 24);
    let cycles = env("AUDIT3_CYCLES", 12) as usize;
    let mut failures = Vec::new();
    for seed in first..first + count {
        if let Err(e) = rt.block_on(run_seed(seed, cycles)) {
            eprintln!("{e}");
            failures.push(seed);
        }
    }
    let c: Vec<u64> = COV.iter().map(|c| c.load(Ordering::Relaxed)).collect();
    eprintln!(
        "crash: {} of {count} seeds failed ({cycles} cycles each): {failures:?}\ncoverage: crash \
         rounds {}, with mid-round death {}, durable ops {}, durable ops later overwritten \
         non-durably {}, recovered != live {}, recoveries {}, mutating ops in death-free rounds \
         {}, ops failed by faults {}, flaky rounds {}, restarts {}, healed in place {}",
        failures.len(),
        c[0],
        c[1],
        c[2],
        c[3],
        c[4],
        c[5],
        c[6],
        c[7],
        c[8],
        c[9],
        c[10]
    );
    assert!(failures.is_empty(), "failing seeds: {failures:?}");
}

/// The crash oracle must reject a lost durable write and accept a lost
/// volatile one.
#[test]
fn oracle_rejects_a_lost_fua_write() {
    let base = [Val::Zero; SECTORS];
    let w = |id: u32, first: usize, fua: bool, start: u64, end: u64| Rec {
        id,
        task: 0,
        kind: Kind::Write { first, len: 1, fua },
        start,
        end,
        outcome: Outcome::Ok,
        read: None,
    };
    let mut live = base;
    live[0] = Val::Tag(2);
    // FUA write 1 then volatile write 2 of the same sector: 1 or 2 survive.
    let recs = vec![w(1, 0, true, 1, 2), w(2, 0, false, 3, 4)];
    let mut one = base;
    one[0] = Val::Tag(1);
    assert!(crash_consistent(&base, &recs, Some(&live), &one).is_ok());
    assert!(crash_consistent(&base, &recs, Some(&live), &live).is_ok());
    assert!(crash_consistent(&base, &recs, Some(&live), &base).is_err());
    // Acknowledged before a FLUSH was issued: durable.
    let flush = Rec {
        id: 3,
        task: 1,
        kind: Kind::Flush,
        start: 3,
        end: 6,
        outcome: Outcome::Ok,
        read: None,
    };
    let recs = vec![w(1, 0, false, 1, 2), flush.clone()];
    assert!(crash_consistent(&base, &recs, Some(&one), &base).is_err());
    // Acknowledged after the FLUSH was issued: may be lost.
    let recs = vec![w(1, 0, false, 1, 4), flush];
    assert!(crash_consistent(&base, &recs, Some(&one), &base).is_ok());
}
