//! Audit round 4 (crypto-dispatch): randomized sweep over the remote serving
//! stack (`BatchScheduler` → optional `RandomPrefixProvider` →
//! `EndpointSet` → per-endpoint chaos providers) with paused tokio time.
//!
//! Invariants checked after every seed:
//! - a provider that is not retry-safe receives each unit at most once
//!   (attempts the transport proved unsent excluded);
//! - every successful caller result belongs to that caller (unit indices and
//!   bytes);
//! - every inflight / pending / admission counter returns to zero;
//! - once the endpoints are healthy again, a fresh request completes.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use maki_crypto::breaker::BreakerConfig;
use maki_crypto::clock::{Clock, SleepFuture};
use maki_crypto::endpoint::{DispatchConfig, EndpointSet, EndpointValidator};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::scheduler::{BatchScheduler, SchedulerConfig};
use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError,
    CryptoProvider, PlaintextUnit, RandomPrefixProvider, SecretBuffer,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const UNIT: u32 = 64;
const OVERHEAD: u32 = 16;
const PREFIX: u32 = 16;
const FIRST_OP_UNIT: u64 = 1_000_000;
const COMPAT: &str = "audit4-chaos-v1";
const PREFIX_COMPAT: &str = "audit4-chaos-v1+prefix";

pub struct TokioClock {
    start: tokio::time::Instant,
}

impl Clock for TokioClock {
    fn now(&self) -> Duration {
        self.start.elapsed()
    }
    fn sleep(&self, duration: Duration) -> SleepFuture {
        Box::pin(tokio::time::sleep(duration))
    }
}

fn keystream(unit: u64, len: usize) -> Vec<u8> {
    let mut x = unit.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xD1B5_4A32_D192_ED03;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn mac(unit: u64, body: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ unit;
    for b in body {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

fn seal(unit: u64, plain: &[u8]) -> Vec<u8> {
    let ks = keystream(unit, plain.len());
    let body: Vec<u8> = plain.iter().zip(ks).map(|(p, k)| p ^ k).collect();
    let mut out = Vec::with_capacity(plain.len() + OVERHEAD as usize);
    out.extend_from_slice(&unit.to_le_bytes());
    out.extend_from_slice(&mac(unit, &body).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

fn open(unit: u64, ct: &[u8]) -> Option<Vec<u8>> {
    if ct.len() < OVERHEAD as usize {
        return None;
    }
    let stored_unit = u64::from_le_bytes(ct[..8].try_into().unwrap());
    let tag = u64::from_le_bytes(ct[8..16].try_into().unwrap());
    let body = &ct[16..];
    if stored_unit != unit || tag != mac(unit, body) {
        return None;
    }
    let ks = keystream(unit, body.len());
    Some(body.iter().zip(ks).map(|(c, k)| c ^ k).collect())
}

#[derive(Default)]
struct Ledger {
    /// unit -> number of times a provider *received* it (not-sent excluded)
    sent: parking_lot::Mutex<HashMap<u64, u32>>,
}

impl Ledger {
    fn record(&self, units: impl Iterator<Item = u64>) {
        let mut sent = self.sent.lock();
        for unit in units {
            if unit >= FIRST_OP_UNIT {
                *sent.entry(unit).or_default() += 1;
            }
        }
    }
}

struct Chaos {
    name: String,
    plain_size: u32,
    retry_safe: bool,
    healthy: Arc<AtomicBool>,
    rng: parking_lot::Mutex<StdRng>,
    ledger: Arc<Ledger>,
    calls: AtomicU64,
    scale: u64,
}

/// `x` "milliseconds" of test time: real milliseconds under paused time,
/// `scale` microseconds each under a real clock.
fn ms(scale: u64, x: u64) -> Duration {
    Duration::from_micros(x * scale)
}

enum Fault {
    Ok,
    NotSent,
    RetryableSent,
    EndpointFatalSent,
    ShortResult,
    Integrity,
    Slow(u64),
}

impl Chaos {
    fn fault(&self, decrypt: bool) -> Fault {
        if self.healthy.load(Ordering::SeqCst) {
            return Fault::Ok;
        }
        let mut rng = self.rng.lock();
        match rng.random_range(0..20u32) {
            0..=1 => Fault::NotSent,
            2..=3 => Fault::RetryableSent,
            4 => Fault::EndpointFatalSent,
            5 => Fault::ShortResult,
            6 if decrypt => Fault::Integrity,
            7..=9 => Fault::Slow(rng.random_range(1..400)),
            _ => Fault::Ok,
        }
    }
}

#[async_trait]
impl CryptoProvider for Chaos {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        Ok(CryptoCapabilities {
            provider_id: format!("chaos-{}", self.name),
            crypto_compatibility_id: COMPAT.into(),
            supported_plaintext_sizes: vec![self.plain_size],
            max_ciphertext_size: self.plain_size + OVERHEAD,
            stateless: true,
            retry_safe: self.retry_safe,
            batch: BatchCapability {
                supported: true,
                max_items: 6,
                max_bytes: 6 * u64::from(self.plain_size),
            },
            integrity: Capability::Contractual,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        })
    }

    async fn encrypt_batch(
        &self,
        _ctx: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let fault = self.fault(false);
        if matches!(fault, Fault::NotSent) {
            return Err(CryptoError::Retryable("chaos refused connect".into()).not_sent());
        }
        self.ledger.record(items.iter().map(|i| i.unit_index));
        tokio::task::yield_now().await;
        match fault {
            Fault::RetryableSent => return Err(CryptoError::Retryable("chaos reset".into())),
            Fault::EndpointFatalSent => return Err(CryptoError::EndpointFatal("chaos tls".into())),
            Fault::Slow(x) => tokio::time::sleep(ms(self.scale, x)).await,
            _ => {}
        }
        let mut out: Vec<CiphertextUnit> = items
            .iter()
            .map(|i| CiphertextUnit {
                unit_index: i.unit_index,
                data: seal(i.unit_index, i.data.expose()),
            })
            .collect();
        if matches!(fault, Fault::ShortResult) {
            out.pop();
        }
        Ok(out)
    }

    async fn decrypt_batch(
        &self,
        _ctx: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let fault = self.fault(true);
        if matches!(fault, Fault::NotSent) {
            return Err(CryptoError::Retryable("chaos refused connect".into()).not_sent());
        }
        self.ledger.record(items.iter().map(|i| i.unit_index));
        tokio::task::yield_now().await;
        match fault {
            Fault::RetryableSent => return Err(CryptoError::Retryable("chaos reset".into())),
            Fault::EndpointFatalSent => return Err(CryptoError::EndpointFatal("chaos tls".into())),
            Fault::Integrity => return Err(CryptoError::Integrity("chaos tag".into())),
            Fault::Slow(x) => tokio::time::sleep(ms(self.scale, x)).await,
            _ => {}
        }
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let plain = open(item.unit_index, &item.data)
                .ok_or_else(|| CryptoError::Integrity("chaos: authentication failed".into()))?;
            out.push(PlaintextUnit {
                unit_index: item.unit_index,
                data: SecretBuffer::from_slice(&plain),
            });
        }
        if matches!(fault, Fault::ShortResult) {
            out.pop();
        }
        Ok(out)
    }
}

fn ctx(compat: &str) -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0xA0D1_7404),
        format_version: 3,
        crypto_compatibility_id: compat.into(),
    }
}

fn dispatch(retry_safe: bool, bounded: bool, scale: u64) -> DispatchConfig {
    DispatchConfig {
        retry: RetryPolicy {
            initial_delay: ms(scale, 5),
            max_delay: ms(scale, 200),
        },
        budget: RetryBudgetConfig {
            retry_ratio: 0.5,
            burst: 4,
            min_probe_per_sec: 20.0,
        },
        breaker: BreakerConfig {
            failure_threshold: 3,
            open_initial: ms(scale, 100),
            open_max: ms(scale, 1000),
            half_open_max_requests: 1,
            success_threshold: 1,
        },
        global_max_inflight_batches: 3,
        global_max_inflight_bytes: 1 << 16,
        per_endpoint_max_inflight: 2,
        per_endpoint_max_bytes: 1 << 15,
        max_attempts: None,
        max_operation_time: bounded.then_some(ms(scale, 600)),
        retry_safe,
        validation_interval: ms(scale, 100),
    }
}

fn scheduler_config(logical: u32, scale: u64) -> SchedulerConfig {
    SchedulerConfig {
        target_items: 4,
        target_bytes: 4 * u64::from(logical),
        max_items: 6,
        max_bytes: 6 * u64::from(logical),
        max_wait: ms(scale, 2),
        max_pending_items: 32,
        max_pending_plaintext_bytes: 32 * u64::from(logical),
        max_pending_ciphertext_bytes: 32 * u64::from(logical + OVERHEAD + PREFIX),
        max_inflight_batches: 2,
    }
}

#[derive(Clone, Copy, Debug)]
enum Stack {
    Set,
    Scheduler,
    SchedulerPrefix,
}

struct Built {
    top: Arc<dyn CryptoProvider>,
    set: Arc<EndpointSet>,
    stats: Option<Arc<maki_crypto::scheduler::SchedulerStats>>,
    compat: &'static str,
    logical: u32,
}

async fn build(
    stack: Stack,
    seed: u64,
    retry_safe: bool,
    bounded: bool,
    quarantine: bool,
    healthy: &Arc<AtomicBool>,
    ledger: &Arc<Ledger>,
    clock: Arc<dyn Clock>,
    scale: u64,
) -> Built {
    let prefixed = matches!(stack, Stack::SchedulerPrefix);
    let plain_size = if prefixed { UNIT + PREFIX } else { UNIT };
    let mut endpoints: Vec<(String, Arc<dyn CryptoProvider>, bool)> = Vec::new();
    for e in 0..3u64 {
        let provider = Arc::new(Chaos {
            name: format!("e{e}"),
            plain_size,
            retry_safe,
            healthy: healthy.clone(),
            rng: parking_lot::Mutex::new(StdRng::seed_from_u64(seed * 31 + e)),
            ledger: ledger.clone(),
            calls: AtomicU64::new(0),
            scale,
        });
        endpoints.push((format!("e{e}"), provider, !(quarantine && e == 2)));
    }
    let validator: EndpointValidator = Arc::new(move |reference, candidate, context| {
        Box::pin(async move {
            maki_crypto::selftest::cross_endpoint_self_test(
                reference.as_ref(),
                candidate.as_ref(),
                &context,
                plain_size as usize,
            )
            .await
        })
    });
    let set = Arc::new(
        EndpointSet::with_quarantine(
            endpoints,
            Some(validator),
            dispatch(retry_safe, bounded, scale),
            clock.clone(),
        )
        .with_plaintext_size(plain_size),
    );
    match stack {
        Stack::Set => Built {
            top: set.clone(),
            set,
            stats: None,
            compat: COMPAT,
            logical: UNIT,
        },
        Stack::Scheduler => {
            let scheduler = BatchScheduler::with_unit_size(
                set.clone(),
                scheduler_config(UNIT, scale),
                clock,
                UNIT,
            );
            let stats = scheduler.stats();
            Built {
                top: Arc::new(scheduler),
                set,
                stats: Some(stats),
                compat: COMPAT,
                logical: UNIT,
            }
        }
        Stack::SchedulerPrefix => {
            let prefix = RandomPrefixProvider::new(set.clone(), UNIT, PREFIX, PREFIX_COMPAT.into())
                .await
                .expect("random prefix wrapper");
            let scheduler = BatchScheduler::with_unit_size(
                Arc::new(prefix),
                scheduler_config(UNIT, scale),
                clock,
                UNIT,
            );
            let stats = scheduler.stats();
            Built {
                top: Arc::new(scheduler),
                set,
                stats: Some(stats),
                compat: PREFIX_COMPAT,
                logical: UNIT,
            }
        }
    }
}

fn plain_for(unit: u64, len: usize) -> Vec<u8> {
    let mut v = keystream(unit ^ 0x5555, len);
    v[0] = (unit & 0xff) as u8;
    v
}

fn label(e: CryptoError) -> String {
    if e.to_string() == "retryable: operation deadline exceeded" {
        "deadline".to_string()
    } else {
        format!("{:?}", e.class())
    }
}

/// For the prefixed stack the caller cannot build ciphertext itself: it
/// encrypts through the stack first and then decrypts what it got.
async fn run_seed(
    stack: Stack,
    seed: u64,
    retry_safe: bool,
    bounded: bool,
    quarantine: bool,
    scale: u64,
) {
    let clock: Arc<dyn Clock> = Arc::new(TokioClock {
        start: tokio::time::Instant::now(),
    });
    let healthy = Arc::new(AtomicBool::new(false));
    let ledger = Arc::new(Ledger::default());
    let built = build(
        stack, seed, retry_safe, bounded, quarantine, &healthy, &ledger, clock, scale,
    )
    .await;
    let mut rng = StdRng::seed_from_u64(seed ^ 0xFEED);
    let ops = 40u64;
    let mut handles = Vec::new();
    for op in 0..ops {
        let top = built.top.clone();
        let compat = built.compat;
        let logical = built.logical as usize;
        let count = rng.random_range(1..=3u64);
        let units: Vec<u64> = (0..count).map(|i| FIRST_OP_UNIT + op * 10 + i).collect();
        let decrypt = rng.random_bool(0.5) && matches!(stack, Stack::Set | Stack::Scheduler);
        let start_after = ms(scale, rng.random_range(0..300));
        let cancel_after = rng
            .random_bool(0.25)
            .then(|| ms(scale, rng.random_range(0..200)));
        handles.push(tokio::spawn(async move {
            tokio::time::sleep(start_after).await;
            let context = ctx(compat);
            let work = async {
                if decrypt {
                    let items: Vec<CiphertextUnit> = units
                        .iter()
                        .map(|&u| CiphertextUnit {
                            unit_index: u,
                            data: seal(u, &plain_for(u, logical)),
                        })
                        .collect();
                    let out = top.decrypt_batch(&context, &items).await?;
                    assert_eq!(out.len(), units.len(), "seed {seed}: decrypt count");
                    for (got, &u) in out.iter().zip(&units) {
                        assert_eq!(
                            got.unit_index, u,
                            "seed {seed}: decrypt routed to wrong unit"
                        );
                        assert_eq!(
                            got.data.expose(),
                            &plain_for(u, logical)[..],
                            "seed {seed}: decrypt returned another unit's bytes"
                        );
                    }
                } else {
                    let items: Vec<PlaintextUnit> = units
                        .iter()
                        .map(|&u| PlaintextUnit {
                            unit_index: u,
                            data: SecretBuffer::from_slice(&plain_for(u, logical)),
                        })
                        .collect();
                    let out = top.encrypt_batch(&context, &items).await?;
                    assert_eq!(out.len(), units.len(), "seed {seed}: encrypt count");
                    for (got, &u) in out.iter().zip(&units) {
                        assert_eq!(
                            got.unit_index, u,
                            "seed {seed}: encrypt routed to wrong unit"
                        );
                        if matches!(stack, Stack::SchedulerPrefix) {
                            let expanded = open(u, &got.data).expect("own ciphertext opens");
                            assert_eq!(
                                &expanded[PREFIX as usize..],
                                &plain_for(u, logical)[..],
                                "seed {seed}: encrypt returned another unit's ciphertext"
                            );
                        } else {
                            assert_eq!(
                                open(u, &got.data).as_deref(),
                                Some(&plain_for(u, logical)[..]),
                                "seed {seed}: encrypt returned another unit's ciphertext"
                            );
                        }
                    }
                }
                Ok::<(), CryptoError>(())
            };
            let outcome = match cancel_after {
                Some(after) => match tokio::time::timeout(after, work).await {
                    Ok(r) => r.map_err(label),
                    Err(_) => Err("cancelled".to_string()),
                },
                None => work.await.map_err(label),
            };
            outcome
        }));
    }
    // Chaos for a while, then heal.
    tokio::time::sleep(ms(scale, 2000)).await;
    healthy.store(true, Ordering::SeqCst);
    let mut tally: HashMap<String, u32> = HashMap::new();
    for handle in handles {
        let outcome = tokio::time::timeout(Duration::from_secs(3600), handle)
            .await
            .unwrap_or_else(|_| panic!("seed {seed} {stack:?}: an operation never finished"))
            .unwrap();
        *tally
            .entry(outcome.err().unwrap_or_else(|| "ok".into()))
            .or_default() += 1;
    }
    if std::env::var("AUDIT4_VERBOSE").is_ok() {
        let sent: u32 = ledger.sent.lock().values().sum();
        eprintln!("seed {seed} {stack:?} safe={retry_safe} bounded={bounded} q={quarantine}: {tally:?} sent={sent} status={:?}", built.set.endpoint_status());
    }
    // Let abandoned RPC tasks and validation finish.
    tokio::time::sleep(ms(scale, 5000)).await;

    if !retry_safe {
        let sent = ledger.sent.lock();
        let twice: Vec<_> = sent.iter().filter(|(_, n)| **n > 1).collect();
        assert!(
            twice.is_empty(),
            "seed {seed} {stack:?} bounded={bounded}: non-retry-safe units sent more than once: {twice:?}"
        );
    }
    assert_eq!(
        built.set.global_inflight(),
        (0, 0),
        "seed {seed} {stack:?}: global admission leaked"
    );
    for (name, n) in built.set.endpoint_inflight() {
        assert_eq!(
            n, 0,
            "seed {seed} {stack:?}: endpoint {name} inflight leaked"
        );
    }
    if let Some(stats) = &built.stats {
        let deadlines = u64::from(tally.get("deadline").copied().unwrap_or(0));
        assert_eq!(
            stats.deadline_exceeded_total(),
            deadlines,
            "seed {seed} {stack:?}: scheduler deadline metric disagrees with caller outcomes {tally:?}"
        );
        assert_eq!(
            stats.pending_items(),
            0,
            "seed {seed} {stack:?}: pending items leaked"
        );
        assert_eq!(
            stats.pending_bytes(),
            0,
            "seed {seed} {stack:?}: pending bytes leaked"
        );
        assert_eq!(
            stats.inflight_batches(),
            0,
            "seed {seed} {stack:?}: inflight batches leaked"
        );
    }
    // Liveness after healing: every circuit can admit again.
    let context = ctx(built.compat);
    let probe = vec![PlaintextUnit {
        unit_index: 7,
        data: SecretBuffer::from_slice(&plain_for(7, built.logical as usize)),
    }];
    let result = tokio::time::timeout(
        Duration::from_secs(600),
        built.top.encrypt_batch(&context, &probe),
    )
    .await
    .unwrap_or_else(|_| panic!("seed {seed} {stack:?}: healed stack never served"));
    assert!(
        result.is_ok(),
        "seed {seed} {stack:?}: healed stack failed: {:?}",
        result.err()
    );
}

async fn sweep(stack: Stack, retry_safe: bool, bounded: bool, quarantine: bool) {
    let seeds: u64 = std::env::var("AUDIT4_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(40);
    sweep_scaled(stack, retry_safe, bounded, quarantine, 1000, seeds).await;
}

async fn sweep_scaled(
    stack: Stack,
    retry_safe: bool,
    bounded: bool,
    quarantine: bool,
    scale: u64,
    seeds: u64,
) {
    for seed in 0..seeds {
        run_seed(stack, seed, retry_safe, bounded, quarantine, scale).await;
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn sweep_set_not_retry_safe() {
    sweep(Stack::Set, false, true, false).await;
    sweep(Stack::Set, false, false, true).await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn sweep_set_retry_safe() {
    sweep(Stack::Set, true, true, true).await;
    sweep(Stack::Set, true, false, false).await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn sweep_scheduler_not_retry_safe() {
    sweep(Stack::Scheduler, false, true, false).await;
    sweep(Stack::Scheduler, false, false, true).await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn sweep_scheduler_retry_safe() {
    sweep(Stack::Scheduler, true, true, true).await;
    sweep(Stack::Scheduler, true, false, false).await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn sweep_prefix_not_retry_safe() {
    sweep(Stack::SchedulerPrefix, false, true, false).await;
    sweep(Stack::SchedulerPrefix, false, false, true).await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn sweep_prefix_retry_safe() {
    sweep(Stack::SchedulerPrefix, true, true, true).await;
    sweep(Stack::SchedulerPrefix, true, false, false).await;
}

/// Real time on four worker threads: lanes, dispatch tasks, validation and
/// callers race for real. Timings are scaled to 1/5.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sweep_multithread_real_time() {
    let seeds: u64 = std::env::var("AUDIT4_MT_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);
    for stack in [Stack::Set, Stack::Scheduler, Stack::SchedulerPrefix] {
        for (retry_safe, bounded, quarantine) in [
            (false, true, true),
            (false, false, false),
            (true, true, false),
            (true, false, true),
        ] {
            sweep_scaled(stack, retry_safe, bounded, quarantine, 200, seeds).await;
        }
    }
}
