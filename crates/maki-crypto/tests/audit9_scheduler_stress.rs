//! Round 9 audit (providers-native): seeded stress of the batch scheduler
//! with cancellation, mixed deadlines, shared units, two contexts, poisoned
//! requests and a provider that fails, stalls and hangs, on virtual time.
//!
//! Each seed is reproducible: one current-thread runtime with paused time
//! and a clock that reads tokio's virtual time (the injectable `Clock`;
//! nothing sleeps for real).
//!
//! Checked per seed:
//! * every success answers its own request (unit identity, own payload
//!   version, own context), also when requests share a unit;
//! * a poisoned request fails alone with its own verdict when the provider
//!   is retry-safe;
//! * a provider call never exceeds the batch maxima, never mixes contexts
//!   and never carries a unit twice;
//! * when everything has ended, pending items, pending bytes and inflight
//!   batches are zero and no provider call is still running;
//! * no lane slot and no admission permit leaked: the lane reaches its full
//!   `max_inflight_batches` again and admits a request of the maximum size.
//!
//! `AUDIT9_SEEDS=first..last` selects the seed range (default 0..40).

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use maki_crypto::clock::SleepFuture;
use maki_crypto::scheduler::{BatchScheduler, SchedulerConfig};
use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, Clock, CryptoCapabilities, CryptoContext,
    CryptoError, CryptoProvider, PlaintextUnit, SecretBuffer,
};

const UNIT: usize = 64;
const MAX_ITEMS: usize = 8;
const INFLIGHT: u32 = 3;

/// Tokio's virtual time as the injectable clock.
struct VirtualClock(tokio::time::Instant);

impl Clock for VirtualClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
    fn sleep(&self, duration: Duration) -> SleepFuture {
        Box::pin(tokio::time::sleep(duration))
    }
}

fn context(which: u8) -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x900 + u128::from(which)),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".into(),
    }
}

fn tag(context: &CryptoContext, unit: u64, plain: &[u8]) -> [u8; 8] {
    // FNV-1a over the context, the unit and the payload.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |bytes: &[u8]| {
        for b in bytes {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    eat(context.volume_uuid.as_bytes());
    eat(&unit.to_le_bytes());
    eat(plain);
    h.to_le_bytes()
}

fn seal(context: &CryptoContext, unit: u64, plain: &[u8]) -> Vec<u8> {
    let mut out = tag(context, unit, plain).to_vec();
    out.extend(plain.iter().map(|b| b ^ 0xA5));
    out
}

fn open(context: &CryptoContext, unit: u64, cipher: &[u8]) -> Option<Vec<u8>> {
    if cipher.len() != UNIT + 8 {
        return None;
    }
    let plain: Vec<u8> = cipher[8..].iter().map(|b| b ^ 0xA5).collect();
    (tag(context, unit, &plain) == cipher[..8]).then_some(plain)
}

fn payload(unit: u64, version: u64) -> Vec<u8> {
    let mut data = vec![0u8; UNIT];
    data[..8].copy_from_slice(&unit.to_le_bytes());
    data[8..16].copy_from_slice(&version.to_le_bytes());
    for (k, b) in data.iter_mut().enumerate().skip(16) {
        *b = (version as u8).wrapping_mul(17).wrapping_add(k as u8);
    }
    data
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Chaos,
    Healthy,
    /// Every call waits until released: counts reachable concurrency.
    Gate,
}

struct ChaosProvider {
    rng: parking_lot::Mutex<StdRng>,
    mode: parking_lot::Mutex<Mode>,
    retry_safe: bool,
    active: Arc<AtomicUsize>,
    /// Calls in flight per lane (encrypt, decrypt): the bound is per lane.
    lane_active: [Arc<AtomicUsize>; 2],
    max_active: AtomicUsize,
    calls: AtomicU64,
    violations: parking_lot::Mutex<Vec<String>>,
    gate: tokio::sync::Notify,
}

struct Active(Arc<AtomicUsize>, Arc<AtomicUsize>);

impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
        self.1.fetch_sub(1, Ordering::SeqCst);
    }
}

impl ChaosProvider {
    fn new(seed: u64, retry_safe: bool) -> Self {
        Self {
            rng: parking_lot::Mutex::new(StdRng::seed_from_u64(seed ^ 0x5EED)),
            mode: parking_lot::Mutex::new(Mode::Chaos),
            retry_safe,
            active: Arc::new(AtomicUsize::new(0)),
            lane_active: [Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0))],
            max_active: AtomicUsize::new(0),
            calls: AtomicU64::new(0),
            violations: parking_lot::Mutex::new(Vec::new()),
            gate: tokio::sync::Notify::new(),
        }
    }

    fn set_mode(&self, mode: Mode) {
        *self.mode.lock() = mode;
    }

    /// Shape checks on what the scheduler sends, then this call's fate.
    async fn enter(
        &self,
        lane: usize,
        context: &CryptoContext,
        units: Vec<u64>,
    ) -> Result<Active, CryptoError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let total = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_active.fetch_max(total, Ordering::SeqCst);
        let now = self.lane_active[lane].fetch_add(1, Ordering::SeqCst) + 1;
        let guard = Active(self.active.clone(), self.lane_active[lane].clone());
        {
            let mut violations = self.violations.lock();
            if units.is_empty() || units.len() > MAX_ITEMS {
                violations.push(format!("call of {} items", units.len()));
            }
            let distinct: HashSet<_> = units.iter().collect();
            if distinct.len() != units.len() {
                violations.push(format!("call carries a unit twice: {units:?}"));
            }
            if now > INFLIGHT as usize {
                violations.push(format!("{now} calls in flight on lane {lane}, bound {INFLIGHT}"));
            }
            let known = [self::context(0), self::context(1)];
            if !known.contains(context) {
                violations.push("call under an unknown context".into());
            }
        }
        let mode = *self.mode.lock();
        match mode {
            Mode::Healthy => {}
            Mode::Gate => self.gate.notified().await,
            Mode::Chaos => {
                let (delay, fate) = {
                    let mut rng = self.rng.lock();
                    let delay = match rng.random_range(0..20u32) {
                        0..=9 => Duration::ZERO,
                        10..=14 => Duration::from_micros(rng.random_range(1..2000)),
                        15..=17 => Duration::from_millis(rng.random_range(1..80)),
                        18 => Duration::from_secs(5),
                        _ => Duration::from_secs(3600),
                    };
                    (delay, rng.random_range(0..12u32))
                };
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                match fate {
                    0 => return Err(CryptoError::Retryable("chaos".into())),
                    1 => return Err(CryptoError::Throttled("chaos".into())),
                    2 => return Err(CryptoError::EndpointFatal("chaos".into())),
                    _ => {}
                }
            }
        }
        Ok(guard)
    }
}

#[async_trait]
impl CryptoProvider for ChaosProvider {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        Ok(CryptoCapabilities {
            provider_id: "chaos".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            supported_plaintext_sizes: vec![UNIT as u32],
            max_ciphertext_size: UNIT as u32 + 8,
            stateless: true,
            retry_safe: self.retry_safe,
            batch: BatchCapability {
                supported: true,
                max_items: 64,
                max_bytes: 1 << 20,
            },
            integrity: Capability::Verified,
            context_binding: Capability::Verified,
            replay_protection: Capability::Absent,
        })
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        let _active = self
            .enter(0, context, items.iter().map(|i| i.unit_index).collect())
            .await?;
        // A poisoned plaintext (first byte 0xEE in the version field's last
        // byte) is refused as a request error: it concerns that request only.
        if items.iter().any(|i| i.data.expose()[15] == 0xEE) {
            return Err(CryptoError::NonRetryableRequest("poisoned plaintext".into()));
        }
        Ok(items
            .iter()
            .map(|i| CiphertextUnit {
                unit_index: i.unit_index,
                data: seal(context, i.unit_index, i.data.expose()),
            })
            .collect())
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        let _active = self
            .enter(1, context, items.iter().map(|i| i.unit_index).collect())
            .await?;
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let Some(plain) = open(context, item.unit_index, &item.data) else {
                return Err(CryptoError::Integrity("tag mismatch".into()));
            };
            out.push(PlaintextUnit {
                unit_index: item.unit_index,
                data: SecretBuffer::from_vec(plain),
            });
        }
        Ok(out)
    }
}

fn config() -> SchedulerConfig {
    SchedulerConfig {
        target_items: 5,
        target_bytes: 4 * UNIT as u64,
        max_items: MAX_ITEMS,
        max_bytes: (MAX_ITEMS * UNIT) as u64,
        max_wait: Duration::from_micros(700),
        // Exactly one maximum request: any leaked admission permit shows.
        max_pending_items: MAX_ITEMS as u32,
        max_pending_plaintext_bytes: (MAX_ITEMS * UNIT) as u64,
        max_pending_ciphertext_bytes: (MAX_ITEMS * (UNIT + 8)) as u64,
        max_inflight_batches: INFLIGHT,
    }
}

#[derive(Default)]
struct Tally {
    ok: u64,
    transient: u64,
    poisoned: u64,
    cancelled: u64,
}

async fn one_seed(seed: u64, retry_safe: bool) -> Result<Tally, String> {
    let clock: Arc<dyn Clock> = Arc::new(VirtualClock(tokio::time::Instant::now()));
    let provider = Arc::new(ChaosProvider::new(seed, retry_safe));
    let scheduler = Arc::new(BatchScheduler::with_unit_size(
        provider.clone(),
        config(),
        clock,
        UNIT as u32,
    ));
    let stats = scheduler.stats();
    let version = Arc::new(AtomicU64::new(1));
    let mut tasks = Vec::new();
    for task in 0..10u64 {
        let scheduler = scheduler.clone();
        let version = version.clone();
        tasks.push(tokio::spawn(async move {
            let mut rng = StdRng::seed_from_u64(seed.wrapping_mul(1000) + task);
            let mut tally = Tally::default();
            for _ in 0..40 {
                let which = rng.random_range(0..2u8);
                let ctx = context(which);
                let n = rng.random_range(1..=5usize);
                // A small universe, so requests of different tasks share units.
                let mut units: Vec<u64> = Vec::new();
                while units.len() < n {
                    let unit = rng.random_range(0..24u64);
                    if !units.contains(&unit) {
                        units.push(unit);
                    }
                }
                units.sort_unstable();
                let versions: Vec<u64> = units
                    .iter()
                    .map(|_| version.fetch_add(1, Ordering::SeqCst))
                    .collect();
                let poison = rng.random_range(0..8u32) == 0;
                let encrypt = rng.random_bool(0.5);
                let budget = match rng.random_range(0..10u32) {
                    0..=2 => Some(Duration::from_micros(rng.random_range(0..3000))),
                    3 => Some(Duration::from_millis(rng.random_range(1..200))),
                    4 => Some(Duration::from_secs(20)),
                    _ => None,
                };
                let mut plains: Vec<Vec<u8>> = units
                    .iter()
                    .zip(&versions)
                    .map(|(unit, version)| payload(*unit, *version))
                    .collect();
                let outcome: Result<Result<(), String>, CryptoError> = if encrypt {
                    if poison {
                        plains[0][15] = 0xEE;
                    }
                    let items: Vec<PlaintextUnit> = units
                        .iter()
                        .zip(&plains)
                        .map(|(unit, plain)| PlaintextUnit {
                            unit_index: *unit,
                            data: SecretBuffer::from_slice(plain),
                        })
                        .collect();
                    let call = scheduler.encrypt_batch(&ctx, &items);
                    let result = match budget {
                        Some(budget) => match tokio::time::timeout(budget, call).await {
                            Ok(result) => result,
                            Err(_) => {
                                tally.cancelled += 1;
                                continue;
                            }
                        },
                        None => call.await,
                    };
                    result.map(|out| {
                        if out.len() != units.len() {
                            return Err(format!("{} results for {} items", out.len(), units.len()));
                        }
                        for ((ct, unit), plain) in out.iter().zip(&units).zip(&plains) {
                            if ct.unit_index != *unit {
                                return Err(format!("unit {} answered as {}", unit, ct.unit_index));
                            }
                            if open(&ctx, *unit, &ct.data).as_deref() != Some(plain.as_slice()) {
                                return Err(format!(
                                    "encrypt of unit {unit} is not this request's payload/context"
                                ));
                            }
                        }
                        Ok(())
                    })
                } else {
                    let mut items: Vec<CiphertextUnit> = units
                        .iter()
                        .zip(&plains)
                        .map(|(unit, plain)| CiphertextUnit {
                            unit_index: *unit,
                            data: seal(&ctx, *unit, plain),
                        })
                        .collect();
                    if poison {
                        items[0].data[0] ^= 1;
                    }
                    let call = scheduler.decrypt_batch(&ctx, &items);
                    let result = match budget {
                        Some(budget) => match tokio::time::timeout(budget, call).await {
                            Ok(result) => result,
                            Err(_) => {
                                tally.cancelled += 1;
                                continue;
                            }
                        },
                        None => call.await,
                    };
                    result.map(|out| {
                        if out.len() != units.len() {
                            return Err(format!("{} results for {} items", out.len(), units.len()));
                        }
                        for ((pt, unit), plain) in out.iter().zip(&units).zip(&plains) {
                            if pt.unit_index != *unit || pt.data.expose() != plain.as_slice() {
                                return Err(format!(
                                    "decrypt of unit {unit} is not this request's payload"
                                ));
                            }
                        }
                        Ok(())
                    })
                };
                match outcome {
                    Ok(Ok(())) if poison => {
                        return Err("a poisoned request succeeded".to_string());
                    }
                    Ok(Ok(())) => tally.ok += 1,
                    Ok(Err(wrong)) => return Err(wrong),
                    Err(CryptoError::Integrity(_)) | Err(CryptoError::NonRetryableRequest(_))
                        if poison =>
                    {
                        tally.poisoned += 1
                    }
                    Err(
                        CryptoError::Retryable(_)
                        | CryptoError::Throttled(_)
                        | CryptoError::EndpointFatal(_),
                    ) => tally.transient += 1,
                    Err(error @ (CryptoError::Integrity(_) | CryptoError::NonRetryableRequest(_))) => {
                        // Healthy request beside a poisoned one.
                        if retry_safe {
                            return Err(format!(
                                "a healthy request got another request's verdict: {error}"
                            ));
                        }
                        tally.poisoned += 1;
                    }
                    Err(other) => return Err(format!("unexpected error: {other}")),
                }
            }
            Ok(tally)
        }));
    }
    let mut total = Tally::default();
    for task in tasks {
        let tally = task.await.map_err(|e| format!("task panicked: {e}"))??;
        total.ok += tally.ok;
        total.transient += tally.transient;
        total.poisoned += tally.poisoned;
        total.cancelled += tally.cancelled;
    }
    // Let every abandoned provider call notice that its callers left.
    for _ in 0..200 {
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(Duration::from_millis(5)).await;
    let violations = provider.violations.lock().clone();
    if !violations.is_empty() {
        return Err(format!("provider saw: {:?}", &violations[..violations.len().min(3)]));
    }
    if stats.pending_items() != 0 || stats.pending_bytes() != 0 {
        return Err(format!(
            "pending not released: {} items / {} bytes",
            stats.pending_items(),
            stats.pending_bytes()
        ));
    }
    if stats.inflight_batches() != 0 || provider.active.load(Ordering::SeqCst) != 0 {
        return Err(format!(
            "calls still in flight with no caller left: scheduler {} provider {}",
            stats.inflight_batches(),
            provider.active.load(Ordering::SeqCst)
        ));
    }

    // No lane slot leaked: requests that share a unit are never coalesced,
    // so 2*INFLIGHT of them must put exactly INFLIGHT calls in flight.
    provider.set_mode(Mode::Gate);
    provider.max_active.store(0, Ordering::SeqCst);
    for (lane, encrypt) in [("encrypt", true), ("decrypt", false)] {
        let mut waiters = Vec::new();
        for i in 0..2 * INFLIGHT as u64 {
            let scheduler = scheduler.clone();
            waiters.push(tokio::spawn(async move {
                let ctx = context(0);
                let plain = payload(7, 1_000_000 + i);
                if encrypt {
                    scheduler
                        .encrypt_batch(
                            &ctx,
                            &[PlaintextUnit {
                                unit_index: 7,
                                data: SecretBuffer::from_slice(&plain),
                            }],
                        )
                        .await
                        .map(|_| ())
                } else {
                    scheduler
                        .decrypt_batch(
                            &ctx,
                            &[CiphertextUnit {
                                unit_index: 7,
                                data: seal(&ctx, 7, &plain),
                            }],
                        )
                        .await
                        .map(|_| ())
                }
            }));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let reached = provider.active.load(Ordering::SeqCst);
        if reached != INFLIGHT as usize {
            return Err(format!(
                "{lane} lane reaches {reached} concurrent calls after the run, expected {INFLIGHT}"
            ));
        }
        // Release until every waiter is through.
        let mut done = 0;
        let mut spins = 0;
        while done < waiters.len() {
            provider.gate.notify_waiters();
            tokio::time::sleep(Duration::from_millis(1)).await;
            done = waiters.iter().filter(|w| w.is_finished()).count();
            spins += 1;
            if spins > 10_000 {
                return Err(format!("{lane} lane: gated requests never finished"));
            }
        }
        for waiter in waiters {
            waiter
                .await
                .map_err(|e| e.to_string())?
                .map_err(|e| format!("{lane} gated request failed: {e}"))?;
        }
    }

    // No admission permit leaked: one request of the maximum size is admitted.
    provider.set_mode(Mode::Healthy);
    let ctx = context(1);
    let items: Vec<PlaintextUnit> = (0..MAX_ITEMS as u64)
        .map(|unit| PlaintextUnit {
            unit_index: 100 + unit,
            data: SecretBuffer::from_slice(&payload(100 + unit, 9)),
        })
        .collect();
    let sealed = tokio::time::timeout(
        Duration::from_secs(600),
        scheduler.encrypt_batch(&ctx, &items),
    )
    .await
    .map_err(|_| "a maximum-size encrypt is never admitted: admission permits leaked".to_string())?
    .map_err(|e| format!("maximum-size encrypt failed: {e}"))?;
    tokio::time::timeout(
        Duration::from_secs(600),
        scheduler.decrypt_batch(&ctx, &sealed),
    )
    .await
    .map_err(|_| "a maximum-size decrypt is never admitted: admission permits leaked".to_string())?
    .map_err(|e| format!("maximum-size decrypt failed: {e}"))?;
    Ok(total)
}

fn seeds() -> std::ops::Range<u64> {
    match std::env::var("AUDIT9_SEEDS") {
        Ok(range) => {
            let (first, last) = range.split_once("..").expect("AUDIT9_SEEDS=first..last");
            first.parse().unwrap()..last.parse().unwrap()
        }
        Err(_) => 0..40,
    }
}

fn run(retry_safe: bool) {
    let mut failures = Vec::new();
    let (mut ok, mut transient, mut poisoned, mut cancelled) = (0, 0, 0, 0);
    for seed in seeds() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap();
        match runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(1_000_000), one_seed(seed, retry_safe)).await
        }) {
            Ok(Ok(tally)) => {
                ok += tally.ok;
                transient += tally.transient;
                poisoned += tally.poisoned;
                cancelled += tally.cancelled;
            }
            Ok(Err(reason)) => failures.push(format!("seed {seed}: {reason}")),
            Err(_) => failures.push(format!("seed {seed}: did not finish (a request hangs)")),
        }
    }
    println!(
        "retry_safe={retry_safe}: {} seeds, {ok} ok, {transient} transient errors, {poisoned} poisoned verdicts, {cancelled} cancelled",
        seeds().count()
    );
    assert!(failures.is_empty(), "{} failing seed(s):\n{}", failures.len(), failures.join("\n"));
}

#[test]
fn audit9_scheduler_survives_seeded_chaos_with_a_retry_safe_provider() {
    run(true);
}

#[test]
fn audit9_scheduler_survives_seeded_chaos_with_a_provider_that_is_not_retry_safe() {
    run(false);
}
