//! Audit round 8 (merge-interactions): randomized sweep over background
//! validation of a quarantined endpoint (#343, #350, #364) together with the
//! dispatcher, the breaker and the pinned unit size (#351).
//!
//! Every reply a peer makes can be replaced by a failure that proves nothing
//! about the candidate: a transport error, a throttle, an endpoint failure,
//! a request refused without an integrity verdict, a fatal error of the
//! provider, or a reply one item short. Proofs of another contract (a wrong
//! plaintext, an integrity refusal of good ciphertext, a refused context)
//! are never injected. The sweep asks the questions of the round-8 brief:
//!
//! - does the candidate ever serve before a complete validation, or get
//!   admitted by an attempt in which an exchange failed?
//! - is it ever excluded for the life of the set, although nothing proved
//!   another contract?
//! - once every peer is healthy again, is it admitted within the backoff
//!   cap, or can it stay quarantined?
//! - does a deferral spin (more validations than the interval allows), or
//!   leave a permit, an inflight count or a half-open slot behind?
//!
//! Not part of the maintained suite.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use maki_crypto::breaker::{BreakerConfig, CircuitState};
use maki_crypto::endpoint::{DispatchConfig, EndpointSet, EndpointValidator};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::selftest::{cross_endpoint_self_test, provider_self_test};
use maki_crypto::{
    CiphertextUnit, Clock, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    PlaintextUnit, SecretBuffer,
};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::ManualClock;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const U: usize = 256;
/// Serving requests use unit indices from here on; validation probes use
/// small ones.
const SERVING: u64 = 1 << 20;
const INTERVAL: Duration = Duration::from_secs(1);
const CAP: Duration = Duration::from_secs(8);

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x5e_7a11),
        format_version: 3,
        crypto_compatibility_id: "test-profile-v1".into(),
    }
}

fn cfg(deadline: Option<Duration>, retry_safe: bool) -> DispatchConfig {
    DispatchConfig {
        retry: RetryPolicy {
            initial_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(100),
        },
        budget: RetryBudgetConfig {
            retry_ratio: 1.0,
            burst: 16,
            min_probe_per_sec: 1.0,
        },
        breaker: BreakerConfig {
            failure_threshold: 3,
            open_initial: INTERVAL,
            open_max: CAP,
            half_open_max_requests: 2,
            success_threshold: 2,
        },
        global_max_inflight_batches: 2,
        global_max_inflight_bytes: 1 << 20,
        per_endpoint_max_inflight: 2,
        per_endpoint_max_bytes: 1 << 20,
        max_attempts: None,
        max_operation_time: deadline,
        retry_safe,
        validation_interval: INTERVAL,
    }
}

struct Peer {
    name: &'static str,
    inner: FakeCryptoProvider,
    rng: Mutex<StdRng>,
    /// Probability (per mille) that a call fails.
    chaos: AtomicU64,
    /// A validation call (a probe unit) met an injected failure.
    dirty: Arc<AtomicBool>,
    calls: AtomicUsize,
    served: Mutex<Vec<u64>>,
}

impl Peer {
    fn new(name: &'static str, seed: u64, chaos: u64, dirty: Arc<AtomicBool>) -> Arc<Self> {
        Arc::new(Self {
            name,
            inner: FakeCryptoProvider::new(U as u32),
            rng: Mutex::new(StdRng::seed_from_u64(seed)),
            chaos: AtomicU64::new(chaos),
            dirty,
            calls: AtomicUsize::new(0),
            served: Mutex::new(Vec::new()),
        })
    }

    /// `Err` for an injected error, `Ok(Some(validation))` for a reply one
    /// item short, where `validation` says the call was a validation probe.
    async fn fault(&self, units: Vec<u64>) -> Result<Option<bool>, CryptoError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let validation = units.iter().all(|unit| *unit < SERVING);
        let serving: Vec<u64> = units.into_iter().filter(|unit| *unit >= SERVING).collect();
        self.served.lock().unwrap().extend(serving);
        let (hit, kind, yields) = {
            let mut rng = self.rng.lock().unwrap();
            (
                rng.random_range(0..1000) < self.chaos.load(Ordering::SeqCst),
                rng.random_range(0..6u32),
                rng.random_range(0..4u32),
            )
        };
        // Let other tasks interleave with an RPC in flight.
        for _ in 0..yields {
            tokio::task::yield_now().await;
        }
        if !hit {
            return Ok(None);
        }
        if kind >= 5 {
            // The reply is cut short only if there is one: a negative probe
            // that the peer refuses, as it must, stays a healthy exchange.
            return Ok(Some(validation));
        }
        if validation {
            self.dirty.store(true, Ordering::SeqCst);
        }
        let name = self.name;
        match kind {
            0 => Err(CryptoError::Retryable(format!("{name}: connection reset"))),
            1 => Err(CryptoError::Throttled(format!("{name}: 429"))),
            2 => Err(CryptoError::EndpointFatal(format!("{name}: TLS failure"))),
            3 => Err(CryptoError::NonRetryableRequest(format!("{name}: 421"))),
            // Sanity check of the oracle: with AUDIT8_PLANT_PROOF set, the
            // candidate answers a validation probe with a refusal of the
            // volume's context, which IS proof of another contract, and the
            // sweep must report the exclusion.
            4 if validation
                && name == "candidate"
                && std::env::var_os("AUDIT8_PLANT_PROOF").is_some() =>
            {
                Err(CryptoError::UnsupportedContext(
                    maki_crypto::ContextField::FormatVersion,
                ))
            }
            4 => Err(CryptoError::ProviderFatal(format!(
                "{name}: backend misconfigured"
            ))),
            _ => unreachable!(),
        }
    }
}

#[async_trait]
impl CryptoProvider for Peer {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.inner.capabilities().await
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        let short = self
            .fault(items.iter().map(|item| item.unit_index).collect())
            .await?;
        let mut out = self.inner.encrypt_batch(context, items).await?;
        if let Some(validation) = short {
            out.pop();
            if validation {
                self.dirty.store(true, Ordering::SeqCst);
            }
        }
        Ok(out)
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        let short = self
            .fault(items.iter().map(|item| item.unit_index).collect())
            .await?;
        let mut out = self.inner.decrypt_batch(context, items).await?;
        if let Some(validation) = short {
            out.pop();
            if validation {
                self.dirty.store(true, Ordering::SeqCst);
            }
        }
        Ok(out)
    }
}

struct Validations {
    runs: AtomicUsize,
    /// Attempts that returned `Ok` although one of their exchanges failed.
    admitted_dirty: AtomicUsize,
    admitted: AtomicUsize,
}

fn validator(dirty: Arc<AtomicBool>, seen: Arc<Validations>) -> EndpointValidator {
    Arc::new(move |reference, candidate, context| {
        seen.runs.fetch_add(1, Ordering::SeqCst);
        let dirty = dirty.clone();
        let seen = seen.clone();
        Box::pin(async move {
            // One candidate, so one validation at a time: the flag belongs
            // to this attempt.
            dirty.store(false, Ordering::SeqCst);
            let outcome = async {
                provider_self_test(
                    candidate.as_ref(),
                    &context,
                    U,
                    &context.crypto_compatibility_id,
                )
                .await?;
                cross_endpoint_self_test(reference.as_ref(), candidate.as_ref(), &context, U).await
            }
            .await;
            if outcome.is_ok() {
                seen.admitted.fetch_add(1, Ordering::SeqCst);
                if dirty.load(Ordering::SeqCst) {
                    seen.admitted_dirty.fetch_add(1, Ordering::SeqCst);
                }
            }
            outcome
        })
    })
}

async fn settle() {
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
}

/// Run one serving encrypt to its end, advancing the manual clock while it
/// waits (backoff, a cooling circuit, its deadline). `None` when it does
/// not end within `budget` of manual time.
async fn serve(
    set: &Arc<EndpointSet>,
    clock: &Arc<ManualClock>,
    unit: &mut u64,
    count: u64,
    budget: Duration,
) -> Option<Result<(), CryptoError>> {
    let items: Vec<PlaintextUnit> = (0..count)
        .map(|_| {
            *unit += 1;
            PlaintextUnit {
                unit_index: *unit,
                data: SecretBuffer::from_slice(&[(*unit as u8) ^ 0x5a; U]),
            }
        })
        .collect();
    let task = {
        let set = set.clone();
        tokio::spawn(async move {
            let out = set.encrypt_batch(&ctx(), &items).await?;
            let back = FakeCryptoProvider::new(U as u32)
                .decrypt_batch(&ctx(), &out)
                .await
                .expect("a served ciphertext decrypts under the volume key");
            assert_eq!(back.len(), items.len());
            for (got, sent) in back.iter().zip(&items) {
                assert_eq!(got.unit_index, sent.unit_index);
                assert_eq!(got.data, sent.data);
            }
            Ok(())
        })
    };
    let step = Duration::from_millis(5);
    let mut waited = Duration::ZERO;
    loop {
        settle().await;
        if task.is_finished() {
            return Some(task.await.expect("the serving task does not panic"));
        }
        if waited >= budget {
            task.abort();
            let _ = task.await;
            return None;
        }
        clock.advance(step);
        waited += step;
    }
}

struct Outcome {
    runs: usize,
    elapsed: Duration,
    admitted_after: Option<Duration>,
}

async fn one(seed: u64, deadline: Option<Duration>, retry_safe: bool) -> Result<Outcome, String> {
    let mut rng = StdRng::seed_from_u64(seed);
    let clock = Arc::new(ManualClock::new());
    let dirty = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(Validations {
        runs: AtomicUsize::new(0),
        admitted_dirty: AtomicUsize::new(0),
        admitted: AtomicUsize::new(0),
    });
    // The validated reference fails now and then (its breaker opens, real
    // requests fail over or back off); the candidate fails often.
    let reference_chaos = [0, 30, 150][rng.random_range(0..3)];
    let candidate_chaos = [100, 400, 900][rng.random_range(0..3)];
    let reference = Peer::new("reference", seed ^ 0xa, reference_chaos, dirty.clone());
    let candidate = Peer::new("candidate", seed ^ 0xb, candidate_chaos, dirty.clone());
    let set = Arc::new(
        EndpointSet::with_quarantine(
            vec![
                (
                    "reference".to_string(),
                    reference.clone() as Arc<dyn CryptoProvider>,
                    true,
                ),
                (
                    "candidate".to_string(),
                    candidate.clone() as Arc<dyn CryptoProvider>,
                    false,
                ),
            ],
            Some(validator(dirty.clone(), seen.clone())),
            cfg(deadline, retry_safe),
            clock.clone(),
        )
        .with_plaintext_size(U as u32),
    );
    let status = |name: &str| {
        set.endpoint_status()
            .into_iter()
            .find(|status| status.name == name)
            .unwrap()
    };
    let case = format!(
        "seed {seed} deadline {deadline:?} retry_safe {retry_safe} chaos {reference_chaos}/{candidate_chaos}"
    );
    let mut unit = SERVING;
    let check = |phase: &str| -> Result<(), String> {
        let candidate_status = status("candidate");
        if candidate_status.rejected {
            return Err(format!(
                "{case}: {phase}: excluded for the life of the set although nothing proved \
                 another contract: {candidate_status:?}"
            ));
        }
        if !candidate_status.validated && !candidate.served.lock().unwrap().is_empty() {
            return Err(format!(
                "{case}: {phase}: the quarantined candidate served {:?}",
                candidate.served.lock().unwrap()
            ));
        }
        if seen.admitted_dirty.load(Ordering::SeqCst) != 0 {
            return Err(format!(
                "{case}: {phase}: a validation in which an exchange failed returned success"
            ));
        }
        if candidate_status.validated && seen.admitted.load(Ordering::SeqCst) == 0 {
            return Err(format!(
                "{case}: {phase}: admitted without a successful validation"
            ));
        }
        Ok(())
    };

    // Phase 1: chaos.
    for _ in 0..rng.random_range(10..60) {
        match rng.random_range(0..3u32) {
            0 => clock.advance(Duration::from_millis(rng.random_range(0..2500))),
            _ => {
                let count = rng.random_range(1..4);
                // Under `stall` an operation may legitimately wait as long
                // as the reference keeps failing: bound the wait and go on.
                let _ = serve(&set, &clock, &mut unit, count, Duration::from_secs(20)).await;
            }
        }
        settle().await;
        check("chaos")?;
    }

    // Phase 2: every peer is healthy from now on. With traffic, the
    // candidate must be admitted within the backoff cap (plus the time the
    // reference's circuit needs to close), and nothing may stay in flight.
    reference.chaos.store(0, Ordering::SeqCst);
    candidate.chaos.store(0, Ordering::SeqCst);
    let healed = clock.now();
    let mut admitted_after = None;
    while clock.now().saturating_sub(healed) < CAP * 4 {
        match serve(&set, &clock, &mut unit, 1, Duration::from_secs(60)).await {
            Some(Ok(())) => {}
            Some(Err(error)) => {
                // An operation that began under chaos conditions can still
                // end with the reference's cooling circuit; a deadline is
                // fine too. Anything else is a healthy set that refuses.
                if deadline.is_none() {
                    return Err(format!("{case}: healthy peers, yet serving failed: {error}"));
                }
            }
            None => {
                return Err(format!(
                    "{case}: healthy peers, yet a request did not end in 60 s: {:?}",
                    set.endpoint_status()
                ))
            }
        }
        settle().await;
        check("healed")?;
        if status("candidate").validated {
            admitted_after = Some(clock.now().saturating_sub(healed));
            break;
        }
        clock.advance(Duration::from_millis(250));
    }
    if admitted_after.is_none() {
        return Err(format!(
            "{case}: every peer healthy for {:?} of traffic, the candidate is still quarantined: \
             {:?}, {} validations",
            CAP * 4,
            status("candidate"),
            seen.runs.load(Ordering::SeqCst)
        ));
    }
    // It serves now, and the set is idle between requests. Routing takes
    // the least loaded peer and the first listed one among equals, so only
    // concurrent requests reach the candidate.
    let before = candidate.served.lock().unwrap().len();
    for _ in 0..40 {
        let mut second = unit + 1_000_000;
        let (first, other) = tokio::join!(
            serve(&set, &clock, &mut unit, 1, Duration::from_secs(60)),
            serve(&set, &clock, &mut second, 1, Duration::from_secs(60)),
        );
        for outcome in [first, other] {
            match outcome {
                Some(Ok(())) => {}
                other => {
                    return Err(format!(
                        "{case}: admitted and healthy, yet serving ended with {:?}",
                        other.map(|result| result.map_err(|error| error.to_string()))
                    ))
                }
            }
        }
        clock.advance(Duration::from_millis(300));
    }
    settle().await;
    if candidate.served.lock().unwrap().len() == before {
        return Err(format!("{case}: the admitted candidate never serves"));
    }
    if set.global_inflight() != (0, 0)
        || set
            .endpoint_inflight()
            .iter()
            .any(|(_, inflight)| *inflight != 0)
    {
        return Err(format!(
            "{case}: idle set holds permits: global {:?}, endpoints {:?}",
            set.global_inflight(),
            set.endpoint_inflight()
        ));
    }
    for (name, state) in set.endpoint_states() {
        if state != CircuitState::Closed {
            return Err(format!(
                "{case}: {name}'s circuit is {state:?} after 40 healthy requests over 12 s"
            ));
        }
    }
    check("end")?;
    Ok(Outcome {
        runs: seen.runs.load(Ordering::SeqCst),
        elapsed: clock.now(),
        admitted_after,
    })
}

async fn sweep(seeds: std::ops::Range<u64>, deadline: Option<Duration>, retry_safe: bool) {
    let mut failures = Vec::new();
    let mut slowest = Duration::ZERO;
    let mut densest = 0f64;
    for seed in seeds.clone() {
        match one(seed, deadline, retry_safe).await {
            Ok(outcome) => {
                slowest = slowest.max(outcome.admitted_after.unwrap());
                // No spin: an inconclusive validation is not repeated before
                // the validation interval has passed.
                let allowed = (outcome.elapsed.as_secs_f64() / INTERVAL.as_secs_f64()) + 2.0;
                densest = densest.max(outcome.runs as f64 / allowed);
                if outcome.runs as f64 > allowed {
                    failures.push(format!(
                        "seed {seed}: {} validations in {:?} (interval {INTERVAL:?})",
                        outcome.runs, outcome.elapsed
                    ));
                }
            }
            Err(failure) => failures.push(failure),
        }
    }
    println!(
        "audit8 revalidation sweep deadline {deadline:?} retry_safe {retry_safe}: {} seeds, \
         slowest admission after healing {slowest:?}, densest validation rate {densest:.2} of \
         the allowed one, {} failures",
        seeds.end - seeds.start,
        failures.len()
    );
    for failure in failures.iter().take(12) {
        println!("  {failure}");
    }
    assert!(failures.is_empty(), "{} failing seeds", failures.len());
}

#[tokio::test]
async fn audit8_stall_policy_retry_safe() {
    sweep(0..150, None, true).await;
}

#[tokio::test]
async fn audit8_bounded_error_retry_safe() {
    sweep(1000..1150, Some(Duration::from_secs(2)), true).await;
}

#[tokio::test]
async fn audit8_bounded_error_not_retry_safe() {
    sweep(2000..2150, Some(Duration::from_secs(2)), false).await;
}
