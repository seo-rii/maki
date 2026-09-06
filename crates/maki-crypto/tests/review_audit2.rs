//! Regression tests for the second audit's crypto-layer findings (C-series
//! in the remediation log): breaker wedge, permit and breaker accounting on
//! a deadline-abandoned RPC, quarantine validation off the request path,
//! several batches in flight per lane, echo/no-binding providers failing
//! the self-test, item-accurate pending limits, and decrypt length pinned
//! to the volume's unit size.

#![allow(clippy::await_holding_lock)]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use maki_crypto::breaker::{BreakerConfig, CircuitBreaker, CircuitState};
use maki_crypto::checked::CheckedProvider;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet, EndpointValidator};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::scheduler::{BatchScheduler, SchedulerConfig};
use maki_crypto::selftest::provider_self_test;
use maki_crypto::{
    Capability, CiphertextUnit, Clock, CryptoCapabilities, CryptoContext, CryptoError,
    CryptoProvider, PlaintextUnit, SecretBuffer,
};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::ManualClock;

const UNIT: usize = 256;

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0xA2),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".to_string(),
    }
}

fn pt(i: u64) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: i,
        data: SecretBuffer::from_slice(&vec![i as u8; UNIT]),
    }
}

fn fake() -> Arc<FakeCryptoProvider> {
    Arc::new(FakeCryptoProvider::new(UNIT as u32))
}

async fn settle() {
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}

fn breaker_cfg(failure_threshold: u32) -> BreakerConfig {
    BreakerConfig {
        failure_threshold,
        open_initial: Duration::from_millis(10),
        open_max: Duration::from_millis(100),
        half_open_max_requests: 1,
        success_threshold: 1,
    }
}

fn dispatch_cfg(max_operation_time: Option<Duration>, breaker: BreakerConfig) -> DispatchConfig {
    DispatchConfig {
        retry: RetryPolicy {
            initial_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(50),
        },
        budget: RetryBudgetConfig {
            retry_ratio: 1.0,
            burst: 16,
            min_probe_per_sec: 1.0,
        },
        breaker,
        global_max_inflight_batches: 8,
        global_max_inflight_bytes: 8 << 20,
        per_endpoint_max_inflight: 4,
        per_endpoint_max_bytes: 4 << 20,
        max_attempts: None,
        max_operation_time,
        retry_safe: true,
        validation_interval: Duration::from_millis(100),
    }
}

// ---------- C-07: half-open breaker must not wedge ----------

/// `success_threshold` above `half_open_max_requests` used to admit one
/// probe, count its success, and then admit nothing ever again: the probe
/// slots were never returned when a probe completed.
#[test]
fn half_open_admits_new_probes_as_earlier_ones_complete() {
    let clock = Arc::new(ManualClock::new());
    let breaker = CircuitBreaker::new(
        BreakerConfig {
            failure_threshold: 1,
            open_initial: Duration::from_millis(10),
            open_max: Duration::from_millis(100),
            half_open_max_requests: 1,
            success_threshold: 2,
        },
        clock.clone(),
    );
    breaker.on_failure();
    assert_eq!(breaker.state(), CircuitState::Open);
    clock.advance(Duration::from_millis(20));
    assert!(breaker.allow(), "first probe");
    breaker.on_success();
    assert_eq!(breaker.state(), CircuitState::HalfOpen);
    assert!(
        breaker.would_allow() && breaker.allow(),
        "second probe refused although the first completed: breaker wedged"
    );
    breaker.on_success();
    assert_eq!(breaker.state(), CircuitState::Closed);
}

/// A failed probe reopens the circuit and a later probe is admitted again.
#[test]
fn failed_probe_reopens_and_the_next_window_admits_again() {
    let clock = Arc::new(ManualClock::new());
    let breaker = CircuitBreaker::new(breaker_cfg(1), clock.clone());
    breaker.on_failure();
    clock.advance(Duration::from_millis(20));
    assert!(breaker.allow());
    breaker.on_failure();
    assert_eq!(breaker.state(), CircuitState::Open);
    assert!(!breaker.allow());
    clock.advance(Duration::from_millis(200));
    assert!(breaker.allow(), "probe after the reopened window");
    breaker.on_success();
    assert_eq!(breaker.state(), CircuitState::Closed);
}

// ---------- C-06: deadline-abandoned RPC ----------

/// The RPC future dropped at the deadline used to skip the inflight
/// decrement (a permanent drift in `endpoint_inflight`) and the deadline
/// was charged to whichever endpoint happened to be in flight, opening its
/// circuit for a budget the *operation* ran out of.
#[tokio::test]
async fn deadline_abandoned_rpc_releases_inflight_and_does_not_charge_the_breaker() {
    let clock = Arc::new(ManualClock::new());
    let slow = fake();
    slow.set_latency(clock.clone(), Duration::from_secs(10));
    let set = Arc::new(EndpointSet::new(
        vec![("slow".to_string(), slow.clone() as Arc<dyn CryptoProvider>)],
        dispatch_cfg(Some(Duration::from_millis(100)), breaker_cfg(1)),
        clock.clone(),
    ));
    let task = {
        let set = set.clone();
        tokio::spawn(async move { set.encrypt_batch(&ctx(), &[pt(1)]).await })
    };
    settle().await;
    assert_eq!(set.endpoint_inflight()[0].1, 1, "RPC in flight");
    clock.advance(Duration::from_millis(200));
    settle().await;
    let err = task.await.unwrap().unwrap_err();
    assert!(err.is_retryable(), "{err}");
    assert_eq!(
        set.endpoint_inflight()[0].1,
        0,
        "inflight leaked past the deadline"
    );
    assert_eq!(
        set.endpoint_status()[0].circuit,
        CircuitState::Closed,
        "operation deadline charged to the endpoint's breaker"
    );
    assert_eq!(set.metrics().deadline_exceeded_total(), 1);
}

// ---------- C-03: quarantine validation off the request path ----------

/// Validating a quarantined endpoint ran inline in every request, with no
/// deadline: a black-holed endpoint stalled every request behind its
/// transport timeout, roughly once per validation interval, forever.
#[tokio::test]
async fn quarantined_endpoint_validation_never_blocks_requests() {
    let clock = Arc::new(ManualClock::new());
    let a = fake();
    let b = fake();
    let validator: EndpointValidator = Arc::new({
        let clock = clock.clone();
        move |_reference, _candidate, _context| {
            let clock = clock.clone();
            Box::pin(async move {
                clock.sleep(Duration::from_secs(10)).await;
                Ok(())
            })
        }
    });
    let set = Arc::new(EndpointSet::with_quarantine(
        vec![
            ("a".to_string(), a.clone() as Arc<dyn CryptoProvider>, true),
            ("b".to_string(), b.clone() as Arc<dyn CryptoProvider>, false),
        ],
        Some(validator),
        dispatch_cfg(None, breaker_cfg(3)),
        clock.clone(),
    ));
    let task = {
        let set = set.clone();
        tokio::spawn(async move { set.encrypt_batch(&ctx(), &[pt(1)]).await })
    };
    settle().await;
    assert!(
        task.is_finished(),
        "request waited for the quarantined endpoint's validation"
    );
    task.await.unwrap().unwrap();
    assert!(
        !set.endpoint_status()
            .iter()
            .any(|s| s.name == "b" && s.validated),
        "validated without the validator having finished"
    );
    // The validation still completes on its own and admits the endpoint.
    clock.advance(Duration::from_secs(11));
    settle().await;
    assert!(
        set.endpoint_status()
            .iter()
            .any(|s| s.name == "b" && s.validated),
        "background validation never admitted the endpoint"
    );
}

// ---------- C-04: several batches in flight per lane ----------

fn scheduler_cfg(target_items: usize, max_inflight_batches: u32) -> SchedulerConfig {
    SchedulerConfig {
        target_items,
        target_bytes: 1 << 20,
        max_items: 16,
        max_bytes: 1 << 20,
        max_wait: Duration::from_millis(5),
        max_pending_items: 64,
        max_pending_plaintext_bytes: 1 << 20,
        max_pending_ciphertext_bytes: 1 << 20,
        max_inflight_batches,
    }
}

/// The lane awaited each provider call inline: one batch per round trip
/// per lane, so the configured inflight limits were unreachable and one
/// stalled batch blocked every request behind it.
#[tokio::test]
async fn lane_keeps_several_batches_in_flight() {
    let clock = Arc::new(ManualClock::new());
    let provider = fake();
    provider.set_latency(clock.clone(), Duration::from_secs(1));
    let scheduler = Arc::new(BatchScheduler::new(
        provider.clone(),
        scheduler_cfg(1, 4),
        clock.clone(),
    ));
    let tasks: Vec<_> = (0..4u64)
        .map(|i| {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.encrypt_batch(&ctx(), &[pt(i)]).await })
        })
        .collect();
    settle().await;
    assert!(
        provider.max_concurrent_calls() >= 2,
        "lane serializes provider calls ({} in flight)",
        provider.max_concurrent_calls()
    );
    clock.advance(Duration::from_secs(1));
    settle().await;
    for task in tasks {
        assert!(task.is_finished(), "batches did not overlap");
        task.await.unwrap().unwrap();
    }
}

/// The inflight limit is honoured: with one slot the calls do serialize.
#[tokio::test]
async fn lane_honours_its_inflight_limit() {
    let clock = Arc::new(ManualClock::new());
    let provider = fake();
    provider.set_latency(clock.clone(), Duration::from_secs(1));
    let scheduler = Arc::new(BatchScheduler::new(
        provider.clone(),
        scheduler_cfg(1, 1),
        clock.clone(),
    ));
    let tasks: Vec<_> = (0..3u64)
        .map(|i| {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.encrypt_batch(&ctx(), &[pt(i)]).await })
        })
        .collect();
    settle().await;
    assert_eq!(provider.max_concurrent_calls(), 1);
    for _ in 0..3 {
        clock.advance(Duration::from_secs(1));
        settle().await;
    }
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    assert_eq!(provider.max_concurrent_calls(), 1);
}

// ---------- C-10: pending limit counts items ----------

/// `max_pending_items` took one permit per *request*; a request of eight
/// items counted as one, so the bound was eight times looser than stated.
/// Batch formation is held back (large target, a manual clock that never
/// reaches `max_wait`) so every admitted item stays queued and countable.
#[tokio::test]
async fn pending_item_limit_counts_items_not_requests() {
    let clock = Arc::new(ManualClock::new());
    let provider = fake();
    let mut cfg = scheduler_cfg(16, 4);
    cfg.max_pending_items = 4;
    let scheduler = Arc::new(BatchScheduler::new(provider.clone(), cfg, clock.clone()));
    let first = {
        let scheduler = scheduler.clone();
        tokio::spawn(async move { scheduler.encrypt_batch(&ctx(), &[pt(100)]).await })
    };
    settle().await;
    assert_eq!(scheduler.stats().pending_items(), 1);
    // Four more items need four permits; only three are free, so the
    // request must wait at admission instead of joining the queue.
    let four: Vec<PlaintextUnit> = (0..4).map(pt).collect();
    let second = {
        let scheduler = scheduler.clone();
        tokio::spawn(async move { scheduler.encrypt_batch(&ctx(), &four).await })
    };
    settle().await;
    assert_eq!(
        scheduler.stats().pending_items(),
        1,
        "a four-item request was admitted past max_pending_items = 4 with one item queued"
    );
    // `max_wait` flushes the first batch, its permit returns, the second
    // request is admitted and flushed in turn.
    for _ in 0..4 {
        clock.advance(Duration::from_millis(10));
        settle().await;
    }
    for task in [first, second] {
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("request hung")
            .unwrap()
            .unwrap();
    }
    assert_eq!(scheduler.stats().pending_items(), 0);
}

// ---------- C-09: self-test rejects pass-through and unbound providers ----------

/// Returns the plaintext as "ciphertext" and back.
struct Echo(Arc<FakeCryptoProvider>);

#[async_trait]
impl CryptoProvider for Echo {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        let mut caps = self.0.capabilities().await?;
        caps.integrity = Capability::Absent;
        caps.context_binding = Capability::Absent;
        Ok(caps)
    }
    async fn encrypt_batch(
        &self,
        _context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        Ok(items
            .iter()
            .map(|p| CiphertextUnit {
                unit_index: p.unit_index,
                data: p.data.expose().to_vec(),
            })
            .collect())
    }
    async fn decrypt_batch(
        &self,
        _context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        Ok(items
            .iter()
            .map(|c| PlaintextUnit {
                unit_index: c.unit_index,
                data: SecretBuffer::from_slice(&c.data),
            })
            .collect())
    }
}

/// A provider in pass-through mode round-trips perfectly; attaching it
/// would persist plaintext. The self-test must notice.
#[tokio::test]
async fn self_test_rejects_a_pass_through_provider() {
    let echo = Echo(fake());
    let err = provider_self_test(&echo, &ctx(), UNIT, "test-profile-v1")
        .await
        .expect_err("echo provider passed the self-test");
    assert!(matches!(err, CryptoError::ProviderFatal(_)), "{err}");
}

/// Claims context binding but ignores the context.
struct ClaimsBinding(Arc<FakeCryptoProvider>);

#[async_trait]
impl CryptoProvider for ClaimsBinding {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        let mut caps = self.0.capabilities().await?;
        caps.context_binding = Capability::Contractual;
        Ok(caps)
    }
    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.0.encrypt_batch(context, items).await
    }
    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.0.decrypt_batch(context, items).await
    }
}

/// A claimed capability must be exercised, not trusted.
#[tokio::test]
async fn self_test_checks_a_claimed_context_binding() {
    let unbound = Arc::new(
        FakeCryptoProvider::new(UNIT as u32)
            .with_context_binding(false)
            .with_integrity_check(false),
    );
    let err = provider_self_test(&ClaimsBinding(unbound), &ctx(), UNIT, "test-profile-v1")
        .await
        .expect_err("unbound provider claiming context binding passed");
    assert!(matches!(err, CryptoError::ProviderFatal(_)), "{err}");
    // A provider that really binds still passes.
    let bound = FakeCryptoProvider::new(UNIT as u32).with_context_binding(true);
    provider_self_test(&bound, &ctx(), UNIT, "test-profile-v1")
        .await
        .unwrap();
}

// ---------- C-08: decrypt length pinned to the unit size ----------

/// Declares two plaintext sizes and returns the smaller one.
struct ShortDecrypt(Arc<FakeCryptoProvider>);

#[async_trait]
impl CryptoProvider for ShortDecrypt {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        let mut caps = self.0.capabilities().await?;
        caps.supported_plaintext_sizes.push(UNIT as u32 / 2);
        Ok(caps)
    }
    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.0.encrypt_batch(context, items).await
    }
    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        let pts = self.0.decrypt_batch(context, items).await?;
        Ok(pts
            .into_iter()
            .map(|p| PlaintextUnit {
                unit_index: p.unit_index,
                data: SecretBuffer::from_slice(&p.data.expose()[..UNIT / 2]),
            })
            .collect())
    }
}

/// "A supported size" is not the contract; the volume's unit size is.
#[tokio::test]
async fn checked_provider_pins_decrypt_length_to_the_unit_size() {
    let inner: Arc<dyn CryptoProvider> = Arc::new(ShortDecrypt(fake()));
    let checked = CheckedProvider::pinned(inner, UNIT as u32);
    let cts = checked.encrypt_batch(&ctx(), &[pt(1)]).await.unwrap();
    let err = checked
        .decrypt_batch(&ctx(), &cts)
        .await
        .expect_err("short plaintext accepted");
    assert!(matches!(err, CryptoError::Contract(_)), "{err}");
}
