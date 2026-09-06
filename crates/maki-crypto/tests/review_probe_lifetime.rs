//! BUG-004: every admitted probe must release its slot, even when the
//! operation finishes without an endpoint success/failure verdict.

use std::sync::Arc;
use std::time::Duration;

use maki_crypto::breaker::{BreakerConfig, CircuitState};
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{CryptoContext, CryptoError, CryptoProvider, PlaintextUnit, SecretBuffer};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::ManualClock;

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(5),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".into(),
    }
}

fn plaintext() -> PlaintextUnit {
    PlaintextUnit {
        unit_index: 1,
        data: SecretBuffer::zeroed(64),
    }
}

fn config() -> DispatchConfig {
    DispatchConfig {
        retry: RetryPolicy {
            initial_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        },
        budget: RetryBudgetConfig {
            retry_ratio: 1.0,
            burst: 16,
            min_probe_per_sec: 1.0,
        },
        breaker: BreakerConfig {
            failure_threshold: 1,
            open_initial: Duration::from_millis(10),
            open_max: Duration::from_millis(100),
            half_open_max_requests: 1,
            success_threshold: 1,
        },
        global_max_inflight_batches: 8,
        global_max_inflight_bytes: 1 << 20,
        per_endpoint_max_inflight: 8,
        per_endpoint_max_bytes: 1 << 20,
        max_attempts: Some(1),
        max_operation_time: Some(Duration::from_millis(100)),
        retry_safe: true,
        validation_interval: Duration::from_millis(10),
    }
}

async fn open_breaker() -> (Arc<ManualClock>, Arc<FakeCryptoProvider>, Arc<EndpointSet>) {
    let clock = Arc::new(ManualClock::new());
    let provider = Arc::new(FakeCryptoProvider::new(64));
    let set = Arc::new(EndpointSet::new(
        vec![("only".into(), provider.clone())],
        config(),
        clock.clone(),
    ));
    provider.fail_next([CryptoError::Retryable("outage".into())]);
    assert!(set.encrypt_batch(&context(), &[plaintext()]).await.is_err());
    assert_eq!(set.endpoint_status()[0].circuit, CircuitState::Open);
    clock.advance(Duration::from_millis(20));
    (clock, provider, set)
}

async fn assert_recovers(provider: &FakeCryptoProvider, set: &EndpointSet) {
    assert_eq!(set.endpoint_inflight()[0].1, 0);
    assert_eq!(set.endpoint_status()[0].circuit, CircuitState::HalfOpen);
    let calls = provider.encrypt_calls();
    set.encrypt_batch(&context(), &[plaintext()])
        .await
        .expect("a neutral probe outcome must leave a slot for a healthy request");
    assert_eq!(provider.encrypt_calls(), calls + 1);
    assert_eq!(set.endpoint_status()[0].circuit, CircuitState::Closed);
}

#[tokio::test]
async fn request_error_releases_half_open_slot() {
    let (_clock, provider, set) = open_breaker().await;
    provider.fail_next([CryptoError::NonRetryableRequest("invalid request".into())]);
    assert!(matches!(
        set.encrypt_batch(&context(), &[plaintext()]).await,
        Err(CryptoError::NonRetryableRequest(_))
    ));
    assert_recovers(&provider, &set).await;
}

#[tokio::test]
async fn provider_error_releases_half_open_slot() {
    let (_clock, provider, set) = open_breaker().await;
    provider.fail_next([CryptoError::ProviderFatal("bad profile".into())]);
    assert!(matches!(
        set.encrypt_batch(&context(), &[plaintext()]).await,
        Err(CryptoError::ProviderFatal(_))
    ));
    assert_recovers(&provider, &set).await;
}

async fn settle() {
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn deadline_releases_half_open_slot_without_charging_a_failure() {
    let (clock, provider, set) = open_breaker().await;
    provider.set_latency(clock.clone(), Duration::from_secs(10));
    let task = tokio::spawn({
        let set = set.clone();
        async move { set.encrypt_batch(&context(), &[plaintext()]).await }
    });
    settle().await;
    assert_eq!(set.endpoint_inflight()[0].1, 1);
    clock.advance(Duration::from_millis(101));
    settle().await;
    assert!(
        task.is_finished(),
        "operation deadline must finish the probe"
    );
    assert!(task
        .await
        .unwrap()
        .unwrap_err()
        .to_string()
        .contains("deadline"));
    provider.set_latency(clock, Duration::ZERO);
    assert_recovers(&provider, &set).await;
}

#[tokio::test]
async fn cancelled_operation_releases_half_open_slot() {
    let (clock, provider, set) = open_breaker().await;
    provider.set_latency(clock.clone(), Duration::from_secs(10));
    let task = tokio::spawn({
        let set = set.clone();
        async move { set.encrypt_batch(&context(), &[plaintext()]).await }
    });
    settle().await;
    assert_eq!(set.endpoint_inflight()[0].1, 1);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    provider.set_latency(clock, Duration::ZERO);
    assert_recovers(&provider, &set).await;
}

#[tokio::test]
async fn exhausted_retry_budget_does_not_consume_a_half_open_slot() {
    let clock = Arc::new(ManualClock::new());
    let provider = Arc::new(FakeCryptoProvider::new(64));
    let mut config = config();
    config.max_attempts = Some(2);
    config.breaker.open_initial = Duration::ZERO;
    config.budget.retry_ratio = 0.0;
    config.budget.min_probe_per_sec = 0.0;
    let set = EndpointSet::new(vec![("only".into(), provider.clone())], config, clock);
    provider.fail_next([CryptoError::Retryable("outage".into())]);
    assert!(set.encrypt_batch(&context(), &[plaintext()]).await.is_err());
    assert_eq!(
        provider.encrypt_calls(),
        1,
        "retry budget refuses the resend"
    );
    assert_recovers(&provider, &set).await;
}
