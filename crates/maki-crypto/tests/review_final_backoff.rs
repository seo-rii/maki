//! BUG-158: backoff separates attempts; it does not delay an exhausted result.

use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::Poll,
    time::Duration,
};

use maki_crypto::{
    breaker::BreakerConfig,
    clock::{Clock, SleepFuture},
    endpoint::{DispatchConfig, EndpointSet},
    retry::{RetryBudgetConfig, RetryPolicy},
    CryptoContext, CryptoError, CryptoProvider, PlaintextUnit, SecretBuffer,
};
use maki_test_support::{fake_provider::FakeCryptoProvider, ManualClock};

const UNIT: usize = 512;

#[derive(Default)]
struct CountingClock {
    manual: ManualClock,
    sleeps: AtomicUsize,
}

impl Clock for CountingClock {
    fn now(&self) -> Duration {
        self.manual.now()
    }

    fn sleep(&self, duration: Duration) -> SleepFuture {
        // Count even a zero-duration jitter draw, so the regression does
        // not depend on randomness producing a positive delay.
        self.sleeps.fetch_add(1, Ordering::SeqCst);
        self.manual.sleep(duration)
    }
}

fn config(attempts: Option<u32>) -> DispatchConfig {
    DispatchConfig {
        retry: RetryPolicy {
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(1),
        },
        budget: RetryBudgetConfig {
            retry_ratio: 4.0,
            burst: 16,
            min_probe_per_sec: 0.0,
        },
        breaker: BreakerConfig::default(),
        global_max_inflight_batches: 1,
        global_max_inflight_bytes: 4096,
        per_endpoint_max_inflight: 1,
        per_endpoint_max_bytes: 4096,
        max_attempts: attempts,
        max_operation_time: None,
        retry_safe: true,
        validation_interval: Duration::from_secs(1),
    }
}

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(158),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".into(),
    }
}

fn plaintext() -> Vec<PlaintextUnit> {
    vec![PlaintextUnit {
        unit_index: 1,
        data: SecretBuffer::zeroed(UNIT),
    }]
}

fn failure() -> CryptoError {
    CryptoError::Retryable("ordinary provider failure".into())
}

async fn poll_once<F: Future + ?Sized>(mut future: Pin<&mut F>) -> Poll<F::Output> {
    std::future::poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx))).await
}

async fn drive<F: Future>(future: F, clock: &CountingClock) -> F::Output {
    let mut future = Box::pin(future);
    for _ in 0..4 {
        if let Poll::Ready(result) = poll_once(future.as_mut()).await {
            return result;
        }
        clock.manual.advance(Duration::from_secs(1));
    }
    panic!("request did not finish within its configured passes");
}

#[tokio::test]
async fn last_encrypt_attempt_returns_error_without_sleeping() {
    let provider = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    provider.fail_next([failure()]);
    let clock = Arc::new(CountingClock::default());
    let endpoints = EndpointSet::new(
        vec![("only".into(), provider.clone())],
        config(Some(1)),
        clock.clone(),
    );
    let context = context();
    let input = plaintext();
    let mut request = Box::pin(endpoints.encrypt_batch(&context, &input));
    let result = poll_once(request.as_mut()).await;
    assert_eq!(provider.encrypt_calls(), 1);
    assert_eq!(clock.sleeps.load(Ordering::SeqCst), 0);
    assert!(
        matches!(result, Poll::Ready(Err(CryptoError::Retryable(message))) if message == "ordinary provider failure")
    );
}

#[tokio::test]
async fn last_decrypt_attempt_returns_error_without_sleeping() {
    let provider = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let context = context();
    let ciphertext = provider
        .encrypt_batch(&context, &plaintext())
        .await
        .unwrap();
    provider.fail_next([failure()]);
    let clock = Arc::new(CountingClock::default());
    let endpoints = EndpointSet::new(
        vec![("only".into(), provider.clone())],
        config(Some(1)),
        clock.clone(),
    );
    let mut request = Box::pin(endpoints.decrypt_batch(&context, &ciphertext));
    let result = poll_once(request.as_mut()).await;
    assert_eq!(provider.decrypt_calls(), 1);
    assert_eq!(clock.sleeps.load(Ordering::SeqCst), 0);
    assert!(matches!(
        result,
        Poll::Ready(Err(CryptoError::Retryable(_)))
    ));
}

#[tokio::test]
async fn all_peers_are_tried_in_the_last_pass_without_a_final_backoff() {
    let a = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let b = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    a.fail_next([failure()]);
    b.fail_next([failure()]);
    let clock = Arc::new(CountingClock::default());
    let endpoints = EndpointSet::new(
        vec![("a".into(), a.clone()), ("b".into(), b.clone())],
        config(Some(1)),
        clock.clone(),
    );
    assert!(
        drive(endpoints.encrypt_batch(&context(), &plaintext()), &clock)
            .await
            .is_err()
    );
    assert_eq!(a.encrypt_calls(), 1);
    assert_eq!(b.encrypt_calls(), 1);
    assert_eq!(clock.sleeps.load(Ordering::SeqCst), 0);
    assert_eq!(endpoints.metrics().failovers_total(), 1);
}

#[tokio::test]
async fn two_failed_passes_have_exactly_one_backoff() {
    let provider = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    provider.fail_next([failure(), failure()]);
    let clock = Arc::new(CountingClock::default());
    let endpoints = EndpointSet::new(
        vec![("only".into(), provider.clone())],
        config(Some(2)),
        clock.clone(),
    );
    assert!(
        drive(endpoints.encrypt_batch(&context(), &plaintext()), &clock)
            .await
            .is_err()
    );
    assert_eq!(provider.encrypt_calls(), 2);
    assert_eq!(clock.sleeps.load(Ordering::SeqCst), 1);
    assert_eq!(endpoints.metrics().retries_total(), 1);
}

#[tokio::test]
async fn exhausted_pass_with_no_admissible_peer_returns_the_last_error() {
    let provider = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    provider.fail_next([failure()]);
    let clock = Arc::new(CountingClock::default());
    let mut config = config(Some(2));
    config.breaker.failure_threshold = 1;
    config.breaker.open_initial = Duration::from_secs(30);
    config.breaker.open_max = Duration::from_secs(30);
    let endpoints = EndpointSet::new(
        vec![("only".into(), provider.clone())],
        config,
        clock.clone(),
    );
    let result = drive(endpoints.encrypt_batch(&context(), &plaintext()), &clock).await;
    assert!(
        matches!(result, Err(CryptoError::Retryable(message)) if message == "ordinary provider failure")
    );
    assert_eq!(provider.encrypt_calls(), 1);
    assert_eq!(clock.sleeps.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn unlimited_policy_keeps_backoff_and_recovers_on_a_later_attempt() {
    let provider = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    provider.fail_next([failure(), failure()]);
    let clock = Arc::new(CountingClock::default());
    let endpoints = EndpointSet::new(
        vec![("only".into(), provider.clone())],
        config(None),
        clock.clone(),
    );
    drive(endpoints.encrypt_batch(&context(), &plaintext()), &clock)
        .await
        .unwrap();
    assert_eq!(provider.encrypt_calls(), 3);
    assert_eq!(clock.sleeps.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn zero_attempt_limit_neither_calls_nor_sleeps() {
    let provider = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let clock = Arc::new(CountingClock::default());
    let endpoints = EndpointSet::new(
        vec![("only".into(), provider.clone())],
        config(Some(0)),
        clock.clone(),
    );
    assert!(endpoints
        .encrypt_batch(&context(), &plaintext())
        .await
        .is_err());
    assert_eq!(provider.encrypt_calls(), 0);
    assert_eq!(clock.sleeps.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn successful_last_attempt_does_not_sleep() {
    let provider = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let clock = Arc::new(CountingClock::default());
    let endpoints = EndpointSet::new(
        vec![("only".into(), provider.clone())],
        config(Some(1)),
        clock.clone(),
    );
    endpoints
        .encrypt_batch(&context(), &plaintext())
        .await
        .unwrap();
    assert_eq!(provider.encrypt_calls(), 1);
    assert_eq!(clock.sleeps.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn operation_deadline_does_not_delay_an_already_exhausted_result() {
    let provider = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    provider.fail_next([failure()]);
    let clock = Arc::new(CountingClock::default());
    let mut config = config(Some(1));
    config.max_operation_time = Some(Duration::from_secs(60));
    let endpoints = EndpointSet::new(
        vec![("only".into(), provider.clone())],
        config,
        clock.clone(),
    );
    let context = context();
    let input = plaintext();
    let mut request = Box::pin(endpoints.encrypt_batch(&context, &input));
    let result = poll_once(request.as_mut()).await;
    assert!(
        matches!(result, Poll::Ready(Err(CryptoError::Retryable(message))) if message == "ordinary provider failure")
    );
    assert_eq!(provider.encrypt_calls(), 1);
    assert_eq!(clock.now(), Duration::ZERO);
    assert_eq!(endpoints.metrics().deadline_exceeded_total(), 0);
}

#[tokio::test]
async fn final_inflight_attempt_still_obeys_the_operation_deadline() {
    let provider = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let clock = Arc::new(CountingClock::default());
    provider.set_latency(clock.clone(), Duration::from_secs(1));
    let mut config = config(Some(1));
    config.max_operation_time = Some(Duration::from_millis(100));
    let endpoints = EndpointSet::new(
        vec![("only".into(), provider.clone())],
        config,
        clock.clone(),
    );
    let context = context();
    let input = plaintext();
    let mut request = Box::pin(endpoints.encrypt_batch(&context, &input));
    assert!(poll_once(request.as_mut()).await.is_pending());
    clock.manual.advance(Duration::from_millis(100));
    let result = poll_once(request.as_mut()).await;
    assert!(
        matches!(result, Poll::Ready(Err(CryptoError::Retryable(message))) if message == "operation deadline exceeded")
    );
    assert_eq!(provider.encrypt_calls(), 1);
    assert_eq!(endpoints.metrics().deadline_exceeded_total(), 1);
    assert_eq!(clock.manual.sleeper_count(), 0);
}
