//! BUG-086: waiting for the first RPC must follow breaker readiness.

use async_trait::async_trait;
use maki_crypto::{
    breaker::{BreakerConfig, CircuitState},
    endpoint::{DispatchConfig, EndpointSet},
    retry::{RetryBudgetConfig, RetryPolicy},
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit,
    SecretBuffer,
};
use maki_test_support::{FakeCryptoProvider, ManualClock};
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
use tokio::sync::Notify;

const UNIT: u32 = 64;

struct Peer {
    inner: FakeCryptoProvider,
    calls: AtomicUsize,
    release: Notify,
}

impl Peer {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: FakeCryptoProvider::new(UNIT),
            calls: AtomicUsize::new(0),
            release: Notify::new(),
        })
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
        self.calls.fetch_add(1, Ordering::SeqCst);
        if items[0].unit_index == 1 {
            self.release.notified().await;
        }
        self.inner.encrypt_batch(context, items).await
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.inner.decrypt_batch(context, items).await
    }
}

fn config() -> DispatchConfig {
    DispatchConfig {
        retry: RetryPolicy {
            initial_delay: Duration::from_secs(30),
            max_delay: Duration::from_secs(30),
        },
        budget: RetryBudgetConfig {
            retry_ratio: 1.0,
            burst: 16,
            min_probe_per_sec: 1.0,
        },
        breaker: BreakerConfig {
            failure_threshold: 1,
            open_initial: Duration::from_secs(1),
            open_max: Duration::from_secs(30),
            half_open_max_requests: 1,
            success_threshold: 1,
        },
        global_max_inflight_batches: 2,
        global_max_inflight_bytes: 4096,
        per_endpoint_max_inflight: 2,
        per_endpoint_max_bytes: 4096,
        // With one pass the old implementation can never succeed after
        // entering backoff, irrespective of the random delay it samples.
        max_attempts: Some(1),
        max_operation_time: Some(Duration::from_secs(10)),
        retry_safe: false,
        validation_interval: Duration::from_secs(1),
    }
}

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(86),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".into(),
    }
}

fn plaintext(unit_index: u64) -> [PlaintextUnit; 1] {
    [PlaintextUnit {
        unit_index,
        data: SecretBuffer::zeroed(UNIT as usize),
    }]
}

async fn poll<F: Future + ?Sized>(mut future: Pin<&mut F>) -> Poll<F::Output> {
    std::future::poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx))).await
}

async fn open_breaker() -> (Arc<ManualClock>, Arc<Peer>, EndpointSet) {
    let clock = Arc::new(ManualClock::new());
    let peer = Peer::new();
    let set = EndpointSet::new(vec![("only".into(), peer.clone())], config(), clock.clone());
    peer.inner
        .fail_next([CryptoError::Retryable("one-shot outage".into())]);
    assert!(set.encrypt_batch(&context(), &plaintext(0)).await.is_err());
    assert_eq!(set.endpoint_states()[0].1, CircuitState::Open);
    (clock, peer, set)
}

#[tokio::test]
async fn first_rpc_waits_for_open_cooldown_without_consuming_a_retry_pass() {
    let (clock, peer, set) = open_breaker().await;
    let context = context();
    let items = plaintext(2);
    let mut waiting = Box::pin(set.encrypt_batch(&context, &items));
    assert!(poll(waiting.as_mut()).await.is_pending());
    assert_eq!(set.global_inflight(), (0, 0));
    assert_eq!(peer.calls.load(Ordering::SeqCst), 1);
    clock.advance(Duration::from_secs(1));
    assert!(
        matches!(poll(waiting.as_mut()).await, Poll::Ready(Ok(_))),
        "cooldown expiry should admit the first RPC before its deadline"
    );
    assert_eq!(peer.calls.load(Ordering::SeqCst), 2);
    assert_eq!(set.metrics().retries_total(), 0);
    assert_eq!(set.endpoint_states()[0].1, CircuitState::Closed);
}

async fn half_open_return(cancel: bool) {
    let (clock, peer, set) = open_breaker().await;
    clock.advance(Duration::from_secs(1));
    let context = context();
    let probe_items = plaintext(1);
    let next_items = plaintext(2);
    let mut probe = Some(Box::pin(set.encrypt_batch(&context, &probe_items)));
    assert!(poll(probe.as_mut().unwrap().as_mut()).await.is_pending());
    assert_eq!(set.endpoint_states()[0].1, CircuitState::HalfOpen);
    let mut waiting = Box::pin(set.encrypt_batch(&context, &next_items));
    assert!(poll(waiting.as_mut()).await.is_pending());
    assert_eq!(set.global_inflight(), (1, u64::from(UNIT)));
    if cancel {
        drop(probe.take());
    } else {
        peer.release.notify_one();
        assert!(matches!(
            poll(probe.as_mut().unwrap().as_mut()).await,
            Poll::Ready(Ok(_))
        ));
    }
    assert_eq!(set.global_inflight(), (0, 0));
    assert!(
        matches!(poll(waiting.as_mut()).await, Poll::Ready(Ok(_))),
        "probe capacity return should wake an unsent request without advancing time"
    );
    assert_eq!(peer.calls.load(Ordering::SeqCst), 3);
    assert_eq!(set.metrics().retries_total(), 0);
    assert_eq!(set.global_inflight(), (0, 0));
}

#[tokio::test]
async fn successful_probe_wakes_an_unsent_request() {
    half_open_return(false).await;
}

#[tokio::test]
async fn cancelled_probe_wakes_an_unsent_request() {
    half_open_return(true).await;
}

#[tokio::test]
async fn cancelled_readiness_waiter_releases_its_fifo_position() {
    let (clock, peer, set) = open_breaker().await;
    let context = context();
    let first_items = plaintext(2);
    let next_items = plaintext(3);
    let mut first = Box::pin(set.encrypt_batch(&context, &first_items));
    let mut next = Box::pin(set.encrypt_batch(&context, &next_items));
    assert!(poll(first.as_mut()).await.is_pending());
    assert!(poll(next.as_mut()).await.is_pending());
    drop(first);
    clock.advance(Duration::from_secs(1));
    assert!(matches!(poll(next.as_mut()).await, Poll::Ready(Ok(_))));
    assert_eq!(peer.calls.load(Ordering::SeqCst), 2);
    assert_eq!(set.global_inflight(), (0, 0));
    assert_eq!(clock.sleeper_count(), 0);
}

#[tokio::test]
async fn readiness_deadline_sends_no_rpc_and_returns_admission() {
    let (clock, peer, set) = open_breaker().await;
    clock.advance(Duration::from_secs(1));
    let context = context();
    let probe_items = plaintext(1);
    let waiting_items = plaintext(2);
    let mut probe = Box::pin(set.encrypt_batch(&context, &probe_items));
    assert!(poll(probe.as_mut()).await.is_pending());
    let mut waiting = Box::pin(set.encrypt_batch(&context, &waiting_items));
    assert!(poll(waiting.as_mut()).await.is_pending());
    clock.advance(Duration::from_secs(10));
    assert!(matches!(poll(waiting.as_mut()).await, Poll::Ready(Err(_))));
    assert_eq!(peer.calls.load(Ordering::SeqCst), 2);
    drop(probe);
    assert_eq!(set.global_inflight(), (0, 0));
    assert_eq!(clock.sleeper_count(), 0);
    assert!(set.encrypt_batch(&context, &waiting_items).await.is_ok());
}

#[tokio::test]
async fn actual_failed_rpc_still_exhausts_its_configured_pass() {
    let clock = Arc::new(ManualClock::new());
    let peer = Peer::new();
    let mut config = config();
    config.retry_safe = true;
    config.max_operation_time = None;
    let set = EndpointSet::new(vec![("only".into(), peer.clone())], config, clock.clone());
    peer.inner
        .fail_next([CryptoError::Retryable("one-shot outage".into())]);
    let context = context();
    let items = plaintext(2);
    let mut call = Box::pin(set.encrypt_batch(&context, &items));
    let first_poll = poll(call.as_mut()).await;
    let result = match first_poll {
        Poll::Ready(result) => result,
        Poll::Pending => {
            clock.advance(Duration::from_secs(30));
            match poll(call.as_mut()).await {
                Poll::Ready(result) => result,
                Poll::Pending => panic!("exhausted attempt should finish after its backoff"),
            }
        }
    };
    assert!(result.is_err());
    assert_eq!(peer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(set.global_inflight(), (0, 0));
}
