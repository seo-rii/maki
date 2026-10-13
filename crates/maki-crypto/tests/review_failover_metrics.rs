//! BUG-073: count endpoint changes across retry passes.
use async_trait::async_trait;
use maki_crypto::{
    breaker::BreakerConfig,
    endpoint::{DispatchConfig, EndpointSet},
    retry::{RetryBudgetConfig, RetryPolicy},
    *,
};
use maki_test_support::{fake_provider::FakeCryptoProvider, ManualClock};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    task::Poll,
    time::Duration,
};
use tokio::sync::Notify;
const U: usize = 512;
fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(67),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".into(),
    }
}
fn input() -> Vec<PlaintextUnit> {
    vec![PlaintextUnit {
        unit_index: 8,
        data: SecretBuffer::zeroed(U),
    }]
}
fn cfg() -> DispatchConfig {
    DispatchConfig {
        retry: RetryPolicy {
            initial_delay: Duration::from_millis(10),
            max_delay: Duration::from_secs(1),
        },
        budget: RetryBudgetConfig {
            retry_ratio: 1.0,
            burst: 16,
            min_probe_per_sec: 1.0,
        },
        breaker: BreakerConfig::default(),
        global_max_inflight_batches: 1,
        global_max_inflight_bytes: (U + 8) as u64,
        per_endpoint_max_inflight: 1,
        per_endpoint_max_bytes: (U + 8) as u64,
        max_attempts: None,
        max_operation_time: None,
        retry_safe: true,
        validation_interval: Duration::from_secs(1),
    }
}
struct Active<'a>(&'a AtomicUsize);
impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
struct Gated {
    inner: FakeCryptoProvider,
    blocked: AtomicBool,
    active: AtomicUsize,
    release: Notify,
    calls: AtomicUsize,
}
impl Gated {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: FakeCryptoProvider::new(U as u32).with_max_batch(1, U as u64),
            blocked: AtomicBool::new(false),
            active: AtomicUsize::new(0),
            release: Notify::new(),
            calls: AtomicUsize::new(0),
        })
    }
    async fn gate(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let _a = Active(&self.active);
        self.active.fetch_add(1, Ordering::SeqCst);
        if self.blocked.load(Ordering::SeqCst) {
            self.release.notified().await;
        }
    }
}
#[async_trait]
impl CryptoProvider for Gated {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.inner.capabilities().await
    }
    async fn encrypt_batch(
        &self,
        c: &CryptoContext,
        p: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.gate().await;
        self.inner.encrypt_batch(c, p).await
    }
    async fn decrypt_batch(
        &self,
        c: &CryptoContext,
        p: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.gate().await;
        self.inner.decrypt_batch(c, p).await
    }
}
async fn poll<F: Future + ?Sized>(mut f: Pin<&mut F>) -> Poll<F::Output> {
    std::future::poll_fn(|cx| Poll::Ready(f.as_mut().poll(cx))).await
}
#[tokio::test(flavor = "current_thread")]
async fn failover_to_recovered_peer_is_counted() {
    let clock = Arc::new(ManualClock::new());
    let a = Gated::new();
    let b = Gated::new();
    let mut config = cfg();
    config.global_max_inflight_batches = 2;
    config.global_max_inflight_bytes = 1040;
    config.breaker.failure_threshold = 1;
    config.breaker.open_initial = Duration::from_secs(10);
    config.breaker.open_max = Duration::from_secs(10);
    config.retry.initial_delay = Duration::from_secs(1);
    config.retry.max_delay = Duration::from_secs(1);
    let set = EndpointSet::new(
        vec![("a".into(), a.clone()), ("b".into(), b.clone())],
        config,
        clock.clone(),
    );
    a.blocked.store(true, Ordering::SeqCst);
    let c = ctx();
    let data = input();
    let mut hold = Box::pin(set.encrypt_batch(&c, &data));
    assert!(poll(hold.as_mut()).await.is_pending());
    b.inner
        .fail_next([CryptoError::Retryable("ordinary transient".into())]);
    let mut warmup = Box::pin(set.encrypt_batch(&c, &data));
    assert!(poll(warmup.as_mut()).await.is_pending());
    assert_eq!(b.calls.load(Ordering::SeqCst), 1);
    drop(warmup);
    a.blocked.store(false, Ordering::SeqCst);
    a.release.notify_waiters();
    assert!(poll(hold.as_mut()).await.is_ready());
    drop(hold);
    clock.advance(Duration::from_secs(5));
    let initial = set.metrics().failovers_total();
    let a_before = a.calls.load(Ordering::SeqCst);
    let b_before = b.calls.load(Ordering::SeqCst);
    a.inner
        .fail_next([CryptoError::Retryable("ordinary transient".into())]);
    let mut request = Box::pin(set.encrypt_batch(&c, &data));
    assert!(poll(request.as_mut()).await.is_pending());
    clock.advance(Duration::from_secs(5));
    let result = poll(request.as_mut()).await;
    assert!(matches!(result, Poll::Ready(Ok(_))), "{result:?}");
    let observed = set.metrics().failovers_total() - initial;
    println!(
        "across passes: A calls={}, B calls={}, failovers_delta={observed}",
        a.calls.load(Ordering::SeqCst) - a_before,
        b.calls.load(Ordering::SeqCst) - b_before
    );
    assert_eq!(
        observed, 1,
        "switching to a recovered peer was omitted from failover accounting"
    );
}
#[tokio::test(flavor = "current_thread")]
async fn same_pass_failover_is_counted() {
    let a = Gated::new();
    let b = Gated::new();
    a.inner
        .fail_next([CryptoError::Retryable("ordinary transient".into())]);
    let set = EndpointSet::new(
        vec![("a".into(), a.clone()), ("b".into(), b.clone())],
        cfg(),
        Arc::new(ManualClock::new()),
    );
    set.encrypt_batch(&ctx(), &input()).await.unwrap();
    assert_eq!(set.metrics().failovers_total(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn retrying_the_same_peer_does_not_count_as_failover() {
    let clock = Arc::new(ManualClock::new());
    let a = Gated::new();
    a.inner
        .fail_next([CryptoError::Retryable("ordinary transient".into())]);
    let set = EndpointSet::new(vec![("a".into(), a.clone())], cfg(), clock.clone());
    let context = ctx();
    let data = input();
    let mut request = Box::pin(set.encrypt_batch(&context, &data));
    assert!(poll(request.as_mut()).await.is_pending());
    clock.advance(Duration::from_secs(1));
    assert!(matches!(poll(request.as_mut()).await, Poll::Ready(Ok(_))));
    assert_eq!(a.calls.load(Ordering::SeqCst), 2);
    assert_eq!(set.metrics().failovers_total(), 0);
    assert_eq!(set.metrics().retries_total(), 1);
}
