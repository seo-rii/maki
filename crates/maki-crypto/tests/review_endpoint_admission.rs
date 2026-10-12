use async_trait::async_trait;
use maki_crypto::breaker::BreakerConfig;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit,
    SecretBuffer,
};
use maki_test_support::{fake_provider::FakeCryptoProvider, ManualClock};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicU8, AtomicUsize, Ordering},
        Arc,
    },
    task::Poll,
    time::Duration,
};
use tokio::sync::Notify;
use uuid::Uuid;
const UNIT: u32 = 1024;
async fn once<F: Future + ?Sized>(mut f: Pin<&mut F>) -> Poll<F::Output> {
    std::future::poll_fn(|cx| Poll::Ready(f.as_mut().poll(cx))).await
}
struct GatedProvider {
    inner: FakeCryptoProvider,
    mode: AtomicU8,
    release: Notify,
    error_seen: Notify,
    errors: AtomicUsize,
    calls: AtomicUsize,
    gate_unit: Option<u64>,
}
impl GatedProvider {
    fn new(gate_unit: Option<u64>) -> Self {
        Self {
            inner: FakeCryptoProvider::new(UNIT).with_max_batch(1, 1 << 20),
            mode: AtomicU8::new(0),
            release: Notify::new(),
            error_seen: Notify::new(),
            errors: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
            gate_unit,
        }
    }
    async fn barrier(&self, unit: u64, phase: u8) -> Result<(), CryptoError> {
        if self.gate_unit == Some(unit) {
            self.release.notified().await;
        }
        if self.mode.load(Ordering::SeqCst) == phase {
            if unit == 0 {
                self.release.notified().await;
            }
            if unit == 1 {
                self.errors.fetch_add(1, Ordering::SeqCst);
                self.error_seen.notify_one();
                return Err(CryptoError::NonRetryableRequest(
                    "batch 2 is permanently rejected".into(),
                ));
            }
        }
        Ok(())
    }
}
#[async_trait]
impl CryptoProvider for GatedProvider {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.inner.capabilities().await
    }
    async fn encrypt_batch(
        &self,
        ctx: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.barrier(items[0].unit_index, 1).await?;
        self.inner.encrypt_batch(ctx, items).await
    }
    async fn decrypt_batch(
        &self,
        ctx: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.barrier(items[0].unit_index, 2).await?;
        self.inner.decrypt_batch(ctx, items).await
    }
}
fn cfg() -> DispatchConfig {
    DispatchConfig {
        retry: RetryPolicy {
            initial_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(1),
        },
        budget: RetryBudgetConfig {
            retry_ratio: 1.0,
            burst: 16,
            min_probe_per_sec: 1.0,
        },
        breaker: BreakerConfig {
            failure_threshold: 3,
            open_initial: Duration::from_secs(1),
            open_max: Duration::from_secs(30),
            half_open_max_requests: 2,
            success_threshold: 2,
        },
        global_max_inflight_batches: 2,
        global_max_inflight_bytes: 1 << 20,
        per_endpoint_max_inflight: 1,
        per_endpoint_max_bytes: 1 << 20,
        max_attempts: None,
        max_operation_time: None,
        retry_safe: true,
        validation_interval: Duration::from_secs(1),
    }
}
fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: Uuid::from_u128(39),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".into(),
    }
}
fn pt(i: u64) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: i,
        data: SecretBuffer::zeroed(UNIT as usize),
    }
}
#[tokio::test(flavor = "current_thread")]
async fn queued_request_reselects_an_idle_peer() {
    let left = Arc::new(GatedProvider::new(Some(10)));
    let right = Arc::new(GatedProvider::new(Some(11)));
    let set = EndpointSet::new(
        vec![
            ("left".into(), left.clone()),
            ("right".into(), right.clone()),
        ],
        cfg(),
        Arc::new(ManualClock::new()),
    );
    set.capabilities().await.unwrap();
    let ctx = context();
    let ia = [pt(10)];
    let ib = [pt(11)];
    let ic = [pt(12)];
    let id = [pt(13)];
    let mut a = Box::pin(set.encrypt_batch(&ctx, &ia));
    assert!(once(a.as_mut()).await.is_pending());
    let mut b = Box::pin(set.encrypt_batch(&ctx, &ib));
    assert!(once(b.as_mut()).await.is_pending());
    assert_eq!(
        set.endpoint_status()
            .iter()
            .map(|e| e.inflight)
            .collect::<Vec<_>>(),
        [1, 1]
    );
    let mut c = Box::pin(set.encrypt_batch(&ctx, &ic));
    assert!(once(c.as_mut()).await.is_pending());
    // c selected left at [1,1], but cannot yet obtain its global permit.
    right.release.notify_one();
    assert!(once(b.as_mut()).await.is_ready());
    // Admission re-evaluates peers after capacity changes.
    assert!(
        matches!(once(c.as_mut()).await, Poll::Ready(Ok(_))),
        "queued request must use the newly idle right peer"
    );
    assert_eq!(
        set.endpoint_status()
            .iter()
            .map(|e| e.inflight)
            .collect::<Vec<_>>(),
        [1, 0]
    );
    assert_eq!(set.global_inflight(), (1, UNIT as u64));
    let mut d = Box::pin(set.encrypt_batch(&ctx, &id));
    assert!(matches!(once(d.as_mut()).await, Poll::Ready(Ok(_))));
    assert_eq!(right.calls.load(Ordering::SeqCst), 3);
    left.release.notify_one();
    assert!(matches!(once(a.as_mut()).await, Poll::Ready(Ok(_))));
    assert_eq!(set.global_inflight(), (0, 0));
    assert!(set.endpoint_status().iter().all(|e| e.inflight == 0));
}

#[tokio::test(flavor = "current_thread")]
async fn cancelling_a_capacity_waiter_leaves_both_budgets_free() {
    let left = Arc::new(GatedProvider::new(Some(10)));
    let mut config = cfg();
    config.global_max_inflight_batches = 2;
    let set = EndpointSet::new(
        vec![("left".into(), left.clone())],
        config,
        Arc::new(ManualClock::new()),
    );
    set.capabilities().await.unwrap();
    let ctx = context();
    let first = [pt(10)];
    let second = [pt(11)];
    let mut active = Box::pin(set.encrypt_batch(&ctx, &first));
    assert!(once(active.as_mut()).await.is_pending());
    let mut queued = Box::pin(set.encrypt_batch(&ctx, &second));
    assert!(once(queued.as_mut()).await.is_pending());
    assert_eq!(
        set.global_inflight(),
        (1, UNIT as u64),
        "local waiters cannot reserve global capacity"
    );
    drop(queued);
    drop(active);
    assert_eq!(set.global_inflight(), (0, 0));
    assert_eq!(set.endpoint_status()[0].inflight, 0);
    assert!(set.encrypt_batch(&ctx, &second).await.is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn capacity_waiter_reselects_a_recovered_open_peer_without_an_rpc_release() {
    use maki_crypto::breaker::CircuitState;
    let clock = Arc::new(ManualClock::new());
    let left = Arc::new(GatedProvider::new(Some(10)));
    let right = Arc::new(GatedProvider::new(None));
    let mut config = cfg();
    config.breaker.failure_threshold = 1;
    config.retry_safe = false;
    let set = EndpointSet::new(
        vec![
            ("left".into(), left.clone()),
            ("right".into(), right.clone()),
        ],
        config,
        clock.clone(),
    );
    set.capabilities().await.unwrap();
    let ctx = context();
    let ia = [pt(10)];
    let ib = [pt(11)];
    let ic = [pt(12)];
    let id = [pt(13)];
    let mut active = Box::pin(set.encrypt_batch(&ctx, &ia));
    assert!(once(active.as_mut()).await.is_pending());
    right
        .inner
        .fail_next([CryptoError::Retryable("outage".into())]);
    assert!(set.encrypt_batch(&ctx, &ib).await.is_err());
    assert_eq!(set.endpoint_states()[1].1, CircuitState::Open);
    let mut queued = Box::pin(set.encrypt_batch(&ctx, &ic));
    let mut later = Box::pin(set.encrypt_batch(&ctx, &id));
    assert!(once(queued.as_mut()).await.is_pending());
    assert!(once(later.as_mut()).await.is_pending());
    assert_eq!(set.global_inflight(), (1, UNIT as u64));
    clock.advance(Duration::from_secs(1));
    assert!(
        matches!(once(queued.as_mut()).await, Poll::Ready(Ok(_))),
        "the open peer's probe deadline must wake the oldest capacity waiter"
    );
    assert!(matches!(once(later.as_mut()).await, Poll::Ready(Ok(_))));
    assert_eq!(right.calls.load(Ordering::SeqCst), 3);
    assert_eq!(set.endpoint_states()[1].1, CircuitState::Closed);
    assert_eq!(set.global_inflight(), (1, UNIT as u64));
    left.release.notify_one();
    assert!(matches!(once(active.as_mut()).await, Poll::Ready(Ok(_))));
    assert_eq!(set.global_inflight(), (0, 0));
}

#[tokio::test(flavor = "current_thread")]
async fn quarantine_promotion_wakes_capacity_waiters_without_an_rpc_release() {
    use maki_crypto::endpoint::EndpointValidator;
    let left = Arc::new(GatedProvider::new(Some(10)));
    let right = Arc::new(GatedProvider::new(None));
    let ready = Arc::new(Notify::new());
    let validator: EndpointValidator = Arc::new({
        let ready = ready.clone();
        move |_, _, _| {
            let ready = ready.clone();
            Box::pin(async move {
                ready.notified().await;
                Ok(())
            })
        }
    });
    let set = EndpointSet::with_quarantine(
        vec![
            ("left".into(), left.clone(), true),
            ("right".into(), right.clone(), false),
        ],
        Some(validator),
        cfg(),
        Arc::new(ManualClock::new()),
    );
    set.capabilities().await.unwrap();
    let ctx = context();
    let ia = [pt(10)];
    let ic = [pt(12)];
    let id = [pt(13)];
    let mut active = Box::pin(set.encrypt_batch(&ctx, &ia));
    let mut queued = Box::pin(set.encrypt_batch(&ctx, &ic));
    let mut later = Box::pin(set.encrypt_batch(&ctx, &id));
    assert!(once(active.as_mut()).await.is_pending());
    assert!(once(queued.as_mut()).await.is_pending());
    assert!(once(later.as_mut()).await.is_pending());
    assert_eq!(set.global_inflight(), (1, UNIT as u64));
    ready.notify_one();
    for _ in 0..32 {
        if set.endpoint_status()[1].validated {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(set.endpoint_status()[1].validated);
    assert!(
        matches!(once(queued.as_mut()).await, Poll::Ready(Ok(_))),
        "newly eligible peer must wake the existing FIFO capacity waiter"
    );
    assert!(matches!(once(later.as_mut()).await, Poll::Ready(Ok(_))));
    assert_eq!(right.calls.load(Ordering::SeqCst), 2);
    assert_eq!(set.global_inflight(), (1, UNIT as u64));
    left.release.notify_one();
    assert!(matches!(once(active.as_mut()).await, Poll::Ready(Ok(_))));
    assert_eq!(set.global_inflight(), (0, 0));
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_head_returns_its_probe_timer_and_fifo_turn_to_the_next_waiter() {
    let clock = Arc::new(ManualClock::new());
    let left = Arc::new(GatedProvider::new(Some(10)));
    let right = Arc::new(GatedProvider::new(None));
    let mut config = cfg();
    config.breaker.failure_threshold = 1;
    config.retry_safe = false;
    let set = EndpointSet::new(
        vec![
            ("left".into(), left.clone()),
            ("right".into(), right.clone()),
        ],
        config,
        clock.clone(),
    );
    set.capabilities().await.unwrap();
    let ctx = context();
    let ia = [pt(10)];
    let ib = [pt(11)];
    let ic = [pt(12)];
    let id = [pt(13)];
    let mut active = Box::pin(set.encrypt_batch(&ctx, &ia));
    assert!(once(active.as_mut()).await.is_pending());
    right
        .inner
        .fail_next([CryptoError::Retryable("outage".into())]);
    assert!(set.encrypt_batch(&ctx, &ib).await.is_err());
    let mut first = Box::pin(set.encrypt_batch(&ctx, &ic));
    let mut second = Box::pin(set.encrypt_batch(&ctx, &id));
    assert!(once(first.as_mut()).await.is_pending());
    assert!(once(second.as_mut()).await.is_pending());
    assert_eq!(
        clock.sleeper_count(),
        1,
        "only the FIFO head has a probe timer"
    );
    drop(first);
    assert_eq!(
        clock.sleeper_count(),
        0,
        "cancellation unregisters the head timer"
    );
    assert!(once(second.as_mut()).await.is_pending());
    assert_eq!(clock.sleeper_count(), 1);
    assert_eq!(set.global_inflight(), (1, UNIT as u64));
    clock.advance(Duration::from_secs(1));
    assert!(matches!(once(second.as_mut()).await, Poll::Ready(Ok(_))));
    assert_eq!(clock.sleeper_count(), 0);
    assert_eq!(right.calls.load(Ordering::SeqCst), 2);
    drop(active);
    assert_eq!(set.global_inflight(), (0, 0));
}

#[tokio::test(flavor = "current_thread")]
async fn fifo_and_full_half_open_window_do_not_spin_on_an_expired_probe_timer() {
    use maki_crypto::breaker::CircuitState;
    let clock = Arc::new(ManualClock::new());
    let left = Arc::new(GatedProvider::new(Some(10)));
    let right = Arc::new(GatedProvider::new(Some(12)));
    let mut config = cfg();
    config.breaker.failure_threshold = 1;
    config.breaker.half_open_max_requests = 1;
    config.global_max_inflight_batches = 4;
    config.per_endpoint_max_inflight = 2;
    config.retry_safe = false;
    let set = EndpointSet::new(
        vec![
            ("left".into(), left.clone()),
            ("right".into(), right.clone()),
        ],
        config,
        clock.clone(),
    );
    set.capabilities().await.unwrap();
    let ctx = context();
    let ia = [pt(10)];
    let ib = [pt(11)];
    let ic = [pt(12)];
    let id = [pt(13)];
    let mut active = Box::pin(set.encrypt_batch(&ctx, &ia));
    assert!(once(active.as_mut()).await.is_pending());
    right
        .inner
        .fail_next([CryptoError::Retryable("outage".into())]);
    assert!(set.encrypt_batch(&ctx, &ib).await.is_err());
    // Fill both left local slots while the right is OPEN. Once the right
    // starts its probe, its spare local/global slots must not bypass the
    // independent half-open limit.
    let mut second_active = Box::pin(set.encrypt_batch(&ctx, &ia));
    assert!(once(second_active.as_mut()).await.is_pending());
    let mut head = Box::pin(set.encrypt_batch(&ctx, &ic));
    let mut later = Box::pin(set.encrypt_batch(&ctx, &id));
    assert!(once(head.as_mut()).await.is_pending());
    assert!(once(later.as_mut()).await.is_pending());
    clock.advance(Duration::from_secs(1));
    assert!(
        once(later.as_mut()).await.is_pending(),
        "later caller must not steal the ready peer from the FIFO head"
    );
    assert!(once(head.as_mut()).await.is_pending());
    assert_eq!(set.endpoint_states()[1].1, CircuitState::HalfOpen);
    assert_eq!(right.calls.load(Ordering::SeqCst), 2);
    assert!(once(later.as_mut()).await.is_pending());
    assert_eq!(
        clock.sleeper_count(),
        0,
        "a full probe window waits for a release, never a past timestamp"
    );
    assert_eq!(set.global_inflight(), (3, 3 * UNIT as u64));
    clock.advance(Duration::from_secs(100));
    assert!(once(later.as_mut()).await.is_pending());
    assert_eq!(right.calls.load(Ordering::SeqCst), 2);
    right.release.notify_one();
    assert!(matches!(once(head.as_mut()).await, Poll::Ready(Ok(_))));
    assert!(matches!(once(later.as_mut()).await, Poll::Ready(Ok(_))));
    assert_eq!(set.endpoint_states()[1].1, CircuitState::Closed);
    assert_eq!(right.calls.load(Ordering::SeqCst), 3);
    drop(active);
    drop(second_active);
    assert_eq!(set.global_inflight(), (0, 0));
}

#[tokio::test(flavor = "current_thread")]
async fn admission_and_fifo_waiters_keep_their_deadlines_without_charging_a_probe() {
    use maki_crypto::breaker::CircuitState;
    let clock = Arc::new(ManualClock::new());
    let left = Arc::new(GatedProvider::new(Some(10)));
    let right = Arc::new(GatedProvider::new(None));
    let mut config = cfg();
    config.breaker.failure_threshold = 1;
    config.max_operation_time = Some(Duration::from_millis(100));
    config.retry_safe = false;
    let set = EndpointSet::new(
        vec![
            ("left".into(), left.clone()),
            ("right".into(), right.clone()),
        ],
        config,
        clock.clone(),
    );
    set.capabilities().await.unwrap();
    let ctx = context();
    let ia = [pt(10)];
    let ib = [pt(11)];
    let ic = [pt(12)];
    let id = [pt(13)];
    let mut active = Box::pin(set.encrypt_batch(&ctx, &ia));
    assert!(once(active.as_mut()).await.is_pending());
    right
        .inner
        .fail_next([CryptoError::Retryable("outage".into())]);
    assert!(set.encrypt_batch(&ctx, &ib).await.is_err());
    let tokens = set.endpoint_budget_tokens();
    clock.advance(Duration::from_millis(50));
    let mut head = Box::pin(set.encrypt_batch(&ctx, &ic));
    assert!(once(head.as_mut()).await.is_pending());
    clock.advance(Duration::from_millis(30));
    let mut later = Box::pin(set.encrypt_batch(&ctx, &id));
    assert!(once(later.as_mut()).await.is_pending());
    // Keep the manually polled active future parked so no capacity-release
    // notification can make this a test of RPC expiry instead of admission.
    clock.advance(Duration::from_millis(70));
    let head_error = match once(head.as_mut()).await {
        Poll::Ready(Err(error)) => error,
        _ => panic!("head's own deadline was restarted"),
    };
    assert!(head_error.to_string().contains("deadline"));
    assert!(once(later.as_mut()).await.is_pending());
    clock.advance(Duration::from_millis(30));
    let later_error = match once(later.as_mut()).await {
        Poll::Ready(Err(error)) => error,
        _ => panic!("FIFO mutex wait lost the later caller's deadline"),
    };
    assert!(later_error.to_string().contains("deadline"));
    assert_eq!(set.metrics().deadline_exceeded_total(), 2);
    assert_eq!(set.endpoint_states()[1].1, CircuitState::Open);
    assert_eq!(right.calls.load(Ordering::SeqCst), 1);
    assert_eq!(set.endpoint_budget_tokens(), tokens);
    assert_eq!(set.global_inflight(), (1, UNIT as u64));
    drop(active);
    assert_eq!(set.global_inflight(), (0, 0));
    assert_eq!(clock.sleeper_count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn byte_capacity_wait_returns_partial_permits_and_preserves_fifo() {
    let clock = Arc::new(ManualClock::new());
    let left = Arc::new(GatedProvider::new(Some(10)));
    let right = Arc::new(GatedProvider::new(Some(11)));
    let mut config = cfg();
    config.global_max_inflight_batches = 4;
    config.per_endpoint_max_inflight = 3;
    config.global_max_inflight_bytes = 2 * UNIT as u64;
    config.per_endpoint_max_bytes = UNIT as u64;
    let set = EndpointSet::new(
        vec![
            ("left".into(), left.clone()),
            ("right".into(), right.clone()),
        ],
        config,
        clock,
    );
    set.capabilities().await.unwrap();
    let ctx = context();
    let ia = [pt(10)];
    let ib = [pt(11)];
    let ic = [pt(12)];
    let id = [pt(13)];
    let mut a = Box::pin(set.encrypt_batch(&ctx, &ia));
    let mut b = Box::pin(set.encrypt_batch(&ctx, &ib));
    let mut head = Box::pin(set.encrypt_batch(&ctx, &ic));
    let mut later = Box::pin(set.encrypt_batch(&ctx, &id));
    assert!(once(a.as_mut()).await.is_pending());
    assert!(once(b.as_mut()).await.is_pending());
    assert!(once(head.as_mut()).await.is_pending());
    assert!(once(later.as_mut()).await.is_pending());
    assert_eq!(set.global_inflight(), (2, 2 * UNIT as u64));
    right.release.notify_one();
    assert!(matches!(once(b.as_mut()).await, Poll::Ready(Ok(_))));
    assert!(once(later.as_mut()).await.is_pending());
    assert!(matches!(once(head.as_mut()).await, Poll::Ready(Ok(_))));
    assert!(matches!(once(later.as_mut()).await, Poll::Ready(Ok(_))));
    assert_eq!(set.global_inflight(), (1, UNIT as u64));
    drop(a);
    assert_eq!(set.global_inflight(), (0, 0));
}

#[tokio::test(flavor = "current_thread")]
async fn global_byte_shortage_returns_a_tentative_idle_peers_local_permit() {
    let clock = Arc::new(ManualClock::new());
    let left = Arc::new(GatedProvider::new(Some(10)));
    let right = Arc::new(GatedProvider::new(None));
    let mut config = cfg();
    config.global_max_inflight_batches = 4;
    config.global_max_inflight_bytes = UNIT as u64;
    config.per_endpoint_max_bytes = UNIT as u64;
    config.breaker.failure_threshold = 1;
    config.retry_safe = false;
    let set = EndpointSet::new(
        vec![
            ("left".into(), left.clone()),
            ("right".into(), right.clone()),
        ],
        config,
        clock,
    );
    set.capabilities().await.unwrap();
    let ctx = context();
    let ia = [pt(10)];
    let ib = [pt(11)];
    left.inner
        .fail_next([CryptoError::Retryable("left outage".into())]);
    let mut active = Box::pin(set.encrypt_batch(&ctx, &ia));
    let mut queued = Box::pin(set.encrypt_batch(&ctx, &ib));
    assert!(once(active.as_mut()).await.is_pending());
    assert!(once(queued.as_mut()).await.is_pending());
    assert_eq!(
        set.global_inflight(),
        (1, UNIT as u64),
        "failed byte admission must also return its tentative count permit"
    );
    assert_eq!(right.calls.load(Ordering::SeqCst), 0);
    left.release.notify_one();
    assert!(matches!(once(active.as_mut()).await, Poll::Ready(Err(_))));
    assert!(
        matches!(once(queued.as_mut()).await, Poll::Ready(Ok(_))),
        "left is now OPEN, so the idle right peer's tentative local permit must have been returned"
    );
    assert_eq!(right.calls.load(Ordering::SeqCst), 1);
    assert_eq!(set.global_inflight(), (0, 0));
}

#[tokio::test(flavor = "current_thread")]
async fn all_open_peers_keep_backoff_and_do_not_consume_capacity_before_recovery() {
    let clock = Arc::new(ManualClock::new());
    let left = Arc::new(GatedProvider::new(None));
    let right = Arc::new(GatedProvider::new(None));
    let mut config = cfg();
    config.breaker.failure_threshold = 1;
    config.retry_safe = false;
    let set = EndpointSet::new(
        vec![
            ("left".into(), left.clone()),
            ("right".into(), right.clone()),
        ],
        config,
        clock.clone(),
    );
    set.capabilities().await.unwrap();
    let ctx = context();
    left.inner
        .fail_next([CryptoError::Retryable("left outage".into())]);
    right
        .inner
        .fail_next([CryptoError::Retryable("right outage".into())]);
    assert!(set.encrypt_batch(&ctx, &[pt(10)]).await.is_err());
    assert!(set.encrypt_batch(&ctx, &[pt(11)]).await.is_err());
    let items = [pt(12)];
    let mut request = Box::pin(set.encrypt_batch(&ctx, &items));
    assert!(once(request.as_mut()).await.is_pending());
    assert_eq!(set.global_inflight(), (0, 0));
    assert_eq!(left.calls.load(Ordering::SeqCst), 1);
    assert_eq!(right.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        clock.sleeper_count(),
        1,
        "normal all-open backoff remains active"
    );
    clock.advance(Duration::from_secs(1));
    assert!(matches!(once(request.as_mut()).await, Poll::Ready(Ok(_))));
    assert_eq!(set.global_inflight(), (0, 0));
    assert_eq!(clock.sleeper_count(), 0);
}
