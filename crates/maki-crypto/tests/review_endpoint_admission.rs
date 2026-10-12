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
