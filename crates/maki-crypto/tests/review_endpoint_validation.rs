//! BUG-067 / BUG-068 / BUG-072: quarantine admission, attribution and ownership.
use async_trait::async_trait;
use maki_crypto::selftest::{cross_endpoint_self_test, provider_self_test};
use maki_crypto::{
    breaker::BreakerConfig,
    endpoint::{DispatchConfig, EndpointSet, EndpointValidator},
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
    malformed_decrypt: AtomicBool,
}
impl Gated {
    fn new() -> Arc<Self> {
        Self::from_inner(FakeCryptoProvider::new(U as u32).with_max_batch(1, U as u64))
    }
    fn from_inner(inner: FakeCryptoProvider) -> Arc<Self> {
        Arc::new(Self {
            inner,
            blocked: AtomicBool::new(false),
            active: AtomicUsize::new(0),
            release: Notify::new(),
            calls: AtomicUsize::new(0),
            malformed_decrypt: AtomicBool::new(false),
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
        let mut out = self.inner.decrypt_batch(c, p).await?;
        if self.malformed_decrypt.load(Ordering::SeqCst) {
            out.pop();
        }
        Ok(out)
    }
}
async fn poll<F: Future + ?Sized>(mut f: Pin<&mut F>) -> Poll<F::Output> {
    std::future::poll_fn(|cx| Poll::Ready(f.as_mut().poll(cx))).await
}
async fn settle() {
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
}
fn validator() -> EndpointValidator {
    Arc::new(|reference, candidate, c| {
        Box::pin(async move {
            provider_self_test(candidate.as_ref(), &c, U, &c.crypto_compatibility_id).await?;
            cross_endpoint_self_test(reference.as_ref(), candidate.as_ref(), &c, U).await
        })
    })
}
#[tokio::test(flavor = "current_thread")]
async fn quarantined_validation_respects_global_capacity() {
    let good = Gated::new();
    let peers: Vec<_> = (0..4).map(|_| Gated::new()).collect();
    for p in std::iter::once(&good).chain(peers.iter()) {
        provider_self_test(p.as_ref(), &ctx(), U, "test-profile-v1")
            .await
            .unwrap();
        p.blocked.store(true, Ordering::SeqCst);
    }
    let mut endpoints: Vec<(String, Arc<dyn CryptoProvider>, bool)> =
        vec![("good".into(), good.clone(), true)];
    for (i, p) in peers.iter().enumerate() {
        endpoints.push((format!("candidate-{i}"), p.clone(), false));
    }
    let set = EndpointSet::with_quarantine(
        endpoints,
        Some(validator()),
        cfg(),
        Arc::new(ManualClock::new()),
    );
    let context = ctx();
    let data = input();
    let mut call = Box::pin(set.encrypt_batch(&context, &data));
    assert!(poll(call.as_mut()).await.is_pending());
    settle().await;
    let observed = good.active.load(Ordering::SeqCst)
        + peers
            .iter()
            .map(|p| p.active.load(Ordering::SeqCst))
            .sum::<usize>();
    println!(
        "global: actual_rpc={observed}, limit=1, reported={:?}",
        set.global_inflight()
    );
    drop(call);
    for p in std::iter::once(&good).chain(peers.iter()) {
        p.blocked.store(false, Ordering::SeqCst);
        p.release.notify_waiters();
    }
    settle().await;
    assert!(
        observed <= 1,
        "background validation bypassed the global admission limit"
    );
}
#[tokio::test(flavor = "current_thread")]
async fn quarantined_validation_respects_reference_capacity() {
    let good = Gated::new();
    let peer = Gated::new();
    for p in [&good, &peer] {
        provider_self_test(p.as_ref(), &ctx(), U, "test-profile-v1")
            .await
            .unwrap();
    }
    good.blocked.store(true, Ordering::SeqCst);
    let mut config = cfg();
    config.global_max_inflight_batches = 4;
    config.global_max_inflight_bytes = 4 * (U + 8) as u64;
    let set = EndpointSet::with_quarantine(
        vec![
            ("good".into(), good.clone(), true),
            ("candidate".into(), peer.clone(), false),
        ],
        Some(validator()),
        config,
        Arc::new(ManualClock::new()),
    );
    let context = ctx();
    let data = input();
    let mut call = Box::pin(set.encrypt_batch(&context, &data));
    assert!(poll(call.as_mut()).await.is_pending());
    settle().await;
    let observed = good.active.load(Ordering::SeqCst);
    println!(
        "reference: actual_rpc={observed}, endpoint_limit=1, reported={:?}",
        set.endpoint_inflight()
    );
    drop(call);
    good.blocked.store(false, Ordering::SeqCst);
    good.release.notify_waiters();
    settle().await;
    assert!(
        observed <= 1,
        "cross-endpoint validation bypassed reference endpoint capacity"
    );
}
#[tokio::test(flavor = "current_thread")]
async fn ordinary_requests_obey_capacity() {
    let good = Gated::new();
    good.blocked.store(true, Ordering::SeqCst);
    let set = EndpointSet::new(
        vec![("good".into(), good.clone())],
        cfg(),
        Arc::new(ManualClock::new()),
    );
    let context = ctx();
    let data = input();
    let mut a = Box::pin(set.encrypt_batch(&context, &data));
    let mut b = Box::pin(set.encrypt_batch(&context, &data));
    assert!(poll(a.as_mut()).await.is_pending());
    assert!(poll(b.as_mut()).await.is_pending());
    settle().await;
    assert_eq!(good.active.load(Ordering::SeqCst), 1);
    drop(a);
    drop(b);
    assert_eq!(good.active.load(Ordering::SeqCst), 0);
    assert_eq!(set.global_inflight(), (0, 0));
}

#[tokio::test(flavor = "current_thread")]
async fn validators_stop_after_owner_and_last_caller_are_dropped() {
    let good = Gated::new();
    let peer = Gated::new();
    peer.blocked.store(true, Ordering::SeqCst);
    let set = EndpointSet::with_quarantine(
        vec![
            ("good".into(), good.clone(), true),
            ("candidate".into(), peer.clone(), false),
        ],
        Some(validator()),
        cfg(),
        Arc::new(ManualClock::new()),
    );
    set.encrypt_batch(&ctx(), &input()).await.unwrap();
    settle().await;
    assert_eq!(peer.active.load(Ordering::SeqCst), 1);
    drop(set);
    settle().await;
    let observed = peer.active.load(Ordering::SeqCst);
    println!("dropped all dispatcher owners: active_validation_rpc={observed}");
    peer.blocked.store(false, Ordering::SeqCst);
    peer.release.notify_waiters();
    settle().await;
    assert_eq!(
        observed, 0,
        "unowned dispatcher keeps its background RPC active"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_bad_reference_does_not_permanently_reject_a_healthy_candidate() {
    use maki_test_support::fake_provider::Misbehavior;
    let a = Gated::new();
    let b = Gated::new();
    for p in [&a, &b] {
        provider_self_test(p.as_ref(), &ctx(), U, "test-profile-v1")
            .await
            .unwrap();
    }
    a.inner.set_misbehavior(Some(Misbehavior::DropLastItem));
    let set = EndpointSet::with_quarantine(
        vec![
            ("reference".into(), a.clone(), true),
            ("healthy_candidate".into(), b.clone(), false),
        ],
        Some(validator()),
        cfg(),
        Arc::new(ManualClock::new()),
    );
    assert!(matches!(
        set.encrypt_batch(&ctx(), &input()).await,
        Err(CryptoError::Contract(_))
    ));
    settle().await;
    let status = set.endpoint_status();
    println!(
        "reference-only bad reply: candidate validated={} rejected={}",
        status[1].validated, status[1].rejected
    );
    provider_self_test(b.as_ref(), &ctx(), U, "test-profile-v1")
        .await
        .unwrap();
    assert!(!status[1].rejected,"healthy candidate permanently excluded because reference violated its own response contract");
}
#[tokio::test(flavor = "current_thread")]
async fn healthy_reference_promotes_a_healthy_candidate() {
    let a = Gated::new();
    let b = Gated::new();
    let set = EndpointSet::with_quarantine(
        vec![
            ("reference".into(), a.clone(), true),
            ("candidate".into(), b.clone(), false),
        ],
        Some(validator()),
        cfg(),
        Arc::new(ManualClock::new()),
    );
    set.encrypt_batch(&ctx(), &input()).await.unwrap();
    settle().await;
    let status = set.endpoint_status();
    assert!(status[1].validated);
    assert!(!status[1].rejected);
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_reference_decrypt_defers_candidate_then_recovers() {
    let clock = Arc::new(ManualClock::new());
    let reference = Gated::new();
    let candidate = Gated::new();
    reference.malformed_decrypt.store(true, Ordering::SeqCst);
    let set = EndpointSet::with_quarantine(
        vec![
            ("reference".into(), reference.clone(), true),
            ("candidate".into(), candidate.clone(), false),
        ],
        Some(validator()),
        cfg(),
        clock.clone(),
    );
    set.encrypt_batch(&ctx(), &input()).await.unwrap();
    settle().await;
    assert!(
        !set.endpoint_status()[1].rejected,
        "reference malformed decrypt is not candidate incompatibility"
    );
    assert!(!set.endpoint_status()[1].validated);
    reference.malformed_decrypt.store(false, Ordering::SeqCst);
    clock.advance(Duration::from_secs(2));
    set.encrypt_batch(&ctx(), &input()).await.unwrap();
    settle().await;
    assert!(set.endpoint_status()[1].validated);
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_candidate_contract_is_still_rejected() {
    use maki_test_support::fake_provider::Misbehavior;
    let reference = Gated::new();
    let candidate = Gated::new();
    candidate
        .inner
        .set_misbehavior(Some(Misbehavior::DropLastItem));
    let set = EndpointSet::with_quarantine(
        vec![
            ("reference".into(), reference, true),
            ("candidate".into(), candidate, false),
        ],
        Some(validator()),
        cfg(),
        Arc::new(ManualClock::new()),
    );
    set.encrypt_batch(&ctx(), &input()).await.unwrap();
    settle().await;
    assert!(set.endpoint_status()[1].rejected);
}

#[tokio::test(flavor = "current_thread")]
async fn different_key_candidate_is_still_rejected() {
    let reference = Gated::new();
    let candidate = Gated::from_inner(
        FakeCryptoProvider::new(U as u32)
            .with_key(99)
            .with_max_batch(1, U as u64),
    );
    provider_self_test(candidate.as_ref(), &ctx(), U, "test-profile-v1")
        .await
        .unwrap();
    let set = EndpointSet::with_quarantine(
        vec![
            ("reference".into(), reference, true),
            ("candidate".into(), candidate, false),
        ],
        Some(validator()),
        cfg(),
        Arc::new(ManualClock::new()),
    );
    set.encrypt_batch(&ctx(), &input()).await.unwrap();
    settle().await;
    assert!(set.endpoint_status()[1].rejected);
}

#[tokio::test(flavor = "current_thread")]
async fn byte_budget_bounds_validation_even_with_multiple_count_slots() {
    let reference = Gated::new();
    let candidate = Gated::new();
    reference.blocked.store(true, Ordering::SeqCst);
    candidate.blocked.store(true, Ordering::SeqCst);
    let mut config = cfg();
    config.global_max_inflight_batches = 4;
    config.per_endpoint_max_inflight = 4;
    let set = EndpointSet::with_quarantine(
        vec![
            ("reference".into(), reference.clone(), true),
            ("candidate".into(), candidate.clone(), false),
        ],
        Some(validator()),
        config,
        Arc::new(ManualClock::new()),
    );
    let context = ctx();
    let data = input();
    let mut call = Box::pin(set.encrypt_batch(&context, &data));
    assert!(poll(call.as_mut()).await.is_pending());
    settle().await;
    let actual = reference.active.load(Ordering::SeqCst) + candidate.active.load(Ordering::SeqCst);
    drop(call);
    drop(set);
    settle().await;
    reference.release.notify_waiters();
    candidate.release.notify_waiters();
    assert_eq!(
        actual, 1,
        "512-byte requests cannot overlap in a 520-byte budget"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn cancelling_one_caller_keeps_validation_owned_by_live_set() {
    let reference = Gated::new();
    let candidate = Gated::new();
    candidate.blocked.store(true, Ordering::SeqCst);
    let set = EndpointSet::with_quarantine(
        vec![
            ("reference".into(), reference, true),
            ("candidate".into(), candidate.clone(), false),
        ],
        Some(validator()),
        cfg(),
        Arc::new(ManualClock::new()),
    );
    set.encrypt_batch(&ctx(), &input()).await.unwrap();
    settle().await;
    assert_eq!(candidate.active.load(Ordering::SeqCst), 1);
    let context = ctx();
    let data = input();
    let mut caller = Box::pin(set.encrypt_batch(&context, &data));
    assert!(poll(caller.as_mut()).await.is_pending());
    drop(caller);
    assert_eq!(candidate.active.load(Ordering::SeqCst), 1);
    candidate.blocked.store(false, Ordering::SeqCst);
    candidate.release.notify_waiters();
    settle().await;
    assert!(set.endpoint_status()[1].validated);
    assert_eq!(set.global_inflight(), (0, 0));
}

#[tokio::test(flavor = "current_thread")]
async fn large_advertised_self_test_batches_fit_single_rpc_byte_capacity() {
    let reference = Gated::from_inner(FakeCryptoProvider::new(U as u32));
    let candidate = Gated::from_inner(FakeCryptoProvider::new(U as u32));
    let set = EndpointSet::with_quarantine(
        vec![
            ("reference".into(), reference, true),
            ("candidate".into(), candidate, false),
        ],
        Some(validator()),
        cfg(),
        Arc::new(ManualClock::new()),
    );
    set.encrypt_batch(&ctx(), &input()).await.unwrap();
    settle().await;
    assert!(
        set.endpoint_status()[1].validated,
        "admission must split probes instead of making promotion impossible"
    );
    assert_eq!(set.global_inflight(), (0, 0));
}
