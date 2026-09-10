//! R3-004: ciphertext/key interchangeability does not imply equal RPC limits.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use maki_crypto::breaker::BreakerConfig;
use maki_crypto::clock::SystemClock;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet, EndpointValidator};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    ErrorClass, PlaintextUnit, SecretBuffer,
};
use maki_test_support::fake_provider::FakeCryptoProvider;

const UNIT: usize = 256;

struct Peer {
    inner: FakeCryptoProvider,
    caps: CryptoCapabilities,
    largest_request: AtomicUsize,
}

impl Peer {
    async fn new(max_items: u32, max_bytes: u64) -> Self {
        let inner = FakeCryptoProvider::new(UNIT as u32).with_max_batch(max_items, max_bytes);
        let caps = inner.capabilities().await.unwrap();
        Self {
            inner,
            caps,
            largest_request: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl CryptoProvider for Peer {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        Ok(self.caps.clone())
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.largest_request
            .fetch_max(items.len(), Ordering::SeqCst);
        self.inner.encrypt_batch(context, items).await
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.largest_request
            .fetch_max(items.len(), Ordering::SeqCst);
        self.inner.decrypt_batch(context, items).await
    }
}

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(4004),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".into(),
    }
}

fn items() -> Vec<PlaintextUnit> {
    (0..4)
        .map(|unit_index| PlaintextUnit {
            unit_index,
            data: SecretBuffer::from_slice(&vec![unit_index as u8; UNIT]),
        })
        .collect()
}

fn config() -> DispatchConfig {
    DispatchConfig {
        retry: RetryPolicy {
            initial_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(2),
        },
        budget: RetryBudgetConfig {
            retry_ratio: 1.0,
            burst: 16,
            min_probe_per_sec: 1.0,
        },
        breaker: BreakerConfig {
            failure_threshold: 1,
            open_initial: Duration::from_secs(60),
            open_max: Duration::from_secs(60),
            half_open_max_requests: 1,
            success_threshold: 1,
        },
        global_max_inflight_batches: 8,
        global_max_inflight_bytes: 1 << 20,
        per_endpoint_max_inflight: 8,
        per_endpoint_max_bytes: 1 << 20,
        max_attempts: Some(1),
        max_operation_time: Some(Duration::from_secs(1)),
        retry_safe: true,
        validation_interval: Duration::ZERO,
    }
}

fn set(a: Arc<Peer>, b: Arc<Peer>) -> EndpointSet {
    EndpointSet::new(
        vec![("large".into(), a), ("small".into(), b)],
        config(),
        Arc::new(SystemClock::new()),
    )
}

#[tokio::test]
async fn advertised_contract_is_the_common_contract_including_quarantine() {
    let mut a = Peer::new(16, 4096).await;
    a.caps.supported_plaintext_sizes = vec![512, 256, 1024];
    a.caps.max_ciphertext_size = 1040;
    a.caps.integrity = Capability::Verified;
    a.caps.context_binding = Capability::Verified;
    a.caps.replay_protection = Capability::Contractual;
    let mut b = Peer::new(2, 1024).await;
    b.caps.supported_plaintext_sizes = vec![256, 512, 2048];
    b.caps.max_ciphertext_size = 2064;
    b.caps.retry_safe = false;
    b.caps.stateless = false;
    b.caps.integrity = Capability::Contractual;
    b.caps.context_binding = Capability::Absent;
    b.caps.replay_protection = Capability::Verified;
    let set = EndpointSet::with_quarantine(
        vec![
            ("a".into(), Arc::new(a), true),
            ("b".into(), Arc::new(b), false),
        ],
        None,
        config(),
        Arc::new(SystemClock::new()),
    );
    let caps = set.capabilities().await.unwrap();
    assert_eq!(caps.batch.max_items, 2);
    assert_eq!(caps.batch.max_bytes, 1024);
    assert_eq!(caps.supported_plaintext_sizes, vec![256, 512]);
    assert_eq!(caps.max_ciphertext_size, 2064);
    assert!(!caps.retry_safe);
    assert!(!caps.stateless);
    assert_eq!(caps.integrity, Capability::Contractual);
    assert_eq!(caps.context_binding, Capability::Absent);
    assert_eq!(caps.replay_protection, Capability::Contractual);
}

#[tokio::test]
async fn failover_splits_encrypt_and_decrypt_to_the_small_peers_logical_limit() {
    let a = Arc::new(Peer::new(16, 4096).await);
    let b = Arc::new(Peer::new(2, UNIT as u64).await);
    a.inner
        .fail_next([CryptoError::Retryable("unavailable".into())]);
    let set = set(a.clone(), b.clone());
    let plain = items();
    let encrypted = set.encrypt_batch(&context(), &plain).await.unwrap();
    let decrypted = set.decrypt_batch(&context(), &encrypted).await.unwrap();
    assert_eq!(decrypted.len(), plain.len());
    for (actual, expected) in decrypted.iter().zip(&plain) {
        assert_eq!(actual.unit_index, expected.unit_index);
        assert_eq!(actual.data, expected.data);
    }
    assert_eq!(b.largest_request.load(Ordering::SeqCst), 1);
    assert_eq!(b.inner.encrypt_calls(), 4);
    assert_eq!(b.inner.decrypt_calls(), 4);
}

#[tokio::test]
async fn a_recovered_small_peer_does_not_change_the_serving_contract() {
    let a = Arc::new(Peer::new(16, 4096).await);
    let b = Arc::new(Peer::new(1, UNIT as u64).await);
    let validator: EndpointValidator = Arc::new(|_, _, _| Box::pin(async { Ok(()) }));
    let set = EndpointSet::with_quarantine(
        vec![
            ("a".into(), a.clone(), true),
            ("b".into(), b.clone(), false),
        ],
        Some(validator),
        config(),
        Arc::new(SystemClock::new()),
    );
    let before = set.capabilities().await.unwrap();
    assert_eq!(before.batch.max_items, 1);
    set.encrypt_batch(&context(), &items()[..1]).await.unwrap();
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert!(set.endpoint_status()[1].validated);
    assert_eq!(set.capabilities().await.unwrap(), before);
    a.inner
        .fail_next([CryptoError::Retryable("unavailable".into())]);
    set.encrypt_batch(&context(), &items()).await.unwrap();
    assert_eq!(b.largest_request.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn peer_retry_contract_overrides_a_more_permissive_dispatch_config() {
    let mut a = Peer::new(16, 4096).await;
    a.caps.retry_safe = false;
    a.inner
        .fail_next([CryptoError::Retryable("uncertain completion".into())]);
    let a = Arc::new(a);
    let b = Arc::new(Peer::new(16, 4096).await);
    let set = set(a.clone(), b.clone());
    assert!(set.encrypt_batch(&context(), &items()[..1]).await.is_err());
    assert_eq!(a.inner.encrypt_calls(), 1);
    assert_eq!(b.inner.encrypt_calls(), 0);
    assert_eq!(set.metrics().retries_refused_unsafe_total(), 1);
}

#[tokio::test]
async fn incompatible_or_empty_contract_intersections_are_refused() {
    for mismatch in ["profile", "size", "zero-items", "zero-bytes"] {
        let a = Arc::new(Peer::new(16, 4096).await);
        let mut b = Peer::new(16, 4096).await;
        match mismatch {
            "profile" => b.caps.crypto_compatibility_id = "other-profile".into(),
            "size" => b.caps.supported_plaintext_sizes = vec![512],
            "zero-items" => b.caps.batch.max_items = 0,
            "zero-bytes" => b.caps.batch.max_bytes = 0,
            _ => unreachable!(),
        }
        let b = Arc::new(b);
        let set = set(a.clone(), b.clone());
        if mismatch == "size" {
            assert!(set
                .capabilities()
                .await
                .unwrap()
                .supported_plaintext_sizes
                .is_empty());
        } else {
            assert_eq!(
                set.capabilities().await.unwrap_err().class(),
                ErrorClass::ProviderFatal,
                "accepted {mismatch}"
            );
        }
        assert!(set.encrypt_batch(&context(), &items()).await.is_err());
        assert_eq!(a.inner.encrypt_calls(), 0);
        assert_eq!(b.inner.encrypt_calls(), 0);
    }
}

#[tokio::test]
async fn unsupported_plaintext_never_reaches_any_endpoint() {
    let a = Arc::new(Peer::new(16, 4096).await);
    let b = Arc::new(Peer::new(16, 4096).await);
    let set = set(a.clone(), b.clone());
    let unsupported = PlaintextUnit {
        unit_index: 1,
        data: SecretBuffer::from_slice(&[0; UNIT / 2]),
    };
    assert!(matches!(
        set.encrypt_batch(&context(), &[unsupported]).await,
        Err(CryptoError::NonRetryableRequest(_))
    ));
    assert_eq!(a.inner.encrypt_calls(), 0);
    assert_eq!(b.inner.encrypt_calls(), 0);
}

#[tokio::test]
async fn a_non_batch_peer_limits_every_rpc_to_one_item() {
    let a = Arc::new(Peer::new(16, 4096).await);
    let mut b = Peer::new(16, 4096).await;
    b.caps.batch.supported = false;
    let b = Arc::new(b);
    a.inner
        .fail_next([CryptoError::Retryable("unavailable".into())]);
    let set = set(a, b.clone());
    let caps = set.capabilities().await.unwrap();
    assert!(!caps.batch.supported);
    assert_eq!(caps.batch.max_items, 1);
    set.encrypt_batch(&context(), &items()).await.unwrap();
    assert_eq!(b.largest_request.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_incompatible_quarantined_peer_cannot_replace_the_validated_contract() {
    let a = Arc::new(Peer::new(16, 4096).await);
    let mut b = Peer::new(1, UNIT as u64).await;
    b.caps.crypto_compatibility_id = "incompatible-profile".into();
    b.caps.supported_plaintext_sizes.clear();
    let b = Arc::new(b);
    let validator: EndpointValidator = Arc::new(|_, _, _| Box::pin(async { Ok(()) }));
    let set = EndpointSet::with_quarantine(
        vec![
            ("b".into(), b.clone(), false),
            ("a".into(), a.clone(), true),
        ],
        Some(validator),
        config(),
        Arc::new(SystemClock::new()),
    );
    let caps = set.capabilities().await.unwrap();
    assert_eq!(caps.crypto_compatibility_id, a.caps.crypto_compatibility_id);
    assert_eq!(caps.batch.max_items, 16);
    set.encrypt_batch(&context(), &items()).await.unwrap();
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    let quarantined = &set.endpoint_status()[0];
    assert!(!quarantined.validated);
    assert!(quarantined.rejected);
    assert_eq!(b.inner.encrypt_calls(), 0);
}

#[tokio::test]
async fn invalid_ciphertext_is_refused_before_sending_any_chunk() {
    // FakeCryptoProvider appends an eight-byte ciphertext trailer.
    for length in [0, UNIT + 8 + 1] {
        let a = Arc::new(Peer::new(1, UNIT as u64).await);
        let b = Arc::new(Peer::new(1, UNIT as u64).await);
        let set = set(a.clone(), b.clone());
        let ciphertext = vec![
            CiphertextUnit {
                unit_index: 0,
                data: vec![0; UNIT],
            },
            CiphertextUnit {
                unit_index: 1,
                data: vec![0; length],
            },
        ];
        assert!(matches!(
            set.decrypt_batch(&context(), &ciphertext).await,
            Err(CryptoError::NonRetryableRequest(_))
        ));
        assert_eq!(a.inner.decrypt_calls(), 0, "invalid length {length}");
        assert_eq!(b.inner.decrypt_calls(), 0, "invalid length {length}");
    }
}

struct StalledCapabilities {
    started: tokio::sync::Notify,
}

#[async_trait]
impl CryptoProvider for StalledCapabilities {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.started.notify_one();
        std::future::pending().await
    }

    async fn encrypt_batch(
        &self,
        _: &CryptoContext,
        _: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        panic!("stalled capabilities must never permit an RPC")
    }

    async fn decrypt_batch(
        &self,
        _: &CryptoContext,
        _: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        panic!("stalled capabilities must never permit an RPC")
    }
}

async fn stalled_capabilities_respect_deadline(decrypt: bool) {
    let peer = Arc::new(StalledCapabilities {
        started: tokio::sync::Notify::new(),
    });
    let clock = Arc::new(maki_test_support::ManualClock::new());
    let set = Arc::new(EndpointSet::new(
        vec![("stalled".into(), peer.clone())],
        config(),
        clock.clone(),
    ));
    let request_set = set.clone();
    let mut call = tokio::spawn(async move {
        if decrypt {
            request_set
                .decrypt_batch(
                    &context(),
                    &[CiphertextUnit {
                        unit_index: 0,
                        data: vec![0; UNIT],
                    }],
                )
                .await
                .map(|_| ())
        } else {
            request_set
                .encrypt_batch(&context(), &items())
                .await
                .map(|_| ())
        }
    });
    peer.started.notified().await;
    tokio::task::yield_now().await;
    clock.advance(Duration::from_secs(2));
    let result = tokio::time::timeout(Duration::from_millis(100), &mut call).await;
    if result.is_err() {
        call.abort();
    }
    let result = result
        .expect("capability discovery exceeded the operation deadline")
        .unwrap();
    assert!(matches!(result, Err(CryptoError::Retryable(_))));
    assert_eq!(set.metrics().deadline_exceeded_total(), 1);
    assert_eq!(set.global_inflight(), (0, 0));
}

#[tokio::test]
async fn encrypt_deadline_includes_capability_discovery() {
    stalled_capabilities_respect_deadline(false).await;
}

#[tokio::test]
async fn decrypt_deadline_includes_capability_discovery() {
    stalled_capabilities_respect_deadline(true).await;
}
