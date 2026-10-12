//! BUG-058: select a known provider plaintext size without guessing from CT.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use maki_crypto::breaker::{BreakerConfig, CircuitState};
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit,
    SecretBuffer,
};
use maki_test_support::{FakeCryptoProvider, ManualClock};

const UNIT: usize = 512;

struct Peer {
    inner: FakeCryptoProvider,
    wrong_size: bool,
    largest_decrypt: AtomicUsize,
}

impl Peer {
    fn new(wrong_size: bool) -> Self {
        Self {
            inner: FakeCryptoProvider::new(UNIT as u32).with_max_batch(8, UNIT as u64),
            wrong_size,
            largest_decrypt: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl CryptoProvider for Peer {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        let mut caps = self.inner.capabilities().await?;
        caps.supported_plaintext_sizes = vec![UNIT as u32, 4096];
        caps.max_ciphertext_size = 4104;
        Ok(caps)
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.inner.encrypt_batch(context, items).await
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.largest_decrypt
            .fetch_max(items.len(), Ordering::SeqCst);
        let mut output = self.inner.decrypt_batch(context, items).await?;
        if self.wrong_size {
            output[0].data = SecretBuffer::zeroed(4096);
        }
        Ok(output)
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
            open_initial: Duration::from_secs(30),
            open_max: Duration::from_secs(30),
            half_open_max_requests: 1,
            success_threshold: 1,
        },
        global_max_inflight_batches: 2,
        global_max_inflight_bytes: 8192,
        per_endpoint_max_inflight: 1,
        per_endpoint_max_bytes: 8192,
        max_attempts: Some(1),
        max_operation_time: None,
        retry_safe: true,
        validation_interval: Duration::from_secs(30),
    }
}

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(58),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".into(),
    }
}

fn plaintext(size: usize) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: 1,
        data: SecretBuffer::zeroed(size),
    }
}

fn set(peer: Arc<Peer>) -> EndpointSet {
    EndpointSet::new(
        vec![("peer".into(), peer)],
        config(),
        Arc::new(ManualClock::new()),
    )
}

#[tokio::test]
async fn selected_unit_splits_decrypt_logically_even_with_expanded_ciphertext() {
    let peer = Arc::new(Peer::new(false));
    let set = set(peer.clone());
    let before = set.capabilities().await.unwrap();
    let set = set.with_plaintext_size(UNIT as u32);
    assert_eq!(set.capabilities().await.unwrap(), before);
    let input: Vec<_> = (0..4)
        .map(|unit_index| PlaintextUnit {
            unit_index,
            data: SecretBuffer::zeroed(UNIT),
        })
        .collect();
    let encrypted = set.encrypt_batch(&context(), &input).await.unwrap();
    assert!(encrypted.iter().all(|unit| unit.data.len() > UNIT));
    let decrypted = set.decrypt_batch(&context(), &encrypted).await.unwrap();
    for (actual, expected) in decrypted.iter().zip(&input) {
        assert_eq!(actual.unit_index, expected.unit_index);
        assert_eq!(actual.data, expected.data);
    }
    assert_eq!(peer.largest_decrypt.load(Ordering::SeqCst), 1);
    assert_eq!(set.global_inflight(), (0, 0));
}

#[tokio::test]
async fn another_supported_plaintext_size_is_attributed_before_breaker_success() {
    let bad = Arc::new(Peer::new(true));
    let good = Arc::new(Peer::new(false));
    let ciphertext = good
        .encrypt_batch(&context(), &[plaintext(UNIT)])
        .await
        .unwrap();
    let set = EndpointSet::new(
        vec![("bad".into(), bad.clone()), ("good".into(), good.clone())],
        config(),
        Arc::new(ManualClock::new()),
    )
    .with_plaintext_size(UNIT as u32);
    let plain = set.decrypt_batch(&context(), &ciphertext).await.unwrap();
    assert_eq!(plain[0].data.len(), UNIT);
    assert_eq!(bad.inner.decrypt_calls(), 1);
    assert_eq!(good.inner.decrypt_calls(), 1);
    assert_eq!(set.endpoint_states()[0].1, CircuitState::Open);
    assert_eq!(set.global_inflight(), (0, 0));
}

#[tokio::test]
async fn unsupported_or_unadmittable_selected_sizes_fail_before_any_rpc() {
    for size in [0, 1024, 4096] {
        let peer = Arc::new(Peer::new(false));
        let set = set(peer.clone()).with_plaintext_size(size);
        assert!(matches!(
            set.capabilities().await,
            Err(CryptoError::NonRetryableRequest(_))
        ));
        assert!(set
            .encrypt_batch(&context(), &[plaintext(UNIT)])
            .await
            .is_err());
        assert!(set
            .decrypt_batch(
                &context(),
                &[CiphertextUnit {
                    unit_index: 1,
                    data: vec![0x11; UNIT],
                }],
            )
            .await
            .is_err());
        assert_eq!(peer.inner.encrypt_calls(), 0);
        assert_eq!(peer.inner.decrypt_calls(), 0);
    }
}

#[tokio::test]
async fn selected_unit_rejects_an_entire_mixed_input_before_any_rpc() {
    let peer = Arc::new(Peer::new(false));
    let set = set(peer.clone()).with_plaintext_size(UNIT as u32);
    assert!(matches!(
        set.encrypt_batch(&context(), &[plaintext(UNIT), plaintext(4096)])
            .await,
        Err(CryptoError::NonRetryableRequest(_))
    ));
    assert_eq!(peer.inner.encrypt_calls(), 0);
    assert_eq!(set.global_inflight(), (0, 0));
}

#[tokio::test]
async fn unbound_dispatch_remains_conservative_instead_of_guessing_from_ciphertext() {
    let peer = Arc::new(Peer::new(false));
    let ciphertext = peer
        .encrypt_batch(&context(), &[plaintext(UNIT)])
        .await
        .unwrap();
    let set = set(peer.clone());
    assert!(matches!(
        set.decrypt_batch(&context(), &ciphertext).await,
        Err(CryptoError::NonRetryableRequest(_))
    ));
    assert_eq!(peer.inner.decrypt_calls(), 0);
}
