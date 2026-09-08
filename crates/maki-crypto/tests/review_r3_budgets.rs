//! R3-003: plaintext batching and resident ciphertext admission are distinct.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::flow::{BoundedQueue, DualSemaphore};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::scheduler::{BatchScheduler, SchedulerConfig};
use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit,
    SecretBuffer, SystemClock,
};
use maki_test_support::fake_provider::FakeCryptoProvider;

const UNIT: usize = 256;
const CIPHER: u64 = UNIT as u64 + 8;

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0xB003),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".into(),
    }
}

fn plaintext(index: u64) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: index,
        data: SecretBuffer::from_slice(&[7; UNIT]),
    }
}

struct StrictProvider {
    inner: FakeCryptoProvider,
    logical_cap: u64,
}

#[async_trait]
impl CryptoProvider for StrictProvider {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.inner.capabilities().await
    }

    async fn encrypt_batch(
        &self,
        ctx: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.inner.encrypt_batch(ctx, items).await
    }

    async fn decrypt_batch(
        &self,
        ctx: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        assert!(
            items.len() as u64 * UNIT as u64 <= self.logical_cap,
            "scheduler sent a batch exceeding the provider's logical cap"
        );
        self.inner.decrypt_batch(ctx, items).await
    }
}

fn scheduler(provider: Arc<dyn CryptoProvider>, cap: u64, pending: u64) -> BatchScheduler {
    BatchScheduler::new(
        provider,
        SchedulerConfig {
            target_items: 128,
            target_bytes: cap,
            max_bytes: cap,
            max_pending_ciphertext_bytes: pending,
            max_wait: Duration::from_millis(5),
            ..SchedulerConfig::default()
        },
        Arc::new(SystemClock::new()),
    )
}

#[tokio::test]
async fn oversized_semaphore_acquires_do_not_consume_capacity() {
    for (items, bytes) in [(1, 1025), (3, 1024)] {
        let semaphore = DualSemaphore::new(2, 1024);
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            semaphore.acquire_n(items, bytes),
        )
        .await
        .expect("oversize admission must fail immediately");
        assert_eq!(
            semaphore.available_items(),
            2,
            "oversize acquired item slots"
        );
        assert_eq!(semaphore.available_bytes(), 1024, "oversize acquired bytes");
        assert!(matches!(result, Err(CryptoError::NonRetryableRequest(_))));
    }
}

#[tokio::test]
async fn oversized_queue_push_never_enqueues() {
    let queue = BoundedQueue::new(1, 1024);
    let result = queue.push(42, 1025).await;
    assert!(matches!(result, Err(CryptoError::NonRetryableRequest(_))));
    assert!(queue.is_empty(), "queue accepted an over-budget allocation");
}

#[tokio::test]
async fn decrypt_group_respects_logical_cap_with_roomy_ciphertext_queue() {
    let provider = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let cts = provider
        .encrypt_batch(&context(), &[plaintext(1), plaintext(2)])
        .await
        .unwrap();
    let scheduler = scheduler(provider.clone(), UNIT as u64, 16 * CIPHER);
    let result = scheduler.decrypt_batch(&context(), &cts).await;
    assert!(matches!(result, Err(CryptoError::NonRetryableRequest(_))));
    assert_eq!(provider.decrypt_calls(), 0);
    assert_eq!(scheduler.stats().pending_bytes(), 0);
}

#[tokio::test]
async fn decrypt_coalesces_using_logical_bytes_not_ciphertext_bytes() {
    let provider = Arc::new(StrictProvider {
        inner: FakeCryptoProvider::new(UNIT as u32),
        logical_cap: 2 * UNIT as u64,
    });
    let cts = provider
        .encrypt_batch(&context(), &[plaintext(1), plaintext(2)])
        .await
        .unwrap();
    let scheduler = scheduler(provider.clone(), 2 * UNIT as u64, 16 * CIPHER);
    let ctx = context();
    let (a, b) = tokio::join!(
        scheduler.decrypt_batch(&ctx, &cts[..1]),
        scheduler.decrypt_batch(&ctx, &cts[1..]),
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(
        provider.inner.decrypt_calls(),
        1,
        "overhead prevented valid coalescing"
    );
}

#[tokio::test]
async fn decrypt_pending_boundary_counts_ciphertext_overhead() {
    for (pending, accepted) in [(CIPHER - 1, false), (CIPHER, true), (CIPHER + 1, true)] {
        let provider = Arc::new(FakeCryptoProvider::new(UNIT as u32));
        let cts = provider
            .encrypt_batch(&context(), &[plaintext(1)])
            .await
            .unwrap();
        let scheduler = scheduler(provider, UNIT as u64, pending);
        assert_eq!(
            scheduler.decrypt_batch(&context(), &cts).await.is_ok(),
            accepted
        );
    }
}

#[tokio::test]
async fn dispatcher_rejects_ciphertext_over_budget_without_sending() {
    for (global, local) in [(CIPHER - 1, CIPHER), (CIPHER, CIPHER - 1), (CIPHER, CIPHER)] {
        let provider = Arc::new(FakeCryptoProvider::new(UNIT as u32));
        let cts = provider
            .encrypt_batch(&context(), &[plaintext(1)])
            .await
            .unwrap();
        let set = EndpointSet::new(
            vec![("test".into(), provider.clone() as Arc<dyn CryptoProvider>)],
            DispatchConfig {
                retry: RetryPolicy {
                    initial_delay: Duration::from_millis(1),
                    max_delay: Duration::from_millis(10),
                },
                budget: RetryBudgetConfig {
                    retry_ratio: 1.0,
                    burst: 2,
                    min_probe_per_sec: 1.0,
                },
                breaker: Default::default(),
                global_max_inflight_batches: 2,
                global_max_inflight_bytes: global,
                per_endpoint_max_inflight: 2,
                per_endpoint_max_bytes: local,
                max_attempts: Some(1),
                max_operation_time: None,
                retry_safe: true,
                validation_interval: Duration::from_secs(1),
            },
            Arc::new(SystemClock::new()),
        );
        let result = set.decrypt_batch(&context(), &cts).await;
        let accepted = global >= CIPHER && local >= CIPHER;
        assert_eq!(result.is_ok(), accepted);
        assert_eq!(provider.decrypt_calls(), usize::from(accepted));
        if !accepted {
            assert!(matches!(result, Err(CryptoError::NonRetryableRequest(_))));
        }
    }
}
