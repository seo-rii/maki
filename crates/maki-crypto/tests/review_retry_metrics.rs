//! BUG-065: every dispatched split retry contributes to provider call metrics.

use std::future::Future;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use async_trait::async_trait;
use maki_crypto::scheduler::{BatchScheduler, SchedulerConfig};
use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError,
    CryptoProvider, PlaintextUnit, SecretBuffer,
};
use maki_test_support::ManualClock;
use tokio::sync::Notify;

const UNIT: usize = 64;

struct Provider {
    calls: AtomicUsize,
    items: AtomicUsize,
    retry_safe: bool,
    reject_combined: bool,
    blocked: u8,
    started: [Notify; 4],
    release: [Notify; 4],
}

impl Provider {
    fn new(retry_safe: bool, reject_combined: bool, blocked: u8) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            items: AtomicUsize::new(0),
            retry_safe,
            reject_combined,
            blocked,
            started: std::array::from_fn(|_| Notify::new()),
            release: std::array::from_fn(|_| Notify::new()),
        })
    }

    async fn begin(&self, units: impl Iterator<Item = u64>) -> Result<(), CryptoError> {
        let units: Vec<_> = units.collect();
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.items.fetch_add(units.len(), Ordering::SeqCst);
        let tag = units[0] / 10;
        if self.reject_combined && units.iter().any(|unit| unit / 10 != tag) {
            return Err(CryptoError::NonRetryableRequest(
                "one request rejected".into(),
            ));
        }
        self.started[tag as usize].notify_one();
        if self.blocked & (1 << tag) != 0 {
            self.release[tag as usize].notified().await;
        }
        Ok(())
    }
}

#[async_trait]
impl CryptoProvider for Provider {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        Ok(CryptoCapabilities {
            provider_id: "retry-metrics".into(),
            crypto_compatibility_id: "retry-metrics-v1".into(),
            supported_plaintext_sizes: vec![UNIT as u32],
            max_ciphertext_size: UNIT as u32,
            stateless: true,
            retry_safe: self.retry_safe,
            batch: BatchCapability {
                supported: true,
                max_items: 8,
                max_bytes: 8 * UNIT as u64,
            },
            integrity: Capability::Absent,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        })
    }

    async fn encrypt_batch(
        &self,
        _: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.begin(items.iter().map(|item| item.unit_index)).await?;
        Ok(items
            .iter()
            .map(|item| CiphertextUnit {
                unit_index: item.unit_index,
                data: item.data.expose().to_vec(),
            })
            .collect())
    }

    async fn decrypt_batch(
        &self,
        _: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.begin(items.iter().map(|item| item.unit_index)).await?;
        Ok(items
            .iter()
            .map(|item| PlaintextUnit {
                unit_index: item.unit_index,
                data: SecretBuffer::from_slice(&item.data),
            })
            .collect())
    }
}

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x65),
        format_version: 1,
        crypto_compatibility_id: "retry-metrics-v1".into(),
    }
}

fn scheduler(provider: Arc<Provider>, width: u32, target: usize) -> Arc<BatchScheduler> {
    Arc::new(BatchScheduler::with_unit_size(
        provider,
        SchedulerConfig {
            target_items: target,
            target_bytes: 8 * UNIT as u64,
            max_items: 8,
            max_bytes: 8 * UNIT as u64,
            max_wait: Duration::from_secs(1),
            max_pending_items: 8,
            max_pending_plaintext_bytes: 8 * UNIT as u64,
            max_pending_ciphertext_bytes: 8 * UNIT as u64,
            max_inflight_batches: width,
        },
        Arc::new(ManualClock::new()),
        UNIT as u32,
    ))
}

#[derive(Clone, Copy)]
enum Direction {
    Encrypt,
    Decrypt,
}

type Request = tokio::task::JoinHandle<Result<Vec<u64>, CryptoError>>;

fn request(
    scheduler: &Arc<BatchScheduler>,
    direction: Direction,
    tag: u64,
    count: usize,
) -> Request {
    let scheduler = scheduler.clone();
    tokio::spawn(async move {
        let units = (0..count).map(|index| tag * 10 + index as u64);
        match direction {
            Direction::Encrypt => scheduler
                .encrypt_batch(
                    &context(),
                    &units
                        .map(|unit_index| PlaintextUnit {
                            unit_index,
                            data: SecretBuffer::from_slice(&[0x55; UNIT]),
                        })
                        .collect::<Vec<_>>(),
                )
                .await
                .map(|items| items.into_iter().map(|item| item.unit_index).collect()),
            Direction::Decrypt => scheduler
                .decrypt_batch(
                    &context(),
                    &units
                        .map(|unit_index| CiphertextUnit {
                            unit_index,
                            data: vec![0x55; UNIT],
                        })
                        .collect::<Vec<_>>(),
                )
                .await
                .map(|items| items.into_iter().map(|item| item.unit_index).collect()),
        }
    })
}

async fn wait_idle(scheduler: &BatchScheduler) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while scheduler.stats().inflight_batches() != 0
            || scheduler.stats().pending_items() != 0
            || scheduler.stats().pending_bytes() != 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled requests release their scheduler charges");
}

fn assert_metrics(
    scheduler: &BatchScheduler,
    provider: &Provider,
    calls: u64,
    items: u64,
    coalesced: u64,
) {
    let stats = scheduler.stats();
    assert_eq!(provider.calls.load(Ordering::SeqCst) as u64, calls);
    assert_eq!(provider.items.load(Ordering::SeqCst) as u64, items);
    assert_eq!(
        stats.batches_total(),
        calls,
        "all dispatched provider calls are counted"
    );
    assert_eq!(
        stats.batched_items_total(),
        items,
        "repeated items are counted for each call"
    );
    assert_eq!(stats.coalesced_batches_total(), coalesced);
}

async fn split_retry(direction: Direction) {
    let provider = Provider::new(true, true, 0);
    let scheduler = scheduler(provider.clone(), 2, 3);
    let left = request(&scheduler, direction, 1, 2);
    let right = request(&scheduler, direction, 2, 1);
    assert_eq!(left.await.unwrap().unwrap(), vec![10, 11]);
    assert_eq!(right.await.unwrap().unwrap(), vec![20]);
    assert_metrics(&scheduler, &provider, 3, 6, 1);
    assert_eq!(scheduler.stats().inflight_batches(), 0);
    assert_eq!(scheduler.stats().pending_items(), 0);
    assert_eq!(scheduler.stats().pending_bytes(), 0);
}

#[tokio::test]
async fn encrypt_split_retries_count_calls_and_repeated_items() {
    split_retry(Direction::Encrypt).await;
}

#[tokio::test]
async fn decrypt_split_retries_count_calls_and_repeated_items() {
    split_retry(Direction::Decrypt).await;
}

#[tokio::test]
async fn cancelled_unstarted_retry_does_not_increment_totals() {
    let provider = Provider::new(true, true, 1 << 1);
    let scheduler = scheduler(provider.clone(), 1, 2);
    let left = request(&scheduler, Direction::Encrypt, 1, 1);
    let right = request(&scheduler, Direction::Encrypt, 2, 1);
    provider.started[1].notified().await;
    assert_metrics(&scheduler, &provider, 2, 3, 1);
    assert_eq!(scheduler.stats().inflight_batches(), 1);
    right.abort();
    assert!(right.await.unwrap_err().is_cancelled());
    provider.release[1].notify_one();
    left.await.unwrap().unwrap();
    assert_metrics(&scheduler, &provider, 2, 3, 1);
    assert_eq!(scheduler.stats().inflight_batches(), 0);
}

#[tokio::test]
async fn cancelling_running_retries_retains_totals_and_releases_inflight() {
    let provider = Provider::new(true, true, (1 << 1) | (1 << 2));
    let scheduler = scheduler(provider.clone(), 2, 2);
    let left = request(&scheduler, Direction::Decrypt, 1, 1);
    let right = request(&scheduler, Direction::Decrypt, 2, 1);
    provider.started[1].notified().await;
    provider.started[2].notified().await;
    assert_metrics(&scheduler, &provider, 3, 4, 1);
    assert_eq!(scheduler.stats().inflight_batches(), 2);
    left.abort();
    right.abort();
    assert!(left.await.unwrap_err().is_cancelled());
    assert!(right.await.unwrap_err().is_cancelled());
    wait_idle(&scheduler).await;
    assert_metrics(&scheduler, &provider, 3, 4, 1);
    assert_eq!(scheduler.stats().inflight_batches(), 0);
    assert_eq!(scheduler.stats().pending_items(), 0);
}

#[tokio::test]
async fn non_retry_safe_rejection_counts_only_the_combined_call() {
    let provider = Provider::new(false, true, 0);
    let scheduler = scheduler(provider.clone(), 2, 2);
    let left = request(&scheduler, Direction::Encrypt, 1, 1);
    let right = request(&scheduler, Direction::Encrypt, 2, 1);
    assert!(left.await.unwrap().is_err());
    assert!(right.await.unwrap().is_err());
    assert_metrics(&scheduler, &provider, 1, 2, 1);
    assert_eq!(scheduler.stats().inflight_batches(), 0);
}

#[tokio::test]
async fn successful_coalescing_preserves_the_original_counter_semantics() {
    let provider = Provider::new(true, false, 0);
    let scheduler = scheduler(provider.clone(), 2, 3);
    let left = request(&scheduler, Direction::Encrypt, 1, 2);
    let right = request(&scheduler, Direction::Encrypt, 2, 1);
    left.await.unwrap().unwrap();
    right.await.unwrap().unwrap();
    assert_metrics(&scheduler, &provider, 1, 3, 1);
}

#[tokio::test]
async fn one_request_with_two_items_is_not_a_coalesced_call() {
    let provider = Provider::new(true, false, 0);
    let scheduler = scheduler(provider.clone(), 2, 2);
    request(&scheduler, Direction::Decrypt, 1, 2)
        .await
        .unwrap()
        .unwrap();
    assert_metrics(&scheduler, &provider, 1, 2, 0);
}

#[tokio::test]
async fn cancelled_queued_calls_are_not_counted_as_dispatched() {
    let provider = Provider::new(true, false, 0);
    let scheduler = scheduler(provider.clone(), 2, 2);
    let context = context();
    let left_input = [PlaintextUnit {
        unit_index: 10,
        data: SecretBuffer::zeroed(UNIT),
    }];
    let right_input = [PlaintextUnit {
        unit_index: 20,
        data: SecretBuffer::zeroed(UNIT),
    }];
    let mut left = Box::pin(scheduler.encrypt_batch(&context, &left_input));
    let mut right = Box::pin(scheduler.encrypt_batch(&context, &right_input));
    std::future::poll_fn(|cx| {
        assert!(left.as_mut().poll(cx).is_pending());
        assert!(right.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert_eq!(scheduler.stats().pending_items(), 2);
    drop(left);
    drop(right);
    wait_idle(&scheduler).await;
    assert_metrics(&scheduler, &provider, 0, 0, 0);
    assert_eq!(scheduler.stats().pending_items(), 0);
    assert_eq!(scheduler.stats().pending_bytes(), 0);
    assert_eq!(scheduler.stats().inflight_batches(), 0);
}
