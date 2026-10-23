//! BUG-153: time already spent in the admitted queue counts toward max_wait.

use std::sync::{Arc, Mutex};
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
const MAX_WAIT: Duration = Duration::from_millis(50);

struct Provider {
    calls: Mutex<Vec<Vec<u64>>>,
    release: Notify,
    limit: Option<Duration>,
}

impl Provider {
    fn new(limit: Option<Duration>) -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            release: Notify::new(),
            limit,
        })
    }

    fn calls(&self) -> Vec<Vec<u64>> {
        self.calls.lock().unwrap().clone()
    }

    async fn begin(&self, indexes: Vec<u64>) {
        let block = indexes.contains(&0);
        self.calls.lock().unwrap().push(indexes);
        if block {
            self.release.notified().await;
        }
    }
}

#[async_trait]
impl CryptoProvider for Provider {
    fn max_operation_time(&self) -> Option<Duration> {
        self.limit
    }

    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        Ok(CryptoCapabilities {
            provider_id: "queue-wait-test".into(),
            crypto_compatibility_id: "queue-wait-v1".into(),
            supported_plaintext_sizes: vec![UNIT as u32],
            max_ciphertext_size: UNIT as u32,
            stateless: true,
            retry_safe: true,
            batch: BatchCapability {
                supported: true,
                max_items: 4,
                max_bytes: (4 * UNIT) as u64,
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
        self.begin(items.iter().map(|item| item.unit_index).collect())
            .await;
        Ok(items
            .iter()
            .map(|item| CiphertextUnit {
                unit_index: item.unit_index,
                data: item.data.expose().iter().map(|byte| byte ^ 0x5a).collect(),
            })
            .collect())
    }

    async fn decrypt_batch(
        &self,
        _: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.begin(items.iter().map(|item| item.unit_index).collect())
            .await;
        Ok(items
            .iter()
            .map(|item| PlaintextUnit {
                unit_index: item.unit_index,
                data: SecretBuffer::from_slice(
                    &item.data.iter().map(|byte| byte ^ 0x5a).collect::<Vec<_>>(),
                ),
            })
            .collect())
    }
}

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(153),
        format_version: 1,
        crypto_compatibility_id: "queue-wait-v1".into(),
    }
}

fn config() -> SchedulerConfig {
    SchedulerConfig {
        target_items: 2,
        target_bytes: (2 * UNIT) as u64,
        max_items: 4,
        max_bytes: (4 * UNIT) as u64,
        max_wait: MAX_WAIT,
        max_pending_items: 16,
        max_pending_plaintext_bytes: (16 * UNIT) as u64,
        max_pending_ciphertext_bytes: (16 * UNIT) as u64,
        max_inflight_batches: 1,
    }
}

async fn settle() {
    for _ in 0..128 {
        tokio::task::yield_now().await;
    }
}

fn request(
    scheduler: &Arc<BatchScheduler>,
    context: CryptoContext,
    start: u64,
    count: usize,
    decrypt: bool,
) -> tokio::task::JoinHandle<Result<Vec<u64>, CryptoError>> {
    let scheduler = scheduler.clone();
    tokio::spawn(async move {
        if decrypt {
            scheduler
                .decrypt_batch(
                    &context,
                    &(0..count)
                        .map(|index| CiphertextUnit {
                            unit_index: start + index as u64,
                            data: vec![0x55; UNIT],
                        })
                        .collect::<Vec<_>>(),
                )
                .await
                .map(|items| items.into_iter().map(|item| item.unit_index).collect())
        } else {
            scheduler
                .encrypt_batch(
                    &context,
                    &(0..count)
                        .map(|index| PlaintextUnit {
                            unit_index: start + index as u64,
                            data: SecretBuffer::zeroed(UNIT),
                        })
                        .collect::<Vec<_>>(),
                )
                .await
                .map(|items| items.into_iter().map(|item| item.unit_index).collect())
        }
    })
}

async fn assert_backlog_dispatch(decrypt: bool, final_count: usize, wait: Duration, bounded: bool) {
    let clock = Arc::new(ManualClock::new());
    let provider = Provider::new(bounded.then_some(Duration::from_millis(180)));
    let scheduler = Arc::new(BatchScheduler::with_unit_size(
        provider.clone(),
        SchedulerConfig {
            max_wait: wait,
            ..config()
        },
        clock.clone(),
        UNIT as u32,
    ));
    let first = request(&scheduler, context(), 0, 2, decrypt);
    settle().await;
    assert_eq!(provider.calls(), vec![vec![0, 1]]);
    let second = request(&scheduler, context(), 10, 2, decrypt);
    settle().await;
    let third = request(&scheduler, context(), 20, final_count, decrypt);
    settle().await;
    assert_eq!(scheduler.stats().pending_items(), 2 + final_count as u64);

    clock.advance(Duration::from_millis(160));
    provider.release.notify_one();
    settle().await;
    let dispatched_at_release = third.is_finished();
    assert_eq!(first.await.unwrap().unwrap(), vec![0, 1]);
    assert_eq!(second.await.unwrap().unwrap(), vec![10, 11]);

    // Finish even on the old implementation, then assert the original deadline.
    clock.advance(if bounded {
        Duration::from_millis(20)
    } else {
        MAX_WAIT
    });
    settle().await;
    assert!(third.is_finished());
    let result = third.await.unwrap();
    assert_eq!(scheduler.stats().pending_items(), 0);
    assert_eq!(
        result.unwrap(),
        (0..final_count)
            .map(|index| 20 + index as u64)
            .collect::<Vec<_>>()
    );
    assert!(
        dispatched_at_release,
        "max_wait elapsed in the admitted queue; do not wait another window"
    );
    assert_eq!(provider.calls().len(), 3);
}

#[tokio::test]
async fn encrypt_queued_singleton_uses_its_original_wait_deadline() {
    assert_backlog_dispatch(false, 1, MAX_WAIT, false).await;
}

#[tokio::test]
async fn decrypt_queued_singleton_uses_its_original_wait_deadline() {
    assert_backlog_dispatch(true, 1, MAX_WAIT, false).await;
}

#[tokio::test]
async fn queued_singleton_completes_before_the_operation_deadline() {
    assert_backlog_dispatch(false, 1, MAX_WAIT, true).await;
}

#[tokio::test]
async fn queued_full_group_dispatches_without_waiting() {
    assert_backlog_dispatch(false, 2, MAX_WAIT, false).await;
}

#[tokio::test]
async fn queued_singleton_with_zero_wait_dispatches_immediately() {
    assert_backlog_dispatch(false, 1, Duration::ZERO, false).await;
}

#[tokio::test]
async fn fresh_singleton_waits_only_its_original_window() {
    let clock = Arc::new(ManualClock::new());
    let provider = Provider::new(None);
    let scheduler = Arc::new(BatchScheduler::new(
        provider.clone(),
        config(),
        clock.clone(),
    ));
    let caller = request(&scheduler, context(), 20, 1, false);
    settle().await;
    clock.advance(Duration::from_millis(49));
    settle().await;
    assert!(!caller.is_finished());
    assert!(provider.calls().is_empty());
    clock.advance(Duration::from_millis(1));
    settle().await;
    assert!(caller.is_finished());
    assert_eq!(caller.await.unwrap().unwrap(), vec![20]);
}

#[tokio::test]
async fn cancelling_oldest_group_uses_survivors_original_deadline() {
    let clock = Arc::new(ManualClock::new());
    let provider = Provider::new(None);
    let scheduler = Arc::new(BatchScheduler::new(
        provider.clone(),
        SchedulerConfig {
            target_items: 3,
            target_bytes: (3 * UNIT) as u64,
            ..config()
        },
        clock.clone(),
    ));
    let cancelled = request(&scheduler, context(), 10, 1, false);
    settle().await;
    clock.advance(Duration::from_millis(20));
    let surviving = request(&scheduler, context(), 20, 1, false);
    settle().await;
    clock.advance(Duration::from_millis(10));
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    settle().await;
    clock.advance(Duration::from_millis(20));
    settle().await;
    assert!(
        provider.calls().is_empty(),
        "cancelled caller must not shorten the surviving window"
    );
    clock.advance(Duration::from_millis(19));
    settle().await;
    assert!(!surviving.is_finished());
    clock.advance(Duration::from_millis(1));
    settle().await;
    assert!(
        surviving.is_finished(),
        "cancellation must not restart the survivor's window"
    );
    assert_eq!(surviving.await.unwrap().unwrap(), vec![20]);
    assert_eq!(provider.calls(), vec![vec![20]]);
}

async fn assert_carried_group_keeps_deadline(different_context: bool) {
    let clock = Arc::new(ManualClock::new());
    let provider = Provider::new(None);
    let scheduler = Arc::new(BatchScheduler::new(
        provider.clone(),
        config(),
        clock.clone(),
    ));
    let first = request(&scheduler, context(), 0, 2, false);
    settle().await;
    let second = request(&scheduler, context(), 10, 1, false);
    settle().await;
    clock.advance(Duration::from_millis(20));
    let mut carried_context = context();
    let carried_index = if different_context {
        carried_context.volume_uuid = uuid::Uuid::from_u128(154);
        20
    } else {
        10
    };
    let carried = request(&scheduler, carried_context, carried_index, 1, false);
    settle().await;
    clock.advance(Duration::from_millis(140));
    provider.release.notify_one();
    settle().await;
    let finished = carried.is_finished();
    clock.advance(MAX_WAIT);
    settle().await;
    assert_eq!(first.await.unwrap().unwrap(), vec![0, 1]);
    assert_eq!(second.await.unwrap().unwrap(), vec![10]);
    assert_eq!(carried.await.unwrap().unwrap(), vec![carried_index]);
    assert!(
        finished,
        "an incompatible carried group must retain its queue age"
    );
    assert_eq!(
        provider.calls(),
        vec![vec![0, 1], vec![10], vec![carried_index]]
    );
}

#[tokio::test]
async fn carried_group_with_different_context_retains_its_deadline() {
    assert_carried_group_keeps_deadline(true).await;
}

#[tokio::test]
async fn carried_group_with_duplicate_unit_retains_its_deadline() {
    assert_carried_group_keeps_deadline(false).await;
}

#[tokio::test]
async fn queue_wait_starts_after_admission() {
    let clock = Arc::new(ManualClock::new());
    let provider = Provider::new(None);
    let scheduler = Arc::new(BatchScheduler::new(
        provider.clone(),
        SchedulerConfig {
            max_pending_items: 2,
            ..config()
        },
        clock.clone(),
    ));
    let first = request(&scheduler, context(), 0, 2, false);
    settle().await;
    let second = request(&scheduler, context(), 10, 2, false);
    settle().await;
    let waiting_admission = request(&scheduler, context(), 20, 1, false);
    settle().await;
    assert_eq!(scheduler.stats().pending_items(), 2);
    clock.advance(Duration::from_millis(160));
    provider.release.notify_one();
    settle().await;
    assert_eq!(first.await.unwrap().unwrap(), vec![0, 1]);
    assert_eq!(second.await.unwrap().unwrap(), vec![10, 11]);
    assert_eq!(provider.calls().len(), 2);
    assert_eq!(scheduler.stats().pending_items(), 1);
    clock.advance(Duration::from_millis(49));
    settle().await;
    assert!(!waiting_admission.is_finished());
    clock.advance(Duration::from_millis(1));
    settle().await;
    assert!(waiting_admission.is_finished());
    assert_eq!(waiting_admission.await.unwrap().unwrap(), vec![20]);
}

#[tokio::test]
async fn queued_singleton_waits_only_the_remaining_original_window() {
    let clock = Arc::new(ManualClock::new());
    let provider = Provider::new(None);
    let scheduler = Arc::new(BatchScheduler::new(
        provider.clone(),
        config(),
        clock.clone(),
    ));
    let first = request(&scheduler, context(), 0, 2, false);
    settle().await;
    let second = request(&scheduler, context(), 10, 2, false);
    settle().await;
    let third = request(&scheduler, context(), 20, 1, false);
    settle().await;
    clock.advance(Duration::from_millis(30));
    provider.release.notify_one();
    settle().await;
    assert_eq!(first.await.unwrap().unwrap(), vec![0, 1]);
    assert_eq!(second.await.unwrap().unwrap(), vec![10, 11]);
    assert_eq!(provider.calls().len(), 2);
    assert!(!third.is_finished());
    clock.advance(Duration::from_millis(19));
    settle().await;
    assert!(!third.is_finished());
    clock.advance(Duration::from_millis(1));
    settle().await;
    assert!(
        third.is_finished(),
        "queued time must count toward the original 50 ms window"
    );
    assert_eq!(third.await.unwrap().unwrap(), vec![20]);
}
