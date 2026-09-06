//! BUG-013 / SPEC §35: bounded-error counts queue admission, coalescing,
//! and batch-slot waits as part of the same operation's wall-clock budget.

use std::sync::Arc;
use std::time::Duration;

use maki_crypto::breaker::{BreakerConfig, CircuitState};
use maki_crypto::checked::CheckedProvider;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::scheduler::{BatchScheduler, SchedulerConfig};
use maki_crypto::{
    CiphertextUnit, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit, SecretBuffer,
};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::ManualClock;

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(13),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".into(),
    }
}

fn scheduler_config() -> SchedulerConfig {
    SchedulerConfig {
        target_items: 8,
        max_wait: Duration::from_secs(1),
        max_inflight_batches: 1,
        ..SchedulerConfig::default()
    }
}

fn endpoint(provider: Arc<FakeCryptoProvider>, clock: Arc<ManualClock>) -> Arc<EndpointSet> {
    Arc::new(EndpointSet::new(
        vec![("only".into(), provider)],
        DispatchConfig {
            retry: RetryPolicy {
                initial_delay: Duration::ZERO,
                max_delay: Duration::ZERO,
            },
            budget: RetryBudgetConfig {
                retry_ratio: 1.0,
                burst: 8,
                min_probe_per_sec: 1.0,
            },
            breaker: BreakerConfig {
                failure_threshold: 1,
                ..BreakerConfig::default()
            },
            global_max_inflight_batches: 8,
            global_max_inflight_bytes: 1 << 20,
            per_endpoint_max_inflight: 8,
            per_endpoint_max_bytes: 1 << 20,
            max_attempts: None,
            max_operation_time: Some(Duration::from_millis(100)),
            retry_safe: true,
            validation_interval: Duration::from_secs(1),
        },
        clock,
    ))
}

fn request(
    scheduler: &Arc<BatchScheduler>,
    index: u64,
) -> tokio::task::JoinHandle<Result<Vec<CiphertextUnit>, CryptoError>> {
    let scheduler = scheduler.clone();
    tokio::spawn(async move {
        scheduler
            .encrypt_batch(
                &context(),
                &[PlaintextUnit {
                    unit_index: index,
                    data: SecretBuffer::zeroed(64),
                }],
            )
            .await
    })
}

async fn settle() {
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn operation_expires_while_waiting_to_coalesce_without_reaching_an_endpoint() {
    let clock = Arc::new(ManualClock::new());
    let provider = Arc::new(FakeCryptoProvider::new(64));
    let endpoints = endpoint(provider.clone(), clock.clone());
    let scheduler = Arc::new(BatchScheduler::new(
        endpoints.clone(),
        scheduler_config(),
        clock.clone(),
    ));
    let task = request(&scheduler, 1);
    settle().await;
    clock.advance(Duration::from_millis(100));
    settle().await;
    assert!(
        task.is_finished(),
        "bounded-error deadline did not include coalescing time"
    );
    assert!(task
        .await
        .unwrap()
        .unwrap_err()
        .to_string()
        .contains("deadline"));
    assert_eq!(provider.encrypt_calls(), 0);
    assert_eq!(scheduler.stats().pending_items(), 0);
    assert_eq!(endpoints.endpoint_status()[0].circuit, CircuitState::Closed);
}

#[tokio::test]
async fn admission_waiters_keep_their_own_deadlines() {
    let clock = Arc::new(ManualClock::new());
    let provider = Arc::new(FakeCryptoProvider::new(64));
    let mut config = scheduler_config();
    config.max_pending_items = 1;
    let scheduler = Arc::new(BatchScheduler::new(
        endpoint(provider.clone(), clock.clone()),
        config,
        clock.clone(),
    ));
    let first = request(&scheduler, 1);
    settle().await;
    clock.advance(Duration::from_millis(50));
    let second = request(&scheduler, 2);
    settle().await;
    assert_eq!(
        scheduler.stats().pending_items(),
        1,
        "second request is waiting for admission"
    );
    clock.advance(Duration::from_millis(50));
    settle().await;
    assert!(
        first.is_finished(),
        "first queued operation exceeded its deadline"
    );
    assert!(
        !second.is_finished(),
        "later caller retains its own operation budget"
    );
    clock.advance(Duration::from_millis(50));
    settle().await;
    assert!(
        second.is_finished(),
        "admission wait restarted the second caller's budget"
    );
    assert!(first.await.unwrap().is_err());
    assert!(second.await.unwrap().is_err());
    assert_eq!(provider.encrypt_calls(), 0);
    assert_eq!(scheduler.stats().pending_items(), 0);
}

#[tokio::test]
async fn rpc_receives_only_the_budget_left_after_coalescing() {
    let clock = Arc::new(ManualClock::new());
    let provider = Arc::new(FakeCryptoProvider::new(64));
    provider.set_latency(clock.clone(), Duration::from_secs(1));
    let endpoints = endpoint(provider.clone(), clock.clone());
    let mut config = scheduler_config();
    config.max_wait = Duration::from_millis(40);
    let scheduler = Arc::new(BatchScheduler::new(
        endpoints.clone(),
        config,
        clock.clone(),
    ));
    let task = request(&scheduler, 1);
    settle().await;
    clock.advance(Duration::from_millis(40));
    settle().await;
    assert_eq!(provider.encrypt_calls(), 1);
    clock.advance(Duration::from_millis(60));
    settle().await;
    assert!(
        task.is_finished(),
        "dispatch restarted the operation budget"
    );
    assert!(task.await.unwrap().is_err());
    assert_eq!(
        endpoints.endpoint_inflight()[0].1,
        0,
        "expired caller left its RPC alive"
    );
    assert_eq!(endpoints.endpoint_status()[0].circuit, CircuitState::Closed);
}

#[tokio::test]
async fn batch_slot_wait_does_not_restart_the_operation_budget() {
    let clock = Arc::new(ManualClock::new());
    let provider = Arc::new(FakeCryptoProvider::new(64));
    provider.set_latency(clock.clone(), Duration::from_secs(1));
    let mut config = scheduler_config();
    config.target_items = 1;
    let scheduler = Arc::new(BatchScheduler::new(
        endpoint(provider.clone(), clock.clone()),
        config,
        clock.clone(),
    ));
    let first = request(&scheduler, 1);
    settle().await;
    clock.advance(Duration::from_millis(10));
    let second = request(&scheduler, 2);
    settle().await;
    assert_eq!(provider.encrypt_calls(), 1);
    clock.advance(Duration::from_millis(90));
    settle().await;
    assert!(first.is_finished());
    assert!(!second.is_finished());
    clock.advance(Duration::from_millis(10));
    settle().await;
    assert!(
        second.is_finished(),
        "batch-slot wait granted a fresh operation budget"
    );
    assert!(first.await.unwrap().is_err());
    assert!(second.await.unwrap().is_err());
}

#[tokio::test]
async fn checked_provider_preserves_the_deadline_for_the_decrypt_queue() {
    let clock = Arc::new(ManualClock::new());
    let provider = Arc::new(FakeCryptoProvider::new(64));
    let inner = Arc::new(CheckedProvider::new(endpoint(
        provider.clone(),
        clock.clone(),
    )));
    let scheduler = Arc::new(BatchScheduler::new(
        inner,
        scheduler_config(),
        clock.clone(),
    ));
    let task = tokio::spawn({
        let scheduler = scheduler.clone();
        async move {
            scheduler
                .decrypt_batch(
                    &context(),
                    &[CiphertextUnit {
                        unit_index: 1,
                        data: vec![0; 72],
                    }],
                )
                .await
        }
    });
    settle().await;
    clock.advance(Duration::from_millis(100));
    settle().await;
    assert!(
        task.is_finished(),
        "checked wrapper lost the decrypt operation deadline"
    );
    assert!(task
        .await
        .unwrap()
        .unwrap_err()
        .to_string()
        .contains("deadline"));
    assert_eq!(provider.decrypt_calls(), 0);
    assert_eq!(scheduler.stats().pending_items(), 0);
}

#[tokio::test]
async fn a_provider_without_a_deadline_keeps_stall_semantics() {
    let clock = Arc::new(ManualClock::new());
    let provider = Arc::new(FakeCryptoProvider::new(64));
    let scheduler = Arc::new(BatchScheduler::new(
        provider.clone(),
        scheduler_config(),
        clock.clone(),
    ));
    let task = request(&scheduler, 1);
    settle().await;
    clock.advance(Duration::from_millis(100));
    settle().await;
    assert!(!task.is_finished());
    clock.advance(Duration::from_millis(900));
    settle().await;
    task.await.unwrap().unwrap();
    assert_eq!(provider.encrypt_calls(), 1);
}
