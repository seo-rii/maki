//! BUG-012: cancelling callers must stop abandoned batches and release
//! queued resources without interrupting another caller in the same batch.

use std::sync::Arc;
use std::time::Duration;

use maki_crypto::scheduler::{BatchScheduler, SchedulerConfig};
use maki_crypto::{CryptoContext, CryptoProvider, PlaintextUnit, SecretBuffer};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::ManualClock;

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(12),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".into(),
    }
}

fn plaintext(index: u64) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: index,
        data: SecretBuffer::zeroed(64),
    }
}

fn config() -> SchedulerConfig {
    SchedulerConfig {
        target_items: 1,
        max_items: 8,
        max_inflight_batches: 1,
        max_wait: Duration::from_secs(60),
        max_pending_items: 8,
        ..SchedulerConfig::default()
    }
}

async fn settle() {
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
}

fn request(
    scheduler: &Arc<BatchScheduler>,
    index: u64,
) -> tokio::task::JoinHandle<Result<Vec<maki_crypto::CiphertextUnit>, maki_crypto::CryptoError>> {
    let scheduler = scheduler.clone();
    tokio::spawn(async move {
        scheduler
            .encrypt_batch(&context(), &[plaintext(index)])
            .await
    })
}

#[tokio::test]
async fn cancelling_the_only_caller_abandons_the_rpc_and_releases_its_batch_slot() {
    let clock = Arc::new(ManualClock::new());
    let provider = Arc::new(FakeCryptoProvider::new(64));
    provider.set_latency(clock.clone(), Duration::from_secs(10));
    let scheduler = Arc::new(BatchScheduler::new(
        provider.clone(),
        config(),
        clock.clone(),
    ));
    let first = request(&scheduler, 1);
    settle().await;
    assert_eq!(provider.encrypt_calls(), 1);
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    settle().await;
    assert_eq!(
        clock.sleeper_count(),
        0,
        "cancelled caller left its provider RPC alive"
    );
    provider.set_latency(clock, Duration::ZERO);
    let healthy = request(&scheduler, 2);
    settle().await;
    assert!(
        healthy.is_finished(),
        "abandoned batch kept the only dispatch slot"
    );
    assert_eq!(healthy.await.unwrap().unwrap()[0].unit_index, 2);
}

#[tokio::test]
async fn cancelling_during_coalescing_releases_pending_capacity_immediately() {
    let clock = Arc::new(ManualClock::new());
    let provider = Arc::new(FakeCryptoProvider::new(64));
    let mut cfg = config();
    cfg.target_items = 2;
    cfg.max_pending_items = 1;
    let scheduler = Arc::new(BatchScheduler::new(provider.clone(), cfg, clock.clone()));
    let first = request(&scheduler, 1);
    settle().await;
    assert_eq!(scheduler.stats().pending_items(), 1);
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    settle().await;
    assert_eq!(
        scheduler.stats().pending_items(),
        0,
        "cancelled group retains queue admission"
    );
    assert_eq!(scheduler.stats().pending_bytes(), 0);
    assert_eq!(
        clock.sleeper_count(),
        0,
        "cancelled group still waits for max_wait"
    );
    assert_eq!(provider.encrypt_calls(), 0);
}

#[tokio::test]
async fn a_cancelled_batch_waiting_for_dispatch_is_never_sent() {
    let clock = Arc::new(ManualClock::new());
    let provider = Arc::new(FakeCryptoProvider::new(64));
    provider.set_latency(clock.clone(), Duration::from_secs(10));
    let scheduler = Arc::new(BatchScheduler::new(
        provider.clone(),
        config(),
        clock.clone(),
    ));
    let first = request(&scheduler, 1);
    settle().await;
    let abandoned = request(&scheduler, 2);
    settle().await;
    abandoned.abort();
    assert!(abandoned.await.unwrap_err().is_cancelled());
    settle().await;
    assert_eq!(scheduler.stats().pending_items(), 0);
    provider.set_latency(clock.clone(), Duration::ZERO);
    clock.advance(Duration::from_secs(10));
    settle().await;
    first.await.unwrap().unwrap();
    assert_eq!(
        provider.encrypt_calls(),
        1,
        "cancelled queued work reached the provider"
    );
    assert_eq!(scheduler.stats().batches_total(), 1);
}

#[tokio::test]
async fn cancelling_one_coalesced_caller_keeps_the_other_callers_rpc_alive() {
    let clock = Arc::new(ManualClock::new());
    let provider = Arc::new(FakeCryptoProvider::new(64));
    provider.set_latency(clock.clone(), Duration::from_secs(10));
    let mut cfg = config();
    cfg.target_items = 2;
    let scheduler = Arc::new(BatchScheduler::new(provider.clone(), cfg, clock.clone()));
    let abandoned = request(&scheduler, 1);
    let surviving = request(&scheduler, 2);
    settle().await;
    assert_eq!(provider.encrypt_calls(), 1);
    abandoned.abort();
    assert!(abandoned.await.unwrap_err().is_cancelled());
    settle().await;
    assert!(!surviving.is_finished());
    clock.advance(Duration::from_secs(10));
    settle().await;
    assert_eq!(surviving.await.unwrap().unwrap()[0].unit_index, 2);
    assert_eq!(provider.encrypt_calls(), 1);
}

#[tokio::test]
async fn cancelling_one_queued_group_releases_only_its_pending_charge() {
    let clock = Arc::new(ManualClock::new());
    let provider = Arc::new(FakeCryptoProvider::new(64));
    let mut cfg = config();
    cfg.target_items = 3;
    let scheduler = Arc::new(BatchScheduler::new(provider.clone(), cfg, clock.clone()));
    let abandoned = request(&scheduler, 1);
    let surviving = request(&scheduler, 2);
    settle().await;
    assert_eq!(scheduler.stats().pending_items(), 2);
    abandoned.abort();
    assert!(abandoned.await.unwrap_err().is_cancelled());
    settle().await;
    assert_eq!(
        scheduler.stats().pending_items(),
        1,
        "cancelled coalescing peer retains capacity"
    );
    assert_eq!(scheduler.stats().pending_bytes(), 64);
    clock.advance(Duration::from_secs(60));
    settle().await;
    assert_eq!(surviving.await.unwrap().unwrap()[0].unit_index, 2);
    assert_eq!(scheduler.stats().batched_items_total(), 1);
}

#[tokio::test]
async fn cancelling_one_group_waiting_for_a_slot_releases_only_its_pending_charge() {
    let clock = Arc::new(ManualClock::new());
    let provider = Arc::new(FakeCryptoProvider::new(64));
    provider.set_latency(clock.clone(), Duration::from_secs(10));
    let mut cfg = config();
    cfg.target_items = 2;
    let scheduler = Arc::new(BatchScheduler::new(provider.clone(), cfg, clock.clone()));
    let first = request(&scheduler, 1);
    let second = request(&scheduler, 2);
    settle().await;
    assert_eq!(provider.encrypt_calls(), 1);
    let abandoned = request(&scheduler, 3);
    let surviving = request(&scheduler, 4);
    settle().await;
    assert_eq!(scheduler.stats().pending_items(), 2);
    abandoned.abort();
    assert!(abandoned.await.unwrap_err().is_cancelled());
    settle().await;
    assert_eq!(
        scheduler.stats().pending_items(),
        1,
        "cancelled dispatch peer retains capacity"
    );
    provider.set_latency(clock.clone(), Duration::ZERO);
    clock.advance(Duration::from_secs(10));
    settle().await;
    first.await.unwrap().unwrap();
    second.await.unwrap().unwrap();
    assert_eq!(surviving.await.unwrap().unwrap()[0].unit_index, 4);
    assert_eq!(scheduler.stats().batched_items_total(), 3);
}

#[tokio::test]
async fn cancelling_a_queued_tail_releases_its_data_and_admission_while_live_batches_wait() {
    let clock = Arc::new(ManualClock::new());
    let provider = Arc::new(FakeCryptoProvider::new(64));
    provider.set_latency(clock.clone(), Duration::from_secs(10));
    let scheduler = Arc::new(BatchScheduler::new(
        provider.clone(),
        config(),
        clock.clone(),
    ));
    let active = request(&scheduler, 1);
    settle().await;
    let waiting_for_slot = request(&scheduler, 2);
    settle().await;
    let cancelled_tail = request(&scheduler, 3);
    settle().await;
    assert_eq!(provider.encrypt_calls(), 1);
    assert_eq!(scheduler.stats().pending_items(), 2);
    cancelled_tail.abort();
    assert!(cancelled_tail.await.unwrap_err().is_cancelled());
    settle().await;
    assert_eq!(
        scheduler.stats().pending_items(),
        1,
        "cancelled rx tail remains behind a live slot waiter"
    );
    assert_eq!(scheduler.stats().pending_bytes(), 64);
    assert!(!active.is_finished());
    assert!(!waiting_for_slot.is_finished());
    provider.set_latency(clock.clone(), Duration::ZERO);
    clock.advance(Duration::from_secs(10));
    settle().await;
    active.await.unwrap().unwrap();
    assert_eq!(waiting_for_slot.await.unwrap().unwrap()[0].unit_index, 2);
    assert_eq!(provider.encrypt_calls(), 2);
    assert_eq!(scheduler.stats().pending_items(), 0);
}
