//! Follow-up audit: `[crypto.batch]` targets and `max_wait` and the
//! `[limits] max_pending_crypto_*` bounds were parsed but never applied.
//! The batch scheduler now coalesces concurrent requests into bounded
//! provider calls, flushes on target or `max_wait`, never splits a request,
//! fans a provider error out to every waiting request, and bounds pending
//! work.

use std::sync::Arc;
use std::time::Duration;

use maki_crypto::scheduler::{BatchScheduler, SchedulerConfig};
use maki_crypto::{Clock, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit, SecretBuffer};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::ManualClock;

const UNIT: usize = 256;

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(11),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".to_string(),
    }
}

fn pt(i: u64) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: i,
        data: SecretBuffer::from_slice(&vec![i as u8; UNIT]),
    }
}

fn cfg() -> SchedulerConfig {
    SchedulerConfig {
        target_items: 8,
        target_bytes: 1 << 20,
        max_items: 16,
        max_bytes: 1 << 20,
        max_wait: Duration::from_millis(5),
        max_pending_items: 64,
        max_pending_plaintext_bytes: 1 << 20,
        max_pending_ciphertext_bytes: 1 << 20,
        max_inflight_batches: 4,
    }
}

async fn settle() {
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}

struct Harness {
    provider: Arc<FakeCryptoProvider>,
    scheduler: Arc<BatchScheduler>,
    clock: Arc<ManualClock>,
}

fn harness(config: SchedulerConfig) -> Harness {
    let provider = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let clock = Arc::new(ManualClock::new());
    let scheduler = Arc::new(BatchScheduler::new(provider.clone(), config, clock.clone()));
    Harness {
        provider,
        scheduler,
        clock,
    }
}

#[tokio::test]
async fn concurrent_requests_are_coalesced_into_one_provider_call() {
    let h = harness(cfg());
    let mut tasks = Vec::new();
    for i in 0..4u64 {
        let s = h.scheduler.clone();
        tasks.push(tokio::spawn(async move {
            s.encrypt_batch(&ctx(), &[pt(i * 2), pt(i * 2 + 1)]).await
        }));
    }
    // 8 items reach target_items exactly once the 4th request is queued;
    // the batch flushes without any clock movement.
    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await.unwrap().unwrap());
    }
    assert_eq!(h.provider.encrypt_calls(), 1);
    assert_eq!(h.scheduler.stats().batches_total(), 1);
    assert_eq!(h.scheduler.stats().coalesced_batches_total(), 1);
    assert_eq!(h.scheduler.stats().pending_items(), 0);
    // Each request got exactly its own units, in order, with real ciphertext.
    for (i, cts) in results.iter().enumerate() {
        assert_eq!(cts.len(), 2);
        assert_eq!(cts[0].unit_index, i as u64 * 2);
        assert_eq!(cts[1].unit_index, i as u64 * 2 + 1);
        let back = h.provider.decrypt_batch(&ctx(), cts).await.unwrap();
        assert_eq!(back[0].data, pt(i as u64 * 2).data);
    }
}

#[tokio::test]
async fn lone_request_flushes_after_max_wait() {
    let h = harness(cfg());
    let s = h.scheduler.clone();
    let task = tokio::spawn(async move { s.encrypt_batch(&ctx(), &[pt(1)]).await });
    settle().await;
    assert!(!task.is_finished(), "held back for max_wait");
    h.clock.advance(Duration::from_millis(5));
    settle().await;
    assert!(task.is_finished());
    let cts = task.await.unwrap().unwrap();
    assert_eq!(cts.len(), 1);
    assert_eq!(h.provider.encrypt_calls(), 1);
    assert_eq!(h.scheduler.stats().coalesced_batches_total(), 0);
}

#[tokio::test]
async fn requests_are_never_split_and_max_items_is_respected() {
    let mut c = cfg();
    c.target_items = 100;
    c.max_items = 5;
    let h = harness(c);
    let mut tasks = Vec::new();
    for i in 0..3u64 {
        let s = h.scheduler.clone();
        tasks.push(tokio::spawn(async move {
            s.encrypt_batch(&ctx(), &[pt(i * 3), pt(i * 3 + 1), pt(i * 3 + 2)])
                .await
        }));
    }
    settle().await;
    h.clock.advance(Duration::from_millis(5));
    settle().await;
    h.clock.advance(Duration::from_millis(5));
    settle().await;
    for task in tasks {
        let cts = task.await.unwrap().unwrap();
        assert_eq!(cts.len(), 3);
    }
    // 3 groups of 3 with max 5 per batch: [3], [3], [3] or [3][3+..]: never
    // more than one group per batch here, and never a split group.
    assert_eq!(h.provider.encrypt_calls(), 3);
}

#[tokio::test]
async fn provider_error_reaches_every_request_in_the_batch() {
    let h = harness(cfg());
    h.provider
        .fail_next([CryptoError::Retryable("blip".into())]);
    let mut tasks = Vec::new();
    for i in 0..4u64 {
        let s = h.scheduler.clone();
        tasks.push(tokio::spawn(async move {
            s.encrypt_batch(&ctx(), &[pt(i * 2), pt(i * 2 + 1)]).await
        }));
    }
    for task in tasks {
        let err = task.await.unwrap().unwrap_err();
        assert!(err.is_retryable(), "{err}");
    }
    assert_eq!(h.provider.encrypt_calls(), 1);
    // The lane keeps working afterwards.
    let s = h.scheduler.clone();
    let task = tokio::spawn(async move { s.encrypt_batch(&ctx(), &[pt(99)]).await });
    settle().await;
    h.clock.advance(Duration::from_millis(5));
    settle().await;
    let cts = task.await.unwrap().unwrap();
    assert_eq!(cts.len(), 1);
    assert_eq!(h.provider.encrypt_calls(), 2);
}

#[tokio::test]
async fn decrypt_lane_is_independent_and_round_trips() {
    let h = harness(cfg());
    let cts = h
        .provider
        .encrypt_batch(&ctx(), &[pt(5), pt(6)])
        .await
        .unwrap();
    let s = h.scheduler.clone();
    let task = tokio::spawn(async move { s.decrypt_batch(&ctx(), &cts).await });
    settle().await;
    h.clock.advance(Duration::from_millis(5));
    settle().await;
    let pts = task.await.unwrap().unwrap();
    assert_eq!(pts.len(), 2);
    assert_eq!(pts[0].unit_index, 5);
    assert_eq!(pts[0].data, pt(5).data);
    assert_eq!(h.provider.decrypt_calls(), 1);
    assert_eq!(h.provider.encrypt_calls(), 1, "encrypt lane untouched");
}

#[tokio::test]
async fn pending_work_is_bounded() {
    let mut c = cfg();
    c.max_pending_items = 4;
    c.target_items = 100;
    c.max_wait = Duration::from_secs(60);
    let h = harness(c);
    let mut tasks = Vec::new();
    for i in 0..6u64 {
        let s = h.scheduler.clone();
        tasks.push(tokio::spawn(async move {
            s.encrypt_batch(&ctx(), &[pt(i)]).await
        }));
    }
    settle().await;
    assert!(
        h.scheduler.stats().pending_items() <= 4,
        "pending {} exceeds the bound",
        h.scheduler.stats().pending_items()
    );
    h.clock.advance(Duration::from_secs(60));
    settle().await;
    h.clock.advance(Duration::from_secs(60));
    settle().await;
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    assert_eq!(h.scheduler.stats().pending_items(), 0);
    assert_eq!(h.scheduler.stats().batched_items_total(), 6);
}

#[tokio::test]
async fn capabilities_pass_through() {
    let h = harness(cfg());
    let caps = h.scheduler.capabilities().await.unwrap();
    assert_eq!(caps.crypto_compatibility_id, "test-profile-v1");
    let _ = h.clock.now();
}
