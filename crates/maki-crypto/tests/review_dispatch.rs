//! Review M-010 / M-011: the dispatcher must never re-send a request to a
//! provider that is not retry-safe, must honour `max_operation_time` as an
//! absolute wall-clock deadline (cancelling an in-flight RPC and never
//! sleeping past it), and must keep endpoints whose cross-endpoint
//! validation has not run out of the serving pool until it succeeds.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use maki_crypto::breaker::BreakerConfig;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet, EndpointValidator};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{Clock, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit, SecretBuffer};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::ManualClock;

const UNIT: usize = 256;

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(9),
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

fn cfg(retry_safe: bool, max_operation_time: Option<Duration>) -> DispatchConfig {
    DispatchConfig {
        retry: RetryPolicy {
            initial_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(5),
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
        global_max_inflight_batches: 32,
        global_max_inflight_bytes: 32 << 20,
        per_endpoint_max_inflight: 8,
        per_endpoint_max_bytes: 8 << 20,
        max_attempts: None,
        max_operation_time,
        retry_safe,
        validation_interval: Duration::from_secs(1),
    }
}

fn fake() -> Arc<FakeCryptoProvider> {
    Arc::new(FakeCryptoProvider::new(UNIT as u32))
}

async fn settle() {
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
}

// ---------- retry_safe (M-010) ----------

#[tokio::test]
async fn non_retry_safe_provider_is_never_retried() {
    let a = fake();
    let b = fake();
    a.fail_next([CryptoError::Retryable("blip".into())]);
    let set = EndpointSet::new(
        vec![("a".into(), a.clone()), ("b".into(), b.clone())],
        cfg(false, None),
        Arc::new(ManualClock::new()),
    );
    let err = set.encrypt_batch(&ctx(), &[pt(1)]).await.unwrap_err();
    assert!(err.is_retryable(), "{err}");
    assert_eq!(a.encrypt_calls(), 1, "sent exactly once");
    assert_eq!(
        b.encrypt_calls(),
        0,
        "no failover for a non-retry-safe provider"
    );
    assert_eq!(set.metrics().retries_total(), 0);
    assert_eq!(set.metrics().retries_refused_unsafe_total(), 1);
    // A fresh request is a new operation and may proceed.
    set.encrypt_batch(&ctx(), &[pt(2)]).await.unwrap();
}

#[tokio::test]
async fn retry_safe_provider_fails_over_within_the_pass() {
    let a = fake();
    let b = fake();
    a.fail_next([CryptoError::Retryable("blip".into())]);
    let set = EndpointSet::new(
        vec![("a".into(), a.clone()), ("b".into(), b.clone())],
        cfg(true, None),
        Arc::new(ManualClock::new()),
    );
    set.encrypt_batch(&ctx(), &[pt(1)]).await.unwrap();
    assert_eq!(a.encrypt_calls(), 1);
    assert_eq!(b.encrypt_calls(), 1);
    assert_eq!(set.metrics().failovers_total(), 1);
}

// ---------- absolute deadline (M-010) ----------

#[tokio::test]
async fn bounded_error_obeys_wall_clock_deadline_during_an_rpc() {
    let clock = Arc::new(ManualClock::new());
    let slow = fake();
    slow.set_latency(clock.clone(), Duration::from_secs(10));
    let set = Arc::new(EndpointSet::new(
        vec![("slow".into(), slow.clone())],
        cfg(true, Some(Duration::from_secs(1))),
        clock.clone(),
    ));
    let task = tokio::spawn({
        let set = set.clone();
        async move { set.encrypt_batch(&ctx(), &[pt(1)]).await }
    });
    settle().await;
    assert!(!task.is_finished(), "RPC is in flight");
    clock.advance(Duration::from_secs(1));
    settle().await;
    assert!(
        task.is_finished(),
        "deadline must abandon the in-flight RPC"
    );
    let err = task.await.unwrap().unwrap_err();
    assert!(err.to_string().contains("deadline"), "{err}");
    assert_eq!(set.metrics().deadline_exceeded_total(), 1);
    assert_eq!(
        clock.now(),
        Duration::from_secs(1),
        "returned at the deadline, not at 10s"
    );
}

#[tokio::test]
async fn retry_backoff_never_sleeps_past_the_deadline() {
    let clock = Arc::new(ManualClock::new());
    let bad = fake();
    bad.fail_next((0..100).map(|_| CryptoError::Retryable("down".into())));
    let set = Arc::new(EndpointSet::new(
        vec![("bad".into(), bad.clone())],
        cfg(true, Some(Duration::from_millis(500))),
        clock.clone(),
    ));
    let task = tokio::spawn({
        let set = set.clone();
        async move { set.encrypt_batch(&ctx(), &[pt(1)]).await }
    });
    let mut ticks = 0;
    loop {
        settle().await;
        if task.is_finished() {
            break;
        }
        clock.advance(Duration::from_millis(10));
        ticks += 1;
        assert!(ticks < 200, "dispatcher did not stop at the deadline");
    }
    let err = task.await.unwrap().unwrap_err();
    assert!(err.is_retryable(), "{err}");
    assert!(
        clock.now() <= Duration::from_millis(510),
        "finished at {:?}",
        clock.now()
    );
    assert!(bad.encrypt_calls() >= 1);
}

// ---------- quarantine (M-011) ----------

struct Gate {
    attempts: AtomicU32,
    open: AtomicBool,
    fatal: AtomicBool,
}

fn validator(gate: Arc<Gate>) -> EndpointValidator {
    Arc::new(move |_reference, _candidate, _context| {
        gate.attempts.fetch_add(1, Ordering::SeqCst);
        let open = gate.open.load(Ordering::SeqCst);
        let fatal = gate.fatal.load(Ordering::SeqCst);
        Box::pin(async move {
            if fatal {
                Err(CryptoError::ProviderFatal("not interchangeable".into()))
            } else if open {
                Ok(())
            } else {
                Err(CryptoError::Retryable("endpoint down".into()))
            }
        })
    })
}

#[tokio::test]
async fn unverified_endpoint_never_enters_serving_pool() {
    let clock = Arc::new(ManualClock::new());
    let a = fake();
    let b = fake();
    let gate = Arc::new(Gate {
        attempts: AtomicU32::new(0),
        open: AtomicBool::new(false),
        fatal: AtomicBool::new(false),
    });
    let set = EndpointSet::with_quarantine(
        vec![
            ("a".into(), a.clone(), true),
            ("b".into(), b.clone(), false),
        ],
        Some(validator(gate.clone())),
        cfg(true, None),
        clock.clone(),
    );

    for i in 0..5 {
        set.encrypt_batch(&ctx(), &[pt(i)]).await.unwrap();
    }
    assert_eq!(b.encrypt_calls(), 0, "quarantined endpoint served traffic");
    assert_eq!(
        gate.attempts.load(Ordering::SeqCst),
        1,
        "one attempt per interval"
    );
    let status = set.endpoint_status();
    assert!(status[0].validated && !status[1].validated);

    clock.advance(Duration::from_secs(2));
    set.encrypt_batch(&ctx(), &[pt(5)]).await.unwrap();
    assert_eq!(gate.attempts.load(Ordering::SeqCst), 2);
    assert_eq!(b.encrypt_calls(), 0);

    gate.open.store(true, Ordering::SeqCst);
    clock.advance(Duration::from_secs(2));
    set.encrypt_batch(&ctx(), &[pt(6)]).await.unwrap();
    assert_eq!(gate.attempts.load(Ordering::SeqCst), 3);
    assert!(
        set.endpoint_status()[1].validated,
        "promoted after validation"
    );

    // Once validated it takes over when the reference fails.
    a.fail_next([CryptoError::Retryable("blip".into())]);
    set.encrypt_batch(&ctx(), &[pt(7)]).await.unwrap();
    assert_eq!(b.encrypt_calls(), 1);
}

#[tokio::test]
async fn proven_incompatible_endpoint_is_excluded_permanently() {
    let clock = Arc::new(ManualClock::new());
    let a = fake();
    let b = fake();
    let gate = Arc::new(Gate {
        attempts: AtomicU32::new(0),
        open: AtomicBool::new(true),
        fatal: AtomicBool::new(true),
    });
    let set = EndpointSet::with_quarantine(
        vec![
            ("a".into(), a.clone(), true),
            ("b".into(), b.clone(), false),
        ],
        Some(validator(gate.clone())),
        cfg(true, None),
        clock.clone(),
    );
    set.encrypt_batch(&ctx(), &[pt(1)]).await.unwrap();
    assert_eq!(gate.attempts.load(Ordering::SeqCst), 1);
    assert!(set.endpoint_status()[1].rejected);
    for _ in 0..3 {
        clock.advance(Duration::from_secs(5));
        set.encrypt_batch(&ctx(), &[pt(2)]).await.unwrap();
    }
    assert_eq!(
        gate.attempts.load(Ordering::SeqCst),
        1,
        "never re-validated"
    );
    assert_eq!(b.encrypt_calls(), 0);
}

#[tokio::test]
async fn capabilities_come_from_a_validated_endpoint() {
    let a = fake();
    let b = Arc::new(FakeCryptoProvider::new(UNIT as u32).with_compat_id("other"));
    let set = EndpointSet::with_quarantine(
        vec![("b".into(), b, false), ("a".into(), a, true)],
        None,
        cfg(true, None),
        Arc::new(ManualClock::new()),
    );
    assert_eq!(
        set.capabilities().await.unwrap().crypto_compatibility_id,
        "test-profile-v1"
    );
}
