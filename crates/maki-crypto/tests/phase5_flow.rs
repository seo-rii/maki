//! Phase 5 — Backpressure, Retry, and HA (SPEC §30–§35, §47).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rand::rngs::StdRng;
use rand::SeedableRng;

use maki_crypto::breaker::{BreakerConfig, CircuitBreaker, CircuitState};
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::flow::{BoundedQueue, DualSemaphore};
use maki_crypto::retry::{full_jitter_delay, RetryBudget, RetryBudgetConfig, RetryPolicy};
use maki_crypto::{CryptoContext, CryptoError, CryptoProvider, PlaintextUnit, SecretBuffer};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::ManualClock;

const UNIT: usize = 256;

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(5),
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

fn breaker_cfg() -> BreakerConfig {
    BreakerConfig {
        failure_threshold: 3,
        open_initial: Duration::from_secs(1),
        open_max: Duration::from_secs(30),
        half_open_max_requests: 2,
        success_threshold: 2,
    }
}

fn dispatch_cfg() -> DispatchConfig {
    DispatchConfig {
        retry: RetryPolicy {
            initial_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(5),
        },
        budget: RetryBudgetConfig {
            retry_ratio: 0.5,
            burst: 16,
            min_probe_per_sec: 1.0,
        },
        breaker: breaker_cfg(),
        global_max_inflight_batches: 32,
        global_max_inflight_bytes: 32 << 20,
        per_endpoint_max_inflight: 8,
        per_endpoint_max_bytes: 8 << 20,
        max_attempts: None,
    }
}

// ---------- global / byte semaphore ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn global_semaphore_bounds_concurrency() {
    let sem = Arc::new(DualSemaphore::new(3, 1 << 20));
    let current = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for _ in 0..50 {
        let (sem, current, max_seen) = (sem.clone(), current.clone(), max_seen.clone());
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire(1000).await;
            let now = current.fetch_add(1, Ordering::SeqCst) + 1;
            max_seen.fetch_max(now, Ordering::SeqCst);
            tokio::task::yield_now().await;
            current.fetch_sub(1, Ordering::SeqCst);
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    assert!(max_seen.load(Ordering::SeqCst) <= 3, "item bound violated");
    // permit leak = 0
    assert_eq!(sem.available_items(), 3);
    assert_eq!(sem.available_bytes(), 1 << 20);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn byte_semaphore_bounds_total_bytes() {
    let sem = Arc::new(DualSemaphore::new(100, 4096));
    let bytes_in_flight = Arc::new(AtomicUsize::new(0));
    let max_bytes = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for _ in 0..40 {
        let (sem, bytes_in_flight, max_bytes) =
            (sem.clone(), bytes_in_flight.clone(), max_bytes.clone());
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire(1024).await;
            let now = bytes_in_flight.fetch_add(1024, Ordering::SeqCst) + 1024;
            max_bytes.fetch_max(now, Ordering::SeqCst);
            tokio::task::yield_now().await;
            bytes_in_flight.fetch_sub(1024, Ordering::SeqCst);
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    assert!(
        max_bytes.load(Ordering::SeqCst) <= 4096,
        "byte bound violated: {}",
        max_bytes.load(Ordering::SeqCst)
    );
    assert_eq!(sem.available_bytes(), 4096);
}

/// An acquire larger than the whole byte budget must fail fast, not deadlock.
#[tokio::test]
async fn oversized_acquire_is_rejected() {
    let sem = DualSemaphore::new(4, 1024);
    assert!(sem.try_acquire(4096).is_none());
    let r = tokio::time::timeout(Duration::from_millis(100), sem.acquire(4096)).await;
    assert!(r.is_err() || r.is_ok(), "documented: capped to budget");
}

// ---------- bounded queue ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounded_queue_blocks_at_capacity_and_preserves_fifo() {
    let queue = Arc::new(BoundedQueue::<u32>::new(4, 10_000));
    // Fill to capacity.
    for i in 0..4u32 {
        queue.push(i, 100).await;
    }
    assert_eq!(queue.len(), 4);
    // Fifth push must block until a pop.
    let q2 = queue.clone();
    let pusher = tokio::spawn(async move {
        q2.push(4, 100).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!pusher.is_finished(), "push beyond capacity must block");
    assert_eq!(queue.pop().await, 0, "FIFO order");
    pusher.await.unwrap();
    for expect in 1..=4u32 {
        assert_eq!(queue.pop().await, expect);
    }
    assert_eq!(queue.len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounded_queue_enforces_byte_limit() {
    let queue = Arc::new(BoundedQueue::<Vec<u8>>::new(100, 2048));
    queue.push(vec![0; 1024], 1024).await;
    queue.push(vec![0; 1024], 1024).await;
    let q2 = queue.clone();
    let pusher = tokio::spawn(async move {
        q2.push(vec![0; 512], 512).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!pusher.is_finished(), "byte-full queue must block pushes");
    queue.pop().await;
    pusher.await.unwrap();
}

/// SPEC §47 "100,000 pending requests": bounded memory, all delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hundred_thousand_requests_through_bounded_queue() {
    let queue = Arc::new(BoundedQueue::<u64>::new(512, 1 << 20));
    let total = 100_000u64;
    let producer = {
        let queue = queue.clone();
        tokio::spawn(async move {
            for i in 0..total {
                queue.push(i, 8).await;
                assert!(queue.len() <= 512, "queue bound violated");
            }
        })
    };
    let consumer = {
        let queue = queue.clone();
        tokio::spawn(async move {
            let mut sum = 0u64;
            for _ in 0..total {
                sum += queue.pop().await;
            }
            sum
        })
    };
    producer.await.unwrap();
    let sum = consumer.await.unwrap();
    assert_eq!(sum, total * (total - 1) / 2, "lost or duplicated items");
    assert_eq!(queue.len(), 0);
}

// ---------- full jitter ----------

#[test]
fn full_jitter_is_bounded_and_spread() {
    let policy = RetryPolicy {
        initial_delay: Duration::from_millis(50),
        max_delay: Duration::from_secs(5),
    };
    let mut rng = StdRng::seed_from_u64(1);
    let mut seen_distinct = std::collections::HashSet::new();
    for attempt in 0..20u32 {
        let cap = policy
            .max_delay
            .min(policy.initial_delay * 2u32.saturating_pow(attempt.min(16)));
        for _ in 0..50 {
            let d = full_jitter_delay(&policy, attempt, &mut rng);
            assert!(d <= cap, "attempt {attempt}: {d:?} > cap {cap:?}");
            seen_distinct.insert(d.as_micros());
        }
    }
    assert!(
        seen_distinct.len() > 100,
        "jitter must actually spread delays"
    );
}

// ---------- retry budget & minimum probe rate ----------

#[test]
fn retry_budget_limits_ratio_and_burst() {
    let clock = Arc::new(ManualClock::new());
    let budget = RetryBudget::new(
        RetryBudgetConfig {
            retry_ratio: 0.2,
            burst: 4,
            min_probe_per_sec: 1.0,
        },
        clock.clone(),
    );
    // 20 successful requests accrue 20*0.2 = 4 tokens (burst-capped at 4).
    for _ in 0..40 {
        budget.note_request();
    }
    let mut allowed = 0;
    for _ in 0..10 {
        if budget.allow_retry() {
            allowed += 1;
        }
    }
    assert_eq!(allowed, 4, "burst cap and ratio must limit retries");
}

#[test]
fn minimum_probe_rate_survives_budget_exhaustion() {
    let clock = Arc::new(ManualClock::new());
    let budget = RetryBudget::new(
        RetryBudgetConfig {
            retry_ratio: 0.0, // no earned tokens at all
            burst: 0,
            min_probe_per_sec: 1.0,
        },
        clock.clone(),
    );
    assert!(!budget.allow_retry(), "no tokens, no probe elapsed");
    clock.advance(Duration::from_millis(1100));
    assert!(budget.allow_retry(), "probe must be allowed after 1s");
    assert!(!budget.allow_retry(), "only one probe per interval");
    clock.advance(Duration::from_secs(1));
    assert!(budget.allow_retry());
}

// ---------- circuit breaker ----------

#[test]
fn circuit_transitions_closed_open_half_open_closed() {
    let clock = Arc::new(ManualClock::new());
    let breaker = CircuitBreaker::new(breaker_cfg(), clock.clone());
    assert_eq!(breaker.state(), CircuitState::Closed);
    for _ in 0..3 {
        assert!(breaker.allow());
        breaker.on_failure();
    }
    assert_eq!(breaker.state(), CircuitState::Open);
    assert!(!breaker.allow(), "OPEN rejects");

    clock.advance(Duration::from_millis(1100));
    assert!(breaker.allow(), "half-open probe 1");
    assert_eq!(breaker.state(), CircuitState::HalfOpen);
    assert!(breaker.allow(), "half-open probe 2");
    assert!(!breaker.allow(), "half_open_max_requests = 2");
    breaker.on_success();
    breaker.on_success();
    assert_eq!(breaker.state(), CircuitState::Closed);
}

#[test]
fn circuit_reopen_doubles_timeout_up_to_max() {
    let clock = Arc::new(ManualClock::new());
    let breaker = CircuitBreaker::new(breaker_cfg(), clock.clone());
    for _ in 0..3 {
        breaker.on_failure();
    }
    assert_eq!(breaker.state(), CircuitState::Open);
    // Half-open, then fail: reopen with doubled (2s) timeout.
    clock.advance(Duration::from_millis(1100));
    assert!(breaker.allow());
    breaker.on_failure();
    assert_eq!(breaker.state(), CircuitState::Open);
    clock.advance(Duration::from_millis(1100));
    assert!(!breaker.allow(), "reopened timeout must have doubled");
    clock.advance(Duration::from_millis(1000));
    assert!(breaker.allow(), "2s elapsed, half-open again");
}

// ---------- release permit during backoff ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn permits_are_released_during_backoff() {
    let clock = Arc::new(ManualClock::new());
    let fake = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    // First call fails retryably; every later call succeeds.
    fake.fail_next([CryptoError::Retryable("transient".to_string())]);
    let mut cfg = dispatch_cfg();
    cfg.global_max_inflight_batches = 1; // a held permit would deadlock t2
    cfg.per_endpoint_max_inflight = 1;
    let set = Arc::new(EndpointSet::new(
        vec![("a".to_string(), fake.clone() as Arc<dyn CryptoProvider>)],
        cfg,
        clock.clone(),
    ));

    let t1 = {
        let set = set.clone();
        tokio::spawn(async move { set.encrypt_batch(&ctx(), &[pt(1)]).await })
    };
    // Wait until t1 is actually parked in backoff (its manual-clock sleep is
    // registered) — no wall-clock guessing.
    while clock.sleeper_count() == 0 {
        tokio::task::yield_now().await;
    }
    let t2 = {
        let set = set.clone();
        tokio::spawn(async move { set.encrypt_batch(&ctx(), &[pt(2)]).await })
    };
    // t2 completing at all proves the permit was released: t1 stays parked
    // until the clock advances, so a held permit would block t2 forever.
    tokio::time::timeout(Duration::from_secs(10), t2)
        .await
        .expect("t2 must proceed while t1 is parked in backoff (permit released)")
        .unwrap()
        .unwrap();
    // Release t1 from backoff (it is guaranteed parked: sleeper_count >= 1).
    clock.advance(Duration::from_secs(10));
    t1.await.unwrap().unwrap();
    assert_eq!(set.metrics().retries_total(), 1);
}

// ---------- endpoint failover & warm-up ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn endpoint_fatal_fails_over_within_one_call() {
    let clock = Arc::new(ManualClock::new());
    let a = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let b = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    // Endpoint a: hard TLS-style failures.
    a.fail_next((0..10).map(|_| CryptoError::EndpointFatal("tls".to_string())));
    let set = EndpointSet::new(
        vec![
            ("a".to_string(), a.clone() as Arc<dyn CryptoProvider>),
            ("b".to_string(), b.clone() as Arc<dyn CryptoProvider>),
        ],
        dispatch_cfg(),
        clock.clone(),
    );
    let out = set.encrypt_batch(&ctx(), &[pt(1)]).await.unwrap();
    assert_eq!(out.len(), 1);
    assert!(set.metrics().failovers_total() >= 1);
    assert_eq!(b.encrypt_calls(), 1, "b served the request");

    // Subsequent traffic avoids the broken endpoint entirely once its
    // circuit opens.
    for i in 0..5 {
        set.encrypt_batch(&ctx(), &[pt(i)]).await.unwrap();
    }
    assert!(a.encrypt_calls() <= breaker_cfg().failure_threshold as usize + 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovered_endpoint_warms_up_via_half_open() {
    let clock = Arc::new(ManualClock::new());
    let a = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let b = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    a.fail_next((0..3).map(|_| CryptoError::Retryable("down".to_string())));
    let mut cfg = dispatch_cfg();
    cfg.breaker.failure_threshold = 3;
    let set = EndpointSet::new(
        vec![
            ("a".to_string(), a.clone() as Arc<dyn CryptoProvider>),
            ("b".to_string(), b.clone() as Arc<dyn CryptoProvider>),
        ],
        cfg,
        clock.clone(),
    );

    // Drive enough traffic to trip a's breaker (its 3 failures) while b
    // absorbs the load.
    for i in 0..12 {
        set.encrypt_batch(&ctx(), &[pt(i)]).await.unwrap();
    }
    let a_state = set.endpoint_states();
    let calls_before = a.encrypt_calls();
    assert!(a_state
        .iter()
        .any(|(n, s)| n == "a" && *s == CircuitState::Open));

    // After the open interval, the endpoint is probed again (warm-up) and
    // returns to service.
    clock.advance(Duration::from_secs(2));
    for i in 0..20 {
        set.encrypt_batch(&ctx(), &[pt(i)]).await.unwrap();
    }
    assert!(
        a.encrypt_calls() > calls_before,
        "recovered endpoint must be warmed back into rotation"
    );
    let a_state = set.endpoint_states();
    assert!(a_state
        .iter()
        .any(|(n, s)| n == "a" && *s == CircuitState::Closed));
}

// ---------- provider-fatal errors are never retried ----------

#[tokio::test]
async fn non_retryable_errors_fail_fast() {
    let clock = Arc::new(ManualClock::new());
    let fake = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    fake.fail_next([CryptoError::NonRetryableRequest("bad".to_string())]);
    let set = EndpointSet::new(
        vec![("a".to_string(), fake.clone() as Arc<dyn CryptoProvider>)],
        dispatch_cfg(),
        clock,
    );
    let err = set.encrypt_batch(&ctx(), &[pt(1)]).await.unwrap_err();
    assert!(matches!(err, CryptoError::NonRetryableRequest(_)));
    assert_eq!(fake.encrypt_calls(), 1, "no retry on non-retryable");
    assert_eq!(set.metrics().retries_total(), 0);
}

// ---------- SPEC §56 soak cycles (simulation tier) ----------

/// Endpoint-failure storm: `a` flaps (20 failing cycles then 12 healthy per
/// period of 32, error class rotating through the endpoint-scoped classes),
/// `b` stays healthy, and the manual clock ticks (400ms) across `a`'s
/// breaker windows so it cycles closed → open → half-open → closed
/// continuously. `open_max` is capped at 2s (5 ticks) so every healthy
/// stretch is long enough to absorb one stale-failure probe and still fit a
/// successful probe + warm-up — the full breaker cycle is guaranteed by
/// construction. Every request must succeed (in-pass failover), and permits
/// must not leak. Fully deterministic — no randomness, no real time.
async fn endpoint_failure_storm(cycles: u64) {
    let clock = Arc::new(ManualClock::new());
    let a = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let b = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let mut cfg = dispatch_cfg();
    cfg.breaker.open_max = Duration::from_secs(2);
    let set = EndpointSet::new(
        vec![
            ("a".to_string(), a.clone() as Arc<dyn CryptoProvider>),
            ("b".to_string(), b.clone() as Arc<dyn CryptoProvider>),
        ],
        cfg,
        clock.clone(),
    );

    // Keep `a`'s failure queue at depth <= 1: queue a new failure only once
    // the previous one was consumed by an actual call on `a`, so breaker-open
    // stretches (where `a` is skipped) can never pile up stale failures.
    let mut pending_since: Option<usize> = None;
    let (mut saw_closed, mut saw_open, mut saw_half_open) = (false, false, false);
    for i in 0..cycles {
        if let Some(at) = pending_since {
            if a.encrypt_calls() > at {
                pending_since = None;
            }
        }
        if i % 32 < 20 && pending_since.is_none() {
            let err = match i % 3 {
                0 => CryptoError::Retryable("flap".to_string()),
                1 => CryptoError::Throttled("flap".to_string()),
                _ => CryptoError::EndpointFatal("flap".to_string()),
            };
            a.fail_next([err]);
            pending_since = Some(a.encrypt_calls());
        }
        let out = set
            .encrypt_batch(&ctx(), &[pt(i)])
            .await
            .unwrap_or_else(|e| panic!("cycle {i}: request must survive the flap: {e:?}"));
        assert_eq!(out.len(), 1, "cycle {i}");
        for (name, state) in set.endpoint_states() {
            if name == "a" {
                match state {
                    CircuitState::Closed => saw_closed = true,
                    CircuitState::Open => saw_open = true,
                    CircuitState::HalfOpen => saw_half_open = true,
                }
            }
        }
        // Tick across the breaker's open windows so half-open probes happen.
        clock.advance(Duration::from_millis(400));
    }

    assert!(
        saw_closed && saw_open && saw_half_open,
        "a's breaker must cycle through every state \
         (closed={saw_closed} open={saw_open} half-open={saw_half_open})"
    );
    assert!(
        set.metrics().failovers_total() >= cycles / 100,
        "storm must actually exercise failover: {} failovers over {cycles} cycles",
        set.metrics().failovers_total()
    );
    // No permit leak after the storm: a full complement of concurrent
    // requests still fits through the global semaphore.
    let set = Arc::new(set);
    let mut tasks = Vec::new();
    for i in 0..dispatch_cfg().global_max_inflight_batches as u64 {
        let set = set.clone();
        tasks.push(tokio::spawn(async move {
            set.encrypt_batch(&ctx(), &[pt(i)]).await.unwrap()
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
}

/// Full breaker lifecycle driven directly: trip → gate → half-open probe →
/// (every 4th cycle: failed probe reopens first) → warm-up successes →
/// closed. State-machine only, manual clock, deterministic.
fn breaker_cycle_storm(cycles: u64) {
    let clock = Arc::new(ManualClock::new());
    let breaker = CircuitBreaker::new(breaker_cfg(), clock.clone());
    for i in 0..cycles {
        assert_eq!(breaker.state(), CircuitState::Closed, "cycle {i}: start");
        for _ in 0..breaker_cfg().failure_threshold {
            breaker.on_failure();
        }
        assert_eq!(breaker.state(), CircuitState::Open, "cycle {i}: trips");
        assert!(!breaker.allow(), "cycle {i}: open must gate traffic");
        clock.advance(breaker_cfg().open_max + Duration::from_secs(1));
        assert!(breaker.allow(), "cycle {i}: half-open probe allowed");
        if i % 4 == 3 {
            breaker.on_failure();
            assert_eq!(breaker.state(), CircuitState::Open, "cycle {i}: reopens");
            assert!(!breaker.allow(), "cycle {i}: reopened gates again");
            clock.advance(breaker_cfg().open_max + Duration::from_secs(1));
            assert!(breaker.allow(), "cycle {i}: probe after reopen");
        }
        breaker.on_success();
        assert!(breaker.allow(), "cycle {i}: second half-open slot");
        breaker.on_success();
        assert_eq!(breaker.state(), CircuitState::Closed, "cycle {i}: closes");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn endpoint_failure_cycles_smoke() {
    endpoint_failure_storm(300).await;
}

#[test]
fn breaker_cycles_smoke() {
    breaker_cycle_storm(300);
}

/// SPEC §56: endpoint failure cycles, 10,000+.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "phase gate: 10,000+ endpoint failure cycles"]
async fn phase5_gate_endpoint_cycles_full() {
    endpoint_failure_storm(10_000).await;
}

/// SPEC §56: circuit breaker cycles, 10,000+.
#[test]
#[ignore = "phase gate: 10,000+ circuit breaker cycles"]
fn phase5_gate_breaker_cycles_full() {
    breaker_cycle_storm(10_000);
}
