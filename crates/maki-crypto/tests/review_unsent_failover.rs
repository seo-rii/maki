//! A provider that is not retry-safe is sent each request at most once, so
//! the dispatcher never retried or failed over such a request once it had
//! called an endpoint. That also stopped it for a call that failed before
//! any request byte left Maki: a refused TCP connection, a failed TLS
//! handshake or a refused WebSocket upgrade. Sending that request to a peer
//! cannot duplicate an operation, yet the request failed although a healthy
//! peer was configured.
//!
//! A transport now marks exactly such errors with `CryptoError::not_sent`.
//! The dispatcher does not count a marked attempt as having sent the
//! request: it fails it over (and, under the availability policy, retries
//! it) like any request that has not been sent yet. An unmarked error still
//! ends a request that is not retry-safe, and once any attempt may have been
//! sent, the operation's error no longer carries the marker.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use maki_crypto::breaker::{BreakerConfig, CircuitState};
use maki_crypto::clock::Clock;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    CiphertextUnit, ContextField, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    ErrorClass, PlaintextUnit, SecretBuffer,
};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::ManualClock;

const UNIT: usize = 256;
const STEP: Duration = Duration::from_millis(100);

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x0057),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".to_string(),
    }
}

fn pt(i: u64) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: i,
        data: SecretBuffer::from_slice(&[(i as u8) ^ 0x6e; UNIT]),
    }
}

/// The `stall` policy for a provider with the given retry safety.
fn cfg(retry_safe: bool) -> DispatchConfig {
    DispatchConfig {
        retry: RetryPolicy {
            initial_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(1),
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
            success_threshold: 1,
        },
        global_max_inflight_batches: 32,
        global_max_inflight_bytes: 32 << 20,
        per_endpoint_max_inflight: 8,
        per_endpoint_max_bytes: 8 << 20,
        max_attempts: None,
        max_operation_time: None,
        retry_safe,
        validation_interval: Duration::from_secs(1),
    }
}

/// Failures a transport reports before or after writing the request.
fn failover_class_errors() -> Vec<CryptoError> {
    vec![
        CryptoError::EndpointFatal("websocket upgrade HTTP 400".into()),
        CryptoError::Retryable("connection refused".into()),
        CryptoError::Throttled("websocket upgrade HTTP 429".into()),
    ]
}

fn set_of(
    peers: &[(&str, Arc<dyn CryptoProvider>)],
    config: DispatchConfig,
    clock: &Arc<ManualClock>,
) -> Arc<EndpointSet> {
    Arc::new(EndpointSet::new(
        peers
            .iter()
            .map(|(name, peer)| ((*name).into(), peer.clone()))
            .collect(),
        config,
        clock.clone(),
    ))
}

fn fake() -> Arc<FakeCryptoProvider> {
    Arc::new(FakeCryptoProvider::new(UNIT as u32))
}

async fn settle() {
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
}

/// Drive backoff and cooldown sleeps on the manual clock until the task ends.
async fn drive<T: Send + 'static>(clock: &ManualClock, task: tokio::task::JoinHandle<T>) -> T {
    for _ in 0..10_000 {
        settle().await;
        if task.is_finished() {
            return task.await.unwrap();
        }
        clock.advance(STEP);
    }
    panic!("operation did not finish");
}

/// Answers each call with the next scripted error, or with the fake's real
/// result where the script says `None` or has run out.
struct Scripted {
    inner: FakeCryptoProvider,
    script: parking_lot::Mutex<VecDeque<Option<CryptoError>>>,
    calls: AtomicUsize,
}

impl Scripted {
    fn new(inner: FakeCryptoProvider, script: Vec<Option<CryptoError>>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            script: parking_lot::Mutex::new(script.into()),
            calls: AtomicUsize::new(0),
        })
    }
}

#[async_trait]
impl CryptoProvider for Scripted {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.inner.capabilities().await
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(Some(error)) = self.script.lock().pop_front() {
            return Err(error);
        }
        self.inner.encrypt_batch(context, items).await
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.inner.decrypt_batch(context, items).await
    }
}

#[tokio::test]
async fn an_unsent_request_fails_over_although_it_is_not_retry_safe() {
    for failure in failover_class_errors() {
        let clock = Arc::new(ManualClock::new());
        let down = fake();
        let healthy = fake();
        down.fail_next([failure.duplicate().not_sent()]);
        let set = set_of(
            &[("down", down.clone()), ("healthy", healthy.clone())],
            cfg(false),
            &clock,
        );
        let result = set.encrypt_batch(&ctx(), &[pt(1)]).await;
        assert!(
            result.is_ok(),
            "{failure:?} before the request was sent failed it: {:?}",
            result.err()
        );
        assert_eq!(down.encrypt_calls(), 1, "{failure:?}");
        assert_eq!(healthy.encrypt_calls(), 1, "{failure:?}");
        assert_eq!(set.metrics().retries_refused_unsafe_total(), 0);
        assert_eq!(set.metrics().failovers_total(), 1, "{failure:?}");
        // The endpoint is still charged: it could not take the request.
        if failure.class() == ErrorClass::EndpointFatal {
            assert_eq!(set.endpoint_status()[0].circuit, CircuitState::Open);
        }
        assert_eq!(clock.now(), Duration::ZERO, "a failover needs no backoff");
    }
}

/// Negative control: the same failures without the marker may follow a
/// request that reached the endpoint, so a request that is not retry-safe
/// fails and its peer is never sent it.
#[tokio::test]
async fn a_request_that_may_have_been_sent_is_never_failed_over() {
    for failure in failover_class_errors() {
        let clock = Arc::new(ManualClock::new());
        let down = fake();
        let healthy = fake();
        down.fail_next([failure.duplicate()]);
        let set = set_of(
            &[("down", down.clone()), ("healthy", healthy.clone())],
            cfg(false),
            &clock,
        );
        let error = set.encrypt_batch(&ctx(), &[pt(1)]).await.unwrap_err();
        assert_eq!(error.to_string(), failure.to_string());
        assert!(!error.is_not_sent(), "{error:?}");
        assert_eq!(down.encrypt_calls(), 1);
        assert_eq!(healthy.encrypt_calls(), 0, "re-sent {failure:?}");
        assert_eq!(set.metrics().retries_refused_unsafe_total(), 1);
    }
}

/// An unsent attempt does not license re-sending a request that a later
/// attempt may have delivered.
#[tokio::test]
async fn a_possibly_sent_attempt_after_an_unsent_one_still_ends_the_operation() {
    let clock = Arc::new(ManualClock::new());
    let unreachable = fake();
    let lost = fake();
    let healthy = fake();
    unreachable
        .fail_next([CryptoError::EndpointFatal("websocket upgrade HTTP 426".into()).not_sent()]);
    lost.fail_next([CryptoError::Retryable(
        "connection lost after the request was written".into(),
    )]);
    let set = set_of(
        &[
            ("unreachable", unreachable.clone()),
            ("lost", lost.clone()),
            ("healthy", healthy.clone()),
        ],
        cfg(false),
        &clock,
    );
    let error = set.encrypt_batch(&ctx(), &[pt(2)]).await.unwrap_err();
    assert!(
        matches!(&error, CryptoError::Retryable(message)
            if message == "connection lost after the request was written"),
        "{error:?}"
    );
    assert_eq!(
        (
            unreachable.encrypt_calls(),
            lost.encrypt_calls(),
            healthy.encrypt_calls()
        ),
        (1, 1, 0)
    );
    assert_eq!(set.metrics().retries_refused_unsafe_total(), 1);
}

/// With a single endpoint, the stall policy keeps an unsent request pending
/// until the endpoint takes it, as for any request not yet sent.
#[tokio::test]
async fn an_unsent_request_waits_for_its_only_endpoint_under_stall() {
    let clock = Arc::new(ManualClock::new());
    let only = fake();
    only.fail_next([
        CryptoError::Retryable("connection refused".into()).not_sent(),
        CryptoError::Retryable("connection refused".into()).not_sent(),
    ]);
    let set = set_of(&[("only", only.clone())], cfg(false), &clock);
    let task = {
        let set = set.clone();
        tokio::spawn(async move { set.encrypt_batch(&ctx(), &[pt(3)]).await })
    };
    let result = drive(&clock, task).await;
    assert!(result.is_ok(), "{:?}", result.err());
    assert_eq!(only.encrypt_calls(), 3);
    assert_eq!(set.metrics().retries_total(), 2);
    assert_eq!(set.metrics().retries_refused_unsafe_total(), 0);
}

/// Under `bounded-error` the deadline still ends those retries; nothing was
/// sent, so the error keeps the marker.
#[tokio::test]
async fn the_deadline_bounds_the_retries_of_an_unsent_request() {
    let clock = Arc::new(ManualClock::new());
    let only = fake();
    only.fail_next(
        (0..1000).map(|_| CryptoError::Retryable("connection refused".into()).not_sent()),
    );
    let deadline = Duration::from_millis(500);
    let set = set_of(
        &[("only", only.clone())],
        DispatchConfig {
            max_operation_time: Some(deadline),
            ..cfg(false)
        },
        &clock,
    );
    let task = {
        let set = set.clone();
        tokio::spawn(async move { set.encrypt_batch(&ctx(), &[pt(4)]).await })
    };
    let error = drive(&clock, task).await.unwrap_err();
    assert!(clock.now() >= deadline, "ended at {:?}", clock.now());
    assert_eq!(error.class(), ErrorClass::Retryable, "{error:?}");
    assert!(error.is_not_sent(), "{error:?}");
    assert!(only.encrypt_calls() >= 2);
    assert_eq!(set.metrics().retries_refused_unsafe_total(), 0);
}

/// The operation's error carries the marker only if no attempt of it may
/// have been sent, even for a retry-safe request.
#[tokio::test]
async fn the_operation_error_is_marked_only_when_no_attempt_was_sent() {
    for (first, marked) in [
        (
            CryptoError::Retryable("first refused".into()).not_sent(),
            true,
        ),
        (
            CryptoError::Retryable("first lost after sending".into()),
            false,
        ),
    ] {
        let clock = Arc::new(ManualClock::new());
        let a = fake();
        let b = fake();
        a.fail_next([first]);
        b.fail_next([CryptoError::EndpointFatal("second refused".into()).not_sent()]);
        let set = set_of(
            &[("a", a.clone()), ("b", b.clone())],
            DispatchConfig {
                max_attempts: Some(1),
                ..cfg(true)
            },
            &clock,
        );
        let error = set.encrypt_batch(&ctx(), &[pt(5)]).await.unwrap_err();
        assert_eq!(error.to_string(), "endpoint fatal: second refused");
        assert_eq!(error.is_not_sent(), marked, "{error:?}");
        assert_eq!((a.encrypt_calls(), b.encrypt_calls()), (1, 1));
    }
}

/// A call split into several RPCs has sent its earlier chunks, so an unsent
/// later chunk does not mark the call's error.
#[tokio::test]
async fn an_unsent_later_chunk_does_not_mark_the_whole_call() {
    let clock = Arc::new(ManualClock::new());
    let only = Scripted::new(
        FakeCryptoProvider::new(UNIT as u32).with_max_batch(1, 1 << 20),
        vec![
            None,
            Some(CryptoError::Retryable("connection refused".into()).not_sent()),
        ],
    );
    let set = set_of(
        &[("only", only.clone())],
        DispatchConfig {
            max_attempts: Some(1),
            ..cfg(false)
        },
        &clock,
    );
    let error = set
        .encrypt_batch(&ctx(), &[pt(6), pt(7)])
        .await
        .unwrap_err();
    assert_eq!(only.calls.load(Ordering::SeqCst), 2);
    assert_eq!(error.class(), ErrorClass::Retryable);
    assert!(!error.is_not_sent(), "{error:?}");
}

#[test]
fn the_marker_keeps_the_class_and_message() {
    for error in failover_class_errors() {
        let marked = error.duplicate().not_sent();
        assert!(marked.is_not_sent());
        assert_eq!(marked.class(), error.class());
        assert_eq!(marked.to_string(), error.to_string());
        assert_eq!(marked.is_retryable(), error.is_retryable());
        assert!(marked.duplicate().is_not_sent());
        assert!(marked.duplicate().not_sent().is_not_sent());
        let unmarked = marked.maybe_sent();
        assert!(!unmarked.is_not_sent());
        assert_eq!(format!("{unmarked:?}"), format!("{error:?}"));
    }
}

/// Errors that never fail over are never marked, so matching on their
/// variant keeps working everywhere.
#[test]
fn errors_that_never_fail_over_are_not_marked() {
    for error in [
        CryptoError::NonRetryableRequest("bad request".into()),
        CryptoError::Integrity("auth tag".into()),
        CryptoError::ProviderFatal("misconfigured".into()),
        CryptoError::Contract("malformed response".into()),
        CryptoError::UnsupportedContext(ContextField::FormatVersion),
    ] {
        let marked = error.duplicate().not_sent();
        assert!(!marked.is_not_sent(), "{error:?}");
        assert_eq!(format!("{marked:?}"), format!("{error:?}"));
    }
}
