//! R5-005: a response that breaks the provider contract (malformed body,
//! wrong item count, bad encoding: `CryptoError::Contract`) is the fault of
//! the endpoint that sent it. In a multi-endpoint set it must charge that
//! endpoint's breaker and fail over, instead of failing every request that
//! least-inflight routing keeps sending to the broken endpoint first.

use std::sync::Arc;
use std::time::Duration;

use maki_crypto::breaker::{BreakerConfig, CircuitState};
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{CryptoContext, CryptoError, CryptoProvider, PlaintextUnit, SecretBuffer};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::ManualClock;

const UNIT: usize = 256;

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(13),
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

fn cfg(retry_safe: bool) -> DispatchConfig {
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
        max_attempts: Some(3),
        max_operation_time: None,
        retry_safe,
        validation_interval: Duration::from_secs(1),
    }
}

fn contract() -> CryptoError {
    CryptoError::Contract("response body is not valid JSON".into())
}

#[tokio::test]
async fn a_contract_violation_fails_over_and_opens_the_broken_endpoints_circuit() {
    let broken = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let healthy = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    broken.fail_next((0..100).map(|_| contract()));
    let set = EndpointSet::new(
        vec![
            ("broken".into(), broken.clone()),
            ("healthy".into(), healthy.clone()),
        ],
        cfg(true),
        Arc::new(ManualClock::new()),
    );
    for i in 0..10 {
        let out = set
            .encrypt_batch(&ctx(), &[pt(i)])
            .await
            .expect("the healthy endpoint must serve the request");
        assert_eq!(out[0].unit_index, i);
    }
    let status = set.endpoint_status();
    assert_eq!(status[0].name, "broken");
    assert_eq!(status[0].circuit, CircuitState::Open);
    assert_eq!(status[1].circuit, CircuitState::Closed);
    assert!(
        broken.encrypt_calls() <= 3,
        "an open circuit keeps traffic away from the broken endpoint: {} calls",
        broken.encrypt_calls()
    );
}

#[tokio::test]
async fn a_contract_violation_is_still_never_resent_to_a_non_retry_safe_provider() {
    let broken = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let healthy = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    broken.fail_next([contract()]);
    let set = EndpointSet::new(
        vec![
            ("broken".into(), broken.clone()),
            ("healthy".into(), healthy.clone()),
        ],
        cfg(false),
        Arc::new(ManualClock::new()),
    );
    let err = set.encrypt_batch(&ctx(), &[pt(1)]).await.unwrap_err();
    assert!(matches!(err, CryptoError::Contract(_)), "{err:?}");
    assert_eq!(healthy.encrypt_calls(), 0);
}

#[tokio::test]
async fn a_single_endpoint_still_reports_the_contract_violation() {
    let only = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    only.fail_next([contract()]);
    let set = EndpointSet::new(
        vec![("only".into(), only.clone())],
        cfg(true),
        Arc::new(ManualClock::new()),
    );
    let err = set.encrypt_batch(&ctx(), &[pt(1)]).await.unwrap_err();
    assert!(matches!(err, CryptoError::Contract(_)), "{err:?}");
}

/// R5-005 follow-up: an endpoint that broke the contract for an operation is
/// not retried for that operation on a later pass, even while its circuit
/// is still closed.
#[tokio::test]
async fn a_contract_violating_endpoint_is_not_retried_on_a_later_pass() {
    let clock = Arc::new(ManualClock::new());
    let broken = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let flaky = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    broken.fail_next([contract()]);
    flaky.fail_next((0..10).map(|_| CryptoError::Retryable("blip".into())));
    let set = EndpointSet::new(
        vec![
            ("broken".into(), broken.clone()),
            ("flaky".into(), flaky.clone()),
        ],
        cfg(true),
        clock.clone(),
    );
    let task = tokio::spawn(async move { set.encrypt_batch(&ctx(), &[pt(1)]).await });
    // Backoff between passes sleeps on the manual clock: drive it.
    let result = loop {
        if task.is_finished() {
            break task.await.unwrap();
        }
        clock.advance(Duration::from_secs(10));
        tokio::task::yield_now().await;
    };
    assert!(result.is_err(), "{result:?}");
    assert_eq!(
        broken.encrypt_calls(),
        1,
        "the request was sent again to the endpoint that violated the contract"
    );
}
