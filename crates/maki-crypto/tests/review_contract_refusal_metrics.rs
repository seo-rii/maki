//! BUG-078: a contract failure rejected by retry safety is counted once.

use std::{sync::Arc, time::Duration};

use maki_crypto::{
    endpoint::{DispatchConfig, EndpointSet},
    retry::{RetryBudgetConfig, RetryPolicy},
    CryptoContext, CryptoError, CryptoProvider, PlaintextUnit, SecretBuffer,
};
use maki_test_support::{fake_provider::FakeCryptoProvider, ManualClock};

const UNIT: usize = 512;

async fn dispatch(error: CryptoError, retry_safe: bool, peers: usize) -> (u64, usize, bool) {
    let first = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let second = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    first.fail_next([error]);
    let mut providers: Vec<(String, Arc<dyn CryptoProvider>)> =
        vec![("first".into(), first.clone())];
    if peers > 1 {
        providers.push(("second".into(), second.clone()));
    }
    let set = EndpointSet::new(
        providers,
        DispatchConfig {
            retry: RetryPolicy {
                initial_delay: Duration::from_millis(10),
                max_delay: Duration::from_secs(1),
            },
            budget: RetryBudgetConfig {
                retry_ratio: 1.0,
                burst: 16,
                min_probe_per_sec: 1.0,
            },
            breaker: Default::default(),
            global_max_inflight_batches: 1,
            global_max_inflight_bytes: UNIT as u64,
            per_endpoint_max_inflight: 1,
            per_endpoint_max_bytes: UNIT as u64,
            max_attempts: Some(1),
            max_operation_time: None,
            retry_safe,
            validation_interval: Duration::from_secs(1),
        },
        Arc::new(ManualClock::new()),
    );
    let result = set
        .encrypt_batch(
            &CryptoContext {
                volume_uuid: uuid::Uuid::from_u128(78),
                format_version: 1,
                crypto_compatibility_id: "test-profile-v1".into(),
            },
            &[PlaintextUnit {
                unit_index: 7,
                data: SecretBuffer::zeroed(UNIT),
            }],
        )
        .await;
    assert_eq!(first.encrypt_calls(), 1);
    assert_eq!(set.global_inflight(), (0, 0));
    (
        set.metrics().retries_refused_unsafe_total(),
        second.encrypt_calls(),
        result.is_ok(),
    )
}

#[tokio::test]
async fn unsafe_contract_failover_refusal_is_counted_without_resending() {
    assert_eq!(
        dispatch(CryptoError::Contract("malformed reply".into()), false, 2).await,
        (1, 0, false)
    );
}

#[tokio::test]
async fn unsafe_single_endpoint_contract_refusal_is_counted_once() {
    assert_eq!(
        dispatch(CryptoError::Contract("malformed reply".into()), false, 1).await,
        (1, 0, false)
    );
}

#[tokio::test]
async fn unsafe_retryable_refusal_remains_counted_once() {
    assert_eq!(
        dispatch(CryptoError::Retryable("transient failure".into()), false, 2).await,
        (1, 0, false)
    );
}

#[tokio::test]
async fn safe_contract_failure_reaches_a_healthy_peer_without_a_refusal() {
    assert_eq!(
        dispatch(CryptoError::Contract("malformed reply".into()), true, 2).await,
        (0, 1, true)
    );
}

#[tokio::test]
async fn request_errors_do_not_count_as_retry_safety_refusals() {
    assert_eq!(
        dispatch(
            CryptoError::NonRetryableRequest("bad input".into()),
            false,
            2
        )
        .await,
        (0, 0, false)
    );
}

#[tokio::test]
async fn provider_fatal_errors_do_not_count_as_retry_safety_refusals() {
    assert_eq!(
        dispatch(
            CryptoError::ProviderFatal("provider unavailable".into()),
            false,
            2
        )
        .await,
        (0, 0, false)
    );
}
