//! When the operation deadline expired while a dispatch waited for endpoint
//! admission, the dispatcher returned a generic "operation deadline
//! exceeded" error and dropped the failure of the endpoint it had already
//! tried. Its other deadline exits (before a pass, and right after a failed
//! RPC) return that last endpoint error, so the same outage was reported
//! differently depending only on where the deadline happened to expire.
//!
//! The admission exit now returns the last endpoint error as well. With no
//! earlier failure it is still the deadline error
//! (`review_endpoint_admission.rs`,
//! `admission_and_fifo_waiters_keep_their_deadlines_without_charging_a_probe`).

use std::sync::Arc;
use std::time::Duration;

use maki_crypto::breaker::BreakerConfig;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    CiphertextUnit, CryptoContext, CryptoError, CryptoProvider, ErrorClass, PlaintextUnit,
    SecretBuffer,
};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::ManualClock;

const UNIT: usize = 256;
const DEADLINE: Duration = Duration::from_secs(1);

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0xAD31),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".to_string(),
    }
}

fn pt(i: u64) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: i,
        data: SecretBuffer::from_slice(&[(i as u8) ^ 0x5c; UNIT]),
    }
}

/// `bounded-error` with one RPC slot per endpoint, so an operation can wait
/// in admission for a peer that another operation occupies.
fn cfg() -> DispatchConfig {
    DispatchConfig {
        retry: RetryPolicy {
            initial_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(10),
        },
        budget: RetryBudgetConfig {
            retry_ratio: 1.0,
            burst: 16,
            min_probe_per_sec: 1.0,
        },
        breaker: BreakerConfig {
            failure_threshold: 8,
            open_initial: Duration::from_secs(60),
            open_max: Duration::from_secs(60),
            half_open_max_requests: 1,
            success_threshold: 1,
        },
        global_max_inflight_batches: 8,
        global_max_inflight_bytes: 1 << 20,
        per_endpoint_max_inflight: 1,
        per_endpoint_max_bytes: 1 << 20,
        max_attempts: None,
        max_operation_time: Some(DEADLINE),
        retry_safe: true,
        validation_interval: Duration::from_secs(1),
    }
}

fn spawn_encrypt(
    set: &Arc<EndpointSet>,
    unit: u64,
) -> tokio::task::JoinHandle<Result<Vec<CiphertextUnit>, CryptoError>> {
    let set = set.clone();
    tokio::spawn(async move { set.encrypt_batch(&ctx(), &[pt(unit)]).await })
}

async fn settle() {
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
}

/// `first` answers the operation after 20 ms with `failure`. Meanwhile a
/// second operation occupies `second`'s only RPC slot, so the first
/// operation's failover waits in admission until its deadline.
async fn deadline_while_waiting_for_admission(failure: CryptoError) -> CryptoError {
    let clock = Arc::new(ManualClock::new());
    let first = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let second = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    first.set_latency(clock.clone(), Duration::from_millis(20));
    first.fail_next([failure]);
    second.set_latency(clock.clone(), Duration::from_secs(3600));
    let set = Arc::new(EndpointSet::new(
        vec![
            ("first".into(), first.clone() as Arc<dyn CryptoProvider>),
            ("second".into(), second.clone() as Arc<dyn CryptoProvider>),
        ],
        cfg(),
        clock.clone(),
    ));

    let operation = spawn_encrypt(&set, 1);
    settle().await;
    assert_eq!(first.encrypt_calls(), 1);

    // A later operation (later deadline) takes `second`'s only slot.
    clock.advance(Duration::from_millis(10));
    let occupant = spawn_encrypt(&set, 2);
    settle().await;
    assert_eq!(second.encrypt_calls(), 1);

    // `first` fails; the failover to `second` must wait for its slot.
    clock.advance(Duration::from_millis(10));
    settle().await;
    assert!(
        !operation.is_finished(),
        "the operation did not wait for the occupied peer"
    );
    assert_eq!(second.encrypt_calls(), 1);

    clock.advance(DEADLINE - Duration::from_millis(20));
    settle().await;
    assert!(operation.is_finished(), "the deadline did not end the wait");
    let error = operation.await.unwrap().unwrap_err();
    assert_eq!(set.metrics().deadline_exceeded_total(), 1);
    assert_eq!(
        (first.encrypt_calls(), second.encrypt_calls()),
        (1, 1),
        "no RPC may start after the deadline"
    );
    occupant.abort();
    error
}

#[tokio::test]
async fn an_admission_deadline_reports_the_last_endpoint_error() {
    let error = deadline_while_waiting_for_admission(CryptoError::Retryable(
        "HTTP 503 from the first endpoint".into(),
    ))
    .await;
    assert!(
        matches!(&error, CryptoError::Retryable(message) if message == "HTTP 503 from the first endpoint"),
        "the admission deadline dropped the endpoint's failure: {error:?}"
    );
}

/// The class is the last endpoint error's, as at the other deadline exits,
/// not the deadline error's `Retryable`.
#[tokio::test]
async fn an_admission_deadline_keeps_the_class_of_the_last_endpoint_error() {
    let error = deadline_while_waiting_for_admission(CryptoError::EndpointFatal(
        "HTTP 401 from the first endpoint".into(),
    ))
    .await;
    assert_eq!(error.class(), ErrorClass::EndpointFatal, "{error:?}");
    assert!(
        error
            .to_string()
            .contains("HTTP 401 from the first endpoint"),
        "{error}"
    );
}
