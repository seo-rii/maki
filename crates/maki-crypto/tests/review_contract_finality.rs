//! A contract violation (`CryptoError::Contract`) by one endpoint ended the
//! whole operation as soon as no endpoint was both untried by it and
//! admitting a call right now. A validated peer that had only failed
//! transiently, or whose circuit was cooling after an `EndpointFatal`
//! answer, did not count, so under the `stall` policy the outcome depended on
//! routing order: the same two faults in the opposite order backed off and
//! succeeded.
//!
//! The violation is final only once every validated endpoint has broken the
//! contract for the operation (R5-005: "reported once only such endpoints
//! remain"). Until then the operation stays in the normal backoff loop and
//! the availability policy decides how it ends; it is still never sent again
//! to an endpoint that broke the contract for it.

use std::sync::Arc;
use std::time::Duration;

use maki_crypto::breaker::BreakerConfig;
use maki_crypto::clock::Clock;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    CiphertextUnit, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit, SecretBuffer,
};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::ManualClock;

const UNIT: usize = 256;
const OPEN_INITIAL: Duration = Duration::from_secs(1);
const STEP: Duration = Duration::from_millis(100);

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0xC0F1),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".to_string(),
    }
}

fn pt(i: u64) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: i,
        data: SecretBuffer::from_slice(&[(i as u8) ^ 0x3c; UNIT]),
    }
}

/// The `stall` policy: no pass bound, no deadline.
fn stall_cfg() -> DispatchConfig {
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
            open_initial: OPEN_INITIAL,
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
        retry_safe: true,
        validation_interval: Duration::from_secs(1),
    }
}

fn contract() -> CryptoError {
    CryptoError::Contract("response body is not valid JSON".into())
}

fn transient() -> CryptoError {
    CryptoError::Retryable("connection reset".into())
}

fn endpoint_fatal() -> CryptoError {
    CryptoError::EndpointFatal("HTTP 401 from auth proxy".into())
}

fn set_of(
    peers: &[(&str, &Arc<FakeCryptoProvider>)],
    config: DispatchConfig,
    clock: &Arc<ManualClock>,
) -> Arc<EndpointSet> {
    Arc::new(EndpointSet::new(
        peers
            .iter()
            .map(|(name, peer)| ((*name).into(), (*peer).clone() as Arc<dyn CryptoProvider>))
            .collect(),
        config,
        clock.clone(),
    ))
}

async fn encrypt_one(set: Arc<EndpointSet>) -> Result<Vec<CiphertextUnit>, CryptoError> {
    set.encrypt_batch(&ctx(), &[pt(7)]).await
}

/// Let the spawned operation run until it parks, without moving the clock.
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

/// The healthy peer's one transient failure comes first, then the broken
/// peer's contract violation. The healthy peer still serves the request on
/// the next pass; the broken one is never sent it again.
#[tokio::test]
async fn a_transient_failure_before_a_contract_violation_does_not_end_a_stalled_operation() {
    let clock = Arc::new(ManualClock::new());
    let healthy = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let broken = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    healthy.fail_next([transient()]);
    broken.fail_next((0..100).map(|_| contract()));
    let set = set_of(
        &[("healthy", &healthy), ("broken", &broken)],
        stall_cfg(),
        &clock,
    );
    let result = drive(&clock, tokio::spawn(encrypt_one(set))).await;
    assert!(
        result.is_ok(),
        "the healthy peer only failed transiently, but the stalled operation ended with {:?}",
        result.err()
    );
    assert_eq!(healthy.encrypt_calls(), 2);
    assert_eq!(
        broken.encrypt_calls(),
        1,
        "re-sent to the contract violator"
    );
}

/// Control: the same two faults in the opposite routing order.
#[tokio::test]
async fn the_same_faults_in_the_opposite_order_still_succeed() {
    let clock = Arc::new(ManualClock::new());
    let broken = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let healthy = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    broken.fail_next((0..100).map(|_| contract()));
    healthy.fail_next([transient()]);
    let set = set_of(
        &[("broken", &broken), ("healthy", &healthy)],
        stall_cfg(),
        &clock,
    );
    let result = drive(&clock, tokio::spawn(encrypt_one(set))).await;
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(broken.encrypt_calls(), 1);
    assert_eq!(healthy.encrypt_calls(), 2);
}

/// The healthy peer's circuit is only cooling (an `EndpointFatal` answer
/// opens it at once) when the other peer has broken the contract. The
/// operation waits for the probe deadline under backoff: it sends nothing
/// while the circuit is open, and nothing to the violator.
#[tokio::test]
async fn a_contract_violation_waits_for_a_cooling_peer_under_stall() {
    let clock = Arc::new(ManualClock::new());
    let broken = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let healthy = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    broken.fail_next((0..100).map(|_| contract()));
    healthy.fail_next([endpoint_fatal()]);
    let set = set_of(
        &[("broken", &broken), ("healthy", &healthy)],
        stall_cfg(),
        &clock,
    );
    let task = tokio::spawn(encrypt_one(set));
    settle().await;
    assert_eq!(broken.encrypt_calls(), 1);
    assert_eq!(healthy.encrypt_calls(), 1);
    assert!(!task.is_finished(), "the stalled operation ended at once");
    assert!(
        clock.sleeper_count() > 0,
        "the wait must sleep on the clock"
    );

    let mut elapsed = Duration::ZERO;
    while elapsed + STEP < OPEN_INITIAL {
        clock.advance(STEP);
        elapsed += STEP;
        settle().await;
        if task.is_finished() {
            panic!(
                "the stalled operation ended while the healthy peer was cooling: {:?}",
                task.await.unwrap().err()
            );
        }
        assert_eq!(healthy.encrypt_calls(), 1, "an RPC into an open circuit");
        assert_eq!(
            broken.encrypt_calls(),
            1,
            "re-sent to the contract violator"
        );
    }

    let result = drive(&clock, task).await;
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(
        healthy.encrypt_calls(),
        2,
        "served by the healthy peer's probe"
    );
    assert_eq!(broken.encrypt_calls(), 1);
}

/// Under `bounded-error` the operation deadline, not the contract
/// violation, ends the wait for a cooling peer.
#[tokio::test]
async fn the_deadline_bounds_the_wait_for_a_cooling_peer() {
    let clock = Arc::new(ManualClock::new());
    let broken = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let healthy = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    broken.fail_next((0..100).map(|_| contract()));
    healthy.fail_next([endpoint_fatal()]);
    let deadline = Duration::from_millis(500);
    let set = set_of(
        &[("broken", &broken), ("healthy", &healthy)],
        DispatchConfig {
            max_operation_time: Some(deadline),
            ..stall_cfg()
        },
        &clock,
    );
    let result = drive(&clock, tokio::spawn(encrypt_one(set))).await;
    assert!(result.is_err(), "{result:?}");
    assert!(
        clock.now() >= deadline,
        "ended at {:?}, before the {deadline:?} deadline: {result:?}",
        clock.now()
    );
    assert_eq!(broken.encrypt_calls(), 1);
    assert_eq!(healthy.encrypt_calls(), 1);
}

/// The violation is reported as soon as the last validated endpoint has
/// broken the contract, even on a later pass, without another backoff.
#[tokio::test]
async fn the_violation_is_final_once_every_validated_endpoint_broke_the_contract() {
    let clock = Arc::new(ManualClock::new());
    let first = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let second = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    first.fail_next([transient(), contract()]);
    second.fail_next((0..100).map(|_| contract()));
    let set = set_of(
        &[("first", &first), ("second", &second)],
        stall_cfg(),
        &clock,
    );
    let result = drive(&clock, tokio::spawn(encrypt_one(set))).await;
    assert!(
        matches!(result, Err(CryptoError::Contract(_))),
        "{result:?}"
    );
    assert_eq!(first.encrypt_calls(), 2);
    assert_eq!(second.encrypt_calls(), 1);
    assert_eq!(clock.sleeper_count(), 0, "a sleep outlived the operation");
}

/// Control: when every endpoint breaks the contract on the first pass, the
/// stalled operation reports it at once, with no backoff sleep.
#[tokio::test]
async fn a_violation_by_every_endpoint_is_reported_at_once() {
    let clock = Arc::new(ManualClock::new());
    let left = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let right = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    left.fail_next((0..100).map(|_| contract()));
    right.fail_next((0..100).map(|_| contract()));
    let set = set_of(&[("left", &left), ("right", &right)], stall_cfg(), &clock);
    let task = tokio::spawn(encrypt_one(set));
    settle().await;
    assert!(task.is_finished(), "a backoff before the final verdict");
    let result = task.await.unwrap();
    assert!(
        matches!(result, Err(CryptoError::Contract(_))),
        "{result:?}"
    );
    assert_eq!((left.encrypt_calls(), right.encrypt_calls()), (1, 1));
    assert_eq!(clock.now(), Duration::ZERO);
}

/// Control: a quarantined endpoint is not counted as able to serve, so the
/// only validated endpoint's violation is still reported at once.
#[tokio::test]
async fn a_quarantined_peer_does_not_keep_the_operation_pending() {
    let clock = Arc::new(ManualClock::new());
    let broken = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let quarantined = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    broken.fail_next((0..100).map(|_| contract()));
    let set = Arc::new(EndpointSet::with_quarantine(
        vec![
            (
                "broken".into(),
                broken.clone() as Arc<dyn CryptoProvider>,
                true,
            ),
            (
                "quarantined".into(),
                quarantined.clone() as Arc<dyn CryptoProvider>,
                false,
            ),
        ],
        None,
        stall_cfg(),
        clock.clone(),
    ));
    let task = tokio::spawn(encrypt_one(set));
    settle().await;
    assert!(
        task.is_finished(),
        "a quarantined peer kept the operation pending"
    );
    let result = task.await.unwrap();
    assert!(
        matches!(result, Err(CryptoError::Contract(_))),
        "{result:?}"
    );
    assert_eq!(broken.encrypt_calls(), 1);
    assert_eq!(quarantined.encrypt_calls(), 0);
}
