//! Review R3-004: an `EndpointSet` is one provider made of several. Its
//! reported contract must hold for *every* endpoint a batch can be routed
//! to, including quarantined endpoints that are admitted later, or a batch
//! built against the aggregate fails (`NonRetryableRequest`) the moment
//! load balancing or failover picks the weakest endpoint. Batch limits are
//! therefore the minimum across endpoints, accepted plaintext sizes the
//! intersection, and security capabilities the weakest claim (SPEC §16:
//! what cannot be guaranteed for the whole set is `Absent`).

use std::sync::Arc;
use std::time::Duration;

use maki_crypto::breaker::BreakerConfig;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    Capability, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit, SecretBuffer,
};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::ManualClock;

const UNIT: u32 = 256;

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
        data: SecretBuffer::from_slice(&vec![i as u8; UNIT as usize]),
    }
}

fn cfg() -> DispatchConfig {
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
        max_operation_time: None,
        retry_safe: true,
        validation_interval: Duration::from_secs(1),
    }
}

fn strong() -> Arc<FakeCryptoProvider> {
    Arc::new(
        FakeCryptoProvider::new(UNIT)
            .with_max_batch(16, 1 << 20)
            .with_overhead(16)
            .with_integrity_check(true)
            .with_context_binding(true),
    )
}

fn weak() -> Arc<FakeCryptoProvider> {
    Arc::new(
        FakeCryptoProvider::new(UNIT)
            .with_max_batch(1, UNIT as u64)
            .with_overhead(32)
            .with_integrity_check(false)
            .with_context_binding(false),
    )
}

/// The aggregate batch contract is the minimum over all endpoints, no matter
/// which endpoint happens to be listed or validated first.
#[tokio::test]
async fn aggregate_batch_limits_are_the_minimum_over_all_endpoints() {
    for order in [true, false] {
        let a: Arc<dyn CryptoProvider> = strong();
        let b: Arc<dyn CryptoProvider> = weak();
        let endpoints = if order {
            vec![("a".to_string(), a), ("b".to_string(), b)]
        } else {
            vec![("b".to_string(), b), ("a".to_string(), a)]
        };
        let set = EndpointSet::new(endpoints, cfg(), Arc::new(ManualClock::new()));
        let caps = set.capabilities().await.unwrap();
        assert_eq!(caps.batch.max_items, 1, "order strong-first={order}");
        assert_eq!(
            caps.batch.max_bytes, UNIT as u64,
            "order strong-first={order}"
        );
        // The largest ciphertext any endpoint may produce bounds buffers.
        assert_eq!(
            caps.max_ciphertext_size,
            UNIT + 32,
            "order strong-first={order}"
        );
    }
}

/// A security capability only one endpoint delivers is not a capability of
/// the set: a batch served by the other endpoint has none of it.
#[tokio::test]
async fn aggregate_security_capabilities_are_the_weakest_claim() {
    let set = EndpointSet::new(
        vec![
            ("a".to_string(), strong() as Arc<dyn CryptoProvider>),
            ("b".to_string(), weak() as Arc<dyn CryptoProvider>),
        ],
        cfg(),
        Arc::new(ManualClock::new()),
    );
    let caps = set.capabilities().await.unwrap();
    assert_eq!(caps.integrity, Capability::Absent);
    assert_eq!(caps.context_binding, Capability::Absent);
    assert_eq!(caps.replay_protection, Capability::Absent);
}

/// A quarantined endpoint is not serving yet but will be admitted later
/// without the aggregate being re-read by callers, so it already counts.
#[tokio::test]
async fn quarantined_endpoints_count_towards_the_aggregate() {
    let set = EndpointSet::with_quarantine(
        vec![
            ("a".to_string(), strong() as Arc<dyn CryptoProvider>, true),
            ("b".to_string(), weak() as Arc<dyn CryptoProvider>, false),
        ],
        None,
        cfg(),
        Arc::new(ManualClock::new()),
    );
    let caps = set.capabilities().await.unwrap();
    assert_eq!(caps.batch.max_items, 1);
    assert_eq!(caps.integrity, Capability::Absent);
}

/// Plaintext sizes the set accepts are those every endpoint accepts.
#[tokio::test]
async fn aggregate_plaintext_sizes_are_the_intersection() {
    let a: Arc<dyn CryptoProvider> = Arc::new(FakeCryptoProvider::new(UNIT));
    let b: Arc<dyn CryptoProvider> = Arc::new(FakeCryptoProvider::new(UNIT * 2));
    let set = EndpointSet::new(
        vec![("a".to_string(), a), ("b".to_string(), b)],
        cfg(),
        Arc::new(ManualClock::new()),
    );
    let caps = set.capabilities().await.unwrap();
    assert!(
        !caps.accepts_plaintext_size(UNIT as usize)
            && !caps.accepts_plaintext_size(2 * UNIT as usize),
        "no size is accepted by both endpoints, got {:?}",
        caps.supported_plaintext_sizes
    );
}

/// A batch sized to the aggregate must survive failover to the weakest
/// endpoint: that is the whole point of reporting the minimum.
#[tokio::test]
async fn batch_within_the_aggregate_survives_failover_to_the_weakest_endpoint() {
    let a = strong();
    let b = weak();
    let set = EndpointSet::new(
        vec![
            ("a".to_string(), a.clone() as Arc<dyn CryptoProvider>),
            ("b".to_string(), b.clone() as Arc<dyn CryptoProvider>),
        ],
        cfg(),
        Arc::new(ManualClock::new()),
    );
    let caps = set.capabilities().await.unwrap();
    let items: Vec<PlaintextUnit> = (0..caps.batch.max_items as u64).map(pt).collect();
    // Both idle: the first listed endpoint is picked. It fails transiently;
    // the retry-safe set fails over to the weak endpoint within the pass,
    // and the batch must fit that endpoint too.
    a.fail_next([CryptoError::Retryable("blip".into())]);
    let out = set.encrypt_batch(&ctx(), &items).await.unwrap();
    assert_eq!(out.len(), items.len());
    assert_eq!(a.encrypt_calls(), 1);
    assert_eq!(b.encrypt_calls(), 1);
}
