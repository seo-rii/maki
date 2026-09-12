//! SPEC §40 "Required metrics include ..." (fourth audit pass): every
//! metric the specification names is present in the control plane's
//! `metrics` document, with or without a remote endpoint dispatcher, and
//! the per-endpoint gauges are keyed by endpoint name only (a bounded
//! label set).

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use uuid::Uuid;

use maki_backing::Backing;
use maki_control::server::ControlBackend;
use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
use maki_crypto::breaker::BreakerConfig;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{CryptoProvider, SystemClock};
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_nbdkit::control::EngineControlBackend;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::CrashableBacking;

const UNIT: u32 = 4096;
const DEVICE_SIZE: u64 = 64 * UNIT as u64;

/// The names SPEC §40 lists (histograms as `_sum`/`_count`).
const REQUIRED: &[&str] = &[
    "maki_active_callbacks",
    "maki_plaintext_bytes",
    "maki_ciphertext_bytes",
    "maki_submission_queue_items",
    "maki_submission_queue_bytes",
    "maki_crypto_pending_items",
    "maki_crypto_pending_bytes",
    "maki_crypto_inflight_batches",
    "maki_crypto_inflight_bytes",
    "maki_endpoint_inflight",
    "maki_crypto_latency_seconds_sum",
    "maki_crypto_latency_seconds_count",
    "maki_crypto_retries_total",
    "maki_retry_budget_tokens",
    "maki_circuit_state",
    "maki_endpoint_failover_total",
    "maki_journal_appended_sequence",
    "maki_journal_durable_sequence",
    "maki_journal_bytes",
    "maki_checkpoint_sequence",
    "maki_checkpoint_lag_bytes",
    "maki_flush_seconds_sum",
    "maki_flush_seconds_count",
    "maki_fua_seconds_sum",
    "maki_fua_seconds_count",
    "maki_cache_hits_total",
    "maki_cache_misses_total",
    "maki_backing_free_bytes",
    "maki_volume_state",
];

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0x40),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, UNIT, 512, UNIT + 8, DEVICE_SIZE, 16 * UNIT as u64)
            .unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn dispatch_config() -> DispatchConfig {
    DispatchConfig {
        retry: RetryPolicy {
            initial_delay: Duration::from_millis(10),
            max_delay: Duration::from_secs(1),
        },
        budget: RetryBudgetConfig {
            retry_ratio: 0.5,
            burst: 8,
            min_probe_per_sec: 1.0,
        },
        breaker: BreakerConfig {
            failure_threshold: 3,
            open_initial: Duration::from_secs(1),
            open_max: Duration::from_secs(30),
            half_open_max_requests: 2,
            success_threshold: 2,
        },
        global_max_inflight_batches: 8,
        global_max_inflight_bytes: 8 << 20,
        per_endpoint_max_inflight: 4,
        per_endpoint_max_bytes: 4 << 20,
        max_attempts: None,
        max_operation_time: None,
        retry_safe: true,
        validation_interval: Duration::from_secs(1),
    }
}

async fn engine(provider: Arc<dyn CryptoProvider>) -> Engine {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    Engine::attach(
        backing as Arc<dyn Backing>,
        provider,
        EngineOptions {
            checkpoint: CheckpointPolicy {
                emergency_reserve_bytes: 0,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

fn missing(metrics: &serde_json::Value) -> Vec<&'static str> {
    REQUIRED
        .iter()
        .copied()
        .filter(|k| metrics.get(k).is_none())
        .collect()
}

#[tokio::test]
async fn every_spec_required_metric_is_reported_with_a_dispatcher() {
    let fake: Arc<dyn CryptoProvider> = Arc::new(FakeCryptoProvider::new(UNIT));
    let set = Arc::new(EndpointSet::new(
        vec![
            ("primary".to_string(), fake.clone()),
            ("secondary".to_string(), fake),
        ],
        dispatch_config(),
        Arc::new(SystemClock::new()),
    ));
    let engine = engine(set.clone() as Arc<dyn CryptoProvider>).await;
    engine.write(0, &[7u8; UNIT as usize], true).await.unwrap();
    engine.flush().await.unwrap();
    engine.read(0, UNIT as usize).await.unwrap();

    let backend = EngineControlBackend::new(engine, "vol").with_endpoints(Some(set));
    let metrics = backend.metrics().await;
    assert!(
        missing(&metrics).is_empty(),
        "SPEC 40 metrics missing: {:?}",
        missing(&metrics)
    );
    assert_eq!(metrics["maki_fua_seconds_count"], json!(1));
    assert_eq!(metrics["maki_flush_seconds_count"], json!(1));
    assert!(
        metrics["maki_crypto_latency_seconds_count"]
            .as_u64()
            .unwrap()
            >= 2,
        "the self-test, canary, encrypt and decrypt RPCs were made: {metrics}"
    );
    assert_eq!(metrics["maki_circuit_state"]["primary"], json!(0), "closed");
    assert_eq!(metrics["maki_circuit_state"]["secondary"], json!(0));
    assert!(metrics["maki_retry_budget_tokens"]["primary"].is_number());
    assert_eq!(metrics["maki_endpoint_inflight"]["primary"], json!(0));
    assert_eq!(metrics["maki_endpoint_inflight"]["secondary"], json!(0));
    assert_eq!(metrics["maki_active_callbacks"], json!(0));
    assert_eq!(metrics["maki_plaintext_bytes"], json!(0));
    assert_eq!(metrics["maki_crypto_retries_total"], json!(0));
    assert_eq!(metrics["maki_volume_state"], json!(1));

    let status = backend.status().await;
    let endpoints = status["crypto"]["endpoints"].as_array().unwrap();
    assert_eq!(endpoints.len(), 2);
    assert_eq!(endpoints[0]["name"], json!("primary"));
    assert_eq!(endpoints[0]["circuit"], json!("closed"));
    assert_eq!(endpoints[0]["validated"], json!(true));
    assert!(endpoints[0]["retry_budget_tokens"].is_number());
}

#[tokio::test]
async fn every_spec_required_metric_is_reported_without_a_dispatcher() {
    let engine = engine(Arc::new(FakeCryptoProvider::new(UNIT))).await;
    let backend = EngineControlBackend::new(engine, "vol");
    let metrics = backend.metrics().await;
    assert!(
        missing(&metrics).is_empty(),
        "SPEC 40 metrics missing: {:?}",
        missing(&metrics)
    );
    // Per-endpoint gauges are empty objects, never absent, so a scraper's
    // schema does not depend on the provider type.
    assert_eq!(metrics["maki_endpoint_inflight"], json!({}));
    assert_eq!(metrics["maki_circuit_state"], json!({}));
    assert_eq!(metrics["maki_retry_budget_tokens"], json!({}));
    assert_eq!(metrics["maki_crypto_latency_seconds_count"], json!(0));
    assert_eq!(backend.status().await["crypto"]["endpoints"], json!([]));
}
