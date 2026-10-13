//! BUG-075: every admitted endpoint name survives complete official snapshots.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use maki_backing::Backing;
use maki_control::server::ControlBackend;
use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
use maki_crypto::breaker::BreakerConfig;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{CryptoProvider, SystemClock};
use maki_format::config::{parse_config, EndpointConfig};
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_nbdkit::control::EngineControlBackend;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::CrashableBacking;
use serde_json::{json, Value};
use uuid::Uuid;

const UNIT: u32 = 4096;
const DEVICE_SIZE: u64 = 64 * UNIT as u64;

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

struct Snapshot(Value);

#[async_trait]
impl ControlBackend for Snapshot {
    async fn status(&self) -> Value {
        self.0.clone()
    }
    async fn metrics(&self) -> Value {
        self.0.clone()
    }
    async fn checkpoint(&self) -> Result<u64, String> {
        unreachable!()
    }
    async fn reload(&self, _: &str, _: &Value) -> Result<(), String> {
        unreachable!()
    }
}

fn worst_numbers(value: &mut Value) {
    match value {
        Value::Number(number) => {
            *value = if number.is_f64() {
                json!(f64::MAX)
            } else {
                json!(u64::MAX)
            };
        }
        Value::Array(values) => values.iter_mut().for_each(worst_numbers),
        Value::Object(values) => values.values_mut().for_each(worst_numbers),
        _ => {}
    }
}

async fn assert_readable(names: Vec<String>) {
    let mut config = parse_config(include_str!(
        "../../maki-format/tests/data/full_config.toml"
    ))
    .unwrap();
    config.volume.name = "v".repeat(64);
    config.crypto.http.as_mut().unwrap().endpoint = names
        .iter()
        .map(|name| EndpointConfig {
            name: name.clone(),
            url: "http://127.0.0.1:9000".into(),
        })
        .collect();
    config.validate().unwrap();
    let fake: Arc<dyn CryptoProvider> = Arc::new(FakeCryptoProvider::new(UNIT));
    let endpoints = Arc::new(EndpointSet::new(
        names
            .iter()
            .map(|name| (name.clone(), fake.clone()))
            .collect(),
        dispatch_config(),
        Arc::new(SystemClock::new()),
    ));
    let backend = EngineControlBackend::new(engine(fake).await, config.volume.name)
        .with_endpoints(Some(endpoints));
    for command in ["status", "metrics"] {
        let mut doc = if command == "status" {
            backend.status().await
        } else {
            backend.metrics().await
        };
        // Counters may reach u64::MAX and finite floats may use exponent
        // notation. The budget must not depend on counters currently being 0.
        worst_numbers(&mut doc);
        let expected = doc.clone();
        let (server, client) = tokio::io::duplex(2 * maki_control::protocol::MAX_LINE);
        let task = tokio::spawn(maki_control::server::serve_connection(
            server,
            Arc::new(Snapshot(doc)),
            maki_control::server::ControlLimits::default(),
        ));
        let (mut reader, mut writer) = tokio::io::split(client);
        maki_control::protocol::send_command(
            &mut writer,
            &maki_control::protocol::Request::new(command),
        )
        .await
        .unwrap();
        let response = maki_control::protocol::read_response(&mut reader)
            .await
            .unwrap();
        assert_eq!(response["ok"], true, "{command}: {response}");
        assert_eq!(
            response["data"], expected,
            "the server must not truncate names or endpoint rows"
        );
        if command == "status" {
            assert_eq!(
                response["data"]["crypto"]["endpoints"]
                    .as_array()
                    .unwrap()
                    .len(),
                names.len()
            );
        } else {
            for metric in [
                "maki_endpoint_inflight",
                "maki_retry_budget_tokens",
                "maki_circuit_state",
            ] {
                let rows = response["data"][metric].as_object().unwrap();
                assert_eq!(rows.len(), names.len());
                assert!(names.iter().all(|name| rows.contains_key(name)));
            }
        }
        drop(reader);
        drop(writer);
        task.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn largest_admitted_list_of_64_byte_endpoint_names_is_complete() {
    let count = 48 * 1024 / (384 + 4 * (64 + 2));
    assert_readable(
        (0..count)
            .map(|i| format!("endpoint_{i:04}_{}", "n".repeat(50)))
            .collect(),
    )
    .await;
}

#[tokio::test]
async fn longest_admitted_single_endpoint_name_is_complete() {
    assert_readable(vec!["n".repeat((48 * 1024 - 384) / 4 - 2)]).await;
}

#[tokio::test]
async fn escaped_and_unicode_names_near_the_budget_are_complete() {
    assert_readable(vec!["\u{0001}".repeat(2_030)]).await;
    assert_readable(vec!["서울".repeat(2_030)]).await;
}
