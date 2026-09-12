use base64::Engine as _;
use futures_util::FutureExt;
use maki_crypto::{CiphertextUnit, CryptoContext, CryptoProvider, PlaintextUnit, SecretBuffer};
use maki_crypto_local::{keysource::MapKeySource, AesXtsProvider};
use maki_test_support::http_chaos::{Handler, RecordedRequest, ResponseSpec, TestServer};
use serde_json::json;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

fn xts(seed: u8) -> AesXtsProvider {
    let mut keys = MapKeySource::new();
    keys.insert("audit", (0..64).map(|n| n ^ seed).collect());
    AesXtsProvider::new(&keys, "audit", 512, "audit-uuid-v1").unwrap()
}
fn handler(seed: u8, unavailable: Arc<AtomicBool>) -> Handler {
    handler_with_canary_key(seed, seed, unavailable)
}

fn handler_with_canary_key(seed: u8, canary_seed: u8, unavailable: Arc<AtomicBool>) -> Handler {
    let common = xts(0x10);
    let actual = xts(seed);
    let canary_key = xts(canary_seed);
    Arc::new(move |req: &RecordedRequest| {
        if unavailable.load(Ordering::SeqCst) {
            return ResponseSpec::status(503);
        }
        let v: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        let context = CryptoContext {
            volume_uuid: v["volume"].as_str().unwrap().parse().unwrap(),
            format_version: 1,
            crypto_compatibility_id: "audit-uuid-v1".into(),
        };
        let unit_index = v["unit"].as_u64().unwrap();
        let data = base64::engine::general_purpose::STANDARD
            .decode(v["data"].as_str().unwrap())
            .unwrap();
        let provider = if context.volume_uuid.is_nil() {
            &common
        } else if unit_index == maki_format::canary::CANARY_UNIT_INDEX {
            &canary_key
        } else {
            &actual
        };
        let output = if req.path == "/encrypt" {
            provider
                .encrypt_batch(
                    &context,
                    &[PlaintextUnit {
                        unit_index,
                        data: SecretBuffer::from_vec(data),
                    }],
                )
                .now_or_never()
                .unwrap()
                .unwrap()
                .remove(0)
                .data
        } else {
            provider
                .decrypt_batch(&context, &[CiphertextUnit { unit_index, data }])
                .now_or_never()
                .unwrap()
                .unwrap()
                .remove(0)
                .data
                .expose()
                .to_vec()
        };
        ResponseSpec::json(
            &json!({"data":base64::engine::general_purpose::STANDARD.encode(output)}),
        )
    })
}
fn config(root: &str, urls: &[String]) -> String {
    let endpoints: String = urls
        .iter()
        .enumerate()
        .map(|(i, url)| format!("[[crypto.http.endpoint]]\nname = \"ep{i}\"\nurl = \"{url}\"\n"))
        .collect();
    format!(
        r#"
config_schema_version = 1
[volume]
name = "audit-uuid"
max_virtual_size = "1MiB"
device_block_size = 512
crypto_unit_size = 512
shard_logical_size = "64KiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "audit-uuid-v1"
availability_policy = "bounded-error"
max_operation_time = "2s"
[crypto.capabilities]
supported_plaintext_sizes = [512]
max_ciphertext_size = 512
integrity = "none"
context_binding = "none"
[crypto.retry]
initial_delay = "1ms"
max_delay = "20ms"
[crypto.retry_budget]
retry_ratio = 1.0
burst = 32
minimum_probe_rate = "20/s"
[crypto.circuit_breaker]
failure_threshold = 3
open_initial = "100ms"
open_max = "1s"
{endpoints}
[crypto.http.encrypt]
method = "POST"
path = "/encrypt"
[crypto.http.encrypt.body]
type = "json"
[crypto.http.encrypt.body.fields]
"/data" = {{ source = "payload", encoding = "base64" }}
"/unit" = {{ source = "unit_index" }}
"/volume" = {{ source = "volume_id" }}
[crypto.http.encrypt.response]
type = "json"
data_path = "/data"
encoding = "base64"
[crypto.http.decrypt]
method = "POST"
path = "/decrypt"
[crypto.http.decrypt.body]
type = "json"
[crypto.http.decrypt.body.fields]
"/data" = {{ source = "payload", encoding = "base64" }}
"/unit" = {{ source = "unit_index" }}
"/volume" = {{ source = "volume_id" }}
[crypto.http.decrypt.response]
type = "json"
data_path = "/data"
encoding = "base64"
[backing]
root = "{root}"
journal_emergency_reserve_bytes = "0B"
[cache]
mode = "off"
"#
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn different_real_volume_keys_are_rejected_before_serving_io() {
    let a = TestServer::start(handler(0x11, Arc::new(AtomicBool::new(false)))).await;
    let b = TestServer::start(handler(0x22, Arc::new(AtomicBool::new(false)))).await;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("volume");
    let raw = config(
        &root.to_string_lossy().replace('\\', "/"),
        &[a.url(), b.url()],
    );
    let config = maki_nbdkit::daemon::parse_and_validate(&raw).unwrap();
    let sb = maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();
    assert!(!sb.volume_uuid.is_nil());
    let result = maki_nbdkit::daemon::attach_from_config(&config).await;
    assert!(
        result.is_err(),
        "endpoints with different real-volume keys must not be admitted"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn matching_real_volume_keys_keep_failover_reads_intact() {
    let unavailable = Arc::new(AtomicBool::new(false));
    let a = TestServer::start(handler(0x11, unavailable.clone())).await;
    let b = TestServer::start(handler(0x11, Arc::new(AtomicBool::new(false)))).await;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("volume");
    let raw = config(
        &root.to_string_lossy().replace('\\', "/"),
        &[a.url(), b.url()],
    );
    let config = maki_nbdkit::daemon::parse_and_validate(&raw).unwrap();
    maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();
    let (engine, _, endpoints) = maki_nbdkit::daemon::attach_from_config_with_stats(&config)
        .await
        .unwrap();
    assert!(endpoints
        .unwrap()
        .endpoint_status()
        .iter()
        .all(|endpoint| endpoint.validated));
    let data = vec![0x77; 512];
    engine.write(5120, &data, true).await.unwrap();
    unavailable.store(true, Ordering::SeqCst);
    assert_eq!(engine.read(5120, 512).await.unwrap(), data);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_endpoint_must_match_the_reserved_canary_key() {
    let a = TestServer::start(handler(0x11, Arc::new(AtomicBool::new(false)))).await;
    let b = TestServer::start(handler_with_canary_key(
        0x11,
        0x22,
        Arc::new(AtomicBool::new(false)),
    ))
    .await;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("volume");
    let raw = config(
        &root.to_string_lossy().replace('\\', "/"),
        &[a.url(), b.url()],
    );
    let config = maki_nbdkit::daemon::parse_and_validate(&raw).unwrap();
    maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();
    let result = maki_nbdkit::daemon::attach_from_config(&config).await;
    assert!(
        result.is_err(),
        "matching ordinary units must not hide a different canary key"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn endpoint_validation_uses_real_identity_under_the_volume_lock() {
    use maki_backing::Backing;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("volume");
    let real_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut servers = Vec::new();
    for _ in 0..2 {
        let root = root.clone();
        let count = real_calls.clone();
        let delegate = handler(0x11, Arc::new(AtomicBool::new(false)));
        let observed: Handler = Arc::new(move |request| {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let uuid: uuid::Uuid = body["volume"].as_str().unwrap().parse().unwrap();
            assert!(
                !uuid.is_nil(),
                "endpoint must never be trusted under a synthetic UUID"
            );
            let backing = maki_backing::FileBacking::new(&root).unwrap();
            assert!(
                backing.try_lock("volume.lock").is_err(),
                "validation must retain the volume lock"
            );
            count.fetch_add(1, Ordering::SeqCst);
            delegate(request)
        });
        servers.push(TestServer::start(observed).await);
    }
    let raw = config(
        &root.to_string_lossy().replace('\\', "/"),
        &servers.iter().map(|s| s.url()).collect::<Vec<_>>(),
    );
    let config = maki_nbdkit::daemon::parse_and_validate(&raw).unwrap();
    maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();
    let engine = maki_nbdkit::daemon::attach_from_config(&config)
        .await
        .unwrap();
    assert!(real_calls.load(Ordering::SeqCst) >= 12);
    drop(engine);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovered_quarantined_endpoint_must_match_the_canary() {
    let unavailable = Arc::new(AtomicBool::new(true));
    let a = TestServer::start(handler(0x11, Arc::new(AtomicBool::new(false)))).await;
    let b = TestServer::start(handler_with_canary_key(0x11, 0x22, unavailable.clone())).await;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("volume");
    let raw = config(
        &root.to_string_lossy().replace('\\', "/"),
        &[a.url(), b.url()],
    );
    let config = maki_nbdkit::daemon::parse_and_validate(&raw).unwrap();
    maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();
    let (engine, _, endpoints) = maki_nbdkit::daemon::attach_from_config_with_stats(&config)
        .await
        .unwrap();
    let endpoints = endpoints.unwrap();
    assert!(!endpoints.endpoint_status()[1].validated);
    engine.write(5120, &[0x77; 512], true).await.unwrap();
    unavailable.store(false, Ordering::SeqCst);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            assert_eq!(engine.read(5120, 512).await.unwrap(), [0x77; 512]);
            let peer = &endpoints.endpoint_status()[1];
            assert!(
                !peer.validated,
                "wrong canary endpoint must never be promoted"
            );
            if peer.rejected {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("recovered wrong-key endpoint must be rejected");
}
