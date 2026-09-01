//! Phase 8 — engine over the HTTP provider with chaos (SPEC §50
//! "fake HTTP chaos suite"): flaky endpoints, failover, and durability
//! through the full daemon assembly path.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use base64::Engine as _;
use serde_json::json;

use maki_test_support::http_chaos::{Handler, RecordedRequest, ResponseSpec, TestServer};

const UNIT: usize = 512;
const XOR: u8 = 0x33;

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn xor_handler() -> Handler {
    Arc::new(|req: &RecordedRequest| {
        let v: serde_json::Value = match serde_json::from_slice(&req.body) {
            Ok(v) => v,
            Err(_) => return ResponseSpec::status(400),
        };
        let data = v.pointer("/data").and_then(|d| d.as_str()).unwrap_or("");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(data)
            .unwrap_or_default();
        let out: Vec<u8> = bytes.iter().map(|b| b ^ XOR).collect();
        ResponseSpec::json(&json!({"ciphertext": b64(&out)}))
    })
}

/// Flaky: first `fail_n` requests get 503, then xor service.
fn flaky_handler(fail_n: u32) -> Handler {
    let remaining = Arc::new(AtomicU32::new(fail_n));
    let inner = xor_handler();
    Arc::new(move |req: &RecordedRequest| {
        if remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1))
            .is_ok()
        {
            return ResponseSpec::status(503);
        }
        inner(req)
    })
}

fn config_toml(root: &str, urls: &[String]) -> String {
    let endpoints: String = urls
        .iter()
        .enumerate()
        .map(|(i, url)| format!("[[crypto.http.endpoint]]\nname = \"ep{i}\"\nurl = \"{url}\"\n"))
        .collect();
    format!(
        r#"
config_schema_version = 1
[volume]
name = "httpvol"
max_virtual_size = "1MiB"
device_block_size = 512
crypto_unit_size = 512
shard_logical_size = "64KiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "vendor-profile-v1"
[crypto.capabilities]
supported_plaintext_sizes = [512]
max_ciphertext_size = 512
[crypto.retry]
initial_delay = "10ms"
max_delay = "200ms"
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
[crypto.http.encrypt.response]
type = "json"
data_path = "/ciphertext"
encoding = "base64"
[crypto.http.decrypt]
method = "POST"
path = "/decrypt"
[crypto.http.decrypt.body]
type = "json"
[crypto.http.decrypt.body.fields]
"/data" = {{ source = "payload", encoding = "base64" }}
[crypto.http.decrypt.response]
type = "json"
data_path = "/ciphertext"
encoding = "base64"
[backing]
root = "{root}"
"#
    )
}

async fn attach(config: &str) -> maki_core::engine::Engine {
    let cfg = maki_nbdkit::daemon::parse_and_validate(config).unwrap();
    let _ = maki_nbdkit::daemon::create_volume_from_config_str(config);
    maki_nbdkit::daemon::attach_from_config(&cfg).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn engine_roundtrips_through_http_provider() {
    let server = TestServer::start(xor_handler()).await;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vol").to_string_lossy().replace('\\', "/");
    let engine = attach(&config_toml(&root, &[server.url()])).await;

    engine.write(0, &vec![0xAB; UNIT], true).await.unwrap();
    assert_eq!(engine.read(0, UNIT).await.unwrap(), vec![0xAB; UNIT]);
    // On-disk journal holds ciphertext (xor of plaintext), not plaintext.
    engine.flush().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transient_5xx_is_ridden_out_by_the_dispatcher() {
    let server = TestServer::start(flaky_handler(4)).await;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vol").to_string_lossy().replace('\\', "/");
    // Attach itself runs the self-test through the flaky endpoint.
    let engine = attach(&config_toml(&root, &[server.url()])).await;
    engine.write(0, &vec![0x77; UNIT], true).await.unwrap();
    assert_eq!(engine.read(0, UNIT).await.unwrap(), vec![0x77; UNIT]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dead_endpoint_fails_over_to_healthy_one() {
    let dead = TestServer::start(Arc::new(|_: &RecordedRequest| ResponseSpec::status(503))).await;
    let healthy = TestServer::start(xor_handler()).await;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vol").to_string_lossy().replace('\\', "/");
    // Dead endpoint listed first: everything must fail over.
    let engine = attach(&config_toml(&root, &[dead.url(), healthy.url()])).await;
    for i in 0..4u64 {
        engine
            .write(i * UNIT as u64, &vec![i as u8 + 1; UNIT], false)
            .await
            .unwrap();
    }
    engine.flush().await.unwrap();
    for i in 0..4u64 {
        assert_eq!(
            engine.read(i * UNIT as u64, UNIT).await.unwrap(),
            vec![i as u8 + 1; UNIT]
        );
    }
    assert!(
        healthy.requests.lock().len() >= 4,
        "healthy endpoint must have served the traffic"
    );
}
