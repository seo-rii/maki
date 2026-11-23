use base64::Engine as _;
use futures_util::FutureExt;
use maki_crypto::{
    CiphertextUnit, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit, SecretBuffer,
};
use maki_crypto_local::{keysource::MapKeySource, AesGcmSivProvider, AesXtsProvider};
use maki_test_support::http_chaos::{Handler, RecordedRequest, ResponseSpec, TestServer};
use serde_json::json;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};

fn xts(seed: u8) -> AesXtsProvider {
    let mut keys = MapKeySource::new();
    keys.insert("audit", (0..64).map(|n| n ^ seed).collect());
    AesXtsProvider::new(&keys, "audit", 512, "audit-uuid-v1").unwrap()
}
/// An authenticated cipher: a ciphertext under another key is refused.
fn gcm(seed: u8) -> AesGcmSivProvider {
    let mut keys = MapKeySource::new();
    keys.insert("audit", vec![seed; 32]);
    AesGcmSivProvider::new(&keys, "audit", 512, "audit-uuid-v1").unwrap()
}
fn handler(seed: u8, unavailable: Arc<AtomicBool>) -> Handler {
    handler_with_canary_key(seed, seed, unavailable)
}

fn handler_with_canary_key(seed: u8, canary_seed: u8, unavailable: Arc<AtomicBool>) -> Handler {
    serve(xts, seed, canary_seed, unavailable)
}

/// Serve `cipher(seed)`, `cipher(canary_seed)` for the key canary's unit.
/// A refused ciphertext is answered with the wire contract's integrity
/// failure (HTTP 422, `maki-crypto-error: auth-tag-mismatch`).
fn serve<P: CryptoProvider + 'static>(
    cipher: fn(u8) -> P,
    seed: u8,
    canary_seed: u8,
    unavailable: Arc<AtomicBool>,
) -> Handler {
    let common = cipher(0x10);
    let actual = cipher(seed);
    let canary_key = cipher(canary_seed);
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
            match provider
                .decrypt_batch(&context, &[CiphertextUnit { unit_index, data }])
                .now_or_never()
                .unwrap()
            {
                Ok(mut plain) => plain.remove(0).data.expose().to_vec(),
                Err(CryptoError::Integrity(_)) => {
                    let mut refused = ResponseSpec::status(422);
                    refused
                        .headers
                        .push(("maki-crypto-error".into(), "auth-tag-mismatch".into()));
                    return refused;
                }
                Err(error) => panic!("test cipher failed: {error}"),
            }
        };
        ResponseSpec::json(
            &json!({"data":base64::engine::general_purpose::STANDARD.encode(output)}),
        )
    })
}
fn config(root: &std::path::Path, urls: &[String]) -> String {
    let root = serde_json::to_string(root).unwrap();
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
root = {root}
journal_emergency_reserve_bytes = "0B"
[cache]
mode = "off"
"#
    )
}

#[test]
fn config_preserves_native_path_characters() {
    for root in [
        r"C:\Users\runner\AppData\Local\Temp\volume",
        r#"/tmp/a "quoted" path"#,
    ] {
        let parsed =
            maki_format::config::parse_config(&config(std::path::Path::new(root), &[])).unwrap();
        assert_eq!(parsed.backing.root, root);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn different_real_volume_keys_are_rejected_before_serving_io() {
    let a = TestServer::start(handler(0x11, Arc::new(AtomicBool::new(false)))).await;
    let b = TestServer::start(handler(0x22, Arc::new(AtomicBool::new(false)))).await;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("volume");
    let raw = config(&root, &[a.url(), b.url()]);
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
    let raw = config(&root, &[a.url(), b.url()]);
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
    let raw = config(&root, &[a.url(), b.url()]);
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
    let raw = config(&root, &servers.iter().map(|s| s.url()).collect::<Vec<_>>());
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
    let raw = config(&root, &[a.url(), b.url()]);
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

/// With an authenticated cipher a wrong key cannot decrypt the canary to the
/// wrong plaintext: it refuses it with an integrity failure. That refusal is
/// proof of another key, like the wrong plaintext above, so the recovered
/// quarantined endpoint is rejected for the life of the set rather than
/// deferred (and validated again) forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovered_quarantined_endpoint_whose_canary_is_refused_is_rejected() {
    for (case, seed, canary_seed) in [
        ("another key", 0x22, 0x22),
        ("another canary key", 0x11, 0x22),
    ] {
        let unavailable = Arc::new(AtomicBool::new(true));
        let a = TestServer::start(serve(gcm, 0x11, 0x11, Arc::new(AtomicBool::new(false)))).await;
        let b = TestServer::start(serve(gcm, seed, canary_seed, unavailable.clone())).await;
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("volume");
        let raw = config(&root, &[a.url(), b.url()]).replace(
            "max_ciphertext_size = 512\nintegrity = \"none\"",
            "max_ciphertext_size = 540\nintegrity = \"contractual\"",
        );
        assert!(raw.contains("integrity = \"contractual\""));
        let config = maki_nbdkit::daemon::parse_and_validate(&raw).unwrap();
        maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();
        let (engine, _, endpoints) = maki_nbdkit::daemon::attach_from_config_with_stats(&config)
            .await
            .unwrap();
        let endpoints = endpoints.unwrap();
        assert!(!endpoints.endpoint_status()[1].validated, "{case}");
        engine.write(5120, &[0x77; 512], true).await.unwrap();
        unavailable.store(false, Ordering::SeqCst);
        let canary_probes = || {
            b.requests
                .lock()
                .iter()
                .filter(|request| is_canary_decrypt(request))
                .count()
        };
        let rejected = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                assert_eq!(engine.read(5120, 512).await.unwrap(), [0x77; 512]);
                let peer = &endpoints.endpoint_status()[1];
                assert!(
                    !peer.validated,
                    "{case}: wrong-key endpoint must never be promoted"
                );
                if peer.rejected {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(
            rejected.is_ok(),
            "{case}: an endpoint that refused the volume canary {} time(s) is still only \
             deferred: {:?}",
            canary_probes(),
            endpoints.endpoint_status()[1]
        );
        assert!(canary_probes() >= 1, "{case}");
        drop(engine);
    }
}

fn is_canary_decrypt(request: &RecordedRequest) -> bool {
    request.path == "/decrypt"
        && serde_json::from_slice::<serde_json::Value>(&request.body).unwrap()["unit"].as_u64()
            == Some(maki_format::canary::CANARY_UNIT_INDEX)
}

/// Only an integrity refusal of the canary is proof. A canary decrypt that
/// fails as an exchange (an unavailable endpoint, a reply without the
/// payload) leaves the recovered endpoint quarantined, and a later complete
/// validation admits it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_canary_exchange_defers_a_recovered_endpoint_until_it_validates() {
    let unavailable = Arc::new(AtomicBool::new(true));
    let a = TestServer::start(serve(gcm, 0x11, 0x11, Arc::new(AtomicBool::new(false)))).await;
    let healthy = serve(gcm, 0x11, 0x11, unavailable.clone());
    let glitches = Arc::new(AtomicUsize::new(0));
    let glitched = glitches.clone();
    let b = TestServer::start(Arc::new(move |request: &RecordedRequest| {
        if !is_canary_decrypt(request) {
            return healthy(request);
        }
        match glitched.fetch_add(1, Ordering::SeqCst) {
            0 => ResponseSpec::status(503),
            1 => ResponseSpec::json(&json!({})),
            _ => healthy(request),
        }
    }))
    .await;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("volume");
    let raw = config(&root, &[a.url(), b.url()]).replace(
        "max_ciphertext_size = 512\nintegrity = \"none\"",
        "max_ciphertext_size = 540\nintegrity = \"contractual\"",
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
    let validated = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            assert_eq!(engine.read(5120, 512).await.unwrap(), [0x77; 512]);
            let peer = &endpoints.endpoint_status()[1];
            assert!(
                !peer.rejected,
                "a failed canary exchange is not proof: {peer:?}"
            );
            if peer.validated {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        validated.is_ok(),
        "recovered endpoint never validated after {} canary decrypt(s): {:?}",
        glitches.load(Ordering::SeqCst),
        endpoints.endpoint_status()[1]
    );
    assert!(glitches.load(Ordering::SeqCst) >= 3);
    drop(engine);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounded_error_retries_a_transient_failure_while_time_remains() {
    let fail_once = Arc::new(AtomicBool::new(false));
    let armed = fail_once.clone();
    let healthy = handler(7, Arc::new(AtomicBool::new(false)));
    let server = TestServer::start(Arc::new(move |request| {
        if armed.swap(false, Ordering::SeqCst) {
            ResponseSpec::status(503)
        } else {
            healthy(request)
        }
    }))
    .await;
    let dir = tempfile::tempdir().unwrap();
    let raw = config(&dir.path().join("vol"), &[server.url()])
        .replace(r#"initial_delay = "1ms""#, r#"initial_delay = "1100ms""#)
        .replace(r#"max_delay = "20ms""#, r#"max_delay = "1100ms""#);
    let config = maki_nbdkit::daemon::parse_and_validate(&raw).unwrap();
    maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();
    let (engine, _, endpoints) = maki_nbdkit::daemon::attach_from_config_with_stats(&config)
        .await
        .unwrap();
    fail_once.store(true, Ordering::SeqCst);
    engine.write(0, &[0x77; 512], true).await.unwrap();
    assert_eq!(endpoints.unwrap().metrics().retries_total(), 1);
}
