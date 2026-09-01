//! Phase 8 — HTTP remote provider (SPEC §18–§19, §50).

mod common;

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use serde_json::json;

use common::{Handler, RecordedRequest, ResponseSpec, TestServer};
use maki_crypto::selftest::provider_self_test;
use maki_crypto::{
    Capability, CryptoContext, CryptoError, CryptoProvider, ErrorClass, PlaintextUnit,
    SecretBuffer,
};
use maki_crypto_http::{
    BodySpec, FieldSource, HttpCryptoProvider, HttpProviderSpec, OpSpec, PayloadEncoding,
    RespKind, RespSpec,
};

const UNIT: usize = 512;
const XOR: u8 = 0x5A;

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn b64d(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

fn xor(data: &[u8]) -> Vec<u8> {
    data.iter().map(|b| b ^ XOR).collect()
}

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x88),
        format_version: 1,
        crypto_compatibility_id: "vendor-profile-v1".to_string(),
    }
}

fn caps() -> maki_crypto::CryptoCapabilities {
    maki_crypto::CryptoCapabilities {
        provider_id: "remote-http-test".to_string(),
        crypto_compatibility_id: "vendor-profile-v1".to_string(),
        supported_plaintext_sizes: vec![UNIT as u32],
        max_ciphertext_size: UNIT as u32,
        stateless: true,
        retry_safe: true,
        batch: maki_crypto::BatchCapability {
            supported: true,
            max_items: 64,
            max_bytes: 1 << 20,
        },
        integrity: Capability::Absent,
        context_binding: Capability::Absent,
        replay_protection: Capability::Absent,
    }
}

fn pt(i: u64, fill: u8) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: i,
        data: SecretBuffer::from_slice(&vec![fill; UNIT]),
    }
}

fn json_op(path: &str, data_field: &str, result_path: &str) -> OpSpec {
    OpSpec {
        method: "POST".to_string(),
        path: path.to_string(),
        headers: vec![("x-vendor".to_string(), "maki-test".to_string())],
        query: vec![("profile".to_string(), "v1".to_string())],
        body: BodySpec::Json {
            fields: vec![
                (format!("/{data_field}"), FieldSource::Payload(PayloadEncoding::Base64)),
                ("/volume".to_string(), FieldSource::VolumeId),
                ("/unit".to_string(), FieldSource::UnitIndex),
            ],
            items_path: None,
            item_fields: vec![],
        },
        response: RespSpec {
            kind: RespKind::Json,
            data_path: Some(result_path.to_string()),
            encoding: PayloadEncoding::Base64,
            items_path: None,
            item_index_path: None,
        },
    }
}

fn spec(url: &str, encrypt: OpSpec, decrypt: OpSpec) -> HttpProviderSpec {
    HttpProviderSpec {
        base_url: url.to_string(),
        encrypt,
        decrypt,
        capabilities: caps(),
        timeout: Duration::from_secs(5),
        max_response_bytes: 1 << 20,
        tls: None,
    }
}

/// Handler implementing the xor "vendor crypto" for the single-item JSON
/// mapping.
fn xor_json_handler(data_field: &'static str, result_path: &'static str) -> Handler {
    Arc::new(move |req: &RecordedRequest| {
        let v: serde_json::Value = match serde_json::from_slice(&req.body) {
            Ok(v) => v,
            Err(_) => return ResponseSpec::status(400),
        };
        let Some(data) = v.pointer(&format!("/{data_field}")).and_then(|d| d.as_str()) else {
            return ResponseSpec::status(422);
        };
        let ct = xor(&b64d(data));
        ResponseSpec::json(&json!({ result_path: b64(&ct) }))
    })
}

// ---------- JSON mapping + base64 + headers + query ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn json_base64_roundtrip_with_headers_and_query() {
    let server = TestServer::start(xor_json_handler("data", "ciphertext")).await;
    let provider = HttpCryptoProvider::new(spec(
        &server.url(),
        json_op("/encrypt", "data", "/ciphertext"),
        json_op("/decrypt", "data", "/ciphertext"),
    ))
    .unwrap();

    let cts = provider.encrypt_batch(&ctx(), &[pt(7, 0xAB)]).await.unwrap();
    assert_eq!(cts[0].data, xor(&vec![0xAB; UNIT]));
    let pts = provider.decrypt_batch(&ctx(), &cts).await.unwrap();
    assert_eq!(pts[0].data.expose(), &vec![0xAB; UNIT][..]);

    let requests = server.requests.lock().clone();
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].path, "/encrypt");
    assert_eq!(requests[0].query.get("profile").unwrap(), "v1");
    assert_eq!(requests[0].headers.get("x-vendor").unwrap(), "maki-test");
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["unit"], 7);
    assert_eq!(
        body["volume"],
        uuid::Uuid::from_u128(0x88).to_string(),
        "volume id mapped into the body"
    );
    assert_eq!(b64d(body["data"].as_str().unwrap()), vec![0xAB; UNIT]);
    assert_eq!(requests[1].path, "/decrypt");
}

// ---------- hex encoding ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hex_payload_encoding_works() {
    let handler: Handler = Arc::new(|req: &RecordedRequest| {
        let v: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        let hex = v.pointer("/data").unwrap().as_str().unwrap();
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let out = xor(&bytes);
        let out_hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
        ResponseSpec::json(&json!({"result": out_hex}))
    });
    let server = TestServer::start(handler).await;

    let mut op = json_op("/op", "data", "/result");
    op.body = BodySpec::Json {
        fields: vec![("/data".to_string(), FieldSource::Payload(PayloadEncoding::HexLower))],
        items_path: None,
        item_fields: vec![],
    };
    op.response.encoding = PayloadEncoding::HexLower;
    let provider =
        HttpCryptoProvider::new(spec(&server.url(), op.clone(), op)).unwrap();
    let cts = provider.encrypt_batch(&ctx(), &[pt(1, 0x3C)]).await.unwrap();
    assert_eq!(cts[0].data, xor(&vec![0x3C; UNIT]));
}

// ---------- raw payload ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_payload_roundtrip() {
    let handler: Handler = Arc::new(|req: &RecordedRequest| ResponseSpec::raw(xor(&req.body)));
    let server = TestServer::start(handler).await;
    let op = OpSpec {
        method: "POST".to_string(),
        path: "/raw".to_string(),
        headers: vec![],
        query: vec![],
        body: BodySpec::Raw,
        response: RespSpec {
            kind: RespKind::Raw,
            data_path: None,
            encoding: PayloadEncoding::Base64,
            items_path: None,
            item_index_path: None,
        },
    };
    let provider = HttpCryptoProvider::new(spec(&server.url(), op.clone(), op)).unwrap();
    let cts = provider.encrypt_batch(&ctx(), &[pt(3, 0x11)]).await.unwrap();
    assert_eq!(cts[0].data, xor(&vec![0x11; UNIT]));
    let pts = provider.decrypt_batch(&ctx(), &cts).await.unwrap();
    assert_eq!(pts[0].data.expose(), &vec![0x11; UNIT][..]);
}

// ---------- batch layout, reorder, partial response ----------

fn batch_op() -> OpSpec {
    OpSpec {
        method: "POST".to_string(),
        path: "/batch".to_string(),
        headers: vec![],
        query: vec![],
        body: BodySpec::Json {
            fields: vec![("/profile".to_string(), FieldSource::CompatibilityId)],
            items_path: Some("/items".to_string()),
            item_fields: vec![
                ("/data".to_string(), FieldSource::Payload(PayloadEncoding::Base64)),
                ("/idx".to_string(), FieldSource::UnitIndex),
            ],
        },
        response: RespSpec {
            kind: RespKind::Json,
            data_path: Some("/data".to_string()),
            encoding: PayloadEncoding::Base64,
            items_path: Some("/results".to_string()),
            item_index_path: Some("/idx".to_string()),
        },
    }
}

fn batch_handler(reorder: bool, drop_last: bool) -> Handler {
    Arc::new(move |req: &RecordedRequest| {
        let v: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(v["profile"], "vendor-profile-v1");
        let items = v.pointer("/items").unwrap().as_array().unwrap();
        let mut results: Vec<serde_json::Value> = items
            .iter()
            .map(|item| {
                let data = b64d(item.pointer("/data").unwrap().as_str().unwrap());
                json!({
                    "idx": item.pointer("/idx").unwrap(),
                    "data": b64(&xor(&data)),
                })
            })
            .collect();
        if reorder && results.len() >= 2 {
            results.swap(0, 1);
        }
        if drop_last {
            results.pop();
        }
        ResponseSpec::json(&json!({ "results": results }))
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn batch_single_request_preserves_order() {
    let server = TestServer::start(batch_handler(false, false)).await;
    let provider =
        HttpCryptoProvider::new(spec(&server.url(), batch_op(), batch_op())).unwrap();
    let items = vec![pt(10, 1), pt(20, 2), pt(30, 3)];
    let cts = provider.encrypt_batch(&ctx(), &items).await.unwrap();
    assert_eq!(server.requests.lock().len(), 1, "one HTTP request per batch");
    assert_eq!(cts.len(), 3);
    for (i, ct) in cts.iter().enumerate() {
        assert_eq!(ct.unit_index, items[i].unit_index);
        assert_eq!(ct.data, xor(&vec![i as u8 + 1; UNIT]));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn batch_reorder_is_detected() {
    let server = TestServer::start(batch_handler(true, false)).await;
    let provider =
        HttpCryptoProvider::new(spec(&server.url(), batch_op(), batch_op())).unwrap();
    let err = provider
        .encrypt_batch(&ctx(), &[pt(10, 1), pt(20, 2)])
        .await
        .unwrap_err();
    assert!(matches!(err, CryptoError::Contract(_)), "{err:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn partial_batch_response_is_detected() {
    let server = TestServer::start(batch_handler(false, true)).await;
    let provider =
        HttpCryptoProvider::new(spec(&server.url(), batch_op(), batch_op())).unwrap();
    let err = provider
        .encrypt_batch(&ctx(), &[pt(10, 1), pt(20, 2)])
        .await
        .unwrap_err();
    assert!(matches!(err, CryptoError::Contract(_)), "{err:?}");
}

// ---------- response-size limit ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_response_is_refused() {
    let handler: Handler = Arc::new(|_req: &RecordedRequest| {
        ResponseSpec::raw(vec![0u8; 256 * 1024])
    });
    let server = TestServer::start(handler).await;
    let mut s = spec(
        &server.url(),
        json_op("/encrypt", "data", "/ciphertext"),
        json_op("/decrypt", "data", "/ciphertext"),
    );
    s.max_response_bytes = 4096;
    let provider = HttpCryptoProvider::new(s).unwrap();
    let err = provider.encrypt_batch(&ctx(), &[pt(1, 5)]).await.unwrap_err();
    assert_eq!(err.class(), ErrorClass::NonRetryableRequest, "{err:?}");
}

// ---------- HTTP status classification ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_codes_classify_correctly() {
    let server = TestServer::start(Arc::new(|_: &RecordedRequest| ResponseSpec::status(429))).await;
    let provider = HttpCryptoProvider::new(spec(
        &server.url(),
        json_op("/encrypt", "data", "/ciphertext"),
        json_op("/decrypt", "data", "/ciphertext"),
    ))
    .unwrap();

    let err = provider.encrypt_batch(&ctx(), &[pt(1, 1)]).await.unwrap_err();
    assert_eq!(err.class(), ErrorClass::Throttled, "429 → Throttled");

    server.set_handler(Arc::new(|_: &RecordedRequest| ResponseSpec::status(503)));
    let err = provider.encrypt_batch(&ctx(), &[pt(1, 1)]).await.unwrap_err();
    assert_eq!(err.class(), ErrorClass::Retryable, "503 → Retryable");

    server.set_handler(Arc::new(|_: &RecordedRequest| ResponseSpec::status(400)));
    let err = provider.encrypt_batch(&ctx(), &[pt(1, 1)]).await.unwrap_err();
    assert_eq!(err.class(), ErrorClass::NonRetryableRequest, "400");

    server.set_handler(Arc::new(|_: &RecordedRequest| ResponseSpec::status(401)));
    let err = provider.encrypt_batch(&ctx(), &[pt(1, 1)]).await.unwrap_err();
    assert_eq!(err.class(), ErrorClass::EndpointFatal, "401 → endpoint fatal");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timeout_is_retryable() {
    let handler: Handler = Arc::new(|_: &RecordedRequest| {
        let mut r = ResponseSpec::status(200);
        r.delay = Duration::from_secs(10);
        r
    });
    let server = TestServer::start(handler).await;
    let mut s = spec(
        &server.url(),
        json_op("/encrypt", "data", "/ciphertext"),
        json_op("/decrypt", "data", "/ciphertext"),
    );
    s.timeout = Duration::from_millis(200);
    let provider = HttpCryptoProvider::new(s).unwrap();
    let err = provider.encrypt_batch(&ctx(), &[pt(1, 1)]).await.unwrap_err();
    assert_eq!(err.class(), ErrorClass::Retryable, "timeout → Retryable: {err:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn truncated_response_is_an_error_not_garbage() {
    let handler: Handler = Arc::new(|req: &RecordedRequest| {
        let v: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        let data = b64d(v.pointer("/data").unwrap().as_str().unwrap());
        let mut r = ResponseSpec::json(&json!({"ciphertext": b64(&xor(&data))}));
        r.drop_after = Some(20); // close mid-body
        r
    });
    let server = TestServer::start(handler).await;
    let provider = HttpCryptoProvider::new(spec(
        &server.url(),
        json_op("/encrypt", "data", "/ciphertext"),
        json_op("/decrypt", "data", "/ciphertext"),
    ))
    .unwrap();
    assert!(provider.encrypt_batch(&ctx(), &[pt(1, 1)]).await.is_err());
}

// ---------- body-mapping self-test ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provider_passes_body_mapping_self_test() {
    let server = TestServer::start(xor_json_handler("data", "ciphertext")).await;
    let provider = HttpCryptoProvider::new(spec(
        &server.url(),
        json_op("/encrypt", "data", "/ciphertext"),
        json_op("/decrypt", "data", "/ciphertext"),
    ))
    .unwrap();
    provider_self_test(&provider, &ctx(), UNIT, "vendor-profile-v1")
        .await
        .unwrap();
}

// ---------- config integration + credentials ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn from_config_resolves_credentials_into_headers() {
    let server = TestServer::start(xor_json_handler("data", "ciphertext")).await;
    std::env::set_var("MAKI_CREDENTIAL_CRYPTO_TOKEN", "Bearer sekrit-123");

    let toml = format!(
        r#"
config_schema_version = 1
[volume]
name = "t"
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
[[crypto.http.endpoint]]
name = "a"
url = "{url}"
[crypto.http.encrypt]
method = "POST"
path = "/encrypt"
[crypto.http.encrypt.headers]
Authorization = {{ source = "env", name = "crypto-token" }}
[crypto.http.encrypt.body]
type = "json"
[crypto.http.encrypt.body.fields]
"/data" = {{ source = "payload", encoding = "base64" }}
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
root = "/tmp/unused"
"#,
        url = server.url()
    );
    let cfg = maki_format::config::parse_config(&toml).unwrap();
    cfg.validate().unwrap();
    let provider = HttpCryptoProvider::from_config(
        &cfg,
        &server.url(),
        &maki_crypto_local::keysource::EnvKeySource,
    )
    .unwrap();
    let cts = provider.encrypt_batch(&ctx(), &[pt(1, 0x42)]).await.unwrap();
    assert_eq!(cts[0].data, xor(&vec![0x42; UNIT]));
    let requests = server.requests.lock().clone();
    assert_eq!(
        requests[0].headers.get("authorization").unwrap(),
        "Bearer sekrit-123",
        "credential resolved into header"
    );
}

// ---------- absence of payload logging ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn payloads_never_appear_in_logs() {
    use tracing_subscriber::layer::SubscriberExt;

    #[derive(Clone, Default)]
    struct Capture(Arc<parking_lot::Mutex<String>>);
    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().push_str(&String::from_utf8_lossy(buf));
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(move || writer.clone())
            .with_filter(tracing_subscriber::filter::LevelFilter::TRACE),
    );
    let _guard = tracing::subscriber::set_default(subscriber);

    let server = TestServer::start(xor_json_handler("data", "ciphertext")).await;
    let provider = HttpCryptoProvider::new(spec(
        &server.url(),
        json_op("/encrypt", "data", "/ciphertext"),
        json_op("/decrypt", "data", "/ciphertext"),
    ))
    .unwrap();
    let secret = vec![0xABu8; UNIT];
    let cts = provider.encrypt_batch(&ctx(), &[pt(7, 0xAB)]).await.unwrap();
    let _ = provider.decrypt_batch(&ctx(), &cts).await.unwrap();

    let logs = capture.0.lock().clone();
    assert!(
        !logs.contains(&b64(&secret)),
        "plaintext base64 leaked into logs"
    );
    assert!(
        !logs.contains(&b64(&cts[0].data)),
        "ciphertext base64 leaked into logs"
    );
}

use tracing_subscriber::Layer as _;
