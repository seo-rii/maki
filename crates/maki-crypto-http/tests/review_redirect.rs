//! C-01: the HTTP provider must never follow a redirect. reqwest's default
//! policy replays the POST body — the plaintext, on encrypt — to whatever
//! `Location` the server names, possibly another host over plaintext
//! HTTP, and turns 301/302/303 into a body-less GET whose response would
//! then be parsed as ciphertext. C-11: resolved credentials must not print.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::{Handler, RecordedRequest, ResponseSpec, TestServer};
use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    PlaintextUnit, SecretBuffer,
};
use maki_crypto_http::{
    BodySpec, FieldSource, HttpCryptoProvider, HttpProviderSpec, OpSpec, PayloadEncoding, RespKind,
    RespSpec, TlsSpec,
};

const UNIT: usize = 64;

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x3),
        format_version: 1,
        crypto_compatibility_id: "vendor-profile-v1".to_string(),
    }
}

fn caps() -> CryptoCapabilities {
    CryptoCapabilities {
        provider_id: "remote-http-test".to_string(),
        crypto_compatibility_id: "vendor-profile-v1".to_string(),
        supported_plaintext_sizes: vec![UNIT as u32],
        max_ciphertext_size: UNIT as u32,
        stateless: true,
        retry_safe: true,
        batch: BatchCapability {
            supported: true,
            max_items: 64,
            max_bytes: 1 << 20,
        },
        integrity: Capability::Absent,
        context_binding: Capability::Absent,
        replay_protection: Capability::Absent,
    }
}

fn json_op(path: &str) -> OpSpec {
    OpSpec {
        method: "POST".to_string(),
        path: path.to_string(),
        headers: vec![(
            "authorization".to_string(),
            "Bearer SECRET-TOKEN".to_string(),
        )],
        query: vec![("api_key".to_string(), "SECRET-QUERY".to_string())],
        body: BodySpec::Json {
            fields: vec![(
                "/data".to_string(),
                FieldSource::Payload(PayloadEncoding::Base64),
            )],
            items_path: None,
            item_fields: vec![],
        },
        response: RespSpec {
            kind: RespKind::Json,
            data_path: Some("/ciphertext".to_string()),
            encoding: PayloadEncoding::Base64,
            items_path: None,
            item_index_path: None,
        },
    }
}

fn spec(url: &str) -> HttpProviderSpec {
    HttpProviderSpec {
        base_url: url.to_string(),
        encrypt: json_op("/encrypt"),
        decrypt: json_op("/decrypt"),
        capabilities: caps(),
        timeout: Duration::from_secs(5),
        max_response_bytes: 1 << 20,
        tls: Some(TlsSpec {
            ca_pem: None,
            identity_pem: Some(b"-----BEGIN PRIVATE KEY-----SECRET-PEM".to_vec()),
        }),
    }
}

fn pt(i: u64) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: i,
        data: SecretBuffer::from_slice(&[0x5A; UNIT]),
    }
}

fn redirect_to(target: String, status: u16) -> Handler {
    Arc::new(move |_req: &RecordedRequest| {
        let mut spec = ResponseSpec::status(status);
        spec.headers.push(("location".to_string(), target.clone()));
        spec
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirects_are_never_followed() {
    for status in [301u16, 302, 303, 307, 308] {
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let target = TestServer::start(Arc::new(move |_req: &RecordedRequest| {
            counter.fetch_add(1, Ordering::SeqCst);
            ResponseSpec::json(&serde_json::json!({ "ciphertext": "AAAA" }))
        }))
        .await;
        let redirecting =
            TestServer::start(redirect_to(format!("{}/encrypt", target.url()), status)).await;
        // TLS material is not needed for a loopback plaintext test server.
        let mut spec = spec(&redirecting.url());
        spec.tls = None;
        let provider = HttpCryptoProvider::new(spec).unwrap();

        let err = provider
            .encrypt_batch(&ctx(), &[pt(1)])
            .await
            .expect_err("a redirect must fail the request");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "HTTP {status}: the request (plaintext!) was re-sent to the redirect target"
        );
        assert_eq!(
            redirecting.requests.lock().len(),
            1,
            "HTTP {status}: a redirect must not be retried against the same endpoint"
        );
        assert!(
            matches!(err, CryptoError::EndpointFatal(_)),
            "HTTP {status}: a redirect is an endpoint fault, got {err}"
        );
    }
}

#[test]
fn spec_debug_output_redacts_credentials() {
    let text = format!("{:?}", spec("https://crypto.internal"));
    for secret in ["SECRET-TOKEN", "SECRET-QUERY", "SECRET-PEM"] {
        assert!(!text.contains(secret), "{secret} leaked: {text}");
    }
    assert!(
        text.contains("authorization"),
        "header names stay visible: {text}"
    );
}

fn assert_transport_error_is_redacted(error: &CryptoError) {
    assert!(matches!(error, CryptoError::Retryable(_)));
    for rendered in [error.to_string(), format!("{error:?}")] {
        for secret in ["SECRET-TOKEN", "SECRET-QUERY"] {
            assert!(
                !rendered.contains(secret),
                "transport error must not expose credential values"
            );
        }
        assert!(
            !rendered.contains("http://"),
            "transport errors must not retain request URLs"
        );
    }
}

#[tokio::test]
async fn connection_errors_do_not_expose_query_credentials() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        // End the connection without an HTTP response, while keeping the
        // listener bound until this request arrives (no port-reuse race).
        drop(stream);
    });
    let mut config = spec(&format!("http://{address}"));
    config.tls = None;
    let provider = HttpCryptoProvider::new(config).unwrap();
    let error = provider.encrypt_batch(&ctx(), &[pt(0)]).await.unwrap_err();
    server.await.unwrap();
    assert_transport_error_is_redacted(&error);
}

#[tokio::test(start_paused = true)]
async fn timeouts_do_not_expose_query_credentials() {
    let server = TestServer::start(Arc::new(|_| {
        let mut response = ResponseSpec::raw(vec![0; UNIT]);
        response.delay = Duration::from_secs(3600);
        response
    }))
    .await;
    let mut config = spec(&server.url());
    config.tls = None;
    config.timeout = Duration::from_secs(1);
    let provider = HttpCryptoProvider::new(config).unwrap();
    let error = provider.encrypt_batch(&ctx(), &[pt(0)]).await.unwrap_err();
    assert!(error.to_string().contains("timeout"));
    assert_transport_error_is_redacted(&error);
}

#[tokio::test]
async fn response_body_errors_do_not_expose_query_credentials() {
    let server = TestServer::start(Arc::new(|_| {
        let mut response = ResponseSpec::raw(vec![0; UNIT]);
        response.drop_after = Some(1);
        response
    }))
    .await;
    let mut config = spec(&server.url());
    config.tls = None;
    let provider = HttpCryptoProvider::new(config).unwrap();
    let ciphertext = maki_crypto::CiphertextUnit {
        unit_index: 0,
        data: vec![0; UNIT],
    };
    let error = provider
        .decrypt_batch(&ctx(), &[ciphertext])
        .await
        .unwrap_err();
    assert_transport_error_is_redacted(&error);
}
