//! R5-003: the HTTP provider must never route a request through a proxy
//! named in its environment. reqwest honours `HTTP_PROXY`/`ALL_PROXY` by
//! default, so a daemon inheriting `http_proxy` (from `/etc/environment`,
//! `sudo -E`, a unit drop-in) sent the plaintext of every encrypt request to
//! the proxy and accepted the proxy's answer as ciphertext.
//!
//! This binary holds a single test: it changes process-global environment.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{RecordedRequest, ResponseSpec, TestServer};
use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoProvider, PlaintextUnit,
    SecretBuffer,
};
use maki_crypto_http::{
    BodySpec, FieldSource, HttpCryptoProvider, HttpProviderSpec, OpSpec, PayloadEncoding, RespKind,
    RespSpec,
};

const UNIT: usize = 64;

fn op(path: &str) -> OpSpec {
    OpSpec {
        method: "POST".to_string(),
        path: path.to_string(),
        headers: vec![],
        query: vec![],
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn environment_proxies_are_never_used() {
    // The "proxy" answers every request with a well-formed ciphertext.
    let proxy = TestServer::start(Arc::new(|_request: &RecordedRequest| {
        ResponseSpec::json(&serde_json::json!({ "ciphertext": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi" }))
    }))
    .await;
    // The configured endpoint is a closed loopback port: only a proxied
    // request can succeed.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    for name in ["NO_PROXY", "no_proxy"] {
        std::env::remove_var(name);
    }
    for name in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
        std::env::set_var(name, proxy.url());
    }

    let provider = HttpCryptoProvider::new(HttpProviderSpec {
        base_url: endpoint,
        encrypt: op("/encrypt"),
        decrypt: op("/decrypt"),
        capabilities: CryptoCapabilities {
            provider_id: "remote-http-test".to_string(),
            crypto_compatibility_id: "vendor-profile-v1".to_string(),
            supported_plaintext_sizes: vec![UNIT as u32],
            max_ciphertext_size: UNIT as u32,
            stateless: true,
            retry_safe: true,
            batch: BatchCapability {
                supported: true,
                max_items: 8,
                max_bytes: 1 << 20,
            },
            integrity: Capability::Absent,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        },
        timeout: Duration::from_secs(5),
        max_response_bytes: 1 << 20,
        tls: None,
    })
    .unwrap();
    let result = provider
        .encrypt_batch(
            &CryptoContext {
                volume_uuid: uuid::Uuid::from_u128(5),
                format_version: 1,
                crypto_compatibility_id: "vendor-profile-v1".to_string(),
            },
            &[PlaintextUnit {
                unit_index: 0,
                data: SecretBuffer::from_slice(&[0x11; UNIT]),
            }],
        )
        .await;

    assert!(
        proxy.requests.lock().is_empty(),
        "the plaintext request was sent to an environment proxy"
    );
    assert!(
        result.is_err(),
        "a closed endpoint must fail, not be answered by a proxy"
    );
}
