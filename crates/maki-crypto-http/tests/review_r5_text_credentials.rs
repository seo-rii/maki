//! R5-035: a header credential is text. One generated as hex
//! (`openssl rand -hex 32`) went through the key loader's hex decoding and
//! reached the header builder as raw bytes; it must be sent exactly as
//! stored.

#![cfg(unix)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use common::{RecordedRequest, ResponseSpec, TestServer};
use maki_crypto::{CryptoContext, CryptoProvider, PlaintextUnit, SecretBuffer};
use maki_crypto_http::HttpCryptoProvider;
use maki_crypto_local::keysource::FileKeySource;
use maki_format::config::parse_config;

const HEX_TOKEN: &str = "6b1d0f4c9e2a7d3b8c5f1e0a9d4c7b2e6f3a8d1c5e9b0f7a2d6c4e8b1f3a5d7c";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hex_bearer_token_is_sent_verbatim() {
    let server = TestServer::start(Arc::new(|_request: &RecordedRequest| {
        ResponseSpec::status(500)
    }))
    .await;
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("crypto-token");
    std::fs::write(&token, format!("{HEX_TOKEN}\n")).unwrap();
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o400)).unwrap();
    let config = parse_config(
        &include_str!("../../../packaging/examples/postgres-prod.toml").replace("\r\n", "\n"),
    )
    .unwrap();
    config.validate().unwrap();

    let provider =
        HttpCryptoProvider::from_config(&config, &server.url(), &FileKeySource::new(dir.path()))
            .expect("a hex token is a valid header credential");
    let context = CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x35),
        format_version: 1,
        crypto_compatibility_id: "vendor-profile-prod-v1".to_string(),
    };
    let _ = provider
        .encrypt_batch(
            &context,
            &[PlaintextUnit {
                unit_index: 0,
                data: SecretBuffer::from_slice(&[0u8; 4096]),
            }],
        )
        .await;

    let requests = server.requests.lock().clone();
    assert!(!requests.is_empty(), "no request reached the endpoint");
    for request in requests {
        assert_eq!(
            request.headers.get("authorization").map(String::as_str),
            Some(format!("Bearer {HEX_TOKEN}").as_str())
        );
    }
}
