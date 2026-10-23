//! BUG-165: invalid endpoint ports must fail before provider I/O.
mod common;

use std::{sync::Arc, time::Duration};

use common::{ResponseSpec, TestServer};
use maki_crypto::{CryptoContext, CryptoError, CryptoProvider, PlaintextUnit, SecretBuffer};
use maki_crypto_http::{
    BodySpec, HttpCryptoProvider, HttpProviderSpec, OpSpec, PayloadEncoding, RespKind, RespSpec,
};
use maki_crypto_local::keysource::MapKeySource;
use maki_format::config::{parse_config, VolumeConfig};

fn config(url: &str) -> Result<VolumeConfig, maki_format::config::ConfigError> {
    let configuration = parse_config(&format!(
        r#"
config_schema_version = 1
[volume]
name = "audit-endpoint-port"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "audit-endpoint-port-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4096
[crypto.http]
timeout = "1s"
max_response_bytes = "4KiB"
[[crypto.http.endpoint]]
name = "audit"
url = "{url}"
[crypto.http.encrypt]
path = "/encrypt"
[crypto.http.decrypt]
path = "/decrypt"
[backing]
root = "/unused-audit-endpoint-port"
"#
    ))?;
    configuration.validate()?;
    Ok(configuration)
}

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x20261024),
        format_version: 1,
        crypto_compatibility_id: "audit-endpoint-port-v1".into(),
    }
}

fn plaintext() -> [PlaintextUnit; 1] {
    [PlaintextUnit {
        unit_index: 7,
        data: SecretBuffer::from_slice(&[0x27; 4096]),
    }]
}

#[tokio::test]
async fn valid_port_preserves_path_and_query_over_real_http() {
    let server = TestServer::start(Arc::new(|request| {
        ResponseSpec::raw(request.body.iter().map(|byte| byte ^ 0x5a).collect())
    }))
    .await;
    let url = format!("{}/v1?profile=port-test", server.url());
    let configuration = config(&url).unwrap();
    let provider =
        HttpCryptoProvider::from_config(&configuration, &url, &MapKeySource::new()).unwrap();
    let plaintext = plaintext();
    let ciphertext = provider
        .encrypt_batch(&context(), &plaintext)
        .await
        .unwrap();
    let recovered = provider
        .decrypt_batch(&context(), &ciphertext)
        .await
        .unwrap();
    assert_eq!(recovered[0].data.expose(), plaintext[0].data.expose());
    let requests = server.requests.lock();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].path, "/v1/encrypt");
    assert_eq!(requests[1].path, "/v1/decrypt");
    for request in requests.iter() {
        assert_eq!(request.query.get("profile").unwrap(), "port-test");
    }
}

#[test]
fn invalid_ports_must_be_rejected_by_config_preflight() {
    let accepted: Vec<_> = ["http://127.0.0.1:65536", "http://127.0.0.1:not-a-port"]
        .into_iter()
        .filter(|url| config(url).is_ok())
        .collect();
    assert!(
        accepted.is_empty(),
        "preflight accepted invalid URLs: {accepted:?}"
    );
}

#[test]
fn config_constructor_rejects_invalid_endpoint_override_before_io() {
    let configuration = config("http://127.0.0.1:7000").unwrap();
    for url in [
        "http://127.0.0.1:65536",
        "http://127.0.0.1:not-a-port",
        "http://[::1]:65536",
        "http://[::1]:not-a-port",
    ] {
        let error = HttpCryptoProvider::from_config(&configuration, url, &MapKeySource::new())
            .expect_err("invalid endpoint override must fail construction");
        assert!(
            matches!(error, CryptoError::ProviderFatal(ref text) if text == "invalid HTTP endpoint URL"),
            "expected local URL parsing failure, got {error:?}"
        );
    }
}

#[tokio::test]
async fn direct_constructor_rejects_invalid_ports_before_io() {
    let configuration = config("http://127.0.0.1:7000").unwrap();
    let capabilities = HttpCryptoProvider::from_config(
        &configuration,
        "http://127.0.0.1:7000",
        &MapKeySource::new(),
    )
    .unwrap()
    .capabilities()
    .await
    .unwrap();
    let operation = OpSpec {
        method: "POST".into(),
        path: "/crypt".into(),
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
    for (url, valid) in [
        ("http://127.0.0.1", true),
        ("http://127.0.0.1:", true),
        ("http://127.0.0.1:0", true),
        ("https://crypto.example:65535/v1?profile=1", true),
        ("http://[::1]", true),
        ("http://[::1]:8080/v1?profile=1", true),
        ("http://127.0.0.1:65536", false),
        ("http://127.0.0.1:not-a-port", false),
        ("http://[::1]:65536", false),
        ("http://[::1]:not-a-port", false),
    ] {
        let result = HttpCryptoProvider::new(HttpProviderSpec {
            base_url: url.into(),
            encrypt: operation.clone(),
            decrypt: operation.clone(),
            capabilities: capabilities.clone(),
            timeout: Duration::from_secs(1),
            max_response_bytes: 4096,
            tls: None,
        });
        if valid {
            result.unwrap_or_else(|error| panic!("{url}: {error}"));
        } else {
            let error = result.expect_err("invalid port must fail construction");
            assert!(
                matches!(error, CryptoError::ProviderFatal(ref text) if text == "invalid HTTP endpoint URL"),
                "{url}: {error:?}"
            );
        }
    }
}
