//! Audit: R3-006 (config) / BUG-093 require every context field "on the
//! wire" when `context_binding` is declared, but the check counts mapping
//! *sources*, not what the serialized request contains. Request pointers are
//! applied in order and a later pointer (or the batch `items_path`) silently
//! replaces an earlier scalar, and the unit index — which the attach
//! self-test also probes — is not required at all.

use base64::Engine as _;
use maki_crypto::selftest::provider_self_test;
use maki_crypto::{CryptoContext, CryptoProvider, PlaintextUnit, SecretBuffer};
use maki_crypto_http::HttpCryptoProvider;
use maki_crypto_local::keysource::MapKeySource;
use maki_format::config::{parse_config, VolumeConfig};
use maki_test_support::http_chaos::{ResponseSpec, TestServer};
use serde_json::{json, Value};
use std::sync::Arc;

const UUID: u128 = 0x1234_5678_9abc_def0_1122_3344_5566_7788;

fn config(url: &str, body: &str) -> VolumeConfig {
    let mut ops = String::new();
    for op in ["encrypt", "decrypt"] {
        ops += &format!(
            "[crypto.http.{op}]\npath = \"/{op}\"\n{}\n[crypto.http.{op}.response]\n\
             type = \"json\"\ndata_path = \"/data\"\nencoding = \"base64\"\n",
            body.replace("{op}", op)
        );
    }
    parse_config(&format!(
        r#"
config_schema_version = 1
[volume]
name = "audit-context"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "audit-context-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4096
context_binding = "contractual"
[[crypto.http.endpoint]]
name = "loopback"
url = "{url}"
{ops}
[backing]
root = "/unused"
"#
    ))
    .unwrap()
}

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(UUID),
        format_version: 3,
        crypto_compatibility_id: "audit-context-v1".into(),
    }
}

/// XOR "cipher" keyed by whatever context the request actually carries.
fn keyed_handler() -> maki_test_support::http_chaos::Handler {
    Arc::new(|request| {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let mut key = 0x5bu8;
        for v in [
            &body["volume"],
            &body["profile"],
            &body["format"],
            &body["unit"],
        ] {
            for b in v.to_string().bytes() {
                key = key.wrapping_mul(31).wrapping_add(b);
            }
        }
        let data = base64::engine::general_purpose::STANDARD
            .decode(body["data"].as_str().unwrap_or(""))
            .unwrap();
        let out: Vec<u8> = data
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key ^ (i as u8) ^ 0xa5)
            .collect();
        ResponseSpec::json(
            &json!({"data": base64::engine::general_purpose::STANDARD.encode(out)}),
        )
    })
}

async fn first_request_body(config: &VolumeConfig, server: &TestServer) -> String {
    let provider =
        HttpCryptoProvider::from_config(config, &server.url(), &MapKeySource::new()).unwrap();
    let _ = provider
        .encrypt_batch(
            &context(),
            &[PlaintextUnit {
                unit_index: 5,
                data: SecretBuffer::from_slice(&[7u8; 4096]),
            }],
        )
        .await;
    String::from_utf8(server.requests.lock()[0].body.clone()).unwrap()
}

#[tokio::test]
async fn colliding_pointer_drops_a_counted_context_field() {
    let server = TestServer::start(keyed_handler()).await;
    let body = r#"
[crypto.http.{op}.body]
type = "json"
[crypto.http.{op}.body.fields]
"/data" = { source = "payload", encoding = "base64" }
"/volume" = { source = "volume_id" }
"/volume/profile" = { source = "compatibility_id" }
"/format" = { source = "format_version" }
"/unit" = { source = "unit_index" }
"#;
    let config = config(&server.url(), body);
    config
        .validate()
        .expect("validation counts volume_id as sent");
    let wire = first_request_body(&config, &server).await;
    let uuid = uuid::Uuid::from_u128(UUID).to_string();
    assert!(
        wire.contains(&uuid),
        "AUDIT: validated context_binding config never sends the volume UUID: {}",
        &wire[..wire.find("\"data\"").unwrap_or(0).min(wire.len())]
    );
}

#[tokio::test]
async fn batch_items_path_drops_a_counted_context_field() {
    let server = TestServer::start(Arc::new(|_| ResponseSpec::status(500))).await;
    let body = r#"
[crypto.http.{op}.body]
type = "json"
items_path = "/items"
[crypto.http.{op}.body.fields]
"/items" = { source = "volume_id" }
"/profile" = { source = "compatibility_id" }
"/format" = { source = "format_version" }
[crypto.http.{op}.body.item_fields]
"/data" = { source = "payload", encoding = "base64" }
"/unit" = { source = "unit_index" }
"#;
    let mut config = config(&server.url(), body);
    for op in [
        config.crypto.http.as_mut().unwrap().encrypt.as_mut().unwrap(),
    ] {
        let r = op.response.as_mut().unwrap();
        r.items_path = Some("/items".into());
        r.item_index_path = Some("/unit".into());
    }
    {
        let op = config.crypto.http.as_mut().unwrap().decrypt.as_mut().unwrap();
        let r = op.response.as_mut().unwrap();
        r.items_path = Some("/items".into());
        r.item_index_path = Some("/unit".into());
    }
    config
        .validate()
        .expect("validation counts volume_id as sent");
    let wire = first_request_body(&config, &server).await;
    let uuid = uuid::Uuid::from_u128(UUID).to_string();
    assert!(
        wire.contains(&uuid),
        "AUDIT: validated batch config never sends the volume UUID; body starts {}",
        &wire[..wire.len().min(60)]
    );
}

#[tokio::test]
async fn missing_unit_index_validates_but_attach_self_test_fails_late() {
    let server = TestServer::start(keyed_handler()).await;
    let body = r#"
[crypto.http.{op}.body]
type = "json"
[crypto.http.{op}.body.fields]
"/data" = { source = "payload", encoding = "base64" }
"/volume" = { source = "volume_id" }
"/profile" = { source = "compatibility_id" }
"/format" = { source = "format_version" }
"#;
    let config = config(&server.url(), body);
    config
        .validate()
        .expect("unit_index is not required with context_binding");
    let provider =
        HttpCryptoProvider::from_config(&config, &server.url(), &MapKeySource::new()).unwrap();
    let result = provider_self_test(&provider, &context(), 4096, "audit-context-v1").await;
    assert!(
        result.is_ok(),
        "AUDIT: config validated, but attach self-test refuses it late: {result:?}"
    );
}

#[tokio::test]
async fn control_full_context_passes_self_test() {
    let server = TestServer::start(keyed_handler()).await;
    let body = r#"
[crypto.http.{op}.body]
type = "json"
[crypto.http.{op}.body.fields]
"/data" = { source = "payload", encoding = "base64" }
"/volume" = { source = "volume_id" }
"/profile" = { source = "compatibility_id" }
"/format" = { source = "format_version" }
"/unit" = { source = "unit_index" }
"#;
    let config = config(&server.url(), body);
    config.validate().unwrap();
    let provider =
        HttpCryptoProvider::from_config(&config, &server.url(), &MapKeySource::new()).unwrap();
    provider_self_test(&provider, &context(), 4096, "audit-context-v1")
        .await
        .unwrap();
}
