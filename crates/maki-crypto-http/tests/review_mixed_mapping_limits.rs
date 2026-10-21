//! Match response preflight to the batch capability used by the provider and
//! its attach self-test, including mixed batch/per-item operation mappings.
mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use base64::Engine as _;
use common::{ResponseSpec, TestServer};
use maki_crypto::{CryptoContext, CryptoProvider, PlaintextUnit, SecretBuffer};
use maki_crypto_http::HttpCryptoProvider;
use maki_crypto_local::keysource::MapKeySource;
use maki_format::config::{parse_config, ByteSize, VolumeConfig};
use serde_json::json;

fn config(url: &str, encrypt_batch: bool, decrypt_batch: bool) -> VolumeConfig {
    let mut operations = String::new();
    for (name, batch) in [("encrypt", encrypt_batch), ("decrypt", decrypt_batch)] {
        operations += &format!("\n[crypto.http.{name}]\npath = \"/{name}\"\n");
        if batch {
            operations += &format!(
                r#"
[crypto.http.{name}.body]
type = "json"
items_path = "/items"
[crypto.http.{name}.body.item_fields]
"/data" = {{ source = "payload", encoding = "base64" }}
"/unit" = {{ source = "unit_index" }}
[crypto.http.{name}.response]
type = "json"
items_path = "/items"
item_index_path = "/unit"
data_path = "/data"
encoding = "base64"
"#
            );
        }
    }
    // Parse with a permissive cap, then set the limit whose validation is
    // under test. parse_config itself validates before returning the config.
    let mut cfg = parse_config(&format!(
        r#"
config_schema_version = 1
[volume]
name = "mixed-mapping"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "mixed-mapping-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4096
[crypto.batch]
target_items = 1
target_bytes = "4KiB"
max_items = 16
max_bytes = "64KiB"
[crypto.http]
max_response_bytes = "1MiB"
timeout = "2s"
[[crypto.http.endpoint]]
name = "test"
url = "{url}"
{operations}
[backing]
root = "/unused-mixed-mapping"
"#
    ))
    .unwrap();
    cfg.crypto.http.as_mut().unwrap().max_response_bytes = Some(ByteSize(8192));
    cfg
}

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x184),
        format_version: 1,
        crypto_compatibility_id: "mixed-mapping-v1".into(),
    }
}

#[test]
fn two_per_item_operations_fit_a_singleton_response_cap() {
    let cfg = config("http://127.0.0.1:9", false, false);
    assert_eq!(cfg.effective_batch_max_items(), 1);
    cfg.validate().unwrap();
}

#[test]
fn two_batch_operations_still_require_a_full_batch_response_cap() {
    let cfg = config("http://127.0.0.1:9", true, true);
    assert_eq!(cfg.effective_batch_max_items(), 16);
    let error = cfg.validate().unwrap_err().to_string();
    assert!(error.contains("max_response_bytes"), "{error}");
}

#[test]
fn explicit_singleton_limit_accepts_both_mixed_mappings() {
    for (encrypt_batch, decrypt_batch) in [(true, false), (false, true)] {
        let mut cfg = config("http://127.0.0.1:9", encrypt_batch, decrypt_batch);
        cfg.crypto.batch.max_items = 1;
        assert_eq!(cfg.effective_batch_max_items(), 1);
        cfg.validate().unwrap();
    }
}

async fn mixed_mapping_roundtrip(encrypt_batch: bool, decrypt_batch: bool) {
    let response_max = Arc::new(AtomicUsize::new(0));
    let observed_response_max = response_max.clone();
    let server = TestServer::start(Arc::new(move |request| {
        let batch = if request.path == "/encrypt" {
            encrypt_batch
        } else {
            decrypt_batch
        };
        let response = if batch {
            let value: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let items = value["items"].as_array().unwrap();
            assert_eq!(
                items.len(),
                1,
                "the effective provider contract is one item"
            );
            let unit = items[0]["unit"].as_u64().unwrap();
            let mut payload = base64::engine::general_purpose::STANDARD
                .decode(items[0]["data"].as_str().unwrap())
                .unwrap();
            assert_eq!(payload.len(), 4096);
            payload.iter_mut().for_each(|byte| *byte ^= 0x5a);
            ResponseSpec::json(&json!({"items": [{
                "unit": unit,
                "data": base64::engine::general_purpose::STANDARD.encode(payload),
            }]}))
        } else {
            assert_eq!(request.body.len(), 4096);
            ResponseSpec::raw(request.body.iter().map(|byte| byte ^ 0x5a).collect())
        };
        observed_response_max.fetch_max(response.body.len(), Ordering::SeqCst);
        response
    }))
    .await;
    let cfg = config(&server.url(), encrypt_batch, decrypt_batch);
    assert_eq!(cfg.effective_batch_max_items(), 1);
    cfg.validate()
        .expect("mixed mappings must validate against the effective singleton contract");

    let provider =
        HttpCryptoProvider::from_config(&cfg, &server.url(), &MapKeySource::new()).unwrap();
    assert_eq!(provider.capabilities().await.unwrap().batch.max_items, 1);
    let plaintext = [PlaintextUnit {
        unit_index: u64::MAX,
        data: SecretBuffer::from_slice(&[0x31; 4096]),
    }];
    let ciphertext = provider
        .encrypt_batch(&context(), &plaintext)
        .await
        .unwrap();
    let recovered = provider
        .decrypt_batch(&context(), &ciphertext)
        .await
        .unwrap();
    assert_eq!(recovered[0].data.expose(), plaintext[0].data.expose());
    maki_crypto::selftest::provider_self_test(&provider, &context(), 4096, "mixed-mapping-v1")
        .await
        .unwrap();
    let requests = server.requests.lock();
    assert!(requests.iter().any(|r| r.path == "/encrypt"));
    assert!(requests.iter().any(|r| r.path == "/decrypt"));
    assert!(response_max.load(Ordering::SeqCst) <= 8192);
}

#[tokio::test]
async fn batch_encrypt_and_per_item_decrypt_validate_and_roundtrip() {
    mixed_mapping_roundtrip(true, false).await;
}

#[tokio::test]
async fn per_item_encrypt_and_batch_decrypt_validate_and_roundtrip() {
    mixed_mapping_roundtrip(false, true).await;
}
