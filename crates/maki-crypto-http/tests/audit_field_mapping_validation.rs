//! Audit: request field mappings are enumerated settings the runtime
//! consumes, but `VolumeConfig::validate` never checks `source` or the field
//! `encoding`. SPEC §18 lists `utf8`, `integer`, `uuid` as supported
//! encodings; the provider rejects them for payloads at construction time and
//! silently ignores any encoding (even garbage) on non-payload sources.

use maki_crypto::{CryptoContext, CryptoProvider, PlaintextUnit, SecretBuffer};
use maki_crypto_http::HttpCryptoProvider;
use maki_crypto_local::keysource::MapKeySource;
use maki_format::config::{parse_config, VolumeConfig};
use maki_test_support::http_chaos::{ResponseSpec, TestServer};
use std::sync::Arc;

fn config(url: &str, fields: &str) -> VolumeConfig {
    let mut ops = String::new();
    for op in ["encrypt", "decrypt"] {
        ops += &format!(
            "[crypto.http.{op}]\npath = \"/{op}\"\n[crypto.http.{op}.body]\ntype = \"json\"\n\
             [crypto.http.{op}.body.fields]\n{fields}\n[crypto.http.{op}.response]\n\
             type = \"json\"\ndata_path = \"/data\"\nencoding = \"base64\"\n"
        );
    }
    parse_config(&format!(
        r#"
config_schema_version = 1
[volume]
name = "audit-fields"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "audit-fields-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4096
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

#[test]
fn unknown_source_or_payload_encoding_validates_then_fails_construction() {
    let failures_all = std::sync::Mutex::new(Vec::<String>::new());
    for fields in [
        // A plausible typo of volume_id.
        "\"/data\" = { source = \"payload\" }\n\"/volume\" = { source = \"volume_uuid\" }",
        // SPEC 18 lists utf8 as a supported encoding.
        "\"/data\" = { source = \"payload\", encoding = \"utf8\" }",
        "\"/data\" = { source = \"payload\", encoding = \"base-64\" }",
    ] {
        let config = config("http://127.0.0.1:9", fields);
        let mut failures = Vec::new();
        let validated = config.validate();
        let built =
            HttpCryptoProvider::from_config(&config, "http://127.0.0.1:9", &MapKeySource::new());
        if !(validated.is_err() || built.is_ok()) {
            failures.push(format!("{fields:?} -> {:?}", built.err()));
        }
        failures_all.lock().unwrap().extend(failures);
    }
    let failures = failures_all.lock().unwrap();
    assert!(
        failures.is_empty(),
        "AUDIT: `validate()` accepts these mappings but provider construction refuses them: {failures:#?}"
    );
}

#[tokio::test]
async fn encoding_on_a_non_payload_source_is_silently_ignored() {
    let server = TestServer::start(Arc::new(|_| ResponseSpec::status(500))).await;
    let config = config(
        &server.url(),
        "\"/data\" = { source = \"payload\" }\n\"/unit\" = { source = \"unit_index\", encoding = \"utf8\" }",
    );
    config.validate().unwrap();
    let provider =
        HttpCryptoProvider::from_config(&config, &server.url(), &MapKeySource::new()).unwrap();
    let _ = provider
        .encrypt_batch(
            &CryptoContext {
                volume_uuid: uuid::Uuid::from_u128(1),
                format_version: 1,
                crypto_compatibility_id: "audit-fields-v1".into(),
            },
            &[PlaintextUnit {
                unit_index: 5,
                data: SecretBuffer::from_slice(&[0u8; 16]),
            }],
        )
        .await;
    let body: serde_json::Value =
        serde_json::from_slice(&server.requests.lock()[0].body).unwrap();
    assert_eq!(
        body["unit"],
        serde_json::json!("5"),
        "AUDIT: `encoding = \"utf8\"` on unit_index was accepted and ignored; sent {}",
        body["unit"]
    );
}

#[tokio::test]
async fn request_pointer_without_slash_validates_then_every_request_fails() {
    let config = config("http://127.0.0.1:9", "\"data\" = { source = \"payload\" }");
    config.validate().unwrap();
    let provider =
        HttpCryptoProvider::from_config(&config, "http://127.0.0.1:9", &MapKeySource::new())
            .unwrap();
    let result = provider
        .encrypt_batch(
            &CryptoContext {
                volume_uuid: uuid::Uuid::from_u128(1),
                format_version: 1,
                crypto_compatibility_id: "audit-fields-v1".into(),
            },
            &[PlaintextUnit {
                unit_index: 5,
                data: SecretBuffer::from_slice(&[0u8; 16]),
            }],
        )
        .await;
    assert!(
        !matches!(result, Err(maki_crypto::CryptoError::ProviderFatal(_))),
        "AUDIT: request pointer \"data\" passed validate() but every request fails: {:?}",
        result.err()
    );
}
