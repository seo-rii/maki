//! A configuration whose HTTP field mappings validate is exactly one the
//! provider can build and send as written:
//!
//! - an unknown source or payload encoding validated, then provider
//!   construction (attach) refused it; an `encoding` on a non-payload
//!   source was silently dropped; a request pointer without a leading `/`
//!   validated, then failed every request;
//! - with a declared context binding, the configuration validated although
//!   overlapping request pointers dropped a context field from the wire, or
//!   no per-item unit index was mapped, and every attach self-test then
//!   failed late with "context-binding (...) decrypts to the original
//!   plaintext" (the late failure R3-006 meant to prevent).
//!
//! The fixture binds its XOR "cipher" to every non-payload byte the request
//! actually carries, so a context field that never reaches the wire is a
//! field the ciphertext is not bound to.
mod common;

use std::sync::Arc;

use base64::Engine as _;
use common::{Handler, RecordedRequest, ResponseSpec, TestServer};
use maki_crypto::selftest::provider_self_test;
use maki_crypto::{CryptoContext, CryptoProvider, PlaintextUnit, SecretBuffer};
use maki_crypto_http::HttpCryptoProvider;
use maki_crypto_local::keysource::MapKeySource;
use maki_format::config::{parse_config, VolumeConfig};
use serde_json::{json, Map, Value};

const PROFILE: &str = "field-mapping-v1";
const UUID: u128 = 0x1234_5678_9abc_def0_1122_3344_5566_7788;

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(UUID),
        format_version: 3,
        crypto_compatibility_id: PROFILE.into(),
    }
}

/// A complete configuration; `body` is used for both operations with
/// `{op}` replaced. A body with `items_path = "/items"` gets the batch
/// response mapping, any other the single-item one.
fn config(url: &str, context_binding: &str, body: &str) -> VolumeConfig {
    let response = if body.contains("items_path") {
        "items_path = \"/items\"\nitem_index_path = \"/unit\"\n"
    } else {
        ""
    };
    let mut ops = String::new();
    for op in ["encrypt", "decrypt"] {
        ops += &format!(
            "[crypto.http.{op}]\npath = \"/{op}\"\n{}\n[crypto.http.{op}.response]\n\
             type = \"json\"\ndata_path = \"/data\"\nencoding = \"base64\"\n{response}",
            body.replace("{op}", op)
        );
    }
    parse_config(&format!(
        r#"
config_schema_version = 1
[volume]
name = "field-mapping"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "{PROFILE}"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4096
context_binding = "{context_binding}"
[crypto.http]
timeout = "5s"
[[crypto.http.endpoint]]
name = "loopback"
url = "{url}"
{ops}
[backing]
root = "/unused-field-mapping"
"#
    ))
    .unwrap()
}

fn single(fields: &str) -> String {
    format!(
        "[crypto.http.{{op}}.body]\ntype = \"json\"\n[crypto.http.{{op}}.body.fields]\n{fields}"
    )
}

fn batch(fields: &str, item_fields: &str) -> String {
    format!(
        "[crypto.http.{{op}}.body]\ntype = \"json\"\nitems_path = \"/items\"\n\
         [crypto.http.{{op}}.body.fields]\n{fields}\n[crypto.http.{{op}}.body.item_fields]\n{item_fields}"
    )
}

fn build(config: &VolumeConfig, url: &str) -> Result<HttpCryptoProvider, maki_crypto::CryptoError> {
    HttpCryptoProvider::from_config(config, url, &MapKeySource::new())
}

fn mix(key: u8, bytes: &[u8]) -> u8 {
    bytes
        .iter()
        .fold(key, |key, b| key.wrapping_mul(31).wrapping_add(*b))
}

/// Everything in `object` except the payload, as the wire carries it.
fn metadata(object: &Map<String, Value>) -> Vec<u8> {
    let mut rest = object.clone();
    rest.remove("data");
    rest.remove("items");
    serde_json::to_vec(&rest).unwrap()
}

fn transform(key: u8, item: &Map<String, Value>) -> Value {
    let key = mix(key, &metadata(item));
    let data = base64::engine::general_purpose::STANDARD
        .decode(item.get("data").and_then(Value::as_str).unwrap_or(""))
        .unwrap_or_default();
    let out: Vec<u8> = data
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key ^ (i as u8) ^ 0xa5)
        .collect();
    let mut answer = json!({ "data": base64::engine::general_purpose::STANDARD.encode(out) });
    if let Some(unit) = item.get("unit") {
        answer["unit"] = unit.clone();
    }
    answer
}

/// An involutive XOR keyed by every non-payload field on the wire: the top
/// level, plus each batch element's own fields.
fn keyed_handler() -> Handler {
    Arc::new(|request: &RecordedRequest| {
        let Ok(Value::Object(body)) = serde_json::from_slice::<Value>(&request.body) else {
            return ResponseSpec::status(400);
        };
        let key = mix(0x5b, &metadata(&body));
        match body.get("items") {
            Some(Value::Array(items)) => {
                let items: Vec<Value> = items
                    .iter()
                    .map(|item| transform(key, item.as_object().unwrap_or(&Map::new())))
                    .collect();
                ResponseSpec::json(&json!({ "items": items }))
            }
            _ => ResponseSpec::json(&transform(key, &body)),
        }
    })
}

/// Context-bound mappings. The broken ones drop a context field from the
/// wire, or carry no per-item unit index.
fn context_bound_mappings() -> Vec<(&'static str, String)> {
    let payload = "\"/data\" = { source = \"payload\", encoding = \"base64\" }\n";
    let unit = "\"/unit\" = { source = \"unit_index\" }\n";
    let context = "\"/volume\" = { source = \"volume_id\" }\n\
                   \"/profile\" = { source = \"compatibility_id\" }\n\
                   \"/format\" = { source = \"format_version\" }\n";
    vec![
        (
            "per-item control",
            single(&format!("{payload}{unit}{context}")),
        ),
        (
            "nested per-item control",
            single(&format!(
                "{payload}{unit}\"/ctx/volume\" = {{ source = \"volume_id\" }}\n\
                 \"/ctx/profile\" = {{ source = \"compatibility_id\" }}\n\
                 \"/ctx/format\" = {{ source = \"format_version\" }}\n"
            )),
        ),
        ("batch control", batch(context, &format!("{payload}{unit}"))),
        (
            "batch control with per-item context",
            batch("", &format!("{payload}{unit}{context}")),
        ),
        (
            "volume_id replaced by a nested compatibility_id",
            single(&format!(
                "{payload}{unit}\"/volume\" = {{ source = \"volume_id\" }}\n\
                 \"/volume/profile\" = {{ source = \"compatibility_id\" }}\n\
                 \"/format\" = {{ source = \"format_version\" }}\n"
            )),
        ),
        (
            "volume_id replaced by the items array",
            batch(
                "\"/items\" = { source = \"volume_id\" }\n\
                 \"/profile\" = { source = \"compatibility_id\" }\n\
                 \"/format\" = { source = \"format_version\" }\n",
                &format!("{payload}{unit}"),
            ),
        ),
        ("no unit index", single(&format!("{payload}{context}"))),
    ]
}

/// R3-006: a declared context binding validates only when the attach
/// self-test can pass against a provider bound to what the wire carries.
#[tokio::test]
async fn a_validated_context_binding_mapping_passes_the_attach_self_test() {
    let server = TestServer::start(keyed_handler()).await;
    let mut failures = Vec::new();
    for (case, body) in context_bound_mappings() {
        let config = config(&server.url(), "contractual", &body);
        if config.validate().is_err() {
            // Refused before a volume exists: nothing reaches attach.
            assert!(!case.contains("control"), "{case} must validate");
            continue;
        }
        match build(&config, &server.url()) {
            Ok(provider) => {
                if let Err(error) = provider_self_test(&provider, &context(), 4096, PROFILE).await {
                    failures.push(format!("{case}: validated, then attach failed: {error}"));
                }
            }
            Err(error) => failures.push(format!(
                "{case}: validated, then construction failed: {error}"
            )),
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Mappings the provider cannot send as written: validation and provider
/// construction both refuse them, before any request.
#[tokio::test]
async fn unsendable_mappings_are_refused_by_validation_and_construction() {
    let server = TestServer::start(keyed_handler()).await;
    for (case, fields) in [
        (
            "unknown source",
            "\"/data\" = { source = \"payload\" }\n\"/volume\" = { source = \"volume_uuid\" }\n",
        ),
        (
            "unknown payload encoding",
            "\"/data\" = { source = \"payload\", encoding = \"utf8\" }\n",
        ),
        (
            "misspelled payload encoding",
            "\"/data\" = { source = \"payload\", encoding = \"base-64\" }\n",
        ),
        (
            "encoding on a non-payload source",
            "\"/data\" = { source = \"payload\" }\n\"/unit\" = { source = \"unit_index\", encoding = \"utf8\" }\n",
        ),
        (
            "pointer without a slash",
            "\"data\" = { source = \"payload\" }\n",
        ),
        (
            "overlapping pointers",
            "\"/data\" = { source = \"payload\" }\n\"/data/unit\" = { source = \"unit_index\" }\n",
        ),
    ] {
        let config = config(&server.url(), "none", &single(fields));
        assert!(config.validate().is_err(), "{case}: validated");
        assert!(
            build(&config, &server.url()).is_err(),
            "{case}: provider construction accepted it"
        );
    }
    assert!(
        server.requests.lock().is_empty(),
        "no request may be sent for an unsendable mapping"
    );
}

/// SPEC §18: only the payload is encoded. The other sources have one fixed
/// JSON representation each.
#[tokio::test]
async fn non_payload_sources_have_a_fixed_json_representation() {
    let server = TestServer::start(keyed_handler()).await;
    let config = config(
        &server.url(),
        "none",
        &single(
            "\"/data\" = { source = \"payload\", encoding = \"hex-upper\" }\n\
             \"/unit\" = { source = \"unit_index\" }\n\
             \"/volume\" = { source = \"volume_id\" }\n\
             \"/profile\" = { source = \"compatibility_id\" }\n\
             \"/format\" = { source = \"format_version\" }\n\
             \"/ordinal\" = { source = \"batch_index\" }\n",
        ),
    );
    config.validate().unwrap();
    let provider = build(&config, &server.url()).unwrap();
    let _ = provider
        .encrypt_batch(
            &context(),
            &[PlaintextUnit {
                unit_index: 5,
                data: SecretBuffer::from_slice(&[0xab; 4096]),
            }],
        )
        .await;
    let body: Value = serde_json::from_slice(&server.requests.lock()[0].body).unwrap();
    assert_eq!(body["unit"], json!(5));
    assert_eq!(
        body["volume"],
        json!("12345678-9abc-def0-1122-334455667788")
    );
    assert_eq!(body["profile"], json!(PROFILE));
    assert_eq!(body["format"], json!(3));
    assert_eq!(body["ordinal"], json!(0));
    assert_eq!(body["data"], json!("AB".repeat(4096)));
}
