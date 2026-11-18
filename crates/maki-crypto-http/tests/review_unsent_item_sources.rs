//! HTTP JSON body fields that never carry what they name are refused by
//! validation and provider construction alike, before any request:
//!
//! - top-level `fields` of a batch are evaluated once per request with no
//!   item, so a `payload`, `unit_index` or `batch_index` source there was
//!   sent as an empty payload or 0;
//! - `item_fields` of a per-item body (no `items_path`) were never sent.
mod common;

use std::sync::Arc;

use common::{Handler, RecordedRequest, ResponseSpec, TestServer};
use maki_crypto_http::HttpCryptoProvider;
use maki_crypto_local::keysource::MapKeySource;
use maki_format::config::{parse_config, VolumeConfig};

fn config(url: &str, body: &str) -> VolumeConfig {
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
name = "item-sources"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "item-sources-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4096
[crypto.http]
timeout = "5s"
[[crypto.http.endpoint]]
name = "loopback"
url = "{url}"
{ops}
[backing]
root = "/unused-item-sources"
"#
    ))
    .unwrap()
}

fn body(items_path: bool, fields: &str, item_fields: &str) -> String {
    format!(
        "[crypto.http.{{op}}.body]\ntype = \"json\"\n{}\
         [crypto.http.{{op}}.body.fields]\n{fields}\n[crypto.http.{{op}}.body.item_fields]\n{item_fields}",
        if items_path {
            "items_path = \"/items\"\n"
        } else {
            ""
        }
    )
}

fn echo_handler() -> Handler {
    Arc::new(|request: &RecordedRequest| ResponseSpec::raw(request.body.clone()))
}

#[tokio::test]
async fn fields_no_request_carries_are_refused_by_validation_and_construction() {
    let server = TestServer::start(echo_handler()).await;
    let payload = "\"/data\" = { source = \"payload\" }\n";
    let unit = "\"/unit\" = { source = \"unit_index\" }\n";
    let mut cases = Vec::new();
    for source in ["payload", "unit_index", "batch_index"] {
        cases.push((
            format!("top-level {source} in a batch"),
            body(
                true,
                &format!("\"/top\" = {{ source = {source:?} }}\n"),
                &format!("{payload}{unit}"),
            ),
        ));
    }
    cases.push((
        "item_fields of a per-item body".to_string(),
        body(
            false,
            &format!("{payload}{unit}"),
            "\"/ordinal\" = { source = \"batch_index\" }\n",
        ),
    ));
    for (case, body) in cases {
        let config = config(&server.url(), &body);
        assert!(config.validate().is_err(), "{case}: validated");
        assert!(
            HttpCryptoProvider::from_config(&config, &server.url(), &MapKeySource::new()).is_err(),
            "{case}: provider construction accepted it"
        );
    }
    assert!(
        server.requests.lock().is_empty(),
        "no request may be sent for such a mapping"
    );
}

#[test]
fn raw_response_ignores_json_encoding_and_http_headers_validate_before_attach() {
    let url = "http://127.0.0.1:7000";
    let payload = "\"/data\" = { source = \"payload\" }";
    let mut config = config(url, &body(false, payload, ""));
    let encrypt = config
        .crypto
        .http
        .as_mut()
        .unwrap()
        .encrypt
        .as_mut()
        .unwrap();
    let response = encrypt.response.as_mut().unwrap();
    response.response_type = "raw".into();
    response.encoding = Some("binary".into());
    config.validate().unwrap();
    HttpCryptoProvider::from_config(&config, url, &MapKeySource::new()).unwrap();
    config
        .crypto
        .http
        .as_mut()
        .unwrap()
        .encrypt
        .as_mut()
        .unwrap()
        .headers
        .insert(
            "x region".into(),
            maki_format::config::HeaderValue::Literal("west".into()),
        );
    assert!(config.validate().is_err());
    assert!(HttpCryptoProvider::from_config(&config, url, &MapKeySource::new()).is_err());
}
