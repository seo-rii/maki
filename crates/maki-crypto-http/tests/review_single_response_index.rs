//! A configured JSON response echo is a contract for both HTTP operations.
use base64::Engine as _;
use maki_crypto::checked::CheckedProvider;
use maki_crypto::{
    CiphertextUnit, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit, SecretBuffer,
};
use maki_crypto_http::HttpCryptoProvider;
use maki_crypto_local::keysource::MapKeySource;
use maki_format::config::{parse_config, VolumeConfig};
use maki_test_support::http_chaos::{ResponseSpec, TestServer};
use serde_json::{json, Value};
use std::sync::Arc;

#[derive(Clone, Copy, Debug)]
enum Layout {
    Single,
    Batch,
    Raw,
}

fn config(url: &str, layout: Layout, check_index: bool) -> VolumeConfig {
    let mut operations = String::new();
    for operation in ["encrypt", "decrypt"] {
        let index = if check_index {
            r#"item_index_path = "/unit""#
        } else {
            ""
        };
        operations += &format!("[crypto.http.{operation}]\npath = \"/{operation}\"\n");
        if matches!(layout, Layout::Raw) {
            operations += &format!("[crypto.http.{operation}.response]\ntype = \"raw\"\n{index}\n");
            continue;
        }
        let (fields, items) = if matches!(layout, Layout::Batch) {
            ("item_fields", r#"items_path = "/items""#)
        } else {
            ("fields", "")
        };
        operations += &format!(
            r#"
[crypto.http.{operation}.body]
{items}
[crypto.http.{operation}.body.{fields}]
"/data" = {{ source = "payload", encoding = "base64" }}
"/unit" = {{ source = "unit_index" }}
[crypto.http.{operation}.response]
{items}
{index}
data_path = "/data"
encoding = "base64"
"#
        );
    }
    parse_config(&format!(
        r#"
config_schema_version = 1
[volume]
name = "response-index"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "response-index-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4096
[[crypto.http.endpoint]]
name = "loopback"
url = "{url}"
{operations}
[backing]
root = "/unused"
"#
    ))
    .unwrap()
}

async fn run(
    encrypt: bool,
    layout: Layout,
    check_index: bool,
    requested: u64,
    echoed: Option<Value>,
) -> Result<Vec<(u64, Vec<u8>)>, CryptoError> {
    let server = TestServer::start(Arc::new(move |_| {
        if matches!(layout, Layout::Raw) {
            return ResponseSpec::raw(vec![0x5a; 4096]);
        }
        let mut value =
            json!({"data": base64::engine::general_purpose::STANDARD.encode(vec![0x5a; 4096])});
        if let Some(unit) = &echoed {
            value["unit"] = unit.clone();
        }
        ResponseSpec::json(&if matches!(layout, Layout::Batch) {
            json!({"items": [value]})
        } else {
            value
        })
    }))
    .await;
    let config = config(&server.url(), layout, check_index);
    config.validate().unwrap();
    let provider = CheckedProvider::new(Arc::new(
        HttpCryptoProvider::from_config(&config, &server.url(), &MapKeySource::new()).unwrap(),
    ));
    let context = CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(7),
        format_version: 1,
        crypto_compatibility_id: "response-index-v1".into(),
    };
    if encrypt {
        provider
            .encrypt_batch(
                &context,
                &[PlaintextUnit {
                    unit_index: requested,
                    data: SecretBuffer::from_slice(&[0x33; 4096]),
                }],
            )
            .await
            .map(|items| {
                items
                    .into_iter()
                    .map(|item| (item.unit_index, item.data))
                    .collect()
            })
    } else {
        provider
            .decrypt_batch(
                &context,
                &[CiphertextUnit {
                    unit_index: requested,
                    data: vec![0x33; 4096],
                }],
            )
            .await
            .map(|items| {
                items
                    .into_iter()
                    .map(|item| (item.unit_index, item.data.into_vec()))
                    .collect()
            })
    }
}

#[tokio::test]
async fn review_single_json_rejects_missing_or_foreign_index() {
    for encrypt in [true, false] {
        for echoed in [None, Some(json!(8))] {
            let result = run(encrypt, Layout::Single, true, 7, echoed.clone()).await;
            assert!(
                matches!(result, Err(CryptoError::Contract(_))),
                "encrypt={encrypt}, echo={echoed:?}: {result:?}"
            );
        }
    }
}

#[tokio::test]
async fn review_single_json_requires_an_unsigned_integer_index() {
    for encrypt in [true, false] {
        for echoed in [
            json!("7"),
            json!(7.0),
            json!(-1),
            Value::Null,
            json!(true),
            json!([7]),
        ] {
            let result = run(encrypt, Layout::Single, true, 7, Some(echoed.clone())).await;
            assert!(
                matches!(result, Err(CryptoError::Contract(_))),
                "encrypt={encrypt}, echo={echoed:?}: {result:?}"
            );
        }
    }
}

#[tokio::test]
async fn review_single_json_accepts_the_requested_index_and_payload() {
    for encrypt in [true, false] {
        for requested in [0, 7, u64::MAX] {
            let result = run(
                encrypt,
                Layout::Single,
                true,
                requested,
                Some(json!(requested)),
            )
            .await
            .unwrap();
            assert_eq!(result, vec![(requested, vec![0x5a; 4096])]);
        }
    }
}

#[tokio::test]
async fn review_single_json_echo_mapping_remains_optional() {
    for encrypt in [true, false] {
        for echoed in [None, Some(json!(8)), Some(json!("7"))] {
            let result = run(encrypt, Layout::Single, false, 7, echoed)
                .await
                .unwrap();
            assert_eq!(result, vec![(7, vec![0x5a; 4096])]);
        }
    }
}

#[tokio::test]
async fn review_batch_echo_contract_is_preserved() {
    for encrypt in [true, false] {
        for echoed in [None, Some(json!(8)), Some(json!("7"))] {
            let result = run(encrypt, Layout::Batch, true, 7, echoed).await;
            assert!(
                matches!(result, Err(CryptoError::Contract(_))),
                "{result:?}"
            );
        }
        assert_eq!(
            run(encrypt, Layout::Batch, true, 7, Some(json!(7)))
                .await
                .unwrap(),
            vec![(7, vec![0x5a; 4096])]
        );
    }
}

#[tokio::test]
async fn review_raw_response_preserves_bytes_without_an_echo() {
    for encrypt in [true, false] {
        for check_index in [true, false] {
            assert_eq!(
                run(encrypt, Layout::Raw, check_index, 7, None)
                    .await
                    .unwrap(),
                vec![(7, vec![0x5a; 4096])]
            );
        }
    }
}
