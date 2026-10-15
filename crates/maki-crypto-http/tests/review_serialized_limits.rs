//! Exercise accepted configuration limits with actual HTTP responses and the
//! runtime's selected decoder, not a second copy of the size arithmetic.
mod common;

use std::sync::Arc;

use base64::Engine as _;
use common::{ResponseSpec, TestServer};
use maki_crypto::{CryptoContext, CryptoProvider, PlaintextUnit, SecretBuffer};
use maki_crypto_http::{HttpCryptoProvider, PayloadEncoding};
use maki_crypto_local::keysource::MapKeySource;
use maki_format::config::{parse_config, ByteSize, VolumeConfig};
use serde_json::json;

fn config(url: &str, encoding: &str, cipher_len: usize, batch: bool) -> VolumeConfig {
    let mut ops = String::new();
    for op in ["encrypt", "decrypt"] {
        let batch_body = if batch { "items_path = \"/items\"" } else { "" };
        let fields = if batch { "item_fields" } else { "fields" };
        let batch_response = if batch {
            "items_path = \"/result/items\"\nitem_index_path = \"/u~1nit\""
        } else {
            ""
        };
        ops += &format!(
            r#"
[crypto.http.{op}]
path = "/{op}"
[crypto.http.{op}.body]
{batch_body}
[crypto.http.{op}.body.{fields}]
"/data" = {{ source = "payload", encoding = "base64" }}
"/unit" = {{ source = "unit_index" }}
[crypto.http.{op}.response]
{batch_response}
data_path = '/d~0ata"'
encoding = "{encoding}"
"#
        );
    }
    parse_config(&format!(
        r#"
config_schema_version = 1
[volume]
name = "transport-boundary"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "http-boundary"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = {cipher_len}
[crypto.batch]
max_items = 128
max_bytes = "512KiB"
[crypto.http]
[[crypto.http.endpoint]]
name = "test"
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
        volume_uuid: uuid::Uuid::from_u128(0xAB),
        format_version: 1,
        crypto_compatibility_id: "http-boundary".into(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validated_full_batches_roundtrip_at_serialized_http_boundary() {
    for encoding in ["base64", "base64url", "hex", "hex-lower", "hex-upper"] {
        for cipher_len in [4383, 4384, 4385] {
            let codec = PayloadEncoding::parse(encoding).unwrap();
            let handler = Arc::new(move |request: &common::RecordedRequest| {
                let request_json: serde_json::Value =
                    serde_json::from_slice(&request.body).unwrap();
                let items: Vec<_> = request_json["items"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|item| {
                        let mut data = base64::engine::general_purpose::STANDARD
                            .decode(item["data"].as_str().unwrap())
                            .unwrap();
                        data.iter_mut().for_each(|byte| *byte ^= 0x5A);
                        if request.path == "/encrypt" {
                            assert_eq!(data.len(), 4096);
                            data.resize(cipher_len, 0);
                        } else {
                            assert_eq!(data.len(), cipher_len);
                            data.truncate(4096);
                        }
                        json!({"u/nit": item["unit"], "d~ata\"": codec.encode(&data)})
                    })
                    .collect();
                ResponseSpec::json(&json!({"result":{"items":items}}))
            });
            let server = TestServer::start(handler).await;
            let mut cfg = config(&server.url(), encoding, cipher_len, true);
            let largest_response = json!({"result":{"items":(0..128).map(|i| json!({
                "u/nit":u64::MAX-i,
                "d~ata\"":codec.encode(&vec![0xAB;cipher_len]),
            })).collect::<Vec<_>>()}});
            let boundary = serde_json::to_vec(&largest_response).unwrap().len();
            cfg.crypto.http.as_mut().unwrap().max_response_bytes =
                Some(ByteSize(boundary as u64 - 1));
            assert!(cfg
                .validate()
                .unwrap_err()
                .to_string()
                .contains("max_response_bytes"));
            for limit in [boundary, boundary + 1] {
                cfg.crypto.http.as_mut().unwrap().max_response_bytes = Some(ByteSize(limit as u64));
                cfg.validate().unwrap();
                let p = HttpCryptoProvider::from_config(&cfg, &server.url(), &MapKeySource::new())
                    .unwrap();
                let plaintext: Vec<_> = (0..128)
                    .map(|i| PlaintextUnit {
                        unit_index: u64::MAX - i,
                        data: SecretBuffer::from_slice(&vec![i as u8; 4096]),
                    })
                    .collect();
                let encrypted = p.encrypt_batch(&context(), &plaintext).await.unwrap();
                assert!(encrypted.iter().all(|item| item.data.len() == cipher_len));
                let decrypted = p.decrypt_batch(&context(), &encrypted).await.unwrap();
                for (expected, actual) in plaintext.iter().zip(&decrypted) {
                    assert_eq!(expected.data.expose(), actual.data.expose());
                }
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_json_and_raw_responses_are_also_bounded() {
    for raw in [false, true] {
        let server = TestServer::start(Arc::new(move |request| {
            let size = if request.path == "/encrypt" {
                4384
            } else {
                4096
            };
            if raw {
                ResponseSpec::raw(vec![0xAB; size])
            } else {
                ResponseSpec::json(
                    &json!({"d~ata\"":PayloadEncoding::HexUpper.encode(&vec![0xAB;size])}),
                )
            }
        }))
        .await;
        let mut cfg = config(&server.url(), "hex-upper", 4384, false);
        if raw {
            let http = cfg.crypto.http.as_mut().unwrap();
            for op in [&mut http.encrypt, &mut http.decrypt] {
                op.as_mut().unwrap().response = None;
            }
        }
        let boundary = if raw {
            4384
        } else {
            serde_json::to_vec(
                &json!({"d~ata\"":PayloadEncoding::HexUpper.encode(&vec![0xAB;4384])}),
            )
            .unwrap()
            .len()
        };
        cfg.crypto.http.as_mut().unwrap().max_response_bytes = Some(ByteSize(boundary as u64 - 1));
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("max_response_bytes"));
        cfg.crypto.http.as_mut().unwrap().max_response_bytes = Some(ByteSize(boundary as u64));
        cfg.validate().unwrap();
        let p = HttpCryptoProvider::from_config(&cfg, &server.url(), &MapKeySource::new()).unwrap();
        let plaintext = [PlaintextUnit {
            unit_index: 1,
            data: SecretBuffer::from_slice(&vec![0xAB; 4096]),
        }];
        let encrypted = p.encrypt_batch(&context(), &plaintext).await.unwrap();
        assert_eq!(encrypted[0].data.len(), 4384);
        let decrypted = p.decrypt_batch(&context(), &encrypted).await.unwrap();
        assert_eq!(decrypted[0].data.expose(), plaintext[0].data.expose());
    }
}
