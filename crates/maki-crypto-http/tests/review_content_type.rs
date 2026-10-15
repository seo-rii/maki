//! BUG-087: a JSON default must not append a second configured Content-Type.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use base64::Engine as _;
use maki_crypto::{CiphertextUnit, CryptoContext, CryptoProvider, PlaintextUnit, SecretBuffer};
use maki_crypto_http::HttpCryptoProvider;
use maki_crypto_local::keysource::MapKeySource;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Layout {
    Raw,
    Json,
    Batch,
}

fn operation(name: &str, layout: Layout, header: Option<(&str, &str)>) -> String {
    let mut text = format!("[crypto.http.{name}]\nmethod = \"POST\"\npath = \"/{name}\"\n");
    if let Some((key, value)) = header {
        text.push_str(&format!(
            "[crypto.http.{name}.headers]\n{key} = \"{value}\"\n"
        ));
    }
    if layout == Layout::Json {
        text.push_str(&format!(
            "[crypto.http.{name}.body]\ntype = \"json\"\n\
             [crypto.http.{name}.body.fields]\n\
             \"/data\" = {{ source = \"payload\", encoding = \"base64\" }}\n"
        ));
    } else if layout == Layout::Batch {
        text.push_str(&format!(
            "[crypto.http.{name}.body]\ntype = \"json\"\nitems_path = \"/items\"\n\
             [crypto.http.{name}.body.item_fields]\n\
             \"/data\" = {{ source = \"payload\", encoding = \"base64\" }}\n\
             \"/idx\" = {{ source = \"unit_index\" }}\n\
             [crypto.http.{name}.response]\ntype = \"json\"\n\
             data_path = \"/data\"\nencoding = \"base64\"\n\
             items_path = \"/results\"\nitem_index_path = \"/idx\"\n"
        ));
    }
    text
}

fn exchange(layout: Layout, header: Option<(&str, &str)>, decrypt: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let expected: Vec<String> = header
        .map(|(_, value)| value)
        .or((layout != Layout::Raw).then_some("application/json"))
        .into_iter()
        .map(str::to_owned)
        .collect();
    let want = expected.clone();
    let server = std::thread::spawn(move || {
        let (mut connection, _) = listener.accept().unwrap();
        connection
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut data = Vec::new();
        let mut buffer = [0; 4096];
        let end = loop {
            let count = connection.read(&mut buffer).unwrap();
            assert!(count > 0);
            data.extend_from_slice(&buffer[..count]);
            if let Some(at) = data.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                break at + 4;
            }
        };
        let head = std::str::from_utf8(&data[..end]).unwrap();
        let fields: Vec<_> = head
            .lines()
            .filter_map(|line| line.split_once(':'))
            .collect();
        let media_types: Vec<String> = fields
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| value.trim().to_owned())
            .collect();
        let length: usize = fields
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .unwrap()
            .1
            .trim()
            .parse()
            .unwrap();
        while data.len() < end + length {
            let count = connection.read(&mut buffer).unwrap();
            assert!(count > 0);
            data.extend_from_slice(&buffer[..count]);
        }
        let status = if media_types == want {
            "200 OK"
        } else {
            "415 Unsupported Media Type"
        };
        let response = if layout == Layout::Batch {
            let body: serde_json::Value = serde_json::from_slice(&data[end..end + length]).unwrap();
            assert_eq!(body["items"].as_array().unwrap().len(), 2);
            let payload = base64::engine::general_purpose::STANDARD.encode([0x55; 512]);
            serde_json::to_vec(&serde_json::json!({"results": [
                {"idx": 0, "data": payload}, {"idx": 1, "data": payload}
            ]}))
            .unwrap()
        } else {
            vec![0x55; 512]
        };
        write!(
            connection,
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response.len()
        )
        .unwrap();
        // Error responses need not be consumed by the client.
        let _ = connection.write_all(&response);
        media_types
    });
    let text = format!(
        r#"
config_schema_version = 1
[volume]
name = "content-type-regression"
max_virtual_size = "1MiB"
device_block_size = 512
crypto_unit_size = 512
shard_logical_size = "64KiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "content-type-v1"
[crypto.capabilities]
supported_plaintext_sizes = [512]
max_ciphertext_size = 512
[[crypto.http.endpoint]]
name = "only"
url = "{endpoint}"
{}{}
[backing]
root = "/unused"
"#,
        operation("encrypt", layout, header),
        operation("decrypt", layout, header)
    );
    let config = maki_format::config::parse_config(&text).unwrap();
    config.validate().unwrap();
    let provider =
        HttpCryptoProvider::from_config(&config, &endpoint, &MapKeySource::new()).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let context = CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(87),
        format_version: 1,
        crypto_compatibility_id: "content-type-v1".into(),
    };
    let count = if layout == Layout::Batch { 2 } else { 1 };
    let result = runtime.block_on(async {
        if decrypt {
            let items: Vec<_> = (0..count)
                .map(|unit_index| CiphertextUnit {
                    unit_index,
                    data: vec![0x11; 512],
                })
                .collect();
            provider
                .decrypt_batch(&context, &items)
                .await
                .map(|items| items.len())
        } else {
            let items: Vec<_> = (0..count)
                .map(|unit_index| PlaintextUnit {
                    unit_index,
                    data: SecretBuffer::zeroed(512),
                })
                .collect();
            provider
                .encrypt_batch(&context, &items)
                .await
                .map(|items| items.len())
        }
    });
    let actual = server.join().unwrap();
    assert_eq!(actual, expected, "decrypt={decrypt}: result={result:?}");
    assert_eq!(result.unwrap(), count as usize);
}

#[test]
fn explicit_standard_json_content_type_is_sent_once() {
    for decrypt in [false, true] {
        exchange(
            Layout::Json,
            Some(("Content-Type", "application/json")),
            decrypt,
        );
    }
}

#[test]
fn explicit_vendor_json_content_type_is_preserved_case_insensitively() {
    for decrypt in [false, true] {
        exchange(
            Layout::Json,
            Some(("CoNtEnT-TyPe", "application/vnd.maki+json")),
            decrypt,
        );
    }
}

#[test]
fn json_without_content_type_uses_one_default() {
    for decrypt in [false, true] {
        exchange(Layout::Json, None, decrypt);
    }
}

#[test]
fn raw_content_type_is_preserved_without_a_json_default() {
    for decrypt in [false, true] {
        exchange(
            Layout::Raw,
            Some(("content-type", "application/octet-stream")),
            decrypt,
        );
    }
}

#[test]
fn raw_without_content_type_remains_unspecified() {
    for decrypt in [false, true] {
        exchange(Layout::Raw, None, decrypt);
    }
}

#[test]
fn batch_json_without_content_type_uses_one_default() {
    for decrypt in [false, true] {
        exchange(Layout::Batch, None, decrypt);
    }
}

#[test]
fn explicit_batch_standard_content_type_is_sent_once() {
    for decrypt in [false, true] {
        exchange(
            Layout::Batch,
            Some(("content-type", "application/json")),
            decrypt,
        );
    }
}

#[test]
fn explicit_batch_vendor_content_type_is_preserved() {
    for decrypt in [false, true] {
        exchange(
            Layout::Batch,
            Some(("CONTENT-TYPE", "application/vnd.maki+json; version=1")),
            decrypt,
        );
    }
}
