//! Response budgets include every configured single-item JSON field.
use maki_format::config::{parse_config, ByteSize, VolumeConfig};

fn config(index_path: Option<&str>) -> VolumeConfig {
    let index = index_path
        .map(|path| format!("item_index_path = {path:?}"))
        .unwrap_or_default();
    let mut operations = String::new();
    for operation in ["encrypt", "decrypt"] {
        operations += &format!(
            r#"
[crypto.http.{operation}]
path = "/{operation}"
[crypto.http.{operation}.response]
data_path = "/data"
{index}
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
url = "http://127.0.0.1:1"
{operations}
[backing]
root = "/unused"
"#
    ))
    .unwrap()
}

#[test]
fn review_single_json_response_budget_includes_the_index() {
    let payload_length = 4096_u64.div_ceil(3) * 4;
    let payload_only = payload_length + r#"{"data":""}"#.len() as u64;
    let with_index = payload_length + r#"{"data":"","unit":18446744073709551615}"#.len() as u64;
    let mut cfg = config(Some("/unit"));
    cfg.crypto.http.as_mut().unwrap().max_response_bytes = Some(ByteSize(with_index - 1));
    assert!(cfg
        .validate()
        .unwrap_err()
        .to_string()
        .contains("max_response_bytes"));
    cfg.crypto.http.as_mut().unwrap().max_response_bytes = Some(ByteSize(with_index));
    cfg.validate().unwrap();

    let mut cfg = config(None);
    cfg.crypto.http.as_mut().unwrap().max_response_bytes = Some(ByteSize(payload_only));
    cfg.validate().unwrap();
    cfg.crypto.http.as_mut().unwrap().max_response_bytes = Some(ByteSize(payload_only - 1));
    assert!(cfg
        .validate()
        .unwrap_err()
        .to_string()
        .contains("max_response_bytes"));
}

#[test]
fn review_single_json_payload_and_index_need_separate_leaves() {
    for index in ["", "/data", "/data/unit"] {
        let error = config(Some(index)).validate().unwrap_err();
        assert!(error.to_string().contains("separate fields"), "{error}");
    }
    let mut cfg = config(Some("/data"));
    cfg.crypto
        .http
        .as_mut()
        .unwrap()
        .encrypt
        .as_mut()
        .unwrap()
        .response
        .as_mut()
        .unwrap()
        .data_path = Some("/data/value".into());
    assert!(cfg
        .validate()
        .unwrap_err()
        .to_string()
        .contains("separate fields"));
    config(Some("/metadata/unit")).validate().unwrap();
}

#[test]
fn review_single_json_index_pointer_requires_rfc6901_escapes() {
    let error = config(Some("/unit~2")).validate().unwrap_err();
    assert!(error.to_string().contains("pointer escape"), "{error}");
    config(Some("/unit~1number")).validate().unwrap();
}

#[test]
fn review_raw_response_budget_ignores_json_mappings() {
    let mut cfg = config(Some("/unit"));
    let http = cfg.crypto.http.as_mut().unwrap();
    http.max_response_bytes = Some(ByteSize(4096));
    for op in [
        http.encrypt.as_mut().unwrap(),
        http.decrypt.as_mut().unwrap(),
    ] {
        op.response.as_mut().unwrap().response_type = "raw".into();
    }
    cfg.validate().unwrap();
}
