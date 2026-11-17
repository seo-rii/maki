//! Configuration validation and gRPC provider construction must agree on
//! method paths. Validation never looked at `encrypt_path` and
//! `decrypt_path`, so `volume create` accepted a path that provider
//! construction refuses at attach; and construction accepted paths that are
//! not sent as written (a `#` fragment is dropped) or name no method (`*`,
//! a bare `?query`). Pin both to one rule.

use std::time::Duration;

use maki_crypto::{BatchCapability, Capability, CryptoCapabilities};
use maki_crypto_grpc::{GrpcCryptoProvider, GrpcProviderSpec};
use maki_format::config::parse_config;

fn spec(path: &str) -> GrpcProviderSpec {
    GrpcProviderSpec {
        url: "http://127.0.0.1:7000".into(),
        encrypt_path: path.into(),
        decrypt_path: "/maki.CryptoService/DecryptBatch".into(),
        metadata: vec![],
        capabilities: CryptoCapabilities {
            provider_id: "remote-grpc".into(),
            crypto_compatibility_id: "method-path-v1".into(),
            supported_plaintext_sizes: vec![4096],
            max_ciphertext_size: 4384,
            stateless: true,
            retry_safe: true,
            batch: BatchCapability {
                supported: true,
                max_items: 8,
                max_bytes: 1 << 20,
            },
            integrity: Capability::Absent,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        },
        timeout: Duration::from_secs(1),
        max_message_bytes: 4 << 20,
    }
}

/// A TOML basic string holding `value` exactly.
fn toml_string(value: &str) -> String {
    let mut quoted = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            c if c.is_control() => quoted.push_str(&format!("\\u{:04X}", u32::from(c))),
            c => quoted.push(c),
        }
    }
    quoted.push('"');
    quoted
}

fn validates(path: &str) -> bool {
    parse_config(&format!(
        r#"
config_schema_version = 1
[volume]
name = "method-path"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-grpc"
crypto_compatibility_id = "method-path-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[crypto.grpc]
encrypt_path = {}
[[crypto.grpc.endpoint]]
name = "local"
url = "http://127.0.0.1:7000"
[backing]
root = "/unused-method-path"
"#,
        toml_string(path)
    ))
    .unwrap()
    .validate()
    .is_ok()
}

#[tokio::test]
async fn validation_and_construction_accept_exactly_the_paths_sent_as_written() {
    let mut wrong = Vec::new();
    let longest = format!("/{}", "a".repeat(65_533));
    let too_long = format!("/{}", "a".repeat(65_534));
    for (path, sendable) in [
        ("/maki.CryptoService/EncryptBatch", true),
        ("/vendor.Kms/Encrypt", true),
        ("/gateway/maki.CryptoService/EncryptBatch", true),
        ("/maki.CryptoService/EncryptBatch?tenant=demo", true),
        ("/vendor%2EKms/Encrypt", true),
        ("/", true),
        (longest.as_str(), true),
        // Refused by provider construction, accepted by validation.
        ("", false),
        ("maki.CryptoService/EncryptBatch", false),
        ("/maki CryptoService/EncryptBatch", false),
        ("/maki.CryptoService/Encrypt\tBatch", false),
        ("/maki.CryptoService/<EncryptBatch>", false),
        ("/maki.CryptoService/`EncryptBatch`", false),
        ("/maki.CryptoService/EncryptBatch?token=a b", false),
        (too_long.as_str(), false),
        // Accepted by both, but not sent as written or naming no method.
        ("/maki.CryptoService/EncryptBatch#v2", false),
        ("*", false),
        ("?tenant=demo", false),
        ("#v2", false),
        // Not RFC 3986 path characters, which HTTP/2 requires of `:path`.
        ("/maki.CryptoService/{EncryptBatch}", false),
        ("/maki.CryptoService/Encrypt|Batch", false),
        ("/maki.CryptoService/Encrypt\u{e9}", false),
        ("/maki.CryptoService/Encrypt%zz", false),
    ] {
        let validated = validates(path);
        let constructed = GrpcCryptoProvider::new(spec(path)).is_ok();
        if validated != sendable || constructed != sendable {
            wrong.push(format!(
                "{:?} ({}): validation {}, construction {}",
                path.get(..64).unwrap_or(path),
                if sendable { "sendable" } else { "not sendable" },
                verdict(validated),
                verdict(constructed),
            ));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

fn verdict(accepted: bool) -> &'static str {
    if accepted {
        "accepts"
    } else {
        "refuses"
    }
}
