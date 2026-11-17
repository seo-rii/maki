//! gRPC method paths (`[crypto.grpc] encrypt_path` and `decrypt_path`) were
//! never checked by configuration validation. The provider parsed them only
//! at construction, during attach, so `maki volume create` accepted a path
//! the provider refuses (empty, without the leading `/`, with a space or
//! another character a URI cannot carry) and every attach then failed. Some
//! paths the provider accepted were not sent as written either: a `#`
//! fragment was silently dropped, and `*` or a bare `?query` named no
//! method at all.

use maki_format::config::{parse_config, VolumeConfig};

const SECRET: &str = "S3NT1NEL0123456789abcdef";

fn grpc(grpc_section: &str) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "t"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-grpc"
crypto_compatibility_id = "v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[crypto.grpc]
{grpc_section}
[[crypto.grpc.endpoint]]
name = "a"
url = "https://crypto.internal"
[backing]
root = "/x"
"#
    )
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

fn parse(raw: &str) -> VolumeConfig {
    parse_config(raw).unwrap_or_else(|e| panic!("parse: {e}\n{raw}"))
}

/// Paths the provider cannot build, or would not send as written; each
/// carries a marker that must not be echoed (a path may carry a token).
fn refused_paths() -> Vec<(&'static str, String)> {
    vec![
        ("empty", String::new()),
        ("no leading slash", format!("maki.{SECRET}/EncryptBatch")),
        ("a space", format!("/maki.{SECRET} Service/EncryptBatch")),
        ("a tab", format!("/maki.{SECRET}/Encrypt\tBatch")),
        ("a NUL", format!("/maki.{SECRET}/Encrypt\0Batch")),
        ("a DEL", format!("/maki.{SECRET}/Encrypt\u{7f}Batch")),
        ("angle brackets", format!("/maki.{SECRET}/<EncryptBatch>")),
        ("a backtick", format!("/maki.{SECRET}/`EncryptBatch`")),
        ("a backslash", format!("/maki.{SECRET}\\EncryptBatch")),
        ("braces", format!("/maki.{SECRET}/{{EncryptBatch}}")),
        (
            "a non-ASCII letter",
            format!("/maki.{SECRET}/Encrypt\u{e9}"),
        ),
        (
            "a bad percent escape",
            format!("/maki.{SECRET}/Encrypt%zzBatch"),
        ),
        (
            "a truncated percent escape",
            format!("/maki.{SECRET}/Encrypt%2"),
        ),
        ("a fragment", format!("/maki.{SECRET}/EncryptBatch#v2")),
        (
            "a fragment after a query",
            format!("/maki.CryptoService/EncryptBatch?token={SECRET}#v2"),
        ),
        (
            "a space in the query",
            format!("/maki.CryptoService/EncryptBatch?token={SECRET} x"),
        ),
        ("an asterisk", "*".to_string()),
        ("a query without a path", format!("?token={SECRET}")),
        ("a fragment without a path", format!("#{SECRET}")),
        ("too long", format!("/{SECRET}{}", "a".repeat(65_534))),
    ]
}

#[test]
fn method_paths_the_provider_cannot_send_as_written_are_refused() {
    for field in ["encrypt_path", "decrypt_path"] {
        for (case, path) in refused_paths() {
            let raw = grpc(&format!("{field} = {}", toml_string(&path)));
            let error = parse(&raw)
                .validate()
                .err()
                .unwrap_or_else(|| panic!("{field} with {case} validated"));
            let (display, debug) = (error.to_string(), format!("{error:?}"));
            assert!(
                !display.contains(SECRET) && !debug.contains(SECRET),
                "{field} with {case}: the error echoed the path: {display}"
            );
            assert!(display.contains(field), "{field} with {case}: {display}");
        }
    }
}

#[test]
fn method_paths_the_provider_sends_as_written_still_validate() {
    // Unset paths take the reference contract's methods.
    parse(&grpc("")).validate().unwrap();
    for path in [
        "/maki.CryptoService/EncryptBatch",
        "/vendor.Kms/Encrypt",
        "/vendor.v1.Kms/Encrypt_Batch-2",
        // A gateway prefix, a query and percent escapes are part of a URI
        // path-and-query and are sent unchanged.
        "/gateway/maki.CryptoService/EncryptBatch",
        "/maki.CryptoService/EncryptBatch?tenant=demo&v=1/2?",
        "/vendor%2EKms/Encrypt%2fBatch",
        "/~user/!$&'()*+,;=:@",
        "/",
    ] {
        for field in ["encrypt_path", "decrypt_path"] {
            parse(&grpc(&format!("{field} = {}", toml_string(path))))
                .validate()
                .unwrap_or_else(|e| panic!("{field} {path:?}: {e}"));
        }
    }
    let longest = format!("/{}", "a".repeat(65_533));
    parse(&grpc(&format!("encrypt_path = {}", toml_string(&longest))))
        .validate()
        .unwrap();
}
