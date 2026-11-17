//! `env` credential names were unrestricted beyond being non-empty. The
//! development source reads `MAKI_CREDENTIAL_<NAME>`, and no environment
//! variable name can contain `=` (it ends the name in every `NAME=value`
//! entry) or NUL (it ends the entry). Such a name can never be set, and
//! looking it up is not even a clean miss: glibc's `getenv("A=B")` returns
//! the rest of variable `A` after a leading `B=`, so a key or token would be
//! read from part of another variable.

use maki_format::config::{parse_config, VolumeConfig};

const SECRET: &str = "S3NT1NEL0123456789abcdef";

fn local(key: &str) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "t"
max_virtual_size = "1GiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "v1"
key = {key}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "/x"
"#
    )
}

fn remote_http(header: &str) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "t"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[[crypto.http.endpoint]]
name = "a"
url = "https://crypto.internal"
[crypto.http.encrypt]
path = "/encrypt"
[crypto.http.encrypt.headers]
Authorization = {header}
[crypto.http.encrypt.response]
data_path = "/ct"
encoding = "base64"
[crypto.http.decrypt]
path = "/decrypt"
[crypto.http.decrypt.response]
data_path = "/pt"
encoding = "base64"
[backing]
root = "/x"
"#
    )
}

fn remote_grpc(metadata: &str) -> String {
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
[[crypto.grpc.endpoint]]
name = "a"
url = "https://crypto.internal"
[crypto.grpc.metadata]
authorization = {metadata}
[backing]
root = "/x"
"#
    )
}

fn parse(raw: &str) -> VolumeConfig {
    parse_config(raw).unwrap_or_else(|e| panic!("parse: {e}\n{raw}"))
}

/// An `env` reference to `name`, as a TOML inline table.
fn env_reference(name: &str) -> String {
    let mut quoted = String::new();
    for ch in name.chars() {
        match ch {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            c if c.is_control() => quoted.push_str(&format!("\\u{:04X}", u32::from(c))),
            c => quoted.push(c),
        }
    }
    format!("{{ source = \"env\", name = \"{quoted}\" }}")
}

fn configurations(reference: &str) -> [String; 3] {
    [
        local(reference),
        remote_http(reference),
        remote_grpc(reference),
    ]
}

#[test]
fn env_names_no_environment_variable_can_have_are_refused() {
    for name in [
        format!("{SECRET}=x"),
        format!("={SECRET}"),
        format!("{SECRET}="),
        format!("{SECRET}\0"),
        format!("\0{SECRET}"),
    ] {
        for raw in configurations(&env_reference(&name)) {
            let config = parse(&raw);
            for error in [
                config.validate().err(),
                // The public provider preflight checks references on its own.
                config.validate_credential_sources().err(),
            ] {
                let error = error.unwrap_or_else(|| panic!("validated env name {name:?}"));
                let (display, debug) = (error.to_string(), format!("{error:?}"));
                assert!(
                    !display.contains(SECRET) && !debug.contains(SECRET),
                    "the error echoed the credential name: {display}"
                );
                assert!(
                    display.contains("env credential name"),
                    "{name:?}: {display}"
                );
            }
        }
    }
}

/// `env` is a development source: names are not file names, and anything an
/// environment can hold stays valid, including the names in use.
#[test]
fn env_names_an_environment_can_hold_still_validate() {
    for name in [
        "test-key",
        "vol.key",
        "k",
        "MAKI_TEST_KEY",
        "MAKI_CREDENTIAL_INSPECT_EXISTING_KEY",
        "grpc-wiring-token",
        ".vol-key",
        "keys/vol-key",
        "vol key",
        "cl\u{e9}",
    ] {
        for raw in configurations(&env_reference(name)) {
            parse(&raw)
                .validate()
                .unwrap_or_else(|e| panic!("env {name:?}: {e}"));
        }
    }
}
