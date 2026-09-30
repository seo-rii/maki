//! R5-007: SPEC §9 forbids secrets in ordinary TOML, but the literal check
//! matched only nine exact header names, so vendor credential headers such
//! as `X-Vault-Token`, `X-Goog-Api-Key` or `Ocp-Apim-Subscription-Key`
//! validated as literals. A header or gRPC metadata name that looks like a
//! credential must now use a credential reference, and every credential
//! reference is validated whatever header carries it.

use maki_format::config::parse_config;

fn http_config(name: &str, value: &str) -> String {
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
"{name}" = {value}
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

fn grpc_config(name: &str, value: &str) -> String {
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
name = "primary"
url = "http://127.0.0.1:7000"
[crypto.grpc.metadata]
"{name}" = {value}
[backing]
root = "/x"
"#
    )
}

fn valid(text: &str) -> bool {
    parse_config(text).is_ok_and(|config| config.validate().is_ok())
}

const CREDENTIAL_HEADERS: &[&str] = &[
    "X-Vault-Token",
    "X-Goog-Api-Key",
    "Ocp-Apim-Subscription-Key",
    "X-Amz-Security-Token",
    "X-Access-Token",
    "apikey",
    "X-Auth-Key",
    "X-Session-Id",
    "X-Signature",
    "X-Client-Password",
    "Authorization",
];

#[test]
fn credential_like_headers_refuse_literal_values() {
    for name in CREDENTIAL_HEADERS {
        assert!(
            !valid(&http_config(name, "\"s3cr3t\"")),
            "HTTP header {name} accepted a literal secret"
        );
        assert!(
            !valid(&grpc_config(&name.to_lowercase(), "\"s3cr3t\"")),
            "gRPC metadata {name} accepted a literal secret"
        );
        let reference = r#"{ source = "credential", name = "crypto-token" }"#;
        assert!(valid(&http_config(name, reference)), "{name}");
        assert!(
            valid(&grpc_config(&name.to_lowercase(), reference)),
            "{name}"
        );
    }
}

#[test]
fn ordinary_headers_keep_literal_values() {
    for name in [
        "Content-Type",
        "Accept",
        "User-Agent",
        "X-Request-Id",
        "X-Tenant",
    ] {
        assert!(valid(&http_config(name, "\"plain\"")), "{name}");
        assert!(
            valid(&grpc_config(&name.to_lowercase(), "\"plain\"")),
            "{name}"
        );
    }
}

#[test]
fn every_credential_reference_is_validated() {
    let bad = r#"{ source = "keyring", name = "crypto-token" }"#;
    assert!(!valid(&http_config("X-Tenant", bad)));
    assert!(!valid(&grpc_config("x-tenant", bad)));
}
