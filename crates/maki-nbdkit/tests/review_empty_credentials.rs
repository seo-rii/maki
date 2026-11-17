//! SPEC §44: missing or invalid credentials fail closed. A bearer token
//! file that is empty or holds only whitespace (a truncated rotation) was
//! loaded as a present credential: the HTTP provider was built with
//! `Authorization: Bearer ` and the gRPC provider with the same empty
//! metadata value, so the daemon attached and every request went out
//! without a token. Building either provider must refuse it.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;

use maki_format::config::parse_config;
use maki_nbdkit::daemon::{build_provider, create_volume_from_config_str};

fn transport(provider: &str, token_path: &str) -> String {
    match provider {
        "remote-http" => format!(
            r#"[[crypto.http.endpoint]]
name = "local"
url = "http://127.0.0.1:9"
[crypto.http.encrypt]
path = "/encrypt"
[crypto.http.encrypt.headers]
Authorization = {{ source = "file", name = "{token_path}", format = "Bearer {{}}" }}
[crypto.http.decrypt]
path = "/decrypt"
[crypto.http.decrypt.headers]
Authorization = {{ source = "file", name = "{token_path}", format = "Bearer {{}}" }}
"#
        ),
        "remote-grpc" => format!(
            r#"[[crypto.grpc.endpoint]]
name = "local"
url = "http://127.0.0.1:9"
[crypto.grpc.metadata]
authorization = {{ source = "file", name = "{token_path}", format = "Bearer {{}}" }}
"#
        ),
        other => unreachable!("{other}"),
    }
}

fn configuration(provider: &str, token_path: &str, root: &str) -> String {
    let transport = transport(provider, token_path);
    format!(
        r#"
config_schema_version = 1
[volume]
name = "empty-credential"
max_virtual_size = "1MiB"
[crypto]
provider = "{provider}"
crypto_compatibility_id = "review-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4124
{transport}[backing]
root = "{root}"
"#
    )
}

#[tokio::test]
async fn a_blank_bearer_token_fails_closed() {
    for provider in ["remote-http", "remote-grpc"] {
        for content in ["", "\n", "  \t\n"] {
            let dir = tempfile::tempdir().unwrap();
            let token = dir.path().join("token");
            std::fs::write(&token, content).unwrap();
            std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
            let root = dir.path().join("backing");
            std::fs::create_dir(&root).unwrap();
            let raw = configuration(provider, token.to_str().unwrap(), root.to_str().unwrap());
            // Creating the volume does not load the credential; building
            // the provider does, without contacting the endpoint (nothing
            // listens on port 9).
            create_volume_from_config_str(&raw).unwrap();
            let config = parse_config(&raw).unwrap();
            let Err(error) = build_provider(&config).await else {
                panic!("{provider}: a blank bearer token {content:?} was accepted");
            };
            let message = error.to_string();
            assert!(
                message.contains("empty"),
                "{provider} {content:?}: {message}"
            );
        }
    }
}
