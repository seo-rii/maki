//! R5-035: a credential used as text (an HTTP header, gRPC metadata, a PEM
//! private key) went through the key loader, which hex-decodes any
//! even-length hex string because local provider keys may be stored as
//! hex. A bearer token generated with `openssl rand -hex 32` therefore
//! reached the header builder as 32 random bytes: the daemon refused to
//! start ("credential is not valid UTF-8"), and a token whose decoded bytes
//! happened to be printable would have been sent altered. Found by the
//! 2026-10-04 remote-provider campaign; `maki volume create` never loads
//! the credential, so only the daemon failed.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;

use maki_format::config::parse_config;
use maki_nbdkit::daemon::{build_provider, create_volume_from_config_str};

const HEX_TOKEN: &str = "6b1d0f4c9e2a7d3b8c5f1e0a9d4c7b2e6f3a8d1c5e9b0f7a2d6c4e8b1f3a5d7c";

/// The transport section of a remote provider whose bearer token is a
/// `file` credential.
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
name = "text-credential"
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
async fn the_daemon_accepts_a_hex_bearer_token() {
    for provider in ["remote-http", "remote-grpc"] {
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("token");
        std::fs::write(&token, format!("{HEX_TOKEN}\n")).unwrap();
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
        let root = dir.path().join("backing");
        std::fs::create_dir(&root).unwrap();
        let raw = configuration(provider, token.to_str().unwrap(), root.to_str().unwrap());
        // Neither creating the volume nor building the provider contacts
        // the endpoint (nothing listens on port 9).
        create_volume_from_config_str(&raw).unwrap();
        let config = parse_config(&raw).unwrap();
        if let Err(error) = build_provider(&config).await {
            panic!("{provider}: a hex bearer token was refused: {error}");
        }
    }
    // That the header carries the token verbatim is checked at the HTTP
    // provider (maki-crypto-http/tests/review_r5_text_credentials.rs).
}
