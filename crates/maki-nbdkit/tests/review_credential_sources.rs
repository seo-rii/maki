//! BUG-007: one credential name must never silently select another source.

use maki_format::config::parse_config;
use maki_nbdkit::daemon::{build_provider, DaemonError};

fn configuration(decrypt_name: &str, decrypt_source: &str) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "credential-review"
max_virtual_size = "1MiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "review-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4124
[[crypto.http.endpoint]]
name = "local"
url = "http://127.0.0.1:9"
[crypto.http.encrypt]
path = "/encrypt"
[crypto.http.encrypt.headers]
Authorization = {{ source = "credential", name = "shared-token" }}
[crypto.http.decrypt]
path = "/decrypt"
[crypto.http.decrypt.headers]
Authorization = {{ source = "{decrypt_source}", name = "{decrypt_name}" }}
[backing]
root = "/unused-credential-review"
"#
    )
}

#[test]
fn conflicting_credential_sources_are_rejected_before_attach() {
    for source in ["env", "file"] {
        let config = parse_config(&configuration("shared-token", source)).unwrap();
        let error = config
            .validate()
            .expect_err("the same name cannot refer to different credential sources")
            .to_string();
        assert!(error.contains("shared-token"));
        assert!(error.contains("conflicting"));
    }
}

#[test]
fn repeated_identity_and_distinct_credential_names_remain_valid() {
    for (name, source) in [("shared-token", "credential"), ("another-token", "env")] {
        parse_config(&configuration(name, source))
            .unwrap()
            .validate()
            .unwrap();
    }
}

#[tokio::test]
async fn provider_construction_rejects_source_conflicts_without_loading_credentials() {
    // Public callers can construct a VolumeConfig without running validate.
    // A Config error must precede any environment/file lookup or network I/O.
    let config = parse_config(&configuration("shared-token", "env")).unwrap();
    let result = build_provider(&config).await;
    assert!(
        matches!(result, Err(DaemonError::Config(ref error)) if error.to_string().contains("conflicting")),
        "provider construction must reject ambiguous credential sources"
    );
}
