//! BUG-127: semantic validation must not echo rejected credential fields.
use maki_format::config::parse_config;

const SECRET: &str = "AUDIT_SECRET_20261016_0123456789abcdef";

fn config(key: &str) -> String {
    format!(
        "config_schema_version = 1\n[volume]\nname = \"audit-errors\"\nmax_virtual_size = \"1MiB\"\n[backing]\nroot = \"/tmp/unused-audit-diagnostics\"\n[crypto]\nprovider = \"local-aes-gcm-siv\"\ncrypto_compatibility_id = \"audit\"\nkey = {key}\n[crypto.capabilities]\nsupported_plaintext_sizes = [4096]\nmax_ciphertext_size = 4384\n"
    )
}

fn assert_safe_diagnostic(document: String, diagnosis: &str) {
    let config = parse_config(&document).expect("valid TOML and schema");
    let error = config.validate().expect_err("invalid credential reference");
    let display = error.to_string();
    let debug = format!("{error:?}");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, &document).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_maki"))
        .args(["volume", "inspect"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(!output.status.success(), "invalid config was accepted");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        [&display, &debug, stderr.as_ref(), stdout.as_ref()]
            .iter()
            .all(|text| !text.contains(SECRET)),
        "rejected credential input leaked through semantic validation"
    );
    assert!(display.contains(diagnosis), "{display}");
    assert!(stderr.contains(diagnosis), "{stderr}");
}

#[test]
fn credential_source_value_is_not_echoed() {
    assert_safe_diagnostic(
        config(&format!(
            "{{ source = \"{SECRET}\", name = \"volume-key\" }}"
        )),
        "credential source",
    );
}

#[test]
fn credential_file_literal_is_not_echoed() {
    assert_safe_diagnostic(
        config(&format!("{{ source = \"file\", name = \"{SECRET}\" }}")),
        "absolute path",
    );
}

#[test]
fn source_conflict_does_not_echo_either_credential_field() {
    for (name, source) in [(SECRET, "env"), ("volume-key", SECRET)] {
        let document = format!(
            r#"
config_schema_version = 1
[volume]
name = "credential-diagnostics"
max_virtual_size = "1MiB"
[backing]
root = "/unused-credential-diagnostics"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "test-profile-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[[crypto.http.endpoint]]
name = "local"
url = "http://127.0.0.1:9"
[crypto.http.encrypt]
path = "/encrypt"
[crypto.http.encrypt.headers]
Authorization = {{ source = "credential", name = "{name}" }}
[crypto.http.decrypt]
path = "/decrypt"
[crypto.http.decrypt.headers]
Authorization = {{ source = "{source}", name = "{name}" }}
"#
        );
        // This public preflight is also used directly by provider creation.
        let error = parse_config(&document)
            .unwrap()
            .validate_credential_sources()
            .unwrap_err();
        assert!(!error.to_string().contains(SECRET));
        assert!(!format!("{error:?}").contains(SECRET));
        assert_safe_diagnostic(document, "conflicting sources");
    }
}

#[test]
fn malformed_schema_control_stays_redacted() {
    let error = parse_config(&config(&format!("\"{SECRET}\""))).unwrap_err();
    assert!(!error.to_string().contains(SECRET));
    assert!(!format!("{error:?}").contains(SECRET));
}

#[test]
fn valid_reference_control_passes_validation() {
    parse_config(&config(
        "{ source = \"credential\", name = \"volume-key\" }",
    ))
    .unwrap()
    .validate()
    .unwrap();
}

#[tokio::test]
async fn public_provider_preflight_rejects_bad_references_without_echoing_them() {
    for key in [
        format!("{{ source = \"{SECRET}\", name = \"volume-key\" }}"),
        format!("{{ source = \"file\", name = \"{SECRET}\" }}"),
    ] {
        // This API accepts a parsed configuration without VolumeConfig::validate.
        let cfg = parse_config(&config(&key)).unwrap();
        let error = maki_nbdkit::daemon::build_provider(&cfg)
            .await
            .err()
            .expect("malformed references must fail before credential lookup");
        assert!(matches!(error, maki_nbdkit::daemon::DaemonError::Config(_)));
        assert!(!error.to_string().contains(SECRET));
        assert!(!format!("{error:?}").contains(SECRET));
    }
}
