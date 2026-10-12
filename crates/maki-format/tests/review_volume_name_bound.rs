//! BUG-059: valid volume names must fit operational paths and status replies.

use maki_format::config::parse_config;

fn validate_name(name: &str) -> Result<(), maki_format::config::ConfigError> {
    let raw = format!(
        r#"
config_schema_version = 1
[volume]
name = "{name}"
max_virtual_size = "1GiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "v1"
key = {{ source = "env", name = "k" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "/x"
"#
    );
    parse_config(&raw)?.validate()
}

#[test]
fn status_sized_volume_names_are_rejected_at_configuration_validation() {
    let error = validate_name(&"v".repeat(65_536)).expect_err("unbounded name accepted");
    assert!(error.to_string().contains("volume name"));
    assert!(error.to_string().contains("64"));
}

#[test]
fn volume_names_have_an_exact_64_byte_boundary() {
    validate_name(&"v".repeat(64)).unwrap();
    let error = validate_name(&"v".repeat(65)).expect_err("65-byte name accepted");
    assert!(error.to_string().contains("64"));
}

#[test]
fn existing_name_character_rules_are_preserved() {
    for name in ["v", "postgres-prod_2", "A_9-z"] {
        validate_name(name).unwrap();
    }
    for name in ["", "bad.name", "bad/name", "볼륨"] {
        assert!(
            validate_name(name).is_err(),
            "invalid name {name:?} accepted"
        );
    }
}
