use maki_format::config::{parse_config, ByteSize};

fn config(backing: &str) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "rollback"
max_virtual_size = "1GiB"
shard_logical_size = "8MiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "v1"
key = {{ source = "env", name = "MAKI_TEST_KEY" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "/var/lib/maki/rollback"
journal_segment_size = "64KiB"
journal_max_bytes = "1MiB"
checkpoint_reserve_bytes = "64KiB"
journal_emergency_reserve_bytes = "64KiB"
{backing}
[nbd]
maximum_io = "64KiB"
"#
    )
}

fn error(backing: &str) -> String {
    let parsed = parse_config(&config(backing)).unwrap();
    parsed.validate().unwrap_err().to_string()
}

#[test]
fn rollback_protection_parses_without_changing_plain_backing_defaults() {
    let plain = parse_config(&config("")).unwrap();
    assert!(plain.backing.rollback_protection.is_none());

    let protected = parse_config(&config(
        r#"[backing.rollback_protection]
witness_root = "/var/lib/maki-witness/rollback"
capacity = "64MiB""#,
    ))
    .unwrap();
    let rollback = protected.backing.rollback_protection.unwrap();
    assert_eq!(rollback.witness_root, "/var/lib/maki-witness/rollback");
    assert_eq!(rollback.capacity, ByteSize(64 << 20));
}

#[test]
fn rollback_protection_requires_safe_absolute_distinct_paths() {
    for (section, needle) in [
        (
            "[backing.rollback_protection]\nwitness_root = \"relative\"\ncapacity = \"4KiB\"",
            "absolute",
        ),
        (
            "[backing.rollback_protection]\nwitness_root = \"/var/lib/maki/rollback\"\ncapacity = \"4KiB\"",
            "distinct",
        ),
        (
            "[backing.rollback_protection]\nwitness_root = \"/var/lib/maki/rollback/witness\"\ncapacity = \"4KiB\"",
            "nested",
        ),
        (
            "[backing.rollback_protection]\nwitness_root = \"/var/lib/maki\"\ncapacity = \"4KiB\"",
            "nested",
        ),
    ] {
        assert!(error(section).contains(needle), "section: {section}");
    }
}

#[test]
fn rollback_capacity_is_positive_page_aligned_and_bounded() {
    for capacity in ["0", "4095", "1073745920"] {
        let expected = if capacity == "1073745920" {
            "at most"
        } else {
            "positive multiple"
        };
        let section = format!(
            "[backing.rollback_protection]\nwitness_root = \"/witness\"\ncapacity = \"{capacity}\""
        );
        assert!(error(&section).contains(expected), "capacity: {capacity}");
    }

    let parsed = parse_config(&config(
        "[backing.rollback_protection]\nwitness_root = \"/witness\"\ncapacity = \"1048572KiB\"",
    ))
    .unwrap();
    parsed.validate().unwrap();
}

#[test]
fn rollback_capacity_must_cover_progress_reserves() {
    let message =
        error("[backing.rollback_protection]\nwitness_root = \"/witness\"\ncapacity = \"128KiB\"");
    assert!(message.contains("exceed"), "unexpected error: {message}");
    assert!(message.contains("reserve"), "unexpected error: {message}");
}
