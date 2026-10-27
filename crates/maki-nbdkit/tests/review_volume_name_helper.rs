//! BUG-138: names accepted by the daemon must be usable by its helper.

use maki_format::config::parse_config;
use maki_nbdkit::daemon::create_volume_from_config_str;

fn raw(root: &std::path::Path, name: &str) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = {name:?}
max_virtual_size = "8KiB"
device_block_size = 512
crypto_unit_size = 512
shard_logical_size = "8KiB"
[crypto]
provider = "fake"
crypto_compatibility_id = "volume-name-v1"
[crypto.capabilities]
supported_plaintext_sizes = [512]
max_ciphertext_size = 520
[backing]
root = {}
journal_emergency_reserve_bytes = "0B"
checkpoint_reserve_bytes = "0B"
"#,
        serde_json::to_string(root.to_str().unwrap()).unwrap(),
    )
}

#[test]
fn option_like_volume_names_are_rejected_before_volume_creation() {
    for name in ["-audit", "--audit", "-", "-_audit"] {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("volume");
        let config = raw(&root, name);
        let error = parse_config(&config)
            .unwrap()
            .validate()
            .expect_err("daemon accepted a name rejected by helper argument validation");
        assert!(error.to_string().contains("volume name"), "{error}");
        assert!(create_volume_from_config_str(&config).is_err());
        assert!(!root.exists(), "invalid name created backing state");
    }
}

#[test]
fn safe_helper_names_still_create_volumes() {
    for name in ["audit", "audit-tail", "_audit", "A_09-z", "audit-"] {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("volume");
        let raw = raw(&root, name);
        parse_config(&raw).unwrap().validate().unwrap();
        create_volume_from_config_str(&raw).unwrap();
        assert!(root.join("superblock.a").exists(), "{name:?}");
    }
}
