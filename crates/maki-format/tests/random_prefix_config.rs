use maki_format::config::{parse_config, ConfigError, VolumeConfig};

fn config(
    prefix: Option<u32>,
    compatibility_id: &str,
    sizes: &[u32],
    max_ciphertext: u32,
) -> String {
    let random_prefix = prefix
        .map(|bytes| format!("random_prefix_bytes = {bytes}\n"))
        .unwrap_or_default();
    let sizes = sizes
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r#"
config_schema_version = 1
[volume]
name = "prefix-test"
max_virtual_size = "1MiB"
device_block_size = 512
crypto_unit_size = 512
shard_logical_size = "1MiB"
[crypto]
provider = "fake"
crypto_compatibility_id = "{compatibility_id}"
{random_prefix}[crypto.capabilities]
supported_plaintext_sizes = [{sizes}]
max_ciphertext_size = {max_ciphertext}
[backing]
root = "/tmp/maki-prefix-test"
"#
    )
}

fn parse(raw: &str) -> VolumeConfig {
    parse_config(raw).unwrap_or_else(|e| panic!("failed to parse config: {e}\n{raw}"))
}

fn validation_error(raw: &str) -> String {
    parse(raw)
        .validate()
        .expect_err("configuration should be rejected")
        .to_string()
}

#[test]
fn omitted_prefix_preserves_existing_sizes_and_identity() {
    let cfg = parse(&config(None, "vendor-v1", &[512], 512));

    assert_eq!(cfg.crypto.random_prefix_bytes, 0);
    assert_eq!(cfg.provider_plaintext_size().unwrap(), 512);
    assert_eq!(cfg.crypto.effective_compatibility_id(), "vendor-v1");
    cfg.validate().unwrap();
}

#[test]
fn enabled_prefix_expands_provider_plaintext_and_derives_identity() {
    let cfg = parse(&config(Some(32), "vendor-v1", &[544], 544));

    assert_eq!(cfg.provider_plaintext_size().unwrap(), 544);
    assert_eq!(
        cfg.crypto.effective_compatibility_id(),
        "maki-random-prefix-v1:32:vendor-v1"
    );
    cfg.validate().unwrap();
}

#[test]
fn changing_prefix_size_changes_effective_identity() {
    let prefix_16 = parse(&config(Some(16), "vendor-v1", &[528], 528));
    let prefix_32 = parse(&config(Some(32), "vendor-v1", &[544], 544));

    assert_ne!(
        prefix_16.crypto.effective_compatibility_id(),
        prefix_32.crypto.effective_compatibility_id()
    );
}

#[test]
fn enabled_prefix_keeps_logical_geometry() {
    let cfg = parse(&config(Some(32), "vendor-v1", &[544], 600));
    cfg.validate().unwrap();

    let geometry = cfg.geometry().unwrap();
    assert_eq!(geometry.crypto_unit_size, 512);
    assert_eq!(geometry.max_ciphertext_size, 600);
    assert_eq!(geometry.num_units(), 2048);
}

#[test]
fn prefix_length_is_zero_or_a_supported_multiple_of_sixteen() {
    for invalid in [1, 15, 17, 272] {
        let err = validation_error(&config(Some(invalid), "vendor-v1", &[512], 800));
        assert!(err.contains("random_prefix_bytes"), "{invalid}: {err}");
    }
}

#[test]
fn provider_plaintext_size_overflow_is_rejected() {
    let mut cfg = parse(&config(Some(16), "vendor-v1", &[528], 528));
    cfg.volume.crypto_unit_size = u32::MAX;

    assert!(matches!(
        cfg.provider_plaintext_size(),
        Err(ConfigError::Invalid(message)) if message.contains("overflow")
    ));
}

#[test]
fn capabilities_must_support_the_expanded_plaintext_size() {
    let unsupported = validation_error(&config(Some(32), "vendor-v1", &[512], 544));
    assert!(unsupported.contains("544") && unsupported.contains("supported_plaintext_sizes"));

    let ciphertext_too_small = validation_error(&config(Some(32), "vendor-v1", &[544], 543));
    assert!(
        ciphertext_too_small.contains("max_ciphertext_size")
            && ciphertext_too_small.contains("544")
    );
}

#[test]
fn local_provider_ciphertext_bounds_include_expanded_plaintext() {
    let local = |provider: &str, max_ciphertext: u32| {
        config(Some(32), "local-v1", &[544], max_ciphertext)
            .replace("provider = \"fake\"", &format!("provider = \"{provider}\""))
            .replace(
                "random_prefix_bytes = 32\n",
                "random_prefix_bytes = 32\nkey = { source = \"env\", name = \"test-key\" }\n",
            )
    };

    let gcm = validation_error(&local("local-aes-gcm-siv", 571));
    assert!(gcm.contains("572") && gcm.contains("max_ciphertext_size"));
    parse(&local("local-aes-gcm-siv", 572)).validate().unwrap();

    let xts = validation_error(&local("local-aes-xts", 543));
    assert!(xts.contains("544") && xts.contains("max_ciphertext_size"));
    parse(&local("local-aes-xts", 544)).validate().unwrap();
}

#[test]
fn compatibility_id_reserves_the_random_prefix_namespace() {
    let err = validation_error(&config(
        None,
        "maki-random-prefix-v1:32:vendor-v1",
        &[512],
        512,
    ));
    assert!(err.contains("reserved") && err.contains("crypto_compatibility_id"));
}

#[test]
fn derived_compatibility_id_must_fit_the_superblock() {
    let base = "x".repeat(105);
    assert_eq!(base.len(), 105);
    let err = validation_error(&config(Some(256), &base, &[768], 768));

    assert!(err.contains("effective") && err.contains("128"), "{err}");
}

#[test]
fn batch_max_bytes_must_hold_one_expanded_provider_unit() {
    let raw = config(Some(32), "vendor-v1", &[544], 544).replace(
        "[crypto.capabilities]",
        "[crypto.batch]\nmax_bytes = 543\ntarget_bytes = 543\n[crypto.capabilities]",
    );
    let err = validation_error(&raw);

    assert!(err.contains("crypto.batch.max_bytes") && err.contains("544"));
}
