//! R3-003: every ciphertext budget must accommodate a maximal allowed batch.

use maki_format::config::{parse_config, VolumeConfig};

fn config(max_items: u32, logical: u64, ciphertext: u32) -> VolumeConfig {
    parse_config(&format!(
        r#"
config_schema_version = 1
[volume]
name = "test"
max_virtual_size = "1GiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "v1"
key = {{ source = "env", name = "test-key" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = {ciphertext}
[crypto.batch]
target_items = 1
target_bytes = "4096"
max_items = {max_items}
max_bytes = "{logical}"
[backing]
root = "/test"
[nbd]
maximum_io = "4KiB"
[limits]
max_plaintext_bytes = "8KiB"
"#
    ))
    .unwrap()
}

#[test]
fn ciphertext_pending_must_hold_one_maximal_ciphertext_unit() {
    let mut cfg = config(1, 4096, 12288);
    cfg.limits.max_ciphertext_bytes.0 = 8192;
    let err = cfg
        .validate()
        .expect_err("maximum ciphertext cannot fit the pending queue");
    assert!(err.to_string().contains("max_ciphertext_bytes"));
}

#[test]
fn ciphertext_budgets_cover_the_largest_logically_allowed_batch() {
    for (items, logical) in [(2, 8192), (3, 8192), (2, 16384)] {
        let required = 2 * 4384;
        for budget in [required - 1, required, required + 1] {
            for field in [
                "max_ciphertext_bytes",
                "max_crypto_inflight_bytes",
                "max_inflight_bytes_per_endpoint",
            ] {
                let mut cfg = config(items, logical, 4384);
                match field {
                    "max_ciphertext_bytes" => cfg.limits.max_ciphertext_bytes.0 = budget,
                    "max_crypto_inflight_bytes" => cfg.limits.max_crypto_inflight_bytes.0 = budget,
                    _ => cfg.limits.max_inflight_bytes_per_endpoint.0 = budget,
                }
                let result = cfg.validate();
                assert_eq!(
                    result.is_ok(),
                    budget >= required,
                    "{field}={budget}, {items} items, logical={logical}: {result:?}"
                );
                if let Err(err) = result {
                    assert!(err.to_string().contains(field), "{err}");
                }
            }
        }
    }
}

#[test]
fn configured_byte_limits_cannot_exceed_runtime_semaphore_capacity() {
    let supported = (u32::MAX >> 1) as u64;
    let mut cfg = config(1, 4096, 4384);
    cfg.limits.max_plaintext_bytes.0 = supported;
    cfg.limits.max_ciphertext_bytes.0 = supported;
    cfg.limits.max_pending_crypto_bytes.0 = supported;
    cfg.limits.max_crypto_inflight_bytes.0 = supported;
    cfg.limits.max_inflight_bytes_per_endpoint.0 = supported;
    cfg.validate()
        .expect("largest implemented capacity is valid");
    for field in [
        "max_plaintext_bytes",
        "max_ciphertext_bytes",
        "max_pending_crypto_bytes",
        "max_crypto_inflight_bytes",
        "max_inflight_bytes_per_endpoint",
    ] {
        let mut cfg = cfg.clone();
        match field {
            "max_plaintext_bytes" => cfg.limits.max_plaintext_bytes.0 += 1,
            "max_ciphertext_bytes" => cfg.limits.max_ciphertext_bytes.0 += 1,
            "max_pending_crypto_bytes" => cfg.limits.max_pending_crypto_bytes.0 += 1,
            "max_crypto_inflight_bytes" => cfg.limits.max_crypto_inflight_bytes.0 += 1,
            _ => cfg.limits.max_inflight_bytes_per_endpoint.0 += 1,
        }
        let err = cfg
            .validate()
            .expect_err("configuration must not advertise silently truncated capacity");
        assert!(err.to_string().contains(field), "{field}: {err}");
    }
}
