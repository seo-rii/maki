//! R4-005: `limits.max_overlay_bytes` and `limits.max_overlay_entries` bound
//! the in-memory ciphertext overlay. They default to values that keep the
//! daemon's RAM budget independent of the multi-GiB journal, may be set to 0
//! to disable the bound explicitly, and must leave room for one maximal
//! request or writes could never be admitted.

use maki_format::config::{parse_config, VolumeConfig};

fn config(extra_limits: &str) -> VolumeConfig {
    parse_config(&format!(
        r#"
config_schema_version = 1
[volume]
name = "test"
max_virtual_size = "1GiB"
crypto_unit_size = 4096
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "v1"
key = {{ source = "env", name = "test-key" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "/test"
[nbd]
maximum_io = "1MiB"
[limits]
max_plaintext_bytes = "128MiB"
max_ciphertext_bytes = "160MiB"
{extra_limits}
"#
    ))
    .unwrap()
}

#[test]
fn overlay_limits_have_ram_sized_defaults() {
    let cfg = config("");
    cfg.validate().unwrap();
    assert_eq!(cfg.limits.max_overlay_bytes.0, 256 << 20);
    assert_eq!(cfg.limits.max_overlay_entries, 262_144);
}

#[test]
fn zero_disables_an_overlay_limit_explicitly() {
    let cfg = config("max_overlay_bytes = 0\nmax_overlay_entries = 0");
    cfg.validate().unwrap();
    assert_eq!(cfg.limits.max_overlay_bytes.0, 0);
    assert_eq!(cfg.limits.max_overlay_entries, 0);
}

#[test]
fn overlay_byte_limit_must_hold_one_maximal_request_twice() {
    // A request is charged twice at most (latest and durable copy), so the
    // bound must be at least 2 * max_plaintext_bytes' worth of ciphertext.
    let cfg = config("max_overlay_bytes = \"200MiB\"");
    let err = cfg.validate().expect_err("too small for one maximal request");
    assert!(err.to_string().contains("limits.max_overlay_bytes"), "{err}");
    config("max_overlay_bytes = \"256MiB\"").validate().unwrap();
}

#[test]
fn overlay_entry_limit_must_hold_one_maximal_request() {
    // 128 MiB / 4 KiB = 32768 units in one maximal request.
    let cfg = config("max_overlay_entries = 1000");
    let err = cfg.validate().expect_err("too few entries for one maximal request");
    assert!(err.to_string().contains("limits.max_overlay_entries"), "{err}");
    config("max_overlay_entries = 32769").validate().unwrap();
}
