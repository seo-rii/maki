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
fn overlay_byte_limit_must_hold_the_largest_request_twice() {
    // The largest request is nbd.maximum_io (1 MiB) plus one unit of
    // misalignment: 257 units of 4384 ciphertext bytes, charged twice
    // (latest and durable copy) = 2,253,376 bytes.
    let cfg = config("max_overlay_bytes = \"2MiB\"");
    let err = cfg.validate().expect_err("too small for the largest request");
    assert!(err.to_string().contains("limits.max_overlay_bytes"), "{err}");
    config("max_overlay_bytes = 2253376").validate().unwrap();
    config("max_overlay_bytes = 2253375")
        .validate()
        .expect_err("one byte short");
}

#[test]
fn overlay_entry_limit_must_hold_the_largest_request() {
    let cfg = config("max_overlay_entries = 256");
    let err = cfg.validate().expect_err("too few entries for the largest request");
    assert!(err.to_string().contains("limits.max_overlay_entries"), "{err}");
    config("max_overlay_entries = 257").validate().unwrap();
}

#[test]
fn the_overlay_bound_does_not_constrain_the_admission_budget() {
    // The admission budget may be far larger than the overlay bound: the
    // largest single request, not the budget, is what must fit.
    let mut cfg = config("");
    cfg.limits.max_plaintext_bytes.0 = (u32::MAX >> 1) as u64;
    cfg.limits.max_ciphertext_bytes.0 = (u32::MAX >> 1) as u64;
    cfg.validate().unwrap();
}
