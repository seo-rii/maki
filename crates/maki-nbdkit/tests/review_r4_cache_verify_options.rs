//! R4-006 follow-up: `cache.verify_on_hit` restores "damaged payload => EIO"
//! for cache hits at the cost of the payload read. The daemon must hand the
//! setting to the engine; it is off by default (R4-006 behaviour).

use maki_format::config::parse_config;
use maki_nbdkit::daemon::engine_options;

const CONFIG: &str = r#"
config_schema_version = 1
[volume]
name = "cache-verify"
max_virtual_size = "1GiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "v1"
key = { source = "env", name = "test-key" }
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "/test"
[cache]
mode = "read"
"#;

#[test]
fn verify_on_hit_is_off_by_default() {
    let cfg = parse_config(CONFIG).unwrap();
    cfg.validate().unwrap();
    assert!(!cfg.cache.verify_on_hit);
    let cache = engine_options(&cfg).cache.expect("cache.mode = read");
    assert!(!cache.verify_on_hit);
}

#[test]
fn configured_verify_on_hit_reaches_the_engine() {
    let cfg = parse_config(&format!("{CONFIG}verify_on_hit = true\n")).unwrap();
    cfg.validate().unwrap();
    let cache = engine_options(&cfg).cache.expect("cache.mode = read");
    assert!(cache.verify_on_hit);
}
