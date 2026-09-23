//! R4-005: the daemon hands the configured overlay bounds to the engine.

use maki_format::config::parse_config;
use maki_nbdkit::daemon::engine_options;

const CONFIG: &str = r#"
config_schema_version = 1
[volume]
name = "overlay-options"
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
[limits]
max_overlay_bytes = "300MiB"
max_overlay_entries = 40000
"#;

#[test]
fn configured_overlay_limits_reach_the_engine() {
    let cfg = parse_config(CONFIG).unwrap();
    cfg.validate().unwrap();
    let options = engine_options(&cfg);
    assert_eq!(options.limits.max_overlay_bytes, 300 << 20);
    assert_eq!(options.limits.max_overlay_entries, 40_000);
}

#[test]
fn default_overlay_limits_are_bounded_for_the_daemon() {
    let cfg = parse_config(&CONFIG.replace(
        "max_overlay_bytes = \"300MiB\"\nmax_overlay_entries = 40000\n",
        "",
    ))
    .unwrap();
    let options = engine_options(&cfg);
    assert_eq!(options.limits.max_overlay_bytes, 256 << 20);
    assert_eq!(options.limits.max_overlay_entries, 262_144);
}
