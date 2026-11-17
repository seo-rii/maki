//! nbdkit's `.block_size` contract (nbdkit-plugin(3)) requires the preferred
//! block size to be a power of two between 512 bytes and 32 MiB; nbdkit
//! fails the callback otherwise, and with it every NBD_OPT_GO / NBD_OPT_INFO
//! handshake. Validation bounded `nbd.minimum_io` and `nbd.maximum_io` for
//! the same reason but not `nbd.preferred_io`: a larger power of two was
//! accepted, the daemon became READY and every client handshake failed.

use maki_format::config::{parse_config, VolumeConfig};

const NBDKIT_MAX_PREFERRED: u32 = 32 << 20;

fn config(preferred: Option<u32>, maximum: &str) -> VolumeConfig {
    let preferred = preferred
        .map(|value| format!("preferred_io = {value}\n"))
        .unwrap_or_default();
    parse_config(&format!(
        r#"
config_schema_version = 1
[volume]
name = "preferred-limit"
max_virtual_size = "256MiB"
device_block_size = 512
crypto_unit_size = 4096
shard_logical_size = "64MiB"
[crypto]
provider = "fake"
crypto_compatibility_id = "test-profile-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4104
[limits]
max_plaintext_bytes = "256MiB"
max_ciphertext_bytes = "512MiB"
max_overlay_bytes = "0B"
max_overlay_entries = 0
max_journal_pending_bytes = "128MiB"
[backing]
root = "/unused-preferred-limit"
journal_emergency_reserve_bytes = "0B"
journal_segment_size = "256MiB"
journal_max_bytes = "1GiB"
[nbd]
minimum_io = 4096
{preferred}maximum_io = "{maximum}"
"#
    ))
    .unwrap()
}

#[test]
fn a_preferred_size_above_the_nbdkit_limit_is_refused() {
    for (preferred, maximum) in [(64 << 20, "64MiB"), (1 << 30, "64MiB")] {
        let error = config(Some(preferred), maximum)
            .validate()
            .expect_err("nbdkit refuses this preferred block size at every handshake");
        let error = error.to_string();
        assert!(error.contains("nbd.preferred_io"), "{preferred}: {error}");
        assert!(error.contains("33554432"), "{preferred}: {error}");
    }
}

#[test]
fn preferred_sizes_within_the_nbdkit_range_still_validate() {
    for (preferred, maximum) in [
        (Some(NBDKIT_MAX_PREFERRED), "64MiB"),
        (Some(NBDKIT_MAX_PREFERRED), "32MiB"),
        (Some(4096), "1MiB"),
        // Unset: the crypto unit, raised to minimum_io.
        (None, "64MiB"),
    ] {
        let config = config(preferred, maximum);
        config
            .validate()
            .unwrap_or_else(|e| panic!("{preferred:?}/{maximum}: {e}"));
        assert!((512..=NBDKIT_MAX_PREFERRED).contains(&config.nbd_preferred_io()));
    }
}
