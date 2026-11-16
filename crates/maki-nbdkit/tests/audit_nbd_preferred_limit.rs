//! Audit (nbdkit-control-cli): nbdkit's `.block_size` contract requires the
//! preferred block size to be a power of two between 512 bytes and 32 MiB
//! (nbdkit-plugin(3), `.block_size`; enforced in server/plugins.c, which
//! fails the callback and therefore every NBD handshake otherwise).
//! Configuration validation bounds `nbd.minimum_io` (64 KiB) and
//! `nbd.maximum_io` (u32) for the same reason (BUG-011), but not
//! `nbd.preferred_io`: a power-of-two preferred size above 32 MiB is
//! accepted, the daemon becomes READY, and the plugin advertises it.

use maki_nbdkit::adapter::NbdAdapter;

const NBDKIT_MAX_PREFERRED: u32 = 32 * 1024 * 1024;

fn config(root: &str, socket: &str) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "audit-preferred"
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
root = "{root}"
journal_emergency_reserve_bytes = "0B"
journal_segment_size = "256MiB"
journal_max_bytes = "1GiB"
[nbd]
minimum_io = 4096
preferred_io = 67108864
maximum_io = "64MiB"
threads = 2
[control]
socket = "{socket}"
"#
    )
}

#[test]
fn preferred_io_above_nbdkit_limit_is_refused_by_validation() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("volume");
    let socket = directory.path().join("control.sock");
    let raw = config(root.to_str().unwrap(), socket.to_str().unwrap());
    let parsed = maki_nbdkit::daemon::parse_and_validate(&raw);
    match parsed {
        Err(error) => {
            // Desired behaviour: refused before creation or export, and for
            // the preferred size (not for an unrelated fixture limit).
            assert!(
                error.to_string().contains("preferred"),
                "fixture refused for an unrelated reason: {error}"
            );
        }
        Ok(cfg) => {
            let preferred = cfg.nbd_preferred_io();
            // Demonstrate that the value really reaches the NBD negotiation.
            maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();
            let path = directory.path().join("volume.toml");
            std::fs::write(&path, &raw).unwrap();
            let adapter = NbdAdapter::open_config(path.to_str().unwrap()).unwrap();
            let advertised = adapter.block_sizes();
            adapter.shutdown().unwrap();
            panic!(
                "configuration with nbd.preferred_io = {preferred} (> nbdkit's 32 MiB limit \
                 {NBDKIT_MAX_PREFERRED}) was accepted, attach succeeded and the plugin \
                 advertises block sizes {advertised:?}; nbdkit rejects this .block_size \
                 answer, so every NBD handshake fails after READY"
            );
        }
    }
}
