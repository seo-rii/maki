//! A configuration that advertises incompatible storage geometry must fail
//! before credential loading, provider probing, or publication of READY.
#![cfg(unix)]
use maki_nbdkit::daemon::{attach_from_config, create_volume_from_config_str, parse_and_validate};
use std::os::unix::fs::PermissionsExt;

#[tokio::test]
async fn attach_rejects_changed_immutable_geometry_and_preserves_data() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("volume");
    let key = directory.path().join("key");
    let key_bytes = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
    std::fs::write(&key, key_bytes).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let raw = format!(
        r#"
config_schema_version = 1
[volume]
name = "geometry-review"
max_virtual_size = "1MiB"
device_block_size = 4096
crypto_unit_size = 4096
shard_logical_size = "128KiB"
[crypto]
provider = "local-aes-xts"
crypto_compatibility_id = "local-profile-v1"
key = {{ source = "file", name = "{}" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4096
[backing]
root = "{}"
slot_alignment = 4096
journal_emergency_reserve_bytes = "0B"
[nbd]
minimum_io = 4096
preferred_io = 4096
threads = 2
"#,
        key.display(),
        root.display()
    );
    let config = parse_and_validate(&raw).unwrap();
    create_volume_from_config_str(&raw).unwrap();
    let engine = attach_from_config(&config).await.unwrap();
    engine.write(0, &[0x5a; 4096], true).await.unwrap();
    engine.checkpoint().await.unwrap();
    drop(engine);
    for field in [
        "device_block_size",
        "crypto_unit_size",
        "shard_logical_size",
        "slot_alignment",
        "max_ciphertext_size",
        "max_virtual_size",
    ] {
        let mut changed = config.clone();
        match field {
            "device_block_size" => {
                changed.volume.device_block_size = 512;
                changed.nbd.minimum_io = 512;
            }
            "crypto_unit_size" => {
                changed.volume.crypto_unit_size = 8192;
                changed.crypto.capabilities.supported_plaintext_sizes = vec![8192];
                changed.crypto.capabilities.max_ciphertext_size = 8192;
            }
            "shard_logical_size" => changed.volume.shard_logical_size.0 = 65536,
            "slot_alignment" => changed.backing.slot_alignment = 8192,
            "max_ciphertext_size" => changed.crypto.capabilities.max_ciphertext_size = 8192,
            "max_virtual_size" => changed.volume.max_virtual_size.0 = 2097152,
            _ => unreachable!(),
        }
        changed.validate().unwrap();
        // No credential exists: geometry must be rejected before attempting
        // to construct the provider or resolving any secret.
        std::fs::remove_file(&key).unwrap();
        let result = attach_from_config(&changed).await;
        let error = match result {
            Err(error) => error.to_string(),
            Ok(_) => panic!("accepted changed {field}"),
        };
        assert!(
            error.contains(field) && error.contains("geometry"),
            "{field}: {error}"
        );
        std::fs::write(&key, key_bytes).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut operational = config.clone();
    operational.nbd.maximum_io.0 = 8192;
    operational.validate().unwrap();
    let engine = attach_from_config(&operational).await.unwrap();
    assert_eq!(engine.read(0, 4096).await.unwrap(), [0x5a; 4096]);
}
