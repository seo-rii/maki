//! R3 follow-up: configuration drift against an existing volume must refuse
//! attach through the daemon path, never serve with the wrong geometry.

use maki_nbdkit::daemon::{attach_from_config, create_volume_from_config_str, parse_and_validate};

const SIV_KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

struct Fixture {
    dir: tempfile::TempDir,
    root: String,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("vol").to_string_lossy().replace('\\', "/");
        Self { dir, root }
    }

    fn key_file(&self) -> String {
        let path = self.dir.path().join("vol.key");
        std::fs::write(&path, SIV_KEY).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path.to_string_lossy().replace('\\', "/")
    }

    fn config(&self, key_path: &str, unit: u32) -> String {
        format!(
            r#"
config_schema_version = 1
[volume]
name = "driftvol"
max_virtual_size = "1MiB"
device_block_size = 512
crypto_unit_size = {unit}
shard_logical_size = "128KiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "local-profile-v1"
key = {{ source = "file", name = "{key_path}" }}
[crypto.capabilities]
supported_plaintext_sizes = [{unit}]
max_ciphertext_size = {max_ct}
[backing]
root = "{root}"
"#,
            max_ct = unit + 64,
            root = self.root
        )
    }
}

/// A configuration whose crypto unit size no longer matches the volume it
/// points at builds a provider for the wrong unit; attach must refuse it
/// (the volume's geometry is authoritative) and the volume must still open
/// with the original configuration afterwards.
#[tokio::test]
async fn crypto_unit_size_drift_refuses_attach_and_leaves_the_volume_intact() {
    let fx = Fixture::new();
    let key_path = fx.key_file();
    let original = fx.config(&key_path, 4096);
    let config = parse_and_validate(&original).unwrap();
    create_volume_from_config_str(&original).unwrap();
    let engine = attach_from_config(&config).await.unwrap();
    engine.write(0, &vec![0x5A; 4096], true).await.unwrap();
    drop(engine);

    let drifted = parse_and_validate(&fx.config(&key_path, 8192)).unwrap();
    let err = attach_from_config(&drifted)
        .await
        .expect_err("a unit size that does not match the volume must refuse attach");
    let text = err.to_string();
    assert!(
        !text.to_lowercase().contains("corrupt"),
        "configuration drift is not corruption: {text}"
    );

    let engine = attach_from_config(&config).await.unwrap();
    assert_eq!(engine.read(0, 4096).await.unwrap(), vec![0x5A; 4096]);
}
