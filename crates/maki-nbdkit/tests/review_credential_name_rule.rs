//! Configuration validation and the credential loader each carry the
//! credential name rule (maki-crypto-local does not depend on maki-format).
//! A name validation accepts but the loader refuses is stored as a volume's
//! immutable key identity by `volume create`, and no attach can then load
//! the key; pin the two rules to each other.

use maki_crypto_local::keysource::{FileKeySource, KeySource};
use maki_format::config::{parse_config, VolumeConfig};

fn config(source: &str, name: &str) -> VolumeConfig {
    let escaped = name
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n");
    parse_config(&format!(
        r#"
config_schema_version = 1
[volume]
name = "name-rule"
max_virtual_size = "1MiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "v1"
key = {{ source = "{source}", name = "{escaped}" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "/unused-name-rule"
"#
    ))
    .unwrap()
}

#[test]
fn validation_accepts_exactly_the_names_the_loader_accepts() {
    let directory = tempfile::tempdir().unwrap();
    let loader = FileKeySource::new(directory.path());
    let root = directory.path().to_str().unwrap().replace('\\', "/");
    for name in [
        "vol-key",
        "vol.key",
        "Vol_Key-2.hex",
        "a",
        "-",
        "a..b",
        "keys/vol-key",
        ".vol-key",
        "..",
        "vol key",
        "vol:key",
        "vol\\key",
        "vol-key\n",
        "cl\u{e9}",
    ] {
        // No file exists: an accepted name is merely unavailable.
        let error = loader.load(name).expect_err("no credential file exists");
        let loader_accepts = !error.to_string().contains("invalid credential name");
        assert_eq!(
            config("credential", name).validate().is_ok(),
            loader_accepts,
            "credential {name:?}: {error}"
        );
        if !name.contains(['/', '\\']) {
            assert_eq!(
                config("file", &format!("{root}/{name}")).validate().is_ok(),
                loader_accepts,
                "file {name:?}: {error}"
            );
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn corrected_key_path_reopens_a_volume_with_a_legacy_directory_suffix() {
    use maki_backing::FileBacking;
    use maki_format::superblock::{Superblock, CRYPTO_FORMAT_VERSION};
    use maki_nbdkit::daemon::attach_from_config;
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let key = directory.path().join("key");
    std::fs::write(&key, [0x97; 32]).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let other = directory.path().join("other");
    std::fs::hard_link(&key, &other).unwrap();
    for (n, suffix) in ["/", "/.", "//./"].into_iter().enumerate() {
        let mut cfg = config("file", key.to_str().unwrap());
        cfg.backing.root = directory
            .path()
            .join(n.to_string())
            .to_str()
            .unwrap()
            .to_owned();
        cfg.validate().unwrap();
        let backing = FileBacking::new(&cfg.backing.root).unwrap();
        let stored = Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::new_v4(),
            provider_type: cfg.crypto.provider.clone(),
            crypto_compatibility_id: cfg.crypto.effective_compatibility_id(),
            key_identity: format!("{}{suffix}", key.display()),
            geometry: cfg.geometry().unwrap(),
            format_version: CRYPTO_FORMAT_VERSION,
            created_unix: 0,
        };
        maki_format::init::create_volume(&backing, stored).unwrap();
        let engine = attach_from_config(&cfg).await.unwrap();
        engine.write(0, &[0x47; 4096], true).await.unwrap();
        engine.checkpoint().await.unwrap();
        drop(engine);
        let engine = attach_from_config(&cfg).await.unwrap();
        assert_eq!(engine.read(0, 4096).await.unwrap(), [0x47; 4096]);
        drop(engine);
        cfg.crypto.key.as_mut().unwrap().name = other.to_str().unwrap().to_owned();
        let error = attach_from_config(&cfg)
            .await
            .expect_err("different path refused");
        assert!(error.to_string().contains("key identity"));
    }
}
