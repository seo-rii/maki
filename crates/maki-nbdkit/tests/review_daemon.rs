//! Daemon-path regression tests for review M-001 and M-008 with the real
//! local providers: a rotated key file, a changed provider type, or a
//! renamed key must refuse attach through `attach_from_config`, and the
//! `fake` provider must be refused by builds without the feature.

use maki_core::engine::AttachError;
use maki_nbdkit::daemon::{
    attach_from_config, check_provider_available, create_volume_from_config_str,
    parse_and_validate, DaemonError,
};

const XTS_KEY_A: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\
                         ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
const XTS_KEY_B: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\
                         fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
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

    fn key_file(&self, name: &str, hex: &str) -> String {
        let path = self.dir.path().join(name);
        std::fs::write(&path, hex).unwrap();
        path.to_string_lossy().replace('\\', "/")
    }

    fn config(&self, provider: &str, key_path: &str, max_ct: u32) -> String {
        format!(
            r#"
config_schema_version = 1
[volume]
name = "reviewvol"
max_virtual_size = "1MiB"
device_block_size = 512
crypto_unit_size = 4096
shard_logical_size = "128KiB"
[crypto]
provider = "{provider}"
crypto_compatibility_id = "local-profile-v1"
key = {{ source = "file", name = "{key_path}" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = {max_ct}
[backing]
root = "{root}"
"#,
            root = self.root
        )
    }
}

fn key_mismatch(err: DaemonError) -> bool {
    matches!(err, DaemonError::Attach(AttachError::KeyMismatch(_)))
}

fn identity_mismatch(err: DaemonError) -> bool {
    matches!(err, DaemonError::Attach(AttachError::IdentityMismatch(_)))
}

#[tokio::test]
async fn xts_wrong_key_is_refused_at_attach() {
    let fx = Fixture::new();
    let key_path = fx.key_file("vol.key", XTS_KEY_A);
    let raw = fx.config("local-aes-xts", &key_path, 4096);
    let config = parse_and_validate(&raw).unwrap();
    create_volume_from_config_str(&raw).unwrap();

    let engine = attach_from_config(&config).await.unwrap();
    engine.write(0, &vec![0x5A; 4096], true).await.unwrap();
    engine.checkpoint().await.unwrap();
    drop(engine);

    // Same key *name*, different material: XTS would happily decrypt the
    // slots to garbage; the canary must catch it.
    fx.key_file("vol.key", XTS_KEY_B);
    let err = attach_from_config(&config)
        .await
        .expect_err("wrong key must refuse attach");
    assert!(key_mismatch(err));

    fx.key_file("vol.key", XTS_KEY_A);
    let engine = attach_from_config(&config).await.unwrap();
    assert_eq!(engine.read(0, 4096).await.unwrap(), vec![0x5A; 4096]);
}

#[tokio::test]
async fn provider_type_change_is_refused_at_attach() {
    let fx = Fixture::new();
    let siv_key = fx.key_file("siv.key", SIV_KEY);
    let raw = fx.config("local-aes-gcm-siv", &siv_key, 4096 + 28);
    let config = parse_and_validate(&raw).unwrap();
    create_volume_from_config_str(&raw).unwrap();
    drop(attach_from_config(&config).await.unwrap());

    let xts_key = fx.key_file("siv.key", XTS_KEY_A);
    let xts = parse_and_validate(&fx.config("local-aes-xts", &xts_key, 4096)).unwrap();
    let err = attach_from_config(&xts).await.unwrap_err();
    assert!(identity_mismatch(err));
}

#[tokio::test]
async fn key_identity_change_is_refused_at_attach() {
    let fx = Fixture::new();
    let key_path = fx.key_file("vol.key", XTS_KEY_A);
    let raw = fx.config("local-aes-xts", &key_path, 4096);
    let config = parse_and_validate(&raw).unwrap();
    create_volume_from_config_str(&raw).unwrap();
    drop(attach_from_config(&config).await.unwrap());

    let renamed = fx.key_file("vol-renamed.key", XTS_KEY_A);
    let config2 = parse_and_validate(&fx.config("local-aes-xts", &renamed, 4096)).unwrap();
    let err = attach_from_config(&config2).await.unwrap_err();
    assert!(identity_mismatch(err));
}

#[test]
fn fake_provider_is_refused_without_the_feature() {
    let fx = Fixture::new();
    let raw = fx
        .config("fake", "unused", 4104)
        .replace("key = { source = \"file\", name = \"unused\" }\n", "");
    let cfg = maki_format::config::parse_config(&raw).unwrap();
    cfg.validate().unwrap();
    let err = check_provider_available(&cfg, false).unwrap_err();
    assert!(err.to_string().contains("fake"), "{err}");
    check_provider_available(&cfg, true).unwrap();
}
