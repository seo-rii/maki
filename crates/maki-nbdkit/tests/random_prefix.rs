use maki_crypto::{CryptoContext, CryptoError, CryptoProvider, PlaintextUnit, SecretBuffer};
use maki_crypto_local::keysource::MapKeySource;
use maki_crypto_local::AesGcmSivProvider;
use maki_nbdkit::daemon::{
    attach_from_config, build_provider, create_volume_from_config_str,
    create_volume_with_discard_from_config_str, parse_and_validate,
};

const UNIT: usize = 4096;
const BASE_PROFILE: &str = "prefix-local-v1";

#[test]
fn scheduler_aggregation_respects_expanded_provider_byte_limit() {
    let directory = fixture();
    let raw = config(&directory, 256).replace(
        "[crypto.capabilities]",
        "[crypto.batch]\nmax_items = 32\ntarget_items = 32\nmax_bytes = 131072\ntarget_bytes = 131072\n[crypto.capabilities]",
    );
    let parsed = parse_and_validate(&raw).unwrap();
    let scheduler = maki_nbdkit::daemon::scheduler_config(&parsed);
    // 32 logical units fit 128 KiB, but only 30 expanded 4352-byte
    // units fit the same provider cap. Concurrent requests may coalesce.
    assert_eq!(scheduler.max_items, 30);
    assert_eq!(scheduler.max_bytes, 30 * UNIT as u64);
    assert!(scheduler.target_items <= scheduler.max_items);
    assert!(scheduler.target_bytes <= scheduler.max_bytes);
}

fn fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    let key = directory.path().join("key");
    std::fs::write(&key, [0x85; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    directory
}

fn config(directory: &tempfile::TempDir, prefix: u32) -> String {
    let key = directory
        .path()
        .join("key")
        .to_string_lossy()
        .replace('\\', "/");
    let root = directory
        .path()
        .join("backing")
        .to_string_lossy()
        .replace('\\', "/");
    format!(
        r#"
config_schema_version = 1
[volume]
name = "prefix"
max_virtual_size = "64KiB"
device_block_size = 512
crypto_unit_size = 4096
shard_logical_size = "64KiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "{BASE_PROFILE}"
random_prefix_bytes = {prefix}
key = {{ source = "file", name = "{key}" }}
[crypto.capabilities]
supported_plaintext_sizes = [{wire_unit}]
max_ciphertext_size = 4400
integrity = "verified"
context_binding = "verified"
[backing]
root = "{root}"
journal_segment_size = "64KiB"
journal_max_bytes = "1MiB"
checkpoint_reserve_bytes = "64KiB"
journal_emergency_reserve_bytes = "0B"
[nbd]
minimum_io = 512
preferred_io = 4096
maximum_io = "64KiB"
threads = 2
"#,
        wire_unit = UNIT as u32 + prefix,
    )
}

#[tokio::test]
async fn local_prefix_is_inside_authenticated_encryption_and_roundtrips() {
    let directory = fixture();
    let raw = config(&directory, 32);
    let superblock = create_volume_from_config_str(&raw).unwrap();
    assert_eq!(
        superblock.crypto_compatibility_id,
        "maki-random-prefix-v1:32:prefix-local-v1"
    );
    assert_eq!(superblock.geometry.crypto_unit_size, UNIT as u32);
    let config = parse_and_validate(&raw).unwrap();
    let provider = build_provider(&config).await.unwrap();
    let context = CryptoContext {
        volume_uuid: superblock.volume_uuid,
        format_version: superblock.format_version,
        crypto_compatibility_id: superblock.crypto_compatibility_id,
    };
    let inputs = [PlaintextUnit {
        unit_index: 3,
        data: SecretBuffer::from_slice(&[0x37; UNIT]),
    }];
    let first = provider.encrypt_batch(&context, &inputs).await.unwrap();
    let second = provider.encrypt_batch(&context, &inputs).await.unwrap();
    assert_eq!(first[0].data.len(), UNIT + 32 + 28);

    // Independently decrypt the provider's envelope to inspect the actual
    // input to AES; changing GCM-SIV's existing nonce alone cannot satisfy
    // the random-prefix assertion.
    let mut keys = MapKeySource::new();
    keys.insert("key", vec![0x85; 32]);
    let raw_provider =
        AesGcmSivProvider::new(&keys, "key", (UNIT + 32) as u32, BASE_PROFILE).unwrap();
    let raw_context = CryptoContext {
        crypto_compatibility_id: BASE_PROFILE.into(),
        ..context.clone()
    };
    let first_plain = raw_provider
        .decrypt_batch(&raw_context, &first)
        .await
        .unwrap();
    let second_plain = raw_provider
        .decrypt_batch(&raw_context, &second)
        .await
        .unwrap();
    assert_eq!(&first_plain[0].data.expose()[32..], inputs[0].data.expose());
    assert_eq!(
        &second_plain[0].data.expose()[32..],
        inputs[0].data.expose()
    );
    assert_ne!(
        &first_plain[0].data.expose()[..32],
        &second_plain[0].data.expose()[..32]
    );
    let decoded = provider.decrypt_batch(&context, &first).await.unwrap();
    assert_eq!(decoded[0].data.expose(), inputs[0].data.expose());

    let mut changed = first;
    changed[0].data[12] ^= 1;
    assert!(matches!(
        provider.decrypt_batch(&context, &changed).await,
        Err(CryptoError::Integrity(_))
    ));
}

#[tokio::test]
async fn prefixed_volume_preserves_rmw_discard_and_restart() {
    let directory = fixture();
    let raw = config(&directory, 32);
    create_volume_with_discard_from_config_str(&raw).unwrap();
    let parsed = parse_and_validate(&raw).unwrap();
    let engine = attach_from_config(&parsed).await.unwrap();
    let mut expected = vec![0x27; 2 * UNIT];
    engine.write(0, &expected, true).await.unwrap();
    expected[512..1024].fill(0xb4);
    engine.write(512, &[0xb4; 512], true).await.unwrap();
    engine.trim(UNIT as u64, UNIT, true).await.unwrap();
    expected[UNIT..].fill(0);
    engine.checkpoint().await.unwrap();
    drop(engine);

    let engine = attach_from_config(&parsed).await.unwrap();
    assert_eq!(engine.read(0, expected.len()).await.unwrap(), expected);
    engine
        .write(UNIT as u64, &[0x61; UNIT], true)
        .await
        .unwrap();
    drop(engine);
    let engine = attach_from_config(&parsed).await.unwrap();
    assert_eq!(
        engine.read(UNIT as u64, UNIT).await.unwrap(),
        vec![0x61; UNIT]
    );
}

#[tokio::test]
async fn changing_or_removing_prefix_refuses_existing_volume_even_with_same_geometry() {
    for original in [0, 32] {
        let directory = fixture();
        let raw = config(&directory, original);
        create_volume_from_config_str(&raw).unwrap();
        let parsed = parse_and_validate(&raw).unwrap();
        let engine = attach_from_config(&parsed).await.unwrap();
        engine.write(0, &[0x72; UNIT], true).await.unwrap();
        engine.checkpoint().await.unwrap();
        drop(engine);
        for changed in [0, 32, 64].into_iter().filter(|value| *value != original) {
            let changed = parse_and_validate(&config(&directory, changed)).unwrap();
            assert_eq!(changed.geometry().unwrap(), parsed.geometry().unwrap());
            assert!(attach_from_config(&changed).await.is_err());
        }
        let engine = attach_from_config(&parsed).await.unwrap();
        assert_eq!(engine.read(0, UNIT).await.unwrap(), vec![0x72; UNIT]);
    }
}
