//! Attach compares the configuration's crypto identity with the volume's
//! before it loads a credential, as it does the geometry.
//!
//! The provider type, the key identity and the compatibility id (which the
//! random prefix length derives) are fixed at creation (SPEC §20). Attach
//! compared them only after it had built the provider, so a changed
//! configuration loaded the key first and was then refused, or failed on the
//! key itself (a 32-byte key read as an XTS key) without naming the setting.
//! `maki check` compares the same settings with the same function, which
//! needs the comparison to stand on its own: here no key exists at all, and
//! each changed setting must still be refused as an identity mismatch that
//! names both values. A remote provider's configuration is compared the
//! same way, before any request reaches an endpoint, also when only the
//! provider is built (`build_provider_with_endpoints`), where a changed
//! compatibility id was refused as "remote configuration does not match the
//! locked volume identity/geometry" without saying which setting or values.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use maki_core::engine::AttachError;
use maki_nbdkit::daemon::{
    attach_from_config, build_provider_with_endpoints, create_volume_from_config_str,
    parse_and_validate, DaemonError,
};
use maki_test_support::http_chaos::{ResponseSpec, TestServer};

const SIV_KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn write_key(path: &std::path::Path) {
    std::fs::write(path, SIV_KEY).unwrap();
    // A file credential must be owner-only (SPEC 9).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn config(root: &str, provider: &str, compat: &str, prefix: u32, key: &str) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "identity-attach"
max_virtual_size = "1MiB"
device_block_size = 512
crypto_unit_size = 4096
shard_logical_size = "128KiB"
[crypto]
provider = "{provider}"
crypto_compatibility_id = "{compat}"
random_prefix_bytes = {prefix}
key = {{ source = "file", name = "{key}" }}
[crypto.capabilities]
supported_plaintext_sizes = [{plaintext}]
max_ciphertext_size = 4384
[backing]
root = "{root}"
journal_emergency_reserve_bytes = "0B"
"#,
        plaintext = 4096 + prefix
    )
}

#[tokio::test]
async fn a_changed_crypto_identity_is_refused_before_any_credential_is_loaded() {
    let directory = tempfile::tempdir().unwrap();
    let path = |name: &str| {
        directory
            .path()
            .join(name)
            .to_string_lossy()
            .replace('\\', "/")
    };
    let (root, key) = (path("volume"), path("vol.key"));
    let created = config(&root, "local-aes-gcm-siv", "local-profile-v1", 0, &key);
    let parsed = parse_and_validate(&created).unwrap();
    write_key(std::path::Path::new(&key));
    create_volume_from_config_str(&created).unwrap();
    let engine = attach_from_config(&parsed).await.unwrap();
    engine.write(0, &[0x3c; 4096], true).await.unwrap();
    engine.checkpoint().await.unwrap();
    drop(engine);

    let renamed = path("renamed.key");
    for (setting, changed, configured, stored) in [
        (
            "provider",
            config(&root, "local-aes-xts", "local-profile-v1", 0, &key),
            "\"local-aes-xts\"".to_owned(),
            "\"local-aes-gcm-siv\"".to_owned(),
        ),
        (
            "key identity",
            config(&root, "local-aes-gcm-siv", "local-profile-v1", 0, &renamed),
            format!("{renamed:?}"),
            format!("{key:?}"),
        ),
        (
            "compatibility id",
            config(&root, "local-aes-gcm-siv", "local-profile-v2", 0, &key),
            "\"local-profile-v2\"".to_owned(),
            "\"local-profile-v1\"".to_owned(),
        ),
        (
            "compatibility id",
            config(&root, "local-aes-gcm-siv", "local-profile-v1", 16, &key),
            "\"maki-random-prefix-v1:16:local-profile-v1\"".to_owned(),
            "\"local-profile-v1\"".to_owned(),
        ),
    ] {
        let changed = parse_and_validate(&changed).unwrap();
        // No credential exists under either name: the configuration must be
        // refused before the provider would load one.
        std::fs::remove_file(&key).unwrap();
        let error = match attach_from_config(&changed).await {
            Ok(_) => panic!("accepted a changed {setting}"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(
            matches!(error, DaemonError::Attach(AttachError::IdentityMismatch(_))),
            "{setting}: {message}"
        );
        assert!(message.contains(setting), "{message}");
        assert!(
            message.contains(&format!(
                "volume was created with {setting} {stored}, configuration says {configured}"
            )),
            "{message}"
        );
        write_key(std::path::Path::new(&key));
    }

    let engine = attach_from_config(&parsed).await.unwrap();
    assert_eq!(engine.read(0, 4096).await.unwrap(), [0x3c; 4096]);
}

fn remote_config(root: &str, url: &str, compat: &str, prefix: u32) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "identity-remote"
max_virtual_size = "1MiB"
device_block_size = 512
crypto_unit_size = 512
shard_logical_size = "64KiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "{compat}"
random_prefix_bytes = {prefix}
availability_policy = "bounded-error"
max_operation_time = "1s"
[crypto.capabilities]
supported_plaintext_sizes = [{plaintext}]
max_ciphertext_size = 528
stateless = true
[crypto.batch]
max_items = 1
target_items = 1
max_bytes = 528
target_bytes = 528
max_wait = "0ms"
[crypto.http]
max_response_bytes = 4096
timeout = "1s"
[[crypto.http.endpoint]]
name = "only"
url = "{url}"
[crypto.http.encrypt]
path = "/encrypt"
[crypto.http.decrypt]
path = "/decrypt"
[backing]
root = "{root}"
journal_emergency_reserve_bytes = "0B"
[cache]
mode = "off"
"#,
        plaintext = 512 + prefix
    )
}

#[tokio::test]
async fn a_remote_provider_is_not_contacted_for_a_configuration_the_volume_refuses() {
    let requests = Arc::new(AtomicUsize::new(0));
    let counted = requests.clone();
    let server = TestServer::start(Arc::new(move |request| {
        counted.fetch_add(1, Ordering::SeqCst);
        ResponseSpec::raw(request.body.iter().map(|byte| byte ^ 0x5a).collect())
    }))
    .await;
    let directory = tempfile::tempdir().unwrap();
    let root = directory
        .path()
        .join("volume")
        .to_string_lossy()
        .replace('\\', "/");
    let created = remote_config(&root, &server.url(), "remote-v1", 0);
    create_volume_from_config_str(&created).unwrap();
    for (changed, configured) in [
        (
            remote_config(&root, &server.url(), "remote-v2", 0),
            "\"remote-v2\"",
        ),
        (
            remote_config(&root, &server.url(), "remote-v1", 16),
            "\"maki-random-prefix-v1:16:remote-v1\"",
        ),
    ] {
        let changed = parse_and_validate(&changed).unwrap();
        let attached = attach_from_config(&changed).await.err();
        let built = build_provider_with_endpoints(&changed).await.err();
        for error in [attached, built] {
            let error = error.expect("a changed compatibility id was accepted");
            let message = error.to_string();
            assert!(
                matches!(error, DaemonError::Attach(AttachError::IdentityMismatch(_))),
                "{message}"
            );
            assert!(
                message.contains(&format!(
                    "volume was created with compatibility id \"remote-v1\", configuration \
                     says {configured}"
                )),
                "{message}"
            );
        }
    }
    assert_eq!(requests.load(Ordering::SeqCst), 0);

    // The fixture itself attaches through the endpoint it counts.
    let engine = attach_from_config(&parse_and_validate(&created).unwrap())
        .await
        .unwrap();
    engine.write(0, &[0x2d; 512], true).await.unwrap();
    assert_eq!(engine.read(0, 512).await.unwrap(), [0x2d; 512]);
    assert!(requests.load(Ordering::SeqCst) > 0);
}

/// A remote configuration over a volume another provider created, and over a
/// remote volume whose superblock records a key identity (which no remote
/// configuration has, so only a superblock written by hand or by another
/// tool carries one): attach and `build_provider_with_endpoints` compare the
/// provider type and the key identity before any endpoint is asked. They
/// refused a changed provider type as "remote configuration does not match
/// the locked volume identity/geometry", and did not compare the key
/// identity before probing the endpoint.
#[tokio::test]
async fn a_remote_configuration_is_compared_by_provider_type_and_key_identity() {
    use maki_backing::FileBacking;
    use maki_format::superblock::{Superblock, CRYPTO_FORMAT_VERSION};

    let requests = Arc::new(AtomicUsize::new(0));
    let counted = requests.clone();
    let server = TestServer::start(Arc::new(move |request| {
        counted.fetch_add(1, Ordering::SeqCst);
        ResponseSpec::raw(request.body.iter().map(|byte| byte ^ 0x5a).collect())
    }))
    .await;
    let directory = tempfile::tempdir().unwrap();
    for (index, (provider_type, key_identity, refusal)) in [
        (
            "remote-grpc",
            "",
            "volume was created with provider \"remote-grpc\", configuration says \"remote-http\"",
        ),
        (
            "local-aes-gcm-siv",
            "/etc/maki/vol.key",
            "volume was created with provider \"local-aes-gcm-siv\", configuration says \
             \"remote-http\"",
        ),
        (
            "remote-http",
            "stray-key",
            "volume was created with key identity \"stray-key\", configuration says \"\"",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let root = directory
            .path()
            .join(index.to_string())
            .to_string_lossy()
            .replace('\\', "/");
        let config =
            parse_and_validate(&remote_config(&root, &server.url(), "remote-v1", 0)).unwrap();
        let stored = Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::new_v4(),
            provider_type: provider_type.into(),
            crypto_compatibility_id: config.crypto.effective_compatibility_id(),
            key_identity: key_identity.into(),
            geometry: config.geometry().unwrap(),
            format_version: CRYPTO_FORMAT_VERSION,
            created_unix: 0,
        };
        maki_format::init::create_volume(&FileBacking::new(&root).unwrap(), stored).unwrap();
        let attached = attach_from_config(&config).await.err();
        let built = build_provider_with_endpoints(&config).await.err();
        for error in [attached, built] {
            let error =
                error.unwrap_or_else(|| panic!("{provider_type} {key_identity:?} accepted"));
            let message = error.to_string();
            assert!(
                matches!(error, DaemonError::Attach(AttachError::IdentityMismatch(_))),
                "{message}"
            );
            assert!(message.contains(refusal), "{message}");
        }
    }
    assert_eq!(requests.load(Ordering::SeqCst), 0);
}
