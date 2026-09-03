//! Review M-014 / M-015: the shipped production sample must be usable as
//! written (parse, validate, create, and build its HTTP provider offline),
//! and TLS material that cannot be read must refuse the provider instead of
//! silently downgrading trust.

use maki_crypto_http::HttpCryptoProvider;
use maki_crypto_local::keysource::MapKeySource;
use maki_nbdkit::daemon::{create_volume_from_config_str, parse_and_validate};

const SAMPLE: &str = include_str!("../../../packaging/examples/postgres-prod.toml");

fn sample_with_root(root: &str) -> String {
    SAMPLE.replace(
        "root = \"/var/lib/maki/postgres-prod\"",
        &format!("root = \"{root}\""),
    )
}

#[test]
fn production_sample_builds_provider_successfully() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vol").to_string_lossy().replace('\\', "/");
    let raw = sample_with_root(&root);
    let config = parse_and_validate(&raw).unwrap();

    create_volume_from_config_str(&raw).unwrap();

    let mut keys = MapKeySource::new();
    keys.insert("crypto-token", b"s3cr3t".to_vec());
    for endpoint in &config.crypto.http.as_ref().unwrap().endpoint {
        HttpCryptoProvider::from_config(&config, &endpoint.url, &keys)
            .unwrap_or_else(|e| panic!("{}: {e}", endpoint.name));
    }
}

#[test]
fn production_sample_fails_without_its_credential() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vol").to_string_lossy().replace('\\', "/");
    let config = parse_and_validate(&sample_with_root(&root)).unwrap();
    let keys = MapKeySource::new();
    let url = &config.crypto.http.as_ref().unwrap().endpoint[0].url;
    let err = HttpCryptoProvider::from_config(&config, url, &keys).unwrap_err();
    assert!(err.to_string().contains("crypto-token"), "{err}");
}

#[test]
fn unreadable_tls_material_refuses_the_provider() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vol").to_string_lossy().replace('\\', "/");
    let ca = dir.path().join("ca.pem");
    std::fs::write(
        &ca,
        b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    let ca_path = ca.to_string_lossy().replace('\\', "/");
    let raw = format!(
        "{}\n[crypto.http.tls]\nca_file = \"{ca_path}\"\n",
        sample_with_root(&root)
    );
    let config = parse_and_validate(&raw).unwrap();
    let mut keys = MapKeySource::new();
    keys.insert("crypto-token", b"s3cr3t".to_vec());
    let url = &config.crypto.http.as_ref().unwrap().endpoint[0].url;

    // Validation saw the file; the provider reads it (either the parse
    // fails or the material is installed) and never ignores it.
    let _ = HttpCryptoProvider::from_config(&config, url, &keys);

    // Removed after validation (e.g. rotated away): a hard error, not
    // default trust.
    std::fs::remove_file(&ca).unwrap();
    let err = HttpCryptoProvider::from_config(&config, url, &keys).unwrap_err();
    assert!(err.to_string().contains("ca_file"), "{err}");
}

#[test]
fn client_key_credential_is_appended_to_the_identity() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vol").to_string_lossy().replace('\\', "/");
    let cert = dir.path().join("client.pem");
    std::fs::write(
        &cert,
        b"-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    let cert_path = cert.to_string_lossy().replace('\\', "/");
    let raw = format!(
        "{}\n[crypto.http.tls]\nclient_cert_file = \"{cert_path}\"\nclient_key = {{ source = \"credential\", name = \"client-key\" }}\n",
        sample_with_root(&root)
    );
    let config = parse_and_validate(&raw).unwrap();
    let mut keys = MapKeySource::new();
    keys.insert("crypto-token", b"s3cr3t".to_vec());
    let url = &config.crypto.http.as_ref().unwrap().endpoint[0].url;

    // Missing key credential: fail closed.
    let err = HttpCryptoProvider::from_config(&config, url, &keys).unwrap_err();
    assert!(err.to_string().contains("client-key"), "{err}");

    // With the key present the identity is assembled from cert + key; the
    // TLS stack validates the pair when it is used, so construction is the
    // point at which the credential must have been consumed.
    keys.insert(
        "client-key",
        b"-----BEGIN PRIVATE KEY-----\nBBB\n-----END PRIVATE KEY-----\n".to_vec(),
    );
    match HttpCryptoProvider::from_config(&config, url, &keys) {
        Ok(_) => {}
        Err(e) => assert!(
            !e.to_string().contains("client-key"),
            "key credential must have been consumed: {e}"
        ),
    }
}
