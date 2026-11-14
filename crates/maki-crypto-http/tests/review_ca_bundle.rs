//! BUG-181: a configured CA file must contain usable certificates.
//! No connections are opened; configured roots remain additive to built-in trust.

use maki_crypto_http::HttpCryptoProvider;
use maki_crypto_local::keysource::MapKeySource;

fn configured_provider(ca: &[u8]) -> Result<HttpCryptoProvider, maki_crypto::CryptoError> {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ca.pem");
    std::fs::write(&path, ca).unwrap();
    let text = format!(
        r#"
config_schema_version = 1
[volume]
name = "ca-bundle-fixture"
max_virtual_size = "1MiB"
device_block_size = 512
crypto_unit_size = 512
shard_logical_size = "64KiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "ca-bundle-v1"
[crypto.capabilities]
supported_plaintext_sizes = [512]
max_ciphertext_size = 512
[[crypto.http.endpoint]]
name = "a"
url = "https://localhost:1"
[crypto.http.tls]
ca_file = {path:?}
[crypto.http.encrypt]
method = "POST"
path = "/encrypt"
[crypto.http.decrypt]
method = "POST"
path = "/decrypt"
[backing]
root = "/tmp/unused"
"#
    );
    let config = maki_format::config::parse_config(&text).unwrap();
    config.validate().unwrap();
    HttpCryptoProvider::from_config(&config, "https://localhost:1", &MapKeySource::new())
}

fn assert_invalid_ca(ca: &[u8]) {
    let error = configured_provider(ca).expect_err("unusable custom CA was accepted");
    assert!(
        matches!(error, maki_crypto::CryptoError::ProviderFatal(_)),
        "{error:?}"
    );
}

#[tokio::test]
async fn valid_ca_control() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    assert!(configured_provider(cert.cert.pem().as_bytes()).is_ok());
}

#[tokio::test]
async fn invalid_der_certificate_control() {
    assert_invalid_ca(b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n");
}

#[tokio::test]
async fn empty_ca_file_must_be_refused() {
    assert_invalid_ca(b"");
}

#[tokio::test]
async fn non_certificate_ca_file_must_be_refused() {
    assert_invalid_ca(b"this is not a PEM certificate\n");
}

#[tokio::test]
async fn comment_only_ca_file_must_be_refused() {
    assert_invalid_ca(b"# Root bundle, certificates accidentally omitted\n");
}

#[tokio::test]
async fn multiple_valid_certificates_are_accepted() {
    let first = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let second = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let bundle = format!(
        "# Two configured roots\n{}{}",
        first.cert.pem(),
        second.cert.pem()
    );
    assert!(configured_provider(bundle.as_bytes()).is_ok());
}

#[tokio::test]
async fn a_valid_certificate_does_not_hide_an_invalid_bundle_member() {
    let valid = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let invalid = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n";
    for bundle in [
        format!("{}{invalid}", valid.cert.pem()),
        format!("{invalid}{}", valid.cert.pem()),
    ] {
        assert_invalid_ca(bundle.as_bytes());
    }
}

#[tokio::test]
async fn malformed_pem_is_rejected() {
    assert_invalid_ca(b"-----BEGIN CERTIFICATE-----\n!not-base64!\n-----END CERTIFICATE-----\n");
}

#[tokio::test]
async fn a_private_key_is_not_a_ca_certificate() {
    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    assert_invalid_ca(identity.key_pair.serialize_pem().as_bytes());
}
