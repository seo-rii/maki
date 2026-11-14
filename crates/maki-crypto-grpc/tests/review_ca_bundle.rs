//! BUG-181: configured CA material must contain usable certificates.
//! Construction performs validation without opening a connection.

use maki_crypto::{Capability, CryptoCapabilities, CryptoError};
use maki_crypto_grpc::{GrpcCryptoProvider, GrpcProviderSpec, GrpcTlsConfig};
use std::time::Duration;

fn provider(ca: Vec<u8>) -> Result<GrpcCryptoProvider, CryptoError> {
    GrpcCryptoProvider::new_with_tls(
        GrpcProviderSpec {
            url: "https://localhost:1".into(),
            encrypt_path: "/maki.Crypto/EncryptBatch".into(),
            decrypt_path: "/maki.Crypto/DecryptBatch".into(),
            metadata: vec![],
            capabilities: CryptoCapabilities {
                provider_id: "ca-bundle-fixture".into(),
                crypto_compatibility_id: "ca-bundle-v1".into(),
                supported_plaintext_sizes: vec![512],
                max_ciphertext_size: 512,
                stateless: true,
                retry_safe: true,
                batch: Default::default(),
                integrity: Capability::Absent,
                context_binding: Capability::Absent,
                replay_protection: Capability::Absent,
            },
            timeout: Duration::from_secs(1),
            max_message_bytes: 4096,
        },
        GrpcTlsConfig {
            ca_certificate_pem: Some(ca),
            client_identity: None,
        },
    )
}

fn assert_invalid_ca(ca: Vec<u8>) {
    let error = provider(ca).err().expect("unusable custom CA was accepted");
    assert!(matches!(error, CryptoError::ProviderFatal(_)), "{error:?}");
}

#[tokio::test]
async fn valid_ca_control() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    assert!(provider(cert.cert.pem().into_bytes()).is_ok());
}

#[tokio::test]
async fn empty_ca_control() {
    assert_invalid_ca(Vec::new());
}

#[tokio::test]
async fn invalid_der_ca_material_must_be_refused() {
    assert_invalid_ca(b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n".to_vec());
}

#[tokio::test]
async fn malformed_pem_control() {
    assert_invalid_ca(
        b"-----BEGIN CERTIFICATE-----\n!not-base64!\n-----END CERTIFICATE-----\n".to_vec(),
    );
}

#[tokio::test]
async fn non_certificate_ca_material_must_be_refused() {
    assert_invalid_ca(b"this is not a PEM certificate\n".to_vec());
}

#[tokio::test]
async fn comment_only_ca_material_must_be_refused() {
    assert_invalid_ca(b"# Root bundle, certificates accidentally omitted\n".to_vec());
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
    assert!(provider(bundle.into_bytes()).is_ok());
}

#[tokio::test]
async fn a_valid_certificate_does_not_hide_an_invalid_bundle_member() {
    let valid = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let invalid = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n";
    for bundle in [
        format!("{}{invalid}", valid.cert.pem()),
        format!("{invalid}{}", valid.cert.pem()),
    ] {
        assert_invalid_ca(bundle.into_bytes());
    }
}

#[tokio::test]
async fn a_private_key_is_not_a_ca_certificate() {
    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    assert_invalid_ca(identity.key_pair.serialize_pem().into_bytes());
}
