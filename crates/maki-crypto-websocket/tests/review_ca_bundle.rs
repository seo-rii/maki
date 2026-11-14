//! Every configured CA must be usable; one valid root cannot hide a bad one.

use std::time::Duration;

use maki_crypto::{BatchCapability, Capability, CryptoCapabilities, CryptoError};
use maki_crypto_websocket::{WsCryptoProvider, WsProviderSpec, WsTlsOptions};

fn provider(ca: Vec<u8>) -> Result<WsCryptoProvider, CryptoError> {
    WsCryptoProvider::new_checked(WsProviderSpec {
        url: "wss://localhost:1/crypt".into(),
        capabilities: CryptoCapabilities {
            provider_id: "ca-bundle-regression".into(),
            crypto_compatibility_id: "ca-bundle-v1".into(),
            supported_plaintext_sizes: vec![512],
            max_ciphertext_size: 512,
            stateless: true,
            retry_safe: true,
            batch: BatchCapability::default(),
            integrity: Capability::Absent,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        },
        timeout: Duration::from_secs(1),
        max_frame_bytes: 4096,
        tls: Some(WsTlsOptions {
            ca_pem: Some(ca),
            ..Default::default()
        }),
    })
}

const INVALID: &str = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n";

#[test]
fn a_valid_root_is_accepted_control() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    assert!(provider(cert.cert.pem().into_bytes()).is_ok());
}

#[test]
fn multiple_valid_roots_are_accepted() {
    let first = rcgen::generate_simple_self_signed(vec!["first.invalid".into()]).unwrap();
    let second = rcgen::generate_simple_self_signed(vec!["second.invalid".into()]).unwrap();
    let bundle = format!("{}{}", first.cert.pem(), second.cert.pem());
    assert!(provider(bundle.into_bytes()).is_ok());
}

#[test]
fn empty_or_malformed_bundles_are_rejected() {
    for bundle in [
        "",
        "not a certificate",
        "# only a comment\n",
        "-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n",
    ] {
        assert!(matches!(
            provider(bundle.as_bytes().to_vec()),
            Err(CryptoError::ProviderFatal(_))
        ));
    }
}

#[test]
fn invalid_der_alone_is_rejected_control() {
    assert!(matches!(
        provider(INVALID.as_bytes().to_vec()),
        Err(CryptoError::ProviderFatal(_))
    ));
}

#[test]
fn valid_root_must_not_hide_invalid_der_in_the_same_bundle() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let rejected: Vec<_> = [
        format!("{}{INVALID}", cert.cert.pem()),
        format!("{INVALID}{}", cert.cert.pem()),
    ]
    .into_iter()
    .map(|bundle| {
        matches!(
            provider(bundle.into_bytes()),
            Err(CryptoError::ProviderFatal(_))
        )
    })
    .collect();
    assert_eq!(
        rejected,
        [true, true],
        "both CA bundle orders must reject invalid DER"
    );
}
