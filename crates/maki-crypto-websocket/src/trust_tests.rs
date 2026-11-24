//! The roots a WSS connector is built with hold the compiled-in public roots
//! and the configured CA. The host's trust store is covered by
//! `tests/review_default_trust.rs`, which needs a process of its own.

use rustls::pki_types::{pem::PemObject as _, CertificateDer, TrustAnchor};

use super::{trusted_roots, WsTlsOptions};
use maki_crypto::tls_trust::COMPILED_IN_ROOTS;

fn anchor(pem: &[u8]) -> TrustAnchor<'static> {
    let mut store = rustls::RootCertStore::empty();
    store
        .add(CertificateDer::from_pem_slice(pem).unwrap())
        .unwrap();
    store.roots.remove(0)
}

fn missing_compiled_in_roots(roots: &rustls::RootCertStore) -> usize {
    COMPILED_IN_ROOTS
        .iter()
        .filter(|root| !roots.roots.contains(root))
        .count()
}

#[test]
fn the_default_roots_hold_every_compiled_in_public_root() {
    assert!(!COMPILED_IN_ROOTS.is_empty());
    let roots = trusted_roots(&WsTlsOptions::default()).unwrap();
    assert_eq!(missing_compiled_in_roots(&roots), 0);
}

#[test]
fn a_configured_ca_is_added_to_the_compiled_in_roots() {
    let ca = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .unwrap()
        .cert
        .pem()
        .into_bytes();
    let roots = trusted_roots(&WsTlsOptions {
        ca_pem: Some(ca.clone()),
        ..Default::default()
    })
    .unwrap();
    assert!(roots.roots.contains(&anchor(&ca)));
    assert_eq!(missing_compiled_in_roots(&roots), 0);
}
