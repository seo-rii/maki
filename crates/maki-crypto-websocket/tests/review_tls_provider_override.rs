//! An embedder's explicit process provider must remain authoritative.

#[path = "common/tls_provider.rs"]
mod common;

use common::{context, plaintext, provider, server};
use maki_crypto::CryptoProvider;
use maki_crypto_websocket::WsTlsOptions;
use tokio_rustls::rustls;

#[tokio::test]
async fn installed_provider_restrictions_are_preserved() {
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
    let mut installed = rustls::crypto::ring::default_provider();
    installed
        .cipher_suites
        .retain(|suite| suite.version() == &rustls::version::TLS13);
    installed.install_default().unwrap();

    // The fixture explicitly allows only TLS 1.2. Ignoring the embedder's
    // TLS 1.3-only suites would incorrectly let this roundtrip succeed.
    let (address, ca, peer) = server().await;
    let result = provider(
        address,
        Some(WsTlsOptions {
            ca_pem: Some(ca),
            ..Default::default()
        }),
    )
    .encrypt_batch(&context(), &[plaintext()])
    .await;
    assert!(
        result.is_err(),
        "the installed TLS suite policy was ignored"
    );
    assert!(!peer.await.unwrap());
}
