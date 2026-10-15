//! Keep this in its own test process: no fixture installs a global provider.

#[path = "common/tls_provider.rs"]
mod common;

use common::{context, plaintext, provider, server};
use maki_crypto::CryptoProvider;
use maki_crypto_websocket::WsTlsOptions;
use tokio_rustls::rustls;

fn assert_no_implicit_provider() {
    // Both are compiled in through the workspace's ring choice and the TLS
    // test dependency's default aws-lc backend. Neither is installed globally.
    let _ = rustls::crypto::ring::default_provider();
    let _ = rustls::crypto::aws_lc_rs::default_provider();
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
}

#[tokio::test]
async fn configured_ca_roundtrip_does_not_need_a_global_provider() {
    assert_no_implicit_provider();
    let (address, ca, peer) = server().await;
    let provider = provider(
        address,
        Some(WsTlsOptions {
            ca_pem: Some(ca),
            ..Default::default()
        }),
    );
    let result = provider
        .encrypt_batch(&context(), &[plaintext()])
        .await
        .unwrap();
    assert_eq!(result[0].data, vec![0x31; 64]);
    assert!(peer.await.unwrap());
    assert_no_implicit_provider();
}

#[tokio::test]
async fn default_roots_reject_untrusted_peer_without_a_global_provider() {
    assert_no_implicit_provider();
    let (address, _, peer) = server().await;
    let result = provider(address, None)
        .encrypt_batch(&context(), &[plaintext()])
        .await;
    assert!(
        result.is_err(),
        "untrusted TLS certificate must be rejected"
    );
    assert!(!peer.await.unwrap());
    assert_no_implicit_provider();
}
