use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use maki_crypto::{Capability, CryptoCapabilities, CryptoContext, PlaintextUnit, SecretBuffer};
use maki_crypto_websocket::{WsCryptoProvider, WsProviderSpec, WsTlsOptions};
use serde_json::json;
use tokio_rustls::rustls;

pub async fn server() -> (std::net::SocketAddr, Vec<u8>, tokio::task::JoinHandle<bool>) {
    let identity = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let ca = identity.cert.pem().into_bytes();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS12])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![identity.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(identity.key_pair.serialize_der()).into(),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let Ok(tls) = acceptor.accept(tcp).await else {
            return false;
        };
        let mut ws = tokio_tungstenite::accept_async(tls).await.unwrap();
        let request = ws.next().await.unwrap().unwrap().into_text().unwrap();
        let request: serde_json::Value = serde_json::from_str(&request).unwrap();
        ws.send(
            json!({"id": request["id"], "items": request["items"]})
                .to_string()
                .into(),
        )
        .await
        .unwrap();
        true
    });
    (address, ca, task)
}

pub fn provider(address: std::net::SocketAddr, tls: Option<WsTlsOptions>) -> WsCryptoProvider {
    WsCryptoProvider::new_checked(WsProviderSpec {
        url: format!("wss://{address}/"),
        capabilities: CryptoCapabilities {
            provider_id: "tls-provider-selection".into(),
            crypto_compatibility_id: "tls-provider-selection".into(),
            supported_plaintext_sizes: vec![64],
            max_ciphertext_size: 64,
            stateless: true,
            retry_safe: false,
            batch: Default::default(),
            integrity: Capability::Absent,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        },
        timeout: Duration::from_secs(5),
        max_frame_bytes: 4096,
        tls,
    })
    .unwrap()
}

pub fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(7),
        format_version: 1,
        crypto_compatibility_id: "tls-provider-selection".into(),
    }
}

pub fn plaintext() -> PlaintextUnit {
    PlaintextUnit {
        unit_index: 3,
        data: SecretBuffer::from_slice(&[0x31; 64]),
    }
}
