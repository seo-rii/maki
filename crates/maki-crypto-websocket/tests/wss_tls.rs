use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio_rustls::rustls;

use maki_crypto::{CryptoContext, CryptoProvider, ErrorClass, PlaintextUnit, SecretBuffer};
use maki_crypto_websocket::{WsCryptoProvider, WsProviderSpec, WsTlsOptions};

const UNIT: usize = 64;

fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn caps() -> maki_crypto::CryptoCapabilities {
    maki_crypto::CryptoCapabilities {
        provider_id: "wss-test".into(),
        crypto_compatibility_id: "wss-v1".into(),
        supported_plaintext_sizes: vec![UNIT as u32],
        max_ciphertext_size: UNIT as u32,
        stateless: true,
        retry_safe: false,
        batch: Default::default(),
        integrity: maki_crypto::Capability::Absent,
        context_binding: maki_crypto::Capability::Absent,
        replay_protection: maki_crypto::Capability::Absent,
    }
}

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(7),
        format_version: 1,
        crypto_compatibility_id: "wss-v1".into(),
    }
}

fn pt() -> PlaintextUnit {
    PlaintextUnit {
        unit_index: 3,
        data: SecretBuffer::from_slice(&[0x31; UNIT]),
    }
}

struct ServerIdentity {
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    cert_der: rustls::pki_types::CertificateDer<'static>,
    key_der: rustls::pki_types::PrivateKeyDer<'static>,
}

fn identity(san: &str) -> ServerIdentity {
    let certified = rcgen::generate_simple_self_signed(vec![san.into()]).unwrap();
    ServerIdentity {
        cert_pem: certified.cert.pem().into_bytes(),
        key_pem: certified.key_pair.serialize_pem().into_bytes(),
        cert_der: certified.cert.der().clone(),
        key_der: rustls::pki_types::PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der())
            .into(),
    }
}

#[allow(clippy::result_large_err)] // tungstenite fixes the handshake callback's error type
async fn wss_server(
    server: ServerIdentity,
    client_ca: Option<rustls::pki_types::CertificateDer<'static>>,
    expected_uri: &'static str,
) -> std::net::SocketAddr {
    install_crypto_provider();
    // TLS 1.2 is the oldest protocol rustls supports. Constraining the test
    // peer to it verifies the client's lower bound remains interoperable.
    let builder = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12]);
    let config = match client_ca {
        None => builder.with_no_client_auth(),
        Some(cert) => {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert).unwrap();
            builder.with_client_cert_verifier(
                rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                    .build()
                    .unwrap(),
            )
        }
    }
    .with_single_cert(vec![server.cert_der], server.key_der)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(
                    tls,
                    move |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                          response| {
                        assert_eq!(
                            request.uri().path_and_query().map(|value| value.as_str()),
                            Some(expected_uri)
                        );
                        Ok(response)
                    },
                )
                .await
                else {
                    return;
                };
                while let Some(Ok(message)) = ws.next().await {
                    let Ok(text) = message.into_text() else {
                        continue;
                    };
                    let Ok(request) = serde_json::from_str::<serde_json::Value>(&text) else {
                        continue;
                    };
                    let items = request["items"].as_array().unwrap().iter().map(|item| {
                        let data = base64::engine::general_purpose::STANDARD
                            .decode(item["data"].as_str().unwrap()).unwrap();
                        json!({"unit": item["unit"], "data": base64::engine::general_purpose::STANDARD.encode(data)})
                    }).collect::<Vec<_>>();
                    let _ = ws
                        .send(
                            json!({"id": request["id"], "items": items})
                                .to_string()
                                .into(),
                        )
                        .await;
                }
            });
        }
    });
    addr
}

fn provider(port: u16, tls: Option<WsTlsOptions>) -> WsCryptoProvider {
    provider_at(port, "/", tls)
}

fn provider_at(port: u16, path: &str, tls: Option<WsTlsOptions>) -> WsCryptoProvider {
    WsCryptoProvider::new(WsProviderSpec {
        url: format!("wss://localhost:{port}{path}"),
        capabilities: caps(),
        timeout: Duration::from_secs(2),
        max_frame_bytes: 64 * 1024,
        tls,
    })
}

#[test]
fn uppercase_wss_scheme_accepts_tls_options() {
    let result = WsCryptoProvider::new_checked(WsProviderSpec {
        url: "WSS://localhost:443/crypto".into(),
        capabilities: caps(),
        timeout: Duration::from_secs(2),
        max_frame_bytes: 64 * 1024,
        tls: Some(WsTlsOptions::default()),
    });
    assert!(result.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn custom_ca_and_hostname_verification_allow_wss_roundtrip() {
    let server = identity("localhost");
    let ca_pem = server.cert_pem.clone();
    let addr = wss_server(server, None, "/crypto?profile=wss-v1").await;
    let result = provider_at(
        addr.port(),
        "/crypto?profile=wss-v1",
        Some(WsTlsOptions {
            ca_pem: Some(ca_pem),
            ..Default::default()
        }),
    )
    .encrypt_batch(&ctx(), &[pt()])
    .await
    .unwrap();
    assert_eq!(result[0].data, vec![0x31; UNIT]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn untrusted_ca_and_wrong_hostname_are_rejected() {
    let server = identity("localhost");
    let addr = wss_server(server, None, "/").await;
    assert!(provider(addr.port(), None)
        .encrypt_batch(&ctx(), &[pt()])
        .await
        .is_err());

    let server = identity("wrong.invalid");
    let ca_pem = server.cert_pem.clone();
    let addr = wss_server(server, None, "/").await;
    assert!(provider(
        addr.port(),
        Some(WsTlsOptions {
            ca_pem: Some(ca_pem),
            ..Default::default()
        })
    )
    .encrypt_batch(&ctx(), &[pt()])
    .await
    .is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_requires_and_accepts_a_client_certificate_key_pair() {
    let client = identity("maki-client");
    let client_ca = client.cert_der.clone();
    let server = identity("localhost");
    let ca_pem = server.cert_pem.clone();
    let addr = wss_server(server, Some(client_ca), "/").await;
    assert!(provider(
        addr.port(),
        Some(WsTlsOptions {
            ca_pem: Some(ca_pem.clone()),
            ..Default::default()
        })
    )
    .encrypt_batch(&ctx(), &[pt()])
    .await
    .is_err());

    let client_cert_pem = client.cert_pem.clone();
    let client_key_pem = client.key_der.secret_der().to_vec();
    // DER is deliberately invalid for a PEM-only option.
    let malformed = provider(
        addr.port(),
        Some(WsTlsOptions {
            ca_pem: Some(ca_pem.clone()),
            client_cert_pem: Some(client_cert_pem.clone()),
            client_key_pem: Some(Arc::new(SecretBuffer::from_vec(client_key_pem))),
        }),
    )
    .encrypt_batch(&ctx(), &[pt()])
    .await
    .unwrap_err();
    assert_eq!(malformed.class(), ErrorClass::ProviderFatal);

    let accepted_identity = WsTlsOptions {
        ca_pem: Some(ca_pem),
        client_cert_pem: Some(client.cert_pem),
        client_key_pem: Some(Arc::new(SecretBuffer::from_vec(client.key_pem))),
    };
    let result = provider(addr.port(), Some(accepted_identity))
        .encrypt_batch(&ctx(), &[pt()])
        .await
        .unwrap();
    assert_eq!(result[0].data, vec![0x31; UNIT]);
}

#[tokio::test]
async fn incomplete_identity_and_tls_on_plain_ws_are_configuration_errors() {
    let missing_key = provider(
        9,
        Some(WsTlsOptions {
            client_cert_pem: Some(b"certificate".to_vec()),
            ..Default::default()
        }),
    )
    .encrypt_batch(&ctx(), &[pt()])
    .await
    .unwrap_err();
    assert_eq!(missing_key.class(), ErrorClass::ProviderFatal);

    let p = WsCryptoProvider::new(WsProviderSpec {
        url: "ws://127.0.0.1:9".into(),
        capabilities: caps(),
        timeout: Duration::from_millis(100),
        max_frame_bytes: 1024,
        tls: Some(WsTlsOptions::default()),
    });
    assert_eq!(
        p.encrypt_batch(&ctx(), &[pt()]).await.unwrap_err().class(),
        ErrorClass::ProviderFatal
    );
}
