//! Phase 8 — TLS: CA trust, SAN verification, mTLS (SPEC §50).

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls;

use maki_crypto::{CryptoContext, CryptoProvider, ErrorClass, PlaintextUnit, SecretBuffer};
use maki_crypto_http::{
    BodySpec, FieldSource, HttpCryptoProvider, HttpProviderSpec, OpSpec, PayloadEncoding, RespKind,
    RespSpec, TlsSpec,
};

const UNIT: usize = 128;

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x99),
        format_version: 1,
        crypto_compatibility_id: "vendor-profile-v1".to_string(),
    }
}

fn caps() -> maki_crypto::CryptoCapabilities {
    maki_crypto::CryptoCapabilities {
        provider_id: "remote-https-test".to_string(),
        crypto_compatibility_id: "vendor-profile-v1".to_string(),
        supported_plaintext_sizes: vec![UNIT as u32],
        max_ciphertext_size: UNIT as u32,
        stateless: true,
        retry_safe: true,
        batch: Default::default(),
        integrity: maki_crypto::Capability::Absent,
        context_binding: maki_crypto::Capability::Absent,
        replay_protection: maki_crypto::Capability::Absent,
    }
}

fn op() -> OpSpec {
    OpSpec {
        method: "POST".to_string(),
        path: "/op".to_string(),
        headers: vec![],
        query: vec![],
        body: BodySpec::Json {
            fields: vec![(
                "/data".to_string(),
                FieldSource::Payload(PayloadEncoding::Base64),
            )],
            items_path: None,
            item_fields: vec![],
        },
        response: RespSpec {
            kind: RespKind::Json,
            data_path: Some("/result".to_string()),
            encoding: PayloadEncoding::Base64,
            items_path: None,
            item_index_path: None,
        },
    }
}

fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    });
}

/// Minimal HTTPS xor server; optionally requires a client certificate.
async fn tls_server(
    san: &str,
    require_client_cert_from: Option<&rcgen::CertifiedKey>,
) -> (std::net::SocketAddr, String /* server cert pem */) {
    install_crypto_provider();
    let server_cert = rcgen::generate_simple_self_signed(vec![san.to_string()]).unwrap();
    let cert_der = server_cert.cert.der().clone();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(server_cert.key_pair.serialize_der());

    let builder = rustls::ServerConfig::builder();
    let config = match require_client_cert_from {
        None => builder.with_no_client_auth(),
        Some(client_ca) => {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(client_ca.cert.der().clone()).unwrap();
            builder.with_client_cert_verifier(
                rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                    .build()
                    .unwrap(),
            )
        }
    }
    .with_single_cert(vec![cert_der], key_der.into())
    .unwrap();

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pem = server_cert.cert.pem();

    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(tcp).await else {
                    return;
                };
                // Read one request (headers + content-length body).
                let mut buf = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                        return;
                    }
                    buf.push(byte[0]);
                    if buf.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&buf).into_owned();
                let len: usize = head
                    .lines()
                    .find_map(|l| {
                        l.to_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse().unwrap_or(0))
                    })
                    .unwrap_or(0);
                let mut body = vec![0u8; len];
                if len > 0 && stream.read_exact(&mut body).await.is_err() {
                    return;
                }
                let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or(json!({}));
                let data = v
                    .pointer("/data")
                    .and_then(|d| d.as_str())
                    .unwrap_or_default();
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(data)
                    .unwrap_or_default();
                let xored: Vec<u8> = decoded.iter().map(|b| b ^ 0x77).collect();
                let response_body = serde_json::to_vec(&json!({
                    "result": base64::engine::general_purpose::STANDARD.encode(xored)
                }))
                .unwrap();
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    response_body.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(&response_body).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (addr, pem)
}

fn provider(url: &str, tls: TlsSpec) -> HttpCryptoProvider {
    HttpCryptoProvider::new(HttpProviderSpec {
        base_url: url.to_string(),
        encrypt: op(),
        decrypt: op(),
        capabilities: caps(),
        timeout: Duration::from_secs(5),
        max_response_bytes: 1 << 20,
        tls: Some(tls),
    })
    .unwrap()
}

fn pt() -> PlaintextUnit {
    PlaintextUnit {
        unit_index: 1,
        data: SecretBuffer::from_slice(&[0x11; UNIT]),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn custom_ca_is_trusted_and_roundtrip_works() {
    let (addr, cert_pem) = tls_server("localhost", None).await;
    let p = provider(
        &format!("https://localhost:{}", addr.port()),
        TlsSpec {
            ca_pem: Some(cert_pem.into_bytes()),
            identity_pem: None,
        },
    );
    let cts = p.encrypt_batch(&ctx(), &[pt()]).await.unwrap();
    assert_eq!(cts[0].data, vec![0x11 ^ 0x77; UNIT]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn untrusted_ca_is_rejected() {
    let (addr, _cert_pem) = tls_server("localhost", None).await;
    // No custom CA installed: the self-signed server must be rejected.
    let p = provider(
        &format!("https://localhost:{}", addr.port()),
        TlsSpec::default(),
    );
    let err = p.encrypt_batch(&ctx(), &[pt()]).await.unwrap_err();
    assert_eq!(err.class(), ErrorClass::EndpointFatal, "{err:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn san_mismatch_is_rejected() {
    // Certificate for a different name; we connect via localhost.
    let (addr, cert_pem) = tls_server("wrong-host.invalid", None).await;
    let p = provider(
        &format!("https://localhost:{}", addr.port()),
        TlsSpec {
            ca_pem: Some(cert_pem.into_bytes()),
            identity_pem: None,
        },
    );
    let err = p.encrypt_batch(&ctx(), &[pt()]).await.unwrap_err();
    assert_eq!(err.class(), ErrorClass::EndpointFatal, "{err:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_requires_and_accepts_client_identity() {
    let client_identity = rcgen::generate_simple_self_signed(vec!["maki-client".into()]).unwrap();
    let (addr, cert_pem) = tls_server("localhost", Some(&client_identity)).await;
    let url = format!("https://localhost:{}", addr.port());

    // Without a client certificate: refused.
    let p = provider(
        &url,
        TlsSpec {
            ca_pem: Some(cert_pem.clone().into_bytes()),
            identity_pem: None,
        },
    );
    assert!(p.encrypt_batch(&ctx(), &[pt()]).await.is_err());

    // With the client identity: works.
    let identity_pem = format!(
        "{}{}",
        client_identity.key_pair.serialize_pem(),
        client_identity.cert.pem()
    );
    let p = provider(
        &url,
        TlsSpec {
            ca_pem: Some(cert_pem.into_bytes()),
            identity_pem: Some(identity_pem.into_bytes()),
        },
    );
    let cts = p.encrypt_batch(&ctx(), &[pt()]).await.unwrap();
    assert_eq!(cts[0].data, vec![0x11 ^ 0x77; UNIT]);
}
