//! Audit round 8 (merge-interactions): since #369 the HTTP transport builds
//! its rustls configuration itself and hands it to reqwest. The gRPC
//! transport pins how an IP-literal endpoint is verified
//! (`review_ip_literal_tls.rs`: against the certificate's IP addresses,
//! never as a DNS name); nothing pins it for HTTP. This probe checks that an
//! `https://127.0.0.1` and an `https://[::1]` endpoint are verified against
//! the certificate's IP subject alternative names, and that a certificate
//! for another address or for a DNS name only is refused, as in gRPC.
//! Not part of the maintained suite.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    ErrorClass, PlaintextUnit, SecretBuffer,
};
use maki_crypto_http::{
    BodySpec, HttpCryptoProvider, HttpProviderSpec, OpSpec, PayloadEncoding, RespKind, RespSpec,
    TlsSpec,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls;

const UNIT: usize = 64;

/// A CA with a name of its own, so that a server it did not issue fails as
/// an unknown issuer rather than on a same-subject anchor's key.
struct Authority {
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
}

fn authority(name: &str) -> Authority {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    Authority {
        cert: params.self_signed(&key).unwrap(),
        key,
    }
}

impl Authority {
    fn pem(&self) -> Vec<u8> {
        self.cert.pem().into_bytes()
    }
}

/// An HTTPS server on `bind` whose certificate, for `names`, `issuer`
/// signed. It answers each request with its own body. `None` where the
/// address cannot be bound.
async fn server(issuer: &Authority, bind: &str, names: &[&str]) -> Option<SocketAddr> {
    let key = rcgen::KeyPair::generate().unwrap();
    let leaf = rcgen::CertificateParams::new(
        names.iter().map(|name| name.to_string()).collect::<Vec<_>>(),
    )
        .unwrap()
        .signed_by(&key, &issuer.cert, &issuer.key)
        .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind(bind).await.ok()?;
    let address = listener.local_addr().unwrap();
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
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                let length = String::from_utf8_lossy(&head)
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                let mut body = vec![0u8; length];
                if stream.read_exact(&mut body).await.is_err() {
                    return;
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {length}\r\nconnection: close\r\n\r\n"
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(&body).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    Some(address)
}

fn provider(host: &str, address: SocketAddr, tls: Option<TlsSpec>) -> Result<HttpCryptoProvider, CryptoError> {
    let op = OpSpec {
        method: "POST".into(),
        path: "/crypt".into(),
        headers: vec![],
        query: vec![],
        body: BodySpec::Raw,
        response: RespSpec {
            kind: RespKind::Raw,
            data_path: None,
            encoding: PayloadEncoding::Base64,
            items_path: None,
            item_index_path: None,
        },
    };
    HttpCryptoProvider::new(HttpProviderSpec {
        base_url: format!("https://{host}:{}", address.port()),
        encrypt: op.clone(),
        decrypt: op,
        capabilities: CryptoCapabilities {
            provider_id: "default-trust".into(),
            crypto_compatibility_id: "default-trust-v1".into(),
            supported_plaintext_sizes: vec![UNIT as u32],
            max_ciphertext_size: UNIT as u32,
            stateless: true,
            retry_safe: true,
            batch: BatchCapability::default(),
            integrity: Capability::Absent,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        },
        timeout: Duration::from_secs(5),
        max_response_bytes: 4096,
        tls,
    })
}

fn ca_file(issuer: &Authority) -> Option<TlsSpec> {
    Some(TlsSpec {
        ca_pem: Some(issuer.pem()),
        identity_pem: None,
    })
}

async fn encrypt(provider: &HttpCryptoProvider) -> Result<(), CryptoError> {
    let output = provider
        .encrypt_batch(
            &CryptoContext {
                volume_uuid: uuid::Uuid::from_u128(0x7e5),
                format_version: 1,
                crypto_compatibility_id: "default-trust-v1".into(),
            },
            &[PlaintextUnit {
                unit_index: 3,
                data: SecretBuffer::from_slice(&[0x5a; UNIT]),
            }],
        )
        .await?;
    assert_eq!(output[0].data, vec![0x5a; UNIT]);
    Ok(())
}

/// Builds a provider and sends one request; records a deviation from
/// `trusted` in `wrong`.
async fn check(
    wrong: &mut Vec<String>,
    case: &str,
    host: &str,
    address: SocketAddr,
    tls: Option<TlsSpec>,
    trusted: bool,
) {
    let result = match provider(host, address, tls) {
        Ok(provider) => encrypt(&provider).await,
        Err(error) => {
            wrong.push(format!("{case}: provider construction failed: {error:?}"));
            return;
        }
    };
    match (&result, trusted) {
        (Ok(()), true) => {}
        (Err(error), false) if error.class() == ErrorClass::EndpointFatal => {}
        _ => wrong.push(format!(
            "{case}: expected trusted={trusted}, got {result:?}"
        )),
    }
}

#[tokio::test]
async fn audit8_ip_literal_endpoints_are_verified_against_ip_sans() {
    let issuer = authority("audit8 ip literal CA");
    let mut wrong = Vec::new();
    for (bind, host) in [("127.0.0.1:0", "127.0.0.1"), ("[::1]:0", "[::1]")] {
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        let Some(matching) = server(&issuer, bind, &[bare]).await else {
            eprintln!("audit8: skipped {host}: cannot bind {bind}");
            continue;
        };
        check(&mut wrong, &format!("{host}: IP SAN of the endpoint"), host, matching, ca_file(&issuer), true).await;
        let other = if bare == "::1" { "::2" } else { "127.0.0.2" };
        let foreign = server(&issuer, bind, &[other]).await.unwrap();
        check(&mut wrong, &format!("{host}: IP SAN of another address"), host, foreign, ca_file(&issuer), false).await;
        let dns_only = server(&issuer, bind, &["localhost"]).await.unwrap();
        check(&mut wrong, &format!("{host}: DNS SAN only"), host, dns_only, ca_file(&issuer), false).await;
        // And the name still works for the same server by name.
        if bare == "127.0.0.1" {
            check(&mut wrong, "localhost: DNS SAN", "localhost", dns_only, ca_file(&issuer), true).await;
            check(&mut wrong, "localhost: IP SAN only", "localhost", matching, ca_file(&issuer), false).await;
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}
