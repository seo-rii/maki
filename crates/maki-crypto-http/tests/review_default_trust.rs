//! The HTTP transport trusts the same roots as the WebSocket and gRPC
//! transports: the host's trust store, the public roots compiled into the
//! binary, and the configured `ca_file`, which adds to them. A private CA
//! installed only in the host's store authenticates an endpoint without a
//! TLS section.
//!
//! The host's store is pointed at a test bundle through `SSL_CERT_FILE` and
//! `SSL_CERT_DIR`, which are process-global, so this file is a binary of its
//! own with a single test. The variables are set before the runtime starts;
//! later the bundle file itself is emptied rather than the environment
//! changed.

use std::net::SocketAddr;
use std::path::Path;
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

/// An HTTPS server for `localhost` whose certificate `issuer` signed. It
/// answers each request with its own body.
async fn server(issuer: &Authority) -> SocketAddr {
    let key = rcgen::KeyPair::generate().unwrap();
    let leaf = rcgen::CertificateParams::new(vec!["localhost".to_string()])
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
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
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
    address
}

fn provider(address: SocketAddr, tls: Option<TlsSpec>) -> Result<HttpCryptoProvider, CryptoError> {
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
        base_url: format!("https://localhost:{}", address.port()),
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
    address: SocketAddr,
    tls: Option<TlsSpec>,
    trusted: bool,
) {
    let result = match provider(address, tls) {
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

fn write_store(path: &Path, issuers: &[&Authority]) {
    let bundle: Vec<u8> = issuers.iter().flat_map(|issuer| issuer.pem()).collect();
    std::fs::write(path, bundle).unwrap();
}

#[test]
fn the_host_store_and_ca_file_add_to_the_compiled_in_roots() {
    let directory = tempfile::tempdir().unwrap();
    let store = directory.path().join("host-store.pem");
    let store_dir = directory.path().join("host-store.d");
    std::fs::create_dir(&store_dir).unwrap();
    let host = authority("maki host-store test authority");
    let configured = authority("maki ca_file test authority");
    let unrelated = authority("maki untrusted test authority");
    write_store(&store, &[&host]);
    std::env::set_var("SSL_CERT_FILE", &store);
    std::env::set_var("SSL_CERT_DIR", &store_dir);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let wrong = runtime.block_on(async {
        let host_server = server(&host).await;
        let configured_server = server(&configured).await;
        let unrelated_server = server(&unrelated).await;
        let mut wrong = Vec::new();

        // A CA in the host's store authenticates the endpoint with no TLS
        // section, with an empty one and next to a configured CA.
        check(
            &mut wrong,
            "host store, no TLS section",
            host_server,
            None,
            true,
        )
        .await;
        let empty = Some(TlsSpec::default());
        check(
            &mut wrong,
            "host store, empty TLS section",
            host_server,
            empty,
            true,
        )
        .await;
        let ca = ca_file(&configured);
        check(
            &mut wrong,
            "host store next to ca_file",
            host_server,
            ca,
            true,
        )
        .await;

        // A configured CA adds to the roots.
        let ca = ca_file(&configured);
        check(&mut wrong, "ca_file", configured_server, ca, true).await;

        // A CA that is in neither is refused, with or without ca_file.
        check(
            &mut wrong,
            "untrusted, no TLS section",
            unrelated_server,
            None,
            false,
        )
        .await;
        let ca = ca_file(&configured);
        check(
            &mut wrong,
            "untrusted, ca_file",
            unrelated_server,
            ca,
            false,
        )
        .await;

        // With an empty host store the compiled-in public roots remain, so
        // a provider is still built; the private CA is no longer trusted
        // and ca_file still is.
        write_store(&store, &[]);
        check(&mut wrong, "empty host store", host_server, None, false).await;
        let empty = Some(TlsSpec::default());
        check(
            &mut wrong,
            "empty host store, empty TLS section",
            host_server,
            empty,
            false,
        )
        .await;
        let ca = ca_file(&configured);
        check(
            &mut wrong,
            "empty host store, ca_file",
            configured_server,
            ca,
            true,
        )
        .await;
        wrong
    });
    assert!(wrong.is_empty(), "{wrong:#?}");
}
