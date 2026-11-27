//! A TLS protocol failure on an established WebSocket connection is an
//! endpoint failure, as in the connection attempt and as on the HTTP
//! transport (`docs/configuration.md`, provider error signals).
//!
//! After the upgrade, with a request pending, the server breaks the TLS
//! session under it: it writes an application-data record the client cannot
//! decrypt (rustls `DecryptError`), or it reads one itself, and its TLS
//! library answers with a fatal alert (`AlertReceived(BadRecordMac)` at the
//! client). Either reaches the connection's reader as the rustls error
//! inside an I/O error. The request was handed to the connection, so the
//! failure may follow a delivered request and is never marked unsent; and
//! like a TLS failure of the connection attempt it ends the call, without
//! the transparent second attempt a retry-safe provider makes after a lost
//! connection.
//!
//! The control is a connection that ends under the request without TLS
//! `close_notify`: rustls reports that as an I/O error of its own, without
//! a rustls error, and it stays a lost connection.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls;

use maki_crypto::{
    CryptoContext, CryptoError, CryptoProvider, ErrorClass, PlaintextUnit, SecretBuffer,
};
use maki_crypto_websocket::{WsCryptoProvider, WsProviderSpec, WsTlsOptions};

const UNIT: usize = 64;
const TLS_FAILURE: &str = "endpoint fatal: websocket TLS authentication or protocol failure";
const LOST: &str = "retryable: connection lost: closed";

fn caps(retry_safe: bool) -> maki_crypto::CryptoCapabilities {
    maki_crypto::CryptoCapabilities {
        provider_id: "wss-tls-failure".into(),
        crypto_compatibility_id: "wss-tls-failure-v1".into(),
        supported_plaintext_sizes: vec![UNIT as u32],
        max_ciphertext_size: UNIT as u32,
        stateless: true,
        retry_safe,
        batch: Default::default(),
        integrity: maki_crypto::Capability::Absent,
        context_binding: maki_crypto::Capability::Absent,
        replay_protection: maki_crypto::Capability::Absent,
    }
}

/// How the server breaks the TLS session under the pending request.
#[derive(Clone, Copy, Debug)]
enum Break {
    /// Write an application-data record that does not decrypt.
    UndecryptableRecord,
    /// Read such a record itself: its TLS library sends a fatal alert.
    FatalAlert,
    /// End the TCP connection without TLS `close_notify` (the control).
    Close,
}

/// An application-data record no traffic key decrypts.
fn undecryptable_record() -> Vec<u8> {
    let mut record = vec![0x17, 0x03, 0x03, 0x00, 0x40];
    record.extend((0..0x40u8).map(|i| i.wrapping_mul(37)));
    record
}

async fn break_session(tls: &mut tokio_rustls::server::TlsStream<TcpStream>, how: Break) {
    let (tcp, session) = tls.get_mut();
    match how {
        Break::UndecryptableRecord => tcp.write_all(&undecryptable_record()).await.unwrap(),
        Break::FatalAlert => {
            session
                .read_tls(&mut undecryptable_record().as_slice())
                .unwrap();
            let refused = session.process_new_packets().unwrap_err();
            assert_eq!(refused, rustls::Error::DecryptError);
            let mut alert = Vec::new();
            while session.wants_write() {
                session.write_tls(&mut alert).unwrap();
            }
            assert!(!alert.is_empty(), "rustls queued no alert");
            tcp.write_all(&alert).await.unwrap();
        }
        Break::Close => tcp.shutdown().await.unwrap(),
    }
    tcp.flush().await.unwrap();
}

struct Server {
    address: std::net::SocketAddr,
    ca_pem: Vec<u8>,
    ca_der: rustls::pki_types::CertificateDer<'static>,
    connections: Arc<AtomicUsize>,
}

/// A TLS server that breaks every connection's session as `how` says once
/// it has read the first WebSocket message (`websocket`) or the first byte
/// (a plain TLS client). It keeps the connection open afterwards, so the
/// client reads what it was sent rather than a reset.
async fn server(how: Break, websocket: bool) -> Server {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![certified.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()).into(),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let accepted = connections.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            accepted.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls = acceptor.accept(tcp).await.unwrap();
                if websocket {
                    let mut ws = tokio_tungstenite::accept_async(tls).await.unwrap();
                    ws.next().await.unwrap().unwrap();
                    break_session(ws.get_mut(), how).await;
                    std::future::pending::<()>().await;
                } else {
                    let mut byte = [0u8; 1];
                    tls.read_exact(&mut byte).await.unwrap();
                    break_session(&mut tls, how).await;
                    std::future::pending::<()>().await;
                }
            });
        }
    });
    Server {
        address,
        ca_pem: certified.cert.pem().into_bytes(),
        ca_der: certified.cert.der().clone(),
        connections,
    }
}

async fn encrypt_error(server: &Server, retry_safe: bool) -> CryptoError {
    let provider = WsCryptoProvider::new_checked(WsProviderSpec {
        url: format!("wss://127.0.0.1:{}/crypto", server.address.port()),
        capabilities: caps(retry_safe),
        timeout: Duration::from_secs(5),
        max_frame_bytes: 1 << 20,
        tls: Some(WsTlsOptions {
            ca_pem: Some(server.ca_pem.clone()),
            client_cert_pem: None,
            client_key_pem: None,
        }),
    })
    .unwrap();
    provider
        .encrypt_batch(
            &CryptoContext {
                volume_uuid: uuid::Uuid::from_u128(11),
                format_version: 1,
                crypto_compatibility_id: "wss-tls-failure-v1".into(),
            },
            &[PlaintextUnit {
                unit_index: 3,
                data: SecretBuffer::from_slice(&[0x31; UNIT]),
            }],
        )
        .await
        .unwrap_err()
}

/// The error a plain rustls client reads after the server broke the
/// session: the premise that each break is the TLS failure it names.
async fn plain_client_error(how: Break) -> std::io::Error {
    let server = server(how, false).await;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(server.ca_der.clone()).unwrap();
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
    let tcp = TcpStream::connect(server.address).await.unwrap();
    let mut tls = connector
        .connect("127.0.0.1".try_into().unwrap(), tcp)
        .await
        .unwrap();
    tls.write_all(b"x").await.unwrap();
    let mut buffer = [0u8; 16];
    tls.read(&mut buffer).await.unwrap_err()
}

fn rustls_error(error: &std::io::Error) -> Option<&rustls::Error> {
    error.get_ref().and_then(|inner| inner.downcast_ref())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn premise_each_break_reaches_a_tls_client_as_what_it_names() {
    let undecryptable = plain_client_error(Break::UndecryptableRecord).await;
    assert_eq!(
        rustls_error(&undecryptable),
        Some(&rustls::Error::DecryptError),
        "{undecryptable:?}"
    );
    let alert = plain_client_error(Break::FatalAlert).await;
    assert_eq!(
        rustls_error(&alert),
        Some(&rustls::Error::AlertReceived(
            rustls::AlertDescription::BadRecordMac
        )),
        "{alert:?}"
    );
    let closed = plain_client_error(Break::Close).await;
    assert_eq!(
        closed.kind(),
        std::io::ErrorKind::UnexpectedEof,
        "{closed:?}"
    );
    assert_eq!(rustls_error(&closed), None, "{closed:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_undecryptable_record_on_an_established_connection_is_an_endpoint_failure() {
    let server = server(Break::UndecryptableRecord, true).await;
    let error = encrypt_error(&server, false).await;
    assert_eq!(error.class(), ErrorClass::EndpointFatal, "{error}");
    assert_eq!(error.to_string(), TLS_FAILURE);
    assert!(
        !error.is_not_sent(),
        "the request was handed over: {error:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fatal_alert_on_an_established_connection_is_an_endpoint_failure() {
    let server = server(Break::FatalAlert, true).await;
    let error = encrypt_error(&server, false).await;
    assert_eq!(error.class(), ErrorClass::EndpointFatal, "{error}");
    assert_eq!(error.to_string(), TLS_FAILURE);
    assert!(
        !error.is_not_sent(),
        "the request was handed over: {error:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_retry_safe_provider_does_not_repeat_a_request_after_a_tls_failure() {
    for how in [Break::UndecryptableRecord, Break::FatalAlert] {
        let server = server(how, true).await;
        let error = encrypt_error(&server, true).await;
        assert_eq!(error.to_string(), TLS_FAILURE, "{how:?}");
        assert!(!error.is_not_sent(), "{how:?}: {error:?}");
        assert_eq!(
            server.connections.load(Ordering::SeqCst),
            1,
            "{how:?}: the request was sent again on a new connection"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_a_connection_ended_without_close_notify_is_a_lost_connection() {
    let server = server(Break::Close, true).await;
    let error = encrypt_error(&server, false).await;
    assert_eq!(error.to_string(), LOST);
    assert!(!error.is_not_sent(), "{error:?}");

    // A retry-safe provider sends it once more on a new connection.
    let server = self::server(Break::Close, true).await;
    let error = encrypt_error(&server, true).await;
    assert_eq!(error.to_string(), LOST);
    assert_eq!(server.connections.load(Ordering::SeqCst), 2);
}
