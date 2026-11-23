//! Round-5 documentation audit probe (scope `docs-config`).
//!
//! docs/configuration.md says of all three remote transports: "The TLS
//! section is optional when system/default trust is enough. A custom
//! `ca_file` adds trust; it does not disable the built-in roots."
//!
//! This probe shows what each transport trusts without a TLS section. One
//! local TLS listener presents a certificate whose only trust anchor is in
//! the host trust store (`SSL_CERT_FILE`, which `rustls-native-certs`
//! reads); the listener records whether each client completed the handshake.
//!
//! Own test binary: it changes the process environment.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoProvider, PlaintextUnit,
    SecretBuffer,
};

fn capabilities(provider_id: &str) -> CryptoCapabilities {
    CryptoCapabilities {
        provider_id: provider_id.to_string(),
        crypto_compatibility_id: "audit5-trust-v1".to_string(),
        supported_plaintext_sizes: vec![512],
        max_ciphertext_size: 512,
        stateless: true,
        retry_safe: false,
        batch: BatchCapability {
            supported: true,
            max_items: 1,
            max_bytes: 512,
        },
        integrity: Capability::Absent,
        context_binding: Capability::Absent,
        replay_protection: Capability::Absent,
    }
}

/// A TLS listener that only records whether each client finished the
/// handshake, then closes the connection.
async fn listener(
    certificate: &rcgen::CertifiedKey,
) -> (u16, Arc<Mutex<Vec<bool>>>) {
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der());
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.cert.der().clone()], key.into())
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let handshakes = Arc::new(Mutex::new(Vec::new()));
    let recorded = handshakes.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = socket.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let recorded = recorded.clone();
            tokio::spawn(async move {
                let completed = acceptor.accept(tcp).await.is_ok();
                recorded.lock().unwrap().push(completed);
            });
        }
    });
    (port, handshakes)
}

fn http_provider(port: u16, ca_file: Option<&std::path::Path>) -> maki_crypto_http::HttpCryptoProvider {
    let tls = ca_file
        .map(|path| format!("[crypto.http.tls]\nca_file = {path:?}\n"))
        .unwrap_or_default();
    let text = format!(
        r#"
config_schema_version = 1
[volume]
name = "audit5-trust"
max_virtual_size = "1MiB"
device_block_size = 512
crypto_unit_size = 512
shard_logical_size = "64KiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "audit5-trust-v1"
[crypto.capabilities]
supported_plaintext_sizes = [512]
max_ciphertext_size = 512
retry_safe = false
[[crypto.http.endpoint]]
name = "a"
url = "https://localhost:{port}"
{tls}[crypto.http.encrypt]
path = "/encrypt"
[crypto.http.decrypt]
path = "/decrypt"
[backing]
root = "/tmp/audit5-trust-unused"
"#
    );
    let config = maki_format::config::parse_config(&text).unwrap();
    config.validate().unwrap();
    maki_crypto_http::HttpCryptoProvider::from_config(
        &config,
        &format!("https://localhost:{port}"),
        &maki_crypto_local::keysource::MapKeySource::new(),
    )
    .unwrap()
}

/// One encrypt call; returns whether the listener saw a completed handshake
/// for it, and the client-side error text.
async fn attempt(
    name: &str,
    provider: &dyn CryptoProvider,
    handshakes: &Arc<Mutex<Vec<bool>>>,
) -> bool {
    let before = handshakes.lock().unwrap().len();
    let context = CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(5),
        format_version: 1,
        crypto_compatibility_id: "audit5-trust-v1".to_string(),
    };
    let unit = [PlaintextUnit {
        unit_index: 0,
        data: SecretBuffer::from_slice(&[0x5a; 512]),
    }];
    let result = tokio::time::timeout(
        Duration::from_secs(8),
        provider.encrypt_batch(&context, &unit),
    )
    .await;
    // The listener records the verdict after the client call returns or fails.
    for _ in 0..200 {
        if handshakes.lock().unwrap().len() > before {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let seen: Vec<bool> = handshakes.lock().unwrap()[before..].to_vec();
    let completed = seen.iter().any(|ok| *ok);
    let error = match result {
        Ok(Ok(_)) => "unexpected success".to_string(),
        Ok(Err(error)) => error.to_string(),
        Err(_) => "timed out".to_string(),
    };
    println!("{name}: TLS handshake completed = {completed} (listener saw {seen:?}); client error: {error}");
    completed
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit5_which_trust_anchors_each_transport_uses_without_a_tls_section() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let store = directory.path().join("host-store.pem");
    std::fs::write(&store, certificate.cert.pem()).unwrap();
    let empty = directory.path().join("certs");
    std::fs::create_dir(&empty).unwrap();
    // The host trust store, as rustls-native-certs sees it: exactly this CA.
    std::env::set_var("SSL_CERT_FILE", &store);
    std::env::set_var("SSL_CERT_DIR", &empty);

    let (port, handshakes) = listener(&certificate).await;

    let grpc = maki_crypto_grpc::GrpcCryptoProvider::new_with_tls(
        maki_crypto_grpc::GrpcProviderSpec {
            url: format!("https://localhost:{port}"),
            encrypt_path: "/maki.CryptoService/EncryptBatch".into(),
            decrypt_path: "/maki.CryptoService/DecryptBatch".into(),
            metadata: Vec::new(),
            capabilities: capabilities("remote-grpc"),
            timeout: Duration::from_secs(3),
            max_message_bytes: 1 << 20,
        },
        maki_crypto_grpc::GrpcTlsConfig::default(),
    )
    .unwrap();
    let grpc_trusts_host_store = attempt("grpc, no tls section", &grpc, &handshakes).await;

    let websocket = maki_crypto_websocket::WsCryptoProvider::new_checked(
        maki_crypto_websocket::WsProviderSpec {
            url: format!("wss://localhost:{port}"),
            capabilities: capabilities("remote-websocket"),
            timeout: Duration::from_secs(3),
            max_frame_bytes: 1 << 20,
            tls: None,
        },
    )
    .unwrap();
    let websocket_trusts_host_store =
        attempt("websocket, no tls section", &websocket, &handshakes).await;

    let http = http_provider(port, None);
    let http_trusts_host_store = attempt("http, no tls section", &http, &handshakes).await;

    let http_with_ca = http_provider(port, Some(&store));
    let http_trusts_ca_file = attempt("http, ca_file", &http_with_ca, &handshakes).await;

    assert!(grpc_trusts_host_store, "gRPC did not use the host trust store");
    assert!(
        websocket_trusts_host_store,
        "WebSocket did not use the host trust store"
    );
    assert!(http_trusts_ca_file, "HTTP control with ca_file failed");
    assert!(
        !http_trusts_host_store,
        "HTTP used the host trust store: the documentation finding does not hold"
    );
}
