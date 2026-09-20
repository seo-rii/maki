//! Daemon-path coverage for verified WebSocket TLS and mutual TLS.

use std::sync::Arc;

use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use maki_nbdkit::adapter::NbdAdapter;
use serde_json::json;
use tokio_rustls::rustls;

const UNIT: usize = 512;
const XOR: u8 = 0x5a;

struct Identity {
    cert_pem: String,
    key_pem: String,
    cert_der: rustls::pki_types::CertificateDer<'static>,
    key_der: rustls::pki_types::PrivateKeyDer<'static>,
}

fn identity(name: &str) -> Identity {
    let identity = rcgen::generate_simple_self_signed(vec![name.into()]).unwrap();
    Identity {
        cert_pem: identity.cert.pem(),
        key_pem: identity.key_pair.serialize_pem(),
        cert_der: identity.cert.der().clone(),
        key_der: rustls::pki_types::PrivatePkcs8KeyDer::from(identity.key_pair.serialize_der())
            .into(),
    }
}

struct WssServer {
    port: u16,
    server_ca_pem: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl WssServer {
    fn start(trusted_client: Option<&Identity>) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = identity("localhost");
        let server_ca_pem = server.cert_pem.clone();
        let builder =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12]);
        let config = match trusted_client {
            None => builder.with_no_client_auth(),
            Some(client) => {
                let mut roots = rustls::RootCertStore::empty();
                roots.add(client.cert_der.clone()).unwrap();
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
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let (shutdown, mut shutdown_rx) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                    ready_tx.send(listener.local_addr().unwrap().port()).unwrap();
                    loop {
                        let tcp = tokio::select! {
                            _ = &mut shutdown_rx => break,
                            accepted = listener.accept() => accepted.unwrap().0,
                        };
                        let acceptor = acceptor.clone();
                        tokio::spawn(async move {
                            let Ok(tls) = acceptor.accept(tcp).await else { return };
                            let Ok(mut ws) = tokio_tungstenite::accept_async(tls).await else {
                                return;
                            };
                            while let Some(Ok(message)) = ws.next().await {
                                let Ok(text) = message.into_text() else { continue };
                                let request: serde_json::Value =
                                    serde_json::from_str(&text).unwrap();
                                let items = request["items"]
                                    .as_array()
                                    .unwrap()
                                    .iter()
                                    .map(|item| {
                                        let data = base64::engine::general_purpose::STANDARD
                                            .decode(item["data"].as_str().unwrap())
                                            .unwrap()
                                            .into_iter()
                                            .map(|byte| byte ^ XOR)
                                            .collect::<Vec<_>>();
                                        json!({"unit": item["unit"], "data": base64::engine::general_purpose::STANDARD.encode(data)})
                                    })
                                    .collect::<Vec<_>>();
                                ws.send(json!({"id": request["id"], "items": items}).to_string().into())
                                    .await
                                    .unwrap();
                            }
                        });
                    }
                });
        });
        Self {
            port: ready_rx.recv().unwrap(),
            server_ca_pem,
            shutdown: Some(shutdown),
            thread: Some(thread),
        }
    }
}

impl Drop for WssServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

fn private_file(directory: &tempfile::TempDir, name: &str, contents: &str) -> String {
    let path = directory.path().join(name);
    std::fs::write(&path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path.to_string_lossy().replace('\\', "/")
}

fn config(server: &WssServer, client: Option<&Identity>) -> (tempfile::TempDir, String, String) {
    let directory = tempfile::tempdir().unwrap();
    let ca_file = private_file(&directory, "ca.pem", &server.server_ca_pem);
    let client_tls = client
        .map(|client| {
            let cert = private_file(&directory, "client.pem", &client.cert_pem);
            let key = private_file(&directory, "client.key", &client.key_pem);
            format!(
                "client_cert_file = \"{cert}\"\nclient_key = {{ source = \"file\", name = \"{key}\" }}\n"
            )
        })
        .unwrap_or_default();
    let root = directory
        .path()
        .join("volume")
        .to_string_lossy()
        .replace('\\', "/");
    let socket = directory
        .path()
        .join("control.sock")
        .to_string_lossy()
        .replace('\\', "/");
    let raw = format!(
        r#"config_schema_version = 1
[volume]
name = "wss-tls-daemon"
max_virtual_size = "1MiB"
device_block_size = 512
crypto_unit_size = 512
shard_logical_size = "64KiB"
[crypto]
provider = "remote-websocket"
crypto_compatibility_id = "wss-tls-profile-v1"
availability_policy = "bounded-error"
max_operation_time = "800ms"
[crypto.capabilities]
supported_plaintext_sizes = [512]
max_ciphertext_size = 512
[crypto.websocket]
timeout = "250ms"
max_frame_bytes = "2MiB"
[[crypto.websocket.endpoint]]
name = "local-tls"
url = "wss://localhost:{port}/crypto"
[crypto.websocket.tls]
ca_file = "{ca_file}"
{client_tls}[backing]
root = "{root}"
journal_emergency_reserve_bytes = "0B"
[nbd]
minimum_io = 512
preferred_io = 512
maximum_io = "64KiB"
threads = 2
[control]
socket = "{socket}"
"#,
        port = server.port,
    );
    let path = directory.path().join("volume.toml");
    std::fs::write(&path, &raw).unwrap();
    (directory, raw, path.to_string_lossy().into_owned())
}

fn roundtrip(client: Option<&Identity>) {
    let server = WssServer::start(client);
    let (_directory, raw, path) = config(&server, client);
    maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();
    let adapter = NbdAdapter::open_config(&path).unwrap();
    let expected = vec![0xa7; UNIT];
    adapter.pwrite(&expected, 0, true).unwrap();
    let mut actual = vec![0; UNIT];
    adapter.pread(&mut actual, 0).unwrap();
    assert_eq!(actual, expected);
    adapter.shutdown().unwrap();
}

#[test]
fn daemon_roundtrips_over_verified_wss() {
    roundtrip(None);
}

#[test]
fn daemon_roundtrips_over_mutual_wss() {
    let client = identity("maki-client");
    roundtrip(Some(&client));
}
