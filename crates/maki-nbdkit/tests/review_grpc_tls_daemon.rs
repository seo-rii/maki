//! Daemon-path coverage for verified gRPC TLS and mutual TLS. All peers and
//! certificate material are generated locally for the test process.

use std::pin::Pin;
use std::task::{Context, Poll};

use maki_crypto_grpc::{CryptoBatchRequest, CryptoBatchResponse, CryptoItem};
use maki_nbdkit::adapter::NbdAdapter;
use tonic::codegen::http;
use tonic::codegen::{BoxFuture, Service, StdError};
use tonic::server::NamedService;
use tonic::{Request, Response, Status};

const UNIT: usize = 512;
const XOR: u8 = 0x5a;

#[derive(Clone)]
struct CryptoServer;

impl NamedService for CryptoServer {
    const NAME: &'static str = "maki.CryptoService";
}

impl<B> Service<http::Request<B>> for CryptoServer
where
    B: tonic::codegen::Body + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::BoxBody>;
    type Error = std::convert::Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        Box::pin(async move {
            struct Unary;
            impl tonic::server::UnaryService<CryptoBatchRequest> for Unary {
                type Response = CryptoBatchResponse;
                type Future = BoxFuture<Response<Self::Response>, Status>;

                fn call(&mut self, request: Request<CryptoBatchRequest>) -> Self::Future {
                    Box::pin(async move {
                        let items = request
                            .into_inner()
                            .items
                            .into_iter()
                            .map(|item| CryptoItem {
                                unit_index: item.unit_index,
                                data: item.data.into_iter().map(|byte| byte ^ XOR).collect(),
                            })
                            .collect();
                        Ok(Response::new(CryptoBatchResponse { items }))
                    })
                }
            }

            let codec =
                tonic::codec::ProstCodec::<CryptoBatchResponse, CryptoBatchRequest>::default();
            Ok(tonic::server::Grpc::new(codec).unary(Unary, request).await)
        })
    }
}

struct ListenerStream(tokio::net::TcpListener);

impl tonic::codegen::tokio_stream::Stream for ListenerStream {
    type Item = std::io::Result<tokio::net::TcpStream>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.0.poll_accept(cx) {
            Poll::Ready(Ok((stream, _))) => Poll::Ready(Some(Ok(stream))),
            Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}

struct TlsServer {
    port: u16,
    server_certificate_pem: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl TlsServer {
    fn start(server_name: &str, trusted_client: Option<&rcgen::CertifiedKey>) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = rcgen::generate_simple_self_signed(vec![server_name.to_string()]).unwrap();
        let server_certificate_pem = server.cert.pem();
        let identity = tonic::transport::Identity::from_pem(
            server_certificate_pem.clone(),
            server.key_pair.serialize_pem(),
        );
        let mut tls = tonic::transport::ServerTlsConfig::new().identity(identity);
        if let Some(client) = trusted_client {
            tls = tls.client_ca_root(tonic::transport::Certificate::from_pem(client.cert.pem()));
        }
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                ready_tx
                    .send(listener.local_addr().unwrap().port())
                    .unwrap();
                tonic::transport::Server::builder()
                    .tls_config(tls)
                    .unwrap()
                    .add_service(CryptoServer)
                    .serve_with_incoming_shutdown(ListenerStream(listener), async {
                        let _ = shutdown_rx.await;
                    })
                    .await
                    .unwrap();
            });
        });
        Self {
            port: ready_rx.recv().unwrap(),
            server_certificate_pem,
            shutdown: Some(shutdown),
            thread: Some(thread),
        }
    }
}

impl Drop for TlsServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

struct Fixture {
    directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self {
            directory: tempfile::tempdir().unwrap(),
        }
    }

    fn private_file(&self, name: &str, contents: impl AsRef<[u8]>) -> String {
        let path = self.directory.path().join(name);
        std::fs::write(&path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path.to_string_lossy().replace('\\', "/")
    }

    fn config(
        &self,
        port: u16,
        ca_pem: &str,
        client: Option<(&str, &str)>,
    ) -> (String, std::path::PathBuf) {
        let ca_file = self.private_file("ca.pem", ca_pem);
        let client_tls = client
            .map(|(certificate, key)| {
                let certificate = self.private_file("client.pem", certificate);
                let key = self.private_file("client.key", key);
                format!(
                    "client_cert_file = \"{certificate}\"\nclient_key = {{ source = \"file\", name = \"{key}\" }}\n"
                )
            })
            .unwrap_or_default();
        let root = self.directory.path().join("volume");
        let socket = self.directory.path().join("control.sock");
        let raw = format!(
            r#"
config_schema_version = 1
[volume]
name = "grpc-tls-daemon"
max_virtual_size = "1MiB"
device_block_size = 512
crypto_unit_size = 512
shard_logical_size = "64KiB"
[crypto]
provider = "remote-grpc"
crypto_compatibility_id = "grpc-tls-profile-v1"
availability_policy = "bounded-error"
max_operation_time = "800ms"
[crypto.capabilities]
supported_plaintext_sizes = [512]
max_ciphertext_size = 512
[crypto.retry]
initial_delay = "10ms"
max_delay = "50ms"
[crypto.retry_budget]
retry_ratio = 1.0
burst = 64
minimum_probe_rate = "50/s"
[crypto.grpc]
timeout = "250ms"
[[crypto.grpc.endpoint]]
name = "local-tls"
url = "https://localhost:{port}"
[crypto.grpc.tls]
ca_file = "{ca_file}"
{client_tls}
[backing]
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
            root = root.to_string_lossy().replace('\\', "/"),
            socket = socket.to_string_lossy().replace('\\', "/"),
        );
        let path = self.directory.path().join("volume.toml");
        std::fs::write(&path, &raw).unwrap();
        (raw, path)
    }
}

fn initialize_and_open(raw: &str, path: &std::path::Path) -> NbdAdapter {
    maki_nbdkit::daemon::create_volume_from_config_str(raw).unwrap();
    NbdAdapter::open_config(path.to_str().unwrap()).unwrap()
}

#[test]
fn daemon_roundtrips_and_shuts_down_over_verified_grpc_tls() {
    let server = TlsServer::start("localhost", None);
    let fixture = Fixture::new();
    let (raw, path) = fixture.config(server.port, &server.server_certificate_pem, None);
    let adapter = initialize_and_open(&raw, &path);
    let expected = vec![0xa7; UNIT];
    adapter.pwrite(&expected, 0, true).unwrap();
    let mut actual = vec![0; UNIT];
    adapter.pread(&mut actual, 0).unwrap();
    assert_eq!(actual, expected);
    adapter.shutdown().unwrap();
}

#[test]
fn daemon_roundtrips_over_mutual_grpc_tls() {
    let client = rcgen::generate_simple_self_signed(vec!["maki-client".into()]).unwrap();
    let server = TlsServer::start("localhost", Some(&client));
    let fixture = Fixture::new();
    let (raw, path) = fixture.config(
        server.port,
        &server.server_certificate_pem,
        Some((&client.cert.pem(), &client.key_pair.serialize_pem())),
    );
    let adapter = initialize_and_open(&raw, &path);
    let expected = vec![0x3c; UNIT];
    adapter.pwrite(&expected, 0, true).unwrap();
    let mut actual = vec![0; UNIT];
    adapter.pread(&mut actual, 0).unwrap();
    assert_eq!(actual, expected);
    adapter.shutdown().unwrap();
}

#[test]
fn daemon_rejects_wrong_ca() {
    let fixture = Fixture::new();
    let unrelated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let server = TlsServer::start("localhost", None);
    let (raw, path) = fixture.config(server.port, &unrelated.cert.pem(), None);
    maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();
    assert!(NbdAdapter::open_config(path.to_str().unwrap()).is_err());
}

#[test]
fn daemon_rejects_a_tls_certificate_for_the_wrong_name() {
    let server = TlsServer::start("wrong.invalid", None);
    let fixture = Fixture::new();
    let (raw, path) = fixture.config(server.port, &server.server_certificate_pem, None);
    maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();
    assert!(NbdAdapter::open_config(path.to_str().unwrap()).is_err());
}

#[test]
fn daemon_rejects_missing_mtls_client_identity() {
    let client = rcgen::generate_simple_self_signed(vec!["maki-client".into()]).unwrap();
    let server = TlsServer::start("localhost", Some(&client));
    let fixture = Fixture::new();
    let (raw, path) = fixture.config(server.port, &server.server_certificate_pem, None);
    maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();
    assert!(NbdAdapter::open_config(path.to_str().unwrap()).is_err());
}
