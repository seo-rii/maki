//! Phase 9 follow-up — daemon wiring for the WebSocket and gRPC transports
//! (SPEC §18 lists all three remote transports; the daemon must assemble
//! `remote-websocket` / `remote-grpc` through the same dispatcher as
//! `remote-http`). TLS is not yet compiled into these two transports, so a
//! config asking for it must refuse to attach (fail closed), never silently
//! downgrade.

use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio::net::TcpListener;

const UNIT: usize = 512;
const XOR: u8 = 0x5A;

fn b64(d: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(d)
}

fn b64d(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

// ---------------------------------------------------------------- ws server

async fn ws_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let Ok(ws) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                let (mut sink, mut source) = ws.split();
                while let Some(Ok(msg)) = source.next().await {
                    let Ok(text) = msg.into_text() else { continue };
                    let Ok(request) = serde_json::from_str::<serde_json::Value>(&text) else {
                        continue;
                    };
                    let items: Vec<serde_json::Value> = request["items"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|item| {
                            let data = b64d(item["data"].as_str().unwrap());
                            let out: Vec<u8> = data.iter().map(|b| b ^ XOR).collect();
                            json!({"unit": item["unit"], "data": b64(&out)})
                        })
                        .collect();
                    let response = json!({"id": request["id"], "items": items});
                    let _ = sink.send(response.to_string().into()).await;
                }
            });
        }
    });
    format!("ws://{addr}")
}

// -------------------------------------------------------------- grpc server

mod grpc {
    use super::XOR;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use tonic::codegen::http;
    use tonic::codegen::{BoxFuture, Service, StdError};
    use tonic::server::NamedService;
    use tonic::{Code, Request, Response, Status};

    use maki_crypto_grpc::{CryptoBatchRequest, CryptoBatchResponse, CryptoItem};

    #[derive(Clone)]
    pub struct CryptoServer {
        pub require_token: Option<String>,
        pub auth_rejections: Arc<AtomicUsize>,
    }

    impl CryptoServer {
        #[allow(clippy::result_large_err)] // tonic::Status is the natural gRPC error type
        fn handle(
            &self,
            request: Request<CryptoBatchRequest>,
        ) -> Result<CryptoBatchResponse, Status> {
            if let Some(token) = &self.require_token {
                match request
                    .metadata()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                {
                    Some(got) if got == token => {}
                    _ => {
                        self.auth_rejections.fetch_add(1, Ordering::SeqCst);
                        return Err(Status::new(Code::Unauthenticated, "bad token"));
                    }
                }
            }
            let message = request.into_inner();
            let items: Vec<CryptoItem> = message
                .items
                .into_iter()
                .map(|item| CryptoItem {
                    unit_index: item.unit_index,
                    data: item.data.iter().map(|b| b ^ XOR).collect(),
                })
                .collect();
            Ok(CryptoBatchResponse { items })
        }
    }

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

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let this = self.clone();
            let path = req.uri().path().to_string();
            Box::pin(async move {
                match path.as_str() {
                    "/maki.CryptoService/EncryptBatch" | "/maki.CryptoService/DecryptBatch" => {
                        struct Svc(CryptoServer);
                        impl tonic::server::UnaryService<CryptoBatchRequest> for Svc {
                            type Response = CryptoBatchResponse;
                            type Future = BoxFuture<Response<Self::Response>, Status>;
                            fn call(
                                &mut self,
                                request: Request<CryptoBatchRequest>,
                            ) -> Self::Future {
                                let server = self.0.clone();
                                Box::pin(async move { server.handle(request).map(Response::new) })
                            }
                        }
                        let codec: tonic::codec::ProstCodec<
                            CryptoBatchResponse,
                            CryptoBatchRequest,
                        > = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec);
                        Ok(grpc.unary(Svc(this), req).await)
                    }
                    _ => Ok(http::Response::builder()
                        .status(200)
                        .header("grpc-status", (Code::Unimplemented as i32).to_string())
                        .header("content-type", "application/grpc")
                        .body(tonic::body::empty_body())
                        .unwrap()),
                }
            })
        }
    }

    pub struct ListenerStream(pub tokio::net::TcpListener);

    impl tonic::codegen::tokio_stream::Stream for ListenerStream {
        type Item = std::io::Result<tokio::net::TcpStream>;
        fn poll_next(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            match self.0.poll_accept(cx) {
                std::task::Poll::Ready(Ok((stream, _))) => std::task::Poll::Ready(Some(Ok(stream))),
                std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Some(Err(e))),
                std::task::Poll::Pending => std::task::Poll::Pending,
            }
        }
    }

    pub async fn serve(require_token: Option<String>) -> (String, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let auth_rejections = Arc::new(AtomicUsize::new(0));
        let server = CryptoServer {
            require_token,
            auth_rejections: auth_rejections.clone(),
        };
        tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(server)
                .serve_with_incoming(ListenerStream(listener))
                .await;
        });
        (format!("http://{addr}"), auth_rejections)
    }
}

// ------------------------------------------------------------------ configs

fn base_config(root: &str, provider: &str, crypto_extra: &str, transport: &str) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "wiredvol"
max_virtual_size = "1MiB"
device_block_size = 512
crypto_unit_size = 512
shard_logical_size = "64KiB"
[crypto]
provider = "{provider}"
crypto_compatibility_id = "vendor-profile-v1"
{crypto_extra}
[crypto.capabilities]
supported_plaintext_sizes = [512]
max_ciphertext_size = 512
[crypto.retry]
initial_delay = "10ms"
max_delay = "200ms"
{transport}
[backing]
root = "{root}"
"#
    )
}

async fn attach(config: &str) -> Result<maki_core::engine::Engine, String> {
    let cfg = maki_nbdkit::daemon::parse_and_validate(config).map_err(|e| e.to_string())?;
    let _ = maki_nbdkit::daemon::create_volume_from_config_str(config);
    maki_nbdkit::daemon::attach_from_config(&cfg)
        .await
        .map_err(|e| e.to_string())
}

fn temp_root(dir: &tempfile::TempDir) -> String {
    dir.path().join("vol").to_string_lossy().replace('\\', "/")
}

// -------------------------------------------------------------------- tests

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn engine_roundtrips_through_websocket_provider() {
    let url = ws_server().await;
    let dir = tempfile::tempdir().unwrap();
    let transport = format!(
        "[crypto.websocket]\nmax_frame_bytes = \"1MiB\"\n\
         [[crypto.websocket.endpoint]]\nname = \"ep0\"\nurl = \"{url}\"\n"
    );
    let config = base_config(&temp_root(&dir), "remote-websocket", "", &transport);
    let engine = attach(&config).await.unwrap();

    engine.write(0, &vec![0xAB; UNIT], true).await.unwrap();
    assert_eq!(engine.read(0, UNIT).await.unwrap(), vec![0xAB; UNIT]);
    engine.flush().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn engine_roundtrips_through_grpc_provider_with_metadata() {
    // Credential-referenced authorization metadata, resolved through the
    // daemon's key router (env source in development, SPEC §9).
    std::env::set_var("MAKI_CREDENTIAL_GRPC_WIRING_TOKEN", "tok-wiring-1");
    let (url, auth_rejections) = grpc::serve(Some("tok-wiring-1".to_string())).await;
    let dir = tempfile::tempdir().unwrap();
    let transport = format!(
        "[[crypto.grpc.endpoint]]\nname = \"ep0\"\nurl = \"{url}\"\n\
         [crypto.grpc.metadata]\n\
         authorization = {{ source = \"env\", name = \"grpc-wiring-token\" }}\n"
    );
    let config = base_config(&temp_root(&dir), "remote-grpc", "", &transport);
    let engine = attach(&config).await.unwrap();

    engine.write(0, &vec![0x77; UNIT], true).await.unwrap();
    assert_eq!(engine.read(0, UNIT).await.unwrap(), vec![0x77; UNIT]);
    assert_eq!(auth_rejections.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_without_token_is_refused_by_server() {
    // Sanity: the token check above is real — attach without metadata fails
    // after the server rejects the self-test with Unauthenticated.
    let (url, auth_rejections) = grpc::serve(Some("tok-wiring-2".to_string())).await;
    let dir = tempfile::tempdir().unwrap();
    let transport = format!("[[crypto.grpc.endpoint]]\nname = \"ep0\"\nurl = \"{url}\"\n");
    // Bounded-error ends retries; leave enough real-clock time to reach the
    // loopback server under load. Exact deadlines have ManualClock tests.
    // The scheduler may return its deadline before the dispatcher's last
    // endpoint error, so observe authentication at the server itself.
    let policy = "availability_policy = \"bounded-error\"\nmax_operation_time = \"2s\"\n\
                  [crypto.retry_budget]\nretry_ratio = 1.0\nburst = 64\nminimum_probe_rate = \"50/s\"\n";
    let config = base_config(&temp_root(&dir), "remote-grpc", policy, &transport);
    let err = attach(&config).await.unwrap_err();
    assert!(
        auth_rejections.load(std::sync::atomic::Ordering::SeqCst) > 0,
        "server must have rejected missing metadata with Unauthenticated; attach result: {err}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_tls_config_refuses_attach() {
    // wss:// (and [crypto.websocket.tls]) are not yet supported by the
    // transport build — the daemon must fail closed, not downgrade.
    let dir = tempfile::tempdir().unwrap();
    let transport =
        "[[crypto.websocket.endpoint]]\nname = \"ep0\"\nurl = \"wss://crypto.internal:7000\"\n"
            .to_string();
    let config = base_config(&temp_root(&dir), "remote-websocket", "", &transport);
    let err = attach(&config).await.unwrap_err();
    assert!(err.contains("TLS"), "must name the TLS gap: {err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_tls_config_refuses_attach() {
    let dir = tempfile::tempdir().unwrap();
    let transport =
        "[[crypto.grpc.endpoint]]\nname = \"ep0\"\nurl = \"https://crypto.internal:7000\"\n"
            .to_string();
    let config = base_config(&temp_root(&dir), "remote-grpc", "", &transport);
    let err = attach(&config).await.unwrap_err();
    assert!(err.contains("TLS"), "must name the TLS gap: {err}");
}
