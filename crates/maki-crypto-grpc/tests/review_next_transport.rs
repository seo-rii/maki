//! BUG-017: a gRPC server that accepts the connection but never completes
//! the response (stalls after headers, or between message and trailers)
//! must not hold the RPC open past the configured transport timeout. The
//! `Channel::timeout` bounds only the connection, so the provider now wraps
//! readiness plus the unary exchange in one `tokio::time::timeout`.

use std::time::{Duration, Instant};

use tonic::codegen::http;
use tonic::codegen::{BoxFuture, Service, StdError};
use tonic::server::NamedService;

use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    PlaintextUnit, SecretBuffer,
};
use maki_crypto_grpc::{GrpcCryptoProvider, GrpcProviderSpec};

const UNIT: usize = 256;
const TIMEOUT: Duration = Duration::from_millis(250);

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0xB17),
        format_version: 1,
        crypto_compatibility_id: "grpc-profile-v1".to_string(),
    }
}

fn caps() -> CryptoCapabilities {
    CryptoCapabilities {
        provider_id: "remote-grpc-stall".to_string(),
        crypto_compatibility_id: "grpc-profile-v1".to_string(),
        supported_plaintext_sizes: vec![UNIT as u32],
        max_ciphertext_size: UNIT as u32,
        stateless: true,
        retry_safe: true,
        batch: BatchCapability {
            supported: true,
            max_items: 64,
            max_bytes: 1 << 20,
        },
        integrity: Capability::Absent,
        context_binding: Capability::Absent,
        replay_protection: Capability::Absent,
    }
}

/// A server that establishes the HTTP/2 connection (so `ready()` succeeds)
/// but never answers the RPC: the handler sleeps far longer than the
/// client's timeout, so no response header, message, or trailer is sent.
#[derive(Clone)]
struct StallServer;

impl NamedService for StallServer {
    const NAME: &'static str = "maki.CryptoService";
}

impl<B> Service<http::Request<B>> for StallServer
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

    fn call(&mut self, _req: http::Request<B>) -> Self::Future {
        Box::pin(async move {
            // Stall well past the client timeout without ever responding.
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(http::Response::builder()
                .status(200)
                .header("grpc-status", "0")
                .header("content-type", "application/grpc")
                .body(tonic::body::empty_body())
                .unwrap())
        })
    }
}

mod listener {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    pub struct ListenerStream(pub tokio::net::TcpListener);

    impl tonic::codegen::tokio_stream::Stream for ListenerStream {
        type Item = std::io::Result<tokio::net::TcpStream>;
        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            match self.0.poll_accept(cx) {
                Poll::Ready(Ok((stream, _))) => Poll::Ready(Some(Ok(stream))),
                Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
                Poll::Pending => Poll::Pending,
            }
        }
    }
}

async fn stall_server() -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(StallServer)
            .serve_with_incoming(listener::ListenerStream(l))
            .await;
    });
    format!("http://{addr}")
}

fn provider(url: &str) -> GrpcCryptoProvider {
    GrpcCryptoProvider::new(GrpcProviderSpec {
        url: url.to_string(),
        encrypt_path: "/maki.CryptoService/EncryptBatch".to_string(),
        decrypt_path: "/maki.CryptoService/DecryptBatch".to_string(),
        metadata: vec![],
        capabilities: caps(),
        timeout: TIMEOUT,
        max_message_bytes: 1 << 20,
    })
    .unwrap()
}

fn unit(index: u64) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: index,
        data: SecretBuffer::from_slice(&[index as u8; UNIT]),
    }
}

#[tokio::test]
async fn a_stalled_grpc_response_is_bounded_by_the_transport_timeout() {
    let url = stall_server().await;
    let provider = provider(&url);

    let started = Instant::now();
    let result = provider.encrypt_batch(&ctx(), &[unit(0)]).await;
    let elapsed = started.elapsed();

    assert!(
        result.is_err(),
        "a stalled server must not return a successful response"
    );
    assert!(
        matches!(result, Err(CryptoError::Retryable(_))),
        "a timed-out RPC is retryable, got {result:?}"
    );
    // The 30s server stall must be cut off near the 250ms timeout, not held
    // open. Allow generous slack for CI scheduling.
    assert!(
        elapsed < Duration::from_secs(5),
        "RPC ran for {elapsed:?}; the transport timeout did not bound it"
    );
}
