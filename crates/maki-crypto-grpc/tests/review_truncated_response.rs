//! BUG-121: a gRPC response that ended inside a message (the length prefix
//! announced more bytes than arrived before the trailers or the end of the
//! stream), or an OK response that carried no message at all, reached the
//! caller as tonic's local `Internal` status, which maps to Retryable. Like
//! the oversized and undecodable responses of BUG-057, it is a receive
//! contract violation by that endpoint: retried against the same peer it
//! fails the same way, and under `stall` forever.

use std::time::Duration;

use bytes::Bytes;
use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    PlaintextUnit, SecretBuffer,
};
use maki_crypto_grpc::{GrpcCryptoProvider, GrpcProviderSpec};
use tokio::net::TcpListener;

const UNIT: usize = 512;

#[derive(Clone, Copy, Debug)]
enum Reply {
    /// Announce a 10-byte message, send 3 bytes, then OK trailers.
    TruncatedThenTrailers,
    /// Announce a 10-byte message, send 3 bytes, then end the stream.
    TruncatedThenEnd,
    /// OK trailers without any message.
    OkWithoutMessage,
    /// A genuine remote outage status: still retryable.
    Unavailable,
}

async fn server(reply: Reply) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut connection = h2::server::handshake(socket).await.unwrap();
                while let Some(Ok((_request, mut respond))) = connection.accept().await {
                    let response = http::Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .body(())
                        .unwrap();
                    let mut stream = respond.send_response(response, false).unwrap();
                    let mut trailers = http::HeaderMap::new();
                    match reply {
                        Reply::TruncatedThenTrailers | Reply::TruncatedThenEnd => {
                            let partial = Bytes::from_static(&[0, 0, 0, 0, 10, 1, 2, 3]);
                            let end = matches!(reply, Reply::TruncatedThenEnd);
                            stream.send_data(partial, end).unwrap();
                            if end {
                                continue;
                            }
                            trailers.insert("grpc-status", "0".parse().unwrap());
                        }
                        Reply::OkWithoutMessage => {
                            trailers.insert("grpc-status", "0".parse().unwrap());
                        }
                        Reply::Unavailable => {
                            trailers.insert("grpc-status", "14".parse().unwrap());
                        }
                    }
                    let _ = stream.send_trailers(trailers);
                }
            });
        }
    });
    url
}

fn provider(url: String) -> GrpcCryptoProvider {
    GrpcCryptoProvider::new(GrpcProviderSpec {
        url,
        encrypt_path: "/maki.CryptoService/EncryptBatch".into(),
        decrypt_path: "/maki.CryptoService/DecryptBatch".into(),
        metadata: vec![],
        capabilities: CryptoCapabilities {
            provider_id: "grpc-truncated".into(),
            crypto_compatibility_id: "grpc-truncated-v1".into(),
            supported_plaintext_sizes: vec![UNIT as u32],
            max_ciphertext_size: UNIT as u32,
            stateless: true,
            retry_safe: true,
            batch: BatchCapability {
                supported: true,
                max_items: 4,
                max_bytes: 4096,
            },
            integrity: Capability::Absent,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        },
        timeout: Duration::from_secs(2),
        max_message_bytes: 4096,
    })
    .unwrap()
}

async fn encrypt(reply: Reply) -> Result<(), CryptoError> {
    let provider = provider(server(reply).await);
    let context = CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(121),
        format_version: 1,
        crypto_compatibility_id: "grpc-truncated-v1".into(),
    };
    let item = PlaintextUnit {
        unit_index: 1,
        data: SecretBuffer::from_slice(&[9; UNIT]),
    };
    provider
        .encrypt_batch(&context, std::slice::from_ref(&item))
        .await
        .map(|_| ())
}

#[tokio::test]
async fn a_response_that_ends_inside_or_without_a_message_breaks_the_contract() {
    for reply in [
        Reply::TruncatedThenTrailers,
        Reply::TruncatedThenEnd,
        Reply::OkWithoutMessage,
    ] {
        let result = encrypt(reply).await;
        assert!(
            matches!(result, Err(CryptoError::Contract(_))),
            "{reply:?}: {result:?}"
        );
    }
}

#[tokio::test]
async fn a_remote_unavailable_status_is_still_retryable() {
    let result = encrypt(Reply::Unavailable).await;
    assert!(
        matches!(result, Err(CryptoError::Retryable(_))),
        "{result:?}"
    );
}
