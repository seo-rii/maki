//! What a gRPC call reports for a failure of HTTP/2 itself, below the gRPC
//! message framing. The receive checks classify the framing of the gRPC
//! messages (the length prefix, the size limit, a response that ends inside
//! a message, the final status) as contract violations. A stream the peer
//! resets, or a connection it shuts down, is no such violation: it reaches
//! the caller as the gRPC status the library derives from the HTTP/2 error
//! and is classified by the status table like any other status. A reset
//! stream's error code selects the status: `REFUSED_STREAM` is
//! `Unavailable` and `CANCEL` is `Cancelled` (both retryable),
//! `ENHANCE_YOUR_CALM` is `ResourceExhausted` (throttled),
//! `INADEQUATE_SECURITY` is `PermissionDenied` (an endpoint failure), and
//! the other codes are `Internal` (retryable). A GOAWAY that ends the
//! connection under a call is `Unknown` (retryable), whatever its code.

use std::time::Duration;

use bytes::Bytes;
use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    ErrorClass, PlaintextUnit, SecretBuffer,
};
use maki_crypto_grpc::{GrpcCryptoProvider, GrpcProviderSpec};
use tokio::net::TcpListener;

const UNIT: usize = 512;

#[derive(Clone, Copy, Debug)]
enum Failure {
    /// Reset the stream before any response headers.
    ResetBeforeHeaders(h2::Reason),
    /// Send the response headers and part of a message, then reset.
    ResetInsideMessage(h2::Reason),
    /// Send the response headers, then shut the connection down with GOAWAY.
    GoAway(h2::Reason),
}

async fn server(failure: Failure) -> String {
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
                    match failure {
                        Failure::ResetBeforeHeaders(reason) => respond.send_reset(reason),
                        Failure::ResetInsideMessage(reason) => {
                            let mut stream = respond.send_response(response, false).unwrap();
                            let partial = Bytes::from_static(&[0, 0, 0, 0, 10, 1, 2, 3]);
                            stream.send_data(partial, false).unwrap();
                            stream.send_reset(reason);
                        }
                        Failure::GoAway(reason) => {
                            let _stream = respond.send_response(response, false).unwrap();
                            connection.abrupt_shutdown(reason);
                            // Drive the connection until the GOAWAY is out.
                            while connection.accept().await.is_some() {}
                            return;
                        }
                    }
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
            provider_id: "grpc-http2".into(),
            crypto_compatibility_id: "grpc-http2-v1".into(),
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

async fn encrypt(failure: Failure) -> CryptoError {
    let provider = provider(server(failure).await);
    let context = CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(2),
        format_version: 1,
        crypto_compatibility_id: "grpc-http2-v1".into(),
    };
    let item = PlaintextUnit {
        unit_index: 1,
        data: SecretBuffer::from_slice(&[9; UNIT]),
    };
    provider
        .encrypt_batch(&context, std::slice::from_ref(&item))
        .await
        .expect_err("the call failed at the HTTP/2 layer")
}

#[tokio::test]
async fn an_http2_error_is_classified_by_the_status_it_maps_to() {
    use h2::Reason;
    for (reason, reset) in [
        (Reason::PROTOCOL_ERROR, ErrorClass::Retryable),
        (Reason::INTERNAL_ERROR, ErrorClass::Retryable),
        (Reason::FLOW_CONTROL_ERROR, ErrorClass::Retryable),
        (Reason::REFUSED_STREAM, ErrorClass::Retryable),
        (Reason::CANCEL, ErrorClass::Retryable),
        (Reason::ENHANCE_YOUR_CALM, ErrorClass::Throttled),
        (Reason::INADEQUATE_SECURITY, ErrorClass::EndpointFatal),
    ] {
        for (failure, expected) in [
            (Failure::ResetBeforeHeaders(reason), reset),
            (Failure::ResetInsideMessage(reason), reset),
            (Failure::GoAway(reason), ErrorClass::Retryable),
        ] {
            let error = encrypt(failure).await;
            assert_eq!(error.class(), expected, "{failure:?}: {error:?}");
            assert!(
                !matches!(error, CryptoError::Contract(_)),
                "{failure:?}: {error:?}"
            );
        }
    }
}
