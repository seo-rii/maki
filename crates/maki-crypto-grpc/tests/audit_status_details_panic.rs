//! Audit: tonic 0.13.1 parses `grpc-status-details-bin` with
//! `.expect("Invalid status header, expected base64 encoded value")`
//! (tonic src/status.rs, `Status::from_header_map`). The provider's response
//! checks (`response_status`, `BoundedResponseBody`) validate only
//! `grpc-status`, so any remote peer can make a provider call panic by
//! sending a non-base64 details header with an error status, in the initial
//! headers (trailers-only) or in the trailers. Providers are untrusted
//! (CLAUDE.md, SPEC §16); a malformed response must be an error, not a panic.

use std::sync::Arc;
use std::time::Duration;

use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoProvider,
};
use maki_crypto_grpc::{GrpcCryptoProvider, GrpcProviderSpec};

async fn serve(trailers_only: bool) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(mut connection) = h2::server::handshake(socket).await else {
                    return;
                };
                while let Some(Ok((_request, mut respond))) = connection.accept().await {
                    let mut response = http::Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .body(())
                        .unwrap();
                    let mut status = http::HeaderMap::new();
                    status.insert("grpc-status", "13".parse().unwrap());
                    status.insert("grpc-status-details-bin", "!!not-base64!!".parse().unwrap());
                    if trailers_only {
                        response.headers_mut().extend(status);
                        let _ = respond.send_response(response, true);
                    } else {
                        let mut stream = respond.send_response(response, false).unwrap();
                        let _ = stream.send_trailers(status);
                    }
                }
            });
        }
    });
    address
}

fn provider(address: std::net::SocketAddr) -> GrpcCryptoProvider {
    GrpcCryptoProvider::new(GrpcProviderSpec {
        url: format!("http://{address}"),
        encrypt_path: "/maki.CryptoService/EncryptBatch".into(),
        decrypt_path: "/maki.CryptoService/DecryptBatch".into(),
        metadata: vec![],
        capabilities: CryptoCapabilities {
            provider_id: "audit-details".into(),
            crypto_compatibility_id: "audit-details-v1".into(),
            supported_plaintext_sizes: vec![64],
            max_ciphertext_size: 64,
            stateless: true,
            retry_safe: true,
            batch: BatchCapability {
                supported: true,
                max_items: 8,
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

#[tokio::test]
async fn malformed_status_details_from_the_peer_must_not_panic_the_caller() {
    let mut panicked = Vec::new();
    for trailers_only in [true, false] {
        let address = serve(trailers_only).await;
        let provider = Arc::new(provider(address));
        let call = tokio::spawn(async move {
            provider
                .decrypt_batch(
                    &CryptoContext {
                        volume_uuid: uuid::Uuid::from_u128(3),
                        format_version: 1,
                        crypto_compatibility_id: "audit-details-v1".into(),
                    },
                    &[CiphertextUnit {
                        unit_index: 1,
                        data: vec![0x11; 64],
                    }],
                )
                .await
                .map(|_| ())
        });
        let joined = call.await;
        match &joined {
            Ok(result) => eprintln!("trailers_only={trailers_only}: returned {result:?}"),
            Err(error) => eprintln!(
                "trailers_only={trailers_only}: provider call PANICKED (is_panic={})",
                error.is_panic()
            ),
        }
        if joined.is_err() {
            panicked.push(trailers_only);
        }
    }
    assert!(
        panicked.is_empty(),
        "a remote status header panicked the provider call (trailers_only cases: {panicked:?})"
    );
}
