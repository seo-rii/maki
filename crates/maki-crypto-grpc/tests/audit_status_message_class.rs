//! Audit: SPEC §18 says remote error text is ignored, and `map_status`
//! classifies only by the gRPC code plus the allowlisted metadata token. But
//! tonic 0.13.1 (`Status::from_header_map`) replaces the code with `Unknown`
//! when `grpc-message` does not percent-decode to UTF-8. A definitive
//! integrity rejection (FailedPrecondition + `maki-crypto-error:
//! auth-tag-mismatch`) whose message carries non-UTF-8 bytes (a C-core server
//! percent-encodes arbitrary bytes) therefore becomes `Retryable`: a tampered
//! unit is retried (forever under `stall`) and charged to every endpoint's
//! breaker instead of failing with EIO; a `PermissionDenied` likewise loses
//! its EndpointFatal class.

use std::time::Duration;

use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoProvider,
    ErrorClass,
};
use maki_crypto_grpc::{GrpcCryptoProvider, GrpcProviderSpec};

async fn serve(code: &'static str, message: Option<&'static str>) -> std::net::SocketAddr {
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
                    let headers = response.headers_mut();
                    headers.insert("grpc-status", code.parse().unwrap());
                    if code == "9" {
                        headers.insert("maki-crypto-error", "auth-tag-mismatch".parse().unwrap());
                    }
                    if let Some(message) = message {
                        headers.insert("grpc-message", message.parse().unwrap());
                    }
                    let _ = respond.send_response(response, true);
                }
            });
        }
    });
    address
}

async fn decrypt_class(address: std::net::SocketAddr) -> ErrorClass {
    let provider = GrpcCryptoProvider::new(GrpcProviderSpec {
        url: format!("http://{address}"),
        encrypt_path: "/maki.CryptoService/EncryptBatch".into(),
        decrypt_path: "/maki.CryptoService/DecryptBatch".into(),
        metadata: vec![],
        capabilities: CryptoCapabilities {
            provider_id: "audit-message".into(),
            crypto_compatibility_id: "audit-message-v1".into(),
            supported_plaintext_sizes: vec![64],
            max_ciphertext_size: 64,
            stateless: true,
            retry_safe: true,
            batch: BatchCapability {
                supported: true,
                max_items: 8,
                max_bytes: 4096,
            },
            integrity: Capability::Contractual,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        },
        timeout: Duration::from_secs(2),
        max_message_bytes: 4096,
    })
    .unwrap();
    provider
        .decrypt_batch(
            &CryptoContext {
                volume_uuid: uuid::Uuid::from_u128(5),
                format_version: 1,
                crypto_compatibility_id: "audit-message-v1".into(),
            },
            &[CiphertextUnit {
                unit_index: 1,
                data: vec![0x11; 64],
            }],
        )
        .await
        .err()
        .expect("the peer always returns an error status")
        .class()
}

#[tokio::test]
async fn remote_message_text_must_not_change_the_error_class() {
    let mut wrong = Vec::new();
    for (code, expected) in [
        ("9", ErrorClass::NonRetryableRequest), // Integrity's class
        ("7", ErrorClass::EndpointFatal),       // PermissionDenied
        ("16", ErrorClass::EndpointFatal),      // Unauthenticated
    ] {
        // Controls: no message, and a valid UTF-8 message.
        for message in [None, Some("tag%20mismatch"), Some("tag%FFmismatch")] {
            let class = decrypt_class(serve(code, message).await).await;
            eprintln!("grpc-status {code} grpc-message {message:?} -> {class:?}");
            if class != expected {
                wrong.push((code, message, class));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "remote grpc-message text changed the error class: {wrong:?}"
    );
}
