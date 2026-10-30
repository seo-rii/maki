//! BUG-175: a gRPC endpoint behind a proxy (nginx `grpc_pass`, an ingress)
//! answers an upstream outage with an HTTP error page: `:status 502`,
//! `content-type: text/html`, no `grpc-status`. The receive-framing wrapper
//! (BUG-057/121) read the page's first byte as a compression flag and
//! reported a receive contract violation, so a transient outage failed every
//! request at once under `stall` and refused attach as misconfiguration.
//!
//! Without `grpc-status`, a non-200 HTTP status maps through gRPC's
//! HTTP-to-status table (502/503/504/429 Unavailable, 401 Unauthenticated,
//! 403 PermissionDenied, 404 Unimplemented). An HTTP 200 response whose body
//! is not gRPC framing still breaks the contract (R5-005).

use std::time::Duration;

use bytes::Bytes;
use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    ErrorClass, PlaintextUnit, SecretBuffer,
};
use maki_crypto_grpc::{GrpcCryptoProvider, GrpcProviderSpec};
use tokio::net::TcpListener;

const UNIT: usize = 512;
const PAGE: &[u8] = b"<html><body><h1>502 Bad Gateway</h1></body></html>";

#[derive(Clone, Copy, Debug)]
enum Reply {
    /// An HTML error page with this HTTP status and no gRPC status.
    Html(u16),
    /// This HTTP status with an empty body and no gRPC status.
    Empty(u16),
}

async fn server(reply: Reply) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(mut connection) = h2::server::handshake(socket).await else {
                    return;
                };
                while let Some(Ok((_request, mut respond))) = connection.accept().await {
                    let (code, body) = match reply {
                        Reply::Html(code) => (code, Some(PAGE)),
                        Reply::Empty(code) => (code, None),
                    };
                    let response = http::Response::builder()
                        .status(code)
                        .header("content-type", "text/html")
                        .body(())
                        .unwrap();
                    match body {
                        Some(page) => {
                            if let Ok(mut stream) = respond.send_response(response, false) {
                                let _ = stream.send_data(Bytes::from_static(page), true);
                            }
                        }
                        None => {
                            let _ = respond.send_response(response, true);
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
            provider_id: "grpc-http-status".into(),
            crypto_compatibility_id: "grpc-http-status-v1".into(),
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
        volume_uuid: uuid::Uuid::from_u128(175),
        format_version: 1,
        crypto_compatibility_id: "grpc-http-status-v1".into(),
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

const MAPPING: [(u16, ErrorClass); 7] = [
    (502, ErrorClass::Retryable),
    (503, ErrorClass::Retryable),
    (504, ErrorClass::Retryable),
    (429, ErrorClass::Retryable),
    (401, ErrorClass::EndpointFatal),
    (403, ErrorClass::EndpointFatal),
    (404, ErrorClass::EndpointFatal),
];

#[tokio::test]
async fn a_proxy_error_page_maps_from_the_http_status_not_its_body() {
    for (code, class) in MAPPING {
        let error = encrypt(Reply::Html(code)).await.unwrap_err();
        assert!(
            !matches!(error, CryptoError::Contract(_)),
            "HTTP {code} error page: {error:?}"
        );
        assert_eq!(error.class(), class, "HTTP {code} error page: {error:?}");
    }
}

#[tokio::test]
async fn an_empty_error_response_maps_from_the_http_status() {
    for (code, class) in MAPPING {
        let error = encrypt(Reply::Empty(code)).await.unwrap_err();
        assert_eq!(
            error.class(),
            class,
            "HTTP {code} without a body: {error:?}"
        );
    }
}

#[tokio::test]
async fn a_non_grpc_body_with_http_200_still_breaks_the_contract() {
    let result = encrypt(Reply::Html(200)).await;
    assert!(
        matches!(result, Err(CryptoError::Contract(_))),
        "{result:?}"
    );
}
