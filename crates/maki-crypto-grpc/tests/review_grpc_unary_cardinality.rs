//! Additional audit: unary gRPC replies must contain exactly one message.

use std::time::Duration;

use bytes::Bytes;
use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError,
    CryptoProvider, PlaintextUnit, SecretBuffer,
};
use maki_crypto_grpc::{CryptoBatchResponse, CryptoItem, GrpcCryptoProvider, GrpcProviderSpec};
use prost::Message;

enum Reply {
    Messages { count: usize, frame_bytes: usize },
    PartialExtraHeader(usize),
    RemoteStatus { messages: usize, code: &'static str },
}

async fn encrypt_with_reply(reply: Reply) -> Result<Vec<CiphertextUnit>, CryptoError> {
    let (messages, frame_bytes, extra_header_bytes, status) = match reply {
        Reply::Messages { count, frame_bytes } => (count, frame_bytes, 0, "0"),
        Reply::PartialExtraHeader(bytes) => (1, usize::MAX, bytes, "0"),
        Reply::RemoteStatus { messages, code } => (messages, usize::MAX, 0, code),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut connection = h2::server::handshake(socket).await.unwrap();
        while let Some(Ok((_request, mut respond))) = connection.accept().await {
            let response = http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();
            let mut stream = respond.send_response(response, false).unwrap();
            let mut framed = Vec::new();
            for index in 0..messages {
                let response = CryptoBatchResponse {
                    items: vec![CryptoItem {
                        // The extra message is a foreign result. It must not
                        // disappear while the first message becomes success.
                        unit_index: if index == 0 { 7 } else { 99 },
                        data: vec![0x4a + index as u8; 512],
                    }],
                }
                .encode_to_vec();
                framed.push(0);
                framed.extend_from_slice(&(response.len() as u32).to_be_bytes());
                framed.extend_from_slice(&response);
            }
            framed.extend_from_slice(&[0, 0, 0, 0, 4][..extra_header_bytes]);
            for chunk in framed.chunks(frame_bytes) {
                stream
                    .send_data(Bytes::copy_from_slice(chunk), false)
                    .unwrap();
            }
            let mut trailers = http::HeaderMap::new();
            trailers.insert("grpc-status", status.parse().unwrap());
            stream.send_trailers(trailers).unwrap();
        }
    });
    let provider = GrpcCryptoProvider::new(GrpcProviderSpec {
        url: format!("http://{address}"),
        encrypt_path: "/maki.CryptoService/EncryptBatch".into(),
        decrypt_path: "/maki.CryptoService/DecryptBatch".into(),
        metadata: vec![],
        capabilities: CryptoCapabilities {
            provider_id: "audit-unary".into(),
            crypto_compatibility_id: "audit-v1".into(),
            supported_plaintext_sizes: vec![512],
            max_ciphertext_size: 512,
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
        timeout: Duration::from_secs(5),
        max_message_bytes: 4096,
    })
    .unwrap();
    let result = provider
        .encrypt_batch(
            &CryptoContext {
                volume_uuid: uuid::Uuid::from_u128(19),
                format_version: 1,
                crypto_compatibility_id: "audit-v1".into(),
            },
            &[PlaintextUnit {
                unit_index: 7,
                data: SecretBuffer::from_slice(&[0x65; 512]),
            }],
        )
        .await;
    server.abort();
    let _ = server.await;
    result
}

#[tokio::test]
async fn a_second_message_in_a_unary_response_breaks_the_contract() {
    let result = encrypt_with_reply(Reply::Messages {
        count: 2,
        frame_bytes: usize::MAX,
    })
    .await;
    let accepted = result
        .as_ref()
        .ok()
        .map(|items| items.iter().map(|item| item.unit_index).collect::<Vec<_>>());
    assert!(
        matches!(result, Err(CryptoError::Contract(_))),
        "a unary reply with two messages was accepted: {accepted:?}"
    );
}

#[tokio::test]
async fn one_message_in_a_unary_response_is_accepted() {
    let output = encrypt_with_reply(Reply::Messages {
        count: 1,
        frame_bytes: usize::MAX,
    })
    .await
    .unwrap();
    assert_eq!(output.len(), 1);
    assert_eq!(output[0].unit_index, 7);
    assert_eq!(output[0].data, vec![0x4a; 512]);
}

#[tokio::test]
async fn a_fragmented_second_message_also_breaks_the_unary_contract() {
    for frame_bytes in [1, 3, 5, 31] {
        let result = encrypt_with_reply(Reply::Messages {
            count: 2,
            frame_bytes,
        })
        .await;
        assert!(
            matches!(result, Err(CryptoError::Contract(_))),
            "{result:?}"
        );
    }
}

#[tokio::test]
async fn a_partial_second_header_cannot_hide_behind_success_trailers() {
    for bytes in 1..5 {
        let result = encrypt_with_reply(Reply::PartialExtraHeader(bytes)).await;
        assert!(
            matches!(result, Err(CryptoError::Contract(_))),
            "{result:?}"
        );
    }
}

#[tokio::test]
async fn remote_errors_without_a_message_keep_their_original_classification() {
    let result = encrypt_with_reply(Reply::RemoteStatus {
        messages: 0,
        code: "5", // NotFound.
    })
    .await;
    assert!(matches!(result, Err(CryptoError::NonRetryableRequest(_))));
}

#[tokio::test]
async fn a_remote_error_after_one_message_keeps_its_original_classification() {
    let result = encrypt_with_reply(Reply::RemoteStatus {
        messages: 1,
        code: "7", // PermissionDenied.
    })
    .await;
    assert!(matches!(result, Err(CryptoError::EndpointFatal(_))));
}
