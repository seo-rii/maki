//! BUG-178: successful gRPC unary replies need one unambiguous final status.
//! Exercise actual HTTP/2 responses through the public checked provider.

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use maki_crypto::checked::CheckedProvider;
use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError,
    CryptoProvider,
};
use maki_crypto_grpc::{CryptoBatchResponse, CryptoItem, GrpcCryptoProvider, GrpcProviderSpec};
use prost::Message;

struct Reply {
    initial_statuses: Vec<&'static str>,
    final_statuses: Option<Vec<&'static str>>,
    message: bool,
}

impl Reply {
    fn with_trailers(statuses: &[&'static str]) -> Self {
        Self {
            initial_statuses: vec![],
            final_statuses: Some(statuses.to_vec()),
            message: true,
        }
    }
}

fn add_statuses(headers: &mut http::HeaderMap, statuses: &[&str]) {
    for status in statuses {
        headers.append("grpc-status", status.parse().unwrap());
    }
    if statuses.contains(&"9") {
        headers.insert("maki-crypto-error", "auth-tag-mismatch".parse().unwrap());
    }
}

async fn decrypt(reply: Reply) -> Result<(), CryptoError> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut connection = h2::server::handshake(socket).await.unwrap();
        while let Some(Ok((_request, mut respond))) = connection.accept().await {
            let mut response = http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();
            add_statuses(response.headers_mut(), &reply.initial_statuses);
            let mut stream = respond
                .send_response(response, !reply.message && reply.final_statuses.is_none())
                .unwrap();
            if reply.message {
                let protobuf = CryptoBatchResponse {
                    items: vec![CryptoItem {
                        unit_index: 7,
                        data: vec![0x4a; 64],
                    }],
                }
                .encode_to_vec();
                let mut frame = vec![0];
                frame.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
                frame.extend_from_slice(&protobuf);
                if stream
                    .send_data(Bytes::from(frame), reply.final_statuses.is_none())
                    .is_err()
                {
                    continue;
                }
            }
            if let Some(statuses) = &reply.final_statuses {
                let mut trailers = http::HeaderMap::new();
                add_statuses(&mut trailers, statuses);
                let _ = stream.send_trailers(trailers);
            }
        }
    });
    let provider = CheckedProvider::pinned(
        Arc::new(
            GrpcCryptoProvider::new(GrpcProviderSpec {
                url: format!("http://{address}"),
                encrypt_path: "/maki.Crypto/EncryptBatch".into(),
                decrypt_path: "/maki.Crypto/DecryptBatch".into(),
                metadata: vec![],
                capabilities: CryptoCapabilities {
                    provider_id: "final-status-fixture".into(),
                    crypto_compatibility_id: "final-status-v1".into(),
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
            .unwrap(),
        ),
        64,
    );
    let result = provider
        .decrypt_batch(
            &CryptoContext {
                volume_uuid: uuid::Uuid::from_u128(987),
                format_version: 1,
                crypto_compatibility_id: "final-status-v1".into(),
            },
            &[CiphertextUnit {
                unit_index: 7,
                data: vec![0x99; 64],
            }],
        )
        .await;
    server.abort();
    let _ = server.await;
    result.map(|out| {
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].data.expose(), &[0x4a; 64]);
    })
}

#[tokio::test]
async fn normal_success_control() {
    decrypt(Reply::with_trailers(&["0"])).await.unwrap();
}

#[tokio::test]
async fn single_integrity_error_control() {
    assert!(matches!(
        decrypt(Reply::with_trailers(&["9"])).await,
        Err(CryptoError::Integrity(_))
    ));
}

#[tokio::test]
async fn error_first_duplicate_status_is_also_a_contract_error() {
    let result = decrypt(Reply::with_trailers(&["9", "0"])).await;
    assert!(
        matches!(result, Err(CryptoError::Contract(_))),
        "{result:?}"
    );
}

#[tokio::test]
async fn success_first_cannot_hide_an_integrity_error() {
    let result = decrypt(Reply::with_trailers(&["0", "9"])).await;
    assert!(
        matches!(result, Err(CryptoError::Contract(_))),
        "contradictory final status: {result:?}"
    );
}

#[tokio::test]
async fn success_first_cannot_hide_an_authorization_error() {
    let result = decrypt(Reply::with_trailers(&["0", "7"])).await;
    assert!(
        matches!(result, Err(CryptoError::Contract(_))),
        "contradictory final status: {result:?}"
    );
}

#[tokio::test]
async fn success_first_cannot_hide_an_unavailable_error() {
    let result = decrypt(Reply::with_trailers(&["0", "14"])).await;
    assert!(
        matches!(result, Err(CryptoError::Contract(_))),
        "contradictory final status: {result:?}"
    );
}

#[tokio::test]
async fn explicit_end_stream_without_status_is_a_contract_error() {
    let result = decrypt(Reply {
        final_statuses: None,
        ..Reply::with_trailers(&[])
    })
    .await;
    assert!(
        matches!(result, Err(CryptoError::Contract(_))),
        "missing final status: {result:?}"
    );
}

#[tokio::test]
async fn empty_trailers_without_status_are_a_contract_error() {
    let result = decrypt(Reply::with_trailers(&[])).await;
    assert!(
        matches!(result, Err(CryptoError::Contract(_))),
        "{result:?}"
    );
}

#[tokio::test]
async fn duplicate_identical_success_status_is_rejected() {
    let result = decrypt(Reply::with_trailers(&["0", "0"])).await;
    assert!(
        matches!(result, Err(CryptoError::Contract(_))),
        "{result:?}"
    );
}

#[tokio::test]
async fn malformed_final_status_is_a_contract_error() {
    for status in ["", "bogus", "-1", "+0", "00", "17", "0,9"] {
        let result = decrypt(Reply::with_trailers(&[status])).await;
        assert!(
            matches!(result, Err(CryptoError::Contract(_))),
            "status {status:?}: {result:?}"
        );
    }
}

#[tokio::test]
async fn ambiguous_initial_status_is_rejected_before_tonic_selects_one() {
    for statuses in [
        vec!["9", "0"],
        vec!["0", "9"],
        vec!["14", "14"],
        vec!["bogus"],
    ] {
        let result = decrypt(Reply {
            initial_statuses: statuses,
            final_statuses: None,
            message: false,
        })
        .await;
        assert!(
            matches!(result, Err(CryptoError::Contract(_))),
            "{result:?}"
        );
    }
}

#[tokio::test]
async fn legitimate_remote_errors_preserve_their_classes() {
    for trailers_only in [false, true] {
        for status in ["7", "9", "14"] {
            let reply = if trailers_only {
                Reply {
                    initial_statuses: vec![status],
                    final_statuses: None,
                    message: false,
                }
            } else {
                Reply::with_trailers(&[status])
            };
            let error = decrypt(reply).await.unwrap_err();
            match status {
                "7" => assert!(matches!(error, CryptoError::EndpointFatal(_)), "{error:?}"),
                "9" => assert!(matches!(error, CryptoError::Integrity(_)), "{error:?}"),
                "14" => assert!(matches!(error, CryptoError::Retryable(_)), "{error:?}"),
                _ => unreachable!(),
            }
        }
    }
}
