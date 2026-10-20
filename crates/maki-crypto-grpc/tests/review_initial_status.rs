//! BUG-131: initial OK headers made tonic skip the unary completion status.
//! A raw HTTP/2 peer exercises responses a conforming gRPC server would not
//! emit, including a well-shaped result followed by an integrity rejection.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use maki_crypto::breaker::BreakerConfig;
use maki_crypto::checked::CheckedProvider;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError,
    CryptoProvider, ErrorClass, PlaintextUnit, SecretBuffer, SystemClock,
};
use maki_crypto_grpc::{GrpcCryptoProvider, GrpcProviderSpec};
use tokio::task::{JoinHandle, JoinSet};

const UNIT: usize = 64;

#[derive(Clone, Copy, Debug)]
struct Reply {
    initial_status: Option<&'static str>,
    message: bool,
    trailer_status: Option<&'static str>,
}

struct Server {
    url: String,
    calls: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Server {
    async fn start(reply: Reply) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let task = tokio::spawn(async move {
            // Abort every connection when the fixture is dropped, including
            // connections created by a dispatch retry.
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    socket = listener.accept() => {
                        let (socket, _) = socket.unwrap();
                        let calls = observed.clone();
                        connections.spawn(async move {
                            let mut connection = h2::server::handshake(socket).await.unwrap();
                            while let Some(request) = connection.accept().await {
                                let (_request, mut respond) = request.unwrap();
                                calls.fetch_add(1, Ordering::SeqCst);
                                let mut response = http::Response::builder()
                                    .status(200)
                                    .header("content-type", "application/grpc")
                                    .body(())
                                    .unwrap();
                                if let Some(status) = reply.initial_status {
                                    set_status(response.headers_mut(), status);
                                }
                                let end = !reply.message && reply.trailer_status.is_none();
                                let mut stream = respond.send_response(response, end).unwrap();
                                if reply.message {
                                    // Independent protobuf encoding:
                                    // items[0] = {unit_index: 7, data: [0x4a; 64]}.
                                    let mut protobuf = vec![0x0a, 68, 0x08, 7, 0x12, 64];
                                    protobuf.extend_from_slice(&[0x4a; UNIT]);
                                    let mut frame = vec![0];
                                    frame.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
                                    frame.extend_from_slice(&protobuf);
                                    // Rejection at the initial headers may reset this stream.
                                    if stream.send_data(Bytes::from(frame), reply.trailer_status.is_none()).is_err() {
                                        continue;
                                    }
                                }
                                if let Some(status) = reply.trailer_status {
                                    let mut trailers = http::HeaderMap::new();
                                    set_status(&mut trailers, status);
                                    let _ = stream.send_trailers(trailers);
                                }
                            }
                        });
                    }
                    Some(result) = connections.join_next() => result.unwrap(),
                }
            }
        });
        Self { url, calls, task }
    }

    fn provider(&self) -> Arc<dyn CryptoProvider> {
        Arc::new(
            GrpcCryptoProvider::new(GrpcProviderSpec {
                url: self.url.clone(),
                encrypt_path: "/maki.CryptoService/EncryptBatch".into(),
                decrypt_path: "/maki.CryptoService/DecryptBatch".into(),
                metadata: vec![],
                capabilities: CryptoCapabilities {
                    provider_id: "grpc-initial-status".into(),
                    crypto_compatibility_id: "grpc-initial-status-v1".into(),
                    supported_plaintext_sizes: vec![UNIT as u32],
                    max_ciphertext_size: UNIT as u32,
                    stateless: true,
                    retry_safe: true,
                    batch: BatchCapability {
                        supported: true,
                        max_items: 8,
                        max_bytes: 4096,
                    },
                    integrity: Capability::Verified,
                    context_binding: Capability::Absent,
                    replay_protection: Capability::Absent,
                },
                timeout: Duration::from_secs(2),
                max_message_bytes: 4096,
            })
            .unwrap(),
        )
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn set_status(headers: &mut http::HeaderMap, status: &'static str) {
    headers.insert("grpc-status", status.parse().unwrap());
    if status == "9" {
        headers.insert("maki-crypto-error", "auth-tag-mismatch".parse().unwrap());
    }
}

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(131),
        format_version: 1,
        crypto_compatibility_id: "grpc-initial-status-v1".into(),
    }
}

async fn encrypt(provider: &dyn CryptoProvider) -> Result<(), CryptoError> {
    let output = provider
        .encrypt_batch(
            &context(),
            &[PlaintextUnit {
                unit_index: 7,
                data: SecretBuffer::from_slice(&[0x99; UNIT]),
            }],
        )
        .await?;
    assert_eq!(output.len(), 1);
    assert_eq!(output[0].data, [0x4a; UNIT]);
    Ok(())
}

async fn decrypt(provider: &dyn CryptoProvider) -> Result<(), CryptoError> {
    let output = provider
        .decrypt_batch(
            &context(),
            &[CiphertextUnit {
                unit_index: 7,
                data: vec![0x99; UNIT],
            }],
        )
        .await?;
    assert_eq!(output.len(), 1);
    assert_eq!(output[0].data.expose(), &[0x4a; UNIT]);
    Ok(())
}

fn dispatch(servers: &[&Server], retry_safe: bool) -> EndpointSet {
    // The dispatcher fixture models endpoints already validated at attach.
    EndpointSet::new(
        servers
            .iter()
            .enumerate()
            .map(|(index, server)| (format!("endpoint-{index}"), server.provider()))
            .collect(),
        DispatchConfig {
            retry: RetryPolicy {
                initial_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(1),
            },
            budget: RetryBudgetConfig {
                retry_ratio: 1.0,
                burst: 4,
                min_probe_per_sec: 1.0,
            },
            breaker: BreakerConfig {
                failure_threshold: 3,
                open_initial: Duration::from_secs(60),
                open_max: Duration::from_secs(60),
                half_open_max_requests: 1,
                success_threshold: 1,
            },
            global_max_inflight_batches: 2,
            global_max_inflight_bytes: 4096,
            per_endpoint_max_inflight: 2,
            per_endpoint_max_bytes: 4096,
            max_attempts: Some(2),
            max_operation_time: Some(Duration::from_secs(2)),
            retry_safe,
            validation_interval: Duration::from_secs(1),
        },
        Arc::new(SystemClock::new()),
    )
}

#[tokio::test]
async fn initial_ok_without_a_message_is_a_contract_failure() {
    let server = Server::start(Reply {
        initial_status: Some("0"),
        message: false,
        trailer_status: None,
    })
    .await;
    let result = encrypt(server.provider().as_ref()).await;
    assert!(
        matches!(result, Err(CryptoError::Contract(_))),
        "{result:?}"
    );
}

#[tokio::test]
async fn initial_ok_cannot_override_a_later_error_trailer() {
    for status in ["7", "14"] {
        let server = Server::start(Reply {
            initial_status: Some("0"),
            message: true,
            trailer_status: Some(status),
        })
        .await;
        let result = encrypt(server.provider().as_ref()).await;
        assert!(
            matches!(result, Err(CryptoError::Contract(_))),
            "trailer {status}: {result:?}"
        );
    }
}

#[tokio::test]
async fn checked_decrypt_rejects_initial_ok_before_an_integrity_error() {
    let server = Server::start(Reply {
        initial_status: Some("0"),
        message: true,
        trailer_status: Some("9"),
    })
    .await;
    let checked = CheckedProvider::pinned(server.provider(), UNIT as u32);
    let result = decrypt(&checked).await;
    assert!(
        matches!(result, Err(CryptoError::Contract(_))),
        "{result:?}"
    );
}

#[tokio::test]
async fn initial_ok_with_data_is_rejected_even_without_an_error_trailer() {
    for trailer_status in [None, Some("0")] {
        let server = Server::start(Reply {
            initial_status: Some("0"),
            message: true,
            trailer_status,
        })
        .await;
        let result = encrypt(server.provider().as_ref()).await;
        assert!(
            matches!(result, Err(CryptoError::Contract(_))),
            "trailer {trailer_status:?}: {result:?}"
        );
    }
}

#[tokio::test]
async fn healthy_unary_response_still_reaches_checked_callers() {
    let server = Server::start(Reply {
        initial_status: None,
        message: true,
        trailer_status: Some("0"),
    })
    .await;
    let checked = CheckedProvider::pinned(server.provider(), UNIT as u32);
    encrypt(&checked).await.unwrap();
    decrypt(&checked).await.unwrap();
    assert_eq!(server.calls(), 2);
}

#[tokio::test]
async fn legitimate_remote_statuses_keep_their_class_and_integrity_metadata() {
    for (status, class) in [
        ("7", ErrorClass::EndpointFatal),
        ("14", ErrorClass::Retryable),
        ("9", ErrorClass::NonRetryableRequest),
    ] {
        for reply in [
            Reply {
                initial_status: Some(status),
                message: false,
                trailer_status: None,
            },
            Reply {
                initial_status: None,
                message: true,
                trailer_status: Some(status),
            },
        ] {
            let server = Server::start(reply).await;
            let result = decrypt(server.provider().as_ref()).await;
            assert_eq!(result.as_ref().unwrap_err().class(), class, "{reply:?}");
            if status == "9" {
                assert!(
                    matches!(result, Err(CryptoError::Integrity(_))),
                    "{reply:?}"
                );
            }
        }
    }
}

#[tokio::test]
async fn an_initial_ok_contract_failure_is_never_resent_to_the_same_peer() {
    let server = Server::start(Reply {
        initial_status: Some("0"),
        message: false,
        trailer_status: None,
    })
    .await;
    let result = encrypt(&dispatch(&[&server], true)).await;
    assert!(
        matches!(result, Err(CryptoError::Contract(_))),
        "{result:?}"
    );
    assert_eq!(server.calls(), 1);
}

#[tokio::test]
async fn safe_dispatch_uses_a_healthy_peer_instead_of_accepting_false_success() {
    let broken = Server::start(Reply {
        initial_status: Some("0"),
        message: true,
        trailer_status: Some("7"),
    })
    .await;
    let healthy = Server::start(Reply {
        initial_status: None,
        message: true,
        trailer_status: Some("0"),
    })
    .await;
    encrypt(&dispatch(&[&broken, &healthy], true))
        .await
        .unwrap();
    assert_eq!(broken.calls(), 1);
    assert_eq!(healthy.calls(), 1);
}

#[tokio::test]
async fn unsafe_dispatch_does_not_send_the_rejected_request_to_another_peer() {
    let broken = Server::start(Reply {
        initial_status: Some("0"),
        message: true,
        trailer_status: Some("7"),
    })
    .await;
    let healthy = Server::start(Reply {
        initial_status: None,
        message: true,
        trailer_status: Some("0"),
    })
    .await;
    let result = encrypt(&dispatch(&[&broken, &healthy], false)).await;
    assert!(
        matches!(result, Err(CryptoError::Contract(_))),
        "{result:?}"
    );
    assert_eq!(broken.calls(), 1);
    assert_eq!(healthy.calls(), 0);
}
