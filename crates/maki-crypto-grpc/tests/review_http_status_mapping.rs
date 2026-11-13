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

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use maki_crypto::breaker::BreakerConfig;
use maki_crypto::clock::SystemClock;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use prost::Message;

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

// A controllable HTTP/2 intermediary: error pages during an outage, valid
// gRPC frames after recovery. Exercise the actual transport + retry dispatcher,
// including a second outage while decrypting the ciphertext from the first call.
#[derive(Default)]
struct ProxyState {
    healthy: AtomicBool,
    failures: AtomicUsize,
}

async fn recovering_proxy(state: Arc<ProxyState>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let state = state.clone();
            tokio::spawn(async move {
                let Ok(mut connection) = h2::server::handshake(socket).await else {
                    return;
                };
                while let Some(Ok((request, mut respond))) = connection.accept().await {
                    let state = state.clone();
                    tokio::spawn(async move {
                        if !state.healthy.load(Ordering::SeqCst) {
                            let response = http::Response::builder()
                                .status(502)
                                .header("content-type", "text/html")
                                .body(())
                                .unwrap();
                            if let Ok(mut stream) = respond.send_response(response, false) {
                                let _ = stream.send_data(Bytes::from_static(PAGE), true);
                                state.failures.fetch_add(1, Ordering::SeqCst);
                            }
                            return;
                        }
                        let mut body = request.into_body();
                        let mut framed = Vec::new();
                        while let Some(chunk) = body.data().await {
                            let chunk = chunk.unwrap();
                            framed.extend_from_slice(&chunk);
                            body.flow_control().release_capacity(chunk.len()).unwrap();
                        }
                        assert_eq!(framed[0], 0);
                        let request =
                            maki_crypto_grpc::CryptoBatchRequest::decode(&framed[5..]).unwrap();
                        let message = maki_crypto_grpc::CryptoBatchResponse {
                            items: request
                                .items
                                .into_iter()
                                .map(|item| maki_crypto_grpc::CryptoItem {
                                    unit_index: item.unit_index,
                                    data: item.data.iter().map(|byte| byte ^ 0x55).collect(),
                                })
                                .collect(),
                        };
                        let payload = message.encode_to_vec();
                        let mut frame = vec![0];
                        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                        frame.extend_from_slice(&payload);
                        let response = http::Response::builder()
                            .status(200)
                            .header("content-type", "application/grpc")
                            .body(())
                            .unwrap();
                        if let Ok(mut stream) = respond.send_response(response, false) {
                            stream.send_data(Bytes::from(frame), false).unwrap();
                            let mut trailers = http::HeaderMap::new();
                            trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
                            stream.send_trailers(trailers).unwrap();
                        }
                    });
                }
            });
        }
    });
    url
}

async fn observe_outage<T>(state: &ProxyState, request: &tokio::task::JoinHandle<T>) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while state.failures.load(Ordering::SeqCst) < 2 {
            assert!(
                !request.is_finished(),
                "stall request failed during proxy outage"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the dispatcher must retry the HTTP error page");
    assert!(!request.is_finished());
}

#[tokio::test]
async fn stall_resumes_encrypt_and_decrypt_after_a_proxy_recovers() {
    let state = Arc::new(ProxyState::default());
    let remote = Arc::new(provider(recovering_proxy(state.clone()).await));
    let set = Arc::new(EndpointSet::new(
        vec![("proxy".into(), remote)],
        DispatchConfig {
            retry: RetryPolicy {
                initial_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(2),
            },
            budget: RetryBudgetConfig {
                retry_ratio: 1.0,
                burst: 16,
                min_probe_per_sec: 100.0,
            },
            breaker: BreakerConfig {
                failure_threshold: 1,
                open_initial: Duration::from_millis(2),
                open_max: Duration::from_millis(2),
                half_open_max_requests: 1,
                success_threshold: 1,
            },
            global_max_inflight_batches: 1,
            global_max_inflight_bytes: 4096,
            per_endpoint_max_inflight: 1,
            per_endpoint_max_bytes: 4096,
            max_attempts: None,
            max_operation_time: None,
            retry_safe: true,
            validation_interval: Duration::from_millis(2),
        },
        Arc::new(SystemClock::new()),
    ));
    let context = CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(175),
        format_version: 1,
        crypto_compatibility_id: "grpc-http-status-v1".into(),
    };
    let encrypt = {
        let set = set.clone();
        let context = context.clone();
        tokio::spawn(async move {
            set.encrypt_batch(
                &context,
                &[PlaintextUnit {
                    unit_index: 7,
                    data: SecretBuffer::from_slice(&[9; UNIT]),
                }],
            )
            .await
        })
    };
    observe_outage(&state, &encrypt).await;
    state.healthy.store(true, Ordering::SeqCst);
    let ciphertext = tokio::time::timeout(Duration::from_secs(5), encrypt)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(ciphertext[0].unit_index, 7);
    assert_eq!(set.global_inflight(), (0, 0));

    state.failures.store(0, Ordering::SeqCst);
    state.healthy.store(false, Ordering::SeqCst);
    let decrypt = {
        let set = set.clone();
        tokio::spawn(async move { set.decrypt_batch(&context, &ciphertext).await })
    };
    observe_outage(&state, &decrypt).await;
    state.healthy.store(true, Ordering::SeqCst);
    let plaintext = tokio::time::timeout(Duration::from_secs(5), decrypt)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(plaintext[0].unit_index, 7);
    assert_eq!(plaintext[0].data.expose(), &[9; UNIT]);
    assert_eq!(set.global_inflight(), (0, 0));
    assert!(set.metrics().retries_total() >= 2);
}
