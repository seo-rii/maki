//! The remote status text (`grpc-message`) and details
//! (`grpc-status-details-bin`) are peer-controlled bytes that Maki never
//! uses (SPEC §18: remote error text is ignored). tonic parses both while it
//! reads a status: it panics on details that are not base64, and it replaces
//! the status code with `Unknown` when the message does not percent-decode
//! to UTF-8. Neither may crash a provider call or change its error class,
//! whether the status arrives in trailers-only initial headers or in the
//! trailers after a message.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use maki_crypto::breaker::BreakerConfig;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError,
    CryptoProvider, ErrorClass, SystemClock,
};
use maki_crypto_grpc::{CryptoBatchResponse, CryptoItem, GrpcCryptoProvider, GrpcProviderSpec};
use prost::Message as _;
use tokio::task::{JoinHandle, JoinSet};

const UNIT: usize = 64;
const MALFORMED_DETAILS: (&str, &str) = ("grpc-status-details-bin", "!!not-base64!!");

#[derive(Clone, Copy, Debug)]
enum Placement {
    /// A trailers-only response: the status ends the initial headers.
    Initial,
    /// Initial headers without a status, then the status in trailers.
    Trailers,
}

#[derive(Clone, Copy, Debug)]
struct Reply {
    placement: Placement,
    /// A valid one-item result before the trailers (`Trailers` only).
    message: bool,
    status: &'static str,
    /// Sent next to the status.
    headers: &'static [(&'static str, &'static str)],
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
            // connections a dispatch retry opened.
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    socket = listener.accept() => {
                        let (socket, _) = socket.unwrap();
                        let calls = observed.clone();
                        connections.spawn(serve(socket, reply, calls));
                    }
                    Some(_) = connections.join_next() => {}
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
                    provider_id: "grpc-status-headers".into(),
                    crypto_compatibility_id: "grpc-status-headers-v1".into(),
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

async fn serve(socket: tokio::net::TcpStream, reply: Reply, calls: Arc<AtomicUsize>) {
    let Ok(mut connection) = h2::server::handshake(socket).await else {
        return;
    };
    while let Some(Ok((_request, mut respond))) = connection.accept().await {
        calls.fetch_add(1, Ordering::SeqCst);
        let mut response = http::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(())
            .unwrap();
        let mut status = http::HeaderMap::new();
        status.insert("grpc-status", reply.status.parse().unwrap());
        if reply.status == "9" {
            status.insert("maki-crypto-error", "auth-tag-mismatch".parse().unwrap());
        }
        for (name, value) in reply.headers {
            status.append(*name, value.parse().unwrap());
        }
        match reply.placement {
            Placement::Initial => {
                response.headers_mut().extend(status);
                let _ = respond.send_response(response, true);
            }
            Placement::Trailers => {
                let Ok(mut stream) = respond.send_response(response, false) else {
                    continue;
                };
                if reply.message {
                    let protobuf = CryptoBatchResponse {
                        items: vec![CryptoItem {
                            unit_index: 7,
                            data: vec![0x4a; UNIT],
                        }],
                    }
                    .encode_to_vec();
                    let mut frame = vec![0];
                    frame.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
                    frame.extend_from_slice(&protobuf);
                    if stream.send_data(Bytes::from(frame), false).is_err() {
                        continue;
                    }
                }
                let _ = stream.send_trailers(status);
            }
        }
    }
}

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x5747),
        format_version: 1,
        crypto_compatibility_id: "grpc-status-headers-v1".into(),
    }
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

/// One decrypt on its own task, so a panic inside the provider is reported
/// as `Err` instead of aborting the test before every case has run.
async fn isolated_decrypt(
    provider: Arc<dyn CryptoProvider>,
) -> Result<Result<(), CryptoError>, ()> {
    tokio::spawn(async move { decrypt(provider.as_ref()).await })
        .await
        .map_err(|error| assert!(error.is_panic(), "{error:?}"))
}

/// The class the status code alone determines. Status 9 carries Maki's
/// `auth-tag-mismatch` metadata, so it is a definitive integrity failure.
fn expected(status: &str) -> ErrorClass {
    match status {
        "9" | "3" => ErrorClass::NonRetryableRequest,
        "7" | "16" => ErrorClass::EndpointFatal,
        "8" => ErrorClass::Throttled,
        "13" | "14" => ErrorClass::Retryable,
        other => unreachable!("no expectation for status {other}"),
    }
}

/// Checks one reply's outcome against the class of its status code alone.
async fn check(reply: Reply, wrong: &mut Vec<String>) {
    let server = Server::start(reply).await;
    let outcome = isolated_decrypt(server.provider()).await;
    let fault = match &outcome {
        Err(()) => Some("the provider call panicked".to_string()),
        Ok(Ok(())) if reply.status == "0" => None,
        Ok(Ok(())) => Some("an error status returned a result".to_string()),
        Ok(Err(error)) if reply.status == "0" => Some(format!("success became {error:?}")),
        Ok(Err(error)) if error.class() != expected(reply.status) => Some(format!(
            "class {:?}, expected {:?}: {error:?}",
            error.class(),
            expected(reply.status)
        )),
        Ok(Err(error)) if reply.status == "9" && !matches!(error, CryptoError::Integrity(_)) => {
            Some(format!("integrity rejection became {error:?}"))
        }
        Ok(Err(_)) => None,
    };
    if let Some(fault) = fault {
        wrong.push(format!("{reply:?}: {fault}"));
    }
}

#[tokio::test]
async fn malformed_status_details_neither_panic_nor_change_the_status_class() {
    let mut wrong = Vec::new();
    for placement in [Placement::Initial, Placement::Trailers] {
        for status in ["13", "9", "7"] {
            check(
                Reply {
                    placement,
                    message: false,
                    status,
                    headers: &[MALFORMED_DETAILS],
                },
                &mut wrong,
            )
            .await;
        }
    }
    // A unary result followed by OK trailers is a success whatever the
    // details header holds.
    check(
        Reply {
            placement: Placement::Trailers,
            message: true,
            status: "0",
            headers: &[MALFORMED_DETAILS],
        },
        &mut wrong,
    )
    .await;
    assert!(
        wrong.is_empty(),
        "peer status details changed the outcome:\n{}",
        wrong.join("\n")
    );
}

#[tokio::test]
async fn remote_status_text_does_not_change_the_error_class() {
    // Controls (no text, valid percent-encoded UTF-8) and text that does not
    // decode to UTF-8 (a C-core server percent-encodes arbitrary bytes).
    const MESSAGES: [&[(&str, &str)]; 4] = [
        &[],
        &[("grpc-message", "tag%20mismatch")],
        &[("grpc-message", "tag%FFmismatch")],
        &[("grpc-message", "%C3%28")],
    ];
    let mut wrong = Vec::new();
    for placement in [Placement::Initial, Placement::Trailers] {
        for status in ["9", "7", "16", "3", "8", "14"] {
            for headers in MESSAGES {
                check(
                    Reply {
                        placement,
                        message: false,
                        status,
                        headers,
                    },
                    &mut wrong,
                )
                .await;
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "remote status text changed the error class:\n{}",
        wrong.join("\n")
    );
}

#[tokio::test]
async fn a_successful_status_with_undecodable_text_returns_its_result() {
    let mut wrong = Vec::new();
    for headers in [
        &[("grpc-message", "%FF")][..],
        &[("grpc-message", "%FF"), MALFORMED_DETAILS][..],
    ] {
        check(
            Reply {
                placement: Placement::Trailers,
                message: true,
                status: "0",
                headers,
            },
            &mut wrong,
        )
        .await;
    }
    assert!(
        wrong.is_empty(),
        "remote status text turned a success into a failure:\n{}",
        wrong.join("\n")
    );
}

#[tokio::test]
async fn dispatch_fails_over_from_a_peer_with_malformed_status_details() {
    let bad = Server::start(Reply {
        placement: Placement::Trailers,
        message: false,
        status: "13",
        headers: &[MALFORMED_DETAILS],
    })
    .await;
    let good = Server::start(Reply {
        placement: Placement::Trailers,
        message: true,
        status: "0",
        headers: &[],
    })
    .await;
    // Least-inflight selection prefers the first endpoint while both are
    // idle, so the malformed peer is tried first.
    let set = Arc::new(EndpointSet::new(
        vec![
            ("bad".into(), bad.provider()),
            ("good".into(), good.provider()),
        ],
        DispatchConfig {
            retry: RetryPolicy {
                initial_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(1),
            },
            budget: RetryBudgetConfig {
                retry_ratio: 1.0,
                burst: 100,
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
            max_operation_time: Some(Duration::from_secs(5)),
            retry_safe: true,
            validation_interval: Duration::from_secs(1),
        },
        Arc::new(SystemClock::new()),
    ));
    let mut failures = Vec::new();
    for request in 0..10 {
        match isolated_decrypt(set.clone()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => failures.push(format!("request {request}: {error:?}")),
            Err(()) => failures.push(format!("request {request}: dispatch panicked")),
        }
    }
    assert!(
        failures.is_empty(),
        "a peer's malformed status details failed requests a healthy peer \
         could serve:\n{}",
        failures.join("\n")
    );
    assert!(bad.calls() >= 1, "the malformed peer was never tried");
    assert_eq!(good.calls(), 10);
}
