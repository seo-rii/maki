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
//! the other codes are `Internal` (retryable). A GOAWAY whose last stream
//! id is below the call's stream refuses the call (the server did not
//! process it, RFC 9113 §6.8) and is classified by its code exactly like a
//! reset; a gRPC keepalive policy that refuses a client for pinging too
//! often sends `ENHANCE_YOUR_CALM` this way. A GOAWAY that accepted the
//! call and then ends the connection under it is `Unknown` (retryable),
//! whatever its code. The transport marks neither as unsent: the request
//! was handed to the connection, so a provider that is not retry-safe is
//! not sent it again. The next call opens a new connection.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use maki_crypto::breaker::BreakerConfig;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    ErrorClass, PlaintextUnit, SecretBuffer, SystemClock,
};
use maki_crypto_grpc::{CryptoBatchResponse, CryptoItem, GrpcCryptoProvider, GrpcProviderSpec};
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const UNIT: usize = 512;

#[derive(Clone, Copy, Debug)]
enum Failure {
    /// Reset the stream before any response headers.
    ResetBeforeHeaders(h2::Reason),
    /// Send the response headers and part of a message, then reset.
    ResetInsideMessage(h2::Reason),
    /// Send the response headers, then shut the connection down with a
    /// GOAWAY that names the call's stream as processed.
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

async fn encrypt_with(provider: &GrpcCryptoProvider) -> Result<(), CryptoError> {
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
        .map(|out| assert_eq!(out.len(), 1))
}

async fn encrypt(failure: Failure) -> CryptoError {
    encrypt_with(&provider(server(failure).await))
        .await
        .expect_err("the call failed at the HTTP/2 layer")
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = (payload.len() as u32).to_be_bytes()[1..].to_vec();
    frame.extend([kind, flags]);
    frame.extend(stream.to_be_bytes());
    frame.extend(payload);
    frame
}

/// A raw HTTP/2 peer that answers the first request stream it receives
/// with `GOAWAY(last_stream_id = 0, reason)`, so that stream is refused,
/// and keeps the connection open until the client closes it. The h2
/// server API names every accepted stream as processed, so it cannot send
/// this.
async fn refuse_with_goaway(mut socket: TcpStream, reason: h2::Reason, streams: &AtomicUsize) {
    let mut preface = [0; 24];
    if socket.read_exact(&mut preface).await.is_err() {
        return;
    }
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    const SETTINGS: u8 = 0x4;
    const HEADERS: u8 = 0x1;
    const GOAWAY: u8 = 0x7;
    socket.write_all(&frame(SETTINGS, 0, 0, &[])).await.unwrap();
    loop {
        let mut header = [0; 9];
        if socket.read_exact(&mut header).await.is_err() {
            return;
        }
        let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
        let (kind, flags) = (header[3], header[4]);
        let stream = u32::from_be_bytes(header[5..].try_into().unwrap()) & 0x7fff_ffff;
        let mut payload = vec![0; length];
        if socket.read_exact(&mut payload).await.is_err() {
            return;
        }
        let reply = match kind {
            SETTINGS if flags & 0x1 == 0 => frame(SETTINGS, 0x1, 0, &[]),
            HEADERS if stream > 0 => {
                streams.fetch_add(1, Ordering::SeqCst);
                let mut goaway = 0_u32.to_be_bytes().to_vec();
                goaway.extend(u32::from(reason).to_be_bytes());
                frame(GOAWAY, 0, 0, &goaway)
            }
            _ => continue,
        };
        if socket.write_all(&reply).await.is_err() {
            return;
        }
    }
}

/// A healthy gRPC peer for the connections after the first.
async fn serve(socket: TcpStream, streams: &AtomicUsize) {
    let mut connection = h2::server::handshake(socket).await.unwrap();
    while let Some(Ok((_request, mut respond))) = connection.accept().await {
        streams.fetch_add(1, Ordering::SeqCst);
        let response = http::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(())
            .unwrap();
        let mut stream = respond.send_response(response, false).unwrap();
        let message = CryptoBatchResponse {
            items: vec![CryptoItem {
                unit_index: 1,
                data: vec![0x4a; UNIT],
            }],
        }
        .encode_to_vec();
        let mut framed = vec![0];
        framed.extend((message.len() as u32).to_be_bytes());
        framed.extend(message);
        stream.send_data(Bytes::from(framed), false).unwrap();
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().unwrap());
        stream.send_trailers(trailers).unwrap();
    }
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

#[tokio::test]
async fn a_goaway_that_refuses_the_call_is_classified_by_its_code_like_a_reset() {
    use h2::Reason;
    for (reason, expected) in [
        (Reason::NO_ERROR, ErrorClass::Retryable),
        (Reason::PROTOCOL_ERROR, ErrorClass::Retryable),
        (Reason::INTERNAL_ERROR, ErrorClass::Retryable),
        (Reason::FLOW_CONTROL_ERROR, ErrorClass::Retryable),
        (Reason::REFUSED_STREAM, ErrorClass::Retryable),
        (Reason::CANCEL, ErrorClass::Retryable),
        (Reason::ENHANCE_YOUR_CALM, ErrorClass::Throttled),
        (Reason::INADEQUATE_SECURITY, ErrorClass::EndpointFatal),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let connections = Arc::new(AtomicUsize::new(0));
        let refused = Arc::new(AtomicUsize::new(0));
        let served = Arc::new(AtomicUsize::new(0));
        let server = {
            let (connections, refused, served) =
                (connections.clone(), refused.clone(), served.clone());
            tokio::spawn(async move {
                while let Ok((socket, _)) = listener.accept().await {
                    let first = connections.fetch_add(1, Ordering::SeqCst) == 0;
                    let (refused, served) = (refused.clone(), served.clone());
                    tokio::spawn(async move {
                        if first {
                            refuse_with_goaway(socket, reason, &refused).await
                        } else {
                            serve(socket, &served).await
                        }
                    });
                }
            })
        };
        let provider = provider(url);
        let error = encrypt_with(&provider)
            .await
            .expect_err("the GOAWAY refused the call");
        assert_eq!(error.class(), expected, "{reason:?}: {error:?}");
        assert!(
            !matches!(error, CryptoError::Contract(_)),
            "{reason:?}: {error:?}"
        );
        // Handed to the connection: possibly sent, and not resent.
        assert!(!error.is_not_sent(), "{reason:?}: {error:?}");
        assert_eq!(refused.load(Ordering::SeqCst), 1, "{reason:?}");
        // Nothing is wedged: the next call opens a new connection.
        encrypt_with(&provider)
            .await
            .unwrap_or_else(|error| panic!("{reason:?}: the next call failed: {error:?}"));
        assert_eq!(served.load(Ordering::SeqCst), 1, "{reason:?}");
        assert_eq!(connections.load(Ordering::SeqCst), 2, "{reason:?}");
        server.abort();
    }
}

/// A call that a GOAWAY refused was handed to the connection, so the
/// dispatcher counts it as sent: without retry safety it is not sent to
/// another endpoint, although the server did not process it.
#[tokio::test]
async fn a_call_refused_by_goaway_fails_over_only_when_retry_safe() {
    for retry_safe in [false, true] {
        let refusing = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let healthy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let urls = [
            format!("http://{}", refusing.local_addr().unwrap()),
            format!("http://{}", healthy.local_addr().unwrap()),
        ];
        let refused = Arc::new(AtomicUsize::new(0));
        let served = Arc::new(AtomicUsize::new(0));
        let servers = [
            tokio::spawn({
                let refused = refused.clone();
                async move {
                    while let Ok((socket, _)) = refusing.accept().await {
                        let refused = refused.clone();
                        tokio::spawn(async move {
                            refuse_with_goaway(socket, h2::Reason::REFUSED_STREAM, &refused).await
                        });
                    }
                }
            }),
            tokio::spawn({
                let served = served.clone();
                async move {
                    while let Ok((socket, _)) = healthy.accept().await {
                        let served = served.clone();
                        tokio::spawn(async move { serve(socket, &served).await });
                    }
                }
            }),
        ];
        let set = EndpointSet::new(
            urls.iter()
                .enumerate()
                .map(|(index, url)| {
                    (
                        format!("endpoint-{index}"),
                        Arc::new(provider(url.clone())) as Arc<dyn CryptoProvider>,
                    )
                })
                .collect(),
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
                breaker: BreakerConfig::default(),
                global_max_inflight_batches: 2,
                global_max_inflight_bytes: 4096,
                per_endpoint_max_inflight: 2,
                per_endpoint_max_bytes: 4096,
                max_attempts: Some(1),
                max_operation_time: None,
                retry_safe,
                validation_interval: Duration::from_secs(1),
            },
            Arc::new(SystemClock::new()),
        )
        .with_plaintext_size(UNIT as u32);
        let context = CryptoContext {
            volume_uuid: uuid::Uuid::from_u128(2),
            format_version: 1,
            crypto_compatibility_id: "grpc-http2-v1".into(),
        };
        let item = PlaintextUnit {
            unit_index: 1,
            data: SecretBuffer::from_slice(&[9; UNIT]),
        };
        let result = set
            .encrypt_batch(&context, std::slice::from_ref(&item))
            .await;
        assert_eq!(refused.load(Ordering::SeqCst), 1, "retry_safe={retry_safe}");
        if retry_safe {
            assert_eq!(result.unwrap().len(), 1);
            assert_eq!(served.load(Ordering::SeqCst), 1);
            assert_eq!(set.metrics().failovers_total(), 1);
        } else {
            let error = result.expect_err("a refused call was sent to another endpoint");
            assert_eq!(error.class(), ErrorClass::Retryable, "{error:?}");
            assert_eq!(served.load(Ordering::SeqCst), 0);
            assert_eq!(set.metrics().retries_refused_unsafe_total(), 1);
        }
        for server in servers {
            server.abort();
        }
    }
}
