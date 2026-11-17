//! Round-3 audit probe for PR #174 (NotSent failover): hyper-util retries a
//! request on a fresh connection only when a *reused* pooled connection gave
//! it back unwritten; a connect failure on that retry is `is_connect` and so
//! marked not sent. The invariant under test: whenever a request that is not
//! retry-safe fails over to a peer, the first endpoint never received it.
//!
//! The flaky peer keeps its first connection alive (no `Connection: close`)
//! and stops listening after that first accept, so every hyper retry on a
//! new connection is refused (a connect error). What it does with the second
//! request on the kept-alive connection varies by mode and timing.

use std::sync::Arc;
use std::time::Duration;

use maki_crypto::breaker::BreakerConfig;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoProvider,
    PlaintextUnit, SecretBuffer, SystemClock,
};
use maki_crypto_http::{
    BodySpec, HttpCryptoProvider, HttpProviderSpec, OpSpec, PayloadEncoding, RespKind, RespSpec,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const UNIT: usize = 64;
const XOR: u8 = 0x3c;

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0xA3_0174),
        format_version: 1,
        crypto_compatibility_id: "http-unsent-v1".into(),
    }
}

fn unit(index: u64, fill: u8) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: index,
        data: SecretBuffer::from_slice(&[fill; UNIT]),
    }
}

/// Read one request (head + Content-Length body). `None` on EOF/error.
async fn read_request(socket: &mut TcpStream, carry: &mut Vec<u8>) -> Option<Vec<u8>> {
    let mut buffer = [0u8; 1024];
    loop {
        if let Some(end) = carry.windows(4).position(|part| part == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&carry[..end]).unwrap().to_string();
            let body_length = headers
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value.trim().parse::<usize>().unwrap())
                .unwrap_or(0);
            if carry.len() >= end + 4 + body_length {
                let body = carry[end + 4..end + 4 + body_length].to_vec();
                carry.drain(..end + 4 + body_length);
                return Some(body);
            }
        }
        let length = socket.read(&mut buffer).await.ok()?;
        if length == 0 {
            return None;
        }
        carry.extend_from_slice(&buffer[..length]);
    }
}

async fn respond(socket: &mut TcpStream, body: &[u8], close: bool) {
    let body: Vec<u8> = body.iter().map(|byte| byte ^ XOR).collect();
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
         Content-Length: {}\r\n{}\r\n",
        body.len(),
        if close { "Connection: close\r\n" } else { "" }
    );
    let _ = socket.write_all(head.as_bytes()).await;
    let _ = socket.write_all(&body).await;
}

#[derive(Clone, Copy, Debug)]
enum Flaky {
    /// Answer the first request keep-alive, then read the second request on
    /// the same connection and close without answering.
    LoseSecond,
    /// Answer the first request keep-alive, then close the connection after
    /// `delay` (racing the client's second request).
    CloseAfter(Duration),
}

/// Requests whose bytes the flaky peer received, by first payload byte.
struct Peer {
    url: String,
    seen: Arc<parking_lot::Mutex<Vec<u8>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn flaky(mode: Flaky) -> Peer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let log = seen.clone();
    let task = tokio::spawn(async move {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        // Every later connection is refused.
        drop(listener);
        let mut carry = Vec::new();
        let Some(first) = read_request(&mut socket, &mut carry).await else {
            return;
        };
        log.lock().push(first[0]);
        respond(&mut socket, &first, false).await;
        match mode {
            Flaky::LoseSecond => {
                if let Some(second) = read_request(&mut socket, &mut carry).await {
                    log.lock().push(second[0]);
                }
                drop(socket);
            }
            Flaky::CloseAfter(delay) => {
                // Record anything that arrives before the close.
                let read = tokio::time::timeout(delay, read_request(&mut socket, &mut carry)).await;
                if let Ok(Some(second)) = read {
                    log.lock().push(second[0]);
                }
                drop(socket);
            }
        }
    });
    Peer { url, seen, task }
}

async fn good() -> Peer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let log = seen.clone();
    let task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let log = log.clone();
            tokio::spawn(async move {
                let mut carry = Vec::new();
                while let Some(body) = read_request(&mut socket, &mut carry).await {
                    log.lock().push(body[0]);
                    respond(&mut socket, &body, true).await;
                    break;
                }
            });
        }
    });
    Peer { url, seen, task }
}

fn provider(url: &str) -> Arc<dyn CryptoProvider> {
    let operation = OpSpec {
        method: "POST".into(),
        path: "/encrypt".into(),
        headers: vec![],
        query: vec![],
        body: BodySpec::Raw,
        response: RespSpec {
            kind: RespKind::Raw,
            data_path: None,
            encoding: PayloadEncoding::Base64,
            items_path: None,
            item_index_path: None,
        },
    };
    Arc::new(
        HttpCryptoProvider::new(HttpProviderSpec {
            base_url: url.to_string(),
            encrypt: operation.clone(),
            decrypt: operation,
            capabilities: CryptoCapabilities {
                provider_id: "http-unsent".into(),
                crypto_compatibility_id: context().crypto_compatibility_id,
                supported_plaintext_sizes: vec![UNIT as u32],
                max_ciphertext_size: UNIT as u32,
                stateless: true,
                retry_safe: false,
                batch: BatchCapability {
                    supported: true,
                    max_items: 1,
                    max_bytes: UNIT as u64,
                },
                integrity: Capability::Absent,
                context_binding: Capability::Absent,
                replay_protection: Capability::Absent,
            },
            timeout: Duration::from_secs(5),
            max_response_bytes: 4096,
            tls: None,
        })
        .unwrap(),
    )
}

fn not_retry_safe(peers: Vec<(&str, Arc<dyn CryptoProvider>)>) -> EndpointSet {
    EndpointSet::new(
        peers
            .into_iter()
            .map(|(name, peer)| (name.into(), peer))
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
            breaker: BreakerConfig {
                failure_threshold: 100,
                ..BreakerConfig::default()
            },
            global_max_inflight_batches: 2,
            global_max_inflight_bytes: 4096,
            per_endpoint_max_inflight: 2,
            per_endpoint_max_bytes: 4096,
            max_attempts: Some(1),
            max_operation_time: None,
            retry_safe: false,
            validation_interval: Duration::from_secs(1),
        },
        Arc::new(SystemClock::new()),
    )
    .with_plaintext_size(UNIT as u32)
}

/// Run the two-request scenario once; return (flaky saw, good saw, second ok).
async fn scenario(mode: Flaky, pause: Duration) -> (Vec<u8>, Vec<u8>, bool) {
    let flaky = flaky(mode).await;
    let good = good().await;
    // Route the first request to `flaky`: it is the only endpoint in a set
    // whose second member is `good`, but `good` is listed second, and both
    // idle, so the dispatcher picks the first by inflight order. Make that
    // deterministic by sending the first request through the flaky provider
    // directly, sharing the same client (and connection pool).
    let flaky_provider = provider(&flaky.url);
    let first = flaky_provider
        .encrypt_batch(&context(), &[unit(0, 0xA1)])
        .await;
    assert!(first.is_ok(), "first request failed: {first:?}");
    tokio::time::sleep(pause).await;
    let set = not_retry_safe(vec![
        ("flaky", flaky_provider.clone()),
        ("good", provider(&good.url)),
    ]);
    let second = set.encrypt_batch(&context(), &[unit(1, 0xB2)]).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let flaky_seen = flaky.seen.lock().clone();
    let good_seen = good.seen.lock().clone();
    (flaky_seen, good_seen, second.is_ok())
}

/// The second request reached `flaky` and was lost there; it must never be
/// sent to `good` as well.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_lost_on_a_reused_connection_is_not_failed_over() {
    let (flaky_seen, good_seen, ok) = scenario(Flaky::LoseSecond, Duration::ZERO).await;
    assert_eq!(flaky_seen, vec![0xA1, 0xB2], "flaky did not receive both");
    assert!(
        !good_seen.contains(&0xB2),
        "request delivered to flaky was also sent to good (duplicate): flaky {flaky_seen:x?} good {good_seen:x?}"
    );
    assert!(!ok);
}

/// Race the server's close of the kept-alive connection against the second
/// request. Whatever hyper does (reuse, retry on a fresh connection that is
/// refused, or a fresh connection from the start), a request that failed
/// over must not have reached `flaky`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closing_pooled_connection_never_duplicates_a_request() {
    let mut outcomes = std::collections::BTreeMap::new();
    let mut duplicates = Vec::new();
    for round in 0..60u64 {
        let close_after = Duration::from_micros((round % 6) * 400);
        let pause = Duration::from_micros((round / 6) * 300);
        let (flaky_seen, good_seen, ok) =
            scenario(Flaky::CloseAfter(close_after), pause).await;
        let at_flaky = flaky_seen.contains(&0xB2);
        let at_good = good_seen.contains(&0xB2);
        *outcomes.entry((at_flaky, at_good, ok)).or_insert(0u32) += 1;
        if at_flaky && at_good {
            duplicates.push((round, flaky_seen, good_seen));
        }
    }
    eprintln!("outcomes (at_flaky, at_good, ok) -> count: {outcomes:?}");
    assert!(duplicates.is_empty(), "duplicated requests: {duplicates:x?}");
}
