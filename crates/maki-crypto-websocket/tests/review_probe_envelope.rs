//! An `integrity` or `unsupported-context` error frame whose envelope is not
//! exact (no `reason`, a `reason` that is not a string, or a repeated `id`,
//! `error`, `class` or `reason` member) breaks the contract for the one
//! request it answers. The caller gets a contract violation, and the request
//! is not sent again, even by a retry-safe provider. The connection takes no
//! new request and closes once the requests already on it have finished, as
//! after a cancelled request; the next request opens another connection.
//! Requests in flight on the old connection are not failed. A well-formed
//! error frame with a reason its class does not define is a contract
//! violation too, but leaves the connection in use. Repeated members are
//! otherwise read last-value-wins: a frame's class is its last `class`
//! member.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use maki_crypto::selftest::provider_self_test;
use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError,
    CryptoProvider, ErrorClass,
};
use maki_crypto_websocket::{WsCryptoProvider, WsProviderSpec};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

const UNIT: usize = 64;
/// Requests for this unit are answered only once the server is released.
const HELD: u64 = 1000;

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0xe7e1),
        format_version: 1,
        crypto_compatibility_id: "review-envelope-v1".into(),
    }
}

/// An unauthenticated stand-in cipher (each byte XOR 0x5a), with the
/// ciphertexts it issued, so that a decrypt of any other ciphertext can be
/// told apart.
fn success(request: &Value, issued: &Mutex<HashSet<String>>) -> String {
    let encrypt = request["op"] == "encrypt";
    let items: Vec<_> = request["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            let data = base64::engine::general_purpose::STANDARD
                .decode(item["data"].as_str().unwrap())
                .unwrap();
            let data: Vec<_> = data.iter().map(|byte| byte ^ 0x5a).collect();
            let data = base64::engine::general_purpose::STANDARD.encode(data);
            if encrypt {
                issued.lock().unwrap().insert(data.clone());
            }
            json!({"unit": item["unit"], "data": data})
        })
        .collect();
    json!({"id": request["id"], "items": items}).to_string()
}

fn issued_by_us(request: &Value, issued: &Mutex<HashSet<String>>) -> bool {
    let issued = issued.lock().unwrap();
    request["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|item| issued.contains(item["data"].as_str().unwrap()))
}

#[derive(Default)]
struct Replies {
    /// The reply to the next request that is not held, with `{id}`
    /// standing for the request's id.
    next: Option<String>,
    /// The reply to every decrypt of a ciphertext this server did not
    /// issue.
    foreign: Option<String>,
}

struct Server {
    url: String,
    replies: Arc<Mutex<Replies>>,
    connections: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
    held: watch::Sender<usize>,
    closed: watch::Sender<usize>,
    release: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let replies = Arc::new(Mutex::new(Replies::default()));
        let connections = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let (held, _) = watch::channel(0);
        let (closed, _) = watch::channel(0);
        let (release, released) = watch::channel(false);
        let issued = Arc::new(Mutex::new(HashSet::new()));
        let task = {
            let (replies, connections, requests, held, closed) = (
                replies.clone(),
                connections.clone(),
                requests.clone(),
                held.clone(),
                closed.clone(),
            );
            tokio::spawn(async move {
                while let Ok((socket, _)) = listener.accept().await {
                    connections.fetch_add(1, Ordering::SeqCst);
                    let (replies, requests, held, closed, released, issued) = (
                        replies.clone(),
                        requests.clone(),
                        held.clone(),
                        closed.clone(),
                        released.clone(),
                        issued.clone(),
                    );
                    tokio::spawn(async move {
                        let ws = tokio_tungstenite::accept_async(socket).await.unwrap();
                        let (sink, mut source) = ws.split();
                        let sink = Arc::new(tokio::sync::Mutex::new(sink));
                        while let Some(Ok(message)) = source.next().await {
                            let Ok(text) = message.into_text() else {
                                continue;
                            };
                            let request: Value = serde_json::from_str(&text).unwrap();
                            requests.fetch_add(1, Ordering::SeqCst);
                            if request["items"][0]["unit"].as_u64() == Some(HELD) {
                                held.send_modify(|held| *held += 1);
                                let (sink, mut released, issued) =
                                    (sink.clone(), released.clone(), issued.clone());
                                tokio::spawn(async move {
                                    let _ = released.wait_for(|released| *released).await;
                                    let reply = success(&request, &issued);
                                    let _ = sink.lock().await.send(reply.into()).await;
                                });
                                continue;
                            }
                            let frame = {
                                let mut replies = replies.lock().unwrap();
                                let foreign =
                                    request["op"] == "decrypt" && !issued_by_us(&request, &issued);
                                match (replies.next.take(), &replies.foreign) {
                                    (Some(frame), _) => Some(frame),
                                    (None, Some(frame)) if foreign => Some(frame.clone()),
                                    _ => None,
                                }
                            };
                            let frame = match frame {
                                Some(frame) => frame.replace("{id}", &request["id"].to_string()),
                                None => success(&request, &issued),
                            };
                            if sink.lock().await.send(frame.into()).await.is_err() {
                                break;
                            }
                        }
                        closed.send_modify(|closed| *closed += 1);
                    });
                }
            })
        };
        Self {
            url,
            replies,
            connections,
            requests,
            held,
            closed,
            release,
            task,
        }
    }

    fn provider(&self) -> WsCryptoProvider {
        WsCryptoProvider::new(WsProviderSpec {
            url: self.url.clone(),
            capabilities: CryptoCapabilities {
                provider_id: "review-envelope".into(),
                crypto_compatibility_id: context().crypto_compatibility_id,
                supported_plaintext_sizes: vec![UNIT as u32],
                max_ciphertext_size: UNIT as u32,
                stateless: true,
                // A retry-safe provider reconnects once after a retryable
                // failure: a contract violation must not use that resend.
                retry_safe: true,
                batch: BatchCapability {
                    supported: true,
                    max_items: 1,
                    max_bytes: UNIT as u64,
                },
                integrity: Capability::Contractual,
                context_binding: Capability::Absent,
                replay_protection: Capability::Absent,
            },
            timeout: Duration::from_secs(5),
            max_frame_bytes: 4096,
            tls: None,
        })
    }

    /// The next reply that is not held is `frame`.
    fn answer_next_with(&self, frame: &str) {
        self.replies.lock().unwrap().next = Some(frame.to_string());
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

async fn until(what: &str, count: &watch::Sender<usize>, expected: usize) {
    let mut count = count.subscribe();
    tokio::time::timeout(
        Duration::from_secs(5),
        count.wait_for(|count| *count == expected),
    )
    .await
    .unwrap_or_else(|_| panic!("timed out waiting until {what}"))
    .unwrap();
}

async fn decrypt(provider: &WsCryptoProvider, unit: u64) -> Result<(), CryptoError> {
    let items = [CiphertextUnit {
        unit_index: unit,
        data: vec![0x17; UNIT],
    }];
    provider
        .decrypt_batch(&context(), &items)
        .await
        .map(|plain| assert_eq!(plain.len(), 1))
}

/// Each of these answers its request with an `integrity` or
/// `unsupported-context` class in an envelope that is not exact.
const INVALID_ENVELOPES: &[&str] = &[
    r#"{"id":{id},"error":{"class":"integrity"}}"#,
    r#"{"id":{id},"error":{"class":"integrity","reason":null}}"#,
    r#"{"id":{id},"error":{"class":"integrity","reason":7}}"#,
    r#"{"id":{id},"error":{"class":"unsupported-context"}}"#,
    r#"{"id":{id},"error":{"class":"integrity","reason":"auth-tag-mismatch","reason":"auth-tag-mismatch"}}"#,
    r#"{"id":{id},"error":{"class":"bad-request","class":"integrity","reason":"auth-tag-mismatch"}}"#,
    r#"{"id":{id},"error":{"class":"integrity","reason":"auth-tag-mismatch"},"error":{"class":"integrity","reason":"auth-tag-mismatch"}}"#,
    r#"{"id":0,"id":{id},"error":{"class":"unsupported-context","reason":"unsupported-format-version"}}"#,
];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invalid_probe_envelope_fails_its_request_and_retires_the_connection() {
    for (case, frame) in INVALID_ENVELOPES.iter().enumerate() {
        let server = Server::start().await;
        let provider = Arc::new(server.provider());
        decrypt(&provider, 1).await.unwrap();
        assert_eq!(server.connections(), 1);

        // A sibling request in flight on the same connection.
        let sibling = tokio::spawn({
            let provider = provider.clone();
            async move { decrypt(&provider, HELD).await }
        });
        until("the sibling reached the server", &server.held, 1).await;

        server.answer_next_with(frame);
        let before = server.requests();
        let error = decrypt(&provider, 2).await.unwrap_err();
        assert!(
            matches!(
                &error,
                CryptoError::Contract(message)
                    if message == "remote crypto provider returned an invalid probe error envelope"
            ),
            "case {case} {frame}: {error:?}"
        );
        assert_eq!(
            server.requests() - before,
            1,
            "case {case}: a contract violation was sent again"
        );

        // The next request opens another connection; the old one only
        // finishes the sibling.
        decrypt(&provider, 3).await.unwrap();
        assert_eq!(server.connections(), 2, "case {case}");
        assert_eq!(*server.closed.borrow(), 0, "case {case}");
        server.release.send(true).unwrap();
        sibling.await.unwrap().unwrap();
        until("the drained connection closed", &server.closed, 1).await;
        decrypt(&provider, 4).await.unwrap();
        assert_eq!(server.connections(), 2, "case {case}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_well_formed_error_with_an_unknown_reason_keeps_the_connection() {
    for (frame, expected) in [
        (
            r#"{"id":{id},"error":{"class":"integrity","reason":"unknown"}}"#,
            "remote crypto provider returned an unrecognized integrity reason",
        ),
        (
            r#"{"id":{id},"error":{"class":"unsupported-context","reason":"auth-tag-mismatch"}}"#,
            "remote crypto provider returned an unrecognized context refusal",
        ),
    ] {
        let server = Server::start().await;
        let provider = server.provider();
        server.answer_next_with(frame);
        let error = decrypt(&provider, 1).await.unwrap_err();
        assert!(
            matches!(&error, CryptoError::Contract(message) if message == expected),
            "{frame}: {error:?}"
        );
        assert_eq!(server.requests(), 1, "{frame}: sent again");
        decrypt(&provider, 2).await.unwrap();
        assert_eq!(server.connections(), 1, "{frame}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repeated_class_is_read_from_its_last_member() {
    for (frame, class) in [
        (
            r#"{"id":{id},"error":{"class":"integrity","class":"bad-request"}}"#,
            ErrorClass::NonRetryableRequest,
        ),
        (
            r#"{"id":{id},"error":{"class":"integrity","reason":"auth-tag-mismatch"},"error":{"class":"throttled"}}"#,
            ErrorClass::Throttled,
        ),
    ] {
        let server = Server::start().await;
        let provider = server.provider();
        server.answer_next_with(frame);
        let error = decrypt(&provider, 1).await.unwrap_err();
        assert_eq!(error.class(), class, "{frame}: {error:?}");
        assert!(!matches!(error, CryptoError::Integrity(_)), "{frame}");
        assert_eq!(server.requests(), 1, "{frame}: sent again");
        decrypt(&provider, 2).await.unwrap();
        assert_eq!(server.connections(), 1, "{frame}");
    }
}

/// A negative self-test probe answered with such a frame fails the
/// self-test with that contract violation, without a verdict on the
/// capability: attach refuses the endpoint, and background validation of a
/// quarantined one tries again later. It never passes as an integrity
/// failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tamper_probe_answered_with_an_invalid_envelope_fails_the_self_test_without_a_verdict() {
    let context = context();
    let server = Server::start().await;
    let provider = server.provider();
    provider_self_test(&provider, &context, UNIT, &context.crypto_compatibility_id)
        .await
        .expect_err("an unauthenticated cipher passed the tamper probe");
    server.replies.lock().unwrap().foreign =
        Some(r#"{"id":{id},"error":{"class":"integrity","reason":"auth-tag-mismatch"}}"#.into());
    provider_self_test(&provider, &context, UNIT, &context.crypto_compatibility_id)
        .await
        .expect("an exact integrity failure satisfies the tamper probe");
    for frame in INVALID_ENVELOPES {
        server.replies.lock().unwrap().foreign = Some(frame.to_string());
        let error = provider_self_test(&provider, &context, UNIT, &context.crypto_compatibility_id)
            .await
            .unwrap_err();
        assert!(
            matches!(
                &error,
                CryptoError::Contract(message)
                    if message == "remote crypto provider returned an invalid probe error envelope"
            ),
            "{frame}: {error:?}"
        );
    }
}
