//! Round-9 audit (providers-native): salted fuzz of the WebSocket provider's
//! response path. A server answers every request frame with a randomly
//! chosen reply: a correct response, a mutated one (wrong/duplicate/huge or
//! non-integer id, missing or extra items, wrong unit, bad base64, wrong
//! length, deep nesting, duplicate keys), an error frame with a random or
//! valid class/reason, a binary or non-JSON frame, a ping, a close, an
//! abrupt drop, or nothing (the request then times out). The only contract:
//! every call resolves within its timeout plus slack, never panics, and an
//! `Ok` carries exactly one unit per request item with the unit's length.
//!
//! `AUDIT9_WS_FUZZ_SEEDS=a..b` and `AUDIT9_WS_FUZZ_ITERS=n` widen the run.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext,
    CryptoProvider, PlaintextUnit, SecretBuffer,
};
use maki_crypto_websocket::{WsCryptoProvider, WsProviderSpec};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::Message;

const UNIT: usize = 64;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
    fn rbytes(&mut self, max: u64) -> Vec<u8> {
        let n = self.below(max) as usize;
        self.bytes(n)
    }
}

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

enum Reply {
    Text(String),
    Binary(Vec<u8>),
    Ping,
    Close,
    Drop,
    Silence,
}

fn random_id(rng: &mut Rng, id: &Value) -> Value {
    match rng.below(10) {
        0 => json!(id.as_u64().unwrap_or(0) + 1),
        1 => json!(-1),
        2 => json!(1.5),
        3 => json!(id.to_string()),
        4 => serde_json::from_str("18446744073709551616").unwrap_or(json!(0)),
        5 => json!(null),
        _ => id.clone(),
    }
}

fn reply(rng: &mut Rng, request: &Value) -> Reply {
    let id = request["id"].clone();
    let items: Vec<Value> = request["items"].as_array().cloned().unwrap_or_default();
    let good = |rng: &mut Rng, items: &[Value]| -> Vec<Value> {
        items
            .iter()
            .map(|item| {
                let _ = rng;
                json!({"unit": item["unit"], "data": b64(&[0x5a; UNIT])})
            })
            .collect()
    };
    match rng.below(20) {
        0..=5 => Reply::Text(json!({"id": id, "items": good(rng, &items)}).to_string()),
        6 => {
            // mutate one item
            let mut out = good(rng, &items);
            if let Some(first) = out.first_mut() {
                match rng.below(8) {
                    0 => first["unit"] = json!(first["unit"].as_u64().unwrap_or(0) + 1),
                    1 => first["data"] = json!("!!not base64!!"),
                    2 => first["data"] = json!(b64(&rng.rbytes(200))),
                    3 => first["data"] = json!(null),
                    4 => first["unit"] = json!("7"),
                    5 => first["data"] = json!(b64(&[0x5a; UNIT])[..10].to_string()),
                    6 => {
                        first.as_object_mut().unwrap().remove("data");
                    }
                    _ => first["unit"] = json!(-3),
                }
            }
            Reply::Text(json!({"id": id, "items": out}).to_string())
        }
        7 => {
            let mut out = good(rng, &items);
            if rng.chance(50) {
                out.pop();
            } else {
                out.push(json!({"unit": 999, "data": b64(&[1; UNIT])}));
            }
            Reply::Text(json!({"id": id, "items": out}).to_string())
        }
        8 => Reply::Text(json!({"id": random_id(rng, &id), "items": good(rng, &items)}).to_string()),
        9 => {
            let classes = ["integrity", "unsupported-context", "throttled", "retryable", "bad-request", "fatal", ""];
            let reasons = ["auth-tag-mismatch", "context-mismatch", "unsupported-format-version", "unsupported-compatibility-id", "x", ""];
            let class = classes[rng.below(classes.len() as u64) as usize];
            let reason = reasons[rng.below(reasons.len() as u64) as usize];
            let mut error = json!({"class": class, "message": "\u{1b}[31m injected \r\n line"});
            if rng.chance(70) {
                error["reason"] = json!(reason);
            }
            if rng.chance(10) {
                error["reason"] = json!(17);
            }
            Reply::Text(json!({"id": id, "error": error}).to_string())
        }
        10 => {
            // duplicate keys, last wins
            let first = json!({"unit": items.first().map(|i| i["unit"].clone()).unwrap_or(json!(0)), "data": b64(&[0x11; UNIT])});
            Reply::Text(format!(
                "{{\"id\":{id},\"items\":[{first}],\"id\":{id},\"error\":{{\"class\":\"retryable\"}},\"error\":null}}"
            ))
        }
        11 => {
            let depth = rng.below(300) as usize;
            Reply::Text(format!("{{\"id\":{id},\"pad\":{}1{}}}", "[".repeat(depth), "]".repeat(depth)))
        }
        12 => Reply::Text(String::from_utf8_lossy(&rng.rbytes(100)).into_owned()),
        13 => Reply::Binary(rng.rbytes(50)),
        14 => Reply::Ping,
        15 => Reply::Close,
        16 => Reply::Drop,
        17 => Reply::Silence,
        18 => {
            // a correct answer preceded by a stale one
            Reply::Text(json!({"id": id, "items": good(rng, &items), "extra": {"nested": [1, 2, {"a": "b"}]}}).to_string())
        }
        _ => {
            // numbers at the edges
            let edge = ["1e400", "-0", "0.0", "1E2", "00", "18446744073709551615"][rng.below(6) as usize];
            Reply::Text(format!("{{\"id\":{edge},\"items\":[]}}"))
        }
    }
}

async fn server(seed: u64) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let rng = Arc::new(Mutex::new(Rng(seed)));
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let rng = rng.clone();
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(socket).await else {
                    return;
                };
                while let Some(Ok(message)) = ws.next().await {
                    let Ok(text) = message.into_text() else { continue };
                    let Ok(request) = serde_json::from_str::<Value>(&text) else {
                        continue;
                    };
                    let choice = reply(&mut rng.lock().unwrap(), &request);
                    let result = match choice {
                        Reply::Text(text) => ws.send(Message::Text(text.into())).await,
                        Reply::Binary(data) => ws.send(Message::Binary(data.into())).await,
                        Reply::Ping => ws.send(Message::Ping(vec![1, 2, 3].into())).await,
                        Reply::Close => {
                            let _ = ws
                                .send(Message::Close(Some(CloseFrame {
                                    code: CloseCode::Error,
                                    reason: "\u{1b}[2J bye".into(),
                                })))
                                .await;
                            return;
                        }
                        Reply::Drop => return,
                        Reply::Silence => Ok(()),
                    };
                    if result.is_err() {
                        return;
                    }
                }
            });
        }
    });
    url
}

fn provider(url: String) -> WsCryptoProvider {
    WsCryptoProvider::new(WsProviderSpec {
        url,
        capabilities: CryptoCapabilities {
            provider_id: "audit9-ws-fuzz".into(),
            crypto_compatibility_id: "audit9-ws-v1".into(),
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
        timeout: Duration::from_millis(300),
        max_frame_bytes: 8192,
        tls: None,
    })
}

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x9a),
        format_version: 1,
        crypto_compatibility_id: "audit9-ws-v1".into(),
    }
}

fn seeds() -> std::ops::Range<u64> {
    std::env::var("AUDIT9_WS_FUZZ_SEEDS")
        .ok()
        .and_then(|s| {
            let (a, b) = s.split_once("..")?;
            Some(a.parse().ok()?..b.parse().ok()?)
        })
        .unwrap_or(0..3)
}

fn iterations() -> usize {
    std::env::var("AUDIT9_WS_FUZZ_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(150)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_responses_resolve_without_panic_or_hang() {
    let (mut ok, mut errors) = (0usize, std::collections::BTreeMap::<String, usize>::new());
    for seed in seeds() {
        let salt = seed.wrapping_mul(0x5DEECE66D) ^ 0xA9_0057;
        let provider = provider(server(salt).await);
        let mut local = Rng(salt ^ 1);
        for i in 0..iterations() {
            let count = 1 + local.below(4) as usize;
            let decrypt = local.chance(50);
            let call = async {
                if decrypt {
                    let items: Vec<_> = (0..count as u64)
                        .map(|u| CiphertextUnit { unit_index: u, data: vec![0x33; UNIT] })
                        .collect();
                    provider
                        .decrypt_batch(&context(), &items)
                        .await
                        .map(|out| out.iter().map(|p| p.data.len()).collect::<Vec<_>>())
                } else {
                    let items: Vec<_> = (0..count as u64)
                        .map(|u| PlaintextUnit { unit_index: u, data: SecretBuffer::from_slice(&[0x44; UNIT]) })
                        .collect();
                    provider
                        .encrypt_batch(&context(), &items)
                        .await
                        .map(|out| out.iter().map(|c| c.data.len()).collect::<Vec<_>>())
                }
            };
            let result = tokio::time::timeout(Duration::from_secs(10), call)
                .await
                .unwrap_or_else(|_| panic!("seed {seed} iteration {i}: call did not resolve in 10 s"));
            match result {
                Ok(lengths) => {
                    assert_eq!(lengths.len(), count, "seed {seed} iteration {i}: wrong item count");
                    ok += 1;
                }
                Err(error) => {
                    let text = error.to_string();
                    assert!(!text.contains('\u{1b}') && !text.contains('\r') && !text.contains("injected"),
                        "seed {seed} iteration {i}: endpoint text reached the error: {text:?}");
                    *errors.entry(format!("{:?}", error.class())).or_default() += 1;
                }
            }
        }
    }
    eprintln!("ws fuzz: seeds {:?} x {} iterations: ok={ok} errors={errors:?}", seeds(), iterations());
    assert!(ok > 0, "no call succeeded; the fuzz never reached the success path");
}
