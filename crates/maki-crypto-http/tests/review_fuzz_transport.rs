//! Fuzz the HTTP provider's response path. A remote provider is untrusted
//! (SPEC §16): whatever bytes, status, content type, or truncation it
//! returns, the client must resolve to `Ok` or a classified `Err` and never
//! panic, hang, or abort. This drives random responses through both the
//! per-item and the batched parse paths (`parse_single` / `extract_batch`
//! and the payload codec) over many seeded iterations.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{Handler, RecordedRequest, ResponseSpec, TestServer};
use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    PlaintextUnit, SecretBuffer,
};
use maki_crypto_http::{
    BodySpec, FieldSource, HttpCryptoProvider, HttpProviderSpec, OpSpec, PayloadEncoding, RespKind,
    RespSpec,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const UNIT: usize = 64;

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0xF0),
        format_version: 1,
        crypto_compatibility_id: "vendor-profile-v1".to_string(),
    }
}

fn caps() -> CryptoCapabilities {
    CryptoCapabilities {
        provider_id: "remote-http-fuzz".to_string(),
        crypto_compatibility_id: "vendor-profile-v1".to_string(),
        supported_plaintext_sizes: vec![UNIT as u32],
        max_ciphertext_size: UNIT as u32,
        stateless: true,
        retry_safe: true,
        batch: BatchCapability {
            supported: true,
            max_items: 64,
            max_bytes: 1 << 20,
        },
        integrity: Capability::Absent,
        context_binding: Capability::Absent,
        replay_protection: Capability::Absent,
    }
}

fn per_item_op() -> OpSpec {
    OpSpec {
        method: "POST".to_string(),
        path: "/op".to_string(),
        headers: vec![],
        query: vec![],
        body: BodySpec::Json {
            fields: vec![(
                "/data".to_string(),
                FieldSource::Payload(PayloadEncoding::Base64),
            )],
            items_path: None,
            item_fields: vec![],
        },
        response: RespSpec {
            kind: RespKind::Json,
            data_path: Some("/ciphertext".to_string()),
            encoding: PayloadEncoding::Base64,
            items_path: None,
            item_index_path: None,
        },
    }
}

fn batched_op() -> OpSpec {
    OpSpec {
        method: "POST".to_string(),
        path: "/op".to_string(),
        headers: vec![],
        query: vec![],
        body: BodySpec::Json {
            fields: vec![],
            items_path: Some("/items".to_string()),
            item_fields: vec![(
                "/data".to_string(),
                FieldSource::Payload(PayloadEncoding::HexLower),
            )],
        },
        response: RespSpec {
            kind: RespKind::Json,
            data_path: Some("/ct".to_string()),
            encoding: PayloadEncoding::HexLower,
            items_path: Some("/results".to_string()),
            item_index_path: Some("/idx".to_string()),
        },
    }
}

fn provider(url: &str, op: OpSpec) -> HttpCryptoProvider {
    HttpCryptoProvider::new(HttpProviderSpec {
        base_url: url.to_string(),
        encrypt: op.clone(),
        decrypt: op,
        capabilities: caps(),
        timeout: Duration::from_secs(2),
        max_response_bytes: 1 << 16,
        tls: None,
    })
    .unwrap()
}

fn pt(i: u64) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: i,
        data: SecretBuffer::from_slice(&[0x5A; UNIT]),
    }
}

/// A random, possibly-malformed response.
fn random_response(rng: &mut StdRng) -> ResponseSpec {
    let status = *[200u16, 200, 200, 201, 400, 429, 500, 503]
        .get(rng.random_range(0..8))
        .unwrap();
    let mut spec = match rng.random_range(0..6) {
        // Random raw bytes.
        0 => {
            let len = rng.random_range(0..300);
            let body: Vec<u8> = (0..len).map(|_| rng.random()).collect();
            ResponseSpec::raw(body)
        }
        // A structurally valid-ish JSON object with random field shapes.
        1 | 2 => {
            let mk = |rng: &mut StdRng| -> serde_json::Value {
                match rng.random_range(0..5) {
                    0 => serde_json::json!("QUFBQQ=="), // valid base64 "AAAA"
                    1 => serde_json::json!("zzzz not base64 !!"),
                    2 => serde_json::json!(rng.random::<u32>()),
                    3 => serde_json::json!(null),
                    _ => serde_json::json!([1, 2, 3]),
                }
            };
            let n = rng.random_range(0..4);
            let results: Vec<serde_json::Value> = (0..n)
                .map(|i| serde_json::json!({ "ct": mk(rng), "idx": i }))
                .collect();
            ResponseSpec::json(&serde_json::json!({
                "ciphertext": mk(rng),
                "results": results,
                "items": mk(rng),
            }))
        }
        // Truncated JSON.
        3 => {
            let full = br#"{"ciphertext":"QUFBQQ==","results":[{"ct":"6161","idx":0}]}"#;
            let cut = rng.random_range(0..=full.len());
            ResponseSpec::raw(full[..cut].to_vec())
        }
        // Deeply nested / oversized-ish JSON.
        4 => {
            let depth = rng.random_range(0..40);
            let mut s = String::new();
            for _ in 0..depth {
                s.push_str("{\"a\":");
            }
            s.push('1');
            for _ in 0..depth {
                s.push('}');
            }
            ResponseSpec::raw(s.into_bytes())
        }
        // Empty.
        _ => ResponseSpec::raw(Vec::new()),
    };
    spec.status = status;
    if rng.random_bool(0.3) {
        spec.content_type = "text/plain".to_string();
    }
    if rng.random_bool(0.2) && !spec.body.is_empty() {
        spec.drop_after = Some(rng.random_range(0..spec.body.len()));
    }
    spec
}

async fn fuzz_provider(op: OpSpec, iterations: usize, seed: u64) {
    let rng = Arc::new(Mutex::new(StdRng::seed_from_u64(seed)));
    let handler_rng = rng.clone();
    let handler: Handler = Arc::new(move |_req: &RecordedRequest| {
        random_response(&mut handler_rng.lock().unwrap())
    });
    let server = TestServer::start(handler).await;
    let provider = provider(&server.url(), op);

    for i in 0..iterations {
        let count = 1 + (i % 3);
        let items: Vec<PlaintextUnit> = (0..count as u64).map(pt).collect();
        // The only contract: resolve, never panic/hang/abort. A returned
        // ciphertext set, when Ok, must have one entry per requested item.
        match provider.encrypt_batch(&ctx(), &items).await {
            Ok(out) => assert_eq!(out.len(), items.len(), "Ok response with wrong item count"),
            Err(e) => {
                // Every error is one of the classified variants (compiles by
                // exhaustiveness); nothing to assert beyond that it is Err.
                let _: &CryptoError = &e;
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_item_response_parsing_never_panics_on_random_responses() {
    fuzz_provider(per_item_op(), 400, 0x00F0_22A1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn batched_response_parsing_never_panics_on_random_responses() {
    fuzz_provider(batched_op(), 400, 0x00F0_22B2).await;
}
