//! `max_response_bytes` must bound what a JSON response costs in memory, not
//! only its wire bytes. Materialising every node of a body within the default
//! 8 MiB cap made one response hold over 40 times its size in heap
//! (`{"data":"AAAA","pad":[[],[],...]}`); with default concurrency that is
//! enough for an out-of-memory kill.
//!
//! A counting global allocator measures the peak live heap while one
//! response is received and parsed. The guarded body itself, its growth
//! while chunks arrive and hyper's read buffer account for up to about twice
//! the body; the parse may add at most a small constant on top.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoProvider, PlaintextUnit,
    SecretBuffer,
};
use maki_crypto_http::{
    BodySpec, FieldSource, HttpCryptoProvider, HttpProviderSpec, OpSpec, PayloadEncoding, RespKind,
    RespSpec,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Counting;
static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);

// SAFETY: every operation delegates to System; the counters do not allocate.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            let size = layout.size() as isize;
            let now = LIVE.fetch_add(size, Ordering::SeqCst) + size;
            PEAK.fetch_max(now, Ordering::SeqCst);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::SeqCst);
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

const LIMIT: usize = maki_format::config::DEFAULT_HTTP_MAX_RESPONSE_BYTES as usize;
const UNIT: usize = 4096;
/// The body is held once, may briefly coexist with the buffer it grew out
/// of, and the parse keeps only what a configured pointer reads.
const MAX_PEAK_PER_BODY_BYTE: usize = 3;

#[derive(Clone, Copy)]
enum Mapping {
    /// One request per unit; `data_path` addresses the payload.
    Single(&'static str),
    /// One request per batch; elements at `/results` carry `/idx` and `/data`.
    Batch,
}

fn provider(url: &str, mapping: Mapping) -> HttpCryptoProvider {
    let (body, response) = match mapping {
        Mapping::Single(data_path) => (
            BodySpec::Json {
                fields: vec![(
                    "/data".into(),
                    FieldSource::Payload(PayloadEncoding::Base64),
                )],
                items_path: None,
                item_fields: vec![],
            },
            RespSpec {
                kind: RespKind::Json,
                data_path: Some(data_path.into()),
                encoding: PayloadEncoding::Base64,
                items_path: None,
                item_index_path: None,
            },
        ),
        Mapping::Batch => (
            BodySpec::Json {
                fields: vec![],
                items_path: Some("/items".into()),
                item_fields: vec![
                    (
                        "/data".into(),
                        FieldSource::Payload(PayloadEncoding::Base64),
                    ),
                    ("/idx".into(), FieldSource::UnitIndex),
                ],
            },
            RespSpec {
                kind: RespKind::Json,
                data_path: Some("/data".into()),
                encoding: PayloadEncoding::Base64,
                items_path: Some("/results".into()),
                item_index_path: Some("/idx".into()),
            },
        ),
    };
    let operation = OpSpec {
        method: "POST".into(),
        path: "/encrypt".into(),
        headers: vec![],
        query: vec![],
        body,
        response,
    };
    HttpCryptoProvider::new(HttpProviderSpec {
        base_url: url.into(),
        encrypt: operation.clone(),
        decrypt: operation,
        capabilities: CryptoCapabilities {
            provider_id: "response-memory".into(),
            crypto_compatibility_id: "response-memory-v1".into(),
            supported_plaintext_sizes: vec![UNIT as u32],
            max_ciphertext_size: UNIT as u32 + 28,
            stateless: true,
            retry_safe: true,
            batch: BatchCapability {
                supported: true,
                max_items: 1,
                max_bytes: UNIT as u64,
            },
            integrity: Capability::Absent,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        },
        timeout: Duration::from_secs(60),
        max_response_bytes: LIMIT,
        tls: None,
    })
    .unwrap()
}

/// Answer every request on a keep-alive connection with the same response.
async fn serve(response: Arc<Vec<u8>>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let response = response.clone();
            tokio::spawn(async move {
                let mut buffer = [0u8; 16384];
                loop {
                    let mut seen = Vec::new();
                    loop {
                        let length = match socket.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(length) => length,
                        };
                        seen.extend_from_slice(&buffer[..length]);
                        if let Some(end) = seen.windows(4).position(|part| part == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&seen[..end]).to_lowercase();
                            let body = head
                                .lines()
                                .find_map(|line| line.strip_prefix("content-length:"))
                                .map(|value| value.trim().parse::<usize>().unwrap())
                                .unwrap_or(0);
                            if seen.len() >= end + 4 + body {
                                break;
                            }
                        }
                    }
                    drop(seen);
                    if socket.write_all(&response).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (url, task)
}

/// `prefix` + repeated `filler` + `suffix`, as close to the cap as fits.
fn body(prefix: &str, filler: &str, separator: &str, suffix: &str) -> Vec<u8> {
    let mut body = prefix.as_bytes().to_vec();
    body.extend_from_slice(filler.as_bytes());
    while body.len() + separator.len() + filler.len() + suffix.len() <= LIMIT {
        body.extend_from_slice(separator.as_bytes());
        body.extend_from_slice(filler.as_bytes());
    }
    body.extend_from_slice(suffix.as_bytes());
    assert!(body.len() <= LIMIT && body.len() > LIMIT - 64);
    body
}

/// Peak live heap above the starting point while one response is handled.
async fn peak_for(mapping: Mapping, body: Vec<u8>) -> (usize, usize) {
    let length = body.len();
    let mut response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {length}\r\n\r\n"
    )
    .into_bytes();
    response.extend_from_slice(&body);
    drop(body);
    let (url, server) = serve(Arc::new(response)).await;
    let provider = provider(&url, mapping);
    let context = CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(1),
        format_version: 1,
        crypto_compatibility_id: "response-memory-v1".into(),
    };
    let units = vec![PlaintextUnit {
        unit_index: 0,
        data: SecretBuffer::from_slice(&[1u8; UNIT]),
    }];
    // Warm the connection pool and lazily initialised statics.
    let _ = provider.encrypt_batch(&context, &units).await;
    let base = LIVE.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    let result = provider.encrypt_batch(&context, &units).await;
    let peak = PEAK.load(Ordering::SeqCst) - base;
    drop(result);
    drop(provider);
    server.abort();
    (length, usize::try_from(peak).unwrap_or(0))
}

/// One test, so no other test's allocations share the counters.
#[tokio::test(flavor = "current_thread")]
async fn json_response_memory_is_bounded_by_its_body_size() {
    let cases: [(&str, Mapping, Vec<u8>); 8] = [
        (
            "empty strings beside the payload",
            Mapping::Single("/data"),
            body(r#"{"data":"AAAA","pad":["#, r#""""#, ",", "]}"),
        ),
        (
            "empty arrays beside the payload",
            Mapping::Single("/data"),
            body(r#"{"data":"AAAA","pad":["#, "[]", ",", "]}"),
        ),
        (
            "empty objects beside the payload",
            Mapping::Single("/data"),
            body(r#"{"data":"AAAA","pad":["#, "{}", ",", "]}"),
        ),
        (
            "small numbers beside the payload",
            Mapping::Single("/data"),
            body(r#"{"data":"AAAA","pad":["#, "0", ",", "]}"),
        ),
        (
            "a container where the payload string belongs",
            Mapping::Single("/data"),
            body(r#"{"data":["#, "[]", ",", "]}"),
        ),
        (
            "siblings of an element selected by index",
            Mapping::Single("/r/0"),
            body(r#"{"r":["AAAA","#, "[]", ",", "]}"),
        ),
        (
            "padding beside a batch",
            Mapping::Batch,
            body(
                r#"{"results":[{"idx":0,"data":"AAAA"}],"pad":["#,
                "[]",
                ",",
                "]}",
            ),
        ),
        (
            "more batch elements than requested",
            Mapping::Batch,
            body(r#"{"results":[{"idx":0,"data":"AAAA"},"#, "{}", ",", "]}"),
        ),
    ];
    let mut failures = Vec::new();
    for (case, mapping, body) in cases {
        let (length, peak) = peak_for(mapping, body).await;
        let ratio = peak as f64 / length as f64;
        eprintln!("{case}: {length}-byte response, peak extra heap {peak} bytes ({ratio:.1}x)");
        if peak >= MAX_PEAK_PER_BODY_BYTE * length {
            failures.push(format!(
                "{case}: a {length}-byte response (within max_response_bytes) held {peak} bytes \
                 of heap at peak ({ratio:.1}x)"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
