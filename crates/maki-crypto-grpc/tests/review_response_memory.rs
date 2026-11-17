//! `max_message_bytes` must bound what a response message costs in memory,
//! not only its wire bytes. The decoder used to collect every `CryptoItem` of
//! a response before the item count was checked: an empty item is two bytes
//! on the wire but a 64-byte guarded item in memory, and the growing item
//! vector briefly holds both its old and new allocation, so a message of
//! empty items within the default 4 MiB cap held many times its size in heap.
//!
//! A counting global allocator measures the peak live heap while one response
//! is received and decoded. The message buffer tonic assembles and its growth
//! while frames arrive account for up to about twice the message; decoding
//! may add at most a small constant on top.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    PlaintextUnit, SecretBuffer,
};
use maki_crypto_grpc::{GrpcCryptoProvider, GrpcProviderSpec};
use tokio::net::TcpListener;

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

const LIMIT: usize = maki_format::config::DEFAULT_GRPC_MAX_MESSAGE_BYTES as usize;
const UNIT: usize = 4096;
/// The message is held once by tonic's decode buffer, may briefly coexist
/// with the buffer it grew out of, and decoding keeps only requested items.
const MAX_PEAK_PER_MESSAGE_BYTE: usize = 3;

/// `CryptoItem { unit_index: 0, data: "AAAA" }` as a `CryptoBatchResponse`
/// field: the one item the request asked for.
const REQUESTED_ITEM: &[u8] = &[0x0a, 6, 0x12, 4, b'A', b'A', b'A', b'A'];

fn provider(url: String) -> GrpcCryptoProvider {
    GrpcCryptoProvider::new(GrpcProviderSpec {
        url,
        encrypt_path: "/maki.CryptoService/EncryptBatch".into(),
        decrypt_path: "/maki.CryptoService/DecryptBatch".into(),
        metadata: vec![],
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
        max_message_bytes: LIMIT,
    })
    .unwrap()
}

/// Answer every RPC with the same gRPC-framed message and OK trailers. The
/// framed message is shared, so sending it allocates no copy.
async fn serve(message: Bytes) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let message = message.clone();
            tokio::spawn(async move {
                let mut connection = h2::server::handshake(socket).await.unwrap();
                while let Some(Ok((_request, mut respond))) = connection.accept().await {
                    let response = http::Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .body(())
                        .unwrap();
                    let mut stream = respond.send_response(response, false).unwrap();
                    stream.send_data(message.clone(), false).unwrap();
                    let mut trailers = http::HeaderMap::new();
                    trailers.insert("grpc-status", "0".parse().unwrap());
                    let _ = stream.send_trailers(trailers);
                }
            });
        }
    });
    (url, task)
}

/// `prefix` + repeated `filler`, as close to the message cap as fits.
fn message(prefix: &[u8], filler: &[u8]) -> Bytes {
    let mut payload = prefix.to_vec();
    while payload.len() + filler.len() <= LIMIT {
        payload.extend_from_slice(filler);
    }
    framed(payload)
}

/// The requested item, its length covering `filler` repeated after its data
/// as close to the message cap as fits.
fn padded_item(filler: &[u8]) -> Bytes {
    // A 4 MiB length takes a four-byte varint.
    let count = (LIMIT - 1 - 4 - (REQUESTED_ITEM.len() - 2)) / filler.len();
    let mut content = REQUESTED_ITEM[2..].to_vec();
    for _ in 0..count {
        content.extend_from_slice(filler);
    }
    let mut payload = vec![0x0a];
    let mut length = content.len() as u64;
    while length >= 0x80 {
        payload.push(length as u8 | 0x80);
        length >>= 7;
    }
    payload.push(length as u8);
    payload.extend_from_slice(&content);
    framed(payload)
}

/// The gRPC length-prefixed form of a message within the cap.
fn framed(payload: Vec<u8>) -> Bytes {
    assert!(payload.len() <= LIMIT && payload.len() > LIMIT - 16);
    let mut framed = vec![0];
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(&payload);
    Bytes::from(framed)
}

/// How the measured call ended: the message must have been decoded for it,
/// not refused for another reason before decoding.
fn outcome<T>(result: &Result<T, CryptoError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(CryptoError::Contract(_)) => "contract",
        Err(_) => "other",
    }
}

/// Peak live heap above the starting point while one response is handled,
/// and how the call ended.
async fn peak_for(message: Bytes) -> (usize, usize, &'static str) {
    let length = message.len() - 5;
    let (url, server) = serve(message).await;
    let provider = provider(url);
    let context = CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(1),
        format_version: 1,
        crypto_compatibility_id: "response-memory-v1".into(),
    };
    let units = vec![PlaintextUnit {
        unit_index: 0,
        data: SecretBuffer::from_slice(&[1u8; UNIT]),
    }];
    // Open the channel and warm lazily initialised statics.
    let _ = provider.encrypt_batch(&context, &units).await;
    let base = LIVE.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    let result = provider.encrypt_batch(&context, &units).await;
    let peak = PEAK.load(Ordering::SeqCst) - base;
    let outcome = outcome(&result);
    drop(result);
    drop(provider);
    server.abort();
    (length, usize::try_from(peak).unwrap_or(0), outcome)
}

/// One test, so no other test's allocations share the counters.
#[tokio::test(flavor = "current_thread")]
async fn response_message_memory_is_bounded_by_its_size() {
    let cases: [(&str, Bytes, &str); 4] = [
        (
            "empty items after the requested one",
            message(REQUESTED_ITEM, &[0x0a, 0]),
            "contract",
        ),
        (
            "items echoing another unit after the requested one",
            message(REQUESTED_ITEM, &[0x0a, 2, 0x08, 1]),
            "contract",
        ),
        (
            "unknown fields beside the requested item",
            message(REQUESTED_ITEM, &[0x10, 0]),
            "ok",
        ),
        (
            "unknown fields inside the requested item",
            padded_item(&[0x18, 0]),
            "ok",
        ),
    ];
    let mut failures = Vec::new();
    for (case, message, expected) in cases {
        let (length, peak, outcome) = peak_for(message).await;
        let ratio = peak as f64 / length as f64;
        eprintln!("{case}: {length}-byte message, peak extra heap {peak} bytes ({ratio:.1}x)");
        if peak >= MAX_PEAK_PER_MESSAGE_BYTE * length {
            failures.push(format!(
                "{case}: a {length}-byte message (within max_message_bytes) held {peak} bytes \
                 of heap at peak ({ratio:.1}x)"
            ));
        }
        if outcome != expected {
            failures.push(format!(
                "{case}: the call ended {outcome}, expected {expected}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
