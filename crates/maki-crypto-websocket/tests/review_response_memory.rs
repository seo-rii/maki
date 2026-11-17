//! `max_frame_bytes` must bound what a JSON response frame costs in memory,
//! not only its wire bytes. The reader used to build a guarded tree of every
//! node in the frame before routing it, so a frame of many small values within
//! the default 8 MiB cap (`{"id":1,"items":[...],"pad":[[],[],...]}`) held
//! many times its size in heap; with several connections in flight that is
//! enough for an out-of-memory kill.
//!
//! A counting global allocator measures the peak live heap while one response
//! is received, parsed and decoded. The frame itself, the read buffer it grew
//! in and the provider's guarded copy account for up to about twice the frame;
//! the parse may add at most a small constant on top.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::Duration;

use futures_util::StreamExt;
use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    PlaintextUnit, SecretBuffer,
};
use maki_crypto_websocket::{WsCryptoProvider, WsProviderSpec};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

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

const LIMIT: usize = maki_format::config::DEFAULT_WS_MAX_FRAME_BYTES as usize;
const UNIT: usize = 4096;
/// The frame is held by the read buffer and the provider's guarded owner, may
/// briefly coexist with the buffer it grew out of, and the parse keeps only
/// what the response handling reads.
const MAX_PEAK_PER_FRAME_BYTE: usize = 3;
/// Room for the echoed request id: JSON allows the spaces that pad it.
const ID_WIDTH: usize = 20;
const ID_KEY: &str = r#"{"id":"#;

fn provider(url: &str) -> WsCryptoProvider {
    WsCryptoProvider::new(WsProviderSpec {
        url: url.into(),
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
        max_frame_bytes: LIMIT,
        tls: None,
    })
}

/// The request id the provider serialized (`{"format":1,"id":N,...}`).
fn request_id(text: &str) -> u64 {
    let start = text.find(r#""id":"#).expect("request id") + 5;
    let digits = text[start..].bytes().take_while(u8::is_ascii_digit).count();
    text[start..start + digits].parse().expect("numeric id")
}

/// Answer every request on one connection with `payload`, its id echoed. The
/// frame is written to the socket directly, so the server's own WebSocket
/// output buffer never copies it while the client is measured.
async fn serve(payload: Vec<u8>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let mut frame = vec![0x81, 127];
    frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    let id_at = frame.len() + ID_KEY.len();
    frame.extend_from_slice(&payload);
    drop(payload);
    let task = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
            while let Some(Ok(message)) = ws.next().await {
                let Message::Text(text) = message else {
                    continue;
                };
                let id = request_id(text.as_str()).to_string();
                drop(text);
                let field = &mut frame[id_at..id_at + ID_WIDTH];
                field.fill(b' ');
                field[ID_WIDTH - id.len()..].copy_from_slice(id.as_bytes());
                if ws.get_mut().write_all(&frame).await.is_err() {
                    break;
                }
            }
        }
    });
    (url, task)
}

/// The id placeholder, `rest`, then comma-separated `filler` and `suffix`, as
/// close to the frame cap as fits.
fn payload(rest: &str, filler: &str, suffix: &str) -> Vec<u8> {
    let mut payload = format!("{ID_KEY}{}{rest}", " ".repeat(ID_WIDTH)).into_bytes();
    payload.extend_from_slice(filler.as_bytes());
    while payload.len() + 1 + filler.len() + suffix.len() <= LIMIT {
        payload.push(b',');
        payload.extend_from_slice(filler.as_bytes());
    }
    payload.extend_from_slice(suffix.as_bytes());
    assert!(payload.len() <= LIMIT && payload.len() > LIMIT - 64);
    payload
}

/// How the measured call ended: the frame must have been parsed and routed
/// to it, not dropped (which would end in a timeout).
fn outcome<T>(result: &Result<T, CryptoError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(CryptoError::Contract(_)) => "contract",
        Err(CryptoError::Throttled(_)) => "throttled",
        Err(_) => "other",
    }
}

/// Peak live heap above the starting point while one response is handled,
/// and how the call ended.
async fn peak_for(payload: Vec<u8>) -> (usize, usize, &'static str) {
    let length = payload.len();
    let (url, server) = serve(payload).await;
    let provider = provider(&url);
    let context = CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(1),
        format_version: 1,
        crypto_compatibility_id: "response-memory-v1".into(),
    };
    let units = vec![PlaintextUnit {
        unit_index: 0,
        data: SecretBuffer::from_slice(&[1u8; UNIT]),
    }];
    // Open the connection and warm lazily initialised statics.
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
async fn json_frame_memory_is_bounded_by_its_size() {
    let cases: [(&str, Vec<u8>, &str); 8] = [
        (
            "empty arrays beside the items",
            payload(r#","items":[{"unit":0,"data":"AAAA"}],"pad":["#, "[]", "]}"),
            "ok",
        ),
        (
            "empty strings beside the items",
            payload(
                r#","items":[{"unit":0,"data":"AAAA"}],"pad":["#,
                r#""""#,
                "]}",
            ),
            "ok",
        ),
        (
            "empty objects beside the items",
            payload(r#","items":[{"unit":0,"data":"AAAA"}],"pad":["#, "{}", "]}"),
            "ok",
        ),
        (
            "small numbers beside the items",
            payload(r#","items":[{"unit":0,"data":"AAAA"}],"pad":["#, "0", "]}"),
            "ok",
        ),
        (
            "more items than requested",
            payload(r#","items":[{"unit":0,"data":"AAAA"},"#, "{}", "]}"),
            "contract",
        ),
        (
            "padding inside the requested item",
            payload(r#","items":[{"unit":0,"data":"AAAA","pad":["#, "[]", "]}]}"),
            "ok",
        ),
        (
            "a container where the payload string belongs",
            payload(r#","items":[{"unit":0,"data":["#, "[]", "]}]}"),
            "contract",
        ),
        (
            "padding inside an error envelope",
            payload(r#","error":{"class":"throttled","pad":["#, "[]", "]}}"),
            "throttled",
        ),
    ];
    let mut failures = Vec::new();
    for (case, payload, expected) in cases {
        let (length, peak, outcome) = peak_for(payload).await;
        let ratio = peak as f64 / length as f64;
        eprintln!("{case}: {length}-byte frame, peak extra heap {peak} bytes ({ratio:.1}x)");
        if peak >= MAX_PEAK_PER_FRAME_BYTE * length {
            failures.push(format!(
                "{case}: a {length}-byte frame (within max_frame_bytes) held {peak} bytes of \
                 heap at peak ({ratio:.1}x)"
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
