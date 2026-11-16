//! Audit: the response size cap bounds wire bytes, not what the guarded JSON
//! tree allocates for them. Measure peak live heap while one per-item JSON
//! response within the default 8 MiB cap is processed.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoProvider, PlaintextUnit,
    SecretBuffer,
};
use maki_crypto_http::{
    BodySpec, FieldSource, HttpCryptoProvider, HttpProviderSpec, OpSpec, PayloadEncoding,
    RespKind, RespSpec,
};

struct Counting;
static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let now = LIVE.fetch_add(layout.size() as isize, Ordering::SeqCst) + layout.size() as isize;
            PEAK.fetch_max(now, Ordering::SeqCst);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::SeqCst);
        unsafe { System.dealloc(p, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

const LIMIT: usize = 8 << 20; // DEFAULT_HTTP_MAX_RESPONSE_BYTES

fn provider(url: &str) -> HttpCryptoProvider {
    let op = OpSpec {
        method: "POST".into(),
        path: "/encrypt".into(),
        headers: vec![],
        query: vec![],
        body: BodySpec::Json {
            fields: vec![("/data".into(), FieldSource::Payload(PayloadEncoding::Base64))],
            items_path: None,
            item_fields: vec![],
        },
        response: RespSpec {
            kind: RespKind::Json,
            data_path: Some("/data".into()),
            encoding: PayloadEncoding::Base64,
            items_path: None,
            item_index_path: None,
        },
    };
    HttpCryptoProvider::new(HttpProviderSpec {
        base_url: url.into(),
        encrypt: op.clone(),
        decrypt: op,
        capabilities: CryptoCapabilities {
            provider_id: "audit".into(),
            crypto_compatibility_id: "audit-v1".into(),
            supported_plaintext_sizes: vec![4096],
            max_ciphertext_size: 4124,
            stateless: true,
            retry_safe: true,
            batch: BatchCapability {
                supported: true,
                max_items: 1,
                max_bytes: 4096,
            },
            integrity: Capability::Absent,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        },
        timeout: Duration::from_secs(30),
        max_response_bytes: LIMIT,
        tls: None,
    })
    .unwrap()
}

async fn serve(response: Arc<Vec<u8>>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let response = response.clone();
            tokio::spawn(async move {
                let mut buffer = [0u8; 16384];
                loop {
                    // Requests here are small: one read per request suffices
                    // for headers + a ~5.5 KiB JSON body on loopback.
                    let mut got = 0usize;
                    let mut seen = Vec::new();
                    loop {
                        let n = match socket.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        got += n;
                        seen.extend_from_slice(&buffer[..n]);
                        if let Some(end) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&seen[..end]).to_lowercase();
                            let len = head
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length:"))
                                .map(|v| v.trim().parse::<usize>().unwrap())
                                .unwrap_or(0);
                            if got >= end + 4 + len {
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
    url
}

async fn peak_for(body: Vec<u8>) -> (usize, isize) {
    let len = body.len();
    assert!(len <= LIMIT);
    let mut response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {len}\r\n\r\n"
    )
    .into_bytes();
    response.extend_from_slice(&body);
    drop(body);
    let url = serve(Arc::new(response)).await;
    let provider = provider(&url);
    let context = CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(1),
        format_version: 1,
        crypto_compatibility_id: "audit-v1".into(),
    };
    let units = vec![PlaintextUnit {
        unit_index: 0,
        data: SecretBuffer::from_slice(&[1u8; 4096]),
    }];
    // Warm up the connection pool and lazily initialised statics.
    let _ = provider.encrypt_batch(&context, &units).await;
    let base = LIVE.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    let result = provider.encrypt_batch(&context, &units).await;
    let peak = PEAK.load(Ordering::SeqCst) - base;
    eprintln!(
        "response {len} bytes -> peak extra heap {peak} bytes ({:.1}x), result={:?}",
        peak as f64 / len as f64,
        result.as_ref().map(|r| r.len())
    );
    (len, peak)
}

#[tokio::test(flavor = "current_thread")]
async fn small_values_amplify_the_response_cap() {
    // {"data":"<valid ciphertext>","pad":["","",...]} within the cap.
    let mut body = br#"{"data":"AAAA","pad":[""#.to_vec();
    while body.len() + 4 < LIMIT - 8 {
        body.extend_from_slice(br#"",""#);
    }
    body.extend_from_slice(br#""]}"#);
    let (len, peak) = peak_for(body).await;
    // Wire bytes are copied into one guarded body (1x) and the tree; more
    // than ~4x means the cap does not bound the provider's memory.
    assert!(
        (peak as usize) < 4 * len,
        "AUDIT: an {len}-byte response (within max_response_bytes) made the HTTP provider \
         hold {peak} bytes of heap at peak ({:.1}x)",
        peak as f64 / len as f64
    );
}

#[tokio::test(flavor = "current_thread")]
async fn empty_arrays_amplify_the_response_cap() {
    let mut body = br#"{"data":"AAAA","pad":[[]"#.to_vec();
    while body.len() + 3 < LIMIT - 8 {
        body.extend_from_slice(b",[]");
    }
    body.extend_from_slice(b"]}");
    let (len, peak) = peak_for(body).await;
    assert!(
        (peak as usize) < 4 * len,
        "AUDIT: an {len}-byte response (within max_response_bytes) made the HTTP provider \
         hold {peak} bytes of heap at peak ({:.1}x)",
        peak as f64 / len as f64
    );
}
