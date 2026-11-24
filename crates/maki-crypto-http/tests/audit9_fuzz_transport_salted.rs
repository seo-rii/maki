//! Round-9 audit (providers-native): `review_fuzz_transport` run longer and
//! salted, plus a raw-TCP variant that reaches HTTP/1.1 framing faults a
//! well-behaved server library never sends: mutated status lines, conflicting
//! or huge `content-length`, chunked bodies with huge, negative or malformed
//! sizes and missing terminators, close-delimited bodies, obs-text and
//! control bytes in reason phrases and header values, `maki-crypto-error`
//! tokens on random statuses, redirects, keep-alive versus close, and
//! silence (the call times out).
//!
//! Contract: every call resolves within its timeout plus slack, never panics,
//! an `Ok` has one unit per request item, and an error message never
//! carries endpoint text.
//!
//! `AUDIT9_HTTP_FUZZ_SEEDS=a..b`, `AUDIT9_HTTP_FUZZ_ITERS=n` widen it.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoProvider,
    PlaintextUnit, SecretBuffer,
};
use maki_crypto_http::{
    BodySpec, FieldSource, HttpCryptoProvider, HttpProviderSpec, OpSpec, PayloadEncoding, RespKind,
    RespSpec,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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
    fn rbytes(&mut self, max: u64) -> Vec<u8> {
        let n = self.below(max) as usize;
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0xF1),
        format_version: 1,
        crypto_compatibility_id: "vendor-profile-v1".to_string(),
    }
}

fn caps() -> CryptoCapabilities {
    CryptoCapabilities {
        provider_id: "remote-http-fuzz9".to_string(),
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
            fields: vec![("/data".to_string(), FieldSource::Payload(PayloadEncoding::Base64))],
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
            item_fields: vec![("/data".to_string(), FieldSource::Payload(PayloadEncoding::HexLower))],
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

fn raw_op() -> OpSpec {
    OpSpec {
        method: "POST".to_string(),
        path: "/op".to_string(),
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
    }
}

fn provider(url: &str, op: OpSpec) -> HttpCryptoProvider {
    HttpCryptoProvider::new(HttpProviderSpec {
        base_url: url.to_string(),
        encrypt: op.clone(),
        decrypt: op,
        capabilities: caps(),
        timeout: Duration::from_millis(400),
        max_response_bytes: 1 << 12,
        tls: None,
    })
    .unwrap()
}

#[derive(Clone, Copy)]
enum Layout {
    PerItem,
    Batched,
    Raw,
}

/// A JSON body for the layout: mostly right, sometimes mutated.
fn body(rng: &mut Rng, layout: Layout, items: usize) -> Vec<u8> {
    let b64 = "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWg==";
    let hex = "5a".repeat(UNIT);
    match layout {
        Layout::Raw => vec![0x5a; if rng.chance(80) { UNIT } else { rng.below(200) as usize }],
        Layout::PerItem => match rng.below(6) {
            0 => br#"{"ciphertext":"!!"}"#.to_vec(),
            1 => format!(r#"{{"ciphertext":"{b64}","ciphertext":7}}"#).into_bytes(),
            2 => format!(r#"{{"ciphertext":"{}"}}"#, &b64[..20]).into_bytes(),
            _ => format!(r#"{{"ciphertext":"{b64}","junk":[{{}},"\u001b[31m injected"]}}"#).into_bytes(),
        },
        Layout::Batched => {
            let mut n = items;
            match rng.below(8) {
                0 => n = n.saturating_sub(1),
                1 => n += 1,
                _ => {}
            }
            let elems: Vec<String> = (0..n)
                .map(|i| {
                    let idx = if rng.chance(10) { i + 1 } else { i };
                    let ct = if rng.chance(10) { "zz".to_string() } else { hex.clone() };
                    format!(r#"{{"ct":"{ct}","idx":{idx}}}"#)
                })
                .collect();
            format!(r#"{{"results":[{}]}}"#, elems.join(",")).into_bytes()
        }
    }
}

/// A complete raw HTTP/1.1 response, possibly malformed.
fn response(rng: &mut Rng, layout: Layout, items: usize) -> (Vec<u8>, bool) {
    let payload = body(rng, layout, items);
    let status: &[u8] = match rng.below(24) {
        0 => b"HTTP/1.1 500 \x1b[31mInjected\r\n",
        1 => b"HTTP/1.1 503 Busy \xff\xfe\r\n",
        2 => b"HTTP/1.1 422 Unprocessable\r\n",
        3 => b"HTTP/1.1 429 Slow\r\n",
        4 => b"HTTP/1.1 307 Temporary\r\n",
        5 => b"HTTP/1.0 200 OK\r\n",
        6 => b"HTTP/1.1 999 Odd\r\n",
        7 => b"HTTP/1.1 2000 Odd\r\n",
        8 => b"HTTP/2 200\r\n",
        9 => b"HTTP/1.1 200\r\n",
        10 => b"garbage\r\n",
        11 => b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n",
        12 => b"HTTP/1.1 401 \r\n",
        _ => b"HTTP/1.1 200 OK\r\n",
    };
    let mut out = status.to_vec();
    if rng.chance(20) {
        out.extend_from_slice(b"maki-crypto-error: ");
        out.extend_from_slice(
            [b"auth-tag-mismatch".as_slice(), b"context-mismatch", b"unsupported-format-version", b"x\x1b[2J"]
                [rng.below(4) as usize],
        );
        out.extend_from_slice(b"\r\n");
    }
    if rng.chance(10) {
        out.extend_from_slice(b"location: http://127.0.0.1:9/trap\r\n");
    }
    if rng.chance(10) {
        out.extend_from_slice(b"x-evil: injected \xe2\x80\xae obs \x80\r\n");
    }
    if rng.chance(5) {
        out.extend_from_slice(b"x-folded: a\r\n continued\r\n");
    }
    out.extend_from_slice(b"content-type: application/json\r\n");
    let mut close = rng.chance(30);
    let framing = rng.below(12);
    let mut wire_body = Vec::new();
    match framing {
        0..=4 => {
            out.extend_from_slice(format!("content-length: {}\r\n", payload.len()).as_bytes());
            wire_body = payload.clone();
        }
        5 => {
            out.extend_from_slice(format!("content-length: {}\r\n", payload.len() + 10).as_bytes());
            wire_body = payload.clone();
            close = true;
        }
        6 => {
            out.extend_from_slice(b"content-length: 99999999999999999999999\r\n");
            wire_body = payload.clone();
            close = true;
        }
        7 => {
            out.extend_from_slice(format!("content-length: {}\r\ncontent-length: 3\r\n", payload.len()).as_bytes());
            wire_body = payload.clone();
        }
        8 => {
            out.extend_from_slice(b"transfer-encoding: chunked\r\n");
            let cut = rng.below(payload.len() as u64 + 1) as usize;
            for part in [&payload[..cut], &payload[cut..]] {
                if !part.is_empty() {
                    wire_body.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
                    wire_body.extend_from_slice(part);
                    wire_body.extend_from_slice(b"\r\n");
                }
            }
            if rng.chance(70) {
                wire_body.extend_from_slice(b"0\r\n\r\n");
            } else {
                close = true;
            }
        }
        9 => {
            out.extend_from_slice(b"transfer-encoding: chunked\r\n");
            let sizes: [&[u8]; 5] = [b"ffffffffffffffffffff\r\n", b"-1\r\n", b"zz\r\n", b"4;ext=\x1b\r\n", b"10000\r\n"];
            wire_body.extend_from_slice(sizes[rng.below(5) as usize]);
            wire_body.extend_from_slice(&payload);
            close = true;
        }
        10 => {
            // close-delimited
            wire_body = payload.clone();
            close = true;
        }
        _ => {
            out.extend_from_slice(b"transfer-encoding: gzip, chunked\r\n");
            wire_body.extend_from_slice(format!("{:x}\r\n", payload.len()).as_bytes());
            wire_body.extend_from_slice(&payload);
            wire_body.extend_from_slice(b"\r\n0\r\n\r\n");
        }
    }
    if close {
        out.extend_from_slice(b"connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend(wire_body);
    if rng.chance(5) {
        out.extend(rng.rbytes(64));
    }
    if rng.chance(5) {
        let cut = rng.below(out.len() as u64) as usize;
        out.truncate(cut);
        close = true;
    }
    (out, close)
}

/// Read one request (head + content-length body); false at EOF.
async fn read_request(socket: &mut tokio::net::TcpStream, buffer: &mut Vec<u8>) -> bool {
    loop {
        if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buffer[..end]).to_ascii_lowercase();
            let length: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0)))
                .unwrap_or(0);
            let total = end + 4 + length;
            while buffer.len() < total {
                let mut chunk = [0u8; 4096];
                match socket.read(&mut chunk).await {
                    Ok(0) | Err(_) => return false,
                    Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                }
            }
            buffer.drain(..total);
            return true;
        }
        let mut chunk = [0u8; 4096];
        match socket.read(&mut chunk).await {
            Ok(0) | Err(_) => return false,
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
        }
    }
}

fn count_items(layout: Layout, request: usize) -> usize {
    match layout {
        Layout::Batched => request,
        _ => 1,
    }
}

async fn raw_server(seed: u64, layout: Layout, items: Arc<Mutex<usize>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let rng = Arc::new(Mutex::new(Rng(seed)));
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let rng = rng.clone();
            let items = items.clone();
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                while read_request(&mut socket, &mut buffer).await {
                    let n = count_items(layout, *items.lock().unwrap());
                    let (bytes, close, silence) = {
                        let mut r = rng.lock().unwrap();
                        let silence = r.chance(2);
                        let (bytes, close) = response(&mut r, layout, n);
                        (bytes, close, silence)
                    };
                    if silence {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        return;
                    }
                    if socket.write_all(&bytes).await.is_err() || close {
                        let _ = socket.shutdown().await;
                        return;
                    }
                }
            });
        }
    });
    url
}

fn seeds() -> std::ops::Range<u64> {
    std::env::var("AUDIT9_HTTP_FUZZ_SEEDS")
        .ok()
        .and_then(|s| {
            let (a, b) = s.split_once("..")?;
            Some(a.parse().ok()?..b.parse().ok()?)
        })
        .unwrap_or(0..2)
}

fn iterations() -> usize {
    std::env::var("AUDIT9_HTTP_FUZZ_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(150)
}

async fn run(layout: Layout, op: OpSpec) {
    let (mut ok, mut errors) = (0usize, std::collections::BTreeMap::<String, usize>::new());
    for seed in seeds() {
        let salt = seed.wrapping_mul(0x5DEECE66D) ^ 0xA9_0068;
        let items = Arc::new(Mutex::new(1usize));
        let url = raw_server(salt, layout, items.clone()).await;
        let provider = provider(&url, op.clone());
        let mut local = Rng(salt ^ 3);
        for i in 0..iterations() {
            let count = 1 + local.below(4) as usize;
            *items.lock().unwrap() = count;
            let request: Vec<PlaintextUnit> = (0..count as u64)
                .map(|u| PlaintextUnit { unit_index: u, data: SecretBuffer::from_slice(&[0x44; UNIT]) })
                .collect();
            let result = tokio::time::timeout(Duration::from_secs(10), provider.encrypt_batch(&ctx(), &request))
                .await
                .unwrap_or_else(|_| panic!("seed {seed} iteration {i}: call did not resolve in 10 s"));
            match result {
                Ok(out) => {
                    assert_eq!(out.len(), count, "seed {seed} iteration {i}: wrong item count");
                    ok += 1;
                }
                Err(error) => {
                    let text = error.to_string();
                    assert!(
                        !text.contains('\u{1b}') && !text.contains('\r') && !text.contains("injected") && !text.contains("trap"),
                        "seed {seed} iteration {i}: endpoint text reached the error: {text:?}"
                    );
                    *errors.entry(format!("{:?}", error.class())).or_default() += 1;
                }
            }
        }
    }
    eprintln!("http raw fuzz: seeds {:?} x {} iterations: ok={ok} errors={errors:?}", seeds(), iterations());
    assert!(ok > 0, "the fuzz never reached the success path");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_http_responses_per_item_resolve_without_panic_or_hang() {
    run(Layout::PerItem, per_item_op()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_http_responses_batched_resolve_without_panic_or_hang() {
    run(Layout::Batched, batched_op()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_http_responses_raw_body_resolve_without_panic_or_hang() {
    run(Layout::Raw, raw_op()).await;
}
