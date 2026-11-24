//! Round-9 audit (providers-native): salted fuzz of the gRPC provider's
//! response path with a raw h2 server, so replies tonic's own server would
//! never produce are reachable: random HTTP status and content type,
//! trailers-only responses, random or invalid `grpc-status`, a
//! `maki-crypto-error` token on random statuses, gRPC message frames with a
//! random compressed flag and a length prefix that is right, short, long or
//! huge, protobuf bodies that are random bytes or hand-encoded responses
//! with the right, missing, extra or wrong items, data split across frames,
//! stream resets with random codes, and silence (the call times out).
//!
//! Contract: every call resolves within its timeout plus slack, never
//! panics, an `Ok` has one unit per request item, and an error message
//! never carries endpoint text.
//!
//! `AUDIT9_GRPC_FUZZ_SEEDS=a..b` and `AUDIT9_GRPC_FUZZ_ITERS=n` widen it.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext,
    CryptoProvider, PlaintextUnit, SecretBuffer,
};
use maki_crypto_grpc::{GrpcCryptoProvider, GrpcProviderSpec};
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
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
    fn rbytes(&mut self, max: u64) -> Vec<u8> {
        let n = self.below(max) as usize;
        self.bytes(n)
    }
}

fn varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// CryptoBatchResponse { repeated CryptoItem items = 1 }, CryptoItem {
/// uint64 unit_index = 1; bytes data = 2 }.
fn response_message(rng: &mut Rng, count: usize) -> Vec<u8> {
    let mut units: Vec<u64> = (0..count as u64).collect();
    match rng.below(10) {
        0 => {
            units.pop();
        }
        1 => units.push(count as u64 + 5),
        2 => {
            if let Some(u) = units.first_mut() {
                *u = 77;
            }
        }
        3 => units.reverse(),
        _ => {}
    }
    let mut out = Vec::new();
    for u in units {
        let mut item = Vec::new();
        item.push(0x08);
        varint(u, &mut item);
        let len = match rng.below(12) {
            0 => 0,
            1 => UNIT + 1,
            2 => rng.below(300) as usize,
            _ => UNIT,
        };
        item.push(0x12);
        varint(len as u64, &mut item);
        item.extend(std::iter::repeat_n(0x5a, len));
        if rng.chance(5) {
            // unknown field
            item.extend([0x1a, 0x02, 0xff, 0xfe]);
        }
        out.push(0x0a);
        varint(item.len() as u64, &mut out);
        out.extend(item);
    }
    if rng.chance(5) {
        // a truncated tail
        let cut = rng.below(out.len().max(1) as u64) as usize;
        out.truncate(cut);
    }
    out
}

fn frame(rng: &mut Rng, message: &[u8]) -> Vec<u8> {
    let flag = match rng.below(20) {
        0 => 1u8,
        1 => 2,
        _ => 0,
    };
    let len = match rng.below(20) {
        0 => message.len() as u32 + 3,
        1 => message.len().saturating_sub(1) as u32,
        2 => u32::MAX,
        3 => 0,
        _ => message.len() as u32,
    };
    let mut out = vec![flag];
    out.extend(len.to_be_bytes());
    out.extend_from_slice(message);
    out
}

async fn server(seed: u64) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let rng = Arc::new(Mutex::new(Rng(seed)));
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let rng = rng.clone();
            tokio::spawn(async move {
                let Ok(mut connection) = h2::server::handshake(socket).await else {
                    return;
                };
                while let Some(Ok((request, mut respond))) = connection.accept().await {
                    let rng = rng.clone();
                    tokio::spawn(async move {
                        let mut body = request.into_body();
                        let mut received = Vec::new();
                        while let Some(Ok(chunk)) = body.data().await {
                            let _ = body.flow_control().release_capacity(chunk.len());
                            received.extend_from_slice(&chunk);
                        }
                        // Count request items: field 3 entries of the request.
                        let count = count_request_items(&received);
                        let plan = {
                            let mut r = rng.lock().unwrap();
                            Plan::draw(&mut r, count)
                        };
                        plan.run(&mut respond).await;
                    });
                }
            });
        }
    });
    url
}

/// Number of `items` (field 3) in a CryptoBatchRequest (after the 5-byte
/// gRPC prefix). The request comes from Maki, so it is well formed.
fn count_request_items(frame: &[u8]) -> usize {
    let Some(mut rest) = frame.get(5..) else { return 1 };
    let mut count = 0;
    while !rest.is_empty() {
        let key = rest[0];
        rest = &rest[1..];
        let wire = key & 7;
        match wire {
            0 => {
                while !rest.is_empty() && rest[0] & 0x80 != 0 {
                    rest = &rest[1..];
                }
                rest = rest.get(1..).unwrap_or(&[]);
            }
            2 => {
                let mut len = 0u64;
                let mut shift = 0;
                while let Some((&b, tail)) = rest.split_first() {
                    rest = tail;
                    len |= u64::from(b & 0x7f) << shift;
                    shift += 7;
                    if b & 0x80 == 0 {
                        break;
                    }
                }
                let len = (len as usize).min(rest.len());
                if key >> 3 == 3 {
                    count += 1;
                }
                rest = &rest[len..];
            }
            _ => break,
        }
    }
    count.max(1)
}

struct Plan {
    status: u16,
    content_type: Option<&'static str>,
    trailers_only: bool,
    header_status: Option<String>,
    chunks: Vec<Vec<u8>>,
    trailer_status: Option<String>,
    token: Option<&'static str>,
    reset: Option<u32>,
    silence: bool,
}

impl Plan {
    fn draw(rng: &mut Rng, count: usize) -> Self {
        let statuses = [200u16, 200, 200, 200, 200, 404, 500, 503, 401, 429];
        let codes = ["0", "0", "0", "1", "2", "3", "4", "5", "8", "9", "13", "14", "16", "99", "abc", ""];
        let tokens = ["auth-tag-mismatch", "context-mismatch", "unsupported-format-version", "bogus"];
        let message = if rng.chance(10) {
            rng.rbytes(120)
        } else {
            response_message(rng, count)
        };
        let framed = if rng.chance(85) { frame(rng, &message) } else { rng.rbytes(40) };
        let mut chunks = Vec::new();
        if rng.chance(30) && framed.len() > 2 {
            let cut = 1 + rng.below(framed.len() as u64 - 1) as usize;
            chunks.push(framed[..cut].to_vec());
            chunks.push(framed[cut..].to_vec());
        } else {
            chunks.push(framed);
        }
        if rng.chance(5) {
            // a second message: unary cardinality violation
            let extra = response_message(rng, count);
            chunks.push(frame(rng, &extra));
        }
        let pick = |rng: &mut Rng| codes[rng.below(codes.len() as u64) as usize].to_string();
        Plan {
            status: statuses[rng.below(statuses.len() as u64) as usize],
            content_type: match rng.below(10) {
                0 => None,
                1 => Some("text/html"),
                2 => Some("application/grpc+proto"),
                _ => Some("application/grpc"),
            },
            trailers_only: rng.chance(10),
            header_status: rng.chance(10).then(|| pick(rng)),
            chunks,
            trailer_status: if rng.chance(90) { Some(pick(rng)) } else { None },
            token: rng.chance(15).then(|| tokens[rng.below(tokens.len() as u64) as usize]),
            reset: rng.chance(5).then(|| rng.below(14) as u32),
            silence: rng.chance(2),
        }
    }

    async fn run(self, respond: &mut h2::server::SendResponse<Bytes>) {
        if self.silence {
            tokio::time::sleep(Duration::from_secs(2)).await;
            return;
        }
        if let Some(code) = self.reset {
            respond.send_reset(h2::Reason::from(code));
            return;
        }
        let mut builder = http::Response::builder().status(self.status);
        if let Some(ct) = self.content_type {
            builder = builder.header("content-type", ct);
        }
        if let Some(code) = &self.header_status {
            if let Ok(value) = http::HeaderValue::from_str(code) {
                builder = builder.header("grpc-status", value);
            }
            builder = builder.header("grpc-message", "%1B%5B31m%0D%0Ainjected");
        }
        if let Some(token) = self.token {
            builder = builder.header("maki-crypto-error", token);
        }
        let response = builder.body(()).unwrap();
        let Ok(mut stream) = respond.send_response(response, self.trailers_only) else {
            return;
        };
        if self.trailers_only {
            return;
        }
        for chunk in self.chunks {
            if stream.send_data(Bytes::from(chunk), false).is_err() {
                return;
            }
        }
        let mut trailers = http::HeaderMap::new();
        if let Some(code) = &self.trailer_status {
            if let Ok(value) = http::HeaderValue::from_str(code) {
                trailers.insert("grpc-status", value);
            }
            trailers.insert("grpc-message", http::HeaderValue::from_static("%1B%5B2J%0D%0Ainjected"));
        }
        if let Some(token) = self.token {
            trailers.insert("maki-crypto-error", http::HeaderValue::from_static(token));
        }
        let _ = stream.send_trailers(trailers);
    }
}

fn provider(url: String) -> GrpcCryptoProvider {
    GrpcCryptoProvider::new(GrpcProviderSpec {
        url,
        encrypt_path: "/maki.CryptoService/EncryptBatch".into(),
        decrypt_path: "/maki.CryptoService/DecryptBatch".into(),
        metadata: vec![],
        capabilities: CryptoCapabilities {
            provider_id: "audit9-grpc-fuzz".into(),
            crypto_compatibility_id: "audit9-grpc-v1".into(),
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
        timeout: Duration::from_millis(500),
        max_message_bytes: 4096,
    })
    .unwrap()
}

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x9b),
        format_version: 1,
        crypto_compatibility_id: "audit9-grpc-v1".into(),
    }
}

fn seeds() -> std::ops::Range<u64> {
    std::env::var("AUDIT9_GRPC_FUZZ_SEEDS")
        .ok()
        .and_then(|s| {
            let (a, b) = s.split_once("..")?;
            Some(a.parse().ok()?..b.parse().ok()?)
        })
        .unwrap_or(0..3)
}

fn iterations() -> usize {
    std::env::var("AUDIT9_GRPC_FUZZ_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(150)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_responses_resolve_without_panic_or_hang() {
    let (mut ok, mut errors) = (0usize, std::collections::BTreeMap::<String, usize>::new());
    for seed in seeds() {
        let salt = seed.wrapping_mul(0x5DEECE66D) ^ 0xA9_0067;
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
                        .map(|out| out.len())
                } else {
                    let items: Vec<_> = (0..count as u64)
                        .map(|u| PlaintextUnit { unit_index: u, data: SecretBuffer::from_slice(&[0x44; UNIT]) })
                        .collect();
                    provider.encrypt_batch(&context(), &items).await.map(|out| out.len())
                }
            };
            let result = tokio::time::timeout(Duration::from_secs(10), call)
                .await
                .unwrap_or_else(|_| panic!("seed {seed} iteration {i}: call did not resolve in 10 s"));
            match result {
                Ok(n) => {
                    assert_eq!(n, count, "seed {seed} iteration {i}: wrong item count");
                    ok += 1;
                }
                Err(error) => {
                    let text = error.to_string();
                    assert!(
                        !text.contains('\u{1b}') && !text.contains('\r') && !text.contains("injected"),
                        "seed {seed} iteration {i}: endpoint text reached the error: {text:?}"
                    );
                    *errors.entry(format!("{:?}", error.class())).or_default() += 1;
                }
            }
        }
    }
    eprintln!("grpc fuzz: seeds {:?} x {} iterations: ok={ok} errors={errors:?}", seeds(), iterations());
    assert!(ok > 0, "no call succeeded; the fuzz never reached the success path");
}
