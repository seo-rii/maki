use maki_crypto::{
    Capability, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit,
    SecretBuffer,
};
use maki_crypto_http::{
    BodySpec, HttpCryptoProvider, HttpProviderSpec, OpSpec, PayloadEncoding, RespKind, RespSpec,
};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
struct Server {
    addr: SocketAddr,
    oversized: Arc<AtomicBool>,
    count: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}
impl Server {
    fn start(chunked: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let oversized = Arc::new(AtomicBool::new(false));
        let count = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (big, c, halt) = (oversized.clone(), count.clone(), stop.clone());
        let handle = thread::spawn(move || {
            for conn in listener.incoming() {
                let mut conn = conn.unwrap();
                if halt.load(Ordering::SeqCst) {
                    break;
                }
                conn.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut data = Vec::new();
                let mut tmp = [0u8; 4096];
                let end = loop {
                    let n = conn.read(&mut tmp).unwrap();
                    assert!(n > 0);
                    data.extend_from_slice(&tmp[..n]);
                    if let Some(i) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i + 4;
                    }
                };
                let hdr = std::str::from_utf8(&data[..end]).unwrap();
                let len = hdr
                    .lines()
                    .find_map(|l| {
                        l.to_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|n| n.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                while data.len() < end + len {
                    let n = conn.read(&mut tmp).unwrap();
                    assert!(n > 0);
                    data.extend_from_slice(&tmp[..n]);
                }
                c.fetch_add(1, Ordering::SeqCst);
                let response = vec![
                    0x22;
                    if big.load(Ordering::SeqCst) {
                        2048
                    } else {
                        512
                    }
                ];
                let result = if chunked {
                    conn.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").and_then(|_|write!(conn,"{:x}\r\n",response.len())).and_then(|_|conn.write_all(&response)).and_then(|_|conn.write_all(b"\r\n0\r\n\r\n"))
                } else {
                    write!(
                        conn,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        response.len()
                    )
                    .and_then(|_| conn.write_all(&response))
                };
                let _ = result;
            }
        });
        Self {
            addr,
            oversized,
            count,
            stop,
            handle: Some(handle),
        }
    }
    fn provider(&self, retry_safe: bool) -> Arc<dyn CryptoProvider> {
        let op = OpSpec {
            method: "POST".into(),
            path: "/crypto".into(),
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
                base_url: format!("http://{}", self.addr),
                encrypt: op.clone(),
                decrypt: op,
                capabilities: CryptoCapabilities {
                    provider_id: "repro".into(),
                    crypto_compatibility_id: "repro-v1".into(),
                    supported_plaintext_sizes: vec![512],
                    max_ciphertext_size: 512,
                    stateless: true,
                    retry_safe,
                    batch: maki_crypto::BatchCapability {
                        supported: false,
                        max_items: 1,
                        max_bytes: 512,
                    },
                    integrity: Capability::Absent,
                    context_binding: Capability::Absent,
                    replay_protection: Capability::Absent,
                },
                timeout: Duration::from_secs(3),
                max_response_bytes: 1024,
                tls: None,
            })
            .unwrap(),
        )
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        self.handle.take().unwrap().join().unwrap();
    }
}
async fn http_case(chunked: bool, retry_safe: bool) {
    let left = Server::start(chunked);
    let right = Server::start(false);
    let a = left.provider(retry_safe);
    let b = right.provider(retry_safe);
    let context = CryptoContext {
        volume_uuid: Default::default(),
        format_version: 1,
        crypto_compatibility_id: "repro-v1".into(),
    };
    let items = [PlaintextUnit {
        unit_index: 0,
        data: SecretBuffer::from_slice(&[0x11; 512]),
    }];
    a.encrypt_batch(&context, &items).await.unwrap();
    b.encrypt_batch(&context, &items).await.unwrap();
    left.count.store(0, Ordering::SeqCst);
    right.count.store(0, Ordering::SeqCst);
    left.oversized.store(true, Ordering::SeqCst);
    let config = maki_crypto::endpoint::DispatchConfig {
        retry: maki_crypto::retry::RetryPolicy {
            initial_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        },
        budget: maki_crypto::retry::RetryBudgetConfig {
            retry_ratio: 1.0,
            burst: 32,
            min_probe_per_sec: 1.0,
        },
        breaker: maki_crypto::breaker::BreakerConfig {
            failure_threshold: 1,
            success_threshold: 1,
            half_open_max_requests: 1,
            open_initial: Duration::from_secs(30),
            open_max: Duration::from_secs(30),
        },
        global_max_inflight_batches: 2,
        global_max_inflight_bytes: 4096,
        per_endpoint_max_inflight: 1,
        per_endpoint_max_bytes: 2048,
        max_attempts: Some(1),
        max_operation_time: Some(Duration::from_secs(3)),
        retry_safe,
        validation_interval: Duration::from_secs(30),
    };
    let set = maki_crypto::endpoint::EndpointSet::new(
        vec![("left".into(), a), ("right".into(), b)],
        config,
        Arc::new(maki_crypto::SystemClock::new()),
    );
    let first = set.encrypt_batch(&context, &items).await;
    if retry_safe {
        assert!(first.is_ok(), "{first:?}");
    } else {
        assert!(matches!(first, Err(CryptoError::Contract(_))));
    }
    assert_eq!(left.count.load(Ordering::SeqCst), 1);
    assert_eq!(right.count.load(Ordering::SeqCst), usize::from(retry_safe));
    assert_eq!(
        set.endpoint_states()[0].1,
        maki_crypto::breaker::CircuitState::Open
    );
    assert_eq!(set.global_inflight(), (0, 0));
    for _ in 0..10 {
        set.encrypt_batch(&context, &items).await.unwrap();
    }
    assert_eq!(left.count.load(Ordering::SeqCst), 1);
    assert_eq!(
        right.count.load(Ordering::SeqCst),
        10 + usize::from(retry_safe)
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_peer_fails_over_for_length_and_chunked_responses() {
    http_case(false, true).await;
    http_case(true, true).await;
    http_case(false, false).await;
    http_case(true, false).await;
}
