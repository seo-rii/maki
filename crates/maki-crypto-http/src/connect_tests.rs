//! The connect gives each resolved address of a family a share of the
//! request's `timeout`, so an address that never answers (a route that drops
//! packets) does not hold the request until its timeout while the next
//! address would have served it. The endpoint's name resolves, through
//! reqwest's override, to the test's loopback addresses. One that never
//! answers is a listener whose accept queue is full: Linux drops the SYNs
//! sent to it, so the connect stays pending. Time is paused and moved by
//! hand; loopback I/O runs while a test polls without letting it advance.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError,
    CryptoProvider, PlaintextUnit, SecretBuffer,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::{
    BodySpec, HttpCryptoProvider, HttpProviderSpec, OpSpec, PayloadEncoding, RespKind, RespSpec,
};

const HOST: &str = "provider.test";
const TIMEOUT: Duration = Duration::from_secs(10);
const TICK: Duration = Duration::from_millis(1);
const UNIT: usize = 16;
const XOR: u8 = 0x3c;
/// Wall-clock time a test lets loopback I/O run to show that something
/// does not happen.
const QUIET: Duration = Duration::from_millis(200);
/// Wall-clock bound on what must happen.
const PATIENCE: Duration = Duration::from_secs(10);

/// A loopback address that never answers a connect. The listener's accept
/// queue (backlog 0) holds one connection that is never accepted, and Linux
/// drops every later SYN while the queue is full, so the connect stays
/// pending until its own timeout.
struct Unanswered {
    address: SocketAddr,
    _listener: tokio::net::TcpListener,
    _queued: std::net::TcpStream,
}

impl Unanswered {
    fn new() -> Self {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = socket.listen(0).unwrap();
        let address = listener.local_addr().unwrap();
        let queued = std::net::TcpStream::connect_timeout(&address, PATIENCE)
            .expect("the accept queue takes one connection");
        // A refused connect would let the next address be tried at once,
        // and the tests would prove nothing.
        let probe = std::net::TcpStream::connect_timeout(&address, QUIET);
        assert!(
            matches!(&probe, Err(error) if error.kind() == std::io::ErrorKind::TimedOut),
            "a connect to a full accept queue must go unanswered: {probe:?}"
        );
        Self {
            address,
            _listener: listener,
            _queued: queued,
        }
    }
}

/// A loopback port that is bound but not listening: a connect to it is
/// refused at once.
struct Refusing {
    address: SocketAddr,
    _socket: tokio::net::TcpSocket,
}

impl Refusing {
    fn new() -> Self {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        Self {
            address: socket.local_addr().unwrap(),
            _socket: socket,
        }
    }
}

/// A loopback endpoint that answers each request with the XOR of its raw
/// body, and records when, in the test's paused time, it accepted each
/// connection.
struct Endpoint {
    address: SocketAddr,
    accepted: Arc<parking_lot::Mutex<Vec<tokio::time::Instant>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Endpoint {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let record = accepted.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                record.lock().push(tokio::time::Instant::now());
                tokio::spawn(answer(socket));
            }
        });
        Self {
            address,
            accepted,
            task,
        }
    }

    /// When each connection was accepted, relative to `started`.
    fn accepted_at(&self, started: tokio::time::Instant) -> Vec<Duration> {
        self.accepted
            .lock()
            .iter()
            .map(|at| at.duration_since(started))
            .collect()
    }
}

/// Read one request and answer it with the XOR of its body.
async fn answer(mut socket: tokio::net::TcpStream) {
    let mut request = Vec::new();
    let mut buffer = [0u8; 1024];
    let body = loop {
        let Ok(length) = socket.read(&mut buffer).await else {
            return;
        };
        if length == 0 {
            return;
        }
        request.extend_from_slice(&buffer[..length]);
        if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&request[..end]).into_owned();
            let body_length = head
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value.trim().parse::<usize>().unwrap())
                .unwrap_or(0);
            if request.len() >= end + 4 + body_length {
                break request[end + 4..end + 4 + body_length].to_vec();
            }
        }
    };
    let body: Vec<u8> = body.iter().map(|byte| byte ^ XOR).collect();
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = socket.write_all(head.as_bytes()).await;
    let _ = socket.write_all(&body).await;
    let _ = socket.shutdown().await;
}

/// A raw single-item provider whose endpoint host resolves to `addresses`.
/// The URL names no port, so each address keeps its own.
fn provider(addresses: &[SocketAddr]) -> HttpCryptoProvider {
    let operation = OpSpec {
        method: "POST".into(),
        path: "/encrypt".into(),
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
    let spec = HttpProviderSpec {
        base_url: format!("http://{HOST}"),
        encrypt: operation.clone(),
        decrypt: operation,
        capabilities: CryptoCapabilities {
            provider_id: "http-connect".into(),
            crypto_compatibility_id: context().crypto_compatibility_id,
            supported_plaintext_sizes: vec![UNIT as u32],
            max_ciphertext_size: UNIT as u32,
            stateless: true,
            retry_safe: false,
            batch: BatchCapability::default(),
            integrity: Capability::Absent,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        },
        timeout: TIMEOUT,
        max_response_bytes: 4096,
        tls: None,
    };
    HttpCryptoProvider::with_client(spec, |client| client.resolve_to_addrs(HOST, addresses))
        .unwrap()
}

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x0c0e),
        format_version: 1,
        crypto_compatibility_id: "http-connect-v1".into(),
    }
}

fn unit() -> PlaintextUnit {
    PlaintextUnit {
        unit_index: 0,
        data: SecretBuffer::from_slice(&[0x42; UNIT]),
    }
}

type Encrypting<'a> =
    std::pin::Pin<Box<dyn Future<Output = Result<Vec<CiphertextUnit>, CryptoError>> + Send + 'a>>;

/// Poll `future` with loopback I/O running for up to `wall` of wall-clock
/// time, while paused time stays where the test put it: a runtime that is
/// never idle does not advance the clock. `None` if it has not finished.
async fn run_for<F: Future + Unpin>(future: &mut F, wall: Duration) -> Option<F::Output> {
    let started = std::time::Instant::now();
    loop {
        if let Poll::Ready(output) = futures_util::poll!(&mut *future) {
            return Some(output);
        }
        if started.elapsed() >= wall {
            return None;
        }
        tokio::task::yield_now().await;
    }
}

/// Start `request` at the current paused time: the first address is dialed.
async fn start(request: &mut Encrypting<'_>) {
    assert!(
        run_for(request, QUIET).await.is_none(),
        "the request finished before any address's share ran out"
    );
}

#[tokio::test(start_paused = true)]
async fn a_first_address_that_never_answers_leaves_the_next_one_of_its_family_its_share() {
    let dead = Unanswered::new();
    let endpoint = Endpoint::start().await;
    let provider = provider(&[dead.address, endpoint.address]);
    let (context, units) = (context(), [unit()]);
    let started = tokio::time::Instant::now();
    let mut request = provider.encrypt_batch(&context, &units);
    start(&mut request).await;

    // Two IPv4 addresses: half the timeout each, one at a time.
    tokio::time::advance(TIMEOUT / 2 - TICK).await;
    assert!(
        run_for(&mut request, QUIET).await.is_none(),
        "the request finished while the first address still had time"
    );
    assert!(
        endpoint.accepted_at(started).is_empty(),
        "the second address was dialed while the first still had time"
    );
    tokio::time::advance(2 * TICK).await;
    let ciphertext = run_for(&mut request, PATIENCE)
        .await
        .expect("an address that never answers held the request past its share of the timeout")
        .expect("the second address serves the request");
    assert_eq!(ciphertext[0].data, vec![0x42 ^ XOR; UNIT]);
    let accepted = endpoint.accepted_at(started);
    assert_eq!(accepted.len(), 1, "{accepted:?}");
    assert!(
        accepted[0] >= TIMEOUT / 2 && accepted[0] <= TIMEOUT / 2 + TICK,
        "the second address was dialed at {:?}",
        accepted[0]
    );
    assert!(started.elapsed() < TIMEOUT, "{:?}", started.elapsed());
}

#[tokio::test(start_paused = true)]
async fn addresses_that_all_fail_within_their_shares_fail_the_request_unsent_before_its_timeout() {
    let dead = Unanswered::new();
    let refusing = Refusing::new();
    let provider = provider(&[dead.address, refusing.address]);
    let (context, units) = (context(), [unit()]);
    let started = tokio::time::Instant::now();
    let mut request = provider.encrypt_batch(&context, &units);
    start(&mut request).await;

    tokio::time::advance(TIMEOUT / 2 - TICK).await;
    assert!(
        run_for(&mut request, QUIET).await.is_none(),
        "the request finished while the first address still had time"
    );
    tokio::time::advance(2 * TICK).await;
    let error = run_for(&mut request, PATIENCE)
        .await
        .expect("an address that never answers held the request past its share of the timeout")
        .expect_err("no address serves");
    // The connect failed at every address, so no byte of the request was
    // written: the dispatcher may send it to a peer, retry-safe or not.
    assert!(error.is_retryable(), "{error:?}");
    assert!(error.is_not_sent(), "{error:?}");
    assert!(
        started.elapsed() <= TIMEOUT / 2 + TICK,
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test(start_paused = true)]
async fn addresses_that_never_answer_hold_the_request_until_its_timeout_and_no_longer() {
    let (first, second) = (Unanswered::new(), Unanswered::new());
    let provider = provider(&[first.address, second.address]);
    let (context, units) = (context(), [unit()]);
    let started = tokio::time::Instant::now();
    let mut request = provider.encrypt_batch(&context, &units);
    start(&mut request).await;

    // The second address is dialed when the first one's share runs out, and
    // its own share would end after the request's timeout.
    for step in [TIMEOUT / 2 + TICK, TIMEOUT - TICK] {
        tokio::time::advance(step - started.elapsed()).await;
        assert!(
            run_for(&mut request, QUIET).await.is_none(),
            "the request ended at {:?}, before its timeout",
            started.elapsed()
        );
    }
    tokio::time::advance(2 * TICK).await;
    let error = run_for(&mut request, PATIENCE)
        .await
        .expect("the request outlived its timeout")
        .expect_err("no address answers");
    assert!(error.is_retryable(), "{error:?}");
    assert!(
        started.elapsed() <= TIMEOUT + TICK,
        "{:?}",
        started.elapsed()
    );
}
