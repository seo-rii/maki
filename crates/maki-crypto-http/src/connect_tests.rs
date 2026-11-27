//! The connect gives each resolved address of a family a share of the
//! request's `timeout`, so an address that never answers (a route that drops
//! packets) does not hold the request until its timeout while the next
//! address would have served it. The endpoint's name resolves, through
//! reqwest's override, to the test's loopback addresses. One that never
//! answers is a listener whose accept queue is full: Linux drops the SYNs
//! sent to it, so the connect stays pending. Time is paused and moved by
//! hand; loopback I/O runs while a test polls without letting it advance.
//!
//! What ends at the request's `timeout` and no sooner: a host with one
//! address, a resolution that never returns, a TLS peer that never answers
//! the handshake. Each ends as a request timeout, not marked unsent: the
//! request's timer starts first, and reqwest's bound over the whole connect
//! (resolution and TLS included), set to the same `timeout`, ends with it.
//!
//! The other address family starts 300 ms after the first (hyper-util's
//! fixed delay, which reqwest 0.12 does not expose), so with a `timeout` of
//! 300 ms or less it is never dialed while the first family's address does
//! not answer. Those tests need the IPv6 loopback address; without it they
//! say so and pass, unless `MAKI_TEST_REQUIRE_IPV6=1` (set in CI), which
//! makes a host without it a failure.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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
    TlsSpec,
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
        Self::at(Ipv4Addr::LOCALHOST.into())
    }

    /// An address that never answers on `ip`, a loopback address.
    fn at(ip: IpAddr) -> Self {
        let socket = match ip {
            IpAddr::V4(_) => tokio::net::TcpSocket::new_v4(),
            IpAddr::V6(_) => tokio::net::TcpSocket::new_v6(),
        }
        .unwrap();
        socket.bind(SocketAddr::new(ip, 0)).unwrap();
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
    provider_with(TIMEOUT, "http", None, |client| {
        client.resolve_to_addrs(HOST, addresses)
    })
}

/// A raw single-item provider for `scheme://HOST` with `timeout` and `tls`,
/// its client builder passed through `adjust`.
fn provider_with(
    timeout: Duration,
    scheme: &str,
    tls: Option<TlsSpec>,
    adjust: impl FnOnce(reqwest::ClientBuilder) -> reqwest::ClientBuilder,
) -> HttpCryptoProvider {
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
        base_url: format!("{scheme}://{HOST}"),
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
        timeout,
        max_response_bytes: 4096,
        tls,
    };
    HttpCryptoProvider::with_client(spec, adjust).unwrap()
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
    the_next_address_serves_after_the_first_ones_share(dead.address).await;
}

/// `dead`, an IPv4 address that never answers, comes first: the second,
/// a live endpoint, is dialed when `dead`'s share runs out and serves.
async fn the_next_address_serves_after_the_first_ones_share(dead: SocketAddr) {
    let endpoint = Endpoint::start().await;
    let provider = provider(&[dead, endpoint.address]);
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
    // A share that ran out is a connect timeout, not the request's.
    assert!(
        error
            .to_string()
            .starts_with("retryable: connect timeout: "),
        "{error}"
    );
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
        error
            .to_string()
            .starts_with("retryable: request timeout: "),
        "{error}"
    );
    assert!(
        started.elapsed() <= TIMEOUT + TICK,
        "{:?}",
        started.elapsed()
    );
}

/// A resolver whose answer never comes.
struct Unresolved;

impl reqwest::dns::Resolve for Unresolved {
    fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(std::future::pending())
    }
}

/// A loopback listener that accepts every connection, reads what it is sent
/// and never sends a byte, so a TLS handshake with it never completes.
struct Silent {
    address: SocketAddr,
    received: Arc<parking_lot::Mutex<Vec<u8>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Silent {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Silent {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let received = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let record = received.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let record = record.clone();
                tokio::spawn(async move {
                    let mut buffer = [0u8; 1024];
                    while let Ok(length @ 1..) = socket.read(&mut buffer).await {
                        record.lock().extend_from_slice(&buffer[..length]);
                    }
                    // Hold the connection open, sending nothing.
                    std::future::pending::<()>().await;
                });
            }
        });
        Self {
            address,
            received,
            task,
        }
    }
}

/// Poll `request`, which must stay pending, with loopback I/O running and
/// paused time where the test put it, until `done` holds.
async fn pending_until(request: &mut Encrypting<'_>, done: impl Fn() -> bool) {
    let started = std::time::Instant::now();
    while !done() {
        assert!(
            futures_util::poll!(&mut *request).is_pending(),
            "the request finished early"
        );
        assert!(
            started.elapsed() < PATIENCE,
            "what the test waits for did not happen"
        );
        tokio::task::yield_now().await;
    }
}

/// `request`, started at `started`, is still pending just before `timeout`
/// and then fails as a request timeout, retryable and not marked unsent.
async fn ends_as_a_request_timeout_at(
    request: &mut Encrypting<'_>,
    started: tokio::time::Instant,
    timeout: Duration,
) {
    tokio::time::advance(timeout - TICK - started.elapsed()).await;
    assert!(
        run_for(request, QUIET).await.is_none(),
        "the request ended at {:?}, before its timeout",
        started.elapsed()
    );
    tokio::time::advance(2 * TICK).await;
    let error = run_for(request, PATIENCE)
        .await
        .expect("the request outlived its timeout")
        .expect_err("nothing serves the request");
    assert!(error.is_retryable(), "{error:?}");
    assert!(!error.is_not_sent(), "{error:?}");
    assert!(
        error
            .to_string()
            .starts_with("retryable: request timeout: "),
        "{error}"
    );
    assert!(
        started.elapsed() <= timeout + TICK,
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test(start_paused = true)]
async fn a_host_with_one_address_keeps_the_whole_timeout() {
    let dead = Unanswered::new();
    let provider = provider(&[dead.address]);
    let (context, units) = (context(), [unit()]);
    let started = tokio::time::Instant::now();
    let mut request = provider.encrypt_batch(&context, &units);
    start(&mut request).await;

    // The address's share is the whole timeout: a connect given up sooner
    // would fail the request then, as a connect timeout.
    ends_as_a_request_timeout_at(&mut request, started, TIMEOUT).await;
}

#[tokio::test(start_paused = true)]
async fn a_resolution_that_never_returns_ends_at_the_request_timeout() {
    let provider = provider_with(TIMEOUT, "http", None, |client| {
        client.dns_resolver(Arc::new(Unresolved))
    });
    let (context, units) = (context(), [unit()]);
    let started = tokio::time::Instant::now();
    let mut request = provider.encrypt_batch(&context, &units);
    start(&mut request).await;

    ends_as_a_request_timeout_at(&mut request, started, TIMEOUT).await;
}

#[tokio::test(start_paused = true)]
async fn a_tls_peer_that_never_answers_ends_at_the_request_timeout_unmarked() {
    let silent = Silent::start().await;
    let address = silent.address;
    let provider = provider_with(TIMEOUT, "https", Some(TlsSpec::default()), |client| {
        client.resolve_to_addrs(HOST, &[address])
    });
    let (context, units) = (context(), [unit()]);
    let started = tokio::time::Instant::now();
    let mut request = provider.encrypt_batch(&context, &units);

    // The connection is made and the client's first handshake record (a
    // ClientHello) has arrived: what is left pending is the handshake.
    pending_until(&mut request, || {
        silent.received.lock().first() == Some(&0x16)
    })
    .await;
    // A handshake that never completes sent no byte of the request, but it
    // ends with the request's own timer, which does not mark it.
    ends_as_a_request_timeout_at(&mut request, started, TIMEOUT).await;
}

/// The delay before the other address family is dialed, hyper-util's.
const OTHER_FAMILY_DELAY: Duration = Duration::from_millis(300);

/// Whether this host has the IPv6 loopback address. A test that needs it
/// says so and passes on a host without it, unless `MAKI_TEST_REQUIRE_IPV6`
/// is `1`, which makes that a failure.
fn ipv6_loopback() -> bool {
    if std::net::TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).is_ok() {
        return true;
    }
    if std::env::var("MAKI_TEST_REQUIRE_IPV6").as_deref() == Ok("1") {
        panic!("MAKI_TEST_REQUIRE_IPV6=1, but this host cannot bind the IPv6 loopback address");
    }
    eprintln!("skipped: this host cannot bind the IPv6 loopback address");
    false
}

#[tokio::test(start_paused = true)]
async fn below_600_ms_the_other_family_starts_after_300_ms_and_has_less_than_half() {
    if !ipv6_loopback() {
        return;
    }
    let timeout = Duration::from_millis(400);
    let dead = Unanswered::at(Ipv6Addr::LOCALHOST.into());
    let endpoint = Endpoint::start().await;
    let addresses = [dead.address, endpoint.address];
    let provider = provider_with(timeout, "http", None, |client| {
        client.resolve_to_addrs(HOST, &addresses)
    });
    let (context, units) = (context(), [unit()]);
    let started = tokio::time::Instant::now();
    let mut request = provider.encrypt_batch(&context, &units);
    start(&mut request).await;

    // Half the timeout has passed and IPv4 has not been dialed.
    tokio::time::advance(OTHER_FAMILY_DELAY - TICK).await;
    assert!(
        run_for(&mut request, QUIET).await.is_none(),
        "the request finished before IPv4 was dialed"
    );
    assert!(
        endpoint.accepted_at(started).is_empty(),
        "IPv4 was dialed before 300 ms"
    );
    tokio::time::advance(2 * TICK).await;
    let ciphertext = run_for(&mut request, PATIENCE)
        .await
        .expect("IPv4 was not dialed after 300 ms")
        .expect("IPv4 serves the request");
    assert_eq!(ciphertext[0].data, vec![0x42 ^ XOR; UNIT]);
    let accepted = endpoint.accepted_at(started);
    assert_eq!(accepted.len(), 1, "{accepted:?}");
    assert!(
        accepted[0] >= OTHER_FAMILY_DELAY && accepted[0] <= OTHER_FAMILY_DELAY + TICK,
        "IPv4 was dialed at {:?}",
        accepted[0]
    );
}

#[tokio::test(start_paused = true)]
async fn with_a_timeout_of_300_ms_the_other_family_is_never_dialed() {
    if !ipv6_loopback() {
        return;
    }
    let dead = Unanswered::at(Ipv6Addr::LOCALHOST.into());
    let endpoint = Endpoint::start().await;
    let addresses = [dead.address, endpoint.address];
    let provider = provider_with(OTHER_FAMILY_DELAY, "http", None, |client| {
        client.resolve_to_addrs(HOST, &addresses)
    });
    let (context, units) = (context(), [unit()]);
    let started = tokio::time::Instant::now();
    let mut request = provider.encrypt_batch(&context, &units);
    start(&mut request).await;

    // The request's timeout and the other family's delay end together, and
    // the request's comes first.
    ends_as_a_request_timeout_at(&mut request, started, OTHER_FAMILY_DELAY).await;
    // Let whatever the connector would still do run.
    assert!(run_for(&mut std::future::pending::<()>(), QUIET)
        .await
        .is_none());
    assert!(
        endpoint.accepted_at(started).is_empty(),
        "IPv4 was dialed: {:?}",
        endpoint.accepted_at(started)
    );
}

/// The loopback address that the packet filter of
/// `a_route_that_drops_packets_leaves_the_next_address_its_share` drops
/// every SYN to.
const DROPPED: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

/// A route that drops packets, rather than a full accept queue, before a
/// live address: in a private network namespace a packet filter drops every
/// SYN sent to one loopback address, so a connect to it is neither answered
/// nor refused, and the next address serves once the first one's share has
/// run out. It needs root, for the namespace and the rule: without root, or
/// where root cannot create a network namespace, it says why it skips. As
/// root it fails when neither `nft` nor `iptables` installs the rule, and
/// when a rule program reports success but the connect is refused.
#[test]
fn a_route_that_drops_packets_leaves_the_next_address_its_share() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping: a private network namespace needs root");
        return;
    }
    // The namespace is this thread's alone (and the rule program's, which it
    // starts): the other tests' sockets stay where they are.
    std::thread::spawn(|| {
        // SAFETY: unshare takes no pointers; CLONE_NEWNET moves only the
        // calling thread into a new network namespace.
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            let error = std::io::Error::last_os_error();
            eprintln!("skipping: cannot create a private network namespace here: {error}");
            return;
        }
        loopback_up();
        drop_syns_to(DROPPED);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap()
            .block_on(async {
                // Nothing listens there: without the rule the connect would
                // be refused at once, and the test would prove nothing.
                let dropped = SocketAddr::new(DROPPED.into(), 1);
                let probe = std::net::TcpStream::connect_timeout(&dropped, QUIET);
                assert!(
                    matches!(&probe, Err(error) if error.kind() == std::io::ErrorKind::TimedOut),
                    "a connect to the dropped address must go unanswered: {probe:?}"
                );
                the_next_address_serves_after_the_first_ones_share(dropped).await;
            });
    })
    .join()
    .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

/// Bring up the loopback interface of this thread's network namespace.
fn loopback_up() {
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    // SAFETY: socket takes no pointers; a nonnegative result is a new
    // descriptor that nothing else owns.
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    assert!(socket >= 0, "socket: {}", std::io::Error::last_os_error());
    // SAFETY: see above.
    let socket = unsafe { OwnedFd::from_raw_fd(socket) };
    // SAFETY: ifreq is plain data, valid when zeroed.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (slot, byte) in request.ifr_name.iter_mut().zip(b"lo") {
        *slot = *byte as libc::c_char;
    }
    // SAFETY: `request` is an ifreq that names an interface, which the
    // ioctl reads and fills.
    let read = unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFFLAGS, &mut request) };
    assert_eq!(read, 0, "SIOCGIFFLAGS: {}", std::io::Error::last_os_error());
    // SAFETY: SIOCGIFFLAGS filled the flags member of the union.
    unsafe { request.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short };
    // SAFETY: as for SIOCGIFFLAGS; the ioctl only reads `request`.
    let set = unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCSIFFLAGS, &request) };
    assert_eq!(set, 0, "SIOCSIFFLAGS: {}", std::io::Error::last_os_error());
}

/// Make this thread's network namespace drop every TCP SYN it sends to
/// `address`, with `nft`, or with `iptables` where `nft` is missing or
/// fails. Panics, with what each said, when neither installs the rule.
fn drop_syns_to(address: Ipv4Addr) {
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    let rules = format!(
        "table ip maki_test {{\n\
         \tchain output {{\n\
         \t\ttype filter hook output priority 0; policy accept;\n\
         \t\tip daddr {address} tcp flags syn drop\n\
         \t}}\n\
         }}\n"
    );
    let nft = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut nft| {
            nft.stdin.take().unwrap().write_all(rules.as_bytes())?;
            nft.wait_with_output()
        });
    let nft = match nft {
        Ok(output) if output.status.success() => return,
        Ok(output) => format!(
            "{}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(error) => error.to_string(),
    };
    let address = address.to_string();
    let arguments = [
        "-w", "-A", "OUTPUT", "-d", &address, "-p", "tcp", "--syn", "-j", "DROP",
    ];
    let iptables = match Command::new("iptables").args(arguments).output() {
        Ok(output) if output.status.success() => return,
        Ok(output) => format!(
            "{}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(error) => error.to_string(),
    };
    panic!("neither nft ({nft}) nor iptables ({iptables}) installed the rule");
}
