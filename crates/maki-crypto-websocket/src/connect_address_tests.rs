//! The connect resolves the URL's host and dials its addresses itself. An
//! address that never answers (a route that drops packets) must not spend
//! the whole connect deadline: the next address still gets time. Most tests
//! replace the dialer, so a name can resolve to addresses that never answer
//! or refuse at once beside a real loopback listener; the TEST-NET addresses
//! below are never dialed for real. One test keeps the system resolver.
//! When the host has addresses of both families, the other family's
//! attempts start 300 ms after the first one, as the gRPC transport's
//! connector does, and the attempt that loses is dropped.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::*;

const HOST: &str = "provider.test";
const PORT: u16 = 7000;
const TIMEOUT: Duration = Duration::from_secs(10);
const TICK: Duration = Duration::from_millis(1);
/// When the other address family's attempts start, after the first attempt.
const OTHER_FAMILY_AFTER: Duration = Duration::from_millis(300);

/// What a test address does when it is dialed.
#[derive(Clone, Copy, Debug)]
enum Answer {
    /// The connect stays pending: nothing answers.
    Never,
    /// The connect is refused at once.
    Refuse,
    /// The connect reaches this loopback listener.
    Serve(SocketAddr),
    /// The connect reaches this loopback listener after this long.
    After(Duration, SocketAddr),
}

enum Resolution {
    Addresses(Vec<(SocketAddr, Answer)>),
    Never,
}

struct TestDialer {
    resolution: Resolution,
    asked: parking_lot::Mutex<Vec<(String, u16)>>,
    dialed: parking_lot::Mutex<Vec<(SocketAddr, tokio::time::Instant)>>,
    /// Attempts dropped before they finished.
    cancelled: Arc<parking_lot::Mutex<Vec<SocketAddr>>>,
}

/// Records its attempt as cancelled when dropped before it finished.
struct Attempt {
    address: SocketAddr,
    finished: bool,
    cancelled: Arc<parking_lot::Mutex<Vec<SocketAddr>>>,
}

impl Drop for Attempt {
    fn drop(&mut self) {
        if !self.finished {
            self.cancelled.lock().push(self.address);
        }
    }
}

impl TestDialer {
    fn new(resolution: Resolution) -> Arc<Self> {
        Arc::new(Self {
            resolution,
            asked: Default::default(),
            dialed: Default::default(),
            cancelled: Default::default(),
        })
    }

    fn cancelled(&self) -> Vec<SocketAddr> {
        self.cancelled.lock().clone()
    }

    fn dialed(&self) -> Vec<SocketAddr> {
        self.dialed
            .lock()
            .iter()
            .map(|(address, _)| *address)
            .collect()
    }

    /// When each address was dialed, relative to `started`.
    fn dialed_at(&self, started: tokio::time::Instant) -> Vec<Duration> {
        self.dialed
            .lock()
            .iter()
            .map(|(_, at)| at.duration_since(started))
            .collect()
    }
}

impl Dialer for TestDialer {
    fn resolve(
        &self,
        host: &str,
        port: u16,
    ) -> BoxFuture<'static, std::io::Result<Vec<SocketAddr>>> {
        self.asked.lock().push((host.to_owned(), port));
        match &self.resolution {
            Resolution::Addresses(addresses) => {
                let addresses = addresses.iter().map(|(address, _)| *address).collect();
                Box::pin(async move { Ok(addresses) })
            }
            Resolution::Never => Box::pin(std::future::pending()),
        }
    }

    fn dial(&self, address: SocketAddr) -> BoxFuture<'static, std::io::Result<TcpStream>> {
        self.dialed
            .lock()
            .push((address, tokio::time::Instant::now()));
        let Resolution::Addresses(addresses) = &self.resolution else {
            unreachable!("nothing resolved");
        };
        let answer = addresses
            .iter()
            .find(|(candidate, _)| *candidate == address)
            .map(|(_, answer)| *answer)
            .expect("only resolved addresses are dialed");
        let attempt = Attempt {
            address,
            finished: false,
            cancelled: self.cancelled.clone(),
        };
        Box::pin(async move {
            // Move the whole guard in: assigning its field alone would
            // capture a copy of the flag and drop the guard here.
            let mut attempt = attempt;
            let result = match answer {
                Answer::Never => std::future::pending().await,
                Answer::Refuse => Err(std::io::ErrorKind::ConnectionRefused.into()),
                Answer::Serve(listener) => TcpStream::connect(listener).await,
                Answer::After(delay, listener) => {
                    tokio::time::sleep(delay).await;
                    TcpStream::connect(listener).await
                }
            };
            attempt.finished = true;
            result
        })
    }
}

fn test_net(last: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)), PORT)
}

/// An IPv6 documentation address, never dialed for real either.
fn doc_net(last: u16) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last)),
        PORT,
    )
}

fn provider(url: &str, tls: Option<WsTlsOptions>, dialer: &Arc<TestDialer>) -> WsCryptoProvider {
    let mut spec = super::decoded_response_tests::provider().spec;
    spec.url = url.to_owned();
    spec.timeout = TIMEOUT;
    spec.tls = tls;
    let mut provider = WsCryptoProvider::new_checked(spec).unwrap();
    provider.dialer = dialer.clone();
    provider
}

/// A plain WebSocket server on loopback that completes one upgrade and keeps
/// the connection open.
async fn websocket_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let _peer = tokio_tungstenite::accept_async(socket).await.unwrap();
        std::future::pending::<()>().await;
    });
    (address, server)
}

/// A WebSocket server on loopback that answers every request frame on one
/// connection with its items unchanged.
async fn echo_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut peer = tokio_tungstenite::accept_async(socket).await.unwrap();
        while let Some(Ok(message)) = peer.next().await {
            let Ok(text) = message.into_text() else {
                continue;
            };
            let request: serde_json::Value = serde_json::from_str(&text).unwrap();
            let items: Vec<_> = request["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| json!({"unit": item["unit"], "data": item["data"]}))
                .collect();
            let answer = json!({"id": request["id"], "items": items}).to_string();
            if peer.send(Message::text(answer)).await.is_err() {
                return;
            }
        }
    });
    address
}

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(1),
        format_version: 1,
        crypto_compatibility_id: "decoded-response-test".into(),
    }
}

fn unit() -> PlaintextUnit {
    PlaintextUnit {
        unit_index: 0,
        data: SecretBuffer::from_slice(&[0x5A; 16]),
    }
}

/// Drive `future` with loopback IO pending while paused time stays where the
/// test put it: a runtime that is never idle does not advance the clock.
async fn without_advancing<T>(future: impl std::future::Future<Output = T>) -> T {
    let started = std::time::Instant::now();
    tokio::pin!(future);
    loop {
        tokio::select! {
            biased;
            result = &mut future => return result,
            _ = tokio::task::yield_now() => {
                assert!(started.elapsed() < Duration::from_secs(10),
                    "the connect made no progress within 10 seconds of wall-clock time");
            }
        }
    }
}

fn is_connect_timeout(result: &Result<Connection, CryptoError>) -> bool {
    matches!(result, Err(CryptoError::Retryable(message)) if message == "websocket connect timeout")
}

#[tokio::test(start_paused = true)]
async fn a_first_address_that_never_answers_leaves_the_next_one_its_share_of_the_deadline() {
    let (listener, _server) = websocket_server().await;
    let dialer = TestDialer::new(Resolution::Addresses(vec![
        (test_net(1), Answer::Never),
        (test_net(2), Answer::Serve(listener)),
    ]));
    let provider = provider(&format!("ws://{HOST}:{PORT}/"), None, &dialer);
    let started = tokio::time::Instant::now();
    let connection = provider.connect();
    tokio::pin!(connection);

    assert!(futures_util::poll!(&mut connection).is_pending());
    assert_eq!(dialer.dialed(), [test_net(1)]);
    // One attempt at a time: the second address waits for the first one's
    // share, half of the deadline with two addresses.
    tokio::time::advance(TIMEOUT / 2 - TICK).await;
    assert!(futures_util::poll!(&mut connection).is_pending());
    assert_eq!(
        dialer.dialed(),
        [test_net(1)],
        "the second address was dialed while the first still had time"
    );
    tokio::time::advance(2 * TICK).await;
    let _ = futures_util::poll!(&mut connection);
    assert_eq!(
        dialer.dialed(),
        [test_net(1), test_net(2)],
        "an address that never answers spent more than its share of the {TIMEOUT:?} deadline"
    );
    let connection = without_advancing(connection)
        .await
        .expect("the second address serves the upgrade");
    assert!(
        started.elapsed() <= TIMEOUT / 2 + 2 * TICK,
        "connected after {:?}",
        started.elapsed()
    );
    assert_eq!(dialer.asked.lock().as_slice(), [(HOST.to_owned(), PORT)]);
    drop(connection);
}

#[tokio::test(start_paused = true)]
async fn an_address_refused_at_once_leaves_its_share_to_the_addresses_after_it() {
    let (listener, _server) = websocket_server().await;
    let dialer = TestDialer::new(Resolution::Addresses(vec![
        (test_net(1), Answer::Refuse),
        (test_net(2), Answer::Never),
        (test_net(3), Answer::Serve(listener)),
    ]));
    let provider = provider(&format!("ws://{HOST}:{PORT}/"), None, &dialer);
    let connection = provider.connect();
    tokio::pin!(connection);

    assert!(futures_util::poll!(&mut connection).is_pending());
    assert_eq!(dialer.dialed(), [test_net(1), test_net(2)]);
    // The refusal took no time, so the two addresses left share the whole
    // deadline: not a third of it each.
    tokio::time::advance(TIMEOUT / 2 - TICK).await;
    assert!(futures_util::poll!(&mut connection).is_pending());
    assert_eq!(dialer.dialed(), [test_net(1), test_net(2)]);
    tokio::time::advance(2 * TICK).await;
    let _ = futures_util::poll!(&mut connection);
    assert_eq!(dialer.dialed(), [test_net(1), test_net(2), test_net(3)]);
    without_advancing(connection)
        .await
        .expect("the third address serves the upgrade");
}

#[tokio::test(start_paused = true)]
async fn addresses_that_never_answer_fail_as_a_connect_timeout_at_the_deadline() {
    let dialer = TestDialer::new(Resolution::Addresses(vec![
        (test_net(1), Answer::Never),
        (test_net(2), Answer::Never),
        (test_net(3), Answer::Never),
    ]));
    let provider = provider(&format!("ws://{HOST}:{PORT}/"), None, &dialer);
    let started = tokio::time::Instant::now();
    let connection = provider.connect();
    tokio::pin!(connection);

    assert!(futures_util::poll!(&mut connection).is_pending());
    // Each address but the last has an equal share of what is left; the
    // last has the rest, up to the connect deadline itself.
    tokio::time::advance(TIMEOUT / 3 + TICK).await;
    assert!(futures_util::poll!(&mut connection).is_pending());
    tokio::time::advance(TIMEOUT / 3 + TICK).await;
    assert!(futures_util::poll!(&mut connection).is_pending());
    assert_eq!(
        dialer.dialed(),
        [test_net(1), test_net(2), test_net(3)],
        "every address must be dialed within the deadline"
    );
    let at = dialer.dialed_at(started);
    assert!(
        at[1] >= TIMEOUT / 3 && at[1] <= TIMEOUT / 3 + TICK,
        "{at:?}"
    );
    assert!(
        at[2] >= TIMEOUT * 2 / 3 && at[2] <= TIMEOUT * 2 / 3 + 2 * TICK,
        "{at:?}"
    );
    tokio::time::advance(TIMEOUT - started.elapsed() - TICK).await;
    assert!(futures_util::poll!(&mut connection).is_pending());
    tokio::time::advance(2 * TICK).await;
    let result = futures_util::poll!(&mut connection);
    assert!(
        matches!(&result, std::task::Poll::Ready(result) if is_connect_timeout(result)),
        "the connect must fail as a timeout at its deadline"
    );
}

#[tokio::test(start_paused = true)]
async fn a_connect_after_a_wait_for_the_connection_shares_what_the_request_has_left() {
    const WAIT: Duration = Duration::from_secs(6);
    let listener = echo_server().await;
    let dialer = TestDialer::new(Resolution::Addresses(vec![
        (test_net(1), Answer::Never),
        (test_net(2), Answer::Serve(listener)),
    ]));
    let mut provider = provider(&format!("ws://{HOST}:{PORT}/"), None, &dialer);
    // One attempt: the request has one timeout in all.
    provider.spec.capabilities.retry_safe = false;
    // Another caller holds the connection for 6 s of the request's 10 s.
    let held = provider.connection.lock().await;
    let started = tokio::time::Instant::now();
    let (context, units) = (context(), [unit()]);
    let request = provider.encrypt_batch(&context, &units);
    tokio::pin!(request);
    assert!(futures_util::poll!(&mut request).is_pending());
    tokio::time::advance(WAIT).await;
    drop(held);
    assert!(futures_util::poll!(&mut request).is_pending());
    assert_eq!(dialer.dialed(), [test_net(1)]);

    // 4 s are left for two addresses: 2 s each, not half of a fresh 10 s.
    let share = (TIMEOUT - WAIT) / 2;
    tokio::time::advance(share - TICK).await;
    assert!(futures_util::poll!(&mut request).is_pending());
    assert_eq!(dialer.dialed(), [test_net(1)]);
    tokio::time::advance(2 * TICK).await;
    let _ = futures_util::poll!(&mut request);
    assert_eq!(
        dialer.dialed(),
        [test_net(1), test_net(2)],
        "the shares must come from what the request has left, not from a full timeout"
    );
    let ciphertext = without_advancing(request)
        .await
        .expect("the second address answers within the request's timeout");
    assert_eq!(ciphertext.len(), 1);
    assert!(started.elapsed() < TIMEOUT, "{:?}", started.elapsed());
}

#[tokio::test(start_paused = true)]
async fn a_request_to_addresses_that_never_answer_fails_retryable_and_unsent_within_the_timeout() {
    let dialer = TestDialer::new(Resolution::Addresses(vec![
        (test_net(1), Answer::Never),
        (test_net(2), Answer::Never),
    ]));
    let mut provider = provider(&format!("ws://{HOST}:{PORT}/"), None, &dialer);
    // One attempt, so the call spends one timeout.
    provider.spec.capabilities.retry_safe = false;
    let started = tokio::time::Instant::now();
    let error = provider
        .encrypt_batch(&context(), &[unit()])
        .await
        .expect_err("no address answers");
    assert!(error.is_retryable(), "{error:?}");
    assert!(error.is_not_sent(), "{error:?}");
    assert!(
        started.elapsed() <= TIMEOUT + TICK,
        "{:?}",
        started.elapsed()
    );
    assert_eq!(dialer.dialed(), [test_net(1), test_net(2)]);
}

#[tokio::test(start_paused = true)]
async fn a_dead_ipv6_address_gives_way_to_ipv4_after_300_ms() {
    let (listener, _server) = websocket_server().await;
    let dialer = TestDialer::new(Resolution::Addresses(vec![
        (doc_net(1), Answer::Never),
        (test_net(2), Answer::Serve(listener)),
    ]));
    let provider = provider(&format!("ws://{HOST}:{PORT}/"), None, &dialer);
    let started = tokio::time::Instant::now();
    let connection = provider.connect();
    tokio::pin!(connection);

    assert!(futures_util::poll!(&mut connection).is_pending());
    assert_eq!(dialer.dialed(), [doc_net(1)]);
    tokio::time::advance(OTHER_FAMILY_AFTER - TICK).await;
    assert!(futures_util::poll!(&mut connection).is_pending());
    assert_eq!(dialer.dialed(), [doc_net(1)], "IPv4 started early");
    tokio::time::advance(2 * TICK).await;
    let _ = futures_util::poll!(&mut connection);
    assert_eq!(
        dialer.dialed(),
        [doc_net(1), test_net(2)],
        "the other family must start {OTHER_FAMILY_AFTER:?} after the first attempt"
    );
    let connection = without_advancing(connection)
        .await
        .expect("the IPv4 address serves the upgrade");
    assert!(
        started.elapsed() <= OTHER_FAMILY_AFTER + 2 * TICK,
        "connected after {:?}",
        started.elapsed()
    );
    assert_eq!(
        dialer.cancelled(),
        [doc_net(1)],
        "the IPv6 attempt that lost must be dropped"
    );
    drop(connection);
}

#[tokio::test(start_paused = true)]
async fn a_preferred_address_that_connects_after_the_other_family_started_drops_that_attempt() {
    let (listener, _server) = websocket_server().await;
    let dialer = TestDialer::new(Resolution::Addresses(vec![
        (
            doc_net(1),
            Answer::After(OTHER_FAMILY_AFTER + Duration::from_millis(100), listener),
        ),
        (test_net(2), Answer::Never),
    ]));
    let provider = provider(&format!("ws://{HOST}:{PORT}/"), None, &dialer);
    let connection = provider.connect();
    tokio::pin!(connection);

    assert!(futures_util::poll!(&mut connection).is_pending());
    tokio::time::advance(OTHER_FAMILY_AFTER + TICK).await;
    assert!(futures_util::poll!(&mut connection).is_pending());
    assert_eq!(dialer.dialed(), [doc_net(1), test_net(2)]);
    tokio::time::advance(Duration::from_millis(100)).await;
    let connection = without_advancing(connection)
        .await
        .expect("the IPv6 address serves the upgrade");
    assert_eq!(
        dialer.cancelled(),
        [test_net(2)],
        "the IPv4 attempt that lost must be dropped"
    );
    drop(connection);
}

#[tokio::test(start_paused = true)]
async fn a_refused_preferred_family_starts_the_other_family_at_once() {
    let (listener, _server) = websocket_server().await;
    let dialer = TestDialer::new(Resolution::Addresses(vec![
        (doc_net(1), Answer::Refuse),
        (doc_net(2), Answer::Refuse),
        (test_net(3), Answer::Serve(listener)),
    ]));
    let provider = provider(&format!("ws://{HOST}:{PORT}/"), None, &dialer);
    let started = tokio::time::Instant::now();
    let connection = provider.connect();
    tokio::pin!(connection);

    let _ = futures_util::poll!(&mut connection);
    assert_eq!(
        dialer.dialed(),
        [doc_net(1), doc_net(2), test_net(3)],
        "a family that failed outright must not hold the other one back"
    );
    without_advancing(connection)
        .await
        .expect("the IPv4 address serves the upgrade");
    assert_eq!(started.elapsed(), Duration::ZERO);
    assert!(dialer.cancelled().is_empty(), "{:?}", dialer.cancelled());
}

#[tokio::test(start_paused = true)]
async fn both_families_dead_fail_at_the_deadline_with_each_family_dialed_on_its_schedule() {
    // The resolver's order mixes the families; each keeps its own order.
    let dialer = TestDialer::new(Resolution::Addresses(vec![
        (doc_net(1), Answer::Never),
        (test_net(1), Answer::Never),
        (doc_net(2), Answer::Never),
        (test_net(2), Answer::Never),
    ]));
    let provider = provider(&format!("ws://{HOST}:{PORT}/"), None, &dialer);
    let started = tokio::time::Instant::now();
    let connection = provider.connect();
    tokio::pin!(connection);
    assert!(futures_util::poll!(&mut connection).is_pending());

    // IPv6 first: half the deadline each. IPv4 from 300 ms: half of what is
    // left then each, so its second address starts at 5.15 s.
    let schedule = [
        (Duration::ZERO, doc_net(1)),
        (OTHER_FAMILY_AFTER, test_net(1)),
        (TIMEOUT / 2, doc_net(2)),
        (
            OTHER_FAMILY_AFTER + (TIMEOUT - OTHER_FAMILY_AFTER) / 2,
            test_net(2),
        ),
    ];
    for (index, (at, address)) in schedule.iter().enumerate() {
        tokio::time::advance(*at + TICK - started.elapsed()).await;
        assert!(futures_util::poll!(&mut connection).is_pending());
        assert_eq!(
            dialer.dialed().get(index),
            Some(address),
            "dialed {:?} by {:?}",
            dialer.dialed(),
            started.elapsed()
        );
        let dialed_at = dialer.dialed_at(started)[index];
        assert!(
            dialed_at >= *at && dialed_at <= *at + 2 * TICK,
            "{address} dialed at {dialed_at:?}, due at {at:?}"
        );
    }
    assert_eq!(dialer.dialed().len(), 4);
    tokio::time::advance(TIMEOUT - started.elapsed() - TICK).await;
    assert!(futures_util::poll!(&mut connection).is_pending());
    tokio::time::advance(2 * TICK).await;
    let result = futures_util::poll!(&mut connection);
    assert!(
        matches!(&result, std::task::Poll::Ready(result) if is_connect_timeout(result)),
        "the connect must fail as a timeout at its deadline"
    );
    let mut cancelled = dialer.cancelled();
    cancelled.sort();
    let mut all = dialer.dialed();
    all.sort();
    assert_eq!(
        cancelled, all,
        "every attempt that did not finish is dropped"
    );
}

#[tokio::test(start_paused = true)]
async fn a_resolution_that_never_returns_ends_at_the_connect_deadline() {
    let dialer = TestDialer::new(Resolution::Never);
    let provider = provider(&format!("ws://{HOST}:{PORT}/"), None, &dialer);
    let started = tokio::time::Instant::now();
    let result = provider.connect().await;
    assert!(is_connect_timeout(&result));
    assert!(
        started.elapsed() <= TIMEOUT + TICK,
        "{:?}",
        started.elapsed()
    );
    assert!(dialer.dialed().is_empty());
}

#[tokio::test]
async fn the_resolver_is_asked_for_the_url_host_and_the_scheme_port() {
    for (url, host, port) in [
        ("WSS://provider.test/path?q=1", "provider.test", 443),
        ("ws://provider.test/", "provider.test", 80),
        ("ws://[::1]:8080/", "::1", 8080),
        ("ws://192.0.2.7:9443", "192.0.2.7", 9443),
    ] {
        let dialer = TestDialer::new(Resolution::Addresses(Vec::new()));
        let provider = provider(url, None, &dialer);
        let result = provider.connect().await;
        assert!(
            matches!(&result, Err(CryptoError::Retryable(message))
                if message == "websocket connection failed before upgrade completed"),
            "{url}: a name with no address is a retryable connect failure"
        );
        assert_eq!(
            dialer.asked.lock().as_slice(),
            [(host.to_owned(), port)],
            "{url}"
        );
    }
}

#[tokio::test]
async fn the_system_resolver_reaches_a_listener_by_name() {
    let v4 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = v4.local_addr().unwrap().port();
    // Serve ::1 too where the host has it, so that whichever loopback
    // address the resolver lists first answers at once.
    let v6 = tokio::net::TcpListener::bind(("::1", port)).await.ok();
    let _server = tokio::spawn(async move {
        let (socket, _) = match &v6 {
            Some(v6) => tokio::select! {
                accepted = v4.accept() => accepted,
                accepted = v6.accept() => accepted,
            },
            None => v4.accept().await,
        }
        .unwrap();
        let _peer = tokio_tungstenite::accept_async(socket).await.unwrap();
        std::future::pending::<()>().await;
    });
    let mut spec = super::decoded_response_tests::provider().spec;
    spec.url = format!("ws://localhost:{port}/");
    spec.timeout = TIMEOUT;
    let provider = WsCryptoProvider::new(spec);
    tokio::time::timeout(TIMEOUT, provider.connect())
        .await
        .expect("the connect has its own deadline")
        .expect("`localhost` resolves to a loopback address that serves");
}

mod tls {
    use super::*;

    struct Identity {
        cert_pem: Vec<u8>,
        cert_der: rustls::pki_types::CertificateDer<'static>,
        key_der: rustls::pki_types::PrivateKeyDer<'static>,
    }

    fn identity(san: &str) -> Identity {
        let certified = rcgen::generate_simple_self_signed(vec![san.into()]).unwrap();
        Identity {
            cert_pem: certified.cert.pem().into_bytes(),
            cert_der: certified.cert.der().clone(),
            key_der: rustls::pki_types::PrivatePkcs8KeyDer::from(
                certified.key_pair.serialize_der(),
            )
            .into(),
        }
    }

    /// A WSS server on loopback that reports the server name the client
    /// asked for, whether or not the handshake then completes.
    async fn wss_server(identity: &Identity) -> (SocketAddr, oneshot::Receiver<Option<String>>) {
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![identity.cert_der.clone()],
            identity.key_der.clone_key(),
        )
        .unwrap();
        let config = Arc::new(config);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (sni, sni_rx) = oneshot::channel();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let start =
                tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), socket)
                    .await
                    .unwrap();
            let _ = sni.send(start.client_hello().server_name().map(str::to_owned));
            if let Ok(stream) = start.into_stream(config).await {
                if let Ok(_peer) = tokio_tungstenite::accept_async(stream).await {
                    std::future::pending::<()>().await;
                }
            }
        });
        (address, sni_rx)
    }

    fn trusting(identity: &Identity) -> Option<WsTlsOptions> {
        Some(WsTlsOptions {
            ca_pem: Some(identity.cert_pem.clone()),
            ..Default::default()
        })
    }

    #[tokio::test]
    async fn the_certificate_is_verified_for_the_url_host_and_named_to_the_server() {
        let identity = identity(HOST);
        let (listener, sni) = wss_server(&identity).await;
        let dialer = TestDialer::new(Resolution::Addresses(vec![(
            test_net(1),
            Answer::Serve(listener),
        )]));
        let provider = provider(
            &format!("wss://{HOST}:{PORT}/"),
            trusting(&identity),
            &dialer,
        );
        let connection = provider
            .connect()
            .await
            .expect("a certificate for the URL's host is accepted at any address");
        assert_eq!(sni.await.unwrap().as_deref(), Some(HOST));
        drop(connection);
    }

    #[tokio::test]
    async fn a_certificate_for_the_resolved_address_alone_is_refused() {
        // The listener's own address is what the name resolves to, and all
        // the certificate names; the URL names the host.
        let identity = identity("127.0.0.1");
        let (listener, sni) = wss_server(&identity).await;
        let dialer = TestDialer::new(Resolution::Addresses(vec![(
            listener,
            Answer::Serve(listener),
        )]));
        let provider = provider(
            &format!("wss://{HOST}:{}/", listener.port()),
            trusting(&identity),
            &dialer,
        );
        let result = provider.connect().await;
        assert!(
            matches!(&result, Err(CryptoError::EndpointFatal(message))
                if message == "websocket TLS authentication or protocol failure"),
            "a certificate for the address but not the URL's host must be refused"
        );
        assert_eq!(sni.await.unwrap().as_deref(), Some(HOST));
        assert_eq!(dialer.dialed(), [listener]);
    }
}
