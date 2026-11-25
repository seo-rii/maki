//! The connect resolves the URL's host and dials its addresses itself. An
//! address that never answers (a route that drops packets) must not spend
//! the whole connect deadline: the next address still gets time. The dialer
//! is replaced here, so a name can resolve to addresses that never answer or
//! refuse at once beside a real loopback listener. The TEST-NET addresses
//! below are never dialed for real.

use std::net::{IpAddr, Ipv4Addr};

use super::*;

const HOST: &str = "provider.test";
const PORT: u16 = 7000;
const TIMEOUT: Duration = Duration::from_secs(10);
const TICK: Duration = Duration::from_millis(1);

/// What a test address does when it is dialed.
#[derive(Clone, Copy, Debug)]
enum Answer {
    /// The connect stays pending: nothing answers.
    Never,
    /// The connect is refused at once.
    Refuse,
    /// The connect reaches this loopback listener.
    Serve(SocketAddr),
}

enum Resolution {
    Addresses(Vec<(SocketAddr, Answer)>),
    Never,
}

struct TestDialer {
    resolution: Resolution,
    asked: parking_lot::Mutex<Vec<(String, u16)>>,
    dialed: parking_lot::Mutex<Vec<(SocketAddr, tokio::time::Instant)>>,
}

impl TestDialer {
    fn new(resolution: Resolution) -> Arc<Self> {
        Arc::new(Self {
            resolution,
            asked: Default::default(),
            dialed: Default::default(),
        })
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
        match answer {
            Answer::Never => Box::pin(std::future::pending()),
            Answer::Refuse => {
                Box::pin(async { Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused)) })
            }
            Answer::Serve(listener) => Box::pin(TcpStream::connect(listener)),
        }
    }
}

fn test_net(last: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)), PORT)
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
        .encrypt_batch(
            &CryptoContext {
                volume_uuid: uuid::Uuid::from_u128(1),
                format_version: 1,
                crypto_compatibility_id: "decoded-response-test".into(),
            },
            &[PlaintextUnit {
                unit_index: 0,
                data: SecretBuffer::from_slice(&[0x5A; 16]),
            }],
        )
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
