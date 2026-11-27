//! The TCP connector handed to tonic is hyper-util's, configured as tonic
//! configures its own: each resolved address of a family may take an equal
//! share of the RPC `timeout`, and the other family starts 300 ms after the
//! first, or at once when the first family has failed. The connection is
//! made by a payload-free background worker (`connection.rs`) that may run
//! for several timeouts, so a connect that outlives one RPC can serve the
//! next. The endpoint's name resolves, through `TestResolver`, to the
//! test's loopback addresses; one that never answers is a listener whose
//! accept queue is full, whose SYNs Linux drops. Time is paused and moved by
//! hand; loopback I/O runs while a test polls without letting it advance.
//!
//! The tests of the other family need the IPv6 loopback address; without it
//! they say so and pass, unless `MAKI_TEST_REQUIRE_IPV6=1` (set in CI), which
//! makes a host without it a failure.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tonic::codegen::{http, BoxFuture, Service};

use super::test_resolver::TestResolver;
use super::{
    CryptoBatchRequest, CryptoBatchResponse, CryptoItem, GrpcCryptoProvider, GrpcProviderSpec,
};
use maki_crypto::{
    Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    ErrorClass, PlaintextUnit, SecretBuffer,
};

const TIMEOUT: Duration = Duration::from_secs(10);
const TICK: Duration = Duration::from_millis(1);
const UNIT: usize = 16;
const XOR: u8 = 0x3c;
/// The delay before the other address family is dialed, hyper-util's.
const OTHER_FAMILY_DELAY: Duration = Duration::from_millis(300);
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

/// A gRPC service that answers every call with the XOR of its items.
#[derive(Clone)]
struct Xor;

impl tonic::server::NamedService for Xor {
    const NAME: &'static str = "crypto";
}

impl tonic::server::UnaryService<CryptoBatchRequest> for Xor {
    type Response = CryptoBatchResponse;
    type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;

    fn call(&mut self, request: tonic::Request<CryptoBatchRequest>) -> Self::Future {
        let items = request
            .into_inner()
            .items
            .into_iter()
            .map(|item| CryptoItem {
                unit_index: item.unit_index,
                data: item.data.iter().map(|byte| byte ^ XOR).collect(),
            })
            .collect();
        Box::pin(async move { Ok(tonic::Response::new(CryptoBatchResponse { items })) })
    }
}

impl<B> Service<http::Request<B>> for Xor
where
    B: tonic::codegen::Body + Send + 'static,
    B::Error: Into<tonic::codegen::StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let service = self.clone();
        Box::pin(async move {
            let codec =
                tonic::codec::ProstCodec::<CryptoBatchResponse, CryptoBatchRequest>::default();
            Ok(tonic::server::Grpc::new(codec)
                .unary(service, request)
                .await)
        })
    }
}

/// When each connection was accepted, in paused time.
type Accepted = Arc<Mutex<Vec<tokio::time::Instant>>>;

/// A listener's connections, each recorded when it is accepted.
struct Accepting {
    listener: tokio::net::TcpListener,
    accepted: Accepted,
}

impl tonic::codegen::tokio_stream::Stream for Accepting {
    type Item = std::io::Result<tokio::net::TcpStream>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.listener.poll_accept(cx) {
            Poll::Ready(Ok((stream, _))) => {
                self.accepted
                    .lock()
                    .unwrap()
                    .push(tokio::time::Instant::now());
                Poll::Ready(Some(Ok(stream)))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// A loopback gRPC endpoint serving [`Xor`].
struct Endpoint {
    address: SocketAddr,
    accepted: Accepted,
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
        let accepted = Accepted::default();
        let incoming = Accepting {
            listener,
            accepted: accepted.clone(),
        };
        let task = tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(Xor)
                .serve_with_incoming(incoming)
                .await;
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
            .unwrap()
            .iter()
            .map(|at| at.duration_since(started))
            .collect()
    }
}

/// A plaintext loopback provider whose endpoint host, `localhost`, resolves
/// to `addresses`. The URL names no port, so each address keeps its own.
fn provider(addresses: &[SocketAddr], timeout: Duration) -> GrpcCryptoProvider {
    let spec = GrpcProviderSpec {
        url: "http://localhost".into(),
        encrypt_path: "/crypto/Encrypt".into(),
        decrypt_path: "/crypto/Decrypt".into(),
        metadata: vec![],
        capabilities: CryptoCapabilities {
            provider_id: "grpc-connect".into(),
            crypto_compatibility_id: context().crypto_compatibility_id,
            supported_plaintext_sizes: vec![UNIT as u32],
            max_ciphertext_size: UNIT as u32,
            stateless: true,
            retry_safe: false,
            batch: Default::default(),
            integrity: Capability::Absent,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        },
        timeout,
        max_message_bytes: 1 << 20,
    };
    GrpcCryptoProvider::build_resolving(spec, None, TestResolver::fixed(addresses)).unwrap()
}

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x0c0e),
        format_version: 1,
        crypto_compatibility_id: "grpc-connect-v1".into(),
    }
}

fn unit() -> PlaintextUnit {
    PlaintextUnit {
        unit_index: 0,
        data: SecretBuffer::from_slice(&[0x42; UNIT]),
    }
}

type Encrypting<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<CiphertextUnit>, CryptoError>> + Send + 'a>>;

/// Poll `future` with loopback I/O running for up to `wall` of wall-clock
/// time, while paused time stays where the test put it: a runtime that is
/// never idle does not advance the clock. `None` if it has not finished.
async fn run_for<F: Future + Unpin>(future: &mut F, wall: Duration) -> Option<F::Output> {
    let started = std::time::Instant::now();
    loop {
        let polled = std::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut *future).poll(cx))).await;
        if let Poll::Ready(output) = polled {
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
        "the call finished before any address's share ran out"
    );
}

/// The call served by the endpoint, with the XOR of the unit.
fn served(result: Option<Result<Vec<CiphertextUnit>, CryptoError>>, what: &str) {
    let ciphertext = result
        .unwrap_or_else(|| panic!("{what}"))
        .expect("the live address serves the call");
    assert_eq!(ciphertext[0].data, vec![0x42 ^ XOR; UNIT]);
}

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
async fn a_dead_address_before_a_live_one_of_its_family_costs_its_share() {
    let dead = Unanswered::at(Ipv4Addr::LOCALHOST.into());
    let endpoint = Endpoint::start().await;
    let provider = provider(&[dead.address, endpoint.address], TIMEOUT);
    let (context, units) = (context(), [unit()]);
    let started = tokio::time::Instant::now();
    let mut call = provider.encrypt_batch(&context, &units);
    start(&mut call).await;

    // Two IPv4 addresses: half the timeout each, one at a time.
    tokio::time::advance(TIMEOUT / 2 - TICK).await;
    assert!(
        run_for(&mut call, QUIET).await.is_none(),
        "the call finished while the first address still had time"
    );
    assert!(
        endpoint.accepted_at(started).is_empty(),
        "the second address was dialed while the first still had time"
    );
    tokio::time::advance(2 * TICK).await;
    served(
        run_for(&mut call, PATIENCE).await,
        "an address that never answers held the call past its share of the timeout",
    );
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
async fn a_dead_ipv6_address_gives_way_to_ipv4_after_300_ms() {
    if !ipv6_loopback() {
        return;
    }
    let dead = Unanswered::at(Ipv6Addr::LOCALHOST.into());
    let endpoint = Endpoint::start().await;
    let provider = provider(&[dead.address, endpoint.address], TIMEOUT);
    let (context, units) = (context(), [unit()]);
    let started = tokio::time::Instant::now();
    let mut call = provider.encrypt_batch(&context, &units);
    start(&mut call).await;

    tokio::time::advance(OTHER_FAMILY_DELAY - TICK).await;
    assert!(
        run_for(&mut call, QUIET).await.is_none(),
        "the call finished before IPv4 was dialed"
    );
    assert!(
        endpoint.accepted_at(started).is_empty(),
        "IPv4 was dialed before 300 ms"
    );
    tokio::time::advance(2 * TICK).await;
    served(
        run_for(&mut call, PATIENCE).await,
        "IPv4 was not dialed after 300 ms",
    );
    let accepted = endpoint.accepted_at(started);
    assert_eq!(accepted.len(), 1, "{accepted:?}");
    assert!(
        accepted[0] >= OTHER_FAMILY_DELAY && accepted[0] <= OTHER_FAMILY_DELAY + TICK,
        "IPv4 was dialed at {:?}",
        accepted[0]
    );
}

#[tokio::test(start_paused = true)]
async fn with_a_short_timeout_the_other_family_is_dialed_for_the_next_call() {
    if !ipv6_loopback() {
        return;
    }
    let timeout = Duration::from_millis(200);
    let dead = Unanswered::at(Ipv6Addr::LOCALHOST.into());
    let endpoint = Endpoint::start().await;
    let provider = provider(&[dead.address, endpoint.address], timeout);
    let (context, units) = (context(), [unit()]);
    let started = tokio::time::Instant::now();
    let mut call = provider.encrypt_batch(&context, &units);
    start(&mut call).await;

    tokio::time::advance(timeout - TICK).await;
    assert!(
        run_for(&mut call, QUIET).await.is_none(),
        "the call ended before its timeout"
    );
    assert!(endpoint.accepted_at(started).is_empty());
    // The IPv6 address's share is the whole timeout, and the call ends with
    // it, before the other family's delay: IPv4 was never dialed for it.
    tokio::time::advance(2 * TICK).await;
    let error = run_for(&mut call, PATIENCE)
        .await
        .expect("the call outlived its timeout")
        .expect_err("nothing served the call in time");
    assert_eq!(error.class(), ErrorClass::Retryable, "{error:?}");
    assert!(error.is_not_sent(), "{error:?}");
    // The connection worker goes on: IPv6 has failed, so IPv4 is dialed at
    // once, and its connection serves the next call.
    let mut idle = std::future::pending::<()>();
    let wall = std::time::Instant::now();
    while endpoint.accepted_at(started).is_empty() {
        assert!(wall.elapsed() < PATIENCE, "IPv4 was never dialed");
        run_for(&mut idle, TICK).await;
    }
    let accepted = endpoint.accepted_at(started);
    assert!(
        accepted[0] >= timeout && accepted[0] <= timeout + TICK,
        "IPv4 was dialed at {:?}",
        accepted[0]
    );
    let mut next = provider.encrypt_batch(&context, &units);
    served(
        run_for(&mut next, PATIENCE).await,
        "the worker's connection did not serve the next call",
    );
    assert_eq!(endpoint.accepted_at(started).len(), 1);
}
