//! An attach whose only remote endpoint cannot serve as configured (a TLS
//! server whose certificate names another host) is refused with that
//! endpoint's failure, under the default `stall` policy too, as it is when
//! every endpoint of a set fails (`docs/configuration.md`: "the attach fails
//! when no other endpoint is reachable"). A lone endpoint used to skip the
//! reachability probe and leave the check to the engine's self-test through
//! the dispatcher, which under `stall` waits for an endpoint forever: no log
//! line, no control socket, no readiness, and nbdkit cannot stop while its
//! startup callback runs.
//!
//! A lone endpoint that is only away (it answers 503) is still waited for
//! under `stall`, as the dispatcher rides out any transient failure, but the
//! attach now says so, naming the endpoint and its failure. That holds only
//! where the dispatcher may send the request again: for a provider that is
//! not retry-safe, a failure that may have reached the endpoint is final, so
//! the attach is refused with it and the endpoint was sent the request once.
//!
//! Each attach runs on its own thread and must end within a bound, so a
//! regression fails instead of hanging.

use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use maki_nbdkit::daemon::{attach_from_config, create_volume_from_config_str, parse_and_validate};
use maki_test_support::http_chaos::{Handler, RecordedRequest, ResponseSpec, TestServer};

const BOUND: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug)]
enum Transport {
    Http,
    WebSocket,
    Grpc,
}

impl Transport {
    const ALL: [Transport; 3] = [Transport::Http, Transport::WebSocket, Transport::Grpc];

    fn section(self) -> &'static str {
        match self {
            Transport::Http => "http",
            Transport::WebSocket => "websocket",
            Transport::Grpc => "grpc",
        }
    }

    /// The URL of the IPv4 listener `port`, by its address. On Windows
    /// `localhost` resolves to ::1 first, which the listener does not serve,
    /// and a refused connect there takes about 2 s: the WebSocket transport
    /// tries the addresses in turn under one deadline, so that alone uses up
    /// the 2 s transport timeout, and the attach would wait out a timeout
    /// rather than meet the certificate. The certificate names another host
    /// whichever name is used.
    fn tls_url(self, port: u16) -> String {
        let scheme = match self {
            Transport::WebSocket => "wss",
            _ => "https",
        };
        format!("{scheme}://127.0.0.1:{port}")
    }

    /// The failure a TLS server with another host's certificate gives.
    fn name_mismatch(self) -> &'static str {
        match self {
            Transport::Http => "endpoint fatal: TLS authentication or protocol failure",
            Transport::WebSocket => {
                "endpoint fatal: websocket TLS authentication or protocol failure"
            }
            Transport::Grpc => "endpoint fatal: grpc TLS authentication or protocol failure",
        }
    }
}

fn config(
    directory: &std::path::Path,
    transport: Transport,
    url: &str,
    ca_file: Option<&std::path::Path>,
    retry_safe: bool,
) -> String {
    let section = transport.section();
    let provider = format!("remote-{section}");
    let root = directory
        .join("volume")
        .to_string_lossy()
        .replace('\\', "/");
    let tls = ca_file
        .map(|path| {
            format!(
                "[crypto.{section}.tls]\nca_file = \"{}\"\n",
                path.to_string_lossy().replace('\\', "/")
            )
        })
        .unwrap_or_default();
    let mapping = match transport {
        Transport::Http => "[crypto.http.encrypt]\npath = \"/encrypt\"\n\
                            [crypto.http.decrypt]\npath = \"/decrypt\"\n"
            .to_string(),
        _ => String::new(),
    };
    format!(
        r#"
config_schema_version = 1
[volume]
name = "single-endpoint"
max_virtual_size = "1MiB"
device_block_size = 512
crypto_unit_size = 512
shard_logical_size = "64KiB"
[crypto]
provider = "{provider}"
crypto_compatibility_id = "single-endpoint-v1"
availability_policy = "stall"
[crypto.capabilities]
supported_plaintext_sizes = [512]
max_ciphertext_size = 512
retry_safe = {retry_safe}
stateless = true
[crypto.batch]
max_items = 1
target_items = 1
max_bytes = 512
target_bytes = 512
max_wait = "0ms"
[crypto.retry]
initial_delay = "10ms"
max_delay = "50ms"
[crypto.circuit_breaker]
open_initial = "50ms"
open_max = "200ms"
[crypto.{section}]
timeout = "2s"
[[crypto.{section}.endpoint]]
name = "only"
url = "{url}"
{tls}{mapping}
[backing]
root = "{root}"
journal_emergency_reserve_bytes = "0B"
[cache]
mode = "off"
"#
    )
}

/// Records the message of every event on the thread it is the default for,
/// and sends each line to `lines`.
struct Capture(Mutex<mpsc::Sender<String>>);

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        struct Message(String);
        impl tracing::field::Visit for Message {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{value:?}");
                }
            }
        }
        let mut message = Message(String::new());
        event.record(&mut message);
        let line = format!("{} {}", event.metadata().level(), message.0);
        let _ = self.0.lock().unwrap().send(line);
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

/// Create the volume, then attach it on a thread of its own whose events
/// go to the returned receiver. The attach writes and reads back one block.
fn start_attach(raw: String) -> (mpsc::Receiver<Result<(), String>>, mpsc::Receiver<String>) {
    let cfg = parse_and_validate(&raw).unwrap();
    create_volume_from_config_str(&raw).unwrap();
    let (done, outcome) = mpsc::channel();
    let (lines, log) = mpsc::channel();
    std::thread::spawn(move || {
        let _capture = tracing::subscriber::set_default(Capture(Mutex::new(lines)));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(async {
            let engine = attach_from_config(&cfg)
                .await
                .map_err(|error| error.to_string())?;
            let data = vec![0x37; 512];
            engine
                .write(0, &data, true)
                .await
                .map_err(|error| error.to_string())?;
            let read = engine
                .read(0, 512)
                .await
                .map_err(|error| error.to_string())?;
            assert_eq!(read, data);
            Ok(())
        });
        let _ = done.send(result);
    });
    (outcome, log)
}

fn refused(transport: Transport, raw: String) -> String {
    match start_attach(raw).0.recv_timeout(BOUND) {
        Err(_) => panic!(
            "{transport:?}: the attach with its only endpoint unusable did not end within {BOUND:?}"
        ),
        Ok(Ok(())) => panic!("{transport:?}: the attach succeeded without a usable endpoint"),
        Ok(Err(error)) => error,
    }
}

/// A TLS server whose certificate names another host. It serves every
/// connection until the process ends; returns its port, the certificate to
/// trust and a count of the handshakes it was asked for.
fn wrong_name_server() -> (u16, String, Arc<AtomicUsize>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certificate = rcgen::generate_simple_self_signed(vec!["other.invalid".into()]).unwrap();
    let pem = certificate.cert.pem();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der());
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![certificate.cert.der().clone()], key.into())
    .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handshakes = Arc::new(AtomicUsize::new(0));
    let counted = handshakes.clone();
    std::thread::spawn(move || {
        for socket in listener.incoming() {
            let Ok(mut socket) = socket else { continue };
            counted.fetch_add(1, Ordering::SeqCst);
            let config = config.clone();
            std::thread::spawn(move || {
                let _ = socket.set_read_timeout(Some(Duration::from_secs(5)));
                let mut connection = rustls::ServerConnection::new(config).unwrap();
                while connection.is_handshaking() {
                    if connection.complete_io(&mut socket).is_err() {
                        break;
                    }
                }
            });
        }
    });
    (port, pem, handshakes)
}

fn ca_file(directory: &std::path::Path, pem: &str) -> std::path::PathBuf {
    let path = directory.join("ca.pem");
    std::fs::write(&path, pem).unwrap();
    path
}

#[test]
fn an_only_endpoint_with_another_hosts_certificate_refuses_the_attach_with_the_tls_failure() {
    for transport in Transport::ALL {
        let directory = tempfile::tempdir().unwrap();
        let (port, pem, handshakes) = wrong_name_server();
        let ca = ca_file(directory.path(), &pem);
        let error = refused(
            transport,
            config(
                directory.path(),
                transport,
                &transport.tls_url(port),
                Some(&ca),
                true,
            ),
        );
        assert!(
            error.contains("no remote endpoint is reachable; attach refused")
                && error.contains(&format!("\"only\": {}", transport.name_mismatch())),
            "{transport:?}: {error}"
        );
        // The probe is bounded: three attempts for a retry-safe provider.
        assert_eq!(handshakes.load(Ordering::SeqCst), 3, "{transport:?}");
    }
}

#[test]
fn an_only_endpoint_of_a_provider_that_is_not_retry_safe_is_probed_once() {
    for transport in Transport::ALL {
        let directory = tempfile::tempdir().unwrap();
        let (port, pem, handshakes) = wrong_name_server();
        let ca = ca_file(directory.path(), &pem);
        let error = refused(
            transport,
            config(
                directory.path(),
                transport,
                &transport.tls_url(port),
                Some(&ca),
                false,
            ),
        );
        assert!(
            error.contains(&format!("\"only\": {}", transport.name_mismatch())),
            "{transport:?}: {error}"
        );
        assert_eq!(handshakes.load(Ordering::SeqCst), 1, "{transport:?}");
    }
}

#[test]
fn an_only_endpoint_that_is_away_is_named_and_waited_for_under_stall() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let server = runtime.block_on(TestServer::start(Arc::new(|_| ResponseSpec::status(503))));
    let directory = tempfile::tempdir().unwrap();
    let (outcome, log) = start_attach(config(
        directory.path(),
        Transport::Http,
        &server.url(),
        None,
        true,
    ));
    let expected = "endpoint \"only\" unreachable at attach (retryable: HTTP 503); it is the \
                    only endpoint, so the attach keeps retrying it under the `stall` \
                    availability policy";
    let deadline = Instant::now() + BOUND;
    let mut seen = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match log.recv_timeout(left) {
            Ok(line) if line == format!("WARN {expected}") => break,
            Ok(line) => seen.push(line),
            Err(_) => panic!("the attach never said why it waits; its log: {seen:#?}"),
        }
    }
    assert!(
        outcome.try_recv().is_err(),
        "a lone endpoint that is away refused the attach under stall"
    );
    server.set_handler(Arc::new(|request| {
        ResponseSpec::raw(request.body.iter().map(|byte| byte ^ 0x5a).collect())
    }));
    match outcome.recv_timeout(BOUND) {
        Ok(Ok(())) => {}
        other => panic!("the attach did not complete once the endpoint served: {other:?}"),
    }
    drop(server);
    drop(runtime);
}

#[test]
fn an_only_endpoint_that_serves_still_attaches_under_stall() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let server = runtime.block_on(TestServer::start(Arc::new(|request| {
        ResponseSpec::raw(request.body.iter().map(|byte| byte ^ 0x5a).collect())
    })));
    let directory = tempfile::tempdir().unwrap();
    let (outcome, _log) = start_attach(config(
        directory.path(),
        Transport::Http,
        &server.url(),
        None,
        true,
    ));
    match outcome.recv_timeout(BOUND) {
        Ok(Ok(())) => {}
        other => panic!("a serving endpoint must attach: {other:?}"),
    }
    drop(server);
    drop(runtime);
}

fn xor(request: &RecordedRequest) -> ResponseSpec {
    ResponseSpec::raw(request.body.iter().map(|byte| byte ^ 0x5a).collect())
}

/// Attach a volume whose lone HTTP endpoint is served by `handler`, and
/// return the attach's outcome, the requests the endpoint received and the
/// attach's log.
fn attach_against(
    handler: Handler,
    retry_safe: bool,
) -> (Result<(), String>, Vec<RecordedRequest>, Vec<String>) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let server = runtime.block_on(TestServer::start(handler));
    let directory = tempfile::tempdir().unwrap();
    let (outcome, log) = start_attach(config(
        directory.path(),
        Transport::Http,
        &server.url(),
        None,
        retry_safe,
    ));
    let result = outcome
        .recv_timeout(BOUND)
        .unwrap_or_else(|_| panic!("the attach did not end within {BOUND:?}"));
    let requests = server.requests.lock().clone();
    (result, requests, log.try_iter().collect())
}

#[test]
fn a_non_retry_safe_lone_endpoint_is_sent_an_uncertain_request_once() {
    let lose_all: Handler = Arc::new(|request| {
        let mut response = xor(request);
        response.drop_after = Some(0);
        response
    });
    let lose_canary: Handler = Arc::new(|request| {
        let mut response = xor(request);
        if request.body.starts_with(b"MAKI-KEY-CANARY-V1") {
            response.drop_after = Some(0);
        }
        response
    });
    let unavailable: Handler = Arc::new(|_| ResponseSpec::status(503));
    for (case, handler, failure) in [
        ("503", unavailable, "\"only\": retryable: HTTP 503"),
        ("lost responses", lose_all, "\"only\": retryable:"),
        ("lost canary response", lose_canary, "\"only\": retryable:"),
    ] {
        let (result, requests, log) = attach_against(handler, false);
        // The request that may have reached the endpoint was not sent again.
        let last = requests.last().expect("the probe reached the endpoint");
        let repeats = requests
            .iter()
            .filter(|request| request.body == last.body)
            .count();
        assert_eq!(repeats, 1, "{case}: {} requests", requests.len());
        let error = result.expect_err(case);
        assert!(
            error.contains("no remote endpoint is reachable; attach refused")
                && error.contains(failure),
            "{case}: {error}"
        );
        assert!(
            !log.iter().any(|line| line.contains("keeps retrying")),
            "{case}: the attach said it waits for a request it may not send again: {log:#?}"
        );
    }
}

/// An endpoint failure in any probe attempt shows the endpoint cannot serve
/// as configured, even when a later attempt only failed transiently.
#[test]
fn an_endpoint_failure_in_any_probe_attempt_refuses_the_attach() {
    let first = Arc::new(AtomicBool::new(true));
    let handler: Handler = Arc::new(move |_| {
        if first.swap(false, Ordering::SeqCst) {
            ResponseSpec::status(401)
        } else {
            ResponseSpec::status(503)
        }
    });
    let (result, requests, _log) = attach_against(handler, true);
    let error = result.expect_err("an endpoint that answered 401 was waited for");
    assert!(
        error.contains(
            "no remote endpoint is reachable; attach refused (\"only\": endpoint fatal: HTTP 401)"
        ),
        "{error}"
    );
    assert_eq!(requests.len(), 3, "the probe makes three attempts");
}

/// A WebSocket endpoint whose upgrade is refused with 503 while `refuse` is
/// set, and that otherwise answers each request with its items XORed.
#[allow(clippy::result_large_err)] // tungstenite fixes the handshake callback's error type
async fn websocket_server(refuse: Arc<AtomicBool>) -> String {
    use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let refuse = refuse.clone();
            tokio::spawn(async move {
                let upgrade = |_: &Request, response: Response| {
                    if refuse.load(Ordering::SeqCst) {
                        let mut refusal = ErrorResponse::new(None);
                        *refusal.status_mut() =
                            tokio_tungstenite::tungstenite::http::StatusCode::SERVICE_UNAVAILABLE;
                        Err(refusal)
                    } else {
                        Ok(response)
                    }
                };
                let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(socket, upgrade).await else {
                    return;
                };
                while let Some(Ok(message)) = ws.next().await {
                    let Ok(text) = message.into_text() else {
                        continue;
                    };
                    let request: serde_json::Value = serde_json::from_str(&text).unwrap();
                    let items: Vec<_> = request["items"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|item| {
                            let data = base64::engine::general_purpose::STANDARD
                                .decode(item["data"].as_str().unwrap())
                                .unwrap();
                            let data: Vec<u8> = data.iter().map(|byte| byte ^ 0x5a).collect();
                            serde_json::json!({
                                "unit": item["unit"],
                                "data": base64::engine::general_purpose::STANDARD.encode(data),
                            })
                        })
                        .collect();
                    let reply = serde_json::json!({"id": request["id"], "items": items});
                    if ws.send(reply.to_string().into()).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    url
}

/// A failure the transport proves happened before any request byte left
/// (here a refused WebSocket upgrade) may be retried for any provider, so
/// a lone endpoint of a provider that is not retry-safe is waited for too.
#[test]
fn a_non_retry_safe_lone_endpoint_whose_failure_was_not_sent_is_waited_for() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let refuse = Arc::new(AtomicBool::new(true));
    let url = runtime.block_on(websocket_server(refuse.clone()));
    let directory = tempfile::tempdir().unwrap();
    let (outcome, log) = start_attach(config(
        directory.path(),
        Transport::WebSocket,
        &url,
        None,
        false,
    ));
    let expected = "WARN endpoint \"only\" unreachable at attach (retryable: websocket upgrade \
                    HTTP 503); it is the only endpoint, so the attach keeps retrying it under \
                    the `stall` availability policy";
    let deadline = Instant::now() + BOUND;
    let mut seen = Vec::new();
    loop {
        match log.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(line) if line == expected => break,
            Ok(line) => seen.push(line),
            Err(_) => panic!("the attach never said why it waits; its log: {seen:#?}"),
        }
    }
    refuse.store(false, Ordering::SeqCst);
    match outcome.recv_timeout(BOUND) {
        Ok(Ok(())) => {}
        other => panic!("the attach did not complete once the endpoint served: {other:?}"),
    }
    drop(runtime);
}
