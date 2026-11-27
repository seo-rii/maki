//! At attach the daemon probes each endpoint of a set on its own. It used
//! to probe them one after another: three attempts each for a `retry_safe`
//! provider, each attempt a self-test whose first request to an endpoint
//! that never answers costs the transport's `timeout`, twice over WebSocket
//! (its own reconnect attempt). At the default 10 s three such WebSocket
//! endpoints listed before a healthy one held the healthy endpoint's probe
//! past `maki@.service`'s `TimeoutStartSec=180` (round-10 audit, C3). The
//! endpoints are now probed at once, so the attach waits about one probe
//! however many endpoints do not answer.
//!
//! The endpoints that never answer are loopback listeners whose accept
//! queue is full (Linux drops the SYNs), reached by their IP literal; the
//! healthy one is a WebSocket server that XORs each unit. The probe and the
//! set are built as attach builds them (`build_provider_with_endpoints`).
//! The paused-clock tests of the same probe are in-crate
//! (`src/endpoint_probe_tests.rs`); this one measures the real transport,
//! scaled to a 500 ms timeout.
#![cfg(target_os = "linux")]

use std::time::{Duration, Instant};

use maki_nbdkit::daemon::{
    build_provider_with_endpoints, create_volume_from_config_str, parse_and_validate,
};

/// The default `crypto.retry.initial_delay`.
const DELAY: Duration = Duration::from_millis(50);

struct Unanswered {
    address: std::net::SocketAddr,
    _listener: tokio::net::TcpListener,
    _queued: std::net::TcpStream,
}

fn unanswered() -> Unanswered {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = socket.listen(0).unwrap();
    let address = listener.local_addr().unwrap();
    let queued = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap();
    let probe = std::net::TcpStream::connect_timeout(&address, Duration::from_millis(200));
    assert!(
        matches!(&probe, Err(e) if e.kind() == std::io::ErrorKind::TimedOut),
        "a connect to a full accept queue must go unanswered: {probe:?}"
    );
    Unanswered {
        address,
        _listener: listener,
        _queued: queued,
    }
}

async fn websocket_endpoint() -> String {
    use base64::Engine as _;
    use futures_util::{SinkExt as _, StreamExt as _};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let Ok(socket) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                let (mut sink, mut source) = socket.split();
                let base64 = base64::engine::general_purpose::STANDARD;
                while let Some(Ok(message)) = source.next().await {
                    let Ok(text) = message.into_text() else {
                        continue;
                    };
                    let request: serde_json::Value = serde_json::from_str(&text).unwrap();
                    let items: Vec<serde_json::Value> = request["items"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|item| {
                            let data = base64.decode(item["data"].as_str().unwrap()).unwrap();
                            let data: Vec<u8> = data.iter().map(|byte| byte ^ 0x5a).collect();
                            serde_json::json!({"unit": item["unit"], "data": base64.encode(data)})
                        })
                        .collect();
                    let response = serde_json::json!({"id": request["id"], "items": items});
                    let _ = sink.send(response.to_string().into()).await;
                }
            });
        }
    });
    format!("ws://{address}")
}

fn config(root: &str, urls: &[String], timeout: &str) -> String {
    let endpoints: String = urls
        .iter()
        .enumerate()
        .map(|(index, url)| {
            format!("[[crypto.websocket.endpoint]]\nname = \"ep{index}\"\nurl = \"{url}\"\n")
        })
        .collect();
    format!(
        r#"
config_schema_version = 1
[volume]
name = "endpoint-probes"
max_virtual_size = "1MiB"
device_block_size = 512
crypto_unit_size = 512
shard_logical_size = "64KiB"
[crypto]
provider = "remote-websocket"
crypto_compatibility_id = "endpoint-probes-v1"
[crypto.capabilities]
supported_plaintext_sizes = [512]
max_ciphertext_size = 528
stateless = true
retry_safe = true
[crypto.batch]
max_items = 1
target_items = 1
max_bytes = 528
target_bytes = 528
max_wait = "0ms"
[crypto.websocket]
timeout = "{timeout}"
{endpoints}
[backing]
root = "{root}"
journal_emergency_reserve_bytes = "0B"
[cache]
mode = "off"
"#
    )
}

/// Build the provider of `unreachable` endpoints that never answer followed
/// by a healthy one, and how long the probes took.
async fn probe_time(unreachable: usize, timeout: &str) -> Duration {
    let dead: Vec<Unanswered> = (0..unreachable).map(|_| unanswered()).collect();
    let mut urls: Vec<String> = dead.iter().map(|d| format!("ws://{}", d.address)).collect();
    urls.push(websocket_endpoint().await);
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("volume");
    let raw = config(&root.to_string_lossy(), &urls, timeout);
    let cfg = parse_and_validate(&raw).unwrap();
    create_volume_from_config_str(&raw).unwrap();
    let started = Instant::now();
    let (_provider, set) = build_provider_with_endpoints(&cfg).await.unwrap();
    let elapsed = started.elapsed();
    let mut states: Vec<_> = set
        .unwrap()
        .endpoint_status()
        .into_iter()
        .map(|status| (status.name, status.validated))
        .collect();
    states.sort();
    eprintln!("{unreachable} unreachable before the healthy endpoint: {elapsed:?}; {states:?}");
    let mut expected: Vec<_> = (0..unreachable)
        .map(|index| (format!("ep{index}"), false))
        .collect();
    expected.push((format!("ep{unreachable}"), true));
    assert_eq!(states, expected);
    elapsed
}

/// One probe of a WebSocket endpoint that never answers: three attempts,
/// each two requests of `timeout`, and the two delays between them.
fn one_probe(timeout: Duration) -> Duration {
    timeout * 6 + DELAY * 2
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreachable_websocket_endpoints_are_probed_at_once() {
    let timeout = Duration::from_millis(500);
    let elapsed = probe_time(3, "500ms").await;
    // One after another this took three probes (about 9.3 s).
    assert!(
        elapsed < one_probe(timeout) * 2,
        "three unreachable WebSocket endpoints delayed the attach by {elapsed:?}, more than two \
         probes of {:?} each",
        one_probe(timeout)
    );
}

/// The same at the default `timeout` of 10 s: about a minute, where one
/// after another took about three (180.38 s in the audit).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn at_the_default_timeout_three_unreachable_endpoints_fit_the_start_deadline() {
    let elapsed = probe_time(3, "10s").await;
    assert!(
        elapsed < one_probe(Duration::from_secs(10)) * 2,
        "the probes took {elapsed:?}; maki@'s TimeoutStartSec is 180 s"
    );
}
