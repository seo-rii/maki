//! Real TLS endpoint failures preserve authority identity and exact operations.
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use maki_backing::remote_witness::{Action, Request, Role, Rpc, StateStore};
use maki_witness::failover::FailoverClient;
use maki_witness::{ClientOptions, Handler, Principal, Server, ServerOptions, TlsFiles};

struct Service {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Service {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        self.worker.take().unwrap().join().unwrap();
    }
}
struct Fixture {
    directory: tempfile::TempDir,
    client: TlsFiles,
    server: TlsFiles,
    fingerprint: String,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let server = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let writer = rcgen::generate_simple_self_signed(vec!["writer".into()]).unwrap();
        let save = |name: &str, key: &rcgen::CertifiedKey, ca: String| {
            let tls = TlsFiles {
                ca_file: directory.path().join(format!("{name}.ca")),
                cert_file: directory.path().join(format!("{name}.cert")),
                key_file: directory.path().join(format!("{name}.key")),
            };
            std::fs::write(&tls.ca_file, ca).unwrap();
            std::fs::write(&tls.cert_file, key.cert.pem()).unwrap();
            std::fs::write(&tls.key_file, key.key_pair.serialize_pem()).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&tls.key_file, std::fs::Permissions::from_mode(0o600))
                    .unwrap();
            }
            tls
        };
        let client = save("writer", &writer, server.cert.pem());
        let files = save("server", &server, writer.cert.pem());
        Self {
            directory,
            client,
            server: files,
            fingerprint: maki_witness::certificate_fingerprint(writer.cert.der()),
        }
    }
    fn service(&self, handler: Arc<Handler>) -> Service {
        let server = Server::new(ServerOptions {
            tls: self.server.clone(),
            principals: vec![Principal {
                certificate_sha256: self.fingerprint.clone(),
                role: Role::Writer,
            }],
            timeout_ms: 1000,
            max_connections: 8,
        })
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = std::thread::spawn(move || {
            for socket in listener.incoming() {
                if stopped.load(Ordering::SeqCst) {
                    break;
                }
                let _ = server.handle_connection(socket.unwrap(), handler.as_ref());
            }
        });
        Service {
            address,
            stop,
            worker: Some(worker),
        }
    }
    fn options(&self, address: SocketAddr) -> ClientOptions {
        ClientOptions {
            address,
            server_name: "localhost".into(),
            timeout_ms: 1000,
            tls: self.client.clone(),
        }
    }
    fn state(&self, name: &str, identity: [u8; 16]) -> Arc<Mutex<StateStore>> {
        Arc::new(Mutex::new(
            StateStore::create(&self.directory.path().join(name), identity).unwrap(),
        ))
    }
}
fn handler(store: Arc<Mutex<StateStore>>, calls: Arc<AtomicUsize>) -> Arc<Handler> {
    Arc::new(move |role, value| {
        calls.fetch_add(1, Ordering::SeqCst);
        let request: Request = serde_json::from_slice(value).map_err(io::Error::other)?;
        let record = store.lock().unwrap().handle(role, &request)?;
        serde_json::to_value(record).map_err(io::Error::other)
    })
}
fn inspect() -> Request {
    Request {
        authorization: None,
        operation_id: [9; 16],
        expected: None,
        action: Action::Inspect,
    }
}

#[test]
fn refused_frontend_connection_fails_over_to_same_authority() {
    let f = Fixture::new();
    let store = f.state("state", [1; 16]);
    let calls = Arc::new(AtomicUsize::new(0));
    let service = f.service(handler(store, calls.clone()));
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let unavailable = closed.local_addr().unwrap();
    drop(closed);
    let client = FailoverClient::new(
        vec![f.options(unavailable), f.options(service.address)],
        [1; 16],
        1000,
    )
    .unwrap();
    assert_eq!(client.call(&inspect()).unwrap().identity, [1; 16]);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn stalled_handshake_leaves_deadline_for_other_frontend() {
    let f = Fixture::new();
    let store = f.state("state", [1; 16]);
    let service = f.service(handler(store, Arc::new(AtomicUsize::new(0))));
    let stalled = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = stalled.local_addr().unwrap();
    let client = FailoverClient::new(
        vec![f.options(address), f.options(service.address)],
        [1; 16],
        300,
    )
    .unwrap();
    let before = Instant::now();
    assert_eq!(client.call(&inspect()).unwrap().identity, [1; 16]);
    assert!(before.elapsed() < Duration::from_secs(1));
}

#[test]
fn successful_frontend_is_reused_without_revisiting_stalled_tls_peer() {
    let f = Fixture::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let service = f.service(handler(f.state("state", [1; 16]), calls.clone()));
    let stalled = TcpListener::bind("127.0.0.1:0").unwrap();
    stalled.set_nonblocking(true).unwrap();
    let client = FailoverClient::new(
        vec![
            f.options(stalled.local_addr().unwrap()),
            f.options(service.address),
        ],
        [1; 16],
        300,
    )
    .unwrap();
    let mut stalled_connections = Vec::new();
    let mut elapsed_micros = Vec::new();
    for _ in 0..4 {
        let start = Instant::now();
        assert_eq!(client.call(&inspect()).unwrap().identity, [1; 16]);
        elapsed_micros.push(start.elapsed().as_micros());
        while let Ok((socket, _)) = stalled.accept() {
            // Keeping the accepted socket open models a silent TLS peer.
            stalled_connections.push(socket);
        }
    }
    eprintln!("witness failover request elapsed_us={elapsed_micros:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        4,
        "every call reads the authority anew"
    );
    assert_eq!(
        stalled_connections.len(),
        1,
        "later calls should start with the successful peer"
    );
}

#[test]
fn failed_preferred_frontend_returns_to_recovered_peer_and_updates_hint() {
    let f = Fixture::new();
    let store = f.state("state", [1; 16]);
    let left_live = Arc::new(AtomicBool::new(false));
    let right_live = Arc::new(AtomicBool::new(true));
    let left_calls = Arc::new(AtomicUsize::new(0));
    let right_calls = Arc::new(AtomicUsize::new(0));
    let health_handler = |live: Arc<AtomicBool>, calls: Arc<AtomicUsize>| -> Arc<Handler> {
        let success = handler(store.clone(), calls.clone());
        Arc::new(move |role, request| {
            if !live.load(Ordering::SeqCst) {
                calls.fetch_add(1, Ordering::SeqCst);
                return Err(io::Error::other("frontend temporarily unavailable"));
            }
            success(role, request)
        })
    };
    let left = f.service(health_handler(left_live.clone(), left_calls.clone()));
    let right = f.service(health_handler(right_live.clone(), right_calls.clone()));
    let client = FailoverClient::new(
        vec![f.options(left.address), f.options(right.address)],
        [1; 16],
        1000,
    )
    .unwrap();
    client.call(&inspect()).unwrap();
    client.call(&inspect()).unwrap();
    assert_eq!(left_calls.load(Ordering::SeqCst), 1);
    assert_eq!(right_calls.load(Ordering::SeqCst), 2);
    left_live.store(true, Ordering::SeqCst);
    right_live.store(false, Ordering::SeqCst);
    client.call(&inspect()).unwrap();
    client.call(&inspect()).unwrap();
    assert_eq!(left_calls.load(Ordering::SeqCst), 3);
    assert_eq!(right_calls.load(Ordering::SeqCst), 3);
}

#[test]
fn lost_durable_mutation_result_retries_identical_operation_on_other_frontend() {
    let f = Fixture::new();
    let store = f.state("state", [1; 16]);
    let calls = Arc::new(AtomicUsize::new(0));
    let first = f.service({
        let store = store.clone();
        Arc::new(move |role, value| {
            let request: Request = serde_json::from_slice(value).map_err(io::Error::other)?;
            store.lock().unwrap().handle(role, &request)?;
            Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "simulated lost durable result",
            ))
        })
    });
    let second = f.service(handler(store.clone(), calls.clone()));
    let client = FailoverClient::new(
        vec![f.options(first.address), f.options(second.address)],
        [1; 16],
        1000,
    )
    .unwrap();
    let before = client.call(&inspect()).unwrap();
    let request = Request {
        authorization: Some(
            maki_backing::remote_witness::SessionAuthorization::from_bytes([7; 32]),
        ),
        operation_id: [7; 16],
        expected: Some(before),
        action: Action::Claim,
    };
    let result = client.call(&request).unwrap();
    assert_eq!(result.fence, 1);
    assert_eq!(result.last_operation, [7; 16]);
    assert_eq!(
        store
            .lock()
            .unwrap()
            .handle(Role::Writer, &inspect())
            .unwrap(),
        result
    );
}

#[test]
fn a_different_authority_identity_is_terminal_and_never_retried() {
    let f = Fixture::new();
    let wrong = f.service(handler(
        f.state("wrong", [2; 16]),
        Arc::new(AtomicUsize::new(0)),
    ));
    let calls = Arc::new(AtomicUsize::new(0));
    let right = f.service(handler(f.state("right", [1; 16]), calls.clone()));
    let client = FailoverClient::new(
        vec![f.options(wrong.address), f.options(right.address)],
        [1; 16],
        1000,
    )
    .unwrap();
    assert_eq!(
        client.call(&inspect()).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn permission_and_comparison_errors_are_terminal() {
    for kind in [io::ErrorKind::PermissionDenied, io::ErrorKind::WouldBlock] {
        let f = Fixture::new();
        let denied = f.service(Arc::new(move |_, _| {
            Err(io::Error::new(kind, "terminal error"))
        }));
        let calls = Arc::new(AtomicUsize::new(0));
        let other = f.service(handler(f.state("state", [1; 16]), calls.clone()));
        let client = FailoverClient::new(
            vec![f.options(denied.address), f.options(other.address)],
            [1; 16],
            1000,
        )
        .unwrap();
        assert_eq!(client.call(&inspect()).unwrap_err().kind(), kind);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn terminal_error_on_preferred_frontend_does_not_retry_a_former_peer() {
    for kind in [
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::WouldBlock,
        io::ErrorKind::InvalidInput,
    ] {
        let f = Fixture::new();
        let public = f.state("state", [1; 16]);
        let left_calls = Arc::new(AtomicUsize::new(0));
        let left = f.service({
            let calls = left_calls.clone();
            Arc::new(move |_, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(io::Error::other("temporary transport failure"))
            })
        });
        let denied = Arc::new(AtomicBool::new(false));
        let right = f.service({
            let denied = denied.clone();
            let success = handler(public, Arc::new(AtomicUsize::new(0)));
            Arc::new(move |role, request| {
                if denied.load(Ordering::SeqCst) {
                    Err(io::Error::new(kind, "terminal error"))
                } else {
                    success(role, request)
                }
            })
        });
        let client = FailoverClient::new(
            vec![f.options(left.address), f.options(right.address)],
            [1; 16],
            1000,
        )
        .unwrap();
        client.call(&inspect()).unwrap();
        denied.store(true, Ordering::SeqCst);
        assert_eq!(client.call(&inspect()).unwrap_err().kind(), kind);
        assert_eq!(
            left_calls.load(Ordering::SeqCst),
            1,
            "a terminal outcome must not revisit the former peer"
        );
    }
}

#[test]
fn all_stalled_frontends_share_one_bounded_deadline() {
    let f = Fixture::new();
    let one = TcpListener::bind("127.0.0.1:0").unwrap();
    let two = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = FailoverClient::new(
        vec![
            f.options(one.local_addr().unwrap()),
            f.options(two.local_addr().unwrap()),
        ],
        [1; 16],
        80,
    )
    .unwrap();
    let before = Instant::now();
    assert!(client.call(&inspect()).is_err());
    assert!(before.elapsed() < Duration::from_secs(1));
}

#[test]
fn endpoint_sets_require_nonzero_identity_and_unique_bounded_addresses() {
    let f = Fixture::new();
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let option = f.options(socket.local_addr().unwrap());
    assert!(FailoverClient::new(vec![], [1; 16], 1000).is_err());
    assert!(FailoverClient::new(vec![option.clone()], [0; 16], 1000).is_err());
    assert!(FailoverClient::new(vec![option.clone(), option.clone()], [1; 16], 1000).is_err());
    assert!(FailoverClient::new(vec![option.clone(); 9], [1; 16], 1000).is_err());
    assert!(FailoverClient::new(vec![option], [1; 16], 0).is_err());
}
