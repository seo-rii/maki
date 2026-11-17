//! A client certificate that a witness frontend's CA trusts but whose
//! allow-list does not name it (a rotation mistake, a wrong role file) is
//! the authority's own denial, and the docs promise that it is final:
//! failover does not try another frontend, a mutation is not retried and a
//! remote rollback session stops. The server decided the denial after the
//! TLS handshake and closed the connection without an answer, so the client
//! saw an EOF, a broken pipe or a reset, exactly like a dropped connection:
//! failover moved on, `transact` retried, and the session reported a witness
//! that could not be asked on every check instead of stopping.
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::ops::Range;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use maki_backing::remote_witness::{Action, Request, Role, Rpc, StateStore};
use maki_witness::failover::FailoverClient;
use maki_witness::{
    certificate_fingerprint, Client, ClientOptions, Handler, Principal, Server, ServerOptions,
    TlsFiles,
};

const IDENTITY: [u8; 16] = [7; 16];

fn save(dir: &Path, name: &str, key: &rcgen::CertifiedKey, ca: &str) -> TlsFiles {
    let tls = TlsFiles {
        ca_file: dir.join(format!("{name}.ca.pem")),
        cert_file: dir.join(format!("{name}.cert.pem")),
        key_file: dir.join(format!("{name}.key.pem")),
    };
    std::fs::write(&tls.ca_file, ca).unwrap();
    std::fs::write(&tls.cert_file, key.cert.pem()).unwrap();
    std::fs::write(&tls.key_file, key.key_pair.serialize_pem()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tls.key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    tls
}

struct Fixture {
    directory: tempfile::TempDir,
    server: TlsFiles,
    writer: TlsFiles,
    writer_fingerprint: String,
    /// Listed instead of the writer by a frontend that denies the writer.
    other_fingerprint: String,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let server = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let writer = rcgen::generate_simple_self_signed(vec!["writer".into()]).unwrap();
        let other = rcgen::generate_simple_self_signed(vec!["other".into()]).unwrap();
        // The server's CA bundle trusts both client certificates.
        let clients = format!("{}{}", writer.cert.pem(), other.cert.pem());
        Self {
            server: save(directory.path(), "server", &server, &clients),
            writer: save(directory.path(), "writer", &writer, &server.cert.pem()),
            writer_fingerprint: certificate_fingerprint(writer.cert.der()),
            other_fingerprint: certificate_fingerprint(other.cert.der()),
            directory,
        }
    }

    /// A frontend whose allow-list names only `fingerprint`, as a writer.
    fn server(&self, fingerprint: &str) -> Server {
        Server::new(ServerOptions {
            tls: self.server.clone(),
            principals: vec![Principal {
                certificate_sha256: fingerprint.to_owned(),
                role: Role::Writer,
            }],
            timeout_ms: 2000,
            max_connections: 4,
        })
        .unwrap()
    }

    fn options(&self, address: SocketAddr) -> ClientOptions {
        ClientOptions {
            address,
            server_name: "localhost".into(),
            timeout_ms: 2000,
            tls: self.writer.clone(),
        }
    }

    fn state(&self, name: &str) -> Arc<Handler> {
        maki_witness::state_handler(
            StateStore::create(&self.directory.path().join(name), IDENTITY).unwrap(),
        )
    }
}

fn counted(handler: Arc<Handler>, calls: &Arc<AtomicUsize>) -> Arc<Handler> {
    let calls = calls.clone();
    Arc::new(move |role, request| {
        calls.fetch_add(1, Ordering::SeqCst);
        handler(role, request)
    })
}

/// One frontend address whose allow-list can change between connections,
/// as across a controlled restart: the connections whose accept index is in
/// `denied` are served by a frontend that does not list the writer.
struct Service {
    address: SocketAddr,
    accepted: Arc<AtomicUsize>,
    denied: Arc<Mutex<Range<usize>>>,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Service {
    fn start(fixture: &Fixture, handler: Arc<Handler>) -> Self {
        let listing = fixture.server(&fixture.writer_fingerprint);
        let denying = fixture.server(&fixture.other_fingerprint);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let denied = Arc::new(Mutex::new(0..0));
        let stop = Arc::new(AtomicBool::new(false));
        let worker = std::thread::spawn({
            let (accepted, denied, stop) = (accepted.clone(), denied.clone(), stop.clone());
            move || {
                for socket in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let index = accepted.fetch_add(1, Ordering::SeqCst);
                    let server = if denied.lock().unwrap().contains(&index) {
                        &denying
                    } else {
                        &listing
                    };
                    let _ = server.handle_connection(socket.unwrap(), handler.as_ref());
                }
            }
        });
        Self {
            address,
            accepted,
            denied,
            stop,
            worker: Some(worker),
        }
    }

    fn deny(&self, connections: Range<usize>) {
        *self.denied.lock().unwrap() = connections;
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        self.worker.take().unwrap().join().unwrap();
    }
}

fn inspect() -> Request {
    Request {
        authorization: None,
        operation_id: *uuid::Uuid::new_v4().as_bytes(),
        expected: None,
        action: Action::Inspect,
    }
}

#[test]
fn an_unlisted_certificate_is_answered_with_a_denial_not_a_dropped_connection() {
    let fixture = Fixture::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let service = Service::start(&fixture, counted(fixture.state("embedded"), &calls));
    service.deny(0..usize::MAX);
    let client = Client::new(fixture.options(service.address)).unwrap();
    for _ in 0..8 {
        let error = Rpc::call(&client, &inspect()).unwrap_err();
        assert_eq!(
            error.kind(),
            io::ErrorKind::PermissionDenied,
            "an allow-list denial looked like a transport failure: {error}"
        );
    }

    // The production accept loop answers it too, from the connection's
    // pending slot: a denied peer never needs, or takes, a worker.
    let server = Arc::new(fixture.server(&fixture.other_fingerprint));
    let workers: Vec<_> = (0..4)
        .map(|_| server.try_reserve_connection().unwrap())
        .collect();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handler = counted(fixture.state("served"), &calls);
    std::thread::spawn(move || server.serve(listener, handler));
    let client = Client::new(fixture.options(address)).unwrap();
    for _ in 0..8 {
        let error = Rpc::call(&client, &inspect()).unwrap_err();
        assert_eq!(
            error.kind(),
            io::ErrorKind::PermissionDenied,
            "an allow-list denial looked like a transport failure: {error}"
        );
    }
    drop(workers);
    assert_eq!(calls.load(Ordering::SeqCst), 0, "a denied peer was served");
}

#[test]
fn failover_stops_at_a_frontend_that_denies_the_certificate() {
    let fixture = Fixture::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let denying = Service::start(&fixture, counted(fixture.state("denying"), &calls));
    denying.deny(0..usize::MAX);
    let listing = Service::start(&fixture, counted(fixture.state("listing"), &calls));
    let client = FailoverClient::new(
        vec![
            fixture.options(denying.address),
            fixture.options(listing.address),
        ],
        IDENTITY,
        2000,
    )
    .unwrap();
    let error = client
        .call(&inspect())
        .expect_err("failover moved past a denial and another frontend answered");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
    assert_eq!(denying.accepted(), 1);
    assert_eq!(listing.accepted(), 0, "failover tried another frontend");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn a_denied_freshness_check_stops_the_remote_session() {
    use maki_backing::{Backing, RollbackBacking};
    let fixture = Fixture::new();
    let service = Service::start(&fixture, fixture.state("state"));
    let client: Arc<dyn Rpc> = Arc::new(Client::new(fixture.options(service.address)).unwrap());
    let root = tempfile::tempdir().unwrap();
    let backing = RollbackBacking::create_remote(root.path(), client, 32 * 4096).unwrap();
    backing.check_freshness().unwrap();

    // The frontend restarts with an allow-list that no longer names the
    // writer: that is a revocation, not an outage.
    service.deny(service.accepted()..usize::MAX);
    let error = backing.check_freshness().unwrap_err();
    assert_eq!(
        error.kind(),
        io::ErrorKind::PermissionDenied,
        "the denial looked like a witness that could not be asked: {error}"
    );
    // Listing the writer again does not resume the stopped session.
    service.deny(0..0);
    let error = backing
        .check_freshness()
        .expect_err("a session the witness denied continued");
    assert!(error.to_string().contains("session stopped"), "{error}");
}

#[cfg(target_os = "linux")]
#[test]
fn a_denied_commit_is_not_retried() {
    use maki_backing::{Backing, RollbackBacking};
    let fixture = Fixture::new();
    let service = Service::start(&fixture, fixture.state("state"));
    let client: Arc<dyn Rpc> = Arc::new(Client::new(fixture.options(service.address)).unwrap());
    let root = tempfile::tempdir().unwrap();
    let backing = RollbackBacking::create_remote(root.path(), client, 32 * 4096).unwrap();
    let file = backing.open("payload", true).unwrap();
    file.write_at(0, b"first").unwrap();
    let start = service.accepted();
    file.sync_data().unwrap();
    // One RPC per connection; a commit's last one is the advance.
    let per_commit = service.accepted() - start;

    file.write_at(0, b"second").unwrap();
    let start = service.accepted();
    service.deny(start + per_commit - 1..usize::MAX);
    let error = file.sync_data().unwrap_err();
    assert_eq!(
        error.kind(),
        io::ErrorKind::PermissionDenied,
        "the denied advance looked like a lost reply: {error}"
    );
    assert_eq!(
        service.accepted() - start,
        per_commit,
        "a denied advance was retried"
    );
}
