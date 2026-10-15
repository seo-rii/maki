use super::*;
use std::sync::mpsc;

struct Fixture {
    _dir: tempfile::TempDir,
    server: Arc<Server>,
    client: Client,
    listener: TcpListener,
}

fn files(dir: &Path, name: &str, cert: &rcgen::CertifiedKey, ca: &str) -> TlsFiles {
    let tls = TlsFiles {
        ca_file: dir.join(format!("{name}.ca.pem")),
        cert_file: dir.join(format!("{name}.cert.pem")),
        key_file: dir.join(format!("{name}.key.pem")),
    };
    std::fs::write(&tls.ca_file, ca).unwrap();
    std::fs::write(&tls.cert_file, cert.cert.pem()).unwrap();
    std::fs::write(&tls.key_file, cert.key_pair.serialize_pem()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tls.key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    tls
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let server_cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let client_cert = rcgen::generate_simple_self_signed(vec!["alice".into()]).unwrap();
        let server_tls = files(dir.path(), "server", &server_cert, &client_cert.cert.pem());
        let client_tls = files(dir.path(), "client", &client_cert, &server_cert.cert.pem());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        Self {
            server: Arc::new(
                Server::new(ServerOptions {
                    tls: server_tls,
                    principals: vec![Principal {
                        certificate_sha256: certificate_fingerprint(client_cert.cert.der()),
                        role: Role::Writer,
                    }],
                    timeout_ms: 20_000,
                    max_connections: 1,
                })
                .unwrap(),
            ),
            client: Client::new(ClientOptions {
                address: listener.local_addr().unwrap(),
                server_name: "localhost".into(),
                timeout_ms: 20_000,
                tls: client_tls,
            })
            .unwrap(),
            listener,
            _dir: dir,
        }
    }

    fn sockets(&self) -> (TcpStream, TcpStream) {
        let client = TcpStream::connect(self.client.address).unwrap();
        let (server, _) = self.listener.accept().unwrap();
        (client, server)
    }
}

#[derive(Default)]
struct Counts {
    tasks: Arc<AtomicUsize>,
    waiters: Arc<AtomicUsize>,
    tls: Arc<AtomicUsize>,
}

fn count_live(count: &Arc<AtomicUsize>) -> ConnectionPermit {
    count.fetch_add(1, Ordering::AcqRel);
    ConnectionPermit(count.clone())
}

type ClientStream = rustls::StreamOwned<rustls::ClientConnection, DeadlineIo>;

fn authenticated_waiter(
    fixture: &Fixture,
    table: &Arc<Handshakes>,
    counts: &Counts,
    hold_teardown: Option<mpsc::Receiver<()>>,
) -> (ClientStream, std::thread::JoinHandle<io::Result<()>>) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let (client, socket) = fixture.sockets();
    let ticket = table.admit(&socket, deadline).unwrap();
    let server = fixture.server.clone();
    let tasks = counts.tasks.clone();
    let tls_count = counts.tls.clone();
    let waiters = counts.waiters.clone();
    let (ready_tx, ready_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let _task = count_live(&tasks);
        let ticket = ticket;
        let (tls, _) = server.authenticate(socket, deadline).unwrap();
        let tls_guard = count_live(&tls_count);
        let waiting = count_live(&waiters);
        ready_tx.send(()).unwrap();
        let result = server
            .reserve_until(deadline, &ticket)
            .and_then(|_permit| ticket.worker_acquired());
        drop(waiting);
        if let Some(hold) = hold_teardown {
            hold.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        drop(tls);
        drop(tls_guard);
        result
    });
    let connection = rustls::ClientConnection::new(
        fixture.client.config.clone(),
        fixture.client.server_name.clone(),
    )
    .unwrap();
    let mut client = rustls::StreamOwned::new(
        connection,
        DeadlineIo {
            socket: client,
            deadline,
        },
    );
    // Flush the client's final TLS flight; the server signals only after it
    // has authenticated and is about to wait with a real ServerStream alive.
    client.write_all(&[0]).unwrap();
    client.flush().unwrap();
    ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    (client, worker)
}

#[test]
fn evicted_authenticated_waiters_release_threads_and_tls_before_deadline() {
    let fixture = Fixture::new();
    let occupied = fixture.server.try_reserve_connection().unwrap();
    let table = Arc::new(Handshakes::new(1));
    let counts = Counts::default();
    let mut clients = Vec::new();
    let mut workers = Vec::new();
    for _ in 0..32 {
        let (client, worker) = authenticated_waiter(&fixture, &table, &counts, None);
        clients.push(client);
        workers.push(worker);
        assert!(counts.tasks.load(Ordering::Acquire) <= 5);
        assert!(counts.waiters.load(Ordering::Acquire) <= 5);
        assert!(counts.tls.load(Ordering::Acquire) <= 5);
    }
    // These are real join handles, independently of the pending table and
    // its lifetime counter. Eviction must retire tasks while workers remain
    // unavailable, rather than letting every waiter survive to its deadline.
    let stopped = Instant::now() + Duration::from_secs(2);
    while workers
        .iter()
        .filter(|worker| !worker.is_finished())
        .count()
        > 4
    {
        assert!(Instant::now() < stopped, "evicted threads remained alive");
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(counts.tasks.load(Ordering::Acquire), 4);
    assert_eq!(counts.waiters.load(Ordering::Acquire), 4);
    assert_eq!(counts.tls.load(Ordering::Acquire), 4);
    drop(occupied);
    let mut evicted = 0;
    for worker in workers {
        if let Err(error) = worker.join().unwrap() {
            assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
            evicted += 1;
        }
    }
    assert_eq!(evicted, 28);
    assert_eq!(counts.tasks.load(Ordering::Acquire), 0);
    assert_eq!(counts.waiters.load(Ordering::Acquire), 0);
    assert_eq!(counts.tls.load(Ordering::Acquire), 0);
    assert_eq!(table.state.lock().unwrap().live, 0);
}

#[test]
fn eviction_does_not_reuse_capacity_before_tls_teardown() {
    let fixture = Fixture::new();
    let occupied = fixture.server.try_reserve_connection().unwrap();
    let table = Arc::new(Handshakes::new(1));
    let counts = Counts::default();
    let mut connections = Vec::new();
    let mut releases = Vec::new();
    for _ in 0..5 {
        let (release, hold) = mpsc::channel();
        connections.push(authenticated_waiter(&fixture, &table, &counts, Some(hold)));
        releases.push(release);
    }
    let (_client, socket) = fixture.sockets();
    let error = table.admit(&socket, Instant::now() + Duration::from_millis(50));
    assert!(matches!(error, Err(e) if e.kind() == io::ErrorKind::TimedOut));
    assert_eq!(counts.tasks.load(Ordering::Acquire), 5);
    assert_eq!(counts.tls.load(Ordering::Acquire), 5);
    assert_eq!(
        connections
            .iter()
            .filter(|(_, task)| !task.is_finished())
            .count(),
        5
    );
    assert_eq!(table.state.lock().unwrap().live, 5);
    // Releasing retired tasks allows admission even though worker capacity
    // is still occupied; shutdown alone must not have done so.
    releases.remove(0).send(()).unwrap();
    let (client, retired) = connections.remove(0);
    assert_eq!(
        retired.join().unwrap().unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
    drop(client);
    let ticket = table
        .admit(&socket, Instant::now() + Duration::from_secs(2))
        .unwrap();
    drop(ticket);
    drop(occupied);
    for release in releases {
        release.send(()).unwrap();
    }
    for (_, task) in connections {
        let _ = task.join().unwrap();
    }
    assert_eq!(counts.tls.load(Ordering::Acquire), 0);
    assert_eq!(table.state.lock().unwrap().live, 0);
}

#[test]
fn failed_thread_spawn_releases_connection_and_serves_next_client() {
    let fixture = Fixture::new();
    let table = Arc::new(Handshakes::new(1));
    let server = fixture.server.clone();
    let listener = fixture.listener;
    let handshakes = table.clone();
    let handled = Arc::new(AtomicUsize::new(0));
    let calls = handled.clone();
    let handler: Arc<Handler> = Arc::new(move |_, request| {
        calls.fetch_add(1, Ordering::AcqRel);
        serde_json::from_slice(request).map_err(io::Error::other)
    });
    let (failed_tx, failed_rx) = mpsc::channel();
    let acceptor = std::thread::spawn(move || {
        let mut attempts = 0;
        let mut workers = Vec::new();
        let result =
            server.serve_incoming(listener.incoming().take(2), handler, handshakes, |task| {
                attempts += 1;
                if attempts == 1 {
                    // Builder::spawn drops the closure when OS thread
                    // creation fails. Inject that failure deterministically.
                    drop(task);
                    failed_tx.send(()).unwrap();
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, "spawn failure"));
                }
                workers.push(std::thread::spawn(task));
                Ok(())
            });
        for worker in workers {
            worker.join().unwrap();
        }
        result.unwrap();
        assert_eq!(attempts, 2);
    });
    assert!(fixture
        .client
        .call::<_, serde_json::Value>(&serde_json::json!({"first": true}))
        .is_err());
    failed_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    {
        let state = table.state.lock().unwrap();
        assert_eq!(state.live, 0);
        assert!(state.pending.is_empty());
    }
    let request = serde_json::json!({"after": "spawn failure"});
    assert_eq!(
        fixture
            .client
            .call::<_, serde_json::Value>(&request)
            .unwrap(),
        request
    );
    acceptor.join().unwrap();
    assert_eq!(handled.load(Ordering::Acquire), 1);
    assert_eq!(fixture.server.active.load(Ordering::Acquire), 0);
    assert_eq!(table.state.lock().unwrap().live, 0);
}
