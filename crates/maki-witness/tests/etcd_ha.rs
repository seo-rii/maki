//! Protocol regressions plus a real, disposable three-member quorum gate.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::sync::{mpsc, Arc};

use base64::Engine as _;
use maki_backing::remote_witness::{Action, CanonicalState, Request, Role};
use maki_witness::etcd::{EtcdEndpoint, EtcdOptions, EtcdStore};
use maki_witness::TlsFiles;
use serde_json::{json, Value};
use uuid::Uuid;

const IDENTITY: [u8; 16] = [19; 16];
const CLUSTER_ID: u64 = 42;

fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn inspect() -> Request {
    Request {
        operation_id: [1; 16],
        expected: None,
        action: Action::Inspect,
    }
}

struct Credentials {
    _dir: tempfile::TempDir,
    client: TlsFiles,
    server_files: TlsFiles,
    server: Arc<rustls::ServerConfig>,
}

fn write_identity(dir: &Path, name: &str, cert: &rcgen::CertifiedKey, ca: &str) -> TlsFiles {
    let files = TlsFiles {
        ca_file: dir.join(format!("{name}.ca.pem")),
        cert_file: dir.join(format!("{name}.cert.pem")),
        key_file: dir.join(format!("{name}.key.pem")),
    };
    std::fs::write(&files.ca_file, ca).unwrap();
    std::fs::write(&files.cert_file, cert.cert.pem()).unwrap();
    std::fs::write(&files.key_file, cert.key_pair.serialize_pem()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&files.key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    files
}

impl Credentials {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let server = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let client = rcgen::generate_simple_self_signed(vec!["witness-backend".into()]).unwrap();
        let client_files = write_identity(dir.path(), "client", &client, &server.cert.pem());
        let server_files = write_identity(dir.path(), "server", &server, &client.cert.pem());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(client.cert.der().clone()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![server.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(client_key(&server)).into(),
        )
        .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self {
            _dir: dir,
            client: client_files,
            server_files,
            server: Arc::new(config),
        }
    }

    fn options(&self, address: SocketAddr) -> EtcdOptions {
        EtcdOptions {
            endpoints: vec![EtcdEndpoint {
                address,
                server_name: "localhost".into(),
            }],
            cluster_id: CLUSTER_ID,
            storage_identity: Uuid::from_bytes(IDENTITY),
            key: "/maki/witness/test".into(),
            timeout_ms: 2000,
            tls: self.client.clone(),
        }
    }
}

fn client_key(cert: &rcgen::CertifiedKey) -> Vec<u8> {
    cert.key_pair.serialize_der()
}

/// One HTTP request per TLS connection; None commits then loses its reply.
fn gateway(
    credentials: &Credentials,
    replies: Vec<Option<Value>>,
) -> (
    SocketAddr,
    mpsc::Receiver<(String, Value)>,
    std::thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let config = credentials.server.clone();
    let (sender, requests) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        for reply in replies {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .unwrap();
            socket
                .set_write_timeout(Some(std::time::Duration::from_secs(3)))
                .unwrap();
            let conn = rustls::ServerConnection::new(config.clone()).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, socket);
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                tls.read_exact(&mut byte).unwrap();
                header.push(byte[0]);
                assert!(header.len() < 8192);
            }
            let header = String::from_utf8(header).unwrap();
            let length: usize = header
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                })
                .unwrap();
            assert!(length < 256 * 1024);
            let mut body = vec![0; length];
            tls.read_exact(&mut body).unwrap();
            sender
                .send((
                    header.lines().next().unwrap().to_owned(),
                    serde_json::from_slice(&body).unwrap(),
                ))
                .unwrap();
            if let Some(reply) = reply {
                let body = serde_json::to_vec(&reply).unwrap();
                write!(tls, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                let result = tls.write_all(&body).and_then(|()| tls.flush());
                if body.len() <= 256 * 1024 {
                    result.unwrap();
                }
            }
        }
    });
    (address, requests, worker)
}

fn range(state: &CanonicalState, revision: u64) -> Value {
    json!({
        "header": {"cluster_id": CLUSTER_ID.to_string(), "revision": revision.to_string()},
        "kvs": [{"key": encode(b"/maki/witness/test"), "value": encode(&state.encode().unwrap()), "mod_revision": revision.to_string()}],
        "count": "1"
    })
}

#[test]
fn lost_cas_reply_is_resolved_by_exact_role_bound_latest_operation() {
    let credentials = Credentials::new();
    let initial = CanonicalState::initial(IDENTITY).unwrap();
    let request = Request {
        operation_id: [2; 16],
        expected: Some(initial.record().clone()),
        action: Action::Claim,
    };
    let claimed = initial.apply(Role::Writer, &request).unwrap();
    let (address, requests, worker) = gateway(
        &credentials,
        vec![
            Some(range(&initial, 1)),
            Some(range(&initial, 1)),
            None,
            Some(range(&claimed, 2)),
        ],
    );
    let store = EtcdStore::open(credentials.options(address)).unwrap();
    assert_eq!(
        store.handle(Role::Writer, &request).unwrap(),
        *claimed.record()
    );
    worker.join().unwrap();
    let requests: Vec<_> = requests.into_iter().collect();
    assert_eq!(requests.len(), 4);
    for (path, request) in &requests {
        if path.contains("/v3/kv/range") {
            assert_eq!(request["serializable"], false);
            assert_eq!(request["key"], encode(b"/maki/witness/test"));
        }
    }
    let transaction = &requests[2].1;
    assert!(requests[2].0.contains("/v3/kv/txn"));
    assert_eq!(transaction["compare"][0]["target"], "MOD");
    assert_eq!(transaction["compare"][0]["mod_revision"], "1");
    assert_eq!(transaction["compare"][1]["target"], "VALUE");
    assert_eq!(
        transaction["compare"][1]["value"],
        encode(&initial.encode().unwrap())
    );
    assert_eq!(
        transaction["success"][0]["request_put"]["value"],
        encode(&claimed.encode().unwrap())
    );
}

#[test]
fn missing_state_and_wrong_cluster_are_never_initialized_by_open() {
    let credentials = Credentials::new();
    for reply in [
        json!({"header":{"cluster_id": "42"}, "count": "0"}),
        json!({"header":{"cluster_id": "43"}, "count": "0"}),
    ] {
        let expected = if reply["header"]["cluster_id"] == "42" {
            std::io::ErrorKind::NotFound
        } else {
            std::io::ErrorKind::InvalidData
        };
        let (address, requests, worker) = gateway(&credentials, vec![Some(reply)]);
        assert_eq!(
            EtcdStore::open(credentials.options(address))
                .err()
                .unwrap()
                .kind(),
            expected
        );
        worker.join().unwrap();
        assert!(requests.recv().unwrap().0.contains("/v3/kv/range"));
        assert!(requests.try_recv().is_err());
    }
}

#[test]
fn initialization_is_one_create_if_absent_transaction() {
    let credentials = Credentials::new();
    let (address, requests, worker) = gateway(
        &credentials,
        vec![
            Some(json!({"header":{"cluster_id":"42"},"count":"0"})),
            Some(json!({"header":{"cluster_id":"42"},"succeeded":true})),
        ],
    );
    EtcdStore::create(credentials.options(address), IDENTITY).unwrap();
    worker.join().unwrap();
    assert!(requests.recv().unwrap().0.contains("/v3/kv/range"));
    let (path, body) = requests.recv().unwrap();
    assert!(path.contains("/v3/kv/txn"));
    assert_eq!(body["compare"][0]["target"], "VERSION");
    assert_eq!(body["compare"][0]["version"], "0");
    assert!(body["success"][0]["request_put"].get("lease").is_none());
    let initial = CanonicalState::initial(IDENTITY).unwrap();
    assert_eq!(
        body["success"][0]["request_put"]["value"],
        encode(&initial.encode().unwrap())
    );
}

#[test]
fn protobuf_gateway_omits_false_succeeded_on_a_conflicting_transaction() {
    let credentials = Credentials::new();
    let initial = CanonicalState::initial(IDENTITY).unwrap();
    let request = Request {
        operation_id: [2; 16],
        expected: Some(initial.record().clone()),
        action: Action::Claim,
    };
    let mut winner = request.clone();
    winner.operation_id = [3; 16];
    let claimed = initial.apply(Role::Writer, &winner).unwrap();
    let (address, requests, worker) = gateway(
        &credentials,
        vec![
            Some(range(&initial, 1)),
            Some(range(&initial, 1)),
            Some(
                json!({"header":{"cluster_id":"42"},"responses":[{"response_range":range(&claimed, 2)}]}),
            ),
        ],
    );
    let store = EtcdStore::open(credentials.options(address)).unwrap();
    assert_eq!(
        store.handle(Role::Writer, &request).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    worker.join().unwrap();
    assert_eq!(requests.into_iter().count(), 3);
}

#[test]
fn invalid_etcd_configuration_is_rejected_before_connecting() {
    let credentials = Credentials::new();
    let address: SocketAddr = "127.0.0.1:2379".parse().unwrap();
    let base = credentials.options(address);
    let mut cases = Vec::new();
    let mut config = base.clone();
    config.cluster_id = 0;
    cases.push(config);
    let mut config = base.clone();
    config.storage_identity = Uuid::nil();
    cases.push(config);
    let mut config = base.clone();
    config.endpoints.clear();
    cases.push(config);
    let mut config = base.clone();
    config.endpoints = vec![config.endpoints[0].clone(); 9];
    cases.push(config);
    let mut config = base.clone();
    config.endpoints.push(config.endpoints[0].clone());
    cases.push(config);
    let mut config = base.clone();
    config.endpoints[0].address.set_port(0);
    cases.push(config);
    let mut config = base.clone();
    config.endpoints[0].server_name.clear();
    cases.push(config);
    let mut config = base.clone();
    config.endpoints[0].server_name = "localhost/evil".into();
    cases.push(config);
    let mut config = base.clone();
    config.endpoints[0].server_name = "203.0.113.1".into();
    cases.push(config);
    let mut config = base.clone();
    config.timeout_ms = 0;
    cases.push(config);
    let mut config = base.clone();
    config.timeout_ms = 60_001;
    cases.push(config);
    let mut config = base.clone();
    config.key = "/maki/witness/../other".into();
    cases.push(config);
    let mut config = base;
    config.key = format!("/maki/witness/{}", "x".repeat(1024));
    cases.push(config);
    for config in cases {
        assert_eq!(
            EtcdStore::open(config).err().unwrap().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }
}

#[test]
fn cluster_identity_config_supports_all_unsigned_etcd_ids_as_decimal_strings() {
    let credentials = Credentials::new();
    let mut value =
        serde_json::to_value(credentials.options("127.0.0.1:2379".parse().unwrap())).unwrap();
    value["cluster_id"] = json!(u64::MAX.to_string());
    let parsed: EtcdOptions = serde_json::from_value(value).unwrap();
    assert_eq!(parsed.cluster_id, u64::MAX);
    assert_eq!(
        serde_json::to_value(parsed).unwrap()["cluster_id"],
        u64::MAX.to_string()
    );
}

#[test]
fn certificate_authentication_failure_does_not_try_another_backend() {
    let credentials = Credentials::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let bad_address = listener.local_addr().unwrap();
    let config = credentials.server.clone();
    let worker = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        let mut connection = rustls::ServerConnection::new(config).unwrap();
        assert!(connection.complete_io(&mut socket).is_err());
    });
    let untouched = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut options = credentials.options(bad_address);
    options.timeout_ms = 300;
    options.endpoints[0].server_name = "wrong.invalid".into();
    options.endpoints.push(EtcdEndpoint {
        address: untouched.local_addr().unwrap(),
        server_name: "localhost".into(),
    });
    assert_eq!(
        EtcdStore::open(options).err().unwrap().kind(),
        std::io::ErrorKind::InvalidData
    );
    worker.join().unwrap();
    untouched.set_nonblocking(true).unwrap();
    assert_eq!(
        untouched.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn leased_corrupt_oversized_or_wrong_identity_state_is_never_authority() {
    let credentials = Credentials::new();
    let state = CanonicalState::initial(IDENTITY).unwrap();
    let base = range(&state, 1);
    let mut replies = Vec::new();
    let mut reply = base.clone();
    reply["kvs"][0]["lease"] = json!("7");
    replies.push(reply);
    let mut reply = base.clone();
    reply["kvs"][0]["key"] = json!(encode(b"/maki/witness/other"));
    replies.push(reply);
    let mut reply = base.clone();
    reply["kvs"][0]["mod_revision"] = json!("0");
    replies.push(reply);
    let mut reply = base.clone();
    reply["kvs"][0]["mod_revision"] = json!("18446744073709551615");
    replies.push(reply);
    let mut reply = base.clone();
    reply["header"]["cluster_id"] = json!("042");
    replies.push(reply);
    let mut reply = base.clone();
    reply["kvs"][0]["value"] = json!("a".repeat(90_000));
    replies.push(reply);
    let mut damaged = state.encode().unwrap();
    damaged[9] ^= 1;
    let mut reply = base.clone();
    reply["kvs"][0]["value"] = json!(encode(&damaged));
    replies.push(reply);
    let wrong = CanonicalState::initial([20; 16]).unwrap();
    let mut reply = base.clone();
    reply["kvs"][0]["value"] = json!(encode(&wrong.encode().unwrap()));
    replies.push(reply);
    let mut reply = base;
    reply["more"] = json!(true);
    replies.push(reply);
    for reply in replies {
        let (address, requests, worker) = gateway(&credentials, vec![Some(reply)]);
        assert_eq!(
            EtcdStore::open(credentials.options(address))
                .err()
                .unwrap()
                .kind(),
            std::io::ErrorKind::InvalidData
        );
        worker.join().unwrap();
        assert_eq!(requests.into_iter().count(), 1);
    }
}

#[test]
fn json_response_body_limit_is_enforced_before_large_body_allocation() {
    let credentials = Credentials::new();
    let mut oversized = range(&CanonicalState::initial(IDENTITY).unwrap(), 1);
    oversized["extra"] = json!("x".repeat(270_000));
    let (address, requests, worker) = gateway(&credentials, vec![Some(oversized)]);
    assert_eq!(
        EtcdStore::open(credentials.options(address))
            .err()
            .unwrap()
            .kind(),
        std::io::ErrorKind::InvalidData
    );
    worker.join().unwrap();
    assert_eq!(requests.into_iter().count(), 1);
}

#[cfg(unix)]
mod quorum {
    use super::*;
    use maki_backing::remote_witness::{namespace, Descriptor, Phase};
    use maki_backing::witness::Anchor;
    use std::net::TcpStream;
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    struct PeerProxy {
        address: SocketAddr,
        blocked: Arc<AtomicBool>,
        stop: Arc<AtomicBool>,
        sockets: Arc<Mutex<Vec<TcpStream>>>,
        worker: Option<std::thread::JoinHandle<()>>,
    }

    impl PeerProxy {
        fn new(target: SocketAddr) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let blocked = Arc::new(AtomicBool::new(false));
            let stop = Arc::new(AtomicBool::new(false));
            let sockets = Arc::new(Mutex::new(Vec::new()));
            let proxy_blocked = blocked.clone();
            let proxy_stop = stop.clone();
            let proxy_sockets = sockets.clone();
            let worker = std::thread::spawn(move || {
                let mut forwards = Vec::new();
                while let Ok((incoming, _)) = listener.accept() {
                    if proxy_stop.load(Ordering::SeqCst) {
                        break;
                    }
                    if proxy_blocked.load(Ordering::SeqCst) {
                        continue;
                    }
                    let Ok(outgoing) =
                        TcpStream::connect_timeout(&target, Duration::from_millis(200))
                    else {
                        continue;
                    };
                    // Synchronize cut with registration so no connection escapes
                    // the partition after observing the old permit.
                    let mut sockets = proxy_sockets.lock().unwrap();
                    if proxy_blocked.load(Ordering::SeqCst) {
                        continue;
                    }
                    sockets.push(incoming.try_clone().unwrap());
                    sockets.push(outgoing.try_clone().unwrap());
                    drop(sockets);
                    forwards.push(std::thread::spawn(move || {
                        let mut reader = incoming.try_clone().unwrap();
                        let mut writer = outgoing.try_clone().unwrap();
                        let other = std::thread::spawn(move || {
                            let _ = std::io::copy(&mut reader, &mut writer);
                            let _ = reader.shutdown(std::net::Shutdown::Both);
                            let _ = writer.shutdown(std::net::Shutdown::Both);
                        });
                        let mut reader = outgoing;
                        let mut writer = incoming;
                        let _ = std::io::copy(&mut reader, &mut writer);
                        let _ = reader.shutdown(std::net::Shutdown::Both);
                        let _ = writer.shutdown(std::net::Shutdown::Both);
                        other.join().unwrap();
                    }));
                }
                for forward in forwards {
                    forward.join().unwrap();
                }
            });
            Self {
                address,
                blocked,
                stop,
                sockets,
                worker: Some(worker),
            }
        }

        fn cut(&self) {
            self.blocked.store(true, Ordering::SeqCst);
            let mut sockets = self.sockets.lock().unwrap();
            for socket in sockets.drain(..) {
                let _ = socket.shutdown(std::net::Shutdown::Both);
            }
        }

        fn heal(&self) {
            self.blocked.store(false, Ordering::SeqCst);
        }
    }

    impl Drop for PeerProxy {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            self.cut();
            let _ = TcpStream::connect(self.address);
            if let Some(worker) = self.worker.take() {
                worker.join().unwrap();
            }
        }
    }

    struct Member {
        process: Child,
        address: SocketAddr,
        arguments: Vec<std::ffi::OsString>,
    }

    struct Cluster {
        dir: tempfile::TempDir,
        members: Vec<Member>,
        proxies: Vec<PeerProxy>,
        client: TlsFiles,
        etcdctl: std::path::PathBuf,
        cluster_id: u64,
    }

    fn address() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    }

    impl Cluster {
        fn new() -> Self {
            let binary = std::env::var_os("MAKI_ETCD_BIN")
                .map(std::path::PathBuf::from)
                .expect(
                    "set MAKI_ETCD_BIN to a verified etcd v3.6 binary; this gate must not skip",
                );
            let etcdctl = binary.with_file_name("etcdctl");
            assert!(etcdctl.is_file(), "matching etcdctl binary required");
            let dir = tempfile::tempdir().unwrap();
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let ca_key = rcgen::KeyPair::generate().unwrap();
            let ca_cert = params.self_signed(&ca_key).unwrap();
            let signed = |name: &str, names: Vec<String>| {
                let mut params = rcgen::CertificateParams::new(names).unwrap();
                params
                    .distinguished_name
                    .push(rcgen::DnType::CommonName, name);
                params.extended_key_usages = vec![
                    rcgen::ExtendedKeyUsagePurpose::ServerAuth,
                    rcgen::ExtendedKeyUsagePurpose::ClientAuth,
                ];
                let key_pair = rcgen::KeyPair::generate().unwrap();
                let cert = params.signed_by(&key_pair, &ca_cert, &ca_key).unwrap();
                rcgen::CertifiedKey { cert, key_pair }
            };
            let client_cert = signed("maki-test-service", vec!["maki-test-service".into()]);
            let client = write_identity(dir.path(), "client", &client_cert, &ca_cert.pem());
            let clients: Vec<_> = (0..3).map(|_| address()).collect();
            let peers: Vec<_> = (0..3).map(|_| address()).collect();
            let proxies: Vec<_> = peers.iter().map(|peer| PeerProxy::new(*peer)).collect();
            let initial_cluster = proxies
                .iter()
                .enumerate()
                .map(|(i, proxy)| format!("node{i}=http://{}", proxy.address))
                .collect::<Vec<_>>()
                .join(",");
            let token = Uuid::new_v4().to_string();
            let mut cluster = Self {
                dir,
                members: Vec::new(),
                proxies,
                client,
                etcdctl,
                cluster_id: 0,
            };
            for i in 0..3 {
                let cert = signed("localhost", vec!["localhost".into(), "127.0.0.1".into()]);
                let tls = write_identity(
                    cluster.dir.path(),
                    &format!("node{i}"),
                    &cert,
                    &ca_cert.pem(),
                );
                let log_path = cluster.dir.path().join(format!("node{i}.log"));
                use std::os::unix::fs::OpenOptionsExt;
                let log = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(log_path)
                    .unwrap();
                let mut command = Command::new(&binary);
                command
                    .arg("--name")
                    .arg(format!("node{i}"))
                    .arg("--data-dir")
                    .arg(cluster.dir.path().join(format!("data{i}")))
                    .arg("--listen-client-urls")
                    .arg(format!("https://{}", clients[i]))
                    .arg("--advertise-client-urls")
                    .arg(format!("https://{}", clients[i]))
                    .arg("--listen-peer-urls")
                    .arg(format!("http://{}", peers[i]))
                    .arg("--initial-advertise-peer-urls")
                    .arg(format!("http://{}", cluster.proxies[i].address))
                    .arg("--initial-cluster")
                    .arg(&initial_cluster)
                    .arg("--initial-cluster-token")
                    .arg(&token)
                    .arg("--initial-cluster-state")
                    .arg("new")
                    .arg("--client-cert-auth")
                    .arg("--trusted-ca-file")
                    .arg(&tls.ca_file)
                    .arg("--cert-file")
                    .arg(&tls.cert_file)
                    .arg("--key-file")
                    .arg(&tls.key_file)
                    .arg("--tls-min-version")
                    .arg("TLS1.3")
                    .arg("--heartbeat-interval")
                    .arg("50")
                    .arg("--election-timeout")
                    .arg("500")
                    .arg("--quota-backend-bytes")
                    .arg("16777216")
                    .arg("--log-level")
                    .arg("warn")
                    .stdin(Stdio::null())
                    .stdout(log.try_clone().unwrap())
                    .stderr(log);
                let arguments = command.get_args().map(std::ffi::OsStr::to_owned).collect();
                let process = command.spawn().unwrap();
                cluster.members.push(Member {
                    process,
                    address: clients[i],
                    arguments,
                });
            }
            cluster.cluster_id = cluster.wait_ready();
            cluster
        }

        fn wait_ready(&mut self) -> u64 {
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                if let Some(status) = self.status() {
                    if status.len() == 3
                        && status
                            .iter()
                            .all(|row| row["Status"]["leader"].as_u64().is_some_and(|id| id != 0))
                    {
                        return status[0]["Status"]["header"]["cluster_id"]
                            .as_u64()
                            .unwrap();
                    }
                }
                assert!(
                    Instant::now() < deadline,
                    "three-member etcd fixture did not become ready"
                );
                assert!(
                    self.members.iter_mut().all(|member| member
                        .process
                        .try_wait()
                        .unwrap()
                        .is_none()),
                    "etcd fixture member exited during startup"
                );
                // This polling is only process readiness, never a correctness delay.
                std::thread::yield_now();
            }
        }

        fn restart_all(&mut self) {
            for member in &mut self.members {
                let _ = member.process.kill();
                let _ = member.process.wait();
            }
            for (index, member) in self.members.iter_mut().enumerate() {
                let log = std::fs::OpenOptions::new()
                    .append(true)
                    .open(self.dir.path().join(format!("node{index}.log")))
                    .unwrap();
                member.process = Command::new(self.etcdctl.with_file_name("etcd"))
                    .args(&member.arguments)
                    .stdin(Stdio::null())
                    .stdout(log.try_clone().unwrap())
                    .stderr(log)
                    .spawn()
                    .unwrap();
            }
            assert_eq!(
                self.wait_ready(),
                self.cluster_id,
                "restart changed the pinned quorum identity"
            );
        }

        fn config_text(&self, prefix: &str) -> String {
            let header = if prefix.is_empty() {
                String::new()
            } else {
                format!("[{prefix}]\n")
            };
            let nested = if prefix.is_empty() {
                String::new()
            } else {
                format!("{prefix}.")
            };
            let endpoints = self
                .members
                .iter()
                .map(|member| {
                    format!(
                        "[[{nested}endpoints]]\naddress = '{}'\nserver_name = 'localhost'\n",
                        member.address
                    )
                })
                .collect::<String>();
            format!("{header}cluster_id = '{}'\nstorage_identity = '{}'\nkey = '/maki/witness/test'\ntimeout_ms = 5000\n{endpoints}[{nested}tls]\n{}",
                self.cluster_id, Uuid::from_bytes(IDENTITY), tls_text(&self.client))
        }

        fn status(&self) -> Option<Vec<Value>> {
            let endpoints = self
                .members
                .iter()
                .map(|member| format!("https://{}", member.address))
                .collect::<Vec<_>>()
                .join(",");
            let output = Command::new(&self.etcdctl)
                .arg("--endpoints")
                .arg(endpoints)
                .arg("--cacert")
                .arg(&self.client.ca_file)
                .arg("--cert")
                .arg(&self.client.cert_file)
                .arg("--key")
                .arg(&self.client.key_file)
                .arg("--dial-timeout=200ms")
                .arg("--command-timeout=500ms")
                .args(["endpoint", "status", "--write-out=json"])
                .output()
                .unwrap();
            output
                .status
                .success()
                .then(|| serde_json::from_slice(&output.stdout).unwrap())
        }

        fn options(&self) -> EtcdOptions {
            EtcdOptions {
                endpoints: self
                    .members
                    .iter()
                    .map(|member| EtcdEndpoint {
                        address: member.address,
                        server_name: "localhost".into(),
                    })
                    .collect(),
                cluster_id: self.cluster_id,
                storage_identity: Uuid::from_bytes(IDENTITY),
                key: "/maki/witness/test".into(),
                timeout_ms: 5000,
                tls: self.client.clone(),
            }
        }
    }

    impl Drop for Cluster {
        fn drop(&mut self) {
            for member in &mut self.members {
                let _ = member.process.kill();
                let _ = member.process.wait();
            }
        }
    }

    struct Frontend {
        process: Child,
        client: maki_witness::Client,
    }

    fn cli_binary() -> std::path::PathBuf {
        std::env::var_os("MAKI_WITNESS_BIN")
            .map(std::path::PathBuf::from)
            .expect("set MAKI_WITNESS_BIN to the built maki-witness CLI for the real frontend gate")
    }

    fn tls_text(files: &TlsFiles) -> String {
        format!(
            "ca_file = {:?}\ncert_file = {:?}\nkey_file = {:?}\n",
            files.ca_file, files.cert_file, files.key_file
        )
    }

    impl Frontend {
        fn new(cluster: &Cluster, credentials: &Credentials) -> Self {
            let binary = cli_binary();
            let address = address();
            let config = cluster
                .dir
                .path()
                .join(format!("frontend-{}.toml", address.port()));
            let text = format!("listen = '{address}'\n[server]\ntimeout_ms = 10000\nmax_connections = 16\n[server.tls]\n{}[[server.principals]]\ncertificate_sha256 = '{}'\nrole = 'writer'\n{}",
                tls_text(&credentials.server_files), maki_witness::certificate_file_fingerprint(&credentials.client.cert_file).unwrap(), cluster.config_text("etcd"));
            std::fs::write(&config, text).unwrap();
            use std::os::unix::fs::OpenOptionsExt;
            let log = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(
                    cluster
                        .dir
                        .path()
                        .join(format!("frontend-{}.log", address.port())),
                )
                .unwrap();
            let process = Command::new(binary)
                .arg("serve")
                .arg(&config)
                .stdin(Stdio::null())
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .unwrap();
            let mut frontend = Self {
                process,
                client: maki_witness::Client::new(maki_witness::ClientOptions {
                    address,
                    server_name: "localhost".into(),
                    timeout_ms: 8000,
                    tls: credentials.client.clone(),
                })
                .unwrap(),
            };
            let ready = maki_witness::Client::new(maki_witness::ClientOptions {
                address,
                server_name: "localhost".into(),
                timeout_ms: 300,
                tls: credentials.client.clone(),
            })
            .unwrap();
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                if ready
                    .call::<_, maki_backing::remote_witness::Record>(&inspect())
                    .is_ok()
                {
                    break;
                }
                assert!(
                    frontend.process.try_wait().unwrap().is_none(),
                    "etcd frontend exited before readiness"
                );
                assert!(
                    Instant::now() < deadline,
                    "etcd frontend did not become ready"
                );
                std::thread::yield_now();
            }
            frontend
        }

        fn call(&self, request: &Request) -> std::io::Result<maki_backing::remote_witness::Record> {
            maki_backing::remote_witness::Rpc::call(&self.client, request)
        }
    }

    impl Drop for Frontend {
        fn drop(&mut self) {
            let _ = self.process.kill();
            let _ = self.process.wait();
        }
    }

    #[test]
    #[ignore = "requires verified MAKI_ETCD_BIN, matching etcdctl, and built MAKI_WITNESS_BIN; launches a disposable quorum and two mTLS frontends"]
    fn real_three_member_quorum_cas_leader_failover_and_majority_loss() {
        let mut cluster = Cluster::new();
        let enrollment = cluster.dir.path().join("enroll-etcd.toml");
        std::fs::write(&enrollment, cluster.config_text("")).unwrap();
        let initialize = || {
            Command::new(cli_binary())
                .arg("init-etcd")
                .arg(&enrollment)
                .arg(Uuid::from_bytes(IDENTITY).to_string())
                .output()
                .unwrap()
        };
        let initialized = initialize();
        assert!(
            initialized.status.success(),
            "{}",
            String::from_utf8_lossy(&initialized.stderr)
        );
        let enrolled: maki_backing::remote_witness::Record =
            serde_json::from_slice(&initialized.stdout).unwrap();
        assert_eq!(enrolled.fence, 0);
        assert!(
            !initialize().status.success(),
            "CLI initialization overwrote the existing authority"
        );
        let primary = Arc::new(EtcdStore::open(cluster.options()).unwrap());
        assert_eq!(
            EtcdStore::create(cluster.options(), IDENTITY)
                .err()
                .unwrap()
                .kind(),
            std::io::ErrorKind::AlreadyExists
        );
        let other = Arc::new(EtcdStore::open(cluster.options()).unwrap());
        let credentials = Credentials::new();
        let first_frontend = Frontend::new(&cluster, &credentials);
        let second_frontend = Frontend::new(&cluster, &credentials);
        let initial = primary.handle(Role::Writer, &inspect()).unwrap();
        assert_eq!(initial, other.handle(Role::Writer, &inspect()).unwrap());
        assert_eq!(first_frontend.call(&inspect()).unwrap(), initial);
        assert_eq!(second_frontend.call(&inspect()).unwrap(), initial);
        let barrier = Arc::new(std::sync::Barrier::new(16));
        let threads: Vec<_> = (0..16)
            .map(|i| {
                let store = if i % 2 == 0 {
                    primary.clone()
                } else {
                    other.clone()
                };
                let expected = initial.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    store.handle(
                        Role::Writer,
                        &Request {
                            operation_id: [i + 2; 16],
                            expected: Some(expected),
                            action: Action::Claim,
                        },
                    )
                })
            })
            .collect();
        let results: Vec<_> = threads
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        for result in results.iter().filter(|result| result.is_err()) {
            let error = result.as_ref().err().unwrap();
            assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock, "{error}");
        }
        let claim = results.into_iter().find_map(Result::ok).unwrap();
        let activate = Request {
            operation_id: [40; 16],
            expected: Some(claim.clone()),
            action: Action::Activate {
                descriptor: Descriptor {
                    anchor: Anchor {
                        identity: IDENTITY,
                        generation: 0,
                        root: [7; 32],
                    },
                    epoch: 0,
                    namespace: namespace(claim.fence, claim.session),
                },
            },
        };
        let active = primary.handle(Role::Writer, &activate).unwrap();
        assert_eq!(active.phase, Phase::Active);
        assert_eq!(other.handle(Role::Writer, &activate).unwrap(), active);
        assert_eq!(second_frontend.call(&activate).unwrap(), active);
        assert_eq!(
            other.handle(Role::Admin, &activate).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );

        let status = cluster.status().unwrap();
        let leader_id = status[0]["Status"]["leader"].as_u64().unwrap();
        let leader = status
            .iter()
            .position(|row| row["Status"]["header"]["member_id"].as_u64() == Some(leader_id))
            .unwrap();
        cluster.members[leader].process.kill().unwrap();
        cluster.members[leader].process.wait().unwrap();
        drop(first_frontend); // Independent frontend failure cannot elect a new writer.
        let advance = Request {
            operation_id: [41; 16],
            expected: Some(active),
            action: Action::Advance {
                anchor: Anchor {
                    identity: IDENTITY,
                    generation: 1,
                    root: [8; 32],
                },
            },
        };
        let advanced = second_frontend.call(&advance).unwrap();
        assert_eq!(
            second_frontend.call(&activate).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "an old idempotency record survived an intervening mutation"
        );
        assert_eq!(primary.handle(Role::Writer, &advance).unwrap(), advanced);
        assert_eq!(primary.handle(Role::Writer, &inspect()).unwrap(), advanced);

        // Stop a second member: the remaining member cannot serve a stale read.
        let stopped = (0..3).find(|i| *i != leader).unwrap();
        assert_eq!(
            unsafe { libc::kill(cluster.members[stopped].process.id() as i32, libc::SIGSTOP) },
            0
        );
        let mut minority_options = cluster.options();
        minority_options.endpoints.retain(|endpoint| {
            endpoint.address != cluster.members[leader].address
                && endpoint.address != cluster.members[stopped].address
        });
        minority_options.timeout_ms = 750;
        let before = Instant::now();
        assert!(
            EtcdStore::open(minority_options).is_err(),
            "a minority must never serve cached freshness authority"
        );
        assert!(
            before.elapsed() < Duration::from_secs(2),
            "minority read exceeded its total deadline"
        );
        assert_eq!(
            unsafe { libc::kill(cluster.members[stopped].process.id() as i32, libc::SIGCONT) },
            0
        );
        assert_eq!(other.handle(Role::Writer, &inspect()).unwrap(), advanced);

        // Cut real raft TCP streams while HTTPS client endpoints stay alive.
        for proxy in &cluster.proxies {
            proxy.cut();
        }
        let live = (0..3).find(|i| *i != leader).unwrap();
        let mut partition = cluster.options();
        partition
            .endpoints
            .retain(|endpoint| endpoint.address == cluster.members[live].address);
        partition.timeout_ms = 750;
        let before = Instant::now();
        assert!(
            EtcdStore::open(partition).is_err(),
            "isolated raft member acknowledged a freshness read"
        );
        assert!(
            before.elapsed() < Duration::from_secs(2),
            "partition exceeded the total operation deadline"
        );
        for proxy in &cluster.proxies {
            proxy.heal();
        }
        assert_eq!(second_frontend.call(&inspect()).unwrap(), advanced);

        // SIGKILL all members, then recover the acknowledged state from WALs.
        cluster.restart_all();
        assert_eq!(second_frontend.call(&inspect()).unwrap(), advanced);
        assert_eq!(primary.handle(Role::Writer, &inspect()).unwrap(), advanced);

        let mut wrong_cluster = cluster.options();
        wrong_cluster.cluster_id ^= 1;
        assert_eq!(
            EtcdStore::open(wrong_cluster).err().unwrap().kind(),
            std::io::ErrorKind::InvalidData
        );
        let mut wrong_identity = cluster.options();
        wrong_identity.storage_identity = Uuid::new_v4();
        assert_eq!(
            EtcdStore::open(wrong_identity).err().unwrap().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert_eq!(primary.handle(Role::Writer, &inspect()).unwrap(), advanced);
    }
}
