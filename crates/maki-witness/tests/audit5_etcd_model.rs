//! Audit round 5 (remote-admin-crash): the etcd-backed authority against a
//! stateful fake of etcd's v3 JSON gateway. Not part of the maintained suite.
//!
//! etcd is not installed here, and the maintained tests script single
//! replies. This model keeps one key with etcd's semantics (a global
//! revision, `mod_revision`, transactions with VERSION / MOD / VALUE
//! compares, a `request_range` failure branch, protobuf-JSON omission of
//! `succeeded: false`) behind several TLS endpoints, and injects what a
//! quorum backend does to a client: a connection closed before the request
//! is processed, a transaction that commits and whose reply is lost, a
//! transaction that commits and answers 503, a 503 without a commit, a
//! commit that lands only after the frontend's attempt timed out, and whole
//! endpoints going away.
//!
//! Several `EtcdStore` frontends share the key. A client drives them the
//! way the volume does through the witness transport: the frontend's error
//! kinds collapse as on the wire, every frontend is tried once per call
//! (`FailoverClient`), and a mutation is retried once (`transact`).
//!
//! Oracle, from the fake's own commit history:
//! - every committed value is `CanonicalState::apply` of one issued request
//!   to its predecessor, and no operation id commits twice;
//! - a mutation reported `Ok(record)` is in the history exactly once with
//!   that record;
//! - a mutation reported with a final refusal (conflict / denied / invalid:
//!   the kinds on which the volume concludes "not applied by me") is not the
//!   authority's latest operation when the refusal is returned, and with a
//!   single client it is never in the history at all.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use maki_backing::remote_witness::{
    namespace, Action, CanonicalState, Descriptor, Phase, Record, Request, Role,
    SessionAuthorization,
};
use maki_backing::witness::Anchor;
use maki_witness::etcd::{EtcdEndpoint, EtcdOptions, EtcdStore};
use maki_witness::TlsFiles;
use serde_json::{json, Value};
use uuid::Uuid;

const IDENTITY: [u8; 16] = [0x51; 16];
const CLUSTER_ID: u64 = 4242;
const KEY: &str = "/maki/witness/audit5";

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn heavy() -> bool {
    std::env::var("AUDIT5_HEAVY").is_ok()
}

// --- deterministic choices ---------------------------------------------------

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

// --- TLS identities (as tests/etcd_ha.rs) ------------------------------------

struct Credentials {
    _dir: tempfile::TempDir,
    client: TlsFiles,
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
            rustls::pki_types::PrivatePkcs8KeyDer::from(server.key_pair.serialize_der()).into(),
        )
        .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self {
            _dir: dir,
            client: client_files,
            server: Arc::new(config),
        }
    }
}

// --- the fake quorum ----------------------------------------------------------

#[derive(Default)]
struct Kv {
    value: Option<Vec<u8>>,
    mod_revision: u64,
    revision: u64,
    /// Every committed value, in commit order.
    history: Vec<Vec<u8>>,
}

#[derive(Default)]
struct Stats {
    requests: AtomicUsize,
    dropped: AtomicUsize,
    committed_lost: AtomicUsize,
    committed_503: AtomicUsize,
    plain_503: AtomicUsize,
    delayed: AtomicUsize,
    down: AtomicUsize,
}

struct Cluster {
    kv: Mutex<Kv>,
    rng: Mutex<Rng>,
    faults: AtomicBool,
    down: Vec<AtomicBool>,
    /// The whole quorum is unreachable until this instant.
    blackout: Mutex<Option<std::time::Instant>>,
    stats: Stats,
    stop: AtomicBool,
}

#[derive(Clone, Copy, PartialEq)]
enum Fault {
    None,
    Drop,
    CommitLost,
    Commit503,
    Plain503,
    Delay(u64),
}

impl Cluster {
    fn header(kv: &Kv) -> Value {
        json!({"cluster_id": CLUSTER_ID.to_string(), "member_id": "1",
               "revision": kv.revision.to_string(), "raft_term": "2"})
    }

    fn range(kv: &Kv) -> Value {
        match &kv.value {
            Some(value) => json!({
                "header": Self::header(kv),
                "kvs": [{"key": b64(KEY.as_bytes()), "create_revision": "1",
                         "mod_revision": kv.mod_revision.to_string(),
                         "version": kv.history.len().to_string(), "value": b64(value)}],
                "count": "1"
            }),
            // protobuf JSON omits an empty list and a zero count.
            None => json!({"header": Self::header(kv)}),
        }
    }

    fn execute(&self, path: &str, body: &Value) -> Value {
        let mut kv = self.kv.lock().unwrap();
        if path.contains("/v3/kv/range") {
            assert_eq!(body["key"], b64(KEY.as_bytes()));
            assert_ne!(body["serializable"], true, "authority reads must be linearizable");
            return Self::range(&kv);
        }
        assert!(path.contains("/v3/kv/txn"), "unexpected path {path}");
        let holds = body["compare"].as_array().unwrap().iter().all(|compare| {
            assert_eq!(compare["key"], b64(KEY.as_bytes()));
            assert_eq!(compare["result"], "EQUAL");
            match compare["target"].as_str().unwrap() {
                "VERSION" => {
                    compare["version"].as_str().unwrap().parse::<usize>().unwrap()
                        == if kv.value.is_some() { kv.history.len() } else { 0 }
                }
                "MOD" => {
                    compare["mod_revision"].as_str().unwrap().parse::<u64>().unwrap()
                        == kv.mod_revision
                }
                "VALUE" => kv.value.as_ref().map(|value| b64(value)).as_deref() == compare["value"].as_str(),
                other => panic!("unexpected compare target {other}"),
            }
        });
        if holds {
            let ops = body["success"].as_array().unwrap();
            assert_eq!(ops.len(), 1);
            let put = &ops[0]["request_put"];
            assert_eq!(put["key"], b64(KEY.as_bytes()));
            assert!(put.get("lease").is_none(), "the authority value must not be leased");
            let value = base64::engine::general_purpose::STANDARD
                .decode(put["value"].as_str().unwrap())
                .unwrap();
            kv.revision += 1;
            kv.mod_revision = kv.revision;
            kv.value = Some(value.clone());
            kv.history.push(value);
            json!({"header": Self::header(&kv), "succeeded": true,
                   "responses": [{"response_put": {"header": Self::header(&kv)}}]})
        } else {
            let ops = body["failure"].as_array().unwrap();
            assert_eq!(ops.len(), 1);
            assert_ne!(ops[0]["request_range"]["serializable"], true);
            // `succeeded: false` is omitted by the gateway.
            json!({"header": Self::header(&kv),
                   "responses": [{"response_range": Self::range(&kv)}]})
        }
    }

    fn choose(&self, transaction: bool) -> Fault {
        if !self.faults.load(Ordering::SeqCst) {
            return Fault::None;
        }
        let mut rng = self.rng.lock().unwrap();
        if heavy() {
            // Most attempts fail: frontends exhaust their budgets, so the
            // client sees unknown outcomes and the retry paths run.
            return match rng.below(100) {
                0..=17 => Fault::Drop,
                18..=39 if transaction => Fault::CommitLost,
                40..=51 if transaction => Fault::Commit503,
                52..=63 => Fault::Plain503,
                64..=81 => Fault::Delay(20 + rng.below(200)),
                _ => Fault::None,
            };
        }
        match rng.below(100) {
            0..=5 => Fault::Drop,
            6..=13 if transaction => Fault::CommitLost,
            14..=18 if transaction => Fault::Commit503,
            19..=23 => Fault::Plain503,
            24..=31 => Fault::Delay(20 + rng.below(140)),
            _ => Fault::None,
        }
    }

    fn serve(self: &Arc<Self>, index: usize, listener: TcpListener, tls: Arc<rustls::ServerConfig>) {
        for socket in listener.incoming() {
            if self.stop.load(Ordering::SeqCst) {
                return;
            }
            let Ok(socket) = socket else { continue };
            let cluster = self.clone();
            let tls = tls.clone();
            std::thread::spawn(move || {
                let _ = cluster.connection(index, socket, tls);
            });
        }
    }

    fn connection(
        &self,
        index: usize,
        socket: std::net::TcpStream,
        config: Arc<rustls::ServerConfig>,
    ) -> io::Result<()> {
        let blackout = self
            .blackout
            .lock()
            .unwrap()
            .is_some_and(|until| std::time::Instant::now() < until);
        if blackout || self.down[index].load(Ordering::SeqCst) {
            self.stats.down.fetch_add(1, Ordering::SeqCst);
            return Ok(());
        }
        socket.set_read_timeout(Some(Duration::from_secs(3)))?;
        socket.set_write_timeout(Some(Duration::from_secs(3)))?;
        let connection = rustls::ServerConnection::new(config).map_err(io::Error::other)?;
        let mut tls = rustls::StreamOwned::new(connection, socket);
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            tls.read_exact(&mut byte)?;
            header.push(byte[0]);
            if header.len() > 8192 {
                return Err(io::Error::other("header too long"));
            }
        }
        let header = String::from_utf8_lossy(&header).into_owned();
        let length: usize = header
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
            })
            .unwrap_or(0);
        let mut body = vec![0; length];
        tls.read_exact(&mut body)?;
        let path = header.lines().next().unwrap_or("").to_string();
        let body: Value = serde_json::from_slice(&body).map_err(io::Error::other)?;
        self.stats.requests.fetch_add(1, Ordering::SeqCst);
        let fault = self.choose(path.contains("/v3/kv/txn"));
        let unavailable = |tls: &mut rustls::StreamOwned<_, _>| -> io::Result<()> {
            let body = br#"{"error":"etcdserver: request timed out","code":14,"message":"etcdserver: request timed out"}"#;
            write!(tls, "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())?;
            tls.write_all(body)?;
            tls.flush()
        };
        match fault {
            Fault::Drop => {
                self.stats.dropped.fetch_add(1, Ordering::SeqCst);
                return Ok(());
            }
            Fault::Plain503 => {
                self.stats.plain_503.fetch_add(1, Ordering::SeqCst);
                return unavailable(&mut tls);
            }
            Fault::Delay(ms) => {
                // The frontend's attempt may time out before this commits.
                self.stats.delayed.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(ms));
            }
            _ => {}
        }
        let reply = self.execute(&path, &body);
        match fault {
            Fault::CommitLost => {
                self.stats.committed_lost.fetch_add(1, Ordering::SeqCst);
                // Sometimes the quorum is lost right after the commit, for
                // longer than the client keeps trying.
                if heavy() && self.rng.lock().unwrap().below(3) == 0 {
                    *self.blackout.lock().unwrap() =
                        Some(std::time::Instant::now() + Duration::from_millis(1500));
                }
                return Ok(());
            }
            Fault::Commit503 => {
                self.stats.committed_503.fetch_add(1, Ordering::SeqCst);
                return unavailable(&mut tls);
            }
            _ => {}
        }
        let reply = serde_json::to_vec(&reply).unwrap();
        write!(tls, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", reply.len())?;
        tls.write_all(&reply)?;
        tls.flush()
    }
}

struct Fixture {
    cluster: Arc<Cluster>,
    frontends: Vec<EtcdStore>,
    _credentials: Credentials,
}

fn fixture(endpoints: usize, frontends: usize, seed: u64, timeout_ms: u64) -> Fixture {
    let credentials = Credentials::new();
    let cluster = Arc::new(Cluster {
        kv: Mutex::new(Kv::default()),
        rng: Mutex::new(Rng(seed | 1)),
        faults: AtomicBool::new(false),
        down: (0..endpoints).map(|_| AtomicBool::new(false)).collect(),
        blackout: Mutex::new(None),
        stats: Stats::default(),
        stop: AtomicBool::new(false),
    });
    let mut addresses: Vec<SocketAddr> = Vec::new();
    for index in 0..endpoints {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        addresses.push(listener.local_addr().unwrap());
        let cluster = cluster.clone();
        let tls = credentials.server.clone();
        std::thread::spawn(move || cluster.serve(index, listener, tls));
    }
    let options = |rotate: usize| EtcdOptions {
        endpoints: (0..endpoints)
            .map(|i| EtcdEndpoint {
                address: addresses[(i + rotate) % endpoints],
                server_name: "localhost".into(),
            })
            .collect(),
        cluster_id: CLUSTER_ID,
        storage_identity: Uuid::from_bytes(IDENTITY),
        key: KEY.into(),
        timeout_ms,
        tls: credentials.client.clone(),
    };
    // `maki-witness init-etcd`, then the serving frontends.
    drop(EtcdStore::create(options(0), IDENTITY).unwrap());
    let frontends = (0..frontends)
        .map(|index| EtcdStore::open(options(index)).unwrap())
        .collect();
    Fixture {
        cluster,
        frontends,
        _credentials: credentials,
    }
}

// --- the client stack ---------------------------------------------------------

fn terminal(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::InvalidInput
            | io::ErrorKind::InvalidData
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::WouldBlock
    )
}

/// What `Server::respond` + `Client::call_until` make of a handler error.
fn over_the_wire(error: io::Error) -> io::Error {
    match error.kind() {
        io::ErrorKind::WouldBlock => io::Error::new(io::ErrorKind::WouldBlock, "conflict"),
        io::ErrorKind::PermissionDenied => io::Error::new(io::ErrorKind::PermissionDenied, "denied"),
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => {
            io::Error::new(io::ErrorKind::InvalidInput, format!("rejected: {error}"))
        }
        _ => io::Error::other(format!("unavailable: {error}")),
    }
}

/// `FailoverClient::call`: each frontend once, final kinds stop.
fn failover(frontends: &[EtcdStore], first: usize, role: Role, request: &Request) -> io::Result<Record> {
    let mut last = io::Error::new(io::ErrorKind::TimedOut, "no frontend");
    for attempt in 0..frontends.len() {
        match frontends[(first + attempt) % frontends.len()]
            .handle(role, request)
            .map_err(over_the_wire)
        {
            Ok(record) => return Ok(record),
            Err(error) if terminal(error.kind()) => return Err(error),
            Err(error) => last = error,
        }
    }
    Err(last)
}

/// `transact` of `rollback/remote.rs`: retry only this exact operation once.
fn transact(frontends: &[EtcdStore], first: usize, role: Role, request: &Request) -> io::Result<Record> {
    match failover(frontends, first, role, request) {
        Ok(record) => Ok(record),
        Err(error) if terminal(error.kind()) => Err(error),
        Err(_) => failover(frontends, first + 1, role, request),
    }
}

// --- the oracle ---------------------------------------------------------------

#[derive(Default)]
struct Issued {
    requests: Mutex<HashMap<[u8; 16], (Role, Request)>>,
    next: AtomicU64,
}

impl Issued {
    fn request(&self, role: Role, expected: &Record, action: Action, authorization: [u8; 32]) -> Request {
        let n = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        let mut operation_id = [0x77; 16];
        operation_id[..8].copy_from_slice(&n.to_le_bytes());
        let request = Request {
            operation_id,
            expected: Some(expected.clone()),
            action,
            authorization: Some(SessionAuthorization::from_bytes(authorization)),
        };
        self.requests
            .lock()
            .unwrap()
            .insert(operation_id, (role, request.clone()));
        request
    }
}

fn history(cluster: &Cluster) -> Vec<CanonicalState> {
    cluster
        .kv
        .lock()
        .unwrap()
        .history
        .iter()
        .map(|bytes| CanonicalState::decode(bytes).unwrap())
        .collect()
}

fn applied(history: &[CanonicalState], operation: &[u8; 16]) -> Vec<usize> {
    history
        .iter()
        .enumerate()
        .filter(|(_, state)| state.record().last_operation == *operation)
        .map(|(index, _)| index)
        .collect()
}

/// Every commit is one issued request applied to its predecessor.
fn check_history(cluster: &Cluster, issued: &Issued) {
    let history = history(cluster);
    let requests = issued.requests.lock().unwrap();
    assert_eq!(
        history[0],
        CanonicalState::initial(IDENTITY).unwrap(),
        "the first commit is the initialization"
    );
    let mut seen = std::collections::HashSet::new();
    for pair in history.windows(2) {
        let operation = pair[1].record().last_operation;
        assert!(seen.insert(operation), "operation {operation:?} committed twice");
        let (role, request) = requests
            .get(&operation)
            .unwrap_or_else(|| panic!("commit of an operation nobody issued: {operation:?}"));
        assert_eq!(
            pair[0].apply(*role, request).unwrap(),
            pair[1],
            "a commit is not its request applied to the predecessor"
        );
    }
}

fn truth(cluster: &Cluster) -> Record {
    history(cluster).last().unwrap().record().clone()
}

fn descriptor(record: &Record, generation: u64, root: u8, epoch: u64) -> Descriptor {
    Descriptor {
        anchor: Anchor {
            identity: IDENTITY,
            generation,
            root: [root; 32],
        },
        epoch,
        namespace: namespace(record.fence, record.session),
    }
}

#[derive(Default, Debug)]
struct Outcomes {
    ok: usize,
    refused: usize,
    ambiguous_applied: usize,
    ambiguous_not_applied: usize,
}

/// One client, many frontends, heavy faults: with nobody else mutating the
/// key, a final refusal must mean "never applied".
fn single_client(seed: u64, steps: usize) -> (Outcomes, Arc<Cluster>) {
    let fixture = fixture(3, 3, seed, if heavy() { 150 } else { 400 });
    let issued = Issued::default();
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let mut outcomes = Outcomes::default();
    fixture.cluster.faults.store(true, Ordering::SeqCst);
    let mut authorization = [1u8; 32];
    let mut holds_session = false;
    for step in 0..steps {
        // Endpoints come and go, never all at once.
        if step % 7 == 0 {
            let victim = rng.below(3) as usize;
            for (index, down) in fixture.cluster.down.iter().enumerate() {
                down.store(index == victim && rng.below(3) == 0, Ordering::SeqCst);
            }
        }
        let known = truth(&fixture.cluster);
        let (role, action) = match known.phase {
            Phase::Released if known.current.is_none() || rng.below(4) != 0 => {
                authorization = [rng.below(250) as u8 + 1; 32];
                (Role::Writer, Action::Claim)
            }
            Phase::Claimed if holds_session => {
                let descriptor = match &known.current {
                    Some(current) => Descriptor {
                        namespace: namespace(known.fence, known.session),
                        ..current.clone()
                    },
                    None => descriptor(&known, 0, 1, 0),
                };
                (Role::Admin, Action::Activate { descriptor })
            }
            Phase::Active if holds_session && rng.below(5) != 0 => {
                let current = known.current.as_ref().unwrap();
                (
                    Role::Writer,
                    Action::Advance {
                        anchor: Anchor {
                            identity: IDENTITY,
                            generation: current.anchor.generation + 1,
                            root: [rng.below(255) as u8; 32],
                        },
                    },
                )
            }
            Phase::Active if holds_session => (Role::Writer, Action::Release),
            // The session is lost (an ambiguous claim): administrator.
            _ if known.current.is_some() => {
                authorization = [rng.below(250) as u8 + 1; 32];
                (Role::Admin, Action::Takeover)
            }
            _ => {
                authorization = [rng.below(250) as u8 + 1; 32];
                (Role::Admin, Action::RecoverEnrollment)
            }
        };
        let installs = matches!(
            action,
            Action::Claim | Action::Takeover | Action::RecoverEnrollment
        );
        let releases = action == Action::Release;
        let request = issued.request(role, &known, action, authorization);
        let first = rng.below(3) as usize;
        let result = transact(&fixture.frontends, first, role, &request);
        let history = history(&fixture.cluster);
        let commits = applied(&history, &request.operation_id);
        assert!(commits.len() <= 1, "seed {seed} step {step}: applied twice");
        match result {
            Ok(record) => {
                outcomes.ok += 1;
                assert_eq!(
                    commits.len(),
                    1,
                    "seed {seed} step {step}: Ok without a commit ({:?})",
                    request.action
                );
                assert_eq!(*history[commits[0]].record(), record);
                holds_session = if releases { false } else { installs || holds_session };
            }
            Err(error) if terminal(error.kind()) => {
                outcomes.refused += 1;
                assert!(
                    commits.is_empty(),
                    "seed {seed} step {step}: {:?} was refused ({error}) but it committed; \
                     the client concludes it was not applied",
                    request.action
                );
            }
            Err(_) => {
                // Both attempts failed: the outcome is unknown to the client.
                if commits.is_empty() {
                    outcomes.ambiguous_not_applied += 1;
                } else {
                    outcomes.ambiguous_applied += 1;
                }
                holds_session = false;
                // Let any transaction the fake still delays land first, as an
                // operator who inspects before acting would see it.
                std::thread::sleep(Duration::from_millis(1600));
            }
        }
    }
    fixture.cluster.faults.store(false, Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(250));
    check_history(&fixture.cluster, &issued);
    (outcomes, fixture.cluster.clone())
}

#[test]
#[ignore = "audit sweep"]
fn audit5_etcd_single_client_fault_sweep() {
    let seeds: u64 = std::env::var("AUDIT5_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(6);
    let base: u64 = std::env::var("AUDIT5_SEED_BASE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let steps: usize = std::env::var("AUDIT5_STEPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(120);
    let mut total = Outcomes::default();
    let mut requests = 0;
    let mut faults = [0usize; 6];
    for seed in base..base + seeds {
        let (outcomes, cluster) = single_client(seed, steps);
        total.ok += outcomes.ok;
        total.refused += outcomes.refused;
        total.ambiguous_applied += outcomes.ambiguous_applied;
        total.ambiguous_not_applied += outcomes.ambiguous_not_applied;
        requests += cluster.stats.requests.load(Ordering::SeqCst);
        for (slot, counter) in faults.iter_mut().zip([
            &cluster.stats.dropped,
            &cluster.stats.committed_lost,
            &cluster.stats.committed_503,
            &cluster.stats.plain_503,
            &cluster.stats.delayed,
            &cluster.stats.down,
        ]) {
            *slot += counter.load(Ordering::SeqCst);
        }
        cluster.stop.store(true, Ordering::SeqCst);
    }
    println!(
        "audit5 etcd single client: {seeds} seeds x {steps} steps, {total:?}; fake served \
         {requests} requests; faults dropped/commit-lost/commit-503/503/delayed/down = {faults:?}"
    );
}

/// A writer session and an administrator race through different frontends.
fn concurrent(seed: u64, rounds: usize) -> (usize, usize, usize, Arc<Cluster>) {
    let fixture = Arc::new(fixture(3, 3, seed, if heavy() { 150 } else { 400 }));
    let issued = Arc::new(Issued::default());
    fixture.cluster.faults.store(true, Ordering::SeqCst);
    let violations = Arc::new(Mutex::new(Vec::<String>::new()));
    let oks = Arc::new(AtomicUsize::new(0));
    let refusals = Arc::new(AtomicUsize::new(0));
    let unknown = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let actor = |name: &'static str, role: Role, first: usize, seed: u64| {
        let fixture = fixture.clone();
        let issued = issued.clone();
        let violations = violations.clone();
        let (oks, refusals, unknown, stop) =
            (oks.clone(), refusals.clone(), unknown.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut rng = Rng(seed | 1);
            let mut session: Option<(Record, [u8; 32])> = None;
            while !stop.load(Ordering::SeqCst) {
                let (expected, action, authorization) = match &session {
                    None => {
                        let known = truth(&fixture.cluster);
                        let authorization = [rng.below(250) as u8 + 1; 32];
                        let action = if role == Role::Admin {
                            if known.current.is_some() {
                                Action::Takeover
                            } else {
                                Action::RecoverEnrollment
                            }
                        } else {
                            Action::Claim
                        };
                        (known, action, authorization)
                    }
                    Some((record, authorization)) => {
                        let action = match record.phase {
                            Phase::Claimed => Action::Activate {
                                descriptor: match &record.current {
                                    Some(current) => Descriptor {
                                        namespace: namespace(record.fence, record.session),
                                        ..current.clone()
                                    },
                                    None => descriptor(record, 0, 1, 0),
                                },
                            },
                            Phase::Active if rng.below(4) != 0 => Action::Advance {
                                anchor: Anchor {
                                    identity: IDENTITY,
                                    generation: record.current.as_ref().unwrap().anchor.generation + 1,
                                    root: [rng.below(255) as u8; 32],
                                },
                            },
                            _ => Action::Release,
                        };
                        (record.clone(), action, *authorization)
                    }
                };
                let releases = action == Action::Release;
                let request = issued.request(role, &expected, action, authorization);
                let result = transact(&fixture.frontends, first, role, &request);
                let history = history(&fixture.cluster);
                let commits = applied(&history, &request.operation_id);
                match result {
                    Ok(record) => {
                        oks.fetch_add(1, Ordering::SeqCst);
                        if commits.len() != 1 || *history[commits[0]].record() != record {
                            violations.lock().unwrap().push(format!(
                                "{name}: Ok({:?}) but commits {commits:?}",
                                request.action
                            ));
                        }
                        session = (!releases).then_some((record, authorization));
                    }
                    Err(error) if terminal(error.kind()) => {
                        refusals.fetch_add(1, Ordering::SeqCst);
                        // "Not applied by me" must hold unless someone else
                        // already mutated the authority after it.
                        if commits.first() == Some(&(history.len() - 1)) {
                            violations.lock().unwrap().push(format!(
                                "{name}: {:?} refused ({error}) while it is the authority's \
                                 latest operation",
                                request.action
                            ));
                        }
                        session = None;
                    }
                    Err(_) => {
                        unknown.fetch_add(1, Ordering::SeqCst);
                        session = None;
                    }
                }
                std::thread::sleep(Duration::from_millis(rng.below(5)));
            }
        })
    };
    let writer = actor("writer", Role::Writer, 0, seed * 31 + 7);
    let admin = actor("admin", Role::Admin, 1, seed * 131 + 11);
    for _ in 0..rounds {
        std::thread::sleep(Duration::from_millis(100));
    }
    stop.store(true, Ordering::SeqCst);
    writer.join().unwrap();
    admin.join().unwrap();
    fixture.cluster.faults.store(false, Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(300));
    check_history(&fixture.cluster, &issued);
    let violations = violations.lock().unwrap();
    assert!(violations.is_empty(), "seed {seed}: {violations:#?}");
    (
        oks.load(Ordering::SeqCst),
        refusals.load(Ordering::SeqCst),
        unknown.load(Ordering::SeqCst),
        fixture.cluster.clone(),
    )
}

#[test]
#[ignore = "audit sweep"]
fn audit5_etcd_concurrent_writer_and_admin() {
    let seeds: u64 = std::env::var("AUDIT5_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4);
    let base: u64 = std::env::var("AUDIT5_SEED_BASE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let (mut oks, mut refusals, mut unknown, mut commits) = (0, 0, 0, 0);
    for seed in base..base + seeds {
        let (a, b, c, cluster) = concurrent(seed, 40);
        oks += a;
        refusals += b;
        unknown += c;
        commits += cluster.kv.lock().unwrap().history.len();
        cluster.stop.store(true, Ordering::SeqCst);
    }
    println!(
        "audit5 etcd concurrent: {seeds} seeds, {oks} ok, {refusals} final refusals, \
         {unknown} unknown outcomes, {commits} commits"
    );
}

/// The planted bug: a backend whose compare is ignored (last write wins)
/// must make the oracle fail, or the oracle proves nothing.
#[test]
#[ignore = "audit sweep"]
fn audit5_etcd_oracle_rejects_a_history_that_skips_a_commit() {
    let fixture = fixture(1, 1, 99, 400);
    let issued = Issued::default();
    let initial = truth(&fixture.cluster);
    let claim = issued.request(Role::Writer, &initial, Action::Claim, [9; 32]);
    let claimed = fixture.frontends[0].handle(Role::Writer, &claim).unwrap();
    // Plant: a commit nobody issued (as a lost-update backend would produce).
    let forged = CanonicalState::decode(&fixture.cluster.kv.lock().unwrap().history[1])
        .unwrap()
        .apply(
            Role::Admin,
            &Request {
                operation_id: [0xEE; 16],
                expected: Some(claimed),
                action: Action::Takeover,
                authorization: Some(SessionAuthorization::from_bytes([8; 32])),
            },
        );
    // Takeover of an unenrolled authority is refused by the state machine,
    // so forge with a repeated claim state instead.
    assert!(forged.is_err());
    let duplicate = fixture.cluster.kv.lock().unwrap().history[1].clone();
    fixture.cluster.kv.lock().unwrap().history.push(duplicate);
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        check_history(&fixture.cluster, &issued)
    }));
    assert!(caught.is_err(), "the oracle accepted a double commit");
}
