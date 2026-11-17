//! A witness frontend whose CA bundle does not trust the client certificate
//! refuses it during the TLS 1.3 handshake with a fatal alert, and an
//! authentication failure is final: failover does not try another frontend,
//! a mutation is not retried and a remote rollback session stops. In TLS 1.3
//! the client has already finished its side of the handshake and writes its
//! request while the frontend checks the certificate, and the frontend closes
//! the connection right after its alert. The client's next write or read then
//! often failed with a broken pipe, a reset or an EOF while the alert sat
//! unread in its socket: the kinds of a witness that could not be asked.
//! Failover moved on to the next frontend, `transact` retried, and the
//! session kept running. The controls keep a frontend that closes without an
//! alert a transport failure.
//!
//! Linux only: the client reads the alert the frontend sent before its reset,
//! which Linux keeps readable after the reset arrives.
#![cfg(target_os = "linux")]
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::ops::Range;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use maki_backing::remote_witness::{Action, Request, Role, Rpc, StateStore};
use maki_backing::{Backing, RollbackBacking};
use maki_witness::failover::FailoverClient;
use maki_witness::{
    certificate_fingerprint, Client, ClientOptions, Handler, Principal, Server, ServerOptions,
    TlsFiles,
};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};

const IDENTITY: [u8; 16] = [7; 16];
/// Connections per case.
const ATTEMPTS: usize = 40;

/// How a frontend's CA bundle treats the writer certificate.
#[derive(Clone, Copy, Debug)]
enum Bundle {
    Trusting,
    /// Names only an unrelated CA: refused with `unknown_ca`.
    OtherCa,
    /// Names a CA with the writer's issuer name but another key, as after a
    /// rotation that kept the name: refused with `decrypt_error`.
    SameNameOtherKey,
}

const REFUSALS: [Bundle; 2] = [Bundle::OtherCa, Bundle::SameNameOtherKey];

/// Run this thread on `cpu`, if the host allows it. The client and its
/// frontends share one CPU, so the frontend, woken by the client's last
/// handshake message, usually refuses and closes before the client writes
/// its request: the ordering that hid the alert (19 in 20 refusals before
/// the fix, against about 1 in 100 unpinned on an idle host).
fn pin(cpu: usize) {
    // SAFETY: a zeroed cpu_set_t is an empty set, CPU_SET stays within it,
    // and the call only changes this thread's affinity.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of_val(&set), &set);
    }
}

fn save(dir: &Path, name: &str, key: &rcgen::CertifiedKey, ca: &str) -> TlsFiles {
    let tls = TlsFiles {
        ca_file: dir.join(format!("{name}.ca.pem")),
        cert_file: dir.join(format!("{name}.cert.pem")),
        key_file: dir.join(format!("{name}.key.pem")),
    };
    std::fs::write(&tls.ca_file, ca).unwrap();
    std::fs::write(&tls.cert_file, key.cert.pem()).unwrap();
    std::fs::write(&tls.key_file, key.key_pair.serialize_pem()).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&tls.key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    tls
}

struct Fixture {
    directory: tempfile::TempDir,
    cpu: usize,
    trusting: TlsFiles,
    other_ca: TlsFiles,
    same_name_other_key: TlsFiles,
    writer: TlsFiles,
    writer_fingerprint: String,
}

impl Fixture {
    /// Also pins the calling thread, the client, to the CPU it runs on.
    fn new() -> Self {
        // SAFETY: sched_getcpu has no preconditions.
        let cpu = usize::try_from(unsafe { libc::sched_getcpu() }).unwrap_or(0);
        pin(cpu);
        let directory = tempfile::tempdir().unwrap();
        let server = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        // Simple self-signed certificates all share one subject name.
        let writer = rcgen::generate_simple_self_signed(vec!["writer".into()]).unwrap();
        let impostor = rcgen::generate_simple_self_signed(vec!["writer".into()]).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["other-ca.invalid".into()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            "unrelated witness client authority",
        );
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let other_ca = params.self_signed(&key).unwrap().pem();
        Self {
            cpu,
            trusting: save(directory.path(), "trusting", &server, &writer.cert.pem()),
            other_ca: save(directory.path(), "other-ca", &server, &other_ca),
            same_name_other_key: save(directory.path(), "same-name", &server, &impostor.cert.pem()),
            writer: save(directory.path(), "writer", &writer, &server.cert.pem()),
            writer_fingerprint: certificate_fingerprint(writer.cert.der()),
            directory,
        }
    }

    /// A frontend whose allow-list names the writer: only its CA bundle
    /// decides whether the writer's certificate is accepted.
    fn server(&self, bundle: Bundle) -> Server {
        Server::new(ServerOptions {
            tls: match bundle {
                Bundle::Trusting => self.trusting.clone(),
                Bundle::OtherCa => self.other_ca.clone(),
                Bundle::SameNameOtherKey => self.same_name_other_key.clone(),
            },
            principals: vec![Principal {
                certificate_sha256: self.writer_fingerprint.clone(),
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

    /// The frontend's identity, with `verifier` or no client authentication.
    fn frontend_tls(&self, verifier: Option<Misbehaving>) -> Arc<rustls::ServerConfig> {
        let builder = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap();
        let builder = match verifier {
            Some(verifier) => builder.with_client_cert_verifier(Arc::new(verifier)),
            None => builder.with_no_client_auth(),
        };
        let config = builder
            .with_single_cert(
                vec![CertificateDer::from_pem_file(&self.trusting.cert_file).unwrap()],
                PrivateKeyDer::from_pem_file(&self.trusting.key_file).unwrap(),
            )
            .unwrap();
        Arc::new(config)
    }

    /// Trusts the writer's CA, then refuses its certificate as a protocol
    /// violation.
    fn misbehaving(&self) -> Misbehaving {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_file(&self.trusting.ca_file).unwrap())
            .unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        Misbehaving(
            rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .unwrap(),
        )
    }
}

/// Refuses every client certificate as a protocol violation, which rustls
/// answers with `illegal_parameter`: a fatal alert that is not about trust.
#[derive(Debug)]
struct Misbehaving(Arc<dyn ClientCertVerifier>);

impl ClientCertVerifier for Misbehaving {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        self.0.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Err(rustls::Error::PeerMisbehaved(
            rustls::PeerMisbehaved::BadCertChainExtensions,
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

fn counted(handler: Arc<Handler>, calls: &Arc<AtomicUsize>) -> Arc<Handler> {
    let calls = calls.clone();
    Arc::new(move |role, request| {
        calls.fetch_add(1, Ordering::SeqCst);
        handler(role, request)
    })
}

/// Run the server side of a TLS handshake until it completes or fails.
fn handshake(config: &Arc<rustls::ServerConfig>, socket: &TcpStream) {
    let mut io = socket;
    let mut connection = rustls::ServerConnection::new(config.clone()).unwrap();
    while connection.is_handshaking() && connection.complete_io(&mut io).is_ok() {}
}

/// Close with a reset and nothing sent first.
fn reset(socket: TcpStream) {
    use std::os::fd::AsRawFd;
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: socket owns a live fd and linger has the size and
    // representation SO_LINGER requires.
    let set = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&linger as *const libc::linger).cast(),
            std::mem::size_of_val(&linger) as libc::socklen_t,
        )
    };
    assert_eq!(set, 0);
}

/// One frontend address whose CA bundle can change between connections, as
/// across a controlled restart: the connections whose accept index is in
/// `refused` are served by a frontend that does not trust the writer.
struct Service {
    address: SocketAddr,
    accepted: Arc<AtomicUsize>,
    refused: Arc<Mutex<Range<usize>>>,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Service {
    fn start(fixture: &Fixture, refusal: Bundle, handler: Arc<Handler>) -> Self {
        let trusting = fixture.server(Bundle::Trusting);
        let refusing = fixture.server(refusal);
        Self::spawn(fixture.cpu, move |_, refused, socket| {
            let server = if refused { &refusing } else { &trusting };
            let _ = server.handle_connection(socket, handler.as_ref());
        })
    }

    /// An outage, not a refusal: resets even connections at once and odd
    /// ones after completing the TLS handshake, never sending an alert.
    fn resetting(fixture: &Fixture) -> Self {
        let config = fixture.frontend_tls(None);
        Self::spawn(fixture.cpu, move |index, _, socket| {
            if index % 2 == 1 {
                handshake(&config, &socket);
            }
            reset(socket);
        })
    }

    /// Ends each handshake with an alert that does not concern trust and
    /// closes the connection, as the witness server does after any alert.
    fn misbehaving(fixture: &Fixture) -> Self {
        let config = fixture.frontend_tls(Some(fixture.misbehaving()));
        Self::spawn(fixture.cpu, move |_, _, socket| handshake(&config, &socket))
    }

    fn spawn(cpu: usize, serve: impl Fn(usize, bool, TcpStream) + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let refused = Arc::new(Mutex::new(0..0));
        let stop = Arc::new(AtomicBool::new(false));
        let worker = std::thread::spawn({
            let (accepted, refused, stop) = (accepted.clone(), refused.clone(), stop.clone());
            move || {
                pin(cpu);
                for socket in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let index = accepted.fetch_add(1, Ordering::SeqCst);
                    let refuse = refused.lock().unwrap().contains(&index);
                    serve(index, refuse, socket.unwrap());
                }
            }
        });
        Self {
            address,
            accepted,
            refused,
            stop,
            worker: Some(worker),
        }
    }

    fn refuse(&self, connections: Range<usize>) {
        *self.refused.lock().unwrap() = connections;
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

/// The kinds the witness callers treat as the authority's final answer.
fn final_answer(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::PermissionDenied
            | io::ErrorKind::InvalidData
            | io::ErrorKind::InvalidInput
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::NotFound
    )
}

/// Every refusal must be a denial; list what was reported instead.
fn assert_all_denied(errors: &[io::Error], case: &str) {
    let other: Vec<_> = errors
        .iter()
        .filter(|error| error.kind() != io::ErrorKind::PermissionDenied)
        .map(|error| error.kind())
        .collect();
    assert!(
        other.is_empty(),
        "{case}: {} of {} refusals were not reported as a denial: {other:?}",
        other.len(),
        errors.len()
    );
}

#[test]
fn an_untrusted_client_certificate_is_a_denial_not_an_outage() {
    let fixture = Fixture::new();
    let calls = Arc::new(AtomicUsize::new(0));
    for bundle in REFUSALS {
        let handler = counted(fixture.state(&format!("{bundle:?}")), &calls);
        let service = Service::start(&fixture, bundle, handler);
        service.refuse(0..usize::MAX);
        let client = Client::new(fixture.options(service.address)).unwrap();
        let errors: Vec<_> = (0..ATTEMPTS)
            .map(|_| Rpc::call(&client, &inspect()).unwrap_err())
            .collect();
        assert_all_denied(&errors, &format!("{bundle:?}"));
        for error in &errors {
            assert!(
                error.to_string().contains("alert"),
                "the refusal does not name the alert: {error}"
            );
        }
    }

    // The production accept loop refuses the same way.
    let server = Arc::new(fixture.server(Bundle::OtherCa));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handler = counted(fixture.state("served"), &calls);
    let cpu = fixture.cpu;
    std::thread::spawn(move || {
        pin(cpu);
        server.serve(listener, handler)
    });
    let client = Client::new(fixture.options(address)).unwrap();
    let errors: Vec<_> = (0..ATTEMPTS)
        .map(|_| Rpc::call(&client, &inspect()).unwrap_err())
        .collect();
    assert_all_denied(&errors, "serve");
    assert_eq!(calls.load(Ordering::SeqCst), 0, "a refused peer was served");
}

#[test]
fn failover_stops_at_a_frontend_that_refuses_the_certificate() {
    let fixture = Fixture::new();
    let calls = Arc::new(AtomicUsize::new(0));
    for bundle in REFUSALS {
        let state = |name| counted(fixture.state(&format!("{bundle:?}-{name}")), &calls);
        let refusing = Service::start(&fixture, bundle, state("refusing"));
        refusing.refuse(0..usize::MAX);
        let trusting = Service::start(&fixture, Bundle::Trusting, state("trusting"));
        let client = FailoverClient::new(
            vec![
                fixture.options(refusing.address),
                fixture.options(trusting.address),
            ],
            IDENTITY,
            2000,
        )
        .unwrap();
        let errors: Vec<_> = (0..ATTEMPTS / 2)
            .map(|_| {
                client
                    .call(&inspect())
                    .expect_err("failover moved past a refusal and another frontend answered")
            })
            .collect();
        assert_all_denied(&errors, &format!("failover, {bundle:?}"));
        assert_eq!(refusing.accepted(), ATTEMPTS / 2);
        assert_eq!(trusting.accepted(), 0, "failover tried another frontend");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn a_reset_without_an_alert_stays_a_transport_failure() {
    let fixture = Fixture::new();
    let resetting = Service::resetting(&fixture);
    let client = Client::new(fixture.options(resetting.address)).unwrap();
    for _ in 0..ATTEMPTS {
        let error = Rpc::call(&client, &inspect()).unwrap_err();
        assert!(
            !final_answer(error.kind()),
            "a reset without an alert looked like the witness's answer: {error:?}"
        );
    }

    // Failover still moves on from such a frontend and is answered.
    let calls = Arc::new(AtomicUsize::new(0));
    let trusting = Service::start(
        &fixture,
        Bundle::Trusting,
        counted(fixture.state("trusting"), &calls),
    );
    for attempt in 1..=ATTEMPTS / 4 {
        // A new client each time: a success makes the answering frontend
        // the next call's first choice.
        let client = FailoverClient::new(
            vec![
                fixture.options(resetting.address),
                fixture.options(trusting.address),
            ],
            IDENTITY,
            2000,
        )
        .unwrap();
        client
            .call(&inspect())
            .expect("failover did not move past a reset connection");
        assert_eq!(trusting.accepted(), attempt);
    }
    assert_eq!(calls.load(Ordering::SeqCst), ATTEMPTS / 4);
}

#[test]
fn another_alert_stays_a_tls_failure_not_a_denial() {
    let fixture = Fixture::new();
    let misbehaving = Service::misbehaving(&fixture);
    let client = Client::new(fixture.options(misbehaving.address)).unwrap();
    for _ in 0..ATTEMPTS {
        let error = Rpc::call(&client, &inspect()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        assert!(error.to_string().contains("IllegalParameter"), "{error}");
    }
}

#[test]
fn a_refused_freshness_check_stops_the_remote_session() {
    for round in 0..ATTEMPTS / 2 {
        let fixture = Fixture::new();
        let bundle = REFUSALS[round % 2];
        let service = Service::start(&fixture, bundle, fixture.state("state"));
        let client: Arc<dyn Rpc> = Arc::new(Client::new(fixture.options(service.address)).unwrap());
        let root = tempfile::tempdir().unwrap();
        let backing = RollbackBacking::create_remote(root.path(), client, 32 * 4096).unwrap();
        backing.check_freshness().unwrap();

        // The frontend restarts with a CA bundle that no longer trusts the
        // writer: that is a refusal, not an outage.
        service.refuse(service.accepted()..usize::MAX);
        let error = backing.check_freshness().unwrap_err();
        assert_eq!(
            error.kind(),
            io::ErrorKind::PermissionDenied,
            "round {round}, {bundle:?}: the refusal looked like a witness that could not be \
             asked: {error}"
        );
        // Trusting the writer again does not resume the stopped session.
        service.refuse(0..0);
        let error = backing
            .check_freshness()
            .expect_err("a session the witness refused continued");
        assert!(error.to_string().contains("session stopped"), "{error}");
    }
}

#[test]
fn a_refused_commit_is_not_retried() {
    for round in 0..ATTEMPTS / 2 {
        let fixture = Fixture::new();
        let bundle = REFUSALS[round % 2];
        let service = Service::start(&fixture, bundle, fixture.state("state"));
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
        service.refuse(start + per_commit - 1..usize::MAX);
        let error = file.sync_data().unwrap_err();
        assert_eq!(
            error.kind(),
            io::ErrorKind::PermissionDenied,
            "round {round}, {bundle:?}: the refused advance looked like a lost reply: {error}"
        );
        assert_eq!(
            service.accepted() - start,
            per_commit,
            "round {round}, {bundle:?}: a refused advance was retried"
        );
    }
}
