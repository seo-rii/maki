//! Authenticated, bounded remote freshness authority transport.
//!
//! Each TLS 1.3 connection carries one versioned, request-id-bound RPC. The
//! A single client call never retries. Identity-pinned endpoint sets retry the
//! same operation after transport failures, resolving possible durable commits.

pub mod failover;

pub mod etcd;

use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

pub use maki_backing::remote_witness::Role;
use maki_backing::remote_witness::{Record, Request, Rpc, StateStore};
use std::time::{Duration, Instant};

use base64::Engine as _;
use maki_crypto::SecretBuffer;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const MAX_FRAME_BYTES: usize = 64 * 1024;
const MAX_TLS_FILE_BYTES: usize = 1024 * 1024;
const WIRE_VERSION: u32 = 2;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsFiles {
    pub ca_file: PathBuf,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
}

impl std::fmt::Debug for TlsFiles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TlsFiles { <credential paths redacted> }")
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientOptions {
    /// A resolved address avoids an unbounded synchronous DNS lookup.
    pub address: SocketAddr,
    /// Required certificate identity, independent of the socket address.
    pub server_name: String,
    pub timeout_ms: u64,
    pub tls: TlsFiles,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    /// Lower-case hex SHA-256 of the authenticated leaf certificate DER.
    pub certificate_sha256: String,
    pub role: Role,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerOptions {
    pub tls: TlsFiles,
    pub principals: Vec<Principal>,
    pub timeout_ms: u64,
    pub max_connections: usize,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireRequest<Q> {
    version: u32,
    id: Uuid,
    request: Q,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IncomingRequest<'a> {
    version: u32,
    id: Uuid,
    #[serde(borrow)]
    request: &'a serde_json::value::RawValue,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireResponse<R> {
    version: u32,
    id: Uuid,
    response: Option<R>,
    error: Option<WireError>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireError {
    Conflict,
    PermissionDenied,
    InvalidRequest,
    Unavailable,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn corrupt(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn tls_error(_: impl std::fmt::Display) -> io::Error {
    // TLS errors must never format key material or a peer's application data.
    corrupt("witness TLS configuration or authentication failed")
}

fn timeout(ms: u64) -> io::Result<Duration> {
    if !(1..=60_000).contains(&ms) {
        return Err(invalid("witness timeout_ms must be in 1..=60000"));
    }
    Ok(Duration::from_millis(ms))
}

fn read_pem(path: &Path, private: bool) -> io::Result<SecretBuffer> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | if private { libc::O_NOFOLLOW } else { 0 });
    }
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_TLS_FILE_BYTES as u64 {
        return Err(invalid(
            "TLS credentials must be regular files at most 1 MiB",
        ));
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "TLS key must not be accessible to group or others",
            ));
        }
    }
    // The buffer owns its wipe duty before the first file byte is copied.
    let mut bytes = SecretBuffer::zeroed(MAX_TLS_FILE_BYTES + 1);
    let mut len = 0;
    while len < bytes.len() {
        match file.read(&mut bytes.expose_mut()[len..]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    if len > MAX_TLS_FILE_BYTES {
        return Err(invalid("TLS credential grew beyond 1 MiB"));
    }
    bytes.truncate(len);
    if !private && bytes.expose().windows(11).any(|w| w == b"PRIVATE KEY") {
        return Err(invalid("certificate files must not contain private keys"));
    }
    Ok(bytes)
}

fn certificates(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let bytes = read_pem(path, false)?;
    let certs = CertificateDer::pem_slice_iter(bytes.expose())
        .collect::<Result<Vec<_>, _>>()
        .map_err(tls_error)?;
    if certs.is_empty() {
        return Err(invalid("empty TLS certificate chain"));
    }
    Ok(certs)
}

fn roots(path: &Path) -> io::Result<rustls::RootCertStore> {
    let mut store = rustls::RootCertStore::empty();
    for cert in certificates(path)? {
        store.add(cert).map_err(tls_error)?;
    }
    Ok(store)
}

// Decode only one key block, keeping both base64 and DER scratch guarded.
// The upstream PEM iterator owns an ordinary base64 Vec; avoid it for keys.
fn signing_key(path: &Path) -> io::Result<Arc<dyn rustls::sign::SigningKey>> {
    let pem = read_pem(path, true)?;
    let mut encoded = SecretBuffer::zeroed(pem.len());
    let mut length = 0;
    let mut kind = None;
    let mut finished = false;
    for line in pem.expose().split(|byte| *byte == b'\n') {
        let line = line.trim_ascii();
        if line.is_empty() {
            continue;
        }
        if finished {
            return Err(invalid(
                "private key file must contain exactly one PEM block",
            ));
        }
        if kind.is_none() {
            kind = Some(match line {
                b"-----BEGIN PRIVATE KEY-----" => 0,
                b"-----BEGIN RSA PRIVATE KEY-----" => 1,
                b"-----BEGIN EC PRIVATE KEY-----" => 2,
                _ => return Err(invalid("unsupported private key PEM block")),
            });
        } else if line.starts_with(b"-----END ") {
            let end: &[u8] = match kind {
                Some(0) => b"-----END PRIVATE KEY-----",
                Some(1) => b"-----END RSA PRIVATE KEY-----",
                _ => b"-----END EC PRIVATE KEY-----",
            };
            if line != end {
                return Err(invalid("private key PEM labels do not match"));
            }
            finished = true;
        } else {
            encoded.expose_mut()[length..length + line.len()].copy_from_slice(line);
            length += line.len();
        }
    }
    if !finished || length == 0 {
        return Err(invalid("incomplete private key PEM block"));
    }
    let mut der = SecretBuffer::zeroed(length);
    let decoded = base64::engine::general_purpose::STANDARD
        .decode_slice(&encoded.expose()[..length], der.expose_mut())
        .map_err(tls_error)?;
    let key = match kind {
        Some(0) => PrivateKeyDer::Pkcs8(der.expose()[..decoded].into()),
        Some(1) => PrivateKeyDer::Pkcs1(der.expose()[..decoded].into()),
        _ => PrivateKeyDer::Sec1(der.expose()[..decoded].into()),
    };
    rustls::crypto::ring::sign::any_supported_type(&key).map_err(tls_error)
}

fn identity(files: &TlsFiles) -> io::Result<Arc<rustls::sign::SingleCertAndKey>> {
    let certified = rustls::sign::CertifiedKey::new(
        certificates(&files.cert_file)?,
        signing_key(&files.key_file)?,
    );
    certified.keys_match().map_err(tls_error)?;
    Ok(Arc::new(rustls::sign::SingleCertAndKey::from(certified)))
}

pub fn certificate_fingerprint(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Compute the allow-list identity from the first certificate in a PEM file.
pub fn certificate_file_fingerprint(path: &Path) -> io::Result<String> {
    Ok(certificate_fingerprint(&certificates(path)?[0]))
}

#[derive(Clone)]
pub struct Client {
    address: SocketAddr,
    server_name: ServerName<'static>,
    timeout: Duration,
    config: Arc<rustls::ClientConfig>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WitnessClient")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl Client {
    pub fn new(options: ClientOptions) -> io::Result<Self> {
        let timeout = timeout(options.timeout_ms)?;
        let server_name = ServerName::try_from(options.server_name).map_err(tls_error)?;
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls_error)?
        .with_root_certificates(roots(&options.tls.ca_file)?)
        .with_client_cert_resolver(identity(&options.tls)?);
        Ok(Self {
            address: options.address,
            server_name,
            timeout,
            config: Arc::new(config),
        })
    }

    pub fn call<Q: Serialize, R: DeserializeOwned>(&self, request: &Q) -> io::Result<R> {
        self.call_until(request, Instant::now() + self.timeout)
    }

    pub(crate) fn call_until<Q: Serialize, R: DeserializeOwned>(
        &self,
        request: &Q,
        deadline: Instant,
    ) -> io::Result<R> {
        let id = Uuid::new_v4();
        let bytes = serialize_frame(&WireRequest {
            version: WIRE_VERSION,
            id,
            request,
        })
        .map_err(|_| invalid("request serialization failed"))?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(invalid("witness request exceeds frame limit"));
        }
        let socket = TcpStream::connect_timeout(&self.address, remaining(deadline)?)?;
        socket.set_nodelay(true)?;
        let io = DeadlineIo { socket, deadline };
        let connection =
            rustls::ClientConnection::new(self.config.clone(), self.server_name.clone())
                .map_err(tls_error)?;
        let mut tls = rustls::StreamOwned::new(connection, io);
        write_frame(&mut tls, bytes.expose())?;
        let response: WireResponse<R> = serde_json::from_slice(read_frame(&mut tls)?.expose())
            .map_err(|_| corrupt("invalid witness response"))?;
        remaining(deadline)?;
        if response.version != WIRE_VERSION || response.id != id {
            return Err(corrupt("witness response version or request id mismatch"));
        }
        match (response.response, response.error) {
            (Some(value), None) => Ok(value),
            (None, Some(error)) => Err(match error {
                WireError::Conflict => {
                    io::Error::new(io::ErrorKind::WouldBlock, "witness predecessor conflict")
                }
                WireError::PermissionDenied => {
                    io::Error::new(io::ErrorKind::PermissionDenied, "witness operation denied")
                }
                WireError::InvalidRequest => invalid("witness request rejected"),
                WireError::Unavailable => {
                    io::Error::other("witness request failed; durable outcome may be unknown")
                }
            }),
            _ => Err(corrupt("ambiguous witness response")),
        }
    }
}

impl Rpc for Client {
    fn call(&self, request: &Request) -> io::Result<Record> {
        let record: Record = Client::call(self, request)?;
        record.validate()?;
        Ok(record)
    }
}

/// Serialize state transactions under the store's exclusive process lease.
/// Parsing precedes the lock; poison makes all subsequent calls fail closed.
pub fn state_handler(store: StateStore) -> Arc<Handler> {
    let store = Mutex::new(store);
    Arc::new(move |role, request| {
        let request: Request =
            serde_json::from_slice(request).map_err(|_| invalid("invalid witness operation"))?;
        let mut store = store
            .lock()
            .map_err(|_| io::Error::other("witness store poisoned"))?;
        let record = store.handle(role, &request)?;
        serde_json::to_value(record).map_err(|_| corrupt("invalid witness state"))
    })
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "witness RPC deadline expired"))
}

struct DeadlineIo {
    socket: TcpStream,
    deadline: Instant,
}

type ServerStream = rustls::StreamOwned<rustls::ServerConnection, DeadlineIo>;
impl Read for DeadlineIo {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.socket
            .set_read_timeout(Some(remaining(self.deadline)?))?;
        self.socket.read(bytes).map_err(deadline_error)
    }
}
impl Write for DeadlineIo {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.socket
            .set_write_timeout(Some(remaining(self.deadline)?))?;
        self.socket.write(bytes).map_err(deadline_error)
    }
    fn flush(&mut self) -> io::Result<()> {
        remaining(self.deadline).map(|_| ())
    }
}
fn deadline_error(error: io::Error) -> io::Error {
    if error.kind() == io::ErrorKind::WouldBlock {
        io::Error::new(io::ErrorKind::TimedOut, "witness RPC deadline expired")
    } else {
        error
    }
}

/// Request bytes borrow guarded frame storage; parse capabilities directly into
/// their zeroizing type, never through an ordinary `serde_json::Value` tree.
pub type Handler = dyn Fn(Role, &[u8]) -> io::Result<serde_json::Value> + Send + Sync;

pub struct Server {
    config: Arc<rustls::ServerConfig>,
    principals: BTreeMap<String, Role>,
    timeout: Duration,
    max_connections: usize,
    active: Arc<AtomicUsize>,
}

/// Connections that have not yet been given a worker slot, oldest first.
/// Each entry holds a duplicate of the socket so it can be cut off.
struct Handshakes {
    capacity: usize,
    task_capacity: usize,
    state: Mutex<HandshakeState>,
    released: Condvar,
}

struct HandshakeState {
    next_id: u64,
    live: usize,
    pending: VecDeque<PendingHandshake>,
}

struct PendingHandshake {
    id: u64,
    socket: TcpStream,
    cancelled: Arc<AtomicBool>,
}

/// Charges a connection task until its TLS state and request processing end,
/// including after its pending handshake is evicted.
struct HandshakeTicket {
    table: Arc<Handshakes>,
    id: u64,
    cancelled: Arc<AtomicBool>,
}

impl Handshakes {
    fn new(workers: usize) -> Self {
        Self {
            capacity: workers * 4,
            task_capacity: workers * 5,
            state: Mutex::new(HandshakeState {
                next_id: 0,
                live: 0,
                pending: VecDeque::new(),
            }),
            released: Condvar::new(),
        }
    }

    fn admit(
        self: &Arc<Self>,
        socket: &TcpStream,
        deadline: Instant,
    ) -> io::Result<HandshakeTicket> {
        let duplicate = socket.try_clone()?;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while state.pending.len() >= self.capacity {
            if let Some(oldest) = state.pending.pop_front() {
                // A TLS read observes shutdown; an authenticated permit
                // waiter observes cancellation. Neither releases task
                // capacity until its connection task actually exits.
                oldest.cancelled.store(true, Ordering::Release);
                let _ = oldest.socket.shutdown(Shutdown::Both);
            }
        }
        while state.live >= self.task_capacity {
            state = self
                .released
                .wait_timeout(state, remaining(deadline)?)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
        remaining(deadline)?;
        let id = state.next_id;
        state.next_id = state.next_id.wrapping_add(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        state.pending.push_back(PendingHandshake {
            id,
            socket: duplicate,
            cancelled: cancelled.clone(),
        });
        state.live += 1;
        Ok(HandshakeTicket {
            table: self.clone(),
            id,
            cancelled,
        })
    }
}

impl HandshakeTicket {
    fn check_cancelled(&self) -> io::Result<()> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "witness pending connection evicted",
            ));
        }
        Ok(())
    }

    fn worker_acquired(&self) -> io::Result<()> {
        let mut state = self
            .table
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.check_cancelled()?;
        state.pending.retain(|pending| pending.id != self.id);
        Ok(())
    }
}

impl Drop for HandshakeTicket {
    fn drop(&mut self) {
        let mut state = self
            .table
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.pending.retain(|pending| pending.id != self.id);
        state.live -= 1;
        self.table.released.notify_one();
    }
}

/// Pause after a failed `accept` before trying again.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// Its drop releases capacity on success, authentication failure, and unwind.
pub struct ConnectionPermit(Arc<AtomicUsize>);
impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Server {
    pub fn new(options: ServerOptions) -> io::Result<Self> {
        let timeout = timeout(options.timeout_ms)?;
        if !(1..=256).contains(&options.max_connections) {
            return Err(invalid("max_connections must be in 1..=256"));
        }
        if options.principals.is_empty() || options.principals.len() > 256 {
            return Err(invalid(
                "between 1 and 256 certificate principals are required",
            ));
        }
        let mut principals = BTreeMap::new();
        for principal in options.principals {
            if principal.certificate_sha256.len() != 64
                || !principal
                    .certificate_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(invalid(
                    "principal fingerprint must be 64 lower-case hex characters",
                ));
            }
            if principals
                .insert(principal.certificate_sha256, principal.role)
                .is_some()
            {
                return Err(invalid("duplicate certificate principal"));
            }
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots(&options.tls.ca_file)?),
            provider.clone(),
        )
        .build()
        .map_err(tls_error)?;
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(tls_error)?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(identity(&options.tls)?);
        Ok(Self {
            config: Arc::new(config),
            principals,
            timeout,
            max_connections: options.max_connections,
            active: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub fn try_reserve_connection(&self) -> io::Result<ConnectionPermit> {
        let mut current = self.active.load(Ordering::Acquire);
        loop {
            if current >= self.max_connections {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "witness connection limit reached",
                ));
            }
            match self.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
        Ok(ConnectionPermit(self.active.clone()))
    }

    /// Handle exactly one connection, sharing one absolute network deadline.
    /// The production accept loop bounds pending handshakes and takes a
    /// worker permit only after authentication (see [`Server::serve`]).
    pub fn handle_connection(&self, socket: TcpStream, handler: &Handler) -> io::Result<()> {
        self.handle_until(socket, Instant::now() + self.timeout, handler)
    }

    fn handle_until(
        &self,
        socket: TcpStream,
        deadline: Instant,
        handler: &Handler,
    ) -> io::Result<()> {
        let (tls, role) = self.authenticate(socket, deadline)?;
        self.respond(tls, role, deadline, handler)
    }

    /// TLS 1.3 with a listed client certificate, mapped to its role.
    fn authenticate(
        &self,
        socket: TcpStream,
        deadline: Instant,
    ) -> io::Result<(ServerStream, Role)> {
        socket.set_nodelay(true)?;
        let mut io = DeadlineIo { socket, deadline };
        let mut connection =
            rustls::ServerConnection::new(self.config.clone()).map_err(tls_error)?;
        while connection.is_handshaking() {
            connection.complete_io(&mut io)?;
        }
        let certificate = connection
            .peer_certificates()
            .and_then(|chain| chain.first())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "client certificate required",
                )
            })?;
        let role = self
            .principals
            .get(&certificate_fingerprint(certificate))
            .copied()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unlisted client certificate",
                )
            })?;
        Ok((rustls::StreamOwned::new(connection, io), role))
    }

    fn respond(
        &self,
        mut tls: ServerStream,
        role: Role,
        deadline: Instant,
        handler: &Handler,
    ) -> io::Result<()> {
        let frame = read_frame(&mut tls)?;
        let request: IncomingRequest<'_> = serde_json::from_slice(frame.expose())
            .map_err(|_| corrupt("invalid witness request"))?;
        if request.version != WIRE_VERSION {
            return Err(corrupt("unsupported witness wire version"));
        }
        remaining(deadline)?;
        let (response, error) = match handler(role, request.request.get().as_bytes()) {
            Ok(response) => (Some(response), None),
            Err(error) => (
                None,
                Some(match error.kind() {
                    io::ErrorKind::WouldBlock => WireError::Conflict,
                    io::ErrorKind::PermissionDenied => WireError::PermissionDenied,
                    io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => {
                        WireError::InvalidRequest
                    }
                    _ => WireError::Unavailable,
                }),
            ),
        };
        remaining(deadline)?;
        let bytes = serialize_frame(&WireResponse {
            version: WIRE_VERSION,
            id: request.id,
            response,
            error,
        })
        .map_err(|_| corrupt("witness response serialization failed"))?;
        write_frame(&mut tls, bytes.expose())
    }

    /// Serve connections, retrying accept and thread-creation failures.
    ///
    /// A worker slot (`max_connections`) is taken only after TLS has
    /// authenticated a listed certificate, and an authenticated connection
    /// waits for one until its deadline or eviction. Before
    /// that, a connection only holds a handshake slot: those are bounded at
    /// four per worker, and when they are all taken the oldest pending
    /// handshake is cancelled and cut off. A separate lifetime charge bounds
    /// all connection tasks (including evicted tasks and their TLS objects)
    /// to five per worker. Admission waits for reclamation before spawning
    /// another task. Idle unauthenticated sockets therefore cannot starve a
    /// client that completes TLS promptly (BUG-104).
    pub fn serve(self: Arc<Self>, listener: TcpListener, handler: Arc<Handler>) -> io::Result<()> {
        let handshakes = Arc::new(Handshakes::new(self.max_connections));
        self.serve_incoming(listener.incoming(), handler, handshakes, |task| {
            std::thread::Builder::new()
                .name("maki-witness-rpc".into())
                .spawn(task)
                .map(|_| ())
        })
    }

    fn serve_incoming(
        self: Arc<Self>,
        incoming: impl IntoIterator<Item = io::Result<TcpStream>>,
        handler: Arc<Handler>,
        handshakes: Arc<Handshakes>,
        mut spawn: impl FnMut(Box<dyn FnOnce() + Send>) -> io::Result<()>,
    ) -> io::Result<()> {
        for accepted in incoming {
            let socket = match accepted {
                Ok(socket) => socket,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                // BUG-111: running out of descriptors or buffers (EMFILE,
                // ENFILE, ENOBUFS), or a connection aborted before accept,
                // is transient. Returning ended the service and with it the
                // freshness authority of every volume using it. Pause so a
                // persistent failure does not spin, and keep accepting, as
                // the control socket does (O-04).
                Err(_) => {
                    std::thread::sleep(ACCEPT_BACKOFF);
                    continue;
                }
            };
            let deadline = Instant::now() + self.timeout;
            let Ok(ticket) = handshakes.admit(&socket, deadline) else {
                continue;
            };
            let server = self.clone();
            let handler = handler.clone();
            let spawned = spawn(Box::new(move || {
                // Keep this outside the inner closure so TLS state is
                // destroyed before the task's lifetime charge releases.
                let ticket = ticket;
                // No application payloads or remote error text are logged.
                let _ = (|| {
                    let (tls, role) = server.authenticate(socket, deadline)?;
                    let _permit = server.reserve_until(deadline, &ticket)?;
                    ticket.worker_acquired()?;
                    server.respond(tls, role, deadline, handler.as_ref())
                })();
            }));
            if spawned.is_err() {
                // Thread creation can hit the same transient resource
                // pressure as accept. Dropping the failed task closes its
                // socket and releases its ticket; keep the listener alive.
                std::thread::sleep(ACCEPT_BACKOFF);
            }
        }
        Ok(())
    }

    /// Wait for a worker slot until `deadline`, observing handshake eviction.
    fn reserve_until(
        &self,
        deadline: Instant,
        ticket: &HandshakeTicket,
    ) -> io::Result<ConnectionPermit> {
        loop {
            ticket.check_cancelled()?;
            let remaining = remaining(deadline)?;
            if let Ok(permit) = self.try_reserve_connection() {
                return Ok(permit);
            }
            std::thread::sleep(remaining.min(Duration::from_millis(2)));
        }
    }
}

// The limit applies while serializing, before any allocation can grow to the
// size of a caller's unbounded request or response.
fn serialize_frame(value: &impl Serialize) -> io::Result<SecretBuffer> {
    struct Bounded(SecretBuffer);
    impl Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > MAX_FRAME_BYTES - self.0.len() {
                return Err(invalid("witness serialization exceeds frame limit"));
            }
            self.0
                .try_extend_from_slice(bytes)
                .map_err(|_| invalid("witness serialization exceeds frame limit"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut output = Bounded(
        SecretBuffer::with_capacity(MAX_FRAME_BYTES)
            .map_err(|_| io::Error::other("witness frame allocation failed"))?,
    );
    serde_json::to_writer(&mut output, value)
        .map_err(|_| invalid("witness serialization failed or exceeded frame limit"))?;
    Ok(output.0)
}

fn read_frame(input: &mut impl Read) -> io::Result<SecretBuffer> {
    let mut header = [0; 4];
    input.read_exact(&mut header)?;
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 || len > MAX_FRAME_BYTES {
        return Err(corrupt("invalid witness frame size"));
    }
    let mut bytes = SecretBuffer::zeroed(len);
    input.read_exact(bytes.expose_mut())?;
    Ok(bytes)
}

fn write_frame(output: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(invalid("invalid witness frame size"));
    }
    output.write_all(&(bytes.len() as u32).to_be_bytes())?;
    output.write_all(bytes)?;
    output.flush()
}

#[cfg(test)]
mod server_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, b"metadata").unwrap();
        assert_eq!(
            read_frame(&mut bytes.as_slice()).unwrap().expose(),
            b"metadata"
        );
    }

    #[test]
    fn oversized_frame_is_rejected_before_reading_body() {
        let header = ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes();
        assert_eq!(
            read_frame(&mut header.as_slice()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn zero_length_and_truncated_frames_are_rejected() {
        assert_eq!(
            read_frame(&mut [0, 0, 0, 0].as_slice()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            read_frame(&mut [0, 0, 0].as_slice()).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            read_frame(&mut [0, 0, 0, 2, b'a'].as_slice())
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn outbound_oversize_never_writes_a_prefix() {
        let mut output = Vec::new();
        assert_eq!(
            write_frame(&mut output, &vec![0; MAX_FRAME_BYTES + 1])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(output.is_empty());
    }
}
