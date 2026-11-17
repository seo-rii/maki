//! audit2 (decoder-fuzz): structure-aware mutation of the witness wire
//! frames in both directions, over real TLS 1.3 connections.
//!
//! * Server side: an authenticated peer sends mutated frames (length
//!   prefix, envelope JSON, `Request` JSON) to `Server::handle_connection`
//!   running `state_handler`. Properties: no panic, the call returns, the
//!   server thread's peak allocation stays bounded, any response frame is a
//!   well-formed v2 envelope with exactly one of response/error.
//! * Client side: a fake TLS server answers `Client`'s request with mutated
//!   response frames. Properties: no panic, bounded client allocation, and
//!   an `Ok` only for a matching id/version envelope carrying a record
//!   that validates.
//!
//! maki-witness has no `rand` dev-dependency; a SplitMix64 generator keeps
//! the runs deterministic per seed.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use maki_backing::remote_witness::{namespace, Action, Descriptor, Phase, Record, Request, Rpc, StateStore};
use maki_backing::witness::Anchor;
use maki_witness::{
    certificate_fingerprint, state_handler, Client, ClientOptions, Principal, Role, Server,
    ServerOptions, TlsFiles,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use serde_json::{json, Value};

// ---------------------------------------------------------------- allocator

struct Counting;
thread_local! {
    static LIVE: Cell<isize> = const { Cell::new(0) };
    static PEAK: Cell<isize> = const { Cell::new(0) };
}
fn note_alloc(size: usize) {
    let _ = LIVE.try_with(|live| {
        let now = live.get() + size as isize;
        live.set(now);
        let _ = PEAK.try_with(|peak| {
            if now > peak.get() {
                peak.set(now)
            }
        });
    });
}
fn note_free(size: usize) {
    let _ = LIVE.try_with(|live| live.set(live.get() - size as isize));
}
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note_alloc(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note_alloc(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        note_free(layout.size());
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note_free(layout.size());
        note_alloc(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}
#[global_allocator]
static GLOBAL: Counting = Counting;

fn measured<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let start = LIVE.with(|l| l.get());
    PEAK.with(|p| p.set(start));
    let out = f();
    let peak = PEAK.with(|p| p.get());
    (out, (peak - start).max(0) as usize)
}

fn panic_text(p: Box<dyn std::any::Any + Send>) -> String {
    p.downcast_ref::<String>()
        .cloned()
        .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default()
}

// ---------------------------------------------------------------- prng

struct Prng(u64);
impl Prng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }
}

// ---------------------------------------------------------------- TLS fixture

fn write_identity(dir: &Path, name: &str, cert: &rcgen::CertifiedKey, ca: &str) -> TlsFiles {
    let tls = TlsFiles {
        ca_file: dir.join(format!("{name}.ca.pem")),
        cert_file: dir.join(format!("{name}.cert.pem")),
        key_file: dir.join(format!("{name}.key.pem")),
    };
    std::fs::write(&tls.ca_file, ca).unwrap();
    std::fs::write(&tls.cert_file, cert.cert.pem()).unwrap();
    std::fs::write(&tls.key_file, cert.key_pair.serialize_pem()).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&tls.key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    tls
}

struct Pki {
    _dir: tempfile::TempDir,
    server: TlsFiles,
    alice: TlsFiles,
    fingerprint: String,
}

fn pki() -> Pki {
    let dir = tempfile::tempdir().unwrap();
    let server = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let alice = rcgen::generate_simple_self_signed(vec!["alice".to_owned()]).unwrap();
    Pki {
        server: write_identity(dir.path(), "server", &server, &alice.cert.pem()),
        alice: write_identity(dir.path(), "alice", &alice, &server.cert.pem()),
        fingerprint: certificate_fingerprint(alice.cert.der()),
        _dir: dir,
    }
}

fn raw_client(pki: &Pki, address: std::net::SocketAddr) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_file(&pki.server.cert_file).unwrap())
        .unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_client_auth_cert(
        vec![CertificateDer::from_pem_file(&pki.alice.cert_file).unwrap()],
        PrivateKeyDer::from_pem_file(&pki.alice.key_file).unwrap(),
    )
    .unwrap();
    let socket = TcpStream::connect(address).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    rustls::StreamOwned::new(
        rustls::ClientConnection::new(Arc::new(config), ServerName::try_from("localhost").unwrap())
            .unwrap(),
        socket,
    )
}

// ---------------------------------------------------------------- JSON mutation

const ID: [u8; 16] = [0x11; 16];

fn record_json(rng: &mut Prng) -> Value {
    let fence = rng.below(4) + 1;
    let session = [rng.below(3) as u8 + 1; 16];
    let record = Record {
        identity: ID,
        current: Some(Descriptor {
            anchor: Anchor {
                identity: ID,
                generation: rng.below(5),
                root: [3; 32],
            },
            epoch: 0,
            namespace: namespace(fence, session),
        }),
        fence,
        session,
        phase: Phase::Active,
        restore_source: None,
        last_operation: [7; 16],
    };
    serde_json::to_value(record).unwrap()
}

fn request_json(rng: &mut Prng) -> Value {
    let action = match rng.below(5) {
        0 => Action::Claim,
        1 => Action::Release,
        2 => Action::Takeover,
        3 => Action::RecoverEnrollment,
        _ => Action::Inspect,
    };
    let mut v = serde_json::to_value(Request {
        operation_id: [rng.below(4) as u8; 16],
        expected: if rng.chance(50) { None } else { serde_json::from_value(record_json(rng)).ok() },
        action,
        authorization: None,
    })
    .unwrap();
    if rng.chance(40) {
        v["authorization"] = json!(vec![rng.below(255); 32]);
    }
    v
}

fn odd_value(rng: &mut Prng) -> Value {
    match rng.below(14) {
        0 => Value::Null,
        1 => json!(u64::MAX),
        2 => json!(-1),
        3 => json!(1e308),
        4 => json!("x".repeat(rng.below(3000) as usize)),
        5 => json!([]),
        6 => json!({}),
        7 => json!(true),
        8 => json!("\u{0000}\u{ffff}\\\"/"),
        9 => json!(vec![255u8; 33]),
        10 => json!(vec![1u8; 15]),
        11 => json!(vec![json!(256); 16]),
        12 => {
            let mut v = json!(0);
            for _ in 0..rng.below(200) {
                v = json!([v]);
            }
            v
        }
        _ => json!(rng.next()),
    }
}

/// Replace, remove or add one node somewhere in `v`.
fn mutate_value(rng: &mut Prng, v: &mut Value, depth: usize) {
    let descend = depth < 6 && rng.chance(65);
    match v {
        Value::Object(map) if !map.is_empty() => {
            let keys: Vec<String> = map.keys().cloned().collect();
            let key = rng.pick(&keys).clone();
            if descend {
                mutate_value(rng, map.get_mut(&key).unwrap(), depth + 1);
            } else {
                match rng.below(3) {
                    0 => {
                        map.remove(&key);
                    }
                    1 => {
                        map.insert(format!("{key}_extra"), odd_value(rng));
                    }
                    _ => {
                        map.insert(key, odd_value(rng));
                    }
                }
            }
        }
        Value::Array(items) if !items.is_empty() => {
            let i = rng.below(items.len() as u64) as usize;
            if descend {
                mutate_value(rng, &mut items[i], depth + 1);
            } else {
                match rng.below(3) {
                    0 => {
                        items.remove(i);
                    }
                    1 => items.push(odd_value(rng)),
                    _ => items[i] = odd_value(rng),
                }
            }
        }
        _ => *v = odd_value(rng),
    }
}

fn mutate_bytes(rng: &mut Prng, b: &mut Vec<u8>) {
    for _ in 0..rng.below(3) + 1 {
        if b.is_empty() {
            b.push(b'{');
        }
        let at = rng.below(b.len() as u64) as usize;
        match rng.below(4) {
            0 => b[at] = *rng.pick(b"{}[],:\"0123456789eE-+.\\nul"),
            1 => b.insert(at, *rng.pick(b"{}[],:\"0123456789")),
            2 => {
                b.remove(at);
            }
            _ => b.truncate(at),
        }
    }
}

/// A frame: length prefix + payload, possibly lying about its length.
fn frame(rng: &mut Prng, payload: &[u8]) -> (Vec<u8>, &'static str) {
    let len = payload.len() as u32;
    let mut out = Vec::new();
    let kind = match rng.below(20) {
        0 => {
            out.extend_from_slice(&0u32.to_be_bytes());
            "zero length"
        }
        1 => {
            out.extend_from_slice(&(64 * 1024 + 1u32).to_be_bytes());
            out.extend_from_slice(payload);
            "oversize length"
        }
        2 => {
            out.extend_from_slice(&u32::MAX.to_be_bytes());
            "u32::MAX length"
        }
        3 => {
            out.extend_from_slice(&(len + 1 + rng.below(100) as u32).to_be_bytes());
            out.extend_from_slice(payload);
            "length longer than body"
        }
        4 if len > 1 => {
            out.extend_from_slice(&(len - 1).to_be_bytes());
            out.extend_from_slice(payload);
            "length shorter than body"
        }
        5 => {
            out.extend_from_slice(&len.to_be_bytes()[..rng.below(4) as usize]);
            "truncated prefix"
        }
        6 => {
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(payload);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(payload);
            "two frames"
        }
        _ => {
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(payload);
            "exact"
        }
    };
    (out, kind)
}

fn valid_envelope_response(v: &Value) -> Result<(), String> {
    let obj = v.as_object().ok_or("response is not an object")?;
    if obj.get("version") != Some(&json!(2)) {
        return Err(format!("response version {:?}", obj.get("version")));
    }
    let response = obj.get("response").cloned().unwrap_or(Value::Null);
    let error = obj.get("error").cloned().unwrap_or(Value::Null);
    if response.is_null() == error.is_null() {
        return Err(format!("response/error both or neither: {v}"));
    }
    Ok(())
}

// ---------------------------------------------------------------- server side

#[test]
fn server_survives_mutated_request_frames() {
    let seed = 0xF4A3_0001;
    let mut rng = Prng(seed);
    let pki = pki();
    let store_dir = tempfile::tempdir().unwrap();
    let handler = state_handler(StateStore::create(store_dir.path(), ID).unwrap());
    let server = Arc::new(
        Server::new(ServerOptions {
            tls: pki.server.clone(),
            principals: vec![Principal {
                certificate_sha256: pki.fingerprint.clone(),
                role: Role::Admin,
            }],
            timeout_ms: 3000,
            max_connections: 4,
        })
        .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let iterations = 1500u64;
    let (tx, rx) = mpsc::channel();
    let srv = server.clone();
    let worker = std::thread::spawn(move || {
        for _ in 0..iterations {
            let (socket, _) = listener.accept().unwrap();
            let started = Instant::now();
            let r = catch_unwind(AssertUnwindSafe(|| {
                measured(|| srv.handle_connection(socket, handler.as_ref()))
            }));
            let outcome = match r {
                Err(p) => Err(format!("handle_connection panicked: {}", panic_text(p))),
                Ok((result, peak)) => Ok((result.map_err(|e| e.kind()), peak, started.elapsed())),
            };
            tx.send(outcome).unwrap();
        }
    });
    let mut failures = Vec::new();
    let mut answered = 0u64;
    let mut max_peak = 0usize;
    let mut kinds = std::collections::BTreeMap::new();
    for i in 0..iterations {
        let mut envelope = json!({
            "version": 2,
            "id": uuid::Uuid::from_u128(rng.next() as u128).to_string(),
            "request": request_json(&mut rng),
        });
        let payload = match rng.below(4) {
            0 => serde_json::to_vec(&envelope).unwrap(),
            1 | 2 => {
                for _ in 0..rng.below(3) + 1 {
                    mutate_value(&mut rng, &mut envelope, 0);
                }
                serde_json::to_vec(&envelope).unwrap()
            }
            _ => {
                let mut b = serde_json::to_vec(&envelope).unwrap();
                mutate_bytes(&mut rng, &mut b);
                b
            }
        };
        let (bytes, kind) = frame(&mut rng, &payload);
        *kinds.entry(kind).or_insert(0u64) += 1;
        let mut tls = raw_client(&pki, address);
        let _ = tls.write_all(&bytes);
        let _ = tls.flush();
        if kind != "exact" || rng.chance(30) {
            let _ = tls.conn.send_close_notify();
            let _ = tls.flush();
            let _ = tls.sock.shutdown(std::net::Shutdown::Write);
        }
        let mut header = [0u8; 4];
        if tls.read_exact(&mut header).is_ok() {
            let len = u32::from_be_bytes(header) as usize;
            if len == 0 || len > 64 * 1024 {
                failures.push(format!("iter {i}: response frame length {len}"));
            } else {
                let mut body = vec![0; len];
                if tls.read_exact(&mut body).is_ok() {
                    answered += 1;
                    match serde_json::from_slice::<Value>(&body) {
                        Ok(v) => {
                            if let Err(e) = valid_envelope_response(&v) {
                                failures.push(format!("iter {i} ({kind}): {e}"));
                            }
                        }
                        Err(e) => failures.push(format!("iter {i}: response is not JSON: {e}")),
                    }
                }
            }
        }
        drop(tls);
        match rx.recv_timeout(Duration::from_secs(10)) {
            Err(_) => {
                failures.push(format!("iter {i} ({kind}): server did not return"));
                break;
            }
            Ok(Err(e)) => failures.push(format!("iter {i} ({kind}): {e}")),
            Ok(Ok((_, peak, elapsed))) => {
                max_peak = max_peak.max(peak);
                if peak > 4 << 20 {
                    failures.push(format!("iter {i} ({kind}): server peak allocation {peak}"));
                }
                if elapsed > Duration::from_millis(3500) {
                    failures.push(format!("iter {i} ({kind}): server took {elapsed:?}"));
                }
            }
        }
    }
    let _ = worker.join();
    eprintln!(
        "[audit2 wire] server: seed {seed:#x} {iterations} connections, {answered} answered, \
         frame kinds {kinds:?}, max server peak {max_peak} bytes"
    );
    for f in failures.iter().take(10) {
        eprintln!("[audit2 wire]   {f}");
    }
    assert!(failures.is_empty(), "{} failures", failures.len());
}

// ---------------------------------------------------------------- client side

fn fake_server_config(pki: &Pki) -> Arc<rustls::ServerConfig> {
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from_pem_file(&pki.server.cert_file).unwrap()],
        PrivateKeyDer::from_pem_file(&pki.server.key_file).unwrap(),
    )
    .unwrap();
    config.send_tls13_tickets = 0;
    Arc::new(config)
}

fn read_request_id(tls: &mut impl Read) -> Option<String> {
    let mut header = [0u8; 4];
    tls.read_exact(&mut header).ok()?;
    let len = u32::from_be_bytes(header) as usize;
    let mut body = vec![0; len.min(1 << 20)];
    tls.read_exact(&mut body).ok()?;
    let v: Value = serde_json::from_slice(&body).ok()?;
    v.get("id")?.as_str().map(str::to_owned)
}

#[test]
fn client_survives_mutated_response_frames() {
    let seed = 0xF4A3_0002;
    let mut rng = Prng(seed);
    let pki = pki();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let client = Client::new(ClientOptions {
        address,
        server_name: "localhost".into(),
        timeout_ms: 3000,
        tls: pki.alice.clone(),
    })
    .unwrap();
    let config = fake_server_config(&pki);
    let iterations = 1500u64;
    let server_seed = rng.next();
    let fake = std::thread::spawn(move || {
        let mut rng = Prng(server_seed);
        let mut plan = Vec::new();
        for _ in 0..iterations {
            let Ok((socket, _)) = listener.accept() else { break };
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let conn = rustls::ServerConnection::new(config.clone()).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, socket);
            let Some(id) = read_request_id(&mut tls) else {
                plan.push(("no request", false));
                continue;
            };
            let _ = &mut rng;
            let mut envelope = json!({
                "version": 2,
                "id": id,
                "response": record_json(&mut rng),
                "error": null,
            });
            // must_refuse: the client must not return Ok for this answer.
            let mut must_refuse = false;
            match rng.below(8) {
                0 => {}
                1 => {
                    envelope["response"] = Value::Null;
                    envelope["error"] = json!(*rng.pick(&["conflict", "permission_denied", "invalid_request", "unavailable", "bogus"]));
                    must_refuse = true;
                }
                2 => {
                    envelope["error"] = json!("conflict");
                    must_refuse = true;
                }
                3 => {
                    envelope["id"] = json!(uuid::Uuid::from_u128(rng.next() as u128).to_string());
                    must_refuse = true;
                }
                4 => {
                    envelope["version"] = json!(*rng.pick(&[1, 3, -1]));
                    must_refuse = true;
                }
                _ => {
                    for _ in 0..rng.below(3) + 1 {
                        mutate_value(&mut rng, &mut envelope, 0);
                    }
                }
            }
            let mut payload = serde_json::to_vec(&envelope).unwrap();
            if rng.chance(15) {
                mutate_bytes(&mut rng, &mut payload);
            }
            let (bytes, kind) = frame(&mut rng, &payload);
            if !matches!(kind, "exact" | "two frames") {
                must_refuse = true;
            }
            let intact = !must_refuse;
            let _ = tls.write_all(&bytes);
            let _ = tls.flush();
            let _ = tls.conn.send_close_notify();
            let _ = tls.flush();
            plan.push((kind, intact));
        }
        plan
    });
    let mut failures = Vec::new();
    let mut outcomes = std::collections::BTreeMap::new();
    let mut max_peak = 0usize;
    let mut results = Vec::new();
    for i in 0..iterations {
        let request = Request {
            operation_id: [0; 16],
            expected: None,
            action: Action::Inspect,
            authorization: None,
        };
        let r = catch_unwind(AssertUnwindSafe(|| {
            measured(|| <Client as Rpc>::call(&client, &request))
        }));
        match r {
            Err(p) => failures.push(format!("iter {i}: Client::call panicked: {}", panic_text(p))),
            Ok((result, peak)) => {
                max_peak = max_peak.max(peak);
                if peak > 4 << 20 {
                    failures.push(format!("iter {i}: client peak allocation {peak}"));
                }
                if let Ok(record) = &result {
                    if let Err(e) = record.validate() {
                        failures.push(format!("iter {i}: accepted invalid record: {e}"));
                    }
                }
                let key = match &result {
                    Ok(_) => "ok".to_string(),
                    Err(e) => format!("{:?}", e.kind()),
                };
                *outcomes.entry(key).or_insert(0u64) += 1;
                results.push(result.is_ok());
            }
        }
    }
    let plan = fake.join().unwrap();
    for (i, (ok, (kind, intact))) in results.iter().zip(plan.iter()).enumerate() {
        if *ok && !intact {
            failures.push(format!("iter {i}: client accepted a mutated response ({kind})"));
        }
    }
    eprintln!(
        "[audit2 wire] client: seed {seed:#x} {iterations} responses, outcomes {outcomes:?}, \
         max client peak {max_peak} bytes"
    );
    for f in failures.iter().take(10) {
        eprintln!("[audit2 wire]   {f}");
    }
    assert!(failures.is_empty(), "{} failures", failures.len());
}

#[allow(dead_code)]
fn unused(_: io::Error) {}
