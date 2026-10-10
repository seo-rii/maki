use std::io;
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::sync::{mpsc, Arc};

use maki_witness::{
    certificate_fingerprint, Client, ClientOptions, Principal, Role, Server, ServerOptions,
    TlsFiles,
};
use serde_json::{json, Value};

struct Fixture {
    dir: tempfile::TempDir,
    server: TlsFiles,
    alice: TlsFiles,
    bob: TlsFiles,
    fingerprint: String,
}

fn identity(dir: &Path, name: &str, cert: &rcgen::CertifiedKey, ca: &str) -> TlsFiles {
    let ca_file = dir.join(format!("{name}.ca.pem"));
    let cert_file = dir.join(format!("{name}.cert.pem"));
    let key_file = dir.join(format!("{name}.key.pem"));
    std::fs::write(&ca_file, ca).unwrap();
    std::fs::write(&cert_file, cert.cert.pem()).unwrap();
    std::fs::write(&key_file, cert.key_pair.serialize_pem()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    TlsFiles {
        ca_file,
        cert_file,
        key_file,
    }
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let server = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let alice = rcgen::generate_simple_self_signed(vec!["alice".to_owned()]).unwrap();
        let bob = rcgen::generate_simple_self_signed(vec!["bob".to_owned()]).unwrap();
        let clients = format!("{}{}", alice.cert.pem(), bob.cert.pem());
        Self {
            server: identity(dir.path(), "server", &server, &clients),
            alice: identity(dir.path(), "alice", &alice, &server.cert.pem()),
            bob: identity(dir.path(), "bob", &bob, &server.cert.pem()),
            fingerprint: certificate_fingerprint(alice.cert.der()),
            dir,
        }
    }

    fn server(&self) -> Server {
        Server::new(ServerOptions {
            tls: self.server.clone(),
            principals: vec![Principal {
                certificate_sha256: self.fingerprint.clone(),
                role: Role::Writer,
            }],
            timeout_ms: 500,
            max_connections: 2,
        })
        .unwrap()
    }

    fn client(&self, address: SocketAddr) -> ClientOptions {
        ClientOptions {
            address,
            server_name: "localhost".into(),
            timeout_ms: 500,
            tls: self.alice.clone(),
        }
    }
}

fn serve_once(server: Server) -> (SocketAddr, std::thread::JoinHandle<io::Result<()>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let thread = std::thread::spawn(move || {
        let (stream, _) = listener.accept()?;
        server.handle_connection(stream, &|role, request: Value| {
            assert_eq!(role, Role::Writer);
            Ok(request)
        })
    });
    (address, thread)
}

#[test]
fn authenticated_roundtrip_binds_writer_identity() {
    let fixture = Fixture::new();
    let (address, worker) = serve_once(fixture.server());
    let result: Value = Client::new(fixture.client(address))
        .unwrap()
        .call(&json!({"inspect": true}))
        .unwrap();
    assert_eq!(result, json!({"inspect": true}));
    worker.join().unwrap().unwrap();
}

#[test]
fn trusted_but_unlisted_certificate_never_reaches_handler() {
    let fixture = Fixture::new();
    let (address, worker) = serve_once(fixture.server());
    let mut options = fixture.client(address);
    options.tls = fixture.bob.clone();
    assert!(Client::new(options)
        .unwrap()
        .call::<_, Value>(&json!({}))
        .is_err());
    assert_eq!(
        worker.join().unwrap().unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
}

#[test]
fn wrong_hostname_and_untrusted_server_are_rejected() {
    let fixture = Fixture::new();
    for wrong_name in [true, false] {
        let (address, worker) = serve_once(fixture.server());
        let mut options = fixture.client(address);
        if wrong_name {
            options.server_name = "wrong.invalid".into();
        } else {
            options.tls.ca_file = fixture.bob.cert_file.clone();
        }
        assert!(Client::new(options)
            .unwrap()
            .call::<_, Value>(&json!({}))
            .is_err());
        assert!(worker.join().unwrap().is_err());
    }
}

#[test]
fn stalled_handshake_expires_and_does_not_retry() {
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (release, wait) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        wait.recv().unwrap();
        drop(stream);
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    });
    let mut options = fixture.client(address);
    options.timeout_ms = 50;
    assert_eq!(
        Client::new(options)
            .unwrap()
            .call::<_, Value>(&json!({}))
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    release.send(()).unwrap();
    worker.join().unwrap();
}

#[test]
fn tls_key_permissions_and_symlinks_are_refused() {
    let fixture = Fixture::new();
    let mut options = fixture.client("127.0.0.1:1".parse().unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt};
        std::fs::set_permissions(
            &options.tls.key_file,
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(Client::new(options.clone()).is_err());
        std::fs::set_permissions(
            &options.tls.key_file,
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let link = fixture.dir.path().join("key-link");
        symlink(&options.tls.key_file, &link).unwrap();
        options.tls.key_file = link;
        assert!(Client::new(options).is_err());
    }
}

#[test]
fn duplicate_principals_and_zero_limits_are_refused() {
    let fixture = Fixture::new();
    let principal = Principal {
        certificate_sha256: fixture.fingerprint.clone(),
        role: Role::Writer,
    };
    let mut options = ServerOptions {
        tls: fixture.server.clone(),
        principals: vec![principal.clone(), principal],
        timeout_ms: 500,
        max_connections: 2,
    };
    assert!(Server::new(options.clone()).is_err());
    options.principals.pop();
    options.max_connections = 0;
    assert!(Server::new(options.clone()).is_err());
    options.max_connections = 1;
    options.timeout_ms = 0;
    assert!(Server::new(options).is_err());
}

#[test]
fn bounded_connections_reject_overload_without_spawning() {
    let fixture = Fixture::new();
    let server = Arc::new(fixture.server());
    let first = server.try_reserve_connection().unwrap();
    let second = server.try_reserve_connection().unwrap();
    assert!(server.try_reserve_connection().is_err());
    drop(first);
    assert!(server.try_reserve_connection().is_ok());
    drop(second);
}

#[test]
fn serialization_stops_at_frame_bound_before_connecting() {
    use serde::ser::SerializeSeq;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Huge<'a>(&'a AtomicUsize);
    impl serde::Serialize for Huge<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut seq = serializer.serialize_seq(Some(100_000))?;
            for _ in 0..100_000 {
                self.0.fetch_add(1, Ordering::SeqCst);
                seq.serialize_element(&0u8)?;
            }
            seq.end()
        }
    }
    let fixture = Fixture::new();
    let seen = AtomicUsize::new(0);
    let error = Client::new(fixture.client("127.0.0.1:1".parse().unwrap()))
        .unwrap()
        .call::<_, Value>(&Huge(&seen))
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(
        seen.load(Ordering::SeqCst) < 40_000,
        "serialization traversed unbounded input"
    );
}

fn raw_client(
    fixture: &Fixture,
    address: SocketAddr,
    identity: Option<&TlsFiles>,
) -> rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_file(&fixture.server.cert_file).unwrap())
        .unwrap();
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots);
    let config = match identity {
        Some(identity) => builder
            .with_client_auth_cert(
                vec![CertificateDer::from_pem_file(&identity.cert_file).unwrap()],
                PrivateKeyDer::from_pem_file(&identity.key_file).unwrap(),
            )
            .unwrap(),
        None => builder.with_no_client_auth(),
    };
    let socket = std::net::TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    socket
        .set_write_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    rustls::StreamOwned::new(
        rustls::ClientConnection::new(Arc::new(config), ServerName::try_from("localhost").unwrap())
            .unwrap(),
        socket,
    )
}

#[test]
fn missing_and_untrusted_client_certificates_are_rejected_before_dispatch() {
    use std::io::{Read, Write};
    let fixture = Fixture::new();
    let alien = Fixture::new();
    for identity in [None, Some(&alien.alice)] {
        let (address, worker) = serve_once(fixture.server());
        let mut client = raw_client(&fixture, address, identity);
        let _ = client.write_all(&[0, 0, 0, 2, b'{', b'}']);
        let mut response = [0; 4];
        assert!(client.read_exact(&mut response).is_err());
        assert!(worker.join().unwrap().is_err());
    }
}

#[test]
fn malformed_frames_and_wrong_version_are_refused_over_real_tls() {
    use std::io::Write;
    let fixture = Fixture::new();
    let wrong_version =
        br#"{"version":2,"id":"00000000-0000-0000-0000-000000000001","request":{}}"#;
    let unknown_field =
        br#"{"version":1,"id":"00000000-0000-0000-0000-000000000001","request":{},"extra":true}"#;
    let invalid_json = b"not-json";
    let mut cases = vec![
        vec![0, 0, 0, 0],
        (65_537u32).to_be_bytes().to_vec(),
        vec![0, 0, 0],
        vec![0, 0, 0, 5, b'{'],
    ];
    for body in [&wrong_version[..], &unknown_field[..], &invalid_json[..]] {
        let mut frame = (body.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(body);
        cases.push(frame);
    }
    for bytes in cases {
        let (address, worker) = serve_once(fixture.server());
        let mut client = raw_client(&fixture, address, Some(&fixture.alice));
        client.write_all(&bytes).unwrap();
        client.flush().unwrap();
        client.conn.send_close_notify();
        let _ = client.flush();
        drop(client);
        assert!(worker.join().unwrap().is_err());
    }
}

#[test]
fn role_denial_is_preserved_and_remote_error_text_is_redacted() {
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = fixture.server();
    let worker = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        server
            .handle_connection(stream, &|role, _| {
                assert_eq!(role, Role::Writer);
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "secret error payload",
                ))
            })
            .unwrap();
    });
    let error = Client::new(fixture.client(address))
        .unwrap()
        .call::<_, Value>(&json!({}))
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(!error.to_string().contains("secret"));
    worker.join().unwrap();
}

#[test]
fn response_stall_uses_total_deadline_and_does_not_retry() {
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = fixture.server();
    let (entered, observed) = mpsc::channel();
    let (release, wait) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        // Receiver is not Sync; the service serializes this deliberately stalled handler.
        let wait = std::sync::Mutex::new(wait);
        let result = server.handle_connection(stream, &move |_, request| {
            entered.send(()).unwrap();
            wait.lock().unwrap().recv().unwrap();
            Ok(request)
        });
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        result
    });
    let mut options = fixture.client(address);
    options.timeout_ms = 200;
    let error = Client::new(options)
        .unwrap()
        .call::<_, Value>(&json!({}))
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    observed
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    release.send(()).unwrap();
    // A disconnected peer or already elapsed deadline can reject the late write.
    let _ = worker.join().unwrap();
}

#[test]
fn lost_reply_after_mutation_is_not_retried() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = fixture.server();
    let mutations = Arc::new(AtomicUsize::new(0));
    let seen = mutations.clone();
    let worker = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let disconnect = stream.try_clone().unwrap();
        let result = server.handle_connection(stream, &move |_, request| {
            seen.fetch_add(1, Ordering::SeqCst);
            disconnect.shutdown(std::net::Shutdown::Both).unwrap();
            Ok(request)
        });
        assert!(result.is_err());
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    });
    assert!(Client::new(fixture.client(address))
        .unwrap()
        .call::<_, Value>(&json!({}))
        .is_err());
    worker.join().unwrap();
    assert_eq!(mutations.load(Ordering::SeqCst), 1);
}

#[test]
fn server_expires_stalled_handshake_and_authenticated_body() {
    use std::io::Write;
    let fixture = Fixture::new();
    for authenticated in [false, true] {
        let (address, worker) = serve_once(fixture.server());
        if authenticated {
            let mut client = raw_client(&fixture, address, Some(&fixture.alice));
            // Complete TLS and a legal frame header, but withhold the body.
            client.write_all(&[0, 0, 0, 1]).unwrap();
            client.flush().unwrap();
            assert_eq!(
                worker.join().unwrap().unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
        } else {
            let _socket = std::net::TcpStream::connect(address).unwrap();
            assert_eq!(
                worker.join().unwrap().unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
        }
    }
}

#[test]
fn oversized_response_is_refused_and_permits_release_on_unwind() {
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = fixture.server();
    let first = server.try_reserve_connection().unwrap();
    let second = server.try_reserve_connection().unwrap();
    let _ = std::panic::catch_unwind(|| {
        let _permit = second;
        panic!("test unwind");
    });
    assert!(server.try_reserve_connection().is_ok());
    drop(first);
    let worker = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        server.handle_connection(stream, &|_, _| Ok(Value::String("x".repeat(65_537))))
    });
    assert!(Client::new(fixture.client(address))
        .unwrap()
        .call::<_, Value>(&json!({}))
        .is_err());
    assert_eq!(
        worker.join().unwrap().unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn response_id_version_and_exclusive_result_are_checked() {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::io::{Read, Write};
    let fixture = Fixture::new();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from_pem_file(&fixture.server.cert_file).unwrap()],
        PrivateKeyDer::from_pem_file(&fixture.server.key_file).unwrap(),
    )
    .unwrap();
    let config = Arc::new(config);
    for case in 0..6 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let config = config.clone();
        let worker = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            socket
                .set_write_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let mut stream =
                rustls::StreamOwned::new(rustls::ServerConnection::new(config).unwrap(), socket);
            let mut header = [0; 4];
            stream.read_exact(&mut header).unwrap();
            let mut body = vec![0; u32::from_be_bytes(header) as usize];
            stream.read_exact(&mut body).unwrap();
            let request: Value = serde_json::from_slice(&body).unwrap();
            let mut response = json!({"version":1,"id":request["id"],"response":true,"error":null});
            match case {
                0 => response["version"] = json!(2),
                1 => response["id"] = json!("00000000-0000-0000-0000-000000000000"),
                2 => response["error"] = json!("permission_denied"),
                3 => response["response"] = Value::Null,
                4 => response["extra"] = json!(true),
                _ => response["error"] = json!("unknown_error"),
            }
            let bytes = serde_json::to_vec(&response).unwrap();
            stream
                .write_all(&(bytes.len() as u32).to_be_bytes())
                .unwrap();
            stream.write_all(&bytes).unwrap();
            stream.flush().unwrap();
        });
        let error = Client::new(fixture.client(address))
            .unwrap()
            .call::<_, Value>(&json!({}))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        worker.join().unwrap();
    }
}

#[test]
fn private_key_loader_refuses_ambiguous_multiple_keys() {
    let fixture = Fixture::new();
    let key = std::fs::read(&fixture.alice.key_file).unwrap();
    let mut duplicate = key.clone();
    duplicate.extend_from_slice(&key);
    std::fs::write(&fixture.alice.key_file, duplicate).unwrap();
    assert!(Client::new(fixture.client("127.0.0.1:1".parse().unwrap())).is_err());
}

#[test]
fn private_key_syntax_size_and_certificate_pair_are_strict() {
    let fixture = Fixture::new();
    let good = std::fs::read(&fixture.alice.key_file).unwrap();
    let mut variants = vec![
        vec![b'x'; 1024 * 1024 + 1],
        b"-----BEGIN PRIVATE KEY-----\nnot-base64\n-----END PRIVATE KEY-----\n".to_vec(),
    ];
    variants.push(
        String::from_utf8(good.clone())
            .unwrap()
            .replace("END PRIVATE KEY", "END RSA PRIVATE KEY")
            .into_bytes(),
    );
    variants.push(good[..good.len() / 2].to_vec());
    for bad in variants {
        std::fs::write(&fixture.alice.key_file, bad).unwrap();
        assert!(Client::new(fixture.client("127.0.0.1:1".parse().unwrap())).is_err());
    }
    std::fs::write(&fixture.alice.key_file, &good).unwrap();
    let mut options = fixture.client("127.0.0.1:1".parse().unwrap());
    options.tls.cert_file = fixture.bob.cert_file.clone();
    assert!(Client::new(options).is_err());
    // Public certificate parsing must not silently decode and discard a key block.
    let mut cert = std::fs::read(&fixture.alice.cert_file).unwrap();
    cert.extend_from_slice(&good);
    std::fs::write(&fixture.alice.cert_file, cert).unwrap();
    assert!(Client::new(fixture.client("127.0.0.1:1".parse().unwrap())).is_err());
}

#[test]
fn state_rpc_enforces_authenticated_roles_and_preserves_cas_conflicts() {
    use maki_backing::remote_witness::{Action, Request, Rpc, StateStore};
    let fixture = Fixture::new();
    let state = StateStore::create(&fixture.dir.path().join("authority"), [1; 16]).unwrap();
    let handler = maki_witness::state_handler(state);
    let server = Server::new(ServerOptions {
        tls: fixture.server.clone(),
        principals: vec![
            Principal {
                certificate_sha256: fixture.fingerprint.clone(),
                role: Role::Writer,
            },
            Principal {
                certificate_sha256: maki_witness::certificate_file_fingerprint(
                    &fixture.bob.cert_file,
                )
                .unwrap(),
                role: Role::Admin,
            },
        ],
        timeout_ms: 2000,
        max_connections: 2,
    })
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let worker = std::thread::spawn(move || {
        for _ in 0..6 {
            let (stream, _) = listener.accept().unwrap();
            server.handle_connection(stream, handler.as_ref()).unwrap();
        }
    });
    let client = Client::new(fixture.client(address)).unwrap();
    let request = |operation, expected, action| Request {
        operation_id: [operation; 16],
        expected,
        action,
    };
    let released = Rpc::call(&client, &request(1, None, Action::Inspect)).unwrap();
    let claimed = Rpc::call(&client, &request(2, Some(released.clone()), Action::Claim)).unwrap();
    let denied = Rpc::call(
        &client,
        &request(3, Some(claimed.clone()), Action::Takeover),
    )
    .unwrap_err();
    assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);
    // Keep going before asserting the conflict so a failed assertion cannot leak the worker.
    let conflict = Rpc::call(&client, &request(4, Some(released), Action::Claim)).unwrap_err();
    let mut options = fixture.client(address);
    options.tls = fixture.bob.clone();
    let admin = Client::new(options).unwrap();
    let replaced = Rpc::call(&admin, &request(5, Some(claimed.clone()), Action::Takeover)).unwrap();
    let inspected = Rpc::call(&client, &request(6, None, Action::Inspect)).unwrap();
    worker.join().unwrap();
    assert_eq!(conflict.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(replaced, inspected);
    assert_eq!(replaced.fence, claimed.fence + 1);
    assert_ne!(replaced.session, claimed.session);
}

#[test]
fn exact_state_operation_can_be_resolved_after_lost_tls_reply() {
    use maki_backing::remote_witness::{Action, Request, Rpc, StateStore};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let fixture = Fixture::new();
    let mut state = StateStore::create(&fixture.dir.path().join("authority"), [1; 16]).unwrap();
    let inspect = Request {
        operation_id: [1; 16],
        expected: None,
        action: Action::Inspect,
    };
    let released = state.handle(Role::Writer, &inspect).unwrap();
    let request = Request {
        operation_id: [2; 16],
        expected: Some(released),
        action: Action::Claim,
    };
    let handler = maki_witness::state_handler(state);
    let server = fixture.server();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let server_handler = handler.clone();
    let worker = std::thread::spawn(move || {
        for index in 0..2 {
            let (stream, _) = listener.accept().unwrap();
            let close = stream.try_clone().unwrap();
            let handler = server_handler.clone();
            let calls = calls.clone();
            let result = server.handle_connection(stream, &move |role, request| {
                let response = handler(role, request)?;
                calls.fetch_add(1, Ordering::SeqCst);
                if index == 0 {
                    close.shutdown(std::net::Shutdown::Both).unwrap();
                }
                Ok(response)
            });
            if index == 0 {
                assert!(result.is_err());
            } else {
                result.unwrap();
            }
        }
    });
    let client = Client::new(fixture.client(address)).unwrap();
    assert!(Rpc::call(&client, &request).is_err());
    let resolved = Rpc::call(&client, &request).unwrap();
    worker.join().unwrap();
    assert_eq!(resolved.fence, 1, "replay minted a second fencing token");
    assert_eq!(resolved.last_operation, request.operation_id);
    assert_eq!(observed.load(Ordering::SeqCst), 2);
    // A new process recovers the exact successful outcome independently of TLS.
    drop(handler);
    let mut reopened = StateStore::open(&fixture.dir.path().join("authority")).unwrap();
    assert_eq!(reopened.handle(Role::Writer, &inspect).unwrap(), resolved);
}
