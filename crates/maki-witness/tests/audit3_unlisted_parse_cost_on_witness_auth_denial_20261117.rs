//! Round-3 audit probe for PR #179 (answer an unlisted witness client
//! certificate with a denial). To bind the denial to the request id, the
//! server now reads and parses the request of a CA-trusted client that the
//! allow-list does not name. Before #179 that connection was closed right
//! after the handshake and never reached the JSON parser. The patched
//! serde_json's error-position parse (VERIFIED2 vendor-r2 #1, fixed only by
//! the separate PR #183) costs O(message length x digits), and a request's
//! unknown field name is copied into the error message. So an unlisted peer
//! can now make the witness spend that CPU on every connection.
//!
//! The test sends two same-size request frames as an unlisted client: one
//! whose unknown field name ends in " at line 000…0", one of plain letters.
//! It measures how long the server takes to finish the connection.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use maki_backing::remote_witness::{Role, StateStore};
use maki_witness::{certificate_fingerprint, Principal, Server, ServerOptions, TlsFiles};

const FRAME: usize = 64 * 1024 - 16;

fn save(dir: &std::path::Path, name: &str, key: &rcgen::CertifiedKey, ca: &str) -> TlsFiles {
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

/// A raw TLS 1.3 client presenting `client` that writes `frame` (length
/// prefixed) and reads until the server ends the connection. Returns the
/// time from the write to the end of the connection.
fn send(
    address: std::net::SocketAddr,
    server: &rcgen::CertifiedKey,
    client: &rcgen::CertifiedKey,
    frame: &[u8],
) -> Duration {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(server.cert.der().clone()).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_client_auth_cert(
        vec![client.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(client.key_pair.serialize_der()).into(),
    )
    .unwrap();
    let socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let connection = rustls::ClientConnection::new(
        Arc::new(config),
        rustls::pki_types::ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut tls = rustls::StreamOwned::new(connection, socket);
    // Complete the handshake before timing.
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock).unwrap();
    }
    let started = Instant::now();
    let mut message = (frame.len() as u32).to_be_bytes().to_vec();
    message.extend_from_slice(frame);
    tls.write_all(&message).unwrap();
    tls.flush().unwrap();
    let mut sink = Vec::new();
    let _ = tls.read_to_end(&mut sink);
    started.elapsed()
}

/// A request whose unknown field name makes up the frame; `digits` decides
/// whether the name ends in " at line " and zeros or is plain letters.
fn frame(digits: bool) -> Vec<u8> {
    let head = r#"{"version":2,"id":"00000000-0000-4000-8000-000000000000","request":{},""#;
    let tail = r#"":1}"#;
    let room = FRAME - head.len() - tail.len();
    let name = if digits {
        let prefix = "x at line ";
        format!("{prefix}{}", "0".repeat(room - prefix.len()))
    } else {
        "x".repeat(room)
    };
    format!("{head}{name}{tail}").into_bytes()
}

#[test]
fn an_unlisted_client_cannot_make_the_witness_parse_its_request() {
    let directory = tempfile::tempdir().unwrap();
    let server_key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let unlisted = rcgen::generate_simple_self_signed(vec!["unlisted".into()]).unwrap();
    let listed = rcgen::generate_simple_self_signed(vec!["listed".into()]).unwrap();
    let clients = format!("{}{}", unlisted.cert.pem(), listed.cert.pem());
    let server_tls = save(directory.path(), "server", &server_key, &clients);
    let server = Arc::new(
        Server::new(ServerOptions {
            tls: server_tls,
            // Only `listed` is allowed; `unlisted` is trusted by the CA
            // bundle but not named.
            principals: vec![Principal {
                certificate_sha256: certificate_fingerprint(listed.cert.der()),
                role: Role::Writer,
            }],
            timeout_ms: 60_000,
            max_connections: 4,
        })
        .unwrap(),
    );
    let handler = maki_witness::state_handler(
        StateStore::create(&directory.path().join("state"), [7; 16]).unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || server.serve(listener, handler));

    // Warm up (TLS setup, allocator).
    send(address, &server_key, &unlisted, &frame(false));
    let mut plain = Duration::MAX;
    let mut crafted = Duration::MAX;
    for _ in 0..3 {
        plain = plain.min(send(address, &server_key, &unlisted, &frame(false)));
        crafted = crafted.min(send(address, &server_key, &unlisted, &frame(true)));
    }
    eprintln!("unlisted client, {FRAME}-byte frame: plain {plain:?}, crafted {crafted:?}");
    assert!(
        crafted < plain * 3 + Duration::from_millis(10),
        "an unlisted (not allow-listed) client made the witness spend {crafted:?} parsing \
         its request (plain frame of the same size: {plain:?})"
    );
}
