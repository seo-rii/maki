//! Round-2 audit probe (transport-pr-review): a trusted-but-unlisted client
//! certificate is the authority's own authentication denial, which
//! docs/remote-witness-service.md calls terminal ("Authentication failures,
//! malformed records and predecessor conflicts remain terminal"). The server
//! decides it after the TLS handshake and closes the connection without an
//! answer, so the client cannot tell it from a dropped connection.
use std::io;
use std::net::{SocketAddr, TcpListener};
use std::path::Path;

use maki_backing::remote_witness::{Action, Request, Rpc};
use maki_witness::failover::FailoverClient;
use maki_witness::{
    certificate_fingerprint, Client, ClientOptions, Principal, Role, Server, ServerOptions,
    TlsFiles,
};
use serde_json::{json, Value};

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

struct Fixture {
    _dir: tempfile::TempDir,
    server: TlsFiles,
    bob: TlsFiles,
    alice_fingerprint: String,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let server = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let alice = rcgen::generate_simple_self_signed(vec!["alice".to_owned()]).unwrap();
        let bob = rcgen::generate_simple_self_signed(vec!["bob".to_owned()]).unwrap();
        // The server trusts both client certificates but lists only alice.
        let clients = format!("{}{}", alice.cert.pem(), bob.cert.pem());
        Self {
            server: identity(dir.path(), "server", &server, &clients),
            bob: identity(dir.path(), "bob", &bob, &server.cert.pem()),
            alice_fingerprint: certificate_fingerprint(alice.cert.der()),
            _dir: dir,
        }
    }

    fn serve(&self, connections: usize) -> SocketAddr {
        let server = Server::new(ServerOptions {
            tls: self.server.clone(),
            principals: vec![Principal {
                certificate_sha256: self.alice_fingerprint.clone(),
                role: Role::Writer,
            }],
            timeout_ms: 2000,
            max_connections: 2,
        })
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for _ in 0..connections {
                let (stream, _) = listener.accept().unwrap();
                let result = server.handle_connection(stream, &|_, request: &[u8]| {
                    serde_json::from_slice(request).map_err(io::Error::other)
                });
                // The server itself knows it denied the peer.
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
            }
        });
        address
    }

    fn bob(&self, address: SocketAddr) -> ClientOptions {
        ClientOptions {
            address,
            server_name: "localhost".into(),
            timeout_ms: 5000,
            tls: self.bob.clone(),
        }
    }
}

/// Kinds the failover client and the remote rollback backing treat as the
/// authority's final answer (failover.rs, rollback/remote.rs).
fn is_final(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::InvalidInput
            | io::ErrorKind::InvalidData
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::WouldBlock
    )
}

#[test]
fn an_unlisted_certificate_denial_reaches_the_client_as_a_final_answer() {
    let fixture = Fixture::new();
    let mut kinds = Vec::new();
    for _ in 0..8 {
        let address = fixture.serve(1);
        let error = Client::new(fixture.bob(address))
            .unwrap()
            .call::<_, Value>(&json!({"inspect": true}))
            .unwrap_err();
        kinds.push((error.kind(), error.to_string()));
    }
    let transient: Vec<_> = kinds.iter().filter(|(kind, _)| !is_final(*kind)).collect();
    assert!(
        transient.is_empty(),
        "authentication denial looked like a transport failure in {} of {} calls: {transient:?}",
        transient.len(),
        kinds.len()
    );
}

#[test]
fn failover_moves_past_an_authentication_denial_and_reports_it_as_unavailable() {
    let fixture = Fixture::new();
    let first = fixture.serve(1);
    let second = fixture.serve(1);
    let client = FailoverClient::new(vec![fixture.bob(first), fixture.bob(second)], [7; 16], 5000)
        .unwrap();
    let error = client
        .call(&Request {
            operation_id: [1; 16],
            expected: None,
            action: Action::Inspect,
            authorization: None,
        })
        .unwrap_err();
    assert!(
        is_final(error.kind()),
        "both frontends denied the certificate, yet failover reported {:?}: {error}",
        error.kind()
    );
}
