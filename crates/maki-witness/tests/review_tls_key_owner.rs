//! A witness TLS private key is a secret file, but the loader checked only
//! its mode bits. The owner of a file can read and rewrite it whatever its
//! mode, so a `0600` key owned by an unrelated unprivileged user was
//! accepted by whatever process loaded it (the `maki-witness` server, the
//! daemon's witness client, `maki` administrator commands, possibly run as
//! root): that user could read or replace the key that authenticates the
//! TLS 1.3 mutual-authentication session. A private key must belong to root
//! or to the user the loading process runs as. Certificates and CA bundles
//! are public and keep their rules.
//!
//! Changing a file's owner needs root, so the refusal case skips otherwise.

#![cfg(unix)]

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use maki_witness::etcd::{EtcdEndpoint, EtcdOptions, EtcdStore};
use maki_witness::failover::FailoverClient;
use maki_witness::{
    certificate_fingerprint, Client, ClientOptions, Principal, Role, Server, ServerOptions,
    TlsFiles,
};

/// An unprivileged uid and gid that is neither root nor this process.
const NOBODY: u32 = 65534;
const IDENTITY: [u8; 16] = [7; 16];

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

struct Fixture {
    _dir: tempfile::TempDir,
    server: TlsFiles,
    client: TlsFiles,
    fingerprint: String,
    /// One base64 line of each private key, to prove no error echoes it.
    key_lines: Vec<String>,
}

fn save(dir: &Path, name: &str, key: &rcgen::CertifiedKey, ca: &str) -> (TlsFiles, String) {
    let tls = TlsFiles {
        ca_file: dir.join(format!("{name}.ca.pem")),
        cert_file: dir.join(format!("{name}.cert.pem")),
        key_file: dir.join(format!("{name}.key.pem")),
    };
    let pem = key.key_pair.serialize_pem();
    std::fs::write(&tls.ca_file, ca).unwrap();
    std::fs::write(&tls.cert_file, key.cert.pem()).unwrap();
    std::fs::write(&tls.key_file, &pem).unwrap();
    std::fs::set_permissions(&tls.key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let line = pem.lines().nth(1).unwrap().to_owned();
    (tls, line)
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let server = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let writer = rcgen::generate_simple_self_signed(vec!["writer".into()]).unwrap();
        let (server_files, server_line) = save(dir.path(), "server", &server, &writer.cert.pem());
        let (client_files, client_line) = save(dir.path(), "writer", &writer, &server.cert.pem());
        Self {
            _dir: dir,
            server: server_files,
            client: client_files,
            fingerprint: certificate_fingerprint(writer.cert.der()),
            key_lines: vec![server_line, client_line],
        }
    }

    fn chown(&self, path: &Path, owner: u32, mode: u32) {
        std::os::unix::fs::chown(path, Some(owner), Some(owner)).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn server(&self) -> io::Result<Server> {
        Server::new(ServerOptions {
            tls: self.server.clone(),
            principals: vec![Principal {
                certificate_sha256: self.fingerprint.clone(),
                role: Role::Writer,
            }],
            timeout_ms: 500,
            max_connections: 2,
        })
    }

    fn client_options(&self, port: u16) -> ClientOptions {
        ClientOptions {
            // Nothing is listening: loading must finish before any connect.
            address: format!("127.0.0.1:{port}").parse().unwrap(),
            server_name: "localhost".into(),
            timeout_ms: 500,
            tls: self.client.clone(),
        }
    }

    fn client(&self) -> io::Result<Client> {
        Client::new(self.client_options(1))
    }

    /// The daemon's path for an endpoint set (`storage_identity` pinned).
    fn failover(&self) -> io::Result<FailoverClient> {
        FailoverClient::new(
            vec![self.client_options(1), self.client_options(2)],
            IDENTITY,
            500,
        )
    }

    /// The quorum-backed server's backend client.
    fn etcd(&self) -> io::Result<EtcdStore> {
        EtcdStore::open(EtcdOptions {
            endpoints: vec![EtcdEndpoint {
                address: "127.0.0.1:1".parse().unwrap(),
                server_name: "localhost".into(),
            }],
            cluster_id: 42,
            storage_identity: uuid::Uuid::from_bytes(IDENTITY),
            key: "/maki/witness/test".into(),
            timeout_ms: 500,
            tls: self.client.clone(),
        })
    }

    fn assert_refused_for_its_owner<T>(&self, what: &str, loaded: io::Result<T>) {
        let Err(error) = loaded else {
            panic!("{what}: a TLS key owned by uid {NOBODY} was accepted");
        };
        let message = error.to_string();
        assert_eq!(
            error.kind(),
            io::ErrorKind::PermissionDenied,
            "{what}: {message}"
        );
        assert!(message.contains("owned by uid 65534"), "{what}: {message}");
        assert!(!message.contains("PRIVATE KEY"), "{what}: {message}");
        for line in &self.key_lines {
            assert!(!message.contains(line.as_str()), "{what}: key leaked");
        }
    }
}

#[test]
fn a_witness_tls_key_owned_by_another_user_is_refused() {
    if !is_root() {
        eprintln!("needs root to chown the fixture to uid {NOBODY}; skipping");
        return;
    }
    let fixture = Fixture::new();
    for mode in [0o600u32, 0o400] {
        fixture.chown(&fixture.server.key_file, NOBODY, mode);
        fixture.assert_refused_for_its_owner("server", fixture.server());
        fixture.chown(&fixture.client.key_file, NOBODY, mode);
        fixture.assert_refused_for_its_owner("client", fixture.client());
        fixture.assert_refused_for_its_owner("failover client", fixture.failover());
        fixture.assert_refused_for_its_owner("etcd backend", fixture.etcd());
    }
}

#[test]
fn root_or_process_owned_keys_still_load_beside_foreign_certificates() {
    let fixture = Fixture::new();
    if is_root() {
        // Root can hand the key to root explicitly; anyone else owns what
        // they create, which is the process's own user. The public
        // certificate and CA files keep their rules: any owner.
        for files in [&fixture.server, &fixture.client] {
            fixture.chown(&files.key_file, 0, 0o600);
            fixture.chown(&files.cert_file, NOBODY, 0o644);
            fixture.chown(&files.ca_file, NOBODY, 0o644);
        }
    }
    fixture
        .server()
        .expect("server key owned by root or this process");
    fixture
        .client()
        .expect("client key owned by root or this process");
    fixture
        .failover()
        .expect("failover key owned by root or this process");
    // Nothing listens on the endpoint: the store fails to connect, which
    // proves its credentials loaded first.
    let error = fixture.etcd().err().expect("no etcd listens on port 1");
    assert_ne!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
}
