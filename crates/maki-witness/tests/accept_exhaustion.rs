//! BUG-111: `Server::serve` returned on any accept error other than EINTR,
//! so running out of file descriptors (EMFILE/ENFILE, a burst of clients or
//! a slow leak elsewhere) ended the witness service, and every protected
//! volume using it lost its freshness authority until someone restarted
//! it. Accept errors are transient: the server pauses and keeps accepting,
//! as the control socket does (O-04).
//!
//! This binary lowers the process descriptor limit, so it holds one test.

#![cfg(target_os = "linux")]

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::{mpsc, Arc};
use std::time::Duration;

use maki_witness::{
    certificate_fingerprint, Client, ClientOptions, Principal, Role, Server, ServerOptions,
    TlsFiles,
};
use serde_json::{json, Value};

fn identity(dir: &Path, name: &str, cert: &rcgen::CertifiedKey, ca: &str) -> TlsFiles {
    use std::os::unix::fs::PermissionsExt;
    let files = TlsFiles {
        ca_file: dir.join(format!("{name}.ca.pem")),
        cert_file: dir.join(format!("{name}.cert.pem")),
        key_file: dir.join(format!("{name}.key.pem")),
    };
    std::fs::write(&files.ca_file, ca).unwrap();
    std::fs::write(&files.cert_file, cert.cert.pem()).unwrap();
    std::fs::write(&files.key_file, cert.key_pair.serialize_pem()).unwrap();
    std::fs::set_permissions(&files.key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    files
}

fn open_descriptors() -> u64 {
    // The directory handle itself is one of the entries.
    std::fs::read_dir("/proc/self/fd").unwrap().count() as u64 - 1
}

fn set_soft_limit(limit: u64) -> u64 {
    let mut current = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: plain syscalls on a properly initialised struct.
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut current), 0);
        let previous = current.rlim_cur;
        current.rlim_cur = limit;
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &current), 0);
        previous
    }
}

#[test]
fn descriptor_exhaustion_does_not_stop_the_server() {
    let dir = tempfile::tempdir().unwrap();
    let server_cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let alice = rcgen::generate_simple_self_signed(vec!["alice".to_owned()]).unwrap();
    let server_tls = identity(dir.path(), "server", &server_cert, &alice.cert.pem());
    let alice_tls = identity(dir.path(), "alice", &alice, &server_cert.cert.pem());
    let server = Arc::new(
        Server::new(ServerOptions {
            tls: server_tls,
            principals: vec![Principal {
                certificate_sha256: certificate_fingerprint(alice.cert.der()),
                role: Role::Writer,
            }],
            timeout_ms: 500,
            max_connections: 4,
        })
        .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address: SocketAddr = listener.local_addr().unwrap();
    // Connections wait in the backlog until the server accepts them.
    let queued: Vec<TcpStream> = (0..3)
        .map(|_| TcpStream::connect(address).unwrap())
        .collect();

    // No descriptor left: the first accept fails with EMFILE.
    let previous = set_soft_limit(open_descriptors());
    let (done_tx, done_rx) = mpsc::channel();
    let handler: Arc<maki_witness::Handler> = Arc::new(|_, request: &[u8]| {
        serde_json::from_slice(request).map_err(std::io::Error::other)
    });
    std::thread::spawn(move || {
        let result = server.serve(listener, handler);
        let _ = done_tx.send(result.map_err(|e| e.to_string()));
    });
    let ended = done_rx.recv_timeout(Duration::from_millis(300));
    set_soft_limit(previous);
    drop(queued);
    assert!(
        ended.is_err(),
        "serve returned on descriptor exhaustion: {ended:?}"
    );

    let client = Client::new(ClientOptions {
        address,
        server_name: "localhost".into(),
        timeout_ms: 2000,
        tls: alice_tls,
    })
    .unwrap();
    assert_eq!(
        client
            .call::<_, Value>(&json!({"after": "exhaustion"}))
            .unwrap(),
        json!({"after": "exhaustion"})
    );
}
