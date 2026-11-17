//! A local socket-layer failure means the witness could not be asked, never
//! that it refused. Linux returns EPERM from connect() when netfilter drops a
//! locally generated SYN (a full conntrack table, a firewall reload), and std
//! reports EPERM and EACCES as `PermissionDenied`, the kind of the server's
//! own denial. Such an outage must refuse the operation without ending
//! frontend failover or stopping the remote session (BUG-103). The test
//! injects EPERM into connect() for one thread with a seccomp filter.
#![cfg(target_os = "linux")]

use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use maki_backing::remote_witness::{Action, Request, Role, Rpc, StateStore};
use maki_backing::{Backing, RollbackBacking};
use maki_witness::failover::FailoverClient;
use maki_witness::{Client, ClientOptions, Principal, Server, ServerOptions, TlsFiles};

struct Service {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Service {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        self.worker.take().unwrap().join().unwrap();
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    client: TlsFiles,
    server: TlsFiles,
    fingerprint: String,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let server = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let writer = rcgen::generate_simple_self_signed(vec!["writer".into()]).unwrap();
        let save = |name: &str, key: &rcgen::CertifiedKey, ca: String| {
            let tls = TlsFiles {
                ca_file: directory.path().join(format!("{name}.ca")),
                cert_file: directory.path().join(format!("{name}.cert")),
                key_file: directory.path().join(format!("{name}.key")),
            };
            std::fs::write(&tls.ca_file, ca).unwrap();
            std::fs::write(&tls.cert_file, key.cert.pem()).unwrap();
            std::fs::write(&tls.key_file, key.key_pair.serialize_pem()).unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tls.key_file, std::fs::Permissions::from_mode(0o600))
                .unwrap();
            tls
        };
        let client = save("writer", &writer, server.cert.pem());
        let files = save("server", &server, writer.cert.pem());
        Self {
            directory,
            client,
            server: files,
            fingerprint: maki_witness::certificate_fingerprint(writer.cert.der()),
        }
    }

    fn service(&self) -> Service {
        let server = Server::new(ServerOptions {
            tls: self.server.clone(),
            principals: vec![Principal {
                certificate_sha256: self.fingerprint.clone(),
                role: Role::Writer,
            }],
            timeout_ms: 2000,
            max_connections: 8,
        })
        .unwrap();
        let handler = maki_witness::state_handler(
            StateStore::create(&self.directory.path().join("authority"), [1; 16]).unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = std::thread::spawn(move || {
            for socket in listener.incoming() {
                if stopped.load(Ordering::SeqCst) {
                    break;
                }
                let _ = server.handle_connection(socket.unwrap(), handler.as_ref());
            }
        });
        Service {
            address,
            stop,
            worker: Some(worker),
        }
    }

    fn options(&self, address: SocketAddr) -> ClientOptions {
        ClientOptions {
            address,
            server_name: "localhost".into(),
            timeout_ms: 2000,
            tls: self.client.clone(),
        }
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

/// Make every connect() of the calling thread fail with EPERM, as a
/// netfilter drop of the outgoing SYN does. Seccomp filters and the
/// no-new-privileges flag are per thread; the filter ends with the thread.
/// Returns false where seccomp filters are unavailable.
fn deny_connect_in_this_thread() -> bool {
    let statement = |code: u32, k: u32, jt: u8, jf: u8| libc::sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    };
    let filter = [
        // seccomp_data.nr
        statement(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0),
        statement(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            libc::SYS_connect as u32,
            0,
            1,
        ),
        statement(
            libc::BPF_RET | libc::BPF_K,
            libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
            0,
            0,
        ),
        statement(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW, 0, 0),
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: both calls affect only this thread; the program outlives them.
    unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
            && libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &program as *const libc::sock_fprog,
            ) == 0
    }
}

/// The kinds the witness callers treat as a final answer from the authority.
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

#[test]
fn local_connect_denial_refuses_operations_without_stopping_the_session() {
    let f = Fixture::new();
    let first = f.service();
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let second = closed.local_addr().unwrap();
    drop(closed);
    let client: Arc<dyn Rpc> = Arc::new(Client::new(f.options(first.address)).unwrap());
    let failover = FailoverClient::new(
        vec![f.options(first.address), f.options(second)],
        [1; 16],
        2000,
    )
    .unwrap();
    let root = tempfile::tempdir().unwrap();
    let backing = RollbackBacking::create_remote(root.path(), client.clone(), 32 * 4096).unwrap();
    let file = backing.open("payload", true).unwrap();
    file.write_at(0, b"before").unwrap();
    file.sync_data().unwrap();
    backing.check_freshness().unwrap();

    let observed = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                if !deny_connect_in_this_thread() {
                    return None;
                }
                let direct = client.call(&inspect()).unwrap_err();
                let failover = failover.call(&inspect()).unwrap_err();
                let freshness = backing.check_freshness().unwrap_err();
                let sync = file.sync_data().unwrap_err();
                Some([direct, failover, freshness, sync])
            })
            .join()
            .unwrap()
    });
    let Some(errors) = observed else {
        eprintln!("skipped: seccomp filters are unavailable on this host");
        return;
    };
    for error in &errors {
        assert!(
            !final_answer(error.kind()),
            "a local connect() EPERM was reported as the witness's final answer: {error:?}"
        );
    }
    // The outage refused only those operations; the session continues.
    backing
        .check_freshness()
        .expect("a local socket failure stopped the remote session");
    file.write_at(0, b"after!").unwrap();
    file.sync_data().unwrap();
    let mut bytes = [0; 6];
    file.read_at(0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"after!");
}
