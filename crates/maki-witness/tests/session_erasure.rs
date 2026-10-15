//! Inspect owned session-key copies while allocations are still live at free.
use std::alloc::{GlobalAlloc, Layout, System};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use maki_backing::remote_witness::{Action, Request, Role, Rpc, SessionAuthorization, StateStore};
use maki_witness::{Client, ClientOptions, Principal, Server, ServerOptions, TlsFiles};

struct Observer;
static OBSERVE: AtomicBool = AtomicBool::new(false);
static RETAINED: AtomicUsize = AtomicUsize::new(0);
static GUARDED_FRAMES: AtomicUsize = AtomicUsize::new(0);
const KEY_BYTES: &[u8] = &[171; 32];
const KEY_JSON: &[u8] = b"[171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171]";
unsafe impl GlobalAlloc for Observer {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Every allocation byte, including unused capacity, is initialized, so
        // the bounded observation never reads uninitialized or freed memory.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if OBSERVE.load(Ordering::SeqCst) {
            let bytes = unsafe { std::slice::from_raw_parts(pointer, layout.size()) };
            if bytes
                .windows(KEY_BYTES.len())
                .any(|value| value == KEY_BYTES)
                || bytes.windows(KEY_JSON.len()).any(|value| value == KEY_JSON)
            {
                RETAINED.fetch_add(1, Ordering::SeqCst);
            }
            if layout.size() == 64 * 1024 && bytes.iter().all(|value| *value == 0) {
                GUARDED_FRAMES.fetch_add(1, Ordering::SeqCst);
            }
        }
        unsafe { System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Observer = Observer;

#[test]
fn session_capability_and_tls_frames_are_erased_on_success_and_rejected_requests() {
    let directory = tempfile::tempdir().unwrap();
    let server_identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let writer_identity = rcgen::generate_simple_self_signed(vec!["writer".into()]).unwrap();
    let save = |name: &str, identity: &rcgen::CertifiedKey, ca: &str| {
        let files = TlsFiles {
            ca_file: directory.path().join(format!("{name}.ca")),
            cert_file: directory.path().join(format!("{name}.cert")),
            key_file: directory.path().join(format!("{name}.key")),
        };
        std::fs::write(&files.ca_file, ca).unwrap();
        std::fs::write(&files.cert_file, identity.cert.pem()).unwrap();
        std::fs::write(&files.key_file, identity.key_pair.serialize_pem()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&files.key_file, std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        files
    };
    let server_files = save("server", &server_identity, &writer_identity.cert.pem());
    let writer_files = save("writer", &writer_identity, &server_identity.cert.pem());
    let state = StateStore::create(&directory.path().join("authority"), [1; 16]).unwrap();
    let handler = maki_witness::state_handler(state);
    let server = Server::new(ServerOptions {
        tls: server_files,
        principals: vec![Principal {
            certificate_sha256: maki_witness::certificate_fingerprint(writer_identity.cert.der()),
            role: Role::Writer,
        }],
        timeout_ms: 10_000,
        max_connections: 2,
    })
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = Client::new(ClientOptions {
        address: listener.local_addr().unwrap(),
        server_name: "localhost".into(),
        timeout_ms: 10_000,
        tls: writer_files,
    })
    .unwrap();
    let worker = std::thread::spawn(move || {
        for _ in 0..3 {
            let (socket, _) = listener.accept().unwrap();
            server.handle_connection(socket, handler.as_ref()).unwrap();
        }
    });
    OBSERVE.store(true, Ordering::SeqCst);
    let key = Box::new(SessionAuthorization::from_bytes([171; 32]));
    let copy = key.clone();
    drop(copy);
    let initial = Rpc::call(
        &client,
        &Request {
            operation_id: [1; 16],
            expected: None,
            action: Action::Inspect,
            authorization: None,
        },
    )
    .unwrap();
    let mut claim = Request {
        operation_id: [2; 16],
        expected: Some(initial),
        action: Action::Claim,
        authorization: Some((*key).clone()),
    };
    let claimed = Rpc::call(&client, &claim).unwrap();
    claim.operation_id = [3; 16];
    claim.expected = Some(claimed);
    claim.action = Action::Inspect;
    assert!(
        Rpc::call(&client, &claim).is_err(),
        "inspection cannot carry a secret capability"
    );
    drop(claim);
    drop(key);
    worker.join().unwrap();
    drop(client);
    OBSERVE.store(false, Ordering::SeqCst);
    assert!(
        GUARDED_FRAMES.load(Ordering::SeqCst) >= 3,
        "actual protected framing allocations were observed"
    );
    assert_eq!(
        RETAINED.load(Ordering::SeqCst),
        0,
        "owned raw or JSON authorization survived at deallocation"
    );
}
