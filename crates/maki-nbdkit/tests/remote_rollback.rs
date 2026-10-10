#![cfg(target_os = "linux")]
use maki_backing::remote_witness::StateStore;
use maki_nbdkit::daemon::{build_backing, create_volume_from_config_str, parse_and_validate};
use maki_witness::{certificate_fingerprint, Principal, Role, Server, ServerOptions, TlsFiles};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

fn files(root: &Path, name: &str, key: &rcgen::CertifiedKey, ca: &str) -> TlsFiles {
    let ca_file = root.join(format!("{name}.ca.pem"));
    let cert_file = root.join(format!("{name}.cert.pem"));
    let key_file = root.join(format!("{name}.key.pem"));
    std::fs::write(&ca_file, ca).unwrap();
    std::fs::write(&cert_file, key.cert.pem()).unwrap();
    std::fs::write(&key_file, key.key_pair.serialize_pem()).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    TlsFiles {
        ca_file,
        cert_file,
        key_file,
    }
}
struct Service {
    address: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Service {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

#[test]
fn configured_remote_volume_uses_authenticated_service_and_refuses_offline_fallback() {
    let root = tempfile::tempdir().unwrap();
    let witness = tempfile::tempdir().unwrap();
    let tls = tempfile::tempdir().unwrap();
    let server_key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let writer_key = rcgen::generate_simple_self_signed(vec!["writer".into()]).unwrap();
    let server_files = files(tls.path(), "server", &server_key, &writer_key.cert.pem());
    let writer_files = files(tls.path(), "writer", &writer_key, &server_key.cert.pem());
    let server = Server::new(ServerOptions {
        tls: server_files,
        principals: vec![Principal {
            certificate_sha256: certificate_fingerprint(writer_key.cert.der()),
            role: Role::Writer,
        }],
        timeout_ms: 2000,
        max_connections: 2,
    })
    .unwrap();
    let state = Arc::new(Mutex::new(
        StateStore::create(witness.path(), [7; 16]).unwrap(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let ending = stop.clone();
    let worker = std::thread::spawn(move || {
        let handler = move |role, value| {
            let request = serde_json::from_value(value).map_err(std::io::Error::other)?;
            let result = state.lock().unwrap().handle(role, &request)?;
            serde_json::to_value(result).map_err(std::io::Error::other)
        };
        for socket in listener.incoming() {
            if ending.load(Ordering::SeqCst) {
                break;
            }
            let socket = socket.unwrap();
            let _ = server.handle_connection(socket, &handler);
        }
    });
    let service = Service {
        address,
        stop,
        worker: Some(worker),
    };
    let config = format!(
        r#"config_schema_version=1
[volume]
name="remote"
max_virtual_size="16MiB"
shard_logical_size="8MiB"
[crypto]
provider="fake"
crypto_compatibility_id="v1"
[crypto.capabilities]
supported_plaintext_sizes=[4096]
max_ciphertext_size=4384
[backing]
root={:?}
journal_segment_size="64KiB"
journal_max_bytes="1MiB"
checkpoint_reserve_bytes="64KiB"
journal_emergency_reserve_bytes="64KiB"
[backing.rollback_protection]
capacity="16MiB"
[backing.rollback_protection.remote]
address="{}"
server_name="localhost"
timeout_ms=2000
ca_file={:?}
client_cert_file={:?}
client_key_file={:?}
[nbd]
maximum_io="64KiB"
"#,
        root.path().display().to_string(),
        address,
        writer_files.ca_file.display().to_string(),
        writer_files.cert_file.display().to_string(),
        writer_files.key_file.display().to_string()
    );
    let created = create_volume_from_config_str(&config).unwrap();
    let parsed = parse_and_validate(&config).unwrap();
    let backing = build_backing(&parsed).unwrap();
    let recovered = maki_core::volume::Volume::recover(
        backing.clone(),
        maki_core::volume::VolumeOptions {
            journal_segment_size: 64 * 1024,
        },
    )
    .unwrap();
    assert_eq!(recovered.superblock().volume_uuid, created.volume_uuid);
    assert!(build_backing(&parsed).is_err());
    drop(recovered);
    drop(backing);
    drop(service);
    assert!(build_backing(&parsed).is_err());
    let mut unprotected = parsed.clone();
    unprotected.backing.rollback_protection = None;
    assert!(build_backing(&unprotected).is_err());
}
