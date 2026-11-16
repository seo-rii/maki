//! Audit (nbdkit-control-cli): M-008 made a release build refuse the
//! test-only, non-cryptographic `fake` provider "at validation time, not at
//! attach" through `parse_and_validate`, so `maki volume create` and attach
//! fail closed. `maki volume resume-enrollment` is a third way to initialize
//! a volume. It validates with `read_config` (parse + `validate`) and
//! `resume_enrollment_from_config` (`validate` again), neither of which calls
//! `check_provider_available`: a release `maki` writes a superblock with
//! provider "fake" and consumes the enrollment (the fence advances and the
//! authority gains a current descriptor), leaving a volume that no release
//! daemon can attach and that resume-enrollment can no longer redo.

#![cfg(target_os = "linux")]

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use maki_backing::remote_witness::{Action, Record, Request, Role, Rpc, StateStore};
use maki_backing::RollbackBacking;
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

fn inspect(rpc: &dyn Rpc) -> Record {
    rpc.call(&Request {
        authorization: None,
        operation_id: *uuid::Uuid::new_v4().as_bytes(),
        expected: None,
        action: Action::Inspect,
    })
    .unwrap()
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_maki"))
        .args(args)
        .output()
        .unwrap()
}

/// Loses the reply to the writer claim, so enrollment stops half-way and
/// only an approved `resume-enrollment` can finish it.
struct LoseClaims(Arc<dyn Rpc>);

impl Rpc for LoseClaims {
    fn call(&self, request: &Request) -> std::io::Result<Record> {
        let result = self.0.call(request)?;
        if request.action == Action::Claim {
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "lost claim reply",
            ))
        } else {
            Ok(result)
        }
    }
}

const FAKE_CRYPTO: &str = r#"[crypto]
provider="fake"
crypto_compatibility_id="test-profile-v1"
[crypto.capabilities]
supported_plaintext_sizes=[4096]
max_ciphertext_size=4104
"#;

#[test]
fn resume_enrollment_refuses_a_provider_this_build_cannot_construct() {
    let dir = tempfile::tempdir().unwrap();

    // Control: this `maki` binary is a release-feature build, so a plain
    // `volume create` with the fake provider is refused at validation.
    let plain_config = dir.path().join("plain.toml");
    std::fs::write(
        &plain_config,
        format!(
            "config_schema_version=1\n[volume]\nname=\"plain\"\nmax_virtual_size=\"1MiB\"\n\
             shard_logical_size=\"64KiB\"\n{FAKE_CRYPTO}[backing]\nroot={:?}\n\
             journal_segment_size=\"64KiB\"\njournal_max_bytes=\"2MiB\"\n\
             checkpoint_reserve_bytes=\"0B\"\njournal_emergency_reserve_bytes=\"0B\"\n",
            dir.path().join("plain-volume").to_str().unwrap()
        ),
    )
    .unwrap();
    let create = run(&["volume", "create", plain_config.to_str().unwrap()]);
    let create_error = String::from_utf8_lossy(&create.stderr).into_owned();
    assert!(
        !create.status.success() && create_error.contains("not compiled"),
        "control expectation failed (is fake-provider enabled for this binary?): {create_error}"
    );

    // A witness service and a half-finished remote enrollment.
    let server_key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let writer_key = rcgen::generate_simple_self_signed(vec!["writer".into()]).unwrap();
    let admin_key = rcgen::generate_simple_self_signed(vec!["admin".into()]).unwrap();
    let save = |name: &str, key: &rcgen::CertifiedKey, ca: &str| {
        let tls = TlsFiles {
            ca_file: dir.path().join(format!("{name}.ca")),
            cert_file: dir.path().join(format!("{name}.cert")),
            key_file: dir.path().join(format!("{name}.key")),
        };
        std::fs::write(&tls.ca_file, ca).unwrap();
        std::fs::write(&tls.cert_file, key.cert.pem()).unwrap();
        std::fs::write(&tls.key_file, key.key_pair.serialize_pem()).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tls.key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        tls
    };
    let server_files = save(
        "server",
        &server_key,
        &format!("{}{}", writer_key.cert.pem(), admin_key.cert.pem()),
    );
    let writer_files = save("writer", &writer_key, &server_key.cert.pem());
    let admin_files = save("admin", &admin_key, &server_key.cert.pem());
    let server = Server::new(ServerOptions {
        tls: server_files,
        timeout_ms: 2000,
        max_connections: 8,
        principals: vec![
            Principal {
                certificate_sha256: maki_witness::certificate_fingerprint(writer_key.cert.der()),
                role: Role::Writer,
            },
            Principal {
                certificate_sha256: maki_witness::certificate_fingerprint(admin_key.cert.der()),
                role: Role::Admin,
            },
        ],
    })
    .unwrap();
    let handler = maki_witness::state_handler(
        StateStore::create(&dir.path().join("authority"), [1; 16]).unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let worker = std::thread::spawn(move || {
        for accepted in listener.incoming() {
            let stream = accepted.unwrap();
            if stopped.load(Ordering::SeqCst) {
                break;
            }
            let _ = server.handle_connection(stream, handler.as_ref());
        }
    });
    let _service = Service {
        address,
        stop,
        worker: Some(worker),
    };
    let root: PathBuf = dir.path().join("volume");
    let admin_config = dir.path().join("admin.toml");
    std::fs::write(
        &admin_config,
        format!(
            r#"config_schema_version=1
[volume]
name="fake-enroll"
max_virtual_size="1MiB"
shard_logical_size="64KiB"
{FAKE_CRYPTO}[backing]
root={root:?}
journal_segment_size="64KiB"
journal_max_bytes="2MiB"
checkpoint_reserve_bytes="0B"
journal_emergency_reserve_bytes="0B"
[backing.rollback_protection]
capacity="64KiB"
[backing.rollback_protection.remote]
address="{address}"
server_name="localhost"
timeout_ms=2000
ca_file={ca:?}
client_cert_file={cert:?}
client_key_file={key:?}
"#,
            root = root.to_str().unwrap(),
            ca = admin_files.ca_file.to_str().unwrap(),
            cert = admin_files.cert_file.to_str().unwrap(),
            key = admin_files.key_file.to_str().unwrap()
        ),
    )
    .unwrap();
    let writer: Arc<dyn Rpc> = Arc::new(
        Client::new(ClientOptions {
            address,
            server_name: "localhost".into(),
            timeout_ms: 2000,
            tls: writer_files,
        })
        .unwrap(),
    );
    assert!(
        RollbackBacking::create_remote(&root, Arc::new(LoseClaims(writer.clone())), 64 * 1024)
            .is_err()
    );
    let before = inspect(writer.as_ref());
    let identity = uuid::Uuid::from_bytes(before.identity).to_string();
    let fence = before.fence.to_string();

    let output = run(&[
        "volume",
        "resume-enrollment",
        admin_config.to_str().unwrap(),
        &fence,
        &identity,
    ]);
    let after = inspect(writer.as_ref());
    assert!(
        !output.status.success(),
        "resume-enrollment initialized a provider=\"fake\" volume in a build without the \
         fake provider (stdout {}; authority fence {} -> {}, current descriptor {})",
        String::from_utf8_lossy(&output.stdout).trim(),
        before.fence,
        after.fence,
        if after.current.is_some() { "present" } else { "absent" }
    );
    assert_eq!(after, before, "a refused enrollment must not change authority");
}
