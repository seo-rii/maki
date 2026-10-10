#![cfg(target_os = "linux")]

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use maki_backing::remote_witness::{
    Action, Descriptor, Phase, Record, Request, Role, Rpc, StateStore,
};
use maki_backing::{Backing, RollbackBacking};
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
    _service: Service,
    dir: tempfile::TempDir,
    root: PathBuf,
    writer_config: PathBuf,
    admin_config: PathBuf,
    writer: Arc<dyn Rpc>,
}
fn inspect(rpc: &dyn Rpc) -> Record {
    rpc.call(&Request {
        operation_id: *uuid::Uuid::new_v4().as_bytes(),
        expected: None,
        action: Action::Inspect,
    })
    .unwrap()
}
fn root_hex(record: &Record) -> String {
    record
        .current
        .as_ref()
        .unwrap()
        .anchor
        .root
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn descriptor_hex(descriptor: &Descriptor) -> String {
    descriptor
        .anchor
        .root
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_maki"))
        .args(args)
        .output()
        .unwrap()
}
fn success(args: &[&str]) -> Output {
    let result = run(args);
    assert!(
        result.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    result
}
fn failure(args: &[&str], message: &str) {
    let result = run(args);
    assert!(!result.status.success(), "unexpected success: {args:?}");
    let error = String::from_utf8_lossy(&result.stderr);
    assert!(error.contains(message), "expected {message:?}, got {error}");
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
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
            std::fs::set_permissions(&tls.key_file, std::fs::Permissions::from_mode(0o600))
                .unwrap();
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
                    certificate_sha256: maki_witness::certificate_fingerprint(
                        writer_key.cert.der(),
                    ),
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
        let root = dir.path().join("volume");
        let config = |tls: &TlsFiles| {
            format!(
                r#"config_schema_version=1
[volume]
name="admin-test"
max_virtual_size="1MiB"
shard_logical_size="64KiB"
[crypto]
provider="local-aes-gcm-siv"
crypto_compatibility_id="local-aes-gcm-siv-v1"
key={{source="env",name="unused-admin-key"}}
[crypto.capabilities]
supported_plaintext_sizes=[4096]
max_ciphertext_size=4384
[backing]
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
                ca = tls.ca_file.to_str().unwrap(),
                cert = tls.cert_file.to_str().unwrap(),
                key = tls.key_file.to_str().unwrap()
            )
        };
        let writer_config = dir.path().join("writer.toml");
        let admin_config = dir.path().join("admin.toml");
        let writer_text = config(&writer_files);
        maki_format::config::parse_config(&writer_text)
            .unwrap()
            .validate()
            .unwrap();
        std::fs::write(&writer_config, writer_text).unwrap();
        std::fs::write(&admin_config, config(&admin_files)).unwrap();
        let client = |tls| {
            Arc::new(
                Client::new(ClientOptions {
                    address,
                    server_name: "localhost".into(),
                    timeout_ms: 2000,
                    tls,
                })
                .unwrap(),
            ) as Arc<dyn Rpc>
        };
        Self {
            _service: Service {
                address,
                stop,
                worker: Some(worker),
            },
            dir,
            root,
            writer_config,
            admin_config,
            writer: client(writer_files),
        }
    }
    fn create(&self) -> RollbackBacking {
        RollbackBacking::create_remote(&self.root, self.writer.clone(), 64 * 1024).unwrap()
    }
    fn path(&self, admin: bool) -> &str {
        if admin {
            &self.admin_config
        } else {
            &self.writer_config
        }
        .to_str()
        .unwrap()
    }
}
fn write(backing: &RollbackBacking, data: &[u8]) {
    let file = backing.open("ciphertext", true).unwrap();
    file.write_at(0, data).unwrap();
    file.set_len(data.len() as u64).unwrap();
    file.sync_data().unwrap();
    backing.sync_dir("").unwrap();
}
fn read(backing: &RollbackBacking) -> Vec<u8> {
    let file = backing.open("ciphertext", false).unwrap();
    let mut bytes = vec![0; file.len().unwrap() as usize];
    file.read_at(0, &mut bytes).unwrap();
    bytes
}

#[test]
fn witness_inspection_is_read_only_and_prints_exact_record() {
    let fixture = Fixture::new();
    let backing = fixture.create();
    let before = inspect(fixture.writer.as_ref());
    let output = success(&["volume", "witness", fixture.path(false)]);
    let record: Record = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(record, before);
    assert_eq!(inspect(fixture.writer.as_ref()), before);
    drop(backing);
}

#[test]
fn snapshot_is_durable_canonical_and_refuses_live_writer_or_existing_target() {
    let fixture = Fixture::new();
    let backing = fixture.create();
    write(&backing, b"ciphertext-old");
    let target = fixture.dir.path().join("backup");
    assert!(!run(&[
        "volume",
        "snapshot",
        fixture.path(false),
        target.to_str().unwrap()
    ])
    .status
    .success());
    assert!(!target.exists());
    drop(backing);
    let output = success(&[
        "volume",
        "snapshot",
        fixture.path(false),
        target.to_str().unwrap(),
    ]);
    let descriptor: Descriptor = serde_json::from_slice(&output.stdout).unwrap();
    let bytes = std::fs::read(target.join("snapshot.json")).unwrap();
    assert_eq!(bytes, serde_json::to_vec(&descriptor).unwrap());
    assert_eq!(inspect(fixture.writer.as_ref()).phase, Phase::Released);
    assert!(!run(&[
        "volume",
        "snapshot",
        fixture.path(false),
        target.to_str().unwrap()
    ])
    .status
    .success());
    assert_eq!(std::fs::read(target.join("snapshot.json")).unwrap(), bytes);
}

#[test]
fn takeover_requires_admin_exact_fence_and_current_root_and_revokes_old_writer() {
    let fixture = Fixture::new();
    let old = fixture.create();
    write(&old, b"ciphertext-current");
    let before = inspect(fixture.writer.as_ref());
    let fence = before.fence.to_string();
    let hash = root_hex(&before);
    for (admin, approval_fence, approval_root) in [
        (false, fence.clone(), hash.clone()),
        (true, (before.fence + 1).to_string(), hash.clone()),
        (true, fence.clone(), "00".repeat(32)),
    ] {
        failure(
            &[
                "volume",
                "takeover",
                fixture.path(admin),
                &approval_fence,
                &approval_root,
            ],
            if admin {
                "approval does not match"
            } else {
                "witness operation denied"
            },
        );
        assert_eq!(inspect(fixture.writer.as_ref()), before);
    }
    let output = success(&["volume", "takeover", fixture.path(true), &fence, &hash]);
    let after: Record = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(after.phase, Phase::Released);
    assert_eq!(after.fence, before.fence + 1);
    assert_eq!(root_hex(&after), hash);
    assert!(old.check_freshness().is_err());
    drop(old);
    let reopened = RollbackBacking::open_remote(&fixture.root, fixture.writer.clone()).unwrap();
    assert_eq!(read(&reopened), b"ciphertext-current");
}

#[test]
fn restore_requires_approved_snapshot_root_and_advances_epoch_without_lowering_generation() {
    let fixture = Fixture::new();
    let backing = fixture.create();
    write(&backing, b"ciphertext-old");
    drop(backing);
    let backup = fixture.dir.path().join("backup");
    let snapshot = success(&[
        "volume",
        "snapshot",
        fixture.path(false),
        backup.to_str().unwrap(),
    ]);
    let source: Descriptor = serde_json::from_slice(&snapshot.stdout).unwrap();
    let live = RollbackBacking::open_remote(&fixture.root, fixture.writer.clone()).unwrap();
    write(&live, b"ciphertext-new");
    let before = inspect(fixture.writer.as_ref());
    let fence = before.fence.to_string();
    let current = root_hex(&before);
    let approved = descriptor_hex(&source);
    for (admin, approval_fence, approval_current, approval_source) in [
        (false, fence.clone(), current.clone(), approved.clone()),
        (
            true,
            (before.fence + 1).to_string(),
            current.clone(),
            approved.clone(),
        ),
        (true, fence.clone(), "00".repeat(32), approved.clone()),
        (true, fence.clone(), current.clone(), "00".repeat(32)),
    ] {
        failure(
            &[
                "volume",
                "restore",
                fixture.path(admin),
                backup.to_str().unwrap(),
                &approval_fence,
                &approval_current,
                &approval_source,
            ],
            if !admin {
                "witness operation denied"
            } else if approval_source != approved {
                "independently approved root"
            } else {
                "approval does not match"
            },
        );
        assert_eq!(inspect(fixture.writer.as_ref()), before);
    }
    let output = success(&[
        "volume",
        "restore",
        fixture.path(true),
        backup.to_str().unwrap(),
        &fence,
        &current,
        &approved,
    ]);
    let after: Record = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(after.phase, Phase::Released);
    assert_eq!(
        after.current.as_ref().unwrap().epoch,
        before.current.as_ref().unwrap().epoch + 1
    );
    assert_eq!(
        after.current.as_ref().unwrap().anchor.generation,
        before.current.as_ref().unwrap().anchor.generation + 1
    );
    assert!(live.check_freshness().is_err());
    drop(live);
    let reopened = RollbackBacking::open_remote(&fixture.root, fixture.writer.clone()).unwrap();
    assert_eq!(read(&reopened), b"ciphertext-old");
}

#[test]
fn malformed_and_unbounded_snapshot_descriptors_do_not_change_authority() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let backing = fixture.create();
    write(&backing, b"ciphertext");
    drop(backing);
    let backup = fixture.dir.path().join("backup");
    let snapshot = success(&[
        "volume",
        "snapshot",
        fixture.path(false),
        backup.to_str().unwrap(),
    ]);
    let source: Descriptor = serde_json::from_slice(&snapshot.stdout).unwrap();
    let good = std::fs::read(backup.join("snapshot.json")).unwrap();
    let before = inspect(fixture.writer.as_ref());
    let fence = before.fence.to_string();
    let hash = root_hex(&before);
    let approved = descriptor_hex(&source);
    let mut extra = serde_json::to_value(&source).unwrap();
    extra["unknown"] = serde_json::json!(true);
    for bad in [
        vec![b'x'; 65537],
        serde_json::to_vec(&extra).unwrap(),
        serde_json::to_string_pretty(&source).unwrap().into_bytes(),
        good[..good.len() / 2].to_vec(),
    ] {
        std::fs::write(backup.join("snapshot.json"), bad).unwrap();
        assert!(!run(&[
            "volume",
            "restore",
            fixture.path(true),
            backup.to_str().unwrap(),
            &fence,
            &hash,
            &approved
        ])
        .status
        .success());
        assert_eq!(inspect(fixture.writer.as_ref()), before);
    }
    std::fs::write(backup.join("other.json"), &good).unwrap();
    std::fs::remove_file(backup.join("snapshot.json")).unwrap();
    symlink(backup.join("other.json"), backup.join("snapshot.json")).unwrap();
    assert!(!run(&[
        "volume",
        "restore",
        fixture.path(true),
        backup.to_str().unwrap(),
        &fence,
        &hash,
        &approved
    ])
    .status
    .success());
    assert_eq!(inspect(fixture.writer.as_ref()), before);
    let missing = fixture.dir.path().join("absent");
    assert!(!run(&[
        "volume",
        "restore",
        fixture.path(true),
        missing.to_str().unwrap(),
        &fence,
        &hash,
        &approved
    ])
    .status
    .success());
    assert!(!missing.exists());
}

#[test]
fn admin_approval_syntax_and_nonremote_configs_fail_before_mutation() {
    let fixture = Fixture::new();
    let backing = fixture.create();
    let before = inspect(fixture.writer.as_ref());
    for (fence, hash) in [
        ("-1", "00".repeat(32)),
        ("1", "ff".repeat(31)),
        ("1", "GG".repeat(32)),
    ] {
        assert!(
            !run(&["volume", "takeover", fixture.path(true), fence, &hash])
                .status
                .success()
        );
        assert_eq!(inspect(fixture.writer.as_ref()), before);
    }
    let raw = std::fs::read_to_string(&fixture.writer_config).unwrap();
    let plain = fixture.dir.path().join("plain.toml");
    std::fs::write(
        &plain,
        raw.split("[backing.rollback_protection]").next().unwrap(),
    )
    .unwrap();
    assert!(!run(&["volume", "witness", plain.to_str().unwrap()])
        .status
        .success());
    drop(backing);
}
