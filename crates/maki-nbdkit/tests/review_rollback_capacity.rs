//! BUG-061: an existing outer COW capacity is immutable configuration geometry.
#![cfg(target_os = "linux")]

use maki_backing::remote_witness::{Phase, StateStore};
use maki_backing::{Backing, RollbackBacking};
use maki_format::config::VolumeConfig;
use maki_nbdkit::daemon::{
    attach_from_config, build_backing, create_volume_from_config_str, existing_volume_from_config,
    parse_and_validate, DaemonError,
};
use maki_witness::{certificate_fingerprint, Principal, Role, Server, ServerOptions, TlsFiles};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const CAPACITY: u64 = 8 * 1024 * 1024;
const XTS_KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\
                       ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

fn config(root: &Path, key: &Path, rollback: &str) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "rollback-capacity"
max_virtual_size = "1MiB"
shard_logical_size = "128KiB"
device_block_size = 4096
crypto_unit_size = 4096
[crypto]
provider = "local-aes-xts"
crypto_compatibility_id = "rollback-capacity-v1"
key = {{ source = "file", name = {:?} }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4096
[backing]
root = {:?}
slot_alignment = 4096
journal_segment_size = "64KiB"
journal_max_bytes = "1MiB"
checkpoint_reserve_bytes = "64KiB"
journal_emergency_reserve_bytes = "64KiB"
{rollback}
[nbd]
minimum_io = 4096
preferred_io = 4096
maximum_io = "64KiB"
threads = 2
"#,
        key.display().to_string(),
        root.display().to_string(),
    )
}

fn write_key(directory: &Path) -> PathBuf {
    let key = directory.join("key");
    std::fs::write(&key, XTS_KEY).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    key
}

struct Local {
    directory: tempfile::TempDir,
    witness: tempfile::TempDir,
    key: PathBuf,
    config: VolumeConfig,
}

impl Local {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let witness = tempfile::tempdir_in("/dev/shm").unwrap();
        let key = write_key(directory.path());
        let rollback = format!(
            "[backing.rollback_protection]\nwitness_root = {:?}\ncapacity = \"8MiB\"",
            witness.path().display().to_string()
        );
        let raw = config(&directory.path().join("volume"), &key, &rollback);
        create_volume_from_config_str(&raw).unwrap();
        Self {
            directory,
            witness,
            key,
            config: parse_and_validate(&raw).unwrap(),
        }
    }
}

fn changed_capacity(config: &VolumeConfig, capacity: u64) -> VolumeConfig {
    let mut changed = config.clone();
    changed
        .backing
        .rollback_protection
        .as_mut()
        .unwrap()
        .capacity
        .0 = capacity;
    changed.validate().unwrap();
    changed
}

fn assert_capacity_error(error: DaemonError, configured: u64) {
    let message = error.to_string();
    assert!(message.contains("capacity"), "{message}");
    assert!(message.contains("mismatch"), "{message}");
    assert!(message.contains(&configured.to_string()), "{message}");
    assert!(message.contains(&CAPACITY.to_string()), "{message}");
}

async fn persist(config: &VolumeConfig, value: u8) {
    let engine = attach_from_config(config).await.unwrap();
    engine.write(0, &[value; 4096], true).await.unwrap();
    engine.checkpoint().await.unwrap();
    engine.stop_checkpoint_worker().await;
}

#[tokio::test]
async fn local_larger_and_smaller_capacity_refuse_attach_and_preserve_fua_data() {
    let fixture = Local::new();
    persist(&fixture.config, 0x5a).await;
    for capacity in [CAPACITY / 2, CAPACITY * 2] {
        let changed = changed_capacity(&fixture.config, capacity);
        let error = attach_from_config(&changed)
            .await
            .expect_err("changed outer COW capacity must refuse READY");
        assert_capacity_error(error, capacity);
    }
    let engine = attach_from_config(&fixture.config).await.unwrap();
    assert_eq!(engine.read(0, 4096).await.unwrap(), [0x5a; 4096]);
    engine.write(4096, &[0x6b; 4096], true).await.unwrap();
}

#[tokio::test]
async fn local_capacity_is_checked_before_loading_provider_credentials() {
    let fixture = Local::new();
    std::fs::remove_file(&fixture.key).unwrap();
    let changed = changed_capacity(&fixture.config, CAPACITY * 2);
    let error = attach_from_config(&changed)
        .await
        .expect_err("capacity mismatch must precede missing provider credentials");
    assert_capacity_error(error, CAPACITY * 2);
}

#[tokio::test]
async fn inflated_capacity_cannot_validate_unusable_reserves_then_publish_ready() {
    let fixture = Local::new();
    let mut changed = changed_capacity(&fixture.config, CAPACITY * 4);
    changed.backing.checkpoint_reserve_bytes.0 = 12 * 1024 * 1024;
    changed.backing.journal_emergency_reserve_bytes.0 = 12 * 1024 * 1024;
    changed.validate().unwrap();
    let error = attach_from_config(&changed)
        .await
        .expect_err("stored capacity cannot satisfy these configured reserves");
    assert_capacity_error(error, CAPACITY * 4);
    persist(&fixture.config, 0x7c).await;
}

#[test]
fn actual_capacity_still_rejects_an_impossible_reserve_policy() {
    let fixture = Local::new();
    let mut changed = fixture.config.clone();
    changed.backing.checkpoint_reserve_bytes.0 = 12 * 1024 * 1024;
    changed.backing.journal_emergency_reserve_bytes.0 = 12 * 1024 * 1024;
    let message = changed.validate().unwrap_err().to_string();
    assert!(message.contains("capacity") && message.contains("reserves"));
}

#[test]
fn low_level_open_without_configuration_keeps_the_stored_capacity() {
    let fixture = Local::new();
    let backing = RollbackBacking::open(
        &fixture.directory.path().join("volume"),
        fixture.witness.path(),
    )
    .unwrap();
    let free = backing.free_bytes().unwrap().unwrap();
    assert!(free > CAPACITY / 2 && free < CAPACITY);
    let lock = backing.try_lock("volume.lock").unwrap();
    drop((lock, backing));
    build_backing(&fixture.config).unwrap();
}

#[tokio::test]
async fn ordinary_backing_without_rollback_configuration_still_attaches() {
    let directory = tempfile::tempdir().unwrap();
    let key = write_key(directory.path());
    let raw = config(&directory.path().join("volume"), &key, "");
    create_volume_from_config_str(&raw).unwrap();
    let config = parse_and_validate(&raw).unwrap();
    persist(&config, 0x8d).await;
    let engine = attach_from_config(&config).await.unwrap();
    assert_eq!(engine.read(0, 4096).await.unwrap(), [0x8d; 4096]);
}

#[test]
fn removing_rollback_configuration_still_refuses_raw_fallback() {
    let fixture = Local::new();
    let mut changed = fixture.config.clone();
    changed.backing.rollback_protection = None;
    let message = build_backing(&changed).err().unwrap().to_string();
    assert!(message.contains("protected backing"), "{message}");
    build_backing(&fixture.config).unwrap();
}

fn tls_files(root: &Path, name: &str, key: &rcgen::CertifiedKey, ca: &str) -> TlsFiles {
    let files = TlsFiles {
        ca_file: root.join(format!("{name}.ca.pem")),
        cert_file: root.join(format!("{name}.cert.pem")),
        key_file: root.join(format!("{name}.key.pem")),
    };
    std::fs::write(&files.ca_file, ca).unwrap();
    std::fs::write(&files.cert_file, key.cert.pem()).unwrap();
    std::fs::write(&files.key_file, key.key_pair.serialize_pem()).unwrap();
    std::fs::set_permissions(&files.key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    files
}

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

struct Remote {
    _service: Service,
    _directory: tempfile::TempDir,
    _witness: tempfile::TempDir,
    _tls: tempfile::TempDir,
    state: Arc<Mutex<StateStore>>,
    config: VolumeConfig,
}

impl Remote {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let witness = tempfile::tempdir().unwrap();
        let tls = tempfile::tempdir().unwrap();
        let key = write_key(directory.path());
        let server_key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let writer_key = rcgen::generate_simple_self_signed(vec!["writer".into()]).unwrap();
        let server_files = tls_files(tls.path(), "server", &server_key, &writer_key.cert.pem());
        let writer_files = tls_files(tls.path(), "writer", &writer_key, &server_key.cert.pem());
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
        let serving = state.clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let ending = stop.clone();
        let worker = std::thread::spawn(move || {
            let handler = move |role, value: &[u8]| {
                let request = serde_json::from_slice(value).map_err(std::io::Error::other)?;
                let result = serving.lock().unwrap().handle(role, &request)?;
                serde_json::to_value(result).map_err(std::io::Error::other)
            };
            for socket in listener.incoming() {
                if ending.load(Ordering::SeqCst) {
                    break;
                }
                let _ = server.handle_connection(socket.unwrap(), &handler);
            }
        });
        let service = Service {
            address,
            stop,
            worker: Some(worker),
        };
        let rollback = format!(
            r#"[backing.rollback_protection]
capacity = "8MiB"
[backing.rollback_protection.remote]
address = "{address}"
server_name = "localhost"
timeout_ms = 2000
ca_file = {:?}
client_cert_file = {:?}
client_key_file = {:?}
"#,
            writer_files.ca_file.display().to_string(),
            writer_files.cert_file.display().to_string(),
            writer_files.key_file.display().to_string(),
        );
        let raw = config(&directory.path().join("volume"), &key, &rollback);
        create_volume_from_config_str(&raw).unwrap();
        Self {
            _service: service,
            _directory: directory,
            _witness: witness,
            _tls: tls,
            state,
            config: parse_and_validate(&raw).unwrap(),
        }
    }

    fn phase(&self) -> Phase {
        self.state
            .lock()
            .unwrap()
            .handle(
                Role::Writer,
                &maki_backing::remote_witness::Request {
                    operation_id: *uuid::Uuid::new_v4().as_bytes(),
                    expected: None,
                    action: maki_backing::remote_witness::Action::Inspect,
                    authorization: None,
                },
            )
            .unwrap()
            .phase
    }
}

#[tokio::test]
async fn remote_larger_and_smaller_capacity_refuse_attach_release_and_preserve_data() {
    let fixture = Remote::new();
    persist(&fixture.config, 0x9e).await;
    for capacity in [CAPACITY / 2, CAPACITY * 2] {
        let changed = changed_capacity(&fixture.config, capacity);
        let error = attach_from_config(&changed)
            .await
            .expect_err("remote COW capacity mismatch must refuse READY");
        assert_capacity_error(error, capacity);
        assert_eq!(fixture.phase(), Phase::Released);
    }
    let engine = attach_from_config(&fixture.config).await.unwrap();
    assert_eq!(engine.read(0, 4096).await.unwrap(), [0x9e; 4096]);
    engine.write(4096, &[0xaf; 4096], true).await.unwrap();
    engine.stop_checkpoint_worker().await;
    drop(engine);
    assert_eq!(fixture.phase(), Phase::Released);
}

#[tokio::test]
async fn existing_remote_volume_probe_preserves_identity_data_and_releases_session() {
    let fixture = Remote::new();
    persist(&fixture.config, 0x70).await;
    let engine = attach_from_config(&fixture.config).await.unwrap();
    let before = engine.geometry().clone();
    engine.stop_checkpoint_worker().await;
    drop(engine);
    let first = existing_volume_from_config(&fixture.config)
        .unwrap()
        .unwrap();
    let second = existing_volume_from_config(&fixture.config)
        .unwrap()
        .unwrap();
    assert_eq!(first.volume_uuid, second.volume_uuid);
    assert_eq!(first.geometry, before);
    assert_eq!(fixture.phase(), Phase::Released);
    let engine = attach_from_config(&fixture.config).await.unwrap();
    assert_eq!(engine.read(0, 4096).await.unwrap(), [0x70; 4096]);
    engine.stop_checkpoint_worker().await;
}

#[test]
fn existing_remote_volume_probe_rejects_capacity_mismatch_and_releases_session() {
    let fixture = Remote::new();
    let changed = changed_capacity(&fixture.config, CAPACITY * 2);
    assert_capacity_error(
        existing_volume_from_config(&changed).unwrap_err(),
        CAPACITY * 2,
    );
    assert_eq!(fixture.phase(), Phase::Released);
}
