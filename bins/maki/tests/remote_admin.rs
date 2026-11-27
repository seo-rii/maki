#![cfg(target_os = "linux")]

#[path = "support/volume_config.rs"]
mod volume_config;

#[path = "support/short_dir.rs"]
mod short_dir;

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use maki_backing::remote_witness::{
    namespace, Action, Descriptor, Phase, Record, Request, Role, Rpc, SessionAuthorization,
    StateStore,
};
use maki_backing::{Backing, RollbackBacking};
use maki_witness::{Client, ClientOptions, Principal, Server, ServerOptions, TlsFiles};

const KEY_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

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
    /// The action of every request the authority was sent, in order.
    actions: Arc<Mutex<Vec<&'static str>>>,
    /// Set to `n`, an administrator takes the authority over, elsewhere,
    /// right after the `n`th inspection from now is answered.
    takeover_after: Arc<Mutex<Option<usize>>>,
    /// Where a data configuration's control socket is bound.
    sockets: tempfile::TempDir,
}
fn action_name(action: &Action) -> &'static str {
    match action {
        Action::Inspect => "inspect",
        Action::Claim => "claim",
        Action::Takeover => "takeover",
        Action::RecoverEnrollment => "recover-enrollment",
        Action::ClaimRestore { .. } => "claim-restore",
        Action::Activate { .. } => "activate",
        Action::Advance { .. } => "advance",
        Action::Release => "release",
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
        let state = maki_witness::state_handler(
            StateStore::create(&dir.path().join("authority"), [1; 16]).unwrap(),
        );
        let actions = Arc::new(Mutex::new(Vec::new()));
        let takeover_after = Arc::new(Mutex::new(None::<usize>));
        let sent = actions.clone();
        let countdown = takeover_after.clone();
        let handler: Arc<maki_witness::Handler> = Arc::new(move |role, request: &[u8]| {
            let parsed = serde_json::from_slice::<Request>(request).ok();
            if let Some(request) = &parsed {
                sent.lock().unwrap().push(action_name(&request.action));
            }
            let answer = state(role, request)?;
            if parsed.is_some_and(|request| request.action == Action::Inspect) {
                let mut countdown = countdown.lock().unwrap();
                if let Some(remaining) = countdown.as_mut() {
                    *remaining -= 1;
                    if *remaining == 0 {
                        *countdown = None;
                        let takeover = Request {
                            operation_id: *uuid::Uuid::new_v4().as_bytes(),
                            expected: Some(serde_json::from_value(answer.clone()).unwrap()),
                            action: Action::Takeover,
                            authorization: Some(SessionAuthorization::generate().unwrap()),
                        };
                        state(Role::Admin, &serde_json::to_vec(&takeover).unwrap())?;
                    }
                }
            }
            Ok(answer)
        });
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
        volume_config::write(&writer_config, writer_text).unwrap();
        volume_config::write(&admin_config, config(&admin_files)).unwrap();
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
            actions,
            takeover_after,
            sockets: short_dir::tempdir().unwrap(),
        }
    }
    fn create(&self) -> RollbackBacking {
        RollbackBacking::create_remote(&self.root, self.writer.clone(), 64 * 1024).unwrap()
    }
    /// A configuration `name` of the writer for a volume that holds data:
    /// a key in a file, a capacity the data fits in and a control socket of
    /// its own, with `edit` applied to its text.
    fn data_config(&self, name: &str, edit: (&str, &str)) -> PathBuf {
        let key = self.dir.path().join("volume.key");
        std::fs::write(&key, KEY_HEX).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let socket = self.sockets.path().join(format!("{name}.sock"));
        let text = std::fs::read_to_string(&self.writer_config)
            .unwrap()
            .replace(
                r#"key={source="env",name="unused-admin-key"}"#,
                &format!("key={{source=\"file\",name={:?}}}", key.to_str().unwrap()),
            )
            .replace(r#"capacity="64KiB""#, r#"capacity="8MiB""#)
            + &format!("[control]\nsocket={:?}\n", socket.to_str().unwrap());
        assert!(text.contains(edit.0), "{edit:?}");
        let path = self.dir.path().join(name);
        volume_config::write(&path, text.replace(edit.0, edit.1)).unwrap();
        path
    }

    /// Forget the actions sent so far.
    fn clear(&self) {
        self.actions.lock().unwrap().clear();
    }

    /// The actions sent since the last [`Self::clear`].
    fn sent(&self) -> Vec<&'static str> {
        self.actions.lock().unwrap().clone()
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
    let before = inspect(fixture.writer.as_ref());
    assert_eq!(before.phase, Phase::Released);
    assert!(!run(&[
        "volume",
        "snapshot",
        fixture.path(false),
        target.to_str().unwrap()
    ])
    .status
    .success());
    assert_eq!(inspect(fixture.writer.as_ref()), before);
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

fn run_with_stdout(args: &[&str], stdout: std::process::Stdio) -> Output {
    Command::new(env!("CARGO_BIN_EXE_maki"))
        .args(args)
        .env("RUST_BACKTRACE", "0")
        .stdout(stdout)
        .output()
        .unwrap()
}

/// `println!` panicked on the record: with a stdout reader that had gone,
/// an inspection exited 101, and so did a takeover that had already moved
/// the fence. The reader has what it wanted; the command's status stands.
#[test]
fn a_closed_stdout_fails_neither_an_inspection_nor_a_completed_takeover() {
    let closed_pipe = || -> std::process::Stdio {
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        writer.into()
    };
    let fixture = Fixture::new();
    let old = fixture.create();
    write(&old, b"ciphertext-current");
    let before = inspect(fixture.writer.as_ref());

    let inspected = run_with_stdout(&["volume", "witness", fixture.path(false)], closed_pipe());
    let stderr = String::from_utf8_lossy(&inspected.stderr);
    assert_eq!(inspected.status.code(), Some(0), "{stderr}");
    assert!(inspected.stderr.is_empty(), "{stderr}");
    assert_eq!(inspect(fixture.writer.as_ref()), before);

    let taken = run_with_stdout(
        &[
            "volume",
            "takeover",
            fixture.path(true),
            &before.fence.to_string(),
            &root_hex(&before),
        ],
        closed_pipe(),
    );
    let stderr = String::from_utf8_lossy(&taken.stderr);
    assert_eq!(taken.status.code(), Some(0), "{stderr}");
    assert!(taken.stderr.is_empty(), "{stderr}");
    let after = inspect(fixture.writer.as_ref());
    assert_eq!(after.phase, Phase::Released);
    assert_eq!(after.fence, before.fence + 1);
    assert!(old.check_freshness().is_err());
}

/// A record that cannot be written (a full destination) fails an inspection,
/// whose output is its result. A takeover has already moved the fence, and
/// the same approval would be refused on a retry: it reports the failure and
/// still succeeds, like `volume create`.
#[test]
fn an_unwritable_record_fails_an_inspection_but_not_a_completed_takeover() {
    let full = || -> std::process::Stdio {
        std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap()
            .into()
    };
    let fixture = Fixture::new();
    let old = fixture.create();
    let before = inspect(fixture.writer.as_ref());

    let inspected = run_with_stdout(&["volume", "witness", fixture.path(false)], full());
    let stderr = String::from_utf8_lossy(&inspected.stderr);
    assert_eq!(inspected.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("error: writing the output failed"),
        "{stderr}"
    );

    let taken = run_with_stdout(
        &[
            "volume",
            "takeover",
            fixture.path(true),
            &before.fence.to_string(),
            &root_hex(&before),
        ],
        full(),
    );
    let stderr = String::from_utf8_lossy(&taken.stderr);
    assert_eq!(taken.status.code(), Some(0), "{stderr}");
    assert!(
        stderr.contains("warning: volume takeover completed, but writing its result failed"),
        "{stderr}"
    );
    assert_eq!(inspect(fixture.writer.as_ref()).fence, before.fence + 1);
    drop(old);
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

/// Every entry below `root` with its mode, its bytes if it is a file, and
/// its modification time, which a rewrite of identical bytes and a created
/// or removed entry (in its directory) change.
fn tree(root: &std::path::Path) -> Vec<(PathBuf, u32, Option<Vec<u8>>, SystemTime)> {
    use std::os::unix::fs::PermissionsExt;
    let mut entries = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        let bytes = if metadata.is_dir() {
            for entry in std::fs::read_dir(&path).unwrap() {
                pending.push(entry.unwrap().path());
            }
            None
        } else {
            Some(std::fs::read(&path).unwrap())
        };
        entries.push((
            path,
            metadata.permissions().mode(),
            bytes,
            metadata.modified().unwrap(),
        ));
    }
    entries.sort();
    entries
}

fn set_modes(root: &std::path::Path, file: u32, directory: u32) {
    use std::os::unix::fs::PermissionsExt;
    for (path, mode, _, _) in tree(root) {
        let mode = if mode & 0o040000 != 0 {
            directory
        } else {
            file
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
}

/// `maki volume restore` only reads its snapshot, so a snapshot kept where
/// the administrator cannot change it restores. The command opened
/// `snapshot.json` and the snapshot's files read-write and failed with
/// "Permission denied" (EROFS on a read-only mount) before asking the
/// authority anything. Root ignores mode bits, so a root test drops
/// CAP_DAC_OVERRIDE from the command's bounding set before it runs.
#[test]
fn restore_reads_a_snapshot_it_may_not_write() {
    use std::os::unix::process::CommandExt;
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
    drop(live);
    let before = inspect(fixture.writer.as_ref());
    set_modes(&backup, 0o400, 0o500);
    let unchanged = tree(&backup);
    let mut command = Command::new(env!("CARGO_BIN_EXE_maki"));
    command.args([
        "volume",
        "restore",
        fixture.path(true),
        backup.to_str().unwrap(),
        &before.fence.to_string(),
        &root_hex(&before),
        &descriptor_hex(&source),
    ]);
    // SAFETY: runs in the forked child before exec and only makes raw
    // system calls.
    unsafe {
        command.pre_exec(|| {
            const CAP_DAC_OVERRIDE: libc::c_ulong = 1;
            if libc::geteuid() == 0
                && libc::prctl(libc::PR_CAPBSET_DROP, CAP_DAC_OVERRIDE, 0, 0, 0) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command.output();
    let after = tree(&backup);
    set_modes(&backup, 0o600, 0o700);
    let output = match output {
        Ok(output) => output,
        Err(error) => {
            eprintln!("skipping: cannot drop CAP_DAC_OVERRIDE for the command ({error})");
            return;
        }
    };
    assert!(
        output.status.success(),
        "restore from a snapshot it may not write: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(after, unchanged, "restore changed its snapshot");
    let record: Record = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(record.phase, Phase::Released);
    assert_eq!(
        record.current.as_ref().unwrap().epoch,
        before.current.as_ref().unwrap().epoch + 1
    );
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
    volume_config::write(
        &plain,
        raw.split("[backing.rollback_protection]").next().unwrap(),
    )
    .unwrap();
    assert!(!run(&["volume", "witness", plain.to_str().unwrap()])
        .status
        .success());
    drop(backing);
}

#[test]
fn gc_keeps_live_revoked_writer_and_reclaims_it_after_drop() {
    let f = Fixture::new();
    let old = f.create();
    let before = inspect(f.writer.as_ref());
    success(&[
        "volume",
        "takeover",
        f.path(true),
        &before.fence.to_string(),
        &root_hex(&before),
    ]);
    let output = success(&["volume", "gc", f.path(false)]);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["skipped_live"].as_array().unwrap().len(), 1);
    assert_eq!(report["counts"]["skipped_live"], 1);
    assert_eq!(report["counts"]["removed"], 0);
    assert_eq!(report["details_truncated"], false);
    drop(old);
    let output = success(&["volume", "gc", f.path(false)]);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["removed"].as_array().unwrap().len(), 1);
    assert_eq!(report["counts"]["removed"], 1);
    assert_eq!(report["counts"]["skipped_live"], 0);
    assert_eq!(report["details_truncated"], false);
}
/// A stale namespace GC cannot examine is kept and does not end the pass:
/// `maki volume gc` names it with the reason, and the automatic pass after
/// an activation says in the log what it left behind.
#[test]
fn gc_reports_a_namespace_it_cannot_examine_and_reclaims_the_rest() {
    let f = Fixture::new();
    drop(f.create());
    // A quiescent stale namespace holding a directory where its arena file
    // belongs, whose name sorts before the created one: whoever runs GC
    // cannot open that arena as a file.
    let mut session = [0; 16];
    session[15] = 1;
    let odd = namespace(1, session);
    std::fs::create_dir(f.root.join(&odd)).unwrap();
    std::fs::write(f.root.join(&odd).join("rollback.lock"), b"").unwrap();
    std::fs::create_dir(f.root.join(&odd).join("rollback.arena")).unwrap();
    let namespaces = || {
        let mut names: Vec<String> = std::fs::read_dir(&f.root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.starts_with("remote-0"))
            .collect();
        names.sort();
        names
    };

    let before = inspect(f.writer.as_ref());
    let takeover = success(&[
        "volume",
        "takeover",
        f.path(true),
        &before.fence.to_string(),
        &root_hex(&before),
    ]);
    let current = inspect(f.writer.as_ref()).current.unwrap().namespace;
    assert_eq!(
        namespaces(),
        [odd.clone(), current],
        "the automatic pass must retire the predecessor"
    );
    let log = String::from_utf8_lossy(&takeover.stderr);
    assert!(
        log.contains("WARN") && log.contains(&odd) && log.contains("Is a directory"),
        "the automatic pass must log the namespace it kept and why: {log}"
    );

    let output = success(&["volume", "gc", f.path(false)]);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let unreadable = report["skipped_unreadable"].as_array().unwrap();
    assert_eq!(unreadable.len(), 1, "{report}");
    assert_eq!(unreadable[0]["name"], odd.as_str());
    let error = unreadable[0]["error"].as_str().unwrap();
    assert!(
        error.contains("rollback.arena") && error.contains("Is a directory"),
        "{error}"
    );
    assert_eq!(report["counts"]["skipped_unreadable"], 1);
    assert_eq!(report["counts"]["skipped_unrecognized"], 0);
    assert_eq!(report["counts"]["removed"], 0);
    assert_eq!(report["details_truncated"], false);
    assert!(f.root.join(&odd).join("rollback.arena").is_dir());
}
/// Run `maki` with `args` as a caller file modes apply to: a root test drops
/// CAP_DAC_OVERRIDE from the command's bounding set before it runs. `None`,
/// with the reason printed, where that cannot be done.
fn run_under_modes(args: &[&str]) -> Option<Output> {
    use std::os::unix::process::CommandExt;
    let mut command = Command::new(env!("CARGO_BIN_EXE_maki"));
    command.args(args);
    // SAFETY: runs in the forked child before exec and only makes raw
    // system calls.
    unsafe {
        command.pre_exec(|| {
            const CAP_DAC_OVERRIDE: libc::c_ulong = 1;
            if libc::geteuid() == 0
                && libc::prctl(libc::PR_CAPBSET_DROP, CAP_DAC_OVERRIDE, 0, 0, 0) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    match command.output() {
        Ok(output) => Some(output),
        Err(error) => {
            eprintln!("skipping: cannot drop CAP_DAC_OVERRIDE for the command ({error})");
            None
        }
    }
}
/// A predecessor namespace GC may examine but not empty is renamed to a
/// tombstone that every later pass meets first. That must not end the
/// pass: `maki volume gc` names the tombstone with the step that failed,
/// and the namespaces behind it are reclaimed.
#[test]
fn gc_reports_a_tombstone_it_cannot_empty_and_reclaims_the_rest() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    drop(f.create());
    let namespaces = || {
        let mut names: Vec<String> = std::fs::read_dir(&f.root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.starts_with("remote-0"))
            .collect();
        names.sort();
        names
    };
    let set_mode = |name: &str, mode| {
        std::fs::set_permissions(f.root.join(name), std::fs::Permissions::from_mode(mode)).unwrap()
    };
    let stuck = namespaces().pop().unwrap();
    let tombstone = format!(".remote-gc-{stuck}");
    set_mode(&stuck, 0o500);
    let takeover = || {
        let before = inspect(f.writer.as_ref());
        run_under_modes(&[
            "volume",
            "takeover",
            f.path(true),
            &before.fence.to_string(),
            &root_hex(&before),
        ])
    };
    let succeeded = |output: &Output| {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };

    let Some(first) = takeover() else {
        set_mode(&stuck, 0o700);
        return;
    };
    succeeded(&first);
    assert!(f.root.join(&tombstone).is_dir());
    let second = takeover().unwrap();
    succeeded(&second);
    let current = inspect(f.writer.as_ref()).current.unwrap().namespace;
    assert_eq!(
        namespaces(),
        [current],
        "the automatic pass must retire the predecessor past the tombstone"
    );
    let log = String::from_utf8_lossy(&second.stderr);
    assert!(
        log.contains("WARN")
            && log.contains(&tombstone)
            && log.contains("unlinking rollback.arena"),
        "the automatic pass must log the tombstone it could not empty and why: {log}"
    );

    let output = run_under_modes(&["volume", "gc", f.path(false)]).unwrap();
    succeeded(&output);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let unfinished = report["unfinished"].as_array().unwrap();
    assert_eq!(unfinished.len(), 1, "{report}");
    assert_eq!(unfinished[0]["name"], tombstone.as_str());
    assert_eq!(
        unfinished[0]["error"],
        "unlinking rollback.arena: Permission denied (os error 13)"
    );
    assert_eq!(report["counts"]["unfinished"], 1);
    assert_eq!(report["counts"]["skipped_unreadable"], 0);
    assert_eq!(report["counts"]["removed"], 0);
    assert!(f.root.join(&tombstone).join("rollback.arena").is_file());

    set_mode(&tombstone, 0o700);
    let output = success(&["volume", "gc", f.path(false)]);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["removed"], serde_json::json!([stuck]));
    assert_eq!(report["counts"]["unfinished"], 0);
}
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
#[test]
fn resume_enrollment_requires_admin_identity_fence_and_completes_volume_initialization() {
    for discard in [false, true] {
        let f = Fixture::new();
        assert!(RollbackBacking::create_remote(
            &f.root,
            Arc::new(LoseClaims(f.writer.clone())),
            64 * 1024
        )
        .is_err());
        let before = inspect(f.writer.as_ref());
        let identity = uuid::Uuid::from_bytes(before.identity).to_string();
        let fence = before.fence.to_string();
        for (admin, approved_fence, approved_identity) in [
            (false, fence.clone(), identity.clone()),
            (true, (before.fence + 1).to_string(), identity.clone()),
            (true, fence.clone(), uuid::Uuid::new_v4().to_string()),
        ] {
            assert!(!run(&[
                "volume",
                "resume-enrollment",
                f.path(admin),
                &approved_fence,
                &approved_identity
            ])
            .status
            .success());
            assert_eq!(inspect(f.writer.as_ref()), before);
        }
        let mut args = vec![
            "volume",
            "resume-enrollment",
            f.path(true),
            &fence,
            &identity,
        ];
        if discard {
            args.push("--discard");
        }
        let output = success(&args);
        let after: Record = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(after.identity, before.identity);
        assert_eq!(after.fence, before.fence + 1);
        assert_eq!(after.phase, Phase::Released);
        assert!(after.current.is_some());
        let inspected = success(&["volume", "inspect", f.path(false)]);
        assert!(String::from_utf8_lossy(&inspected.stdout).contains("uuid:"));
        assert_eq!(inspect(f.writer.as_ref()), after);
        // This fixture explicitly acquires a writer to verify initialization.
        // The diagnostic CLI must never acquire that writer implicitly.
        let backing = RollbackBacking::open_remote(&f.root, f.writer.clone()).unwrap();
        let envelope = maki_format::superblock::load_volume_superblock(&backing).unwrap();
        assert_eq!(envelope.superblock.geometry.max_virtual_size, 1 << 20);
        assert_eq!(envelope.superblock.provider_type, "local-aes-gcm-siv");
        drop(backing);
        assert!(!run(&args).status.success());
    }
}

/// A `volume create` that fails while it writes the format marker (a full
/// disk; here a zero file-size limit refuses the write) has claimed nothing
/// from the authority, and running the same command again completes it.
#[test]
fn volume_create_whose_marker_write_failed_can_be_run_again() {
    use std::os::unix::process::CommandExt;
    let f = Fixture::new();
    let mut create = Command::new(env!("CARGO_BIN_EXE_maki"));
    create.args(["volume", "create", f.path(false)]);
    // SAFETY: the closure makes two async-signal-safe calls between fork
    // and exec. An ignored SIGXFSZ and the limit are kept across exec.
    unsafe {
        create.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::signal(libc::SIGXFSZ, libc::SIG_IGN) == libc::SIG_ERR
                || libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let failed = create.output().unwrap();
    assert!(!failed.status.success());
    let error = String::from_utf8_lossy(&failed.stderr);
    assert!(error.contains("File too large"), "{error}");
    let untouched = inspect(f.writer.as_ref());
    assert_eq!((untouched.fence, untouched.phase), (0, Phase::Released));

    let output = success(&["volume", "create", f.path(false)]);
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("created volume admin-test"),
        "{output:?}"
    );
    let created = inspect(f.writer.as_ref());
    assert_eq!((created.fence, created.phase), (1, Phase::Released));
    assert!(created.current.is_some());
}

/// Whether this `maki` binary has the test-only `fake` provider compiled in.
/// `cargo test --workspace` unifies the nbdkit crate's own dev-dependency
/// features into every binary; `cargo test -p maki` builds the feature set a
/// release has, where a plain `volume create` refuses the provider (M-008).
fn fake_provider_compiled(dir: &std::path::Path) -> bool {
    let config = dir.join("fake-probe.toml");
    volume_config::write(
        &config,
        format!(
            "config_schema_version=1\n[volume]\nname=\"fake-probe\"\nmax_virtual_size=\"1MiB\"\n\
             shard_logical_size=\"64KiB\"\n[crypto]\nprovider=\"fake\"\n\
             crypto_compatibility_id=\"test-profile-v1\"\n[crypto.capabilities]\n\
             supported_plaintext_sizes=[4096]\nmax_ciphertext_size=4104\n[backing]\nroot={:?}\n\
             journal_segment_size=\"64KiB\"\njournal_max_bytes=\"2MiB\"\n\
             checkpoint_reserve_bytes=\"0B\"\njournal_emergency_reserve_bytes=\"0B\"\n",
            dir.join("fake-probe").to_str().unwrap()
        ),
    )
    .unwrap();
    let output = run(&["volume", "create", config.to_str().unwrap()]);
    let error = String::from_utf8_lossy(&output.stderr);
    if output.status.success() {
        return true;
    }
    assert!(
        error.contains("not compiled"),
        "unexpected probe failure: {error}"
    );
    false
}

#[test]
fn resume_enrollment_refuses_a_provider_this_build_cannot_construct() {
    let f = Fixture::new();
    if fake_provider_compiled(f.dir.path()) {
        eprintln!(
            "skipped: this maki binary includes the fake provider (feature unification); \
             run `cargo test -p maki` to exercise the release feature set"
        );
        return;
    }
    assert!(RollbackBacking::create_remote(
        &f.root,
        Arc::new(LoseClaims(f.writer.clone())),
        64 * 1024
    )
    .is_err());
    let before = inspect(f.writer.as_ref());
    let identity = uuid::Uuid::from_bytes(before.identity).to_string();
    let fence = before.fence.to_string();
    let entries = || {
        let mut names: Vec<_> = std::fs::read_dir(&f.root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        names
    };
    let root_before = entries();
    let real = std::fs::read_to_string(&f.admin_config).unwrap();
    let fake = real
        .replace(
            "provider=\"local-aes-gcm-siv\"\ncrypto_compatibility_id=\"local-aes-gcm-siv-v1\"\n\
             key={source=\"env\",name=\"unused-admin-key\"}\n",
            "provider=\"fake\"\ncrypto_compatibility_id=\"test-profile-v1\"\n",
        )
        .replace("max_ciphertext_size=4384", "max_ciphertext_size=4104");
    assert!(fake.contains("provider=\"fake\""));
    volume_config::write(&f.admin_config, fake).unwrap();
    // Initialization would record provider "fake" in a superblock that no
    // build without the provider can attach, and consume the enrollment.
    failure(
        &[
            "volume",
            "resume-enrollment",
            f.path(true),
            &fence,
            &identity,
        ],
        "not compiled",
    );
    assert_eq!(inspect(f.writer.as_ref()), before, "authority changed");
    assert_eq!(entries(), root_before, "backing root changed");
    // The same approval still completes with a provider this build has.
    volume_config::write(&f.admin_config, real).unwrap();
    success(&[
        "volume",
        "resume-enrollment",
        f.path(true),
        &fence,
        &identity,
    ]);
}

#[test]
fn volume_cli_uses_identity_pinned_frontend_failover_for_create_and_witness() {
    let f = Fixture::new();
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let unavailable = closed.local_addr().unwrap();
    drop(closed);
    let identity = uuid::Uuid::from_bytes([1; 16]).to_string();
    let raw = std::fs::read_to_string(&f.writer_config).unwrap().replace(
        &format!("address=\"{}\"", f._service.address),
        &format!(
            "addresses=[\"{unavailable}\",\"{}\"]\nstorage_identity=\"{identity}\"",
            f._service.address
        ),
    );
    let config = f.dir.path().join("ha.toml");
    volume_config::write(&config, &raw).unwrap();
    let path = config.to_str().unwrap();
    success(&["volume", "create", path]);
    let output = success(&["volume", "witness", path]);
    let before: Record = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(before.identity, [1; 16]);
    assert_eq!(before.phase, Phase::Released);
    assert!(before.current.is_some());
    let inspected = success(&["volume", "inspect", path]);
    assert!(String::from_utf8_lossy(&inspected.stdout).contains("uuid:"));
    assert_eq!(inspect(f.writer.as_ref()), before);
    volume_config::write(
        &config,
        raw.replace(&identity, &uuid::Uuid::from_bytes([2; 16]).to_string()),
    )
    .unwrap();
    assert!(!run(&["volume", "witness", path]).status.success());
    assert!(!run(&["volume", "create", path]).status.success());
    assert_eq!(inspect(f.writer.as_ref()), before);
}

#[test]
fn diagnostic_commands_never_claim_or_fork_a_remote_writer() {
    let fixture = Fixture::new();
    let mut backing = Some(fixture.create());
    write(
        backing.as_ref().unwrap(),
        b"diagnostic-must-not-change-authority",
    );
    for active in [true, false] {
        let before = inspect(fixture.writer.as_ref());
        assert_eq!(
            before.phase,
            if active {
                Phase::Active
            } else {
                Phase::Released
            }
        );
        let names = || {
            let mut paths = std::fs::read_dir(&fixture.root)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>();
            paths.sort();
            paths
        };
        let namespaces = names();
        for args in [
            vec!["volume", "inspect", fixture.path(false)],
            vec!["check", fixture.path(false)],
            vec!["check", fixture.path(false), "--deep"],
        ] {
            fixture.actions.lock().unwrap().clear();
            let output = run(&args);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(!output.status.success(), "{args:?}");
            if active {
                // The writer holds its namespace's lock, which the
                // read-only view takes shared.
                assert!(
                    stderr.contains("rollback.lock is held by another process"),
                    "{args:?}: {stderr}"
                );
            } else {
                // The backing holds no volume: the commands read it and
                // say so.
                let output = format!("{stderr}{}", String::from_utf8_lossy(&output.stdout));
                assert!(output.contains("superblock"), "{args:?}: {output}");
            }
            let actions = fixture.actions.lock().unwrap().clone();
            assert!(
                !actions.is_empty() && actions.iter().all(|action| *action == "inspect"),
                "{args:?}: {actions:?}"
            );
            assert_eq!(inspect(fixture.writer.as_ref()), before);
            assert_eq!(names(), namespaces, "diagnostic created a writer namespace");
        }
        if active {
            drop(backing.take());
        }
    }
}

/// `volume inspect`, `check` and `check --deep` read a remote-protected
/// volume through a view that only reads, whether its root can be written
/// or not: the authority is sent nothing but inspections, and nothing in the
/// root changes. Opening the backing to write claims a writer and copies
/// the current state into a namespace of its own, so they refused it.
#[test]
fn diagnostic_commands_read_a_remote_volume_with_inspections_only() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    success(&["volume", "create", fixture.path(false)]);
    let before = inspect(fixture.writer.as_ref());
    assert_eq!(before.phase, Phase::Released);
    let path = fixture.path(false);
    for mode in [0o700, 0o500] {
        std::fs::set_permissions(&fixture.root, std::fs::Permissions::from_mode(mode)).unwrap();
        let unchanged = tree(&fixture.root);
        fixture.actions.lock().unwrap().clear();
        let inspected = success(&["volume", "inspect", path]);
        assert!(String::from_utf8_lossy(&inspected.stdout).contains("uuid:"));
        let check = success(&["check", path]);
        let report = String::from_utf8_lossy(&check.stdout);
        assert!(
            report.contains("warning: read-only check: ") && report.ends_with("check passed\n"),
            "{report}"
        );
        let deep = success(&["check", path, "--deep"]);
        let report = String::from_utf8_lossy(&deep.stdout);
        assert!(
            report.contains("info: deep check verdict: unproven\n")
                && report.ends_with("check passed\n"),
            "{report}"
        );
        let actions = fixture.actions.lock().unwrap().clone();
        assert!(
            !actions.is_empty() && actions.iter().all(|action| *action == "inspect"),
            "{actions:?}"
        );
        assert_eq!(inspect(fixture.writer.as_ref()), before);
        assert_eq!(
            tree(&fixture.root),
            unchanged,
            "a read-only command changed the root"
        );
        std::fs::set_permissions(&fixture.root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

/// Write eight units, in two shards, through the daemon's NBD adapter (what
/// the nbdkit plugin's callbacks call), and checkpoint them into their slots
/// before a clean detach.
fn write_data(config: &std::path::Path) {
    let adapter = maki_nbdkit::adapter::NbdAdapter::open_config(config.to_str().unwrap()).unwrap();
    for (index, unit) in [0u64, 1, 2, 3, 20, 21, 22, 23].into_iter().enumerate() {
        adapter
            .pwrite(&[index as u8 + 1; 4096], unit * 4096, false)
            .unwrap();
    }
    adapter.flush().unwrap();
    adapter.checkpoint().unwrap();
    adapter.shutdown().unwrap();
}

/// The manifest of the authority's current generation, in its namespace of
/// `root`.
fn current_manifest(root: &std::path::Path, record: &Record) -> serde_json::Value {
    let current = record.current.as_ref().unwrap();
    let namespace = root.join(&current.namespace);
    (0..2)
        .filter_map(|index| {
            let bytes = std::fs::read(namespace.join(format!("rollback.manifest.{index}"))).ok()?;
            let len = u64::from_le_bytes(bytes.get(..8)?.try_into().unwrap()) as usize;
            serde_json::from_slice::<serde_json::Value>(bytes.get(8..8 + len)?).ok()
        })
        .find(|manifest| manifest["generation"] == current.anchor.generation)
        .expect("the current generation's manifest")
}

/// The arena slot that holds page `page` of the file `name` in `manifest`.
fn arena_slot(manifest: &serde_json::Value, name: &str, page: u64) -> u64 {
    let id = manifest["entries"][name]["File"].as_u64().unwrap();
    manifest["files"][id.to_string()]["pages"][page.to_string()]["slot"]
        .as_u64()
        .unwrap()
}

/// A remote volume that holds data written through the daemon's NBD adapter
/// is read through the read-only view: the deep check reads every slot, the
/// authority is sent inspections only, and nothing in the root changes. Each
/// command asks the authority three times, however much it reads: twice
/// while the view opens and once before it reports; the deep check asks once
/// more itself, before its verdict. The view sent one inspection before
/// every backing operation, so the count grew with the volume.
#[test]
fn a_remote_volume_holding_data_is_read_with_three_inspections_per_command() {
    let fixture = Fixture::new();
    let config = fixture.data_config("data.toml", ("", ""));
    let path = config.to_str().unwrap();
    success(&["volume", "create", path]);
    write_data(&config);
    let record = inspect(fixture.writer.as_ref());
    assert_eq!(record.phase, Phase::Released);
    let unchanged = tree(&fixture.root);
    for args in [
        vec!["volume", "inspect", path],
        vec!["check", path],
        vec!["check", path, "--deep"],
    ] {
        fixture.clear();
        let output = success(&args);
        let report = String::from_utf8_lossy(&output.stdout);
        if args[0] == "check" {
            assert!(
                report.contains("warning: read-only check: ")
                    && report.contains("info: configuration matches")
                    && report.ends_with("check passed\n"),
                "{args:?}: {report}"
            );
        } else {
            assert!(report.contains("uuid:"), "{report}");
        }
        // The deep check asks once more itself, before its verdict.
        let deep = args.contains(&"--deep");
        if deep {
            assert!(
                report.contains("info: slots: 8 allocated, 0 invalid")
                    && report.contains("info: deep check verdict: unproven\n"),
                "{report}"
            );
        }
        let expected = vec!["inspect"; if deep { 4 } else { 3 }];
        assert_eq!(fixture.sent(), expected, "{args:?}");
    }
    assert_eq!(inspect(fixture.writer.as_ref()), record);
    assert_eq!(
        tree(&fixture.root),
        unchanged,
        "a read-only command changed the root"
    );
}

/// A data slot that does not hold what the engine wrote is an error of the
/// read-only deep check: here a ciphertext byte of unit 0 changed through
/// the backing itself, so that every page still authenticates and only the
/// slot's own checksum finds it. A changed arena page of a data slot fails
/// the authentication of every command.
#[test]
fn a_damaged_data_slot_of_a_remote_volume_is_an_error_read_only() {
    let fixture = Fixture::new();
    let config = fixture.data_config("data.toml", ("", ""));
    let path = config.to_str().unwrap();
    success(&["volume", "create", path]);
    write_data(&config);
    let shard = maki_format::layout::shard_data(0);
    {
        let backing = RollbackBacking::open_remote(&fixture.root, fixture.writer.clone()).unwrap();
        let file = backing.open(&shard, false).unwrap();
        let at = u64::from(maki_format::slot::SLOT_HEADER_SIZE) + 7;
        let mut byte = [0];
        file.read_at(at, &mut byte).unwrap();
        file.write_at(at, &[byte[0] ^ 1]).unwrap();
        file.sync_data().unwrap();
        backing.sync_dir("data").unwrap();
        backing.sync_dir("").unwrap();
    }
    let record = inspect(fixture.writer.as_ref());
    let unchanged = tree(&fixture.root);
    fixture.clear();
    let output = run(&["check", path, "--deep"]);
    let report = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1), "{report}");
    assert!(
        report.contains("ERROR: slot: ")
            && report.contains("1 invalid (0 recoverable by journal replay, 1 unrecoverable)")
            && report.ends_with("check FAILED\n"),
        "{report}"
    );
    assert_eq!(fixture.sent(), ["inspect"; 4]);
    assert_eq!(inspect(fixture.writer.as_ref()), record);
    assert_eq!(tree(&fixture.root), unchanged);

    let arena = fixture
        .root
        .join(&record.current.as_ref().unwrap().namespace)
        .join("rollback.arena");
    let slot = arena_slot(&current_manifest(&fixture.root, &record), &shard, 0);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&arena)
        .unwrap();
    use std::os::unix::fs::FileExt;
    let mut byte = [0];
    file.read_exact_at(&mut byte, slot * 4096 + 100).unwrap();
    file.write_all_at(&[byte[0] ^ 1], slot * 4096 + 100)
        .unwrap();
    for args in [
        vec!["volume", "inspect", path],
        vec!["check", path],
        vec!["check", path, "--deep"],
    ] {
        fixture.clear();
        failure(&args, "rollback arena page authentication failed");
        let sent = fixture.sent();
        assert!(sent.iter().all(|action| *action == "inspect"), "{sent:?}");
    }
    assert_eq!(inspect(fixture.writer.as_ref()), record);
}

/// `maki check` of a remote volume, read read-only, compares the
/// configuration with the superblock as attach does: one that attach
/// refuses fails the check, naming the setting and both values, with the
/// authority sent inspections only and nothing changed.
#[test]
fn a_mismatched_configuration_fails_a_read_only_check_of_a_remote_volume() {
    let fixture = Fixture::new();
    success(&["volume", "create", fixture.path(false)]);
    let other = fixture.dir.path().join("other.toml");
    volume_config::write(
        &other,
        std::fs::read_to_string(&fixture.writer_config)
            .unwrap()
            .replace(
                r#"crypto_compatibility_id="local-aes-gcm-siv-v1""#,
                r#"crypto_compatibility_id="local-aes-gcm-siv-v2""#,
            ),
    )
    .unwrap();
    let record = inspect(fixture.writer.as_ref());
    let unchanged = tree(&fixture.root);
    for deep in [false, true] {
        let mut args = vec!["check", other.to_str().unwrap()];
        if deep {
            args.push("--deep");
        }
        fixture.clear();
        let output = run(&args);
        let report = String::from_utf8_lossy(&output.stdout);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {report}");
        assert!(
            report.contains(
                "ERROR: configuration mismatch: crypto.crypto_compatibility_id is \
                 \"local-aes-gcm-siv-v2\" in the configuration, the volume has \
                 \"local-aes-gcm-siv-v1\"; attach refuses this configuration\n"
            ) && report.contains("warning: read-only check: ")
                && report.ends_with("check FAILED\n"),
            "{args:?}: {report}"
        );
        let sent = fixture.sent();
        assert!(
            !sent.is_empty() && sent.iter().all(|action| *action == "inspect"),
            "{args:?}: {sent:?}"
        );
    }
    assert_eq!(inspect(fixture.writer.as_ref()), record);
    assert_eq!(tree(&fixture.root), unchanged);
}

/// A configuration whose backing root is a snapshot destination is refused
/// read-only: `maki volume snapshot` copies the current generation into a
/// namespace of the same name, without the `rollback.lock` that a writer's
/// namespace holds, and the read-only view refuses a namespace whose lock
/// is missing. The authority is sent inspections only, and neither root
/// changes.
#[test]
fn a_configuration_pointed_at_a_snapshot_destination_is_refused_read_only() {
    let fixture = Fixture::new();
    let backing = fixture.create();
    write(&backing, b"ciphertext-in-snapshot");
    drop(backing);
    let target = fixture.dir.path().join("backup");
    success(&[
        "volume",
        "snapshot",
        fixture.path(false),
        target.to_str().unwrap(),
    ]);
    let record = inspect(fixture.writer.as_ref());
    let namespace = &record.current.as_ref().unwrap().namespace;
    assert!(target.join(namespace).join("rollback.manifest.0").is_file());
    assert!(!target.join(namespace).join("rollback.lock").exists());
    let config = fixture.dir.path().join("snapshot.toml");
    volume_config::write(
        &config,
        std::fs::read_to_string(&fixture.writer_config)
            .unwrap()
            .replace(
                &format!("root={:?}", fixture.root.to_str().unwrap()),
                &format!("root={:?}", target.to_str().unwrap()),
            ),
    )
    .unwrap();
    let path = config.to_str().unwrap();
    let (root_tree, target_tree) = (tree(&fixture.root), tree(&target));
    for args in [
        vec!["volume", "inspect", path],
        vec!["check", path],
        vec!["check", path, "--deep"],
    ] {
        fixture.clear();
        failure(
            &args,
            &format!("{namespace}/rollback.lock is missing, and a read-only open cannot create it"),
        );
        let sent = fixture.sent();
        assert!(
            !sent.is_empty() && sent.iter().all(|action| *action == "inspect"),
            "{args:?}: {sent:?}"
        );
    }
    assert_eq!(inspect(fixture.writer.as_ref()), record);
    assert_eq!(tree(&fixture.root), root_tree);
    assert_eq!(tree(&target), target_tree);
    // Once the volume has been opened to write again, the authority names a
    // namespace the snapshot does not hold, and the refusal says so.
    drop(RollbackBacking::open_remote(&fixture.root, fixture.writer.clone()).unwrap());
    let target_tree = tree(&target);
    for args in [
        vec!["volume", "inspect", path],
        vec!["check", path],
        vec!["check", path, "--deep"],
    ] {
        fixture.clear();
        failure(
            &args,
            "this backing root does not hold the remote authority's current generation",
        );
        let sent = fixture.sent();
        assert!(
            !sent.is_empty() && sent.iter().all(|action| *action == "inspect"),
            "{args:?}: {sent:?}"
        );
    }
    assert_eq!(tree(&target), target_tree);
}

/// The view asks the authority once more before a command reports: an
/// authority that changed after the view opened (here an administrator's
/// takeover, made elsewhere right after the open's second inspection) fails
/// every command, and none prints what it read.
#[test]
fn an_authority_that_changes_while_a_command_reads_fails_the_command() {
    let fixture = Fixture::new();
    let config = fixture.data_config("data.toml", ("", ""));
    let path = config.to_str().unwrap();
    success(&["volume", "create", path]);
    write_data(&config);
    for args in [
        vec!["volume", "inspect", path],
        vec!["check", path],
        vec!["check", path, "--deep"],
    ] {
        let before = inspect(fixture.writer.as_ref());
        *fixture.takeover_after.lock().unwrap() = Some(2);
        let output = run(&args);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{args:?}: {stdout}");
        assert!(
            stderr.contains("the remote authority changed after the backing was opened read-only"),
            "{args:?}: {stderr}"
        );
        assert!(
            !stdout.contains("uuid:") && !stdout.contains("check "),
            "{args:?}: {stdout}"
        );
        assert_ne!(inspect(fixture.writer.as_ref()), before, "{args:?}");
    }
}

/// A command that fails after the view has opened asks the authority once
/// more before it reports the failure, as one that succeeds asks before it
/// reports what it read: an authority that changed meanwhile (here an
/// administrator's takeover, made elsewhere right after the open's second
/// inspection) is reported instead of the failure, which describes a state
/// that may no longer be the volume's. Three such exits: `volume inspect` of
/// a backing that holds no superblock, every command with a configured
/// capacity that is not the stored one, and every command on a committed page
/// that does not authenticate. Where nothing changed, each reports its own
/// error, after three inspections.
#[test]
fn an_authority_that_changes_before_a_command_fails_is_reported_instead() {
    let fixture = Fixture::new();
    let backing = fixture.create();
    write(&backing, b"a backing without a superblock");
    drop(backing);
    let capacity = fixture.dir.path().join("capacity.toml");
    volume_config::write(
        &capacity,
        std::fs::read_to_string(&fixture.writer_config)
            .unwrap()
            .replace(r#"capacity="64KiB""#, r#"capacity="128KiB""#),
    )
    .unwrap();
    let (path, capacity) = (fixture.path(false), capacity.to_str().unwrap());
    let every = |config| {
        [
            vec!["volume", "inspect", config],
            vec!["check", config],
            vec!["check", config, "--deep"],
        ]
    };
    let mut cases = vec![(
        vec!["volume", "inspect", path],
        "no valid superblock".to_string(),
    )];
    for args in every(capacity) {
        cases.push((
            args,
            "protected backing capacity mismatch: configuration 131072, stored 65536".into(),
        ));
    }
    let failed = |cases: &[(Vec<&str>, String)]| {
        for (args, error) in cases {
            *fixture.takeover_after.lock().unwrap() = Some(2);
            let output = run(args);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(!output.status.success(), "{args:?}");
            assert!(
                stderr.contains("the remote authority changed") && !stderr.contains(error.as_str()),
                "{args:?}: {stderr}"
            );
            fixture.clear();
            failure(args, error);
            assert_eq!(fixture.sent(), ["inspect"; 3], "{args:?}");
        }
    };
    failed(&cases);
    let record = inspect(fixture.writer.as_ref());
    let arena = fixture
        .root
        .join(&record.current.as_ref().unwrap().namespace)
        .join("rollback.arena");
    let slot = arena_slot(&current_manifest(&fixture.root, &record), "ciphertext", 0);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&arena)
        .unwrap();
    use std::os::unix::fs::FileExt;
    let mut byte = [0];
    file.read_exact_at(&mut byte, slot * 4096).unwrap();
    file.write_all_at(&[byte[0] ^ 1], slot * 4096).unwrap();
    let damaged: Vec<_> = every(path)
        .into_iter()
        .map(|args| {
            (
                args,
                "rollback arena page authentication failed".to_string(),
            )
        })
        .collect();
    failed(&damaged);
}

/// A read-only view that stopped on a committed page that no longer
/// authenticates (here a byte of it flipped after the open) still asks the
/// authority before the failure is reported, as every other failure is
/// reported: an authority that changed meanwhile (a takeover made elsewhere
/// right after the open's second inspection) is reported instead of the
/// page's error, and one that did not leaves the page's error, both after a
/// failure (`read_failure`) and at the last inspection before a report
/// (`still_current`). Each answer costs one inspection. The view answered from its stop alone and sent
/// nothing, where a view that asked before every operation reported the
/// change first.
#[test]
fn a_view_stopped_by_a_page_still_asks_the_authority_before_the_failure_is_reported() {
    use maki_backing::ReadOnlyRollbackBacking;
    use std::os::unix::fs::FileExt;
    let fixture = Fixture::new();
    let backing = fixture.create();
    write(&backing, b"ciphertext that the view reads");
    drop(backing);
    let record = inspect(fixture.writer.as_ref());
    let arena = fixture
        .root
        .join(&record.current.as_ref().unwrap().namespace)
        .join("rollback.arena");
    let slot = arena_slot(&current_manifest(&fixture.root, &record), "ciphertext", 0);
    let flip = || {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&arena)
            .unwrap();
        let mut byte = [0];
        file.read_exact_at(&mut byte, slot * 4096).unwrap();
        file.write_all_at(&[byte[0] ^ 1], slot * 4096).unwrap();
    };
    // `read_failure`, as after a failure, then `still_current`, as before a
    // report: both must ask once.
    for (changed, last) in [(true, false), (false, false), (true, true), (false, true)] {
        if changed {
            *fixture.takeover_after.lock().unwrap() = Some(2);
        }
        let view =
            ReadOnlyRollbackBacking::open_remote(&fixture.root, fixture.writer.clone()).unwrap();
        flip();
        let file = view.open("ciphertext", false).unwrap();
        let mut bytes = vec![0; file.len().unwrap() as usize];
        let error = file.read_at(0, &mut bytes).unwrap_err();
        flip();
        assert!(
            error
                .to_string()
                .contains("rollback arena page authentication failed"),
            "{error}"
        );
        assert!(view.session_stopped().is_some());
        fixture.clear();
        let reported = if last {
            maki_nbdkit::daemon::still_current(&view).unwrap_err()
        } else {
            maki_nbdkit::daemon::read_failure(&view, error.to_string())
        };
        let expected = if changed {
            "the remote authority changed after the backing was opened read-only"
        } else {
            "rollback arena page authentication failed"
        };
        assert!(
            reported.contains(expected),
            "changed {changed}, last {last}: {reported}"
        );
        assert_eq!(
            fixture.sent(),
            ["inspect"],
            "changed {changed}, last {last}"
        );
        // A later operation's error says only that the view stopped: the
        // stop's reason, or the authority's answer, is reported for it.
        let generic = "rollback session stopped; reopen against the independent witness";
        let reported = maki_nbdkit::daemon::read_failure(&view, generic.into());
        assert!(reported.contains(expected), "{reported}");
    }
}
