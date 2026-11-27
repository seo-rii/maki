//! A rollback-protected volume that the daemon wrote through NBD, checked
//! through the read-only view.
//!
//! The read-only view (`ReadOnlyRollbackBacking`), which `maki check`,
//! `maki check --deep` and `maki volume inspect` open where they may not
//! write a local protected backing and for every remote one, was run on
//! volumes that `volume create` made and on payloads written to the backing
//! directly, never on one that a daemon had written. Here nbdkit serves
//! Maki's plugin, `nbdcopy` writes and flushes 64 KiB of data through NBD,
//! and nbdkit exits, which detaches the volume cleanly (flush, checkpoint,
//! release). The view then opens the volume, local and remote, and the
//! deep check reads every allocated slot: all sixteen are intact, the
//! verdict is `unproven`, and the remote authority is sent inspections
//! only. Without nbdkit and nbdcopy the tests are skipped with a notice;
//! `MAKI_TEST_REQUIRE_NBDKIT=1` makes that a failure.
#![cfg(target_os = "linux")]

#[path = "support/native_plugin.rs"]
mod native_plugin;

#[path = "support/volume_config.rs"]
mod volume_config;

#[path = "support/short_dir.rs"]
mod short_dir;

#[path = "support/other_filesystem.rs"]
mod other_filesystem;

#[path = "support/private_dir.rs"]
mod private_dir;

use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use maki_backing::remote_witness::{Action, Request, StateStore};
use maki_backing::{Backing, ReadOnlyRollbackBacking};
use maki_witness::{certificate_fingerprint, Principal, Role, Server, ServerOptions, TlsFiles};

const REQUIRE: &str = "MAKI_TEST_REQUIRE_NBDKIT";

/// What `nbdcopy` writes: 64 KiB, sixteen units, none of them zero.
fn data() -> Vec<u8> {
    (0..64 * 1024).map(|i| (i % 251) as u8 + 1).collect()
}

fn tools_available(test: &str) -> bool {
    for program in ["nbdkit", "nbdcopy", "timeout"] {
        let reason = match Command::new(program).arg("--version").output() {
            Ok(output) if output.status.success() => continue,
            Ok(output) => format!("`{program} --version` exited with {}", output.status),
            Err(error) => format!("{program} cannot run ({error})"),
        };
        assert!(
            std::env::var_os(REQUIRE).is_none_or(|value| value != "1"),
            "{REQUIRE}=1, but {reason}"
        );
        eprintln!("{test}: skipped: {reason} (set {REQUIRE}=1 to fail instead)");
        return false;
    }
    true
}

fn config(root: &Path, protection: &str, control: &Path) -> String {
    format!(
        r#"config_schema_version = 1
[volume]
name = "daemon-written"
max_virtual_size = "16MiB"
shard_logical_size = "8MiB"
[crypto]
provider = "fake"
crypto_compatibility_id = "v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = {}
journal_segment_size = "64KiB"
journal_max_bytes = "1MiB"
checkpoint_reserve_bytes = "64KiB"
journal_emergency_reserve_bytes = "64KiB"
{protection}[nbd]
maximum_io = "64KiB"
[control]
socket = {}
"#,
        serde_json::to_string(root.to_str().unwrap()).unwrap(),
        serde_json::to_string(control.to_str().unwrap()).unwrap(),
    )
}

/// Create the volume of `raw`, then serve it with nbdkit and the plugin
/// while `nbdcopy` writes [`data`] at its start and flushes; nbdkit exits
/// when the copy has finished, which detaches the volume. A plugin that fails
/// to start leaves `nbdcopy` waiting on a server that has gone, so the whole
/// run is bounded and then killed (coreutils `timeout`), as the drain test
/// bounds its own.
fn write_through_nbd(directory: &Path, raw: &str) {
    maki_nbdkit::daemon::create_volume_from_config_str(raw).unwrap();
    let config = directory.join("volume.toml");
    volume_config::write(&config, raw).unwrap();
    let source = directory.join("data");
    std::fs::write(&source, data()).unwrap();
    let output = Command::new("timeout")
        .args(["--kill-after=5s", "120s", "nbdkit"])
        .args(["--foreground", "--exit-with-parent", "-U", "-"])
        .arg(native_plugin::path())
        .arg(format!("config={}", config.display()))
        .args(["--run", "nbdcopy --flush \"$MAKI_SOURCE\" \"$uri\""])
        .env("MAKI_SOURCE", &source)
        .env_remove("NOTIFY_SOCKET")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "nbdkit or nbdcopy failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The deep check through `view` finds the sixteen slots intact, and says
/// that it read read-only.
fn deep_check_reads_every_slot(view: ReadOnlyRollbackBacking) {
    let view: Arc<dyn Backing> = Arc::new(view);
    let report = maki_core::check::deep_check(view.clone(), 64 * 1024).unwrap();
    assert!(report.errors.is_empty(), "{report:?}");
    assert!(
        report
            .info
            .iter()
            .any(|line| line.starts_with("slots: 16 allocated, 0 invalid")),
        "{report:?}"
    );
    assert!(
        report
            .info
            .iter()
            .any(|line| line == "deep check verdict: unproven"),
        "{report:?}"
    );
    assert!(
        report
            .warnings
            .iter()
            .any(|line| line.starts_with("read-only check: ")),
        "{report:?}"
    );
}

#[test]
fn a_local_protected_volume_the_daemon_wrote_is_checked_read_only() {
    if !tools_available("a_local_protected_volume_the_daemon_wrote_is_checked_read_only") {
        return;
    }
    let directory = short_dir::tempdir().unwrap();
    let root = directory.path().join("volume");
    let Some(witness) = other_filesystem::tempdir(directory.path()) else {
        return;
    };
    let protection = format!(
        "[backing.rollback_protection]\nwitness_root = {}\ncapacity = \"8MiB\"\n",
        serde_json::to_string(witness.path().to_str().unwrap()).unwrap()
    );
    write_through_nbd(
        directory.path(),
        &config(&root, &protection, &directory.path().join("c.sock")),
    );
    deep_check_reads_every_slot(ReadOnlyRollbackBacking::open(&root, witness.path()).unwrap());
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
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&files.key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    files
}

#[test]
fn a_remote_protected_volume_the_daemon_wrote_is_checked_read_only() {
    if !tools_available("a_remote_protected_volume_the_daemon_wrote_is_checked_read_only") {
        return;
    }
    let directory = short_dir::tempdir().unwrap();
    let root = directory.path().join("volume");
    let state = private_dir::tempdir().unwrap();
    let server_key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let writer_key = rcgen::generate_simple_self_signed(vec!["writer".into()]).unwrap();
    let server_files = tls_files(
        directory.path(),
        "server",
        &server_key,
        &writer_key.cert.pem(),
    );
    let writer = tls_files(
        directory.path(),
        "writer",
        &writer_key,
        &server_key.cert.pem(),
    );
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
    let store = Arc::new(Mutex::new(
        StateStore::create(state.path(), [5; 16]).unwrap(),
    ));
    let actions = Arc::new(Mutex::new(Vec::<bool>::new()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let worker = std::thread::spawn({
        let (store, actions, stop) = (store.clone(), actions.clone(), stop.clone());
        move || {
            let handler = move |role, value: &[u8]| {
                let request: Request =
                    serde_json::from_slice(value).map_err(std::io::Error::other)?;
                actions
                    .lock()
                    .unwrap()
                    .push(request.action == Action::Inspect);
                let record = store.lock().unwrap().handle(role, &request)?;
                serde_json::to_value(record).map_err(std::io::Error::other)
            };
            for socket in listener.incoming() {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let _ = server.handle_connection(socket.unwrap(), &handler);
            }
        }
    });
    let protection = format!(
        "[backing.rollback_protection]\ncapacity = \"16MiB\"\n\
         [backing.rollback_protection.remote]\naddress = \"{address}\"\n\
         server_name = \"localhost\"\ntimeout_ms = 2000\nca_file = {}\n\
         client_cert_file = {}\nclient_key_file = {}\n",
        serde_json::to_string(writer.ca_file.to_str().unwrap()).unwrap(),
        serde_json::to_string(writer.cert_file.to_str().unwrap()).unwrap(),
        serde_json::to_string(writer.key_file.to_str().unwrap()).unwrap(),
    );
    write_through_nbd(
        directory.path(),
        &config(&root, &protection, &directory.path().join("c.sock")),
    );
    actions.lock().unwrap().clear();
    let client = maki_witness::Client::new(maki_witness::ClientOptions {
        address,
        server_name: "localhost".into(),
        timeout_ms: 2000,
        tls: writer,
    })
    .unwrap();
    deep_check_reads_every_slot(
        ReadOnlyRollbackBacking::open_remote(&root, Arc::new(client)).unwrap(),
    );
    let sent = actions.lock().unwrap().clone();
    assert!(
        !sent.is_empty() && sent.iter().all(|inspect| *inspect),
        "the read-only view sent more than inspections"
    );
    stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(address);
    worker.join().unwrap();
}
