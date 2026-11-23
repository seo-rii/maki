//! `maki-witness init` that fails or dies before its first record is
//! published must be a command the operator can run again: nothing was
//! enrolled, and the guide warns never to delete or reinitialize an
//! authority. An empty `remote.state` is different. It is what releases that
//! created the file before writing it left of an interrupted `init`, and
//! also what an enrolled authority whose state was truncated looks like, so
//! `init` and `serve` both refuse it, say what it can mean and what the
//! operator may do, and leave it as it is. The store's own cases, including
//! every cut of the step, are in maki-backing
//! (`review_interrupted_enrollment.rs`, `remote_witness_init_tests.rs`).

#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output};

use maki_witness::{Principal, Role, ServerOptions, TlsFiles};

const IDENTITY: &str = "01234567-89ab-cdef-0123-456789abcdef";

fn init(state: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_maki-witness"));
    command.args(["init", state.to_str().unwrap(), IDENTITY]);
    command
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn entries(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// A local-authority server configuration with real credentials, so that
/// `serve` reaches the state directory.
fn server_config(dir: &Path, state: &Path) -> std::path::PathBuf {
    let server = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let writer = rcgen::generate_simple_self_signed(vec!["writer".into()]).unwrap();
    let tls = TlsFiles {
        ca_file: dir.join("client-ca.pem"),
        cert_file: dir.join("server.cert.pem"),
        key_file: dir.join("server.key.pem"),
    };
    std::fs::write(&tls.ca_file, writer.cert.pem()).unwrap();
    std::fs::write(&tls.cert_file, server.cert.pem()).unwrap();
    std::fs::write(&tls.key_file, server.key_pair.serialize_pem()).unwrap();
    std::fs::set_permissions(&tls.key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let options = ServerOptions {
        tls,
        principals: vec![Principal {
            certificate_sha256: maki_witness::certificate_fingerprint(writer.cert.der()),
            role: Role::Writer,
        }],
        timeout_ms: 1000,
        max_connections: 1,
    };
    let config = dir.join("server.toml");
    let text = toml::to_string(
        &serde_json::json!({"state_dir": state, "listen": "127.0.0.1:0", "server": options}),
    )
    .unwrap();
    std::fs::write(&config, text).unwrap();
    config
}

/// A full disk while `init` writes its first record: here a zero file-size
/// limit refuses the write. The command fails, and running it again
/// enrolls the authority.
#[test]
fn init_whose_state_write_failed_can_be_run_again() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let mut refused = init(&state);
    // SAFETY: the closure makes two async-signal-safe calls between fork
    // and exec. An ignored SIGXFSZ and the limit are kept across exec.
    unsafe {
        refused.pre_exec(|| {
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
    let failed = refused.output().unwrap();
    assert!(!failed.status.success());
    assert!(stderr(&failed).contains("File too large"), "{failed:?}");
    assert!(failed.stdout.is_empty());

    let again = init(&state).output().unwrap();
    assert!(
        again.status.success(),
        "init after a failed init, with {:?} left: {}",
        entries(&state),
        stderr(&again)
    );
    let record: serde_json::Value = serde_json::from_slice(&again.stdout).unwrap();
    assert_eq!(record["fence"], 0);
    assert_eq!(record["phase"], "released");
    assert!(record["current"].is_null());
    // Enrolled now, and only once.
    let third = init(&state).output().unwrap();
    assert!(!third.status.success());
    assert!(
        stderr(&third).contains("remote witness already enrolled"),
        "{third:?}"
    );
    maki_backing::remote_witness::StateStore::open(&state).unwrap();
}

#[test]
fn init_and_serve_refuse_an_empty_state_file_and_say_what_to_do() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(state.join("remote.state"), b"").unwrap();
    std::fs::set_permissions(
        state.join("remote.state"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let config = server_config(dir.path(), &state);
    let commands = [
        init(&state).output().unwrap(),
        Command::new(env!("CARGO_BIN_EXE_maki-witness"))
            .args(["serve", config.to_str().unwrap()])
            .output()
            .unwrap(),
    ];
    for output in commands {
        assert!(!output.status.success(), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        let text = stderr(&output);
        assert!(
            text.contains("remote.state is empty")
                && text.contains("did not complete")
                && text.contains("lost its state")
                && text.contains("never been served")
                && text.contains("remove remote.state"),
            "{text}"
        );
    }
    // Neither replaced it.
    assert_eq!(
        std::fs::metadata(state.join("remote.state")).unwrap().len(),
        0
    );
    assert!(!state.join("remote.next").exists());
}
