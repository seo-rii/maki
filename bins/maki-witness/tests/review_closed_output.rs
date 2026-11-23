//! `maki-witness` printed its help, fingerprints, inspected records and the
//! listening line with `print!`/`println!`, which panic when the write
//! fails: `maki-witness --help | head -1` exited 101, and a service started
//! with a stdout nobody reads died before serving. A stdout reader that has
//! gone is not a failure; any other failure to write a requested result is
//! an error.
//!
//! `eprintln!` panics the same way: with a stderr nobody reads, every error
//! (1) became 101. A diagnostic that cannot be delivered is dropped; the
//! status stands.
#![cfg(unix)]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use maki_witness::{ClientOptions, Principal, Role, ServerOptions, TlsFiles};

/// A pipe whose read end is already closed: every write fails with `EPIPE`.
fn closed_pipe() -> Stdio {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    writer.into()
}

fn witness(args: &[&str], stdout: Stdio) -> Output {
    Command::new(env!("CARGO_BIN_EXE_maki-witness"))
        .args(args)
        .env("RUST_BACKTRACE", "0")
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(Stdio::piped())
        .output()
        .expect("spawn maki-witness")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn save(dir: &Path, name: &str, key: &rcgen::CertifiedKey, roots: &str) -> TlsFiles {
    use std::os::unix::fs::PermissionsExt;
    let tls = TlsFiles {
        ca_file: dir.join(format!("{name}.ca")),
        cert_file: dir.join(format!("{name}.cert")),
        key_file: dir.join(format!("{name}.key")),
    };
    std::fs::write(&tls.ca_file, roots).unwrap();
    std::fs::write(&tls.cert_file, key.cert.pem()).unwrap();
    std::fs::write(&tls.key_file, key.key_pair.serialize_pem()).unwrap();
    std::fs::set_permissions(&tls.key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    tls
}

struct Service(std::process::Child);

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// An initialized authority served by a `maki-witness serve` whose stdout
/// nobody reads, and the client configuration that reaches it.
fn service_without_a_stdout_reader(dir: &Path) -> (Service, PathBuf) {
    let server_key = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let writer_key = rcgen::generate_simple_self_signed(vec!["writer".to_owned()]).unwrap();
    let server = save(dir, "server", &server_key, &writer_key.cert.pem());
    let writer = save(dir, "writer", &writer_key, &server_key.cert.pem());
    let state = dir.join("state");
    let initialized = witness(
        &[
            "init",
            state.to_str().unwrap(),
            "01234567-89ab-cdef-0123-456789abcdef",
        ],
        Stdio::piped(),
    );
    assert!(initialized.status.success(), "{}", stderr(&initialized));
    // The listening line cannot be read, so the address is chosen here.
    let address = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let options = ServerOptions {
        tls: server,
        principals: vec![Principal {
            certificate_sha256: maki_witness::certificate_fingerprint(writer_key.cert.der()),
            role: Role::Writer,
        }],
        timeout_ms: 1000,
        max_connections: 2,
    };
    let config = dir.join("server.toml");
    std::fs::write(
        &config,
        toml::to_string(&serde_json::json!({"state_dir":state,"listen":address,"server":options}))
            .unwrap(),
    )
    .unwrap();
    let client = dir.join("client.toml");
    std::fs::write(
        &client,
        toml::to_string(&ClientOptions {
            address,
            server_name: "localhost".into(),
            timeout_ms: 1000,
            tls: writer,
        })
        .unwrap(),
    )
    .unwrap();
    // A configuration its group or others can write is refused, whatever
    // the umask of the test run.
    for path in [&config, &client] {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let service = Service(
        Command::new(env!("CARGO_BIN_EXE_maki-witness"))
            .args(["serve", config.to_str().unwrap()])
            .env("RUST_BACKTRACE", "0")
            .stdin(Stdio::null())
            .stdout(closed_pipe())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    (service, client)
}

#[test]
fn help_and_version_succeed_when_the_stdout_reader_has_gone() {
    for flag in ["--help", "-h", "--version", "-V"] {
        let output = witness(&[flag], closed_pipe());
        let stderr = stderr(&output);
        assert_eq!(output.status.code(), Some(0), "{flag}: {stderr}");
        assert!(stderr.is_empty(), "{flag}: {stderr}");
    }
}

#[test]
fn a_service_nobody_listens_to_still_serves_and_can_be_inspected() {
    let dir = tempfile::tempdir().unwrap();
    let (mut service, client) = service_without_a_stdout_reader(dir.path());
    let client = client.to_str().unwrap();
    // The service answers once it is past its listening line; it must not
    // exit instead.
    let deadline = Instant::now() + Duration::from_secs(20);
    let inspected = loop {
        let inspected = witness(&["inspect", client], Stdio::piped());
        if inspected.status.success() {
            break inspected;
        }
        if let Some(status) = service.0.try_wait().unwrap() {
            let mut log = String::new();
            use std::io::Read;
            let _ = service.0.stderr.take().unwrap().read_to_string(&mut log);
            panic!("maki-witness serve exited with {status}: {log}");
        }
        assert!(
            Instant::now() < deadline,
            "no answer from the service: {}",
            stderr(&inspected)
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    let record: serde_json::Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(record["phase"], "released");

    let unread = witness(&["inspect", client], closed_pipe());
    assert_eq!(unread.status.code(), Some(0), "{}", stderr(&unread));
    assert!(unread.stderr.is_empty(), "{}", stderr(&unread));
}

#[test]
fn a_fingerprint_nobody_reads_is_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let key = rcgen::generate_simple_self_signed(vec!["writer".to_owned()]).unwrap();
    let certificate = dir.path().join("writer.cert");
    std::fs::write(&certificate, key.cert.pem()).unwrap();
    let output = witness(
        &["fingerprint", certificate.to_str().unwrap()],
        closed_pipe(),
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(output.stderr.is_empty(), "{}", stderr(&output));
}

#[cfg(target_os = "linux")]
#[test]
fn a_result_that_cannot_be_written_is_an_error() {
    let full = || -> Stdio {
        std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap()
            .into()
    };
    let dir = tempfile::tempdir().unwrap();
    let key = rcgen::generate_simple_self_signed(vec!["writer".to_owned()]).unwrap();
    let certificate = dir.path().join("writer.cert");
    std::fs::write(&certificate, key.cert.pem()).unwrap();
    for args in [
        vec!["--help"],
        vec!["fingerprint", certificate.to_str().unwrap()],
    ] {
        let output = witness(&args, full());
        let stderr = stderr(&output);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(
            stderr.contains("maki-witness: writing the output failed"),
            "{args:?}: {stderr}"
        );
    }
}

#[test]
fn diagnostics_nobody_reads_do_not_replace_the_exit_status() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.toml");
    for args in [
        vec![],
        vec!["no-such-command"],
        vec!["serve", missing.to_str().unwrap()],
        vec![
            "init",
            dir.path().join("state").to_str().unwrap(),
            "not-a-uuid",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_maki-witness"))
            .args(&args)
            .env("RUST_BACKTRACE", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(closed_pipe())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
    }
}
