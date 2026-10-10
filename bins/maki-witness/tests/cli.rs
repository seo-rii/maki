use std::process::Command;

fn command(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_maki-witness"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn invalid_commands_and_missing_arguments_fail() {
    for args in [
        &[][..],
        &["unknown"],
        &["serve"],
        &["init"],
        &["inspect"],
        &["fingerprint"],
        &["--help", "extra"],
    ] {
        let output = command(args);
        assert!(!output.status.success(), "unexpected success: {args:?}");
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn help_describes_explicit_init_and_separate_serve() {
    let output = command(&["--help"]);
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for name in ["init", "serve", "inspect", "fingerprint"] {
        assert!(help.contains(name));
    }
}

#[test]
fn init_is_explicit_durable_and_refuses_reinitialization() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let args = [
        "init",
        state.to_str().unwrap(),
        "01234567-89ab-cdef-0123-456789abcdef",
    ];
    let first = command(&args);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let record: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(record["phase"], "released");
    assert!(record["current"].is_null());
    assert!(!command(&args).status.success());
    let mut opened = maki_backing::remote_witness::StateStore::open(&state).unwrap();
    use maki_backing::remote_witness::{Action, Request, Role};
    let current = opened
        .handle(
            Role::Admin,
            &Request {
                operation_id: [1; 16],
                expected: None,
                action: Action::Inspect,
            },
        )
        .unwrap();
    assert_eq!(serde_json::to_value(current).unwrap(), record);
}

#[test]
fn invalid_uuid_does_not_create_state() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    assert!(!command(&["init", state.to_str().unwrap(), "invalid"])
        .status
        .success());
    assert!(!state.exists());
}

#[test]
fn config_size_type_and_secret_redaction_are_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    for bytes in [vec![b'x'; 65537], b"unknown = 'DO_NOT_ECHO_ME'".to_vec()] {
        std::fs::write(&config, bytes).unwrap();
        let output = command(&["serve", config.to_str().unwrap()]);
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("DO_NOT_ECHO_ME"));
    }
    assert!(!command(&["serve", dir.path().to_str().unwrap()])
        .status
        .success());
    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt};
        std::fs::write(&config, "invalid=true").unwrap();
        let link = dir.path().join("link.toml");
        symlink(&config, &link).unwrap();
        assert!(!command(&["serve", link.to_str().unwrap()]).status.success());
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(!command(&["serve", config.to_str().unwrap()])
            .status
            .success());
    }
}

#[test]
fn real_service_inspect_and_fingerprint_work_and_serve_never_initializes() {
    use maki_witness::{ClientOptions, Principal, Role, ServerOptions, TlsFiles};
    use std::io::BufRead;
    use std::process::Stdio;
    use std::sync::mpsc;
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let server_key = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let writer_key = rcgen::generate_simple_self_signed(vec!["writer".to_owned()]).unwrap();
    let save = |name: &str, key: &rcgen::CertifiedKey, roots: &str| {
        let tls = TlsFiles {
            ca_file: dir.path().join(format!("{name}.ca")),
            cert_file: dir.path().join(format!("{name}.cert")),
            key_file: dir.path().join(format!("{name}.key")),
        };
        std::fs::write(&tls.ca_file, roots).unwrap();
        std::fs::write(&tls.cert_file, key.cert.pem()).unwrap();
        std::fs::write(&tls.key_file, key.key_pair.serialize_pem()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tls.key_file, std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        tls
    };
    let server = save("server", &server_key, &writer_key.cert.pem());
    let writer = save("writer", &writer_key, &server_key.cert.pem());
    let fingerprint = command(&["fingerprint", writer.cert_file.to_str().unwrap()]);
    assert!(fingerprint.status.success());
    let fingerprint = String::from_utf8(fingerprint.stdout)
        .unwrap()
        .trim()
        .to_owned();
    assert_eq!(
        fingerprint,
        maki_witness::certificate_fingerprint(writer_key.cert.der())
    );
    let options = ServerOptions {
        tls: server,
        principals: vec![Principal {
            certificate_sha256: fingerprint,
            role: Role::Writer,
        }],
        timeout_ms: 1000,
        max_connections: 2,
    };
    let config = dir.path().join("server.toml");
    let text = toml::to_string(
        &serde_json::json!({"state_dir":state,"listen":"127.0.0.1:0","server":options}),
    )
    .unwrap();
    std::fs::write(&config, &text).unwrap();
    assert!(!command(&["serve", config.to_str().unwrap()])
        .status
        .success());
    assert!(!state.exists(), "serve initialized a missing authority");
    assert!(command(&[
        "init",
        state.to_str().unwrap(),
        "01234567-89ab-cdef-0123-456789abcdef"
    ])
    .status
    .success());
    let mut process = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_maki-witness"))
            .args(["serve", config.to_str().unwrap()])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let output = process.0.stdout.take().unwrap();
    let (ready, wait) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut line = String::new();
        std::io::BufReader::new(output)
            .read_line(&mut line)
            .unwrap();
        let _ = ready.send(line);
    });
    let ready = wait
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    let address = ready
        .trim()
        .strip_prefix("maki-witness listening ")
        .expect("missing service readiness")
        .parse()
        .unwrap();
    reader.join().unwrap();
    let client = ClientOptions {
        address,
        server_name: "localhost".into(),
        timeout_ms: 1000,
        tls: writer,
    };
    let client_path = dir.path().join("client.toml");
    std::fs::write(&client_path, toml::to_string(&client).unwrap()).unwrap();
    let inspect = command(&["inspect", client_path.to_str().unwrap()]);
    assert!(
        inspect.status.success(),
        "{}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    let record: serde_json::Value = serde_json::from_slice(&inspect.stdout).unwrap();
    assert_eq!(record["phase"], "released");
    assert!(
        maki_backing::remote_witness::StateStore::open(&state).is_err(),
        "live service did not retain its exclusive state lease"
    );
    drop(process);
    assert!(maki_backing::remote_witness::StateStore::open(&state).is_ok());
}
