//! `--timeout <seconds>` bounds a control-socket round trip. The CLI
//! stripped it from every command line, so `maki volume create|inspect` and
//! `maki check` accepted it and silently ignored it (a volume was created),
//! and `maki check <config> --timeout 0` failed on the value of an option
//! the command never uses. Commands without a control round trip refuse it
//! as misuse (status 2, usage on stderr), before doing anything.

#[path = "support/volume_config.rs"]
mod volume_config;

use std::path::Path;
use std::process::{Command, Output};

const VOLUME: &str = r#"
config_schema_version = 1
[volume]
name = "timeoutvol"
max_virtual_size = "1MiB"
shard_logical_size = "64KiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "local-aes-gcm-siv-v1"
key = { source = "env", name = "timeout-scope-key" }
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
"#;

fn write_config(dir: &Path, name: &str, extra: &str) -> String {
    let path = dir.join(name);
    volume_config::write(
        &path,
        format!(
            "{VOLUME}[backing]\nroot = {:?}\n{extra}",
            dir.join(format!("{name}.vol")).to_string_lossy()
        ),
    )
    .unwrap();
    path.to_string_lossy().into_owned()
}

fn maki(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_maki"))
        .args(args)
        .env_remove("MAKI_LOG")
        .output()
        .unwrap()
}

#[test]
fn commands_without_a_control_round_trip_refuse_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let existing = write_config(dir.path(), "existing.toml", "");
    let out = maki(&["volume", "create", &existing]);
    assert!(out.status.success(), "{out:?}");
    let fresh = write_config(dir.path(), "fresh.toml", "");
    let (existing, fresh) = (existing.as_str(), fresh.as_str());

    for args in [
        vec!["volume", "create", fresh, "--timeout", "5"],
        vec!["volume", "create", fresh, "--discard", "--timeout", "5"],
        vec!["--timeout", "5", "volume", "create", fresh],
        vec!["volume", "inspect", existing, "--timeout", "5"],
        vec!["volume", "witness", existing, "--timeout", "5"],
        vec!["check", existing, "--timeout", "5"],
        vec!["check", existing, "--deep", "--timeout", "5"],
        vec!["check", existing, "--timeout", "0"],
        vec!["check", existing, "--timeout"],
        vec!["--timeout", "5", "check", existing],
        vec!["--help", "--timeout", "5"],
    ] {
        let out = maki(&args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(stderr.contains("usage:"), "{args:?}: {stderr}");
        assert!(
            out.stdout.is_empty(),
            "{args:?} ran: {}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
    assert!(
        !dir.path().join("fresh.toml.vol").exists(),
        "a refused create must not create the volume"
    );
}

/// Every control command, in every documented position of the option,
/// still applies `--timeout`: against a socket that never answers, each
/// gives up after one second instead of its 60 s or 600 s default.
#[cfg(unix)]
#[test]
fn control_commands_keep_applying_timeout() {
    use std::os::unix::net::UnixListener;
    use std::time::{Duration, Instant};

    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let socket = socket.to_str().unwrap();
    let config = write_config(
        dir.path(),
        "volume.toml",
        &format!("[control]\nsocket = {socket:?}\n"),
    );
    // Bound but never served: connects land in the backlog and get no reply.
    let _listener = UnixListener::bind(socket).unwrap();
    let config = config.as_str();
    for args in [
        vec!["status", config, "--timeout", "1"],
        vec!["--timeout", "1", "metrics", config],
        vec!["checkpoint", config, "--timeout", "1"],
        vec!["drain", config, "--timeout", "1"],
        vec![
            "reload",
            config,
            "cache",
            "--max-bytes",
            "4096",
            "--timeout",
            "1",
        ],
        vec!["reload", config, "--timeout", "1", "crypto"],
        vec!["status", "--socket", socket, "--timeout", "1"],
        vec!["--timeout", "1", "drain", "--socket", socket],
    ] {
        let started = Instant::now();
        let out = maki(&args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(stderr.contains("within 1s"), "{args:?}: {stderr}");
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "{args:?} took {:?}",
            started.elapsed()
        );
    }
}
