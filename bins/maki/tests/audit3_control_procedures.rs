#![cfg(unix)]
//! Audit round 3 (cli-ops): run the documented control-plane procedures
//! (docs/operations.md "Control plane", quickstart step 7) with the real
//! `maki` binary against a real in-process daemon (NbdAdapter::open_config),
//! and record exit codes and outputs.

use std::process::{Command, Output};

const KEY_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const KEY_ENV: &str = "MAKI_CREDENTIAL_AUDIT3_CONTROL_KEY";

fn config(root: &str, socket: &str, extra: &str) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "audit3ctl"
max_virtual_size = "8MiB"
shard_logical_size = "1MiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "local-aes-gcm-siv-v1"
key = {{ source = "env", name = "audit3-control-key" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "{root}"
journal_emergency_reserve_bytes = 0
checkpoint_reserve_bytes = 0
[control]
socket = "{socket}"
{extra}
"#
    )
}

fn maki(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_maki"))
        .args(args)
        .env(KEY_ENV, KEY_HEX)
        .output()
        .expect("spawn maki")
}

fn show(out: &Output) -> String {
    format!(
        "status={:?}\nstdout={}\nstderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null)
}

#[test]
fn documented_control_sequence_against_a_live_daemon() {
    std::env::set_var(KEY_ENV, KEY_HEX);
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vol").to_string_lossy().into_owned();
    let socket = dir
        .path()
        .join("control.sock")
        .to_string_lossy()
        .into_owned();
    let cfg_path = dir.path().join("volume.toml");
    std::fs::write(
        &cfg_path,
        config(
            &root,
            &socket,
            "[cache]\nmode = \"read\"\nmax_bytes = \"1MiB\"\nlock_memory = false",
        ),
    )
    .unwrap();
    let cfg = cfg_path.to_str().unwrap();

    let out = maki(&["volume", "create", cfg]);
    assert!(out.status.success(), "{}", show(&out));

    let adapter = maki_nbdkit::adapter::NbdAdapter::open_config(cfg).expect("attach");
    adapter.pwrite(&[0x5a; 4096], 0, false).unwrap();

    let out = maki(&["status", cfg]);
    eprintln!("status: {}", show(&out));
    assert!(out.status.success());
    let status = json(&out);
    assert_eq!(status["data"]["io_state"], "running");

    // Documented reload examples.
    let out = maki(&["reload", cfg, "cache", "--max-bytes", "4096", "--ttl", "1s"]);
    eprintln!("reload cache: {}", show(&out));
    assert!(out.status.success());
    let out = maki(&["reload", cfg, "retry"]);
    eprintln!("reload retry: {}", show(&out));
    assert_eq!(out.status.code(), Some(1));

    let out = maki(&["checkpoint", cfg]);
    eprintln!("checkpoint: {}", show(&out));
    assert!(out.status.success());

    let out = maki(&["drain", cfg]);
    eprintln!("drain 1: {}", show(&out));
    assert!(out.status.success());
    let first = json(&out)["data"]["checkpoint_sequence"].clone();
    let out = maki(&["drain", cfg]);
    eprintln!("drain 2: {}", show(&out));
    assert!(out.status.success());
    assert_eq!(json(&out)["data"]["checkpoint_sequence"], first);

    let out = maki(&["status", cfg]);
    assert_eq!(json(&out)["data"]["io_state"], "drained", "{}", show(&out));

    let out = maki(&["checkpoint", cfg]);
    eprintln!("checkpoint after drain: {}", show(&out));
    assert_eq!(out.status.code(), Some(1));
    let out = maki(&["reload", cfg, "cache", "--max-bytes", "8192"]);
    eprintln!("reload after drain: {}", show(&out));
    assert_eq!(out.status.code(), Some(1));

    let mut buf = vec![0u8; 4096];
    let read = adapter.pread(&mut buf, 0);
    eprintln!("read after drain: {:?}", read.as_ref().err());

    adapter.shutdown().unwrap();
    drop(adapter);

    let out = maki(&["drain", cfg]);
    eprintln!("drain after shutdown: {}", show(&out));
    assert_eq!(out.status.code(), Some(1));

    let out = maki(&["check", cfg, "--deep"]);
    eprintln!("deep check: {}", show(&out));
    assert!(out.status.success());
}

/// Flags the CLI accepts but does not apply, and argument forms it treats
/// as usage errors.
#[test]
fn argument_handling_matrix() {
    std::env::set_var(KEY_ENV, KEY_HEX);
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vol").to_string_lossy().into_owned();
    let socket = dir
        .path()
        .join("control.sock")
        .to_string_lossy()
        .into_owned();
    let cfg_path = dir.path().join("volume.toml");
    std::fs::write(&cfg_path, config(&root, &socket, "")).unwrap();
    let cfg = cfg_path.to_str().unwrap();
    for args in [
        vec!["volume", "create", cfg, "--timeout", "5"],
        vec!["volume", "inspect", cfg, "--timeout", "5"],
        vec!["check", cfg, "--timeout", "5"],
        vec!["check", cfg, "--deep", "--deep"],
        vec!["check", "--deep", cfg],
        vec!["volume", "inspect", cfg, "--deep"],
        vec!["status", cfg, "--timeout", "5", "--timeout", "6"],
        vec!["volume", "create", cfg, "--discard"],
    ] {
        let out = maki(&args);
        eprintln!("{args:?}: {}", show(&out));
    }
}

/// docs/operations.md: a `maki-admin` member (here: group nogroup, uid
/// 65534) reaches the socket with `--socket`; a user outside the group
/// cannot. Root only (setpriv).
#[test]
fn admin_group_member_reaches_the_socket_and_others_do_not() {
    if unsafe { libc::geteuid() } != 0 || !std::path::Path::new("/usr/bin/setpriv").exists() {
        eprintln!("skipped: needs root and setpriv");
        return;
    }
    std::env::set_var(KEY_ENV, KEY_HEX);
    let base = std::path::Path::new("/var/tmp/maki-audit3-ctl");
    let _ = std::fs::remove_dir_all(base);
    std::fs::create_dir_all(base.join("run")).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(base, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(base.join("run"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let root = base.join("vol").to_string_lossy().into_owned();
    let socket = base.join("run/control.sock").to_string_lossy().into_owned();
    let cfg_path = base.join("volume.toml");
    std::fs::write(&cfg_path, config(&root, &socket, "group = \"nogroup\"")).unwrap();
    let cfg = cfg_path.to_str().unwrap();
    let out = maki(&["volume", "create", cfg]);
    assert!(out.status.success(), "{}", show(&out));
    let adapter = maki_nbdkit::adapter::NbdAdapter::open_config(cfg).expect("attach");
    let meta = std::fs::metadata(&socket).unwrap();
    use std::os::unix::fs::MetadataExt;
    eprintln!(
        "socket mode {:o} uid {} gid {}",
        meta.mode() & 0o7777,
        meta.uid(),
        meta.gid()
    );
    let as_user = |uid: &str, gid: &str| {
        Command::new("/usr/bin/setpriv")
            .args([
                "--reuid",
                uid,
                "--regid",
                gid,
                "--clear-groups",
                env!("CARGO_BIN_EXE_maki"),
                "status",
                "--socket",
                &socket,
            ])
            .output()
            .unwrap()
    };
    let member = as_user("65534", "65534");
    eprintln!("member: {}", show(&member));
    let outsider = as_user("65533", "65533");
    eprintln!("outsider: {}", show(&outsider));
    adapter.shutdown().unwrap();
    let _ = std::fs::remove_dir_all(base);
    assert!(member.status.success());
    assert!(!outsider.status.success());
}
