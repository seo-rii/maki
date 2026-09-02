//! End-to-end tests of the `maki` administrative CLI (SPEC §7) as a real
//! process: volume lifecycle (create → inspect → check), fail-closed exits
//! on double-create / corruption / bad configs, with a real filesystem
//! backing and real AES-GCM-SIV keyed from the environment.

use std::io::{Seek, SeekFrom, Write};
use std::process::{Command, Output};

const KEY_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn config(root: &str, name: &str, key_name: &str) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "{name}"
max_virtual_size = "1MiB"
shard_logical_size = "64KiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "local-aes-gcm-siv-v1"
key = {{ source = "env", name = "{key_name}" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "{root}"
"#
    )
}

fn maki(args: &[&str], key_env: Option<(&str, &str)>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_maki"));
    cmd.args(args);
    if let Some((k, v)) = key_env {
        cmd.env(k, v);
    }
    cmd.output().expect("spawn maki")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

struct Volume {
    _dir: tempfile::TempDir,
    root: String,
    config_path: String,
}

fn setup(name: &str, key_name: &str) -> Volume {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vol").to_string_lossy().replace('\\', "/");
    let config_path = dir
        .path()
        .join("volume.toml")
        .to_string_lossy()
        .into_owned();
    std::fs::write(&config_path, config(&root, name, key_name)).unwrap();
    Volume {
        _dir: dir,
        root,
        config_path,
    }
}

fn scribble(path: &str, offset: u64) {
    let mut f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    f.seek(SeekFrom::Start(offset)).unwrap();
    f.write_all(&[0xFF; 16]).unwrap();
}

#[test]
fn volume_lifecycle_create_inspect_check() {
    let vol = setup("e2evol", "e2e-cli-key");
    let key = ("MAKI_CREDENTIAL_E2E_CLI_KEY", KEY_HEX);

    // Inspecting a not-yet-created volume fails closed.
    let out = maki(&["volume", "inspect", &vol.config_path], Some(key));
    assert!(!out.status.success(), "inspect before create must fail");

    let out = maki(&["volume", "create", &vol.config_path], Some(key));
    assert!(out.status.success(), "create failed: {}", stderr(&out));
    assert!(stdout(&out).contains("created volume"), "{}", stdout(&out));

    // A second create must refuse — never reinitialize an existing volume.
    let out = maki(&["volume", "create", &vol.config_path], Some(key));
    assert!(!out.status.success(), "double create must fail");
    assert!(stderr(&out).contains("already"), "{}", stderr(&out));

    let out = maki(&["volume", "inspect", &vol.config_path], Some(key));
    assert!(out.status.success(), "inspect failed: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("e2evol"), "{text}");
    assert!(text.contains("local-aes-gcm-siv"), "{text}");
    assert!(text.contains("generation"), "{text}");

    let out = maki(&["check", &vol.config_path], Some(key));
    assert!(out.status.success(), "check failed: {}", stderr(&out));
    assert!(stdout(&out).contains("check passed"), "{}", stdout(&out));
}

#[test]
fn check_survives_one_corrupt_superblock_copy_and_fails_on_both() {
    let vol = setup("e2ecorrupt", "e2e-corrupt-key");
    let key = ("MAKI_CREDENTIAL_E2E_CORRUPT_KEY", KEY_HEX);
    let out = maki(&["volume", "create", &vol.config_path], Some(key));
    assert!(out.status.success(), "create failed: {}", stderr(&out));

    // One corrupt copy: the A/B protocol falls back and the check passes.
    scribble(&format!("{}/superblock.a", vol.root), 100);
    let out = maki(&["check", &vol.config_path], Some(key));
    assert!(
        out.status.success(),
        "single corrupt copy must fall back to the sibling: {}",
        stdout(&out)
    );

    // Both copies corrupt: fail closed, non-zero exit.
    scribble(&format!("{}/superblock.b", vol.root), 100);
    let out = maki(&["check", &vol.config_path], Some(key));
    assert!(!out.status.success(), "check must fail with no valid copy");
    assert!(stdout(&out).contains("check FAILED"), "{}", stdout(&out));
}

#[test]
fn usage_and_bad_inputs_fail_closed() {
    let out = maki(&[], None);
    assert_eq!(out.status.code(), Some(2), "no args -> usage, exit 2");
    assert!(stderr(&out).contains("usage"), "{}", stderr(&out));

    let out = maki(&["check", "does-not-exist.toml"], None);
    assert!(!out.status.success(), "missing config must fail");

    // Invalid config (unknown provider) is rejected by validation.
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("bad.toml").to_string_lossy().into_owned();
    let root = dir.path().join("vol").to_string_lossy().replace('\\', "/");
    std::fs::write(
        &bad,
        config(&root, "badvol", "k").replace("local-aes-gcm-siv\"", "no-such-provider\""),
    )
    .unwrap();
    let out = maki(&["check", &bad], None);
    assert!(!out.status.success(), "unknown provider must fail");
    assert!(stderr(&out).contains("error"), "{}", stderr(&out));
}
