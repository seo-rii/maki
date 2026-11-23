//! `maki-benchmark` assembles the daemon from a volume configuration, which
//! names the crypto provider, its endpoints and the credentials sent to
//! them, and the backing it overwrites. It read the file with
//! `read_to_string`, so a file the group or others could write, a file
//! another user owns, a symlink and a file with a second hard link were
//! loaded like the operator's own. It must refuse them as the daemon does,
//! naming the problem, and still load the user's own `0600`/`0640`/`0644`
//! file.
//!
//! Changing a file's owner needs root; that case skips otherwise.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The fixture parses but fails validation on its name: this error proves
/// that the file was read and handed to the parser.
const LOADED: &str = "volume name \"-config-loaded\"";

fn write_config(dir: &Path, name: &str, mode: u32) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(
        &path,
        format!(
            "config_schema_version = 1\n[volume]\nname = \"-config-loaded\"\n\
             max_virtual_size = \"1MiB\"\n[backing]\nroot = {:?}\n[crypto]\n\
             provider = \"local-aes-gcm-siv\"\ncrypto_compatibility_id = \"test\"\n\
             key = {{ source = \"env\", name = \"unused\" }}\n[crypto.capabilities]\n\
             supported_plaintext_sizes = [4096]\nmax_ciphertext_size = 4384\n",
            dir.join("volume").to_str().unwrap()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

fn run(config: &Path) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_maki-benchmark"))
        .arg(config)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        !output.status.success(),
        "{}: unexpected success: {stderr}",
        config.display()
    );
    stderr
}

fn assert_loaded(config: &Path, what: &str) {
    let stderr = run(config);
    assert!(stderr.contains(LOADED), "{what}: not loaded: {stderr}");
}

fn assert_refused(config: &Path, problem: &str, what: &str) {
    let stderr = run(config);
    assert!(!stderr.contains(LOADED), "{what}: loaded: {stderr}");
    assert!(
        stderr.contains(problem),
        "{what}: expected {problem:?}: {stderr}"
    );
    assert!(
        stderr.contains(config.to_str().unwrap()),
        "{what}: the error does not name the file: {stderr}"
    );
}

#[test]
fn untrusted_configurations_are_refused_and_own_ones_load() {
    let dir = tempfile::tempdir().unwrap();
    for mode in [0o620, 0o664, 0o602, 0o666] {
        let config = write_config(dir.path(), &format!("mode-{mode:o}.toml"), mode);
        assert_refused(
            &config,
            "writable by the group or by others",
            &format!("mode {mode:o}"),
        );
    }
    for mode in [0o600, 0o640, 0o644] {
        let config = write_config(dir.path(), &format!("own-{mode:o}.toml"), mode);
        assert_loaded(&config, &format!("own file, mode {mode:o}"));
    }

    let target = write_config(dir.path(), "target.toml", 0o640);
    let link = dir.path().join("link.toml");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert_refused(&link, "symbolic link", "symlink");
    let second = dir.path().join("second.toml");
    std::fs::hard_link(&target, &second).unwrap();
    assert_refused(&target, "hard links", "first of two links");
    assert_refused(&second, "hard links", "second of two links");

    // Only root may give a file away; an unprivileged run skips this case.
    let foreign = write_config(dir.path(), "foreign.toml", 0o644);
    let own_uid = std::os::unix::fs::MetadataExt::uid(&foreign.metadata().unwrap());
    let other = if own_uid == 65534 { 65533 } else { 65534 };
    match std::os::unix::fs::chown(&foreign, Some(other), Some(other)) {
        Ok(()) => assert_refused(
            &foreign,
            &format!("owned by uid {other}"),
            "another user's file",
        ),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("needs root to chown the fixture; skipping the owner case")
        }
        Err(error) => panic!("chown: {error}"),
    }
}
