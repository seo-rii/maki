//! A volume configuration decides where plaintext goes: the crypto provider
//! and its endpoints, TLS trust, credential references, the backing root and
//! the rollback witness. The daemon read it with `read_to_string`, so a file
//! the group or others could write, a file another user owns (its owner can
//! rewrite it whatever its mode), a symlink and a file with a second hard
//! link (through either, a user who controls some directory can substitute
//! a file of their choosing) were loaded like the operator's own: their
//! author could send the volume's plaintext to an endpoint they control.
//! The daemon must refuse such a file before parsing it, naming the
//! problem, while the process user's own `0600`/`0640`/`0644` file and a
//! root-owned `0640` file (SPEC 8's `root:maki`) still load.
//!
//! Changing a file's owner needs root; those cases skip otherwise.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use maki_nbdkit::adapter::NbdAdapter;

/// Unprivileged ids that are neither root nor this process.
const NOBODY: u32 = 65534;

/// The fixture parses but fails validation on its name: this error proves
/// that the file was read and handed to the parser.
const LOADED: &str = "volume name \"-config-loaded\"";

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

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

fn open(path: &Path) -> String {
    match NbdAdapter::open_config(path.to_str().unwrap()) {
        Ok(_) => panic!("{}: the fixture attached", path.display()),
        Err(error) => error.to_string(),
    }
}

fn assert_loaded(path: &Path, what: &str) {
    let error = open(path);
    assert!(error.contains(LOADED), "{what}: not loaded: {error}");
}

fn assert_refused(path: &Path, problem: &str, what: &str) {
    let error = open(path);
    assert!(!error.contains(LOADED), "{what}: loaded: {error}");
    assert!(
        error.contains(problem),
        "{what}: expected {problem:?}: {error}"
    );
    assert!(
        error.contains(path.to_str().unwrap()),
        "{what}: the error does not name the file: {error}"
    );
}

#[test]
fn group_or_world_writable_configurations_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    for mode in [0o620, 0o660, 0o664, 0o602, 0o646, 0o666, 0o622] {
        let path = write_config(dir.path(), &format!("mode-{mode:o}.toml"), mode);
        assert_refused(
            &path,
            "writable by the group or by others",
            &format!("mode {mode:o}"),
        );
    }
}

#[test]
fn a_symlinked_configuration_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let target = write_config(dir.path(), "target.toml", 0o640);
    assert_loaded(&target, "symlink target");
    let link = dir.path().join("link.toml");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert_refused(&link, "symbolic link", "symlink");
}

#[test]
fn a_hardlinked_configuration_is_refused_under_both_names() {
    let dir = tempfile::tempdir().unwrap();
    let first = write_config(dir.path(), "first.toml", 0o640);
    let second = dir.path().join("second.toml");
    std::fs::hard_link(&first, &second).unwrap();
    assert_refused(&first, "hard links", "first name");
    assert_refused(&second, "hard links", "second name");
    std::fs::remove_file(&second).unwrap();
    assert_loaded(&first, "single link again");
}

#[test]
fn a_directory_is_not_a_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let directory = dir.path().join("volume.toml");
    std::fs::create_dir(&directory).unwrap();
    assert_refused(&directory, "not a regular file", "directory");
}

#[test]
fn a_configuration_owned_by_another_user_is_refused() {
    if !is_root() {
        eprintln!("needs root to chown the fixture; skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    // The owner can make any mode writable again, so none is safe.
    for mode in [0o644, 0o640, 0o600, 0o400] {
        let path = write_config(dir.path(), &format!("foreign-{mode:o}.toml"), mode);
        std::os::unix::fs::chown(&path, Some(NOBODY), Some(NOBODY)).unwrap();
        assert_refused(
            &path,
            &format!("owned by uid {NOBODY}"),
            &format!("owner {NOBODY}, mode {mode:o}"),
        );
    }
}

#[test]
fn root_owned_and_own_configurations_still_load() {
    let dir = tempfile::tempdir().unwrap();
    // Group and other read stay allowed: a configuration holds no secret.
    for mode in [0o600, 0o640, 0o644, 0o400, 0o444] {
        let path = write_config(dir.path(), &format!("own-{mode:o}.toml"), mode);
        assert_loaded(&path, &format!("own file, mode {mode:o}"));
    }
    if is_root() {
        // SPEC 8: root:maki 0640, which the daemon reads through its group.
        let path = write_config(dir.path(), "root-group.toml", 0o640);
        std::os::unix::fs::chown(&path, Some(0), Some(NOBODY)).unwrap();
        assert_loaded(&path, "root-owned, group-readable");
    }
}
