//! A local rollback-protected backing opens two configured directories:
//! the backing root (`backing.root`) and the witness directory
//! (`backing.rollback_protection.witness_root`). When one of them is
//! missing (a typo, or a witness filesystem that is not mounted and whose
//! mount point is gone) or this process may not open it, the daemon,
//! `maki check`, `maki volume inspect` and `maki-benchmark` must say which
//! directory, where and what to check, not repeat the bare system error.
//! The error kind stays what the system said. Opening never creates
//! either directory; `volume create` still does.
#![cfg(target_os = "linux")]

#[path = "support/other_filesystem.rs"]
mod other_filesystem;

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use maki_backing::RollbackBacking;

const WITNESS_KEY: &str = "backing.rollback_protection.witness_root";
const ROOT_KEY: &str = "backing.root";

/// A backing root and a witness directory on another filesystem.
fn pair() -> Option<(tempfile::TempDir, tempfile::TempDir)> {
    let root = tempfile::tempdir().unwrap();
    let witness = other_filesystem::tempdir(root.path())?;
    Some((root, witness))
}

fn open_error(root: &Path, witness: &Path) -> io::Error {
    RollbackBacking::open(root, witness)
        .err()
        .expect("the pair must not open")
}

fn assert_names(error: &io::Error, path: &Path, key: &str, kind: io::ErrorKind, check: &str) {
    let message = error.to_string();
    assert_eq!(error.kind(), kind, "{message}");
    assert!(message.contains(&path.display().to_string()), "{message}");
    assert!(message.contains(&format!("`{key}`")), "{message}");
    assert!(message.contains(check), "{message}");
}

#[test]
fn a_missing_witness_directory_is_named_with_its_setting() {
    let root = tempfile::tempdir().unwrap();
    let parent = tempfile::tempdir().unwrap();
    let witness = parent.path().join("not-mounted");
    let error = open_error(root.path(), &witness);
    assert_names(
        &error,
        &witness,
        WITNESS_KEY,
        io::ErrorKind::NotFound,
        "does not exist: check the configured path for a typo",
    );
    assert!(error.to_string().contains("mounted"), "{error}");
    assert!(!witness.exists(), "opening created the witness directory");
}

#[test]
fn a_missing_backing_root_is_named_with_its_setting() {
    let parent = tempfile::tempdir().unwrap();
    let witness = tempfile::tempdir().unwrap();
    let root = parent.path().join("volume");
    let error = open_error(&root, witness.path());
    assert_names(
        &error,
        &root,
        ROOT_KEY,
        io::ErrorKind::NotFound,
        "does not exist: check the configured path for a typo",
    );
    assert!(!root.exists(), "opening created the backing root");
}

#[test]
fn a_witness_path_that_is_a_file_is_named_with_its_setting() {
    let root = tempfile::tempdir().unwrap();
    let parent = tempfile::tempdir().unwrap();
    let witness = parent.path().join("witness");
    std::fs::write(&witness, b"").unwrap();
    let error = open_error(root.path(), &witness);
    // The kind the witness has always given a path that is not a directory.
    assert_names(
        &error,
        &witness,
        WITNESS_KEY,
        io::ErrorKind::InvalidInput,
        "is not a directory",
    );
}

#[test]
fn a_backing_root_that_is_a_file_is_named_with_its_setting() {
    let parent = tempfile::tempdir().unwrap();
    let witness = tempfile::tempdir().unwrap();
    let root = parent.path().join("volume");
    std::fs::write(&root, b"").unwrap();
    let error = open_error(&root, witness.path());
    assert_names(
        &error,
        &root,
        ROOT_KEY,
        io::ErrorKind::NotADirectory,
        "is not a directory",
    );
}

/// A configured path is never followed through a symbolic link, and one
/// that leads through a file is not a directory either. The refusal says
/// which, and keeps the kind opening the pair has always given: only a
/// witness path that is, followed, something other than a directory is
/// InvalidInput; the others are the system's NotADirectory.
#[test]
fn a_path_that_is_not_a_directory_is_named_with_what_is_wrong() {
    let Some((root, witness)) = pair() else {
        return;
    };
    drop(RollbackBacking::create(root.path(), witness.path(), 4 * 4096).unwrap());
    drop(RollbackBacking::open(root.path(), witness.path()).unwrap());
    let links = tempfile::tempdir().unwrap();
    let to_witness = links.path().join("witness");
    std::os::unix::fs::symlink(witness.path(), &to_witness).unwrap();
    let to_parent = links.path().join("parent");
    std::os::unix::fs::symlink(witness.path().parent().unwrap(), &to_parent).unwrap();
    let through = to_parent.join(witness.path().file_name().unwrap());
    let file = links.path().join("file");
    std::fs::write(&file, b"").unwrap();
    let under_file = file.join("witness");
    let to_file = links.path().join("to-file");
    std::os::unix::fs::symlink(&file, &to_file).unwrap();
    for (path, kind, says) in [
        (
            &to_witness,
            io::ErrorKind::NotADirectory,
            "is a symbolic link, which is not followed",
        ),
        (
            &through,
            io::ErrorKind::NotADirectory,
            "is reached through a symbolic link",
        ),
        (
            &under_file,
            io::ErrorKind::NotADirectory,
            "a component of its path is not a directory",
        ),
        (
            &to_file,
            io::ErrorKind::InvalidInput,
            "is a symbolic link, which is not followed",
        ),
    ] {
        let error = open_error(root.path(), path);
        assert_names(&error, path, WITNESS_KEY, kind, says);
    }
    // The pair itself still opens.
    drop(RollbackBacking::open(root.path(), witness.path()).unwrap());
}

/// Restores a directory's mode before it is removed.
struct Mode<'a>(&'a Path);

impl Drop for Mode<'_> {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(self.0, std::fs::Permissions::from_mode(0o700));
    }
}

/// Root may open a mode-000 directory (CAP_DAC_OVERRIDE): only another
/// user is refused one.
fn refused_a_closed_directory() -> bool {
    let probe = tempfile::tempdir().unwrap();
    let closed = probe.path().join("closed");
    std::fs::create_dir(&closed).unwrap();
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).unwrap();
    let _mode = Mode(&closed);
    std::fs::read_dir(&closed).is_err()
}

#[test]
fn a_directory_this_user_may_not_open_is_named_with_its_setting() {
    if !refused_a_closed_directory() {
        eprintln!("needs a user that a mode-000 directory refuses (not root); skipping");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let Some(witness) = other_filesystem::tempdir(root.path()) else {
        return;
    };
    for (closed, key) in [(witness.path(), WITNESS_KEY), (root.path(), ROOT_KEY)] {
        std::fs::set_permissions(closed, std::fs::Permissions::from_mode(0o000)).unwrap();
        let mode = Mode(closed);
        let error = open_error(root.path(), witness.path());
        assert_names(
            &error,
            closed,
            key,
            io::ErrorKind::PermissionDenied,
            "check the owner and mode",
        );
        drop(mode);
    }
}

#[test]
fn creation_still_makes_a_missing_witness_directory() {
    let root = tempfile::tempdir().unwrap();
    let Some(parent) = other_filesystem::tempdir(root.path()) else {
        return;
    };
    let witness = parent.path().join("witness");
    drop(RollbackBacking::create(root.path(), &witness, 4 * 4096).unwrap());
    assert!(witness.is_dir());
    drop(RollbackBacking::open(root.path(), &witness).unwrap());
}
