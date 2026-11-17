//! The remote witness state directory *is* the freshness authority: its
//! `remote.state` file decides which session and root every volume client
//! accepts. `StateStore::open`/`create` pinned the directory without
//! following a symlink but checked neither its owner nor its mode, nor
//! those of the `remote.*` files inside, so any user who could write the
//! directory or one of those files (its owner, or anyone when group/other
//! write was granted) could put an older state back and roll the
//! authority back across a restart. The state directory and its entries
//! must belong to root or to the user the process runs as and must not be
//! writable by group or others. Read access stays allowed: the files hold
//! the public record and digests of random 256-bit capabilities.
//!
//! `FileBacking` itself has no such rule: volume backing roots are checked
//! by their own owners (the attach plan, the daemon's startup checks).
//!
//! Changing an owner needs root, so those cases skip otherwise.

#![cfg(unix)]

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use maki_backing::remote_witness::{Action, Request, Role, StateStore};

/// An unprivileged uid and gid that is neither root nor this process.
const NOBODY: u32 = 65534;
const ID: [u8; 16] = [3; 16];

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

fn chown(path: &Path, owner: u32) {
    std::os::unix::fs::chown(path, Some(owner), Some(owner)).unwrap();
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn uid(path: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).unwrap().uid()
}

fn inspect(store: &mut StateStore) {
    store
        .handle(
            Role::Admin,
            &Request {
                authorization: None,
                operation_id: [9; 16],
                expected: None,
                action: Action::Inspect,
            },
        )
        .unwrap();
}

fn assert_refused(what: &str, result: io::Result<StateStore>, reason: &str) {
    let Err(error) = result else {
        panic!("{what}: the witness state was accepted");
    };
    assert_eq!(
        error.kind(),
        io::ErrorKind::PermissionDenied,
        "{what}: {error}"
    );
    assert!(error.to_string().contains(reason), "{what}: {error}");
}

fn entries(directory: &Path) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// An enrolled authority in a fresh directory, closed again.
fn enrolled() -> (tempfile::TempDir, std::path::PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("authority");
    drop(StateStore::create(&state, ID).unwrap());
    (temp, state)
}

#[test]
fn a_state_directory_another_user_owns_is_refused() {
    if !is_root() {
        eprintln!("needs root to chown the fixture to uid {NOBODY}; skipping");
        return;
    }
    // Enrollment into a directory someone else already controls.
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("authority");
    std::fs::create_dir(&state).unwrap();
    for mode in [0o700, 0o755] {
        chown(&state, NOBODY);
        chmod(&state, mode);
        assert_refused(
            &format!("create, mode {mode:o}"),
            StateStore::create(&state, ID),
            "state directory is owned by uid 65534",
        );
        assert!(entries(&state).is_empty(), "a refused create wrote state");
    }

    // An enrolled authority handed to another user afterwards.
    let (_temp, state) = enrolled();
    let own = uid(&state);
    chown(&state, NOBODY);
    assert_refused(
        "open",
        StateStore::open(&state),
        "state directory is owned by uid 65534",
    );
    chown(&state, own);
    inspect(&mut StateStore::open(&state).unwrap());
}

#[test]
fn a_state_directory_writable_by_group_or_others_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let fresh = temp.path().join("fresh");
    std::fs::create_dir(&fresh).unwrap();
    let (_enrolled, state) = enrolled();
    // Sticky bits do not help: a stranger could still create the next
    // `remote.next` before the service does.
    for mode in [0o770, 0o720, 0o707, 0o702, 0o777, 0o1777, 0o3775] {
        chmod(&fresh, mode);
        assert_refused(
            &format!("create, mode {mode:o}"),
            StateStore::create(&fresh, ID),
            "state directory must not be writable by group or others",
        );
        assert!(entries(&fresh).is_empty(), "a refused create wrote state");
        chmod(&state, mode);
        assert_refused(
            &format!("open, mode {mode:o}"),
            StateStore::open(&state),
            "state directory must not be writable by group or others",
        );
    }
    chmod(&state, 0o700);
    inspect(&mut StateStore::open(&state).unwrap());
}

#[test]
fn state_files_another_user_owns_or_can_write_are_refused() {
    let (_temp, state) = enrolled();
    let foreign = is_root();
    if !foreign {
        eprintln!("needs root to chown the fixture to uid {NOBODY}; checking modes only");
    }
    for name in ["remote.state", "remote.lock"] {
        let path = state.join(name);
        let own = uid(&path);
        if foreign {
            chown(&path, NOBODY);
            assert_refused(
                &format!("open, {name} owned by {NOBODY}"),
                StateStore::open(&state),
                &format!("state file {name} is owned by uid 65534"),
            );
            chown(&path, own);
        }
        for mode in [0o620, 0o602, 0o666] {
            chmod(&path, mode);
            assert_refused(
                &format!("open, {name} mode {mode:o}"),
                StateStore::open(&state),
                &format!("state file {name} must not be writable by group or others"),
            );
        }
        chmod(&path, 0o600);
    }

    // A planted `remote.next` would be reused by the next publish and
    // renamed into place as the authority record.
    let planted = state.join("remote.next");
    std::fs::write(&planted, b"").unwrap();
    chmod(&planted, 0o666);
    assert_refused(
        "open, remote.next mode 666",
        StateStore::open(&state),
        "state file remote.next must not be writable by group or others",
    );
    if foreign {
        chmod(&planted, 0o600);
        chown(&planted, NOBODY);
        assert_refused(
            &format!("open, remote.next owned by {NOBODY}"),
            StateStore::open(&state),
            "state file remote.next is owned by uid 65534",
        );
        // The same before enrollment: only a lock and a stray file exist.
        let temp = tempfile::tempdir().unwrap();
        let fresh = temp.path().join("fresh");
        std::fs::create_dir(&fresh).unwrap();
        std::fs::write(fresh.join("remote.lock"), b"").unwrap();
        chown(&fresh.join("remote.lock"), NOBODY);
        assert_refused(
            "create, remote.lock owned by 65534",
            StateStore::create(&fresh, ID),
            "state file remote.lock is owned by uid 65534",
        );
        assert!(!fresh.join("remote.state").exists());
    }
    std::fs::remove_file(&planted).unwrap();
    inspect(&mut StateStore::open(&state).unwrap());
}

#[test]
fn private_and_world_readable_state_still_opens() {
    let (_temp, state) = enrolled();
    // As enrolled: an owner-only directory and owner-only files.
    inspect(&mut StateStore::open(&state).unwrap());
    // Read and search access for group and others reveal only public
    // state, so they are allowed, as is a setgid directory.
    for (directory, file) in [(0o755, 0o644), (0o750, 0o640), (0o2750, 0o640)] {
        chmod(&state, directory);
        for name in ["remote.state", "remote.lock"] {
            chmod(&state.join(name), file);
        }
        inspect(&mut StateStore::open(&state).unwrap());
    }
    if is_root() {
        // Root owns what root creates; an explicit root owner is accepted.
        chown(&state, 0);
        inspect(&mut StateStore::open(&state).unwrap());
    }
}
