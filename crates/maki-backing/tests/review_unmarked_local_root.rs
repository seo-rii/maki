//! A local rollback backing without its format marker is what a creation
//! leaves that stopped before it published the marker, and also what a
//! wrong `backing.root` looks like. Opening it says which: running
//! `volume create` again continues the first, but `volume create` refuses,
//! and keeps refusing, a pair holding anything an interrupted creation does
//! not leave (the `lost+found` of a filesystem mounted at the backing root,
//! a file in the witness directory, a manifest slot that holds data). Such
//! a pair must not be told that running `volume create` again continues it;
//! the refusal names what stops the creation instead.
#![cfg(target_os = "linux")]

#[path = "support/other_filesystem.rs"]
mod other_filesystem;

use std::io;
use std::path::Path;

use maki_backing::RollbackBacking;

const CAPACITY: u64 = 4 * 4096;
const CONTINUES: &str = "which running volume create again continues";
const STOPPED: &str = "volume create does not continue a creation here";
const MAY_NOT_OPEN: &str = "which this user may not open";

fn dirs() -> Option<(tempfile::TempDir, tempfile::TempDir)> {
    let root = tempfile::tempdir().unwrap();
    let witness = other_filesystem::tempdir(root.path())?;
    Some((root, witness))
}

fn open_refusal(root: &Path, witness: &Path) -> String {
    let error = RollbackBacking::open(root, witness)
        .err()
        .expect("a backing without its marker must not open");
    assert_eq!(error.kind(), io::ErrorKind::NotFound, "{error}");
    error.to_string()
}

/// The refusal of a pair `create` will not continue: it names `entries`,
/// never offers `create`, and `create` refuses the pair, before and after.
fn assert_not_offered(root: &Path, witness: &Path, entries: &[&str]) {
    for attempt in ["before", "after"] {
        let message = open_refusal(root, witness);
        assert!(!message.contains(CONTINUES), "{attempt}: {message}");
        assert!(message.contains(STOPPED), "{attempt}: {message}");
        for entry in entries {
            assert!(
                message.contains(&format!("\"{entry}\"")),
                "{attempt}: {entry}: {message}"
            );
        }
        if attempt == "before" {
            let refused = RollbackBacking::create(root, witness, CAPACITY)
                .err()
                .expect("create refuses the pair");
            assert_eq!(refused.kind(), io::ErrorKind::AlreadyExists, "{refused}");
        }
    }
}

#[test]
fn a_backing_root_holding_lost_and_found_is_not_offered_to_create() {
    let Some((root, witness)) = dirs() else {
        return;
    };
    std::fs::create_dir(root.path().join("lost+found")).unwrap();
    assert_not_offered(root.path(), witness.path(), &["lost+found"]);
}

#[test]
fn a_witness_directory_holding_another_file_is_not_offered_to_create() {
    let Some((root, witness)) = dirs() else {
        return;
    };
    std::fs::write(witness.path().join("notes"), b"kept").unwrap();
    assert_not_offered(root.path(), witness.path(), &["notes"]);
}

#[test]
fn a_manifest_slot_holding_data_is_not_offered_to_create() {
    let Some((root, witness)) = dirs() else {
        return;
    };
    std::fs::write(root.path().join("rollback.manifest.1"), b"committed").unwrap();
    std::fs::create_dir(root.path().join("lost+found")).unwrap();
    std::fs::write(witness.path().join("anchor.old"), b"kept").unwrap();
    assert_not_offered(
        root.path(),
        witness.path(),
        &["lost+found", "rollback.manifest.1", "anchor.old"],
    );
}

#[test]
fn an_interrupted_creation_is_still_offered_to_create_which_continues_it() {
    let Some((root, witness)) = dirs() else {
        return;
    };
    // What a creation leaves that stopped while it staged its marker.
    std::fs::write(root.path().join("rollback.format.next"), b"MAKI").unwrap();
    std::fs::write(witness.path().join("witness.lock"), b"").unwrap();
    let message = open_refusal(root.path(), witness.path());
    assert!(message.contains(CONTINUES), "{message}");
    drop(RollbackBacking::create(root.path(), witness.path(), CAPACITY).unwrap());
    drop(RollbackBacking::open(root.path(), witness.path()).unwrap());
}

/// What a creation stages under a name (`rollback.format.next`), and the
/// files it reserves (`rollback.arena`, the manifest slots), are files it
/// writes again from the start: a regular file with one name. Anything
/// else under those names (a directory, a symbolic link, a FIFO, a file
/// with a second name) fails the creation when it opens the entry, after
/// it has published its marker, and then every later run the same way. It
/// is refused before anything changes, named, and never offered.
#[test]
fn a_reserved_name_that_is_not_a_regular_file_is_not_offered_to_create() {
    type Plant = fn(&Path, &Path);
    let plants: [(&str, Plant); 9] = [
        ("rollback.arena", |root, _| {
            std::fs::create_dir(root.join("rollback.arena")).unwrap();
        }),
        ("rollback.arena", |root, _| {
            std::os::unix::fs::symlink("elsewhere", root.join("rollback.arena")).unwrap();
        }),
        ("rollback.format.next", |root, _| {
            std::os::unix::fs::symlink("elsewhere", root.join("rollback.format.next")).unwrap();
        }),
        ("rollback.format.next", |root, _| {
            std::fs::create_dir(root.join("rollback.format.next")).unwrap();
        }),
        ("rollback.format.next", |root, _| {
            mkfifo(&root.join("rollback.format.next"))
        }),
        ("rollback.format.next", |root, outside| {
            std::fs::write(root.join("rollback.format.next"), b"MAKI").unwrap();
            std::fs::hard_link(
                root.join("rollback.format.next"),
                outside.join("second-name"),
            )
            .unwrap();
        }),
        ("rollback.manifest.0", |root, _| {
            mkfifo(&root.join("rollback.manifest.0"))
        }),
        ("rollback.manifest.1", |root, _| {
            std::fs::create_dir(root.join("rollback.manifest.1")).unwrap();
        }),
        ("rollback.arena", |root, outside| {
            std::fs::write(root.join("rollback.arena"), b"").unwrap();
            std::fs::hard_link(root.join("rollback.arena"), outside.join("second-name")).unwrap();
        }),
    ];
    for (name, plant) in plants {
        let Some((root, witness)) = dirs() else {
            return;
        };
        let outside = tempfile::tempdir_in(root.path().parent().unwrap()).unwrap();
        plant(root.path(), outside.path());
        assert_not_offered(root.path(), witness.path(), &[name]);
        assert!(
            !root.path().join("rollback.format").exists(),
            "{name}: the refused creation published its marker"
        );
    }
}

fn mkfifo(path: &Path) {
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a NUL-terminated path; mkfifo only creates the entry.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
}

/// The staged marker (`rollback.format.next`) is never read. A regular
/// file there that this user may not open is what a creation run as root
/// leaves when it is killed between creating the name and giving the file
/// to the directory's owner (review_root_staged_marker.rs runs that case as
/// the daemon user). It is offered to `volume create`, which removes it,
/// stages the marker anew and continues in one run.
#[test]
fn a_staged_marker_this_user_may_not_open_is_replaced_in_one_run() {
    use std::os::unix::fs::PermissionsExt;
    let Some((root, witness)) = dirs() else {
        return;
    };
    let staged = root.path().join("rollback.format.next");
    std::fs::write(&staged, b"").unwrap();
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o000)).unwrap();
    // Root may open a mode-000 file (CAP_DAC_OVERRIDE): only another user
    // is refused one.
    if std::fs::File::open(&staged).is_ok() {
        eprintln!("needs a user that a mode-000 file refuses (not root); skipping");
        return;
    }
    let message = open_refusal(root.path(), witness.path());
    assert!(message.contains(CONTINUES), "{message}");
    drop(RollbackBacking::create(root.path(), witness.path(), CAPACITY).unwrap());
    drop(RollbackBacking::open(root.path(), witness.path()).unwrap());
    assert!(!staged.exists());
}

/// A reserved file this user may not open (the root-owned arena or slot a
/// creation run as root leaves when it is killed before it gives the file
/// to the directory's owner) is refused before anything changes, as a file
/// this user may not open, with the way out; never as something an
/// interrupted creation does not leave.
#[test]
fn a_reserved_file_this_user_may_not_open_is_named_with_the_way_out() {
    use std::os::unix::fs::PermissionsExt;
    let Some((root, witness)) = dirs() else {
        return;
    };
    let arena = root.path().join("rollback.arena");
    std::fs::write(&arena, b"").unwrap();
    std::fs::set_permissions(&arena, std::fs::Permissions::from_mode(0o000)).unwrap();
    // Root may open a mode-000 file (CAP_DAC_OVERRIDE): only another user
    // is refused one. review_root_staged_marker.rs runs the root-owned case
    // as the daemon user.
    if std::fs::File::open(&arena).is_ok() {
        eprintln!("needs a user that a mode-000 file refuses (not root); skipping");
        return;
    }
    let message = open_refusal(root.path(), witness.path());
    assert!(!message.contains(CONTINUES), "{message}");
    assert!(
        !message.contains("an interrupted creation does not leave"),
        "{message}"
    );
    assert!(message.contains("\"rollback.arena\""), "{message}");
    assert!(message.contains(MAY_NOT_OPEN), "{message}");
    let refused = RollbackBacking::create(root.path(), witness.path(), CAPACITY)
        .err()
        .expect("create refuses the pair");
    assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied, "{refused}");
    assert!(refused.to_string().contains("rollback.arena"), "{refused}");
    assert!(refused.to_string().contains(MAY_NOT_OPEN), "{refused}");
    assert!(!root.path().join("rollback.format").exists());
}

/// Where the entries cannot all be listed (a name that is not UTF-8), what a
/// creation would do cannot be told: nothing is offered and nothing named.
#[test]
fn a_root_that_cannot_be_listed_is_offered_nothing() {
    use std::os::unix::ffi::OsStrExt;
    let Some((root, witness)) = dirs() else {
        return;
    };
    std::fs::write(
        root.path().join(std::ffi::OsStr::from_bytes(b"stray-\xfe")),
        b"",
    )
    .unwrap();
    let message = open_refusal(root.path(), witness.path());
    assert!(!message.contains(CONTINUES), "{message}");
    assert!(!message.contains(STOPPED), "{message}");
    assert!(
        message.contains("this is not the volume's backing root"),
        "{message}"
    );
}
