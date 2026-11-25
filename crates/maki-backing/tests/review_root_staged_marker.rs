//! A local creation run as root creates each file below a backing root
//! that the daemon user owns for that user: without unnamed temporary
//! files it creates the file under its name and then gives it away
//! (`O_CREAT | O_EXCL`, then `fchown`). Killed in between, it leaves a
//! root-owned `0600` file. Under the staged marker's name
//! (`rollback.format.next`), which nothing reads, that is a state the
//! daemon user's `volume create` must continue, in one run. Under the
//! arena's name (the creation had published its marker) the daemon user's
//! `volume create` cannot continue it: it says that this user may not open
//! the file and how to give it back, and continues once it is given back.
//!
//! Acting as root and as the daemon user needs root: the test re-executes
//! itself as uid 65534 for the daemon user's commands.
#![cfg(target_os = "linux")]

#[path = "support/other_filesystem.rs"]
mod other_filesystem;
#[path = "support/shared_dir.rs"]
mod shared_dir;

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output};

use maki_backing::RollbackBacking;

/// Stands in for the daemon user. Distinct uid and gid, neither root's.
const DAEMON: (u32, u32) = (65534, 65533);
const CAPACITY: u64 = 4 * 4096;
const STEP: &str = "MAKI_ROOT_STAGED_MARKER_STEP";
const ROOT: &str = "MAKI_ROOT_STAGED_MARKER_ROOT";
const WITNESS: &str = "MAKI_ROOT_STAGED_MARKER_WITNESS";

/// The daemon user's half: run one command on the pair and report it.
fn step(name: &str, root: &Path, witness: &Path) {
    let outcome = match name {
        "probe" => Ok(()),
        "open" => RollbackBacking::open(root, witness).map(drop),
        "create" => RollbackBacking::create(root, witness, CAPACITY).map(drop),
        other => panic!("unknown step {other}"),
    };
    match outcome {
        Ok(()) => println!("{name}: ok"),
        Err(error) => {
            println!("{name}: {:?}: {error}", error.kind());
            std::process::exit(1);
        }
    }
}

/// Run `step` as the daemon user in a child that re-enters `test`.
fn as_daemon(test: &str, step: &str, root: &Path, witness: &Path) -> Output {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(STEP, step)
        .env(ROOT, root)
        .env(WITNESS, witness)
        .uid(DAEMON.0)
        .gid(DAEMON.1)
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The pair as `install -d -o maki -g maki -m 0700` makes it for the daemon
/// user, below directories every user may reach, or `None` with the reason
/// the test is skipped printed.
fn daemon_pair(test: &str) -> Option<(tempfile::TempDir, tempfile::TempDir)> {
    if let (Some(name), Some(root), Some(witness)) = (
        std::env::var_os(STEP),
        std::env::var_os(ROOT),
        std::env::var_os(WITNESS),
    ) {
        step(
            name.to_str().unwrap(),
            Path::new(&root),
            Path::new(&witness),
        );
        return None;
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("{test}: skipped: acting as root and as the daemon user needs root");
        return None;
    }
    let top = match shared_dir::tempdir() {
        Ok(top) => top,
        Err(reason) => {
            eprintln!("{test}: skipped: {reason}");
            return None;
        }
    };
    let root = top.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let witness = other_filesystem::reachable_tempdir(&root)?;
    for directory in [root.as_path(), witness.path()] {
        std::os::unix::fs::chown(directory, Some(DAEMON.0), Some(DAEMON.1)).unwrap();
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let probe = as_daemon(test, "probe", &root, witness.path());
    if !probe.status.success() {
        eprintln!(
            "{test}: skipped: cannot run this test binary as uid {} ({probe:?})",
            DAEMON.0
        );
        return None;
    }
    Some((top, witness))
}

/// A root-owned `0600` file, as the creation left it.
fn plant_root_owned(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(std::fs::metadata(path).unwrap().uid(), 0);
}

#[test]
fn a_staged_marker_root_left_is_continued_by_the_daemon_user() {
    const TEST: &str = "a_staged_marker_root_left_is_continued_by_the_daemon_user";
    let Some((top, witness)) = daemon_pair(TEST) else {
        return;
    };
    let root = top.path().join("root");
    plant_root_owned(&root.join("rollback.format.next"), b"");

    let open = as_daemon(TEST, "open", &root, witness.path());
    assert!(!open.status.success(), "{open:?}");
    assert!(
        stdout(&open).contains("which running volume create again continues"),
        "{}",
        stdout(&open)
    );
    let create = as_daemon(TEST, "create", &root, witness.path());
    assert!(
        create.status.success(),
        "the first run: {}",
        stdout(&create)
    );
    let open = as_daemon(TEST, "open", &root, witness.path());
    assert!(open.status.success(), "{}", stdout(&open));
    assert!(!root.join("rollback.format.next").exists());
    assert_eq!(
        std::fs::metadata(root.join("rollback.format"))
            .unwrap()
            .uid(),
        DAEMON.0
    );
}

#[test]
fn an_arena_root_left_is_named_with_the_way_out_and_continued_once_given_back() {
    const TEST: &str = "an_arena_root_left_is_named_with_the_way_out_and_continued_once_given_back";
    let Some((top, witness)) = daemon_pair(TEST) else {
        return;
    };
    let root = top.path().join("root");
    // The creation published its marker and was killed while it created
    // the arena: the marker of a creation elsewhere is the same file.
    let scratch = tempfile::tempdir().unwrap();
    let Some(scratch_witness) = other_filesystem::tempdir(scratch.path()) else {
        return;
    };
    drop(RollbackBacking::create(scratch.path(), scratch_witness.path(), CAPACITY).unwrap());
    std::fs::copy(
        scratch.path().join("rollback.format"),
        root.join("rollback.format"),
    )
    .unwrap();
    std::os::unix::fs::chown(root.join("rollback.format"), Some(DAEMON.0), Some(DAEMON.1)).unwrap();
    plant_root_owned(&root.join("rollback.arena"), b"");

    for run in ["first", "second"] {
        let create = as_daemon(TEST, "create", &root, witness.path());
        assert!(!create.status.success(), "{run}: {}", stdout(&create));
        let text = stdout(&create);
        assert!(text.contains("PermissionDenied"), "{run}: {text}");
        assert!(text.contains("\"rollback.arena\""), "{run}: {text}");
        assert!(
            text.contains("which this user may not open"),
            "{run}: {text}"
        );
        assert!(text.contains("chown"), "{run}: {text}");
        assert!(
            !text.contains("an interrupted creation does not leave"),
            "{run}: {text}"
        );
    }
    std::os::unix::fs::chown(root.join("rollback.arena"), Some(DAEMON.0), Some(DAEMON.1)).unwrap();
    let create = as_daemon(TEST, "create", &root, witness.path());
    assert!(
        create.status.success(),
        "once given back: {}",
        stdout(&create)
    );
    let open = as_daemon(TEST, "open", &root, witness.path());
    assert!(open.status.success(), "{}", stdout(&open));
}
