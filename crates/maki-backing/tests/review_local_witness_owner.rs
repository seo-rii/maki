//! Opening a local rollback witness republishes its anchor (a fresh file
//! renamed over the old one) so a record that may be cache-only becomes
//! durable. An offline `maki check --deep` or `maki volume inspect` run as
//! root must not hand that record to root: a root-owned `0600` anchor locks
//! the daemon user out of its own witness. Observing a change of owner needs
//! root; the tests that give files to another user print why they are
//! skipped when the suite runs unprivileged (as CI does).
#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use maki_backing::witness::FileWitness;
use maki_backing::{Backing, RollbackBacking};

/// Stands in for the daemon user. Distinct uid and gid, neither root's.
const DAEMON: (u32, u32) = (65534, 65533);
const IDENTITY: [u8; 16] = *b"volume-identity!";

fn running_as_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

fn skip_unless_root(test: &str) -> bool {
    if running_as_root() {
        return false;
    }
    eprintln!("{test}: skipped: giving files to another user needs root");
    true
}

fn give(path: &Path, (uid, gid): (u32, u32)) {
    std::os::unix::fs::lchown(path, Some(uid), Some(gid)).unwrap();
    if fs::symlink_metadata(path).unwrap().is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            give(&entry.unwrap().path(), (uid, gid));
        }
    }
}

/// Every entry below `path` (itself included) as (path, uid, gid).
fn owners(path: &Path, out: &mut Vec<(String, u32, u32)>) {
    let metadata = fs::symlink_metadata(path).unwrap();
    out.push((path.display().to_string(), metadata.uid(), metadata.gid()));
    if metadata.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            owners(&entry.unwrap().path(), out);
        }
    }
}

fn foreign(paths: &[&Path], owner: (u32, u32)) -> Vec<(String, u32, u32)> {
    let mut all = Vec::new();
    for path in paths {
        owners(path, &mut all);
    }
    all.retain(|(_, uid, gid)| (*uid, *gid) != owner);
    all
}

fn anchor_mode(witness: &Path) -> u32 {
    fs::metadata(witness.join("anchor")).unwrap().mode() & 0o7777
}

#[test]
fn root_republish_keeps_the_anchor_owner_and_mode() {
    if skip_unless_root("root_republish_keeps_the_anchor_owner_and_mode") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    drop(FileWitness::create(dir.path(), IDENTITY, [0x11; 32]).unwrap());
    give(dir.path(), DAEMON);

    // Open alone republishes; an advance publishes the next generation.
    drop(FileWitness::open(dir.path()).unwrap());
    assert_eq!(foreign(&[dir.path()], DAEMON), []);
    assert_eq!(anchor_mode(dir.path()), 0o600);

    let mut witness = FileWitness::open(dir.path()).unwrap();
    witness.advance([0x22; 32]).unwrap();
    drop(witness);
    assert_eq!(foreign(&[dir.path()], DAEMON), []);
    assert_eq!(anchor_mode(dir.path()), 0o600);
    assert_eq!(
        FileWitness::open(dir.path()).unwrap().anchor().generation,
        1
    );
}

#[test]
fn root_reopen_of_a_daemon_owned_rollback_backing_creates_no_root_owned_file() {
    if skip_unless_root("root_reopen_of_a_daemon_owned_rollback_backing_creates_no_root_owned_file")
    {
        return;
    }
    // Explicit roots keep the witness on an independent filesystem.
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let witness = tempfile::tempdir_in("/dev/shm").unwrap();
    let backing = RollbackBacking::create(root.path(), witness.path(), 8 * 4096).unwrap();
    let file = backing.open("data", true).unwrap();
    file.write_at(0, b"daemon").unwrap();
    file.sync_data().unwrap();
    backing.sync_dir("").unwrap();
    drop(file);
    drop(backing);
    give(root.path(), DAEMON);
    give(witness.path(), DAEMON);

    // What an offline check run as root does, plus a commit that advances
    // the witness.
    let backing = RollbackBacking::open(root.path(), witness.path()).unwrap();
    let file = backing.open("data", false).unwrap();
    file.write_at(0, b"offline").unwrap();
    file.sync_data().unwrap();
    drop(file);
    drop(backing);

    assert_eq!(foreign(&[root.path(), witness.path()], DAEMON), []);
    assert_eq!(anchor_mode(witness.path()), 0o600);
    drop(RollbackBacking::open(root.path(), witness.path()).unwrap());
}

#[test]
fn republish_by_the_anchor_owner_changes_neither_owner_nor_mode() {
    // Runs as any user: the owner republishing its own record (the daemon,
    // or root on a root-owned witness) gives nothing away.
    let dir = tempfile::tempdir().unwrap();
    drop(FileWitness::create(dir.path(), IDENTITY, [0x11; 32]).unwrap());
    let metadata = fs::metadata(dir.path().join("anchor")).unwrap();
    let owner = (metadata.uid(), metadata.gid());

    let mut witness = FileWitness::open(dir.path()).unwrap();
    witness.advance([0x22; 32]).unwrap();
    drop(witness);
    drop(FileWitness::open(dir.path()).unwrap());

    assert_eq!(foreign(&[dir.path()], owner), []);
    assert_eq!(anchor_mode(dir.path()), 0o600);
}
