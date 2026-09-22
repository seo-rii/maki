#![cfg(target_os = "linux")]

use maki_backing::{Backing, RollbackBacking};
use std::io;

fn dirs() -> (tempfile::TempDir, tempfile::TempDir) {
    (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir_in("/dev/shm").unwrap(),
    )
}

#[test]
fn only_explicitly_synced_data_and_names_survive() {
    let (root, witness) = dirs();
    let b = RollbackBacking::create(root.path(), witness.path(), 64 * 4096).unwrap();
    let a = b.open("a", true).unwrap();
    a.write_at(0, b"old").unwrap();
    a.sync_data().unwrap();
    b.sync_dir("").unwrap();
    a.write_at(0, b"new").unwrap();
    let c = b.open("c", true).unwrap();
    c.write_at(0, b"other").unwrap();
    c.sync_data().unwrap();
    // Syncing c must neither commit a's bytes nor c's directory binding.
    drop((a, c, b));
    let b = RollbackBacking::open(root.path(), witness.path()).unwrap();
    let mut bytes = [0; 3];
    b.open("a", false).unwrap().read_at(0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"old");
    assert!(!b.exists("c").unwrap());
}

#[test]
fn directory_sync_does_not_promote_unsynced_file_bytes() {
    let (root, witness) = dirs();
    let b = RollbackBacking::create(root.path(), witness.path(), 64 * 4096).unwrap();
    b.open("a", true).unwrap().write_at(0, b"pending").unwrap();
    b.sync_dir("").unwrap();
    drop(b);
    let b = RollbackBacking::open(root.path(), witness.path()).unwrap();
    // Physical reservation may persist EOF, but cannot publish pending bytes.
    let file = b.open("a", false).unwrap();
    assert_eq!(file.len().unwrap(), 7);
    let mut bytes = [0xff; 7];
    file.read_at(0, &mut bytes).unwrap();
    assert_eq!(bytes, [0; 7]);
}

#[test]
fn old_whole_backing_cannot_replace_witnessed_generation() {
    let (root, witness) = dirs();
    let saved = tempfile::tempdir().unwrap();
    let b = RollbackBacking::create(root.path(), witness.path(), 64 * 4096).unwrap();
    let f = b.open("a", true).unwrap();
    f.write_at(0, b"old").unwrap();
    f.sync_data().unwrap();
    b.sync_dir("").unwrap();
    for entry in std::fs::read_dir(root.path()).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), saved.path().join(entry.file_name())).unwrap();
    }
    f.write_at(0, b"new").unwrap();
    f.sync_data().unwrap();
    drop((f, b));
    for entry in std::fs::read_dir(saved.path()).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), root.path().join(entry.file_name())).unwrap();
    }
    assert!(RollbackBacking::open(root.path(), witness.path()).is_err());
}

#[test]
fn namespace_changes_do_not_redirect_existing_handles() {
    let (root, witness) = dirs();
    let b = RollbackBacking::create(root.path(), witness.path(), 64 * 4096).unwrap();
    let old = b.open("a", true).unwrap();
    old.write_at(0, b"old").unwrap();
    old.sync_data().unwrap();
    b.sync_dir("").unwrap();
    b.rename("a", "b").unwrap();
    let new = b.open("a", true).unwrap();
    new.write_at(0, b"new").unwrap();
    new.sync_data().unwrap();
    b.remove("b").unwrap();
    old.write_at(0, b"xyz").unwrap();
    old.sync_data().unwrap();
    b.sync_dir("").unwrap();
    let mut bytes = [0; 3];
    new.read_at(0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"new");
    assert!(!b.exists("b").unwrap());
    drop((old, new, b));
    let b = RollbackBacking::open(root.path(), witness.path()).unwrap();
    assert_eq!(b.list("").unwrap(), vec!["a"]);
}

#[test]
fn reservations_survive_restart_and_rewrites_need_no_more_capacity() {
    let (root, witness) = dirs();
    let b = RollbackBacking::create(root.path(), witness.path(), 2 * 4096).unwrap();
    let f = b.open("a", true).unwrap();
    b.sync_dir("").unwrap();
    f.allocate_range(0, 8192).unwrap();
    assert_eq!(b.free_bytes().unwrap(), Some(0));
    assert!(f.allocate_range(8192, 1).is_err());
    drop((f, b));
    let b = RollbackBacking::open(root.path(), witness.path()).unwrap();
    assert_eq!(b.free_bytes().unwrap(), Some(0));
    let f = b.open("a", false).unwrap();
    for value in 1..5 {
        f.write_at(0, &[value; 8192]).unwrap();
        f.sync_data().unwrap();
    }
    f.punch_hole(0, 8192).unwrap();
    f.sync_data().unwrap();
    assert_eq!(b.free_bytes().unwrap(), Some(8192));
}

#[test]
fn corrupt_committed_data_and_conflicting_writers_are_refused() {
    use std::os::unix::fs::FileExt;
    let (root, witness) = dirs();
    let b = RollbackBacking::create(root.path(), witness.path(), 64 * 4096).unwrap();
    assert!(RollbackBacking::open(root.path(), witness.path()).is_err());
    let f = b.open("a", true).unwrap();
    f.write_at(0, &[0x42; 4096]).unwrap();
    f.sync_data().unwrap();
    b.sync_dir("").unwrap();
    let arena = std::fs::OpenOptions::new()
        .write(true)
        .open(root.path().join("rollback.arena"))
        .unwrap();
    // Overwrite every arena page so the test does not depend on placement.
    for page in 0..128 {
        arena.write_all_at(&[0x24; 4096], page * 4096).unwrap();
    }
    assert!(f.read_at(0, &mut [0; 4096]).is_err());
    drop((f, b));
    assert!(RollbackBacking::open(root.path(), witness.path()).is_err());
}

#[test]
fn witness_must_be_independent_and_existing_authority_is_never_reenrolled() {
    let (root, witness) = dirs();
    let same_fs = tempfile::tempdir().unwrap();
    assert_eq!(
        RollbackBacking::create(root.path(), same_fs.path(), 4096)
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    let b = RollbackBacking::create(root.path(), witness.path(), 4096).unwrap();
    drop(b);
    assert!(RollbackBacking::create(root.path(), witness.path(), 4096).is_err());
    let absent = witness.path().join("absent");
    assert!(RollbackBacking::open(root.path(), &absent).is_err());
    assert!(!absent.exists());
}
