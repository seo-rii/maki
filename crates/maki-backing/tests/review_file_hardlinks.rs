//! BUG-169: Linux backing opens must reject inodes already shared by multiple
//! hardlinks. The check applies to ordinary files and volume locks alike.

#![cfg(target_os = "linux")]

use std::io;
use std::os::unix::fs::{symlink, MetadataExt};

use maki_backing::{Backing, FileBacking};

#[test]
fn opening_an_external_hardlink_cannot_modify_the_other_name() {
    let dir = tempfile::tempdir().unwrap();
    let outside = dir.path().join("outside-marker");
    std::fs::write(&outside, b"original").unwrap();
    let root = dir.path().join("volume");
    let backing = FileBacking::new(&root).unwrap();
    std::fs::hard_link(&outside, root.join("linked-marker")).unwrap();

    if let Ok(file) = backing.open("linked-marker", false) {
        file.write_at(0, b"modified").unwrap();
        file.sync_data().unwrap();
    }

    assert_eq!(
        std::fs::read(&outside).unwrap(),
        b"original",
        "a backing write modified an inode also named outside its root"
    );
}

#[test]
fn create_cannot_open_an_existing_external_hardlink() {
    let dir = tempfile::tempdir().unwrap();
    let outside = dir.path().join("outside-marker");
    std::fs::write(&outside, b"original").unwrap();
    let root = dir.path().join("volume");
    let backing = FileBacking::new(&root).unwrap();
    std::fs::hard_link(&outside, root.join("linked-marker")).unwrap();

    let error = backing
        .open("linked-marker", true)
        .err()
        .expect("create must not open an existing multiply linked inode");
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(std::fs::read(&outside).unwrap(), b"original");
    assert_eq!(std::fs::metadata(&outside).unwrap().nlink(), 2);
}

#[test]
fn aliases_within_the_same_backing_are_also_refused() {
    let dir = tempfile::tempdir().unwrap();
    let backing = FileBacking::new(dir.path()).unwrap();
    backing.open("original", true).unwrap();
    std::fs::hard_link(dir.path().join("original"), dir.path().join("alias")).unwrap();

    for name in ["original", "alias"] {
        assert!(
            backing.open(name, false).is_err(),
            "multiple links inside one root still alias the same backing file"
        );
    }
}

#[test]
fn a_hardlinked_volume_lock_is_refused_without_modifying_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let outside = dir.path().join("outside-marker");
    std::fs::write(&outside, b"original").unwrap();
    let root = dir.path().join("volume");
    let backing = FileBacking::new(&root).unwrap();
    std::fs::hard_link(&outside, root.join("volume.lock")).unwrap();

    let error = backing
        .try_lock("volume.lock")
        .err()
        .expect("a volume lock must not share another file's inode");
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(std::fs::read(&outside).unwrap(), b"original");
}

#[test]
fn removing_an_extra_link_restores_an_ordinary_file() {
    let dir = tempfile::tempdir().unwrap();
    let outside = dir.path().join("outside-marker");
    std::fs::write(&outside, b"original").unwrap();
    let root = dir.path().join("volume");
    let backing = FileBacking::new(&root).unwrap();
    std::fs::hard_link(&outside, root.join("ordinary")).unwrap();
    std::fs::remove_file(&outside).unwrap();

    let file = backing.open("ordinary", false).unwrap();
    file.write_at(0, b"modified").unwrap();
    file.sync_data().unwrap();
    assert_eq!(std::fs::read(root.join("ordinary")).unwrap(), b"modified");
    assert_eq!(std::fs::metadata(root.join("ordinary")).unwrap().nlink(), 1);
}

#[test]
fn created_and_reopened_regular_files_and_locks_keep_working() {
    let dir = tempfile::tempdir().unwrap();
    let backing = FileBacking::new(dir.path()).unwrap();
    let file = backing.open("ordinary", true).unwrap();
    file.write_at(0, b"ordinary").unwrap();
    file.sync_data().unwrap();
    for create in [false, true] {
        let mut bytes = [0; 8];
        backing
            .open("ordinary", create)
            .unwrap()
            .read_at(0, &mut bytes)
            .unwrap();
        assert_eq!(&bytes, b"ordinary");
    }
    assert_eq!(
        std::fs::metadata(dir.path().join("ordinary"))
            .unwrap()
            .nlink(),
        1
    );

    let lock = backing.try_lock("volume.lock").unwrap();
    assert_eq!(
        backing.try_lock("volume.lock").err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
    drop(lock);
    backing.try_lock("volume.lock").unwrap();
}

#[test]
fn directories_and_symlinks_remain_refused() {
    let dir = tempfile::tempdir().unwrap();
    let outside = dir.path().join("outside-marker");
    std::fs::write(&outside, b"original").unwrap();
    let root = dir.path().join("volume");
    let backing = FileBacking::new(&root).unwrap();
    backing.create_dir_all("directory").unwrap();
    symlink(&outside, root.join("symlink")).unwrap();

    for name in ["directory", "symlink"] {
        for create in [false, true] {
            assert!(backing.open(name, create).is_err());
        }
        assert!(backing.try_lock(name).is_err());
    }
    assert_eq!(std::fs::read(&outside).unwrap(), b"original");
    assert!(root.join("directory").is_dir());
    assert!(std::fs::symlink_metadata(root.join("symlink"))
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn a_link_created_after_open_is_refused_by_subsequent_opens() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("volume");
    let backing = FileBacking::new(&root).unwrap();
    let file = backing.open("ordinary", true).unwrap();
    let outside = dir.path().join("outside-marker");
    std::fs::hard_link(root.join("ordinary"), &outside).unwrap();

    // Open-time validation cannot revoke a previously returned descriptor
    // or prevent a writer to the namespace from adding another hardlink.
    file.write_at(0, b"existing handle").unwrap();
    assert_eq!(std::fs::read(&outside).unwrap(), b"existing handle");
    assert!(backing.open("ordinary", false).is_err());
    assert!(backing.open("ordinary", true).is_err());
    assert!(backing.try_lock("ordinary").is_err());
}
