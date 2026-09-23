//! FUP-014: namespace replacement must not redirect an attached backing.
#![cfg(target_os = "linux")]

use maki_backing::{Backing, FileBacking};
use std::{fs, os::unix::fs::symlink};

#[test]
fn replacing_the_root_path_cannot_redirect_any_backing_operation() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("volume");
    let moved = temp.path().join("attached-volume");
    let outside = temp.path().join("other-volume");
    let backing = FileBacking::new(&root).unwrap();
    fs::create_dir(&outside).unwrap();
    for dir in [&root, &outside] {
        fs::write(dir.join("data"), b"original").unwrap();
        fs::write(dir.join("remove-me"), b"original").unwrap();
        fs::write(dir.join("rename-me"), b"original").unwrap();
    }
    let lock = backing.try_lock("volume.lock").unwrap();
    fs::rename(&root, &moved).unwrap();
    symlink(&outside, &root).unwrap();

    backing
        .open("data", false)
        .unwrap()
        .write_at(0, b"changed!")
        .unwrap();
    assert_eq!(fs::read(outside.join("data")).unwrap(), b"original");
    assert_eq!(fs::read(moved.join("data")).unwrap(), b"changed!");
    backing.open("created", true).unwrap();
    backing.remove("remove-me").unwrap();
    backing.rename("rename-me", "renamed").unwrap();
    backing.create_dir_all("nested/child").unwrap();
    assert!(backing.exists("created").unwrap());
    assert!(!backing.exists("remove-me").unwrap());
    assert!(backing.list("").unwrap().contains(&"renamed".to_owned()));
    assert!(!outside.join("created").exists());
    assert!(outside.join("remove-me").exists());
    assert!(outside.join("rename-me").exists());
    assert!(!outside.join("renamed").exists());
    assert!(!outside.join("nested").exists());
    assert!(moved.join("nested/child").is_dir());
    assert!(backing.try_lock("volume.lock").is_err());
    backing.sync_dir("").unwrap();
    assert!(backing.free_bytes().unwrap().is_some());
    drop(lock);
}

#[test]
fn root_and_root_ancestors_must_not_be_symlinks() {
    let temp = tempfile::tempdir().unwrap();
    let outside = temp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    symlink(&outside, temp.path().join("link")).unwrap();
    assert!(FileBacking::new(temp.path().join("link")).is_err());
    assert!(FileBacking::new(temp.path().join("link/new-volume")).is_err());
    assert!(!outside.join("new-volume").exists());
}

#[test]
fn repeated_directory_lists_and_missing_nested_paths_are_consistent() {
    let temp = tempfile::tempdir().unwrap();
    let backing = FileBacking::new(temp.path()).unwrap();
    backing.create_dir_all("nested/child").unwrap();
    backing.open("nested/child/data", true).unwrap();
    assert_eq!(backing.list("nested/child").unwrap(), ["data"]);
    assert_eq!(backing.list("nested/child").unwrap(), ["data"]);
    assert!(!backing.exists("missing/child/data").unwrap());
}

#[test]
fn an_execute_only_ancestor_does_not_require_directory_listing_permission() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let ancestor = temp.path().join("private-ancestor");
    let root = ancestor.join("volume");
    fs::create_dir_all(&root).unwrap();
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o111)).unwrap();
    let result = FileBacking::new(&root);
    // Restore permissions before any assertion, including fixture cleanup.
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700)).unwrap();
    result.expect("known-path traversal needs search permission, not listing");
}
