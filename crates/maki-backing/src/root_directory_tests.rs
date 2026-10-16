//! Root-name durability is outside Backing::sync_dir("")'s namespace.
//! These tests use actual directories/fsync and inject only barrier failures.

use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

fn path(file: &File) -> PathBuf {
    fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap()
}

#[test]
fn new_nested_root_syncs_every_created_name_bottom_up() {
    let temp = tempfile::tempdir().unwrap();
    let parent = temp.path().join("new-parent");
    let root = parent.join("volume");
    let mut synced = Vec::new();
    Directory::new_with_sync(&root, |file| {
        synced.push(path(file));
        file.sync_all()
    })
    .unwrap();
    assert_eq!(
        &synced[..3],
        [root.clone(), parent.clone(), temp.path().to_path_buf()]
    );
    assert!(root.is_dir());
}

#[test]
fn existing_root_retries_failed_parent_barriers_and_preserves_eio() {
    let temp = tempfile::tempdir().unwrap();
    let parent = temp.path().join("new-parent");
    let root = parent.join("volume");
    for _ in 0..2 {
        let error = Directory::new_with_sync(&root, |file| {
            if path(file) == temp.path() {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            file.sync_all()
        })
        .err()
        .expect("an existing entry does not discharge its failed parent sync");
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert!(root.is_dir());
    }
    let mut synced = Vec::new();
    Directory::new_with_sync(&root, |file| {
        synced.push(path(file));
        file.sync_all()
    })
    .unwrap();
    assert!(synced.contains(&parent));
    assert!(synced.contains(&temp.path().to_path_buf()));
}

#[test]
fn concurrent_opener_syncs_a_name_before_its_creator_finishes() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("volume");
    let watched_parent = temp.path().to_path_buf();
    let first_root = root.clone();
    let (waiting, arrived) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    let creator = std::thread::spawn(move || {
        Directory::new_with_sync(&first_root, |file| {
            if path(file) == watched_parent {
                waiting.send(()).unwrap();
                released.recv_timeout(Duration::from_secs(10)).unwrap();
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            file.sync_all()
        })
    });
    arrived.recv_timeout(Duration::from_secs(10)).unwrap();
    let mut parent_synced = false;
    let second = Directory::new_with_sync(&root, |file| {
        parent_synced |= path(file) == temp.path();
        file.sync_all()
    });
    release.send(()).unwrap();
    assert_eq!(
        creator.join().unwrap().err().unwrap().raw_os_error(),
        Some(libc::EIO)
    );
    second.unwrap();
    assert!(
        parent_synced,
        "observing another creator's entry still requires its parent barrier"
    );
}

#[test]
fn a_writable_descendant_below_a_search_only_ancestor_can_be_created() {
    let temp = tempfile::tempdir().unwrap();
    let ancestor = temp.path().join("search-only");
    let parent = ancestor.join("writable");
    fs::create_dir_all(&parent).unwrap();
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o111)).unwrap();
    let result = Directory::new(&parent.join("volume"));
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700)).unwrap();
    result.expect("existing ancestors need only search permission");
}

#[test]
fn unreadable_parent_is_refused_before_creating_a_child() {
    // DAC cannot deny a root process with CAP_DAC_READ_SEARCH. The ordinary
    // Linux CI user exercises the actual permission error, without setuid.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let parent = temp.path().join("write-search-only");
    let root = parent.join("volume");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o311)).unwrap();
    let result = Directory::new(&root);
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        result.err().unwrap().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(!root.exists(), "failed sync preparation must precede mkdir");
}

#[test]
fn a_different_filesystem_discards_ancestor_syncs() {
    let temp = tempfile::tempdir_in("/dev/shm").unwrap();
    let selected_device = temp.path().metadata().unwrap().dev();
    if selected_device == fs::metadata("/").unwrap().dev() {
        return;
    }
    Directory::new_with_sync(&temp.path().join("volume"), |file| {
        assert_eq!(file.metadata()?.dev(), selected_device);
        file.sync_all()
    })
    .unwrap();
}

#[test]
fn readonly_existing_filesystem_does_not_require_a_sync_barrier() {
    let root = File::open("/sys").unwrap();
    if writable_directory(&root).unwrap() {
        return;
    }
    Directory::new_with_sync(Path::new("/sys"), |_| {
        panic!("read-only existing filesystem must not require directory fsync")
    })
    .unwrap();
}
