//! A file or directory a root process creates in a directory another user
//! owns is that user's. Giving an entry to another user needs root, so
//! these tests drive the creation path with an owner the running user may
//! give an entry to (itself) and with one it may not (another user, refused
//! unless root); the integration tests in `review_root_created_ownership.rs`
//! cover the root decision itself. Both file creation forms run: unnamed
//! (`O_TMPFILE`) and, for filesystems without it, under the final name.

use super::*;
use crate::FileOwner;
use std::fs;
use std::os::unix::fs::PermissionsExt;

const ACCESS: i32 = libc::O_RDWR | libc::O_NONBLOCK;

fn me() -> FileOwner {
    // SAFETY: getuid and getgid have no preconditions and cannot fail.
    unsafe {
        FileOwner {
            uid: libc::getuid(),
            gid: libc::getgid(),
        }
    }
}

fn running_as_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// The directory as `FileBacking` holds a parent: an `O_PATH` descriptor.
fn directory(path: &std::path::Path) -> File {
    // An absolute name ignores the descriptor it is resolved against.
    open_at(
        &File::open("/").unwrap(),
        &name(path.as_os_str()).unwrap(),
        libc::O_PATH | libc::O_DIRECTORY,
    )
    .unwrap()
}

fn owner_of(path: &std::path::Path) -> (u32, u32) {
    let metadata = fs::symlink_metadata(path).unwrap();
    (metadata.uid(), metadata.gid())
}

#[test]
fn only_root_creates_a_file_for_another_owner_of_its_directory() {
    let daemon = FileOwner {
        uid: 4242,
        gid: 4343,
    };
    let root_group = FileOwner { uid: 0, gid: 4343 };
    assert_eq!(new_entry_owner(0, daemon), Some(daemon));
    // A root-owned directory gets root's files, whatever its group.
    assert_eq!(new_entry_owner(0, root_group), None);
    // Nobody else can give a file away, and they need not.
    assert_eq!(new_entry_owner(4242, daemon), None);
    assert_eq!(new_entry_owner(4444, daemon), None);
}

#[test]
fn a_file_created_for_an_owner_is_given_away_synced_and_linked_once() {
    for unnamed in [true, false] {
        let temp = tempfile::tempdir().unwrap();
        let parent = directory(temp.path());
        let file = create_or_open_for(&parent, c"volume.lock", ACCESS, me(), unnamed).unwrap();
        file.try_lock().unwrap();
        let path = temp.path().join("volume.lock");
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert!(metadata.is_file(), "unnamed {unnamed}");
        assert_eq!(metadata.nlink(), 1, "unnamed {unnamed}");
        assert_eq!(metadata.mode() & 0o777, 0o600, "unnamed {unnamed}");
        assert_eq!(owner_of(&path), (me().uid, me().gid), "unnamed {unnamed}");
        // The descriptor is the named file.
        use std::os::unix::fs::FileExt;
        file.write_all_at(b"bytes", 0).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"bytes", "unnamed {unnamed}");
        // Nothing else was left in the directory.
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }
}

#[test]
fn an_unnamed_file_is_linked_either_way_once() {
    type Link = fn(&File, &File, &CStr) -> io::Result<()>;
    for (form, link) in [
        ("descriptor", link_descriptor as Link),
        ("proc", link_through_proc as Link),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let parent = directory(temp.path());
        let file = open_at(&parent, c".", libc::O_TMPFILE | libc::O_RDWR).unwrap();
        match link(&file, &parent, c"volume.lock") {
            // Before Linux 6.10, AT_EMPTY_PATH needs CAP_DAC_READ_SEARCH.
            Err(error) if form == "descriptor" && error.kind() == io::ErrorKind::NotFound => {
                eprintln!("an_unnamed_file_is_linked_either_way_once: {form}: skipped: {error}");
                continue;
            }
            linked => linked.unwrap(),
        }
        let metadata = fs::symlink_metadata(temp.path().join("volume.lock")).unwrap();
        assert_eq!(metadata.ino(), file.metadata().unwrap().ino(), "{form}");
        assert_eq!(metadata.nlink(), 1, "{form}");
        // A taken name is never replaced.
        let other = open_at(&parent, c".", libc::O_TMPFILE | libc::O_RDWR).unwrap();
        let error = link(&other, &parent, c"volume.lock").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "{form}");
        assert_eq!(
            fs::symlink_metadata(temp.path().join("volume.lock"))
                .unwrap()
                .ino(),
            metadata.ino(),
            "{form}"
        );
    }
}

#[test]
fn an_existing_entry_is_opened_as_it_is_never_given_away() {
    for unnamed in [true, false] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("superblock.a");
        fs::write(&path, b"existing").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let before = fs::metadata(&path).unwrap();
        let parent = directory(temp.path());
        // An owner the file must not be given to.
        let foreign = FileOwner {
            uid: 4242,
            gid: 4343,
        };
        let file = create_or_open_for(&parent, c"superblock.a", ACCESS, foreign, unnamed).unwrap();
        assert_eq!(file.metadata().unwrap().ino(), before.ino());
        assert_eq!(owner_of(&path), (before.uid(), before.gid()));
        assert_eq!(fs::read(&path).unwrap(), b"existing");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o640);
        // A name taken after the existence check is left to its creator.
        assert!(create_for(&parent, c"superblock.a", ACCESS, me(), unnamed)
            .unwrap()
            .is_none());
        assert_eq!(owner_of(&path), (before.uid(), before.gid()));
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }
}

#[test]
fn a_refused_owner_change_leaves_no_entry_behind() {
    if running_as_root() {
        // Root can give the file away; the integration test drops CAP_CHOWN.
        eprintln!(
            "a_refused_owner_change_leaves_no_entry_behind: skipped: root may give files away"
        );
        return;
    }
    let other = FileOwner {
        uid: 4242,
        gid: 4343,
    };
    for unnamed in [true, false] {
        let temp = tempfile::tempdir().unwrap();
        let parent = directory(temp.path());
        let error =
            create_or_open_for(&parent, c"volume.lock", ACCESS, other, unnamed).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        assert!(error.to_string().contains("uid 4242, gid 4343"), "{error}");
        assert_eq!(
            fs::read_dir(temp.path()).unwrap().count(),
            0,
            "unnamed {unnamed}"
        );
    }
}

#[test]
fn a_new_directory_is_given_away_only_while_it_is_empty() {
    let temp = tempfile::tempdir().unwrap();
    let parent = directory(temp.path());
    fs::create_dir(temp.path().join("journal")).unwrap();
    give_new_directory(&parent, c"journal", me()).unwrap();
    assert_eq!(owner_of(&temp.path().join("journal")), (me().uid, me().gid));
    // A directory swapped in under the name, holding an entry, is refused.
    fs::create_dir(temp.path().join("data")).unwrap();
    fs::write(temp.path().join("data/shard-0"), b"").unwrap();
    let before = owner_of(&temp.path().join("data"));
    let error = give_new_directory(&parent, c"data", me()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
    assert_eq!(owner_of(&temp.path().join("data")), before);
    assert!(temp.path().join("data/shard-0").exists());
}

#[test]
fn a_refused_directory_owner_change_removes_the_directory() {
    if running_as_root() {
        // Root can give the directory away; the integration test drops
        // CAP_CHOWN.
        eprintln!(
            "a_refused_directory_owner_change_removes_the_directory: skipped: root may give \
             directories away"
        );
        return;
    }
    let other = FileOwner {
        uid: 4242,
        gid: 4343,
    };
    let temp = tempfile::tempdir().unwrap();
    let parent = directory(temp.path());
    fs::create_dir(temp.path().join("journal")).unwrap();
    let error = give_new_directory(&parent, c"journal", other).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
    assert!(!temp.path().join("journal").exists());
}

#[test]
fn directory_owner_describes_the_named_directory() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("journal")).unwrap();
    let backing = FileBacking::new(temp.path()).unwrap();
    for dir in ["", "journal"] {
        let owner = backing.directory_owner(dir).unwrap().unwrap();
        assert_eq!(
            (owner.uid, owner.gid),
            owner_of(&temp.path().join(dir)),
            "{dir:?}"
        );
    }
    assert_eq!(
        backing.directory_owner("missing").unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}
