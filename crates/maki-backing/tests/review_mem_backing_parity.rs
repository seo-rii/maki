//! Regression tests: `MemBacking` stands in for a real filesystem in unit
//! tests, so it must refuse what `FileBacking` refuses. A namespace looser
//! than POSIX lets code that opens a file in a directory it never created,
//! or lists a directory that does not exist, pass in memory and fail on a
//! real volume. The namespace table is shared with maki-test-support,
//! which runs it against `CrashableBacking`.

#[path = "common/namespace_parity.rs"]
mod namespace_parity;

use maki_backing::{Backing, MemBacking};
use namespace_parity::check;

#[test]
fn mem_backing_namespace_follows_posix_path_rules() {
    check("MemBacking", || Box::new(MemBacking::new()));
}

/// The table's expectations are what Linux returns through `FileBacking`.
#[cfg(target_os = "linux")]
#[test]
fn file_backing_namespace_matches_the_expectations() {
    let roots = std::cell::RefCell::new(Vec::new());
    check("FileBacking", || {
        let root = tempfile::tempdir().unwrap();
        let backing = maki_backing::FileBacking::new(root.path()).unwrap();
        roots.borrow_mut().push(root);
        Box::new(backing)
    });
}

fn check_lock_identity(backing: &dyn Backing) {
    let original = backing.try_lock("lock").unwrap();
    let displaced = backing.try_lock("renamed").unwrap();
    backing.rename("lock", "renamed").unwrap();
    let replacement = backing.try_lock("lock").unwrap();

    drop(displaced);
    assert_eq!(
        backing.try_lock("renamed").err().unwrap().kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop(original);
    let renamed = backing.try_lock("renamed").unwrap();
    assert_eq!(
        backing.try_lock("lock").err().unwrap().kind(),
        std::io::ErrorKind::WouldBlock
    );

    backing.remove("lock").unwrap();
    let recreated = backing.try_lock("lock").unwrap();
    drop(replacement);
    assert_eq!(
        backing.try_lock("lock").err().unwrap().kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop(recreated);
    drop(renamed);
    backing.try_lock("lock").unwrap();
}

#[test]
fn memory_file_locks_follow_the_file_across_rename_and_unlink() {
    check_lock_identity(&MemBacking::new());
}

#[cfg(target_os = "linux")]
#[test]
fn linux_file_locks_follow_the_file_across_rename_and_unlink() {
    let root = tempfile::tempdir().unwrap();
    check_lock_identity(&maki_backing::FileBacking::new(root.path()).unwrap());
}

#[cfg(target_os = "linux")]
#[test]
fn rollback_file_locks_follow_the_file_across_rename_and_unlink() {
    let root = tempfile::tempdir().unwrap();
    let witness = tempfile::tempdir_in("/dev/shm").unwrap();
    let backing =
        maki_backing::RollbackBacking::create(root.path(), witness.path(), 64 * 4096).unwrap();
    check_lock_identity(&backing);
}

#[cfg(target_os = "linux")]
#[test]
fn rollback_file_lock_keeps_unlinked_pages_until_release() {
    let root = tempfile::tempdir().unwrap();
    let witness = tempfile::tempdir_in("/dev/shm").unwrap();
    let backing =
        maki_backing::RollbackBacking::create(root.path(), witness.path(), 64 * 4096).unwrap();
    let file = backing.open("lock", true).unwrap();
    file.write_at(0, &[7; 4096]).unwrap();
    file.sync_data().unwrap();
    drop(file);
    backing.sync_dir("").unwrap();
    let held = backing.try_lock("lock").unwrap();
    let free = backing.free_bytes().unwrap().unwrap();
    backing.remove("lock").unwrap();
    backing.sync_dir("").unwrap();
    assert_eq!(backing.free_bytes().unwrap(), Some(free));
    drop(held);
    assert_eq!(backing.free_bytes().unwrap(), Some(free + 4096));
}

// ---------- zero-length allocation ----------

/// Every backing must agree on `allocate_range(_, 0)`: it reserves nothing
/// and succeeds without changing the file, wherever the offset lies. Linux
/// `fallocate(2)` rejects `len == 0` with EINVAL, the in-memory default
/// extended the file to the offset, and `RollbackBacking` treats it as a
/// no-op, so the same call failed, grew the file or did nothing depending
/// on the backing.
fn assert_zero_length_allocation_is_a_no_op(name: &str, backing: &dyn Backing) {
    let file = backing.open("f", true).unwrap();
    for (offset, len_before) in [(0, 0), (4096, 0)] {
        file.allocate_range(offset, 0)
            .unwrap_or_else(|error| panic!("{name}: allocate_range({offset}, 0) failed: {error}"));
        assert_eq!(
            file.len().unwrap(),
            len_before,
            "{name}: allocate_range({offset}, 0) changed the length"
        );
    }
    file.write_at(0, &[7; 100]).unwrap();
    file.allocate_range(8192, 0).unwrap();
    assert_eq!(file.len().unwrap(), 100, "{name}: grew past its data");
}

#[test]
fn zero_length_allocation_is_a_no_op_on_every_backing() {
    assert_zero_length_allocation_is_a_no_op("MemBacking", &MemBacking::new());
    let root = tempfile::tempdir().unwrap();
    assert_zero_length_allocation_is_a_no_op(
        "FileBacking",
        &maki_backing::FileBacking::new(root.path()).unwrap(),
    );
    #[cfg(target_os = "linux")]
    {
        let root = tempfile::tempdir().unwrap();
        let witness = tempfile::tempdir_in("/dev/shm").unwrap();
        assert_zero_length_allocation_is_a_no_op(
            "RollbackBacking",
            &maki_backing::RollbackBacking::create(root.path(), witness.path(), 64 * 4096).unwrap(),
        );
    }
}

#[test]
fn empty_positional_io_past_eof_is_a_no_op() {
    let backing = MemBacking::new();
    let file = backing.open("empty", true).unwrap();
    file.write_at(16, &[]).unwrap();
    assert_eq!(file.len().unwrap(), 0);
    file.read_at(32, &mut []).unwrap();
}

#[test]
fn short_allocation_preserves_concurrent_longer_writes() {
    use std::sync::Barrier;

    let backing = MemBacking::new();
    let reserving = backing.open("shared", true).unwrap();
    let writing = backing.open("shared", false).unwrap();
    let start = Barrier::new(3);
    let finish = Barrier::new(3);
    const ROUNDS: usize = 8192;
    let mut lost = 0;
    std::thread::scope(|threads| {
        threads.spawn(|| {
            for _ in 0..ROUNDS {
                start.wait();
                reserving.allocate_range(0, 4).unwrap();
                finish.wait();
            }
        });
        threads.spawn(|| {
            for _ in 0..ROUNDS {
                start.wait();
                writing.write_at(8, b"written").unwrap();
                finish.wait();
            }
        });
        for _ in 0..ROUNDS {
            writing.set_len(0).unwrap();
            start.wait();
            finish.wait();
            let mut bytes = [0; 7];
            if writing.read_at(8, &mut bytes).is_err() || bytes != *b"written" {
                lost += 1;
            }
        }
    });
    assert_eq!(
        lost, 0,
        "a successful allocation truncated a concurrent write"
    );
}

#[cfg(unix)]
#[test]
fn filesystem_listing_refuses_names_that_cannot_round_trip() {
    use std::os::unix::ffi::OsStrExt;
    let dir = tempfile::tempdir().unwrap();
    let backing = maki_backing::FileBacking::new(dir.path()).unwrap();
    let valid = "photo-�";
    backing.open(valid, true).unwrap();
    assert_eq!(backing.list("").unwrap(), [valid]);
    let raw = std::ffi::OsStr::from_bytes(b"photo-\x80");
    std::fs::write(dir.path().join(raw), b"x").unwrap();
    assert_eq!(
        backing.list("").unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
}
