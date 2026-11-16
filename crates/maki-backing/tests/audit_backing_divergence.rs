//! Audit: `MemBacking` (and the default trait methods the in-memory backings
//! use) accept operations a real Linux `FileBacking` refuses, so a test on
//! the in-memory backing can pass for code that fails on a real filesystem.

use std::io;

use maki_backing::{Backing, FileBacking, MemBacking};

/// POSIX `open(O_CREAT)` needs an existing parent directory (ENOENT).
#[test]
fn opening_a_file_in_a_missing_directory_fails_on_both_backings() {
    let dir = tempfile::tempdir().unwrap();
    let real = FileBacking::new(dir.path()).unwrap();
    let real_error = real.open("never-created/seg-1", true).err().unwrap();
    assert_eq!(real_error.kind(), io::ErrorKind::NotFound);

    let mem = MemBacking::new();
    let mem_result = mem.open("never-created/seg-1", true);
    assert!(
        mem_result.is_err(),
        "MemBacking created a file in a directory that does not exist"
    );
}

/// `opendir` of a missing directory is ENOENT, not an empty listing.
#[test]
fn listing_a_missing_directory_fails_on_both_backings() {
    let dir = tempfile::tempdir().unwrap();
    let real = FileBacking::new(dir.path()).unwrap();
    assert_eq!(
        real.list("missing").unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    let mem = MemBacking::new();
    let listed = mem.list("missing");
    assert!(
        listed.is_err(),
        "MemBacking listed a missing directory as {listed:?}"
    );
}

/// A name is either a directory or a file (EISDIR on open of a directory).
#[test]
fn a_directory_name_cannot_also_be_opened_as_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let real = FileBacking::new(dir.path()).unwrap();
    real.create_dir_all("journal").unwrap();
    assert!(real.open("journal", true).is_err());

    let mem = MemBacking::new();
    mem.create_dir_all("journal").unwrap();
    assert!(
        mem.open("journal", true).is_err(),
        "MemBacking opened a directory name as a regular file"
    );
}

/// `fallocate(2)` rejects `len == 0` with EINVAL; the in-memory backings'
/// default `allocate_range` treats it as a no-op.
#[test]
fn zero_length_allocation_behaves_the_same_on_both_backings() {
    let dir = tempfile::tempdir().unwrap();
    let real = FileBacking::new(dir.path()).unwrap();
    let real_result = real.open("f", true).unwrap().allocate_range(0, 0);
    let mem = MemBacking::new();
    let mem_result = mem.open("f", true).unwrap().allocate_range(0, 0);
    assert_eq!(
        real_result.is_ok(),
        mem_result.is_ok(),
        "real {real_result:?} vs in-memory {mem_result:?}"
    );
}
