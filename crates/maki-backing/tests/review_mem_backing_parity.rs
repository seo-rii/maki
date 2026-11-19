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
