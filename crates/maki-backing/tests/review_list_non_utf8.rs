//! `FileBacking::list` refuses a directory holding an entry whose name is
//! not UTF-8: a caller that accounts for every entry must not miss one, and
//! a lossy name could open a different entry. Scans that look only for the
//! volume's own (ASCII) names use `list_skipping_non_utf8`, which leaves
//! such names out and returns every other name exactly, wherever the
//! entries fall in the directory's order.
#![cfg(target_os = "linux")]

#[path = "support/other_filesystem.rs"]
mod other_filesystem;

use std::ffi::OsStr;
use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use maki_backing::{Backing, FileBacking, RollbackBacking};

fn plant(dir: &Path, name: &[u8]) {
    std::fs::write(dir.join(OsStr::from_bytes(name)), b"stray").unwrap();
}

#[test]
fn skipping_listing_returns_each_utf8_name_exactly_and_no_other() {
    let root = tempfile::tempdir().unwrap();
    let backing = FileBacking::new(root.path()).unwrap();
    backing.create_dir_all("data").unwrap();
    // The literal replacement character a lossy conversion of the planted
    // `photo-\x80` would produce, beside it.
    let mut expected = vec!["photo-\u{FFFD}".to_string(), "café".to_string()];
    expected.extend((0..32).map(|i| format!("shard-{i:08x}.dat")));
    for name in &expected {
        backing.open(&format!("data/{name}"), true).unwrap();
    }
    backing.create_dir_all("data/nested").unwrap();
    expected.push("nested".to_string());
    expected.sort();
    let data = root.path().join("data");
    plant(&data, b"photo-\x80");
    plant(&data, b"caf\xe9");
    for i in 0..32u8 {
        plant(&data, &[b's', b'-', b'a' + i % 26, b'0' + i / 26, 0xFF]);
    }
    assert_eq!(backing.list_skipping_non_utf8("data").unwrap(), expected);
    assert_eq!(
        backing.list("data").unwrap_err().kind(),
        ErrorKind::InvalidData
    );
    // Each name returned resolves to an existing entry: none is a lossy
    // stand-in for a name that is not UTF-8.
    for name in backing.list_skipping_non_utf8("data").unwrap() {
        assert!(backing.exists(&format!("data/{name}")).unwrap(), "{name}");
    }
}

/// Control: rollback enrollment proves the backing root empty with `list`,
/// so an entry whose name is not UTF-8 still refuses it.
#[test]
fn rollback_enrollment_still_refuses_a_root_holding_a_non_utf8_entry() {
    let root = tempfile::tempdir().unwrap();
    let Some(witness) = other_filesystem::tempdir(root.path()) else {
        return;
    };
    plant(root.path(), b"caf\xe9.bak");
    let error = RollbackBacking::create(root.path(), witness.path(), 64 * 4096)
        .err()
        .expect("a backing root holding an entry was enrolled");
    assert_eq!(error.kind(), ErrorKind::InvalidData, "{error}");
    assert_eq!(
        std::fs::read(root.path().join(OsStr::from_bytes(b"caf\xe9.bak"))).unwrap(),
        b"stray"
    );
    assert_eq!(std::fs::read_dir(witness.path()).unwrap().count(), 0);
}
