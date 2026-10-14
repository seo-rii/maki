//! TEST-004: `CrashableBacking` must not offer crash outcomes a POSIX
//! filesystem cannot produce, nor hide ones it can; durability tests
//! are only as strong as this model.
//!
//! - A name and an inode are different things. A durable directory entry
//!   whose data was never synced survives a power loss as an empty (or
//!   partial) file; the model deleted it. A file re-created at a removed
//!   name is a new inode and never shows the unlinked inode's bytes.
//! - `rename` over an existing file is the atomic-replace idiom (the witness
//!   anchor and state files use it): the target is always the old or the new
//!   file, never absent, the moved inode keeps the data already synced in it,
//!   and after the directory sync the target is the new file.

use rand::rngs::StdRng;
use rand::SeedableRng;

use maki_backing::Backing;
use maki_test_support::crash_backing::CrashableBacking;

fn write_synced(backing: &CrashableBacking, path: &str, data: &[u8]) {
    let file = backing.open(path, true).unwrap();
    file.set_len(0).unwrap();
    file.write_at(0, data).unwrap();
    file.sync_data().unwrap();
}

fn read(backing: &CrashableBacking, path: &str) -> Vec<u8> {
    let file = backing.open(path, false).unwrap();
    let mut bytes = vec![0; file.len().unwrap() as usize];
    file.read_at(0, &mut bytes).unwrap();
    bytes
}

/// Every outcome of `crash` over many seeds, plus `crash_all_lost`.
fn outcomes(setup: impl Fn() -> CrashableBacking, path: &str) -> Vec<Option<Vec<u8>>> {
    let mut seen = Vec::new();
    for seed in 0..200 {
        let backing = setup();
        backing.crash(&mut StdRng::seed_from_u64(seed));
        seen.push(backing.exists(path).unwrap().then(|| read(&backing, path)));
    }
    let backing = setup();
    backing.crash_all_lost();
    seen.push(backing.exists(path).unwrap().then(|| read(&backing, path)));
    seen
}

#[test]
fn a_durable_entry_without_synced_data_survives_as_a_file() {
    let backing = CrashableBacking::new();
    let file = backing.open("f", true).unwrap();
    backing.sync_dir("").unwrap();
    file.write_at(0, b"never synced").unwrap();
    drop(file);
    backing.crash_all_lost();
    assert!(
        backing.exists("f").unwrap(),
        "a durable directory entry vanished in the crash"
    );
    assert_eq!(read(&backing, "f"), b"");
}

#[test]
fn a_recreated_file_never_shows_the_unlinked_inodes_bytes() {
    let setup = || {
        let backing = CrashableBacking::new();
        write_synced(&backing, "f", b"OLD");
        backing.sync_dir("").unwrap();
        backing.remove("f").unwrap();
        let file = backing.open("f", true).unwrap();
        backing.sync_dir("").unwrap();
        file.write_at(0, b"NEW").unwrap();
        backing
    };
    for outcome in outcomes(setup, "f") {
        let bytes = outcome.expect("a durable directory entry vanished");
        assert!(
            bytes.is_empty() || bytes == b"NEW",
            "the re-created inode showed {:?}",
            String::from_utf8_lossy(&bytes)
        );
    }
}

#[test]
fn a_lost_recreation_restores_the_unlinked_file() {
    let setup = || {
        let backing = CrashableBacking::new();
        write_synced(&backing, "f", b"OLD");
        backing.sync_dir("").unwrap();
        backing.remove("f").unwrap();
        write_synced(&backing, "f", b"NEW");
        backing
    };
    let seen = outcomes(setup, "f");
    for outcome in &seen {
        let bytes = outcome.as_ref().expect("neither the old nor the new file");
        assert!(bytes == b"OLD" || bytes == b"NEW", "{bytes:?}");
    }
    assert_eq!(
        seen.last().unwrap().as_deref(),
        Some(&b"OLD"[..]),
        "losing every unsynced directory change must restore the old file"
    );
}

#[test]
fn an_atomic_replace_is_the_new_file_after_the_directory_sync() {
    let setup = || {
        let backing = CrashableBacking::new();
        write_synced(&backing, "f", b"OLD");
        backing.sync_dir("").unwrap();
        write_synced(&backing, "f.tmp", b"NEW");
        backing.rename("f.tmp", "f").unwrap();
        backing.sync_dir("").unwrap();
        backing
    };
    for outcome in outcomes(setup, "f") {
        assert_eq!(outcome.as_deref(), Some(&b"NEW"[..]));
    }
    let backing = setup();
    backing.crash_all_lost();
    assert!(!backing.exists("f.tmp").unwrap());
}

#[test]
fn an_unsynced_replace_is_atomic_and_never_leaves_the_target_absent() {
    let setup = || {
        let backing = CrashableBacking::new();
        write_synced(&backing, "f", b"OLD");
        backing.sync_dir("").unwrap();
        write_synced(&backing, "f.tmp", b"NEW");
        backing.sync_dir("").unwrap();
        backing.rename("f.tmp", "f").unwrap();
        backing
    };
    let mut new = 0;
    for seed in 0..200 {
        let backing = setup();
        backing.crash(&mut StdRng::seed_from_u64(seed));
        let target = read(&backing, "f");
        let source = backing.exists("f.tmp").unwrap();
        match target.as_slice() {
            b"NEW" => {
                new += 1;
                assert!(!source, "the rename both happened and did not");
            }
            b"OLD" => assert_eq!(read(&backing, "f.tmp"), b"NEW"),
            other => panic!("the target is neither old nor new: {other:?}"),
        }
    }
    assert!(new > 0, "a crash after a rename never kept it");
    let backing = setup();
    backing.crash_all_lost();
    assert_eq!(read(&backing, "f"), b"OLD");
    assert_eq!(read(&backing, "f.tmp"), b"NEW");
}
