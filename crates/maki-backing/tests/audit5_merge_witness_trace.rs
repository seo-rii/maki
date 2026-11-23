//! Round-5 audit probe (merge-interactions): drives the local witness and a
//! root-created lock through the public API so the syscall order of #344's
//! `write_temporary` (remove, create, write, sync, rename, directory sync)
//! and of `FileBacking`'s unnamed creation can be read from `strace`.
//!
//! Without `AUDIT5_WITNESS_DIR` the test only checks the invariants that a
//! process can observe itself: a publication never leaves `anchor.next`
//! behind, the anchor is always a single-link regular file, and a leftover
//! or planted `anchor.next` (file, of this user) never survives as the
//! published record's inode.

#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use maki_backing::witness::FileWitness;
use maki_backing::{Backing, FileBacking};

const IDENTITY: [u8; 16] = *b"audit5-identity!";

fn exercise(dir: &Path) {
    let mut witness = FileWitness::create(dir, IDENTITY, [1; 32]).unwrap();
    witness.advance([2; 32]).unwrap();
    drop(witness);
    // A leftover temporary record, as a failed publication leaves one, with
    // a writable descriptor of it kept open (which also keeps its inode
    // number from being reused, so the comparison below means something).
    fs::write(dir.join("anchor.next"), b"left behind").unwrap();
    let held = fs::OpenOptions::new()
        .write(true)
        .open(dir.join("anchor.next"))
        .unwrap();
    let planted = held.metadata().unwrap().ino();
    let mut witness = FileWitness::open(dir).unwrap();
    let anchor = fs::metadata(dir.join("anchor")).unwrap();
    assert_ne!(
        anchor.ino(),
        planted,
        "a leftover anchor.next was published"
    );
    assert_eq!(anchor.nlink(), 1);
    assert_eq!(
        held.metadata().unwrap().nlink(),
        0,
        "the leftover was not removed"
    );
    assert!(!dir.join("anchor.next").exists());
    // The kept descriptor cannot rewrite the published record.
    let published = fs::read(dir.join("anchor")).unwrap();
    {
        use std::os::unix::fs::FileExt;
        held.write_all_at(&[0xAA; 104], 0).unwrap();
    }
    assert_eq!(fs::read(dir.join("anchor")).unwrap(), published);
    witness.verify_current().unwrap();
    witness.advance([3; 32]).unwrap();
    assert_eq!(witness.anchor().generation, 2);
    assert!(!dir.join("anchor.next").exists());
    drop(witness);
    // A lock a root process creates below a directory another user owns.
    let backing = FileBacking::new(dir).unwrap();
    drop(backing.try_lock("audit5.lock").unwrap());
    assert_eq!(fs::metadata(dir.join("audit5.lock")).unwrap().nlink(), 1);
}

#[test]
fn witness_publication_and_root_creation_trace() {
    match std::env::var_os("AUDIT5_WITNESS_DIR") {
        Some(dir) => exercise(Path::new(&dir)),
        None => {
            let dir = tempfile::tempdir().unwrap();
            exercise(dir.path());
        }
    }
}
