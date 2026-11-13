//! Keep descriptor exhaustion in its own test binary: no other test in this
//! process can observe the temporary soft limit or compete for descriptors.
#![cfg(target_os = "linux")]

use std::fs::File;
use std::io;

use maki_backing::{Backing, RollbackBacking};

struct ExhaustedDescriptors {
    original: libc::rlimit,
    files: Vec<File>,
}

impl ExhaustedDescriptors {
    fn new() -> Self {
        let mut original = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes into the live, owned struct.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut original) },
            0
        );
        let lowered = libc::rlimit {
            rlim_cur: original.rlim_cur.min(128),
            rlim_max: original.rlim_max,
        };
        // SAFETY: this only lowers this isolated process's soft limit and
        // leaves its hard limit unchanged. Drop restores the original value.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lowered) }, 0);
        let mut exhausted = Self {
            original,
            files: Vec::new(),
        };
        loop {
            match File::open("/dev/null") {
                Ok(file) => exhausted.files.push(file),
                Err(error) => {
                    assert_eq!(error.raw_os_error(), Some(libc::EMFILE));
                    break;
                }
            }
        }
        exhausted
    }
}

impl Drop for ExhaustedDescriptors {
    fn drop(&mut self) {
        self.files.clear();
        // SAFETY: the original struct is still valid and the unchanged hard
        // limit permits restoring this process's original soft limit.
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &self.original) },
            0
        );
    }
}

#[test]
fn open_rollback_handles_resume_after_descriptor_exhaustion_but_not_anchor_changes() {
    // Explicit roots keep the witness on an independent filesystem even if
    // the build or test runner uses TMPDIR=/dev/shm.
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let witness = tempfile::tempdir_in("/dev/shm").unwrap();
    let backing = RollbackBacking::create(root.path(), witness.path(), 8 * 4096).unwrap();
    let file = backing.open("data", true).unwrap();
    file.write_at(0, b"old").unwrap();
    file.sync_data().unwrap();
    backing.sync_dir("").unwrap();

    let exhausted = ExhaustedDescriptors::new();
    let mut bytes = [0; 3];
    for error in [
        file.read_at(0, &mut bytes).unwrap_err(),
        file.write_at(0, b"bad").unwrap_err(),
        file.sync_data().unwrap_err(),
        backing.exists("data").unwrap_err(),
    ] {
        assert_eq!(error.raw_os_error(), Some(libc::EMFILE));
    }
    drop(exhausted);

    // All four failed operations must leave the same open session usable,
    // and none may have applied the failed write.
    file.read_at(0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"old");
    assert!(backing.exists("data").unwrap());
    file.write_at(0, b"new").unwrap();
    file.sync_data().unwrap();
    backing.sync_dir("").unwrap();
    drop((file, backing));

    let backing = RollbackBacking::open(root.path(), witness.path()).unwrap();
    let file = backing.open("data", false).unwrap();
    file.read_at(0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"new");

    // Missing authority is different from inability to read it. Once the
    // disappearance is observed, restoring its bytes cannot revive either
    // the parent backing or an already-open file handle.
    let anchor = witness.path().join("anchor");
    let published = std::fs::read(&anchor).unwrap();
    std::fs::remove_file(&anchor).unwrap();
    assert_eq!(
        backing.exists("data").unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    std::fs::write(&anchor, published).unwrap();
    assert!(file.read_at(0, &mut bytes).is_err());
    assert!(file.write_at(0, b"bad").is_err());
    assert!(file.sync_data().is_err());
    assert!(backing.exists("data").is_err());
}
