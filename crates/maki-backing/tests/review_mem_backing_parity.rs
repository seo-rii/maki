//! Regression tests: `MemBacking` stands in for a real filesystem in unit
//! tests, so it must refuse what `FileBacking` refuses. A namespace looser
//! than POSIX lets code that opens a file in a directory it never created,
//! or lists a directory that does not exist, pass in memory and fail on a
//! real volume.

use std::io;

use maki_backing::{Backing, MemBacking};

/// What an operation returned: its value rendered, or the error kind.
type Outcome = Result<String, io::ErrorKind>;

fn done<T>(result: io::Result<T>) -> Outcome {
    result
        .map(|_| "ok".to_string())
        .map_err(|error| error.kind())
}

fn value<T: std::fmt::Debug>(result: io::Result<T>) -> Outcome {
    result
        .map(|value| format!("{value:?}"))
        .map_err(|error| error.kind())
}

/// The namespace every case starts from: a directory `dir` holding the
/// file `dir/inner`, and a file `file` at the root.
fn prepare(backing: &dyn Backing) {
    backing.create_dir_all("dir").unwrap();
    backing.open("dir/inner", true).unwrap();
    backing.open("file", true).unwrap();
}

type Case = (&'static str, Outcome, fn(&dyn Backing) -> Outcome);

fn cases() -> Vec<Case> {
    use io::ErrorKind::{IsADirectory, NotADirectory, NotFound};
    vec![
        // Controls: what the prepared namespace does hold.
        ("open an existing file", Ok("ok".into()), |b| {
            done(b.open("dir/inner", false))
        }),
        ("list a directory", Ok(r#"["inner"]"#.into()), |b| {
            value(b.list("dir"))
        }),
        ("exists for a directory", Ok("true".into()), |b| {
            value(b.exists("dir"))
        }),
        ("rename within a directory", Ok("ok".into()), |b| {
            done(b.rename("dir/inner", "dir/renamed"))
        }),
        // A parent that does not exist (ENOENT).
        ("create a file in a missing directory", Err(NotFound), |b| {
            done(b.open("missing/f", true))
        }),
        ("exists in a missing directory", Ok("false".into()), |b| {
            value(b.exists("missing/f"))
        }),
        ("remove in a missing directory", Err(NotFound), |b| {
            done(b.remove("missing/f"))
        }),
        ("rename into a missing directory", Err(NotFound), |b| {
            done(b.rename("file", "missing/f"))
        }),
        ("rename out of a missing directory", Err(NotFound), |b| {
            done(b.rename("missing/f", "g"))
        }),
        ("list a missing directory", Err(NotFound), |b| {
            done(b.list("missing"))
        }),
        ("sync a missing directory", Err(NotFound), |b| {
            done(b.sync_dir("missing"))
        }),
        ("lock in a missing directory", Err(NotFound), |b| {
            done(b.try_lock("missing/lock"))
        }),
        // A parent that is a regular file (ENOTDIR).
        ("create a file below a file", Err(NotADirectory), |b| {
            done(b.open("file/f", true))
        }),
        ("exists below a file", Err(NotADirectory), |b| {
            done(b.exists("file/f"))
        }),
        ("create a directory below a file", Err(NotADirectory), |b| {
            done(b.create_dir_all("file/sub"))
        }),
        ("list a file", Err(NotADirectory), |b| done(b.list("file"))),
        ("sync a file as a directory", Err(NotADirectory), |b| {
            done(b.sync_dir("file"))
        }),
        // A name that is a directory (EISDIR).
        ("create a file over a directory", Err(IsADirectory), |b| {
            done(b.open("dir", true))
        }),
        ("open a directory as a file", Err(IsADirectory), |b| {
            done(b.open("dir", false))
        }),
        ("rename a file over a directory", Err(IsADirectory), |b| {
            done(b.rename("file", "dir"))
        }),
        ("lock a directory", Err(IsADirectory), |b| {
            done(b.try_lock("dir"))
        }),
    ]
}

fn check(name: &str, fresh: impl Fn() -> Box<dyn Backing>) {
    let mut mismatches = Vec::new();
    for (case, expected, operation) in cases() {
        let backing = fresh();
        prepare(backing.as_ref());
        let actual = operation(backing.as_ref());
        if actual != expected {
            mismatches.push(format!("{case}: expected {expected:?}, got {actual:?}"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{name} namespace differs from POSIX:\n{}",
        mismatches.join("\n")
    );
}

#[test]
fn mem_backing_namespace_follows_posix_path_rules() {
    check("MemBacking", || Box::new(MemBacking::new()));
}

/// The expectations above are what Linux returns through `FileBacking`.
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
