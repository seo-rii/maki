//! A temporary directory on a filesystem other than a given path's.
//!
//! A rollback-protected backing refuses a witness on the filesystem of its
//! backing tree. Fixtures that took `/dev/shm` for that second filesystem
//! failed where it does not exist, and where `TMPDIR` is itself on it.
//! [`tempdir`] makes its directory in the first of `/dev/shm`,
//! `/run/user/<uid>`, `/var/tmp`, `/tmp`, `TMPDIR` and `/run` whose device
//! differs from that of the path it is given. With none, it prints that the
//! calling test is skipped and why, and returns `None`; the test returns.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

fn candidates() -> Vec<PathBuf> {
    let mut candidates = vec![PathBuf::from("/dev/shm")];
    // `/proc/self` belongs to the effective user.
    if let Ok(process) = std::fs::metadata("/proc/self") {
        candidates.push(format!("/run/user/{}", process.uid()).into());
    }
    for candidate in [
        "/var/tmp".into(),
        "/tmp".into(),
        std::env::temp_dir(),
        "/run".into(),
    ] {
        if !candidates.contains(&candidate) {
            candidates.push(candidate);
        }
    }
    candidates
}

/// Why some user cannot reach `directory`, or `None`.
fn unreachable(directory: &Path) -> Option<String> {
    directory
        .ancestors()
        .find_map(|ancestor| match std::fs::metadata(ancestor) {
            Ok(metadata) if metadata.permissions().mode() & 0o001 != 0 => None,
            Ok(metadata) => Some(format!(
                "{} has mode {:04o}",
                ancestor.display(),
                metadata.permissions().mode() & 0o7777
            )),
            Err(error) => Some(format!("{}: {error}", ancestor.display())),
        })
}

fn make(reference: &Path, reachable: bool) -> Option<tempfile::TempDir> {
    let device = std::fs::metadata(reference)
        .unwrap_or_else(|error| panic!("{}: {error}", reference.display()))
        .dev();
    let mut refused = Vec::new();
    for candidate in candidates() {
        let made = std::fs::canonicalize(&candidate)
            .and_then(|base| Ok((std::fs::metadata(&base)?.dev(), base)))
            .map_err(|error| error.to_string())
            .and_then(|(found, base)| {
                if found == device {
                    return Err(format!("on the filesystem of {}", reference.display()));
                }
                if let Some(reason) = unreachable(&base).filter(|_| reachable) {
                    return Err(reason);
                }
                let directory = tempfile::tempdir_in(base).map_err(|error| error.to_string())?;
                // Whatever the umask: `set_permissions` is not subject to it.
                std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                    .map_err(|error| error.to_string())?;
                Ok(directory)
            });
        match made {
            Ok(directory) => return Some(directory),
            Err(reason) => refused.push(format!("{}: {reason}", candidate.display())),
        }
    }
    eprintln!(
        "{}: skipped: no temporary directory on a filesystem other than that of {} ({})",
        std::thread::current().name().unwrap_or("test"),
        reference.display(),
        refused.join("; ")
    );
    None
}

/// A fresh `0700` directory on a filesystem other than `reference`'s, or
/// `None` after printing why the test is skipped.
#[allow(dead_code)] // not every test target uses both
pub fn tempdir(reference: &Path) -> Option<tempfile::TempDir> {
    make(reference, false)
}

/// [`tempdir`] where every user may search down from `/`, for a fixture a
/// command run as another user opens.
#[allow(dead_code)] // not every test target uses both
pub fn reachable_tempdir(reference: &Path) -> Option<tempfile::TempDir> {
    make(reference, true)
}
