//! A temporary directory on a filesystem other than a given path's.
//!
//! A rollback-protected backing refuses a witness on the filesystem of its
//! backing tree. Fixtures that took `/dev/shm` for that second filesystem
//! failed where it does not exist, and where `TMPDIR` is itself on it.
//! [`tempdir`] makes its directory in the first of `/dev/shm`,
//! `/run/user/<uid>`, `/var/tmp`, `/tmp`, `TMPDIR` and `/run` whose device
//! differs from that of the path it is given. With none, it prints that the
//! calling test is skipped and why, and returns `None`; the test returns.
//!
//! A skipped test still passes, and a run that does not show the output of
//! passing tests (`cargo test` without `--show-output`, the background
//! runner) never shows the notice. Where a second filesystem belongs to the
//! environment, `MAKI_TEST_REQUIRE_OTHER_FILESYSTEM=1` turns the missing
//! filesystem into a failure instead: CI and the background runner's
//! rollback profile set it.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Set to `1`, a missing second filesystem fails the test.
pub const REQUIRE: &str = "MAKI_TEST_REQUIRE_OTHER_FILESYSTEM";

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

fn make(reference: &Path, reachable: bool, candidates: &[PathBuf]) -> Option<tempfile::TempDir> {
    let device = std::fs::metadata(reference)
        .unwrap_or_else(|error| panic!("{}: {error}", reference.display()))
        .dev();
    let mut refused = Vec::new();
    for candidate in candidates {
        let made = std::fs::canonicalize(candidate)
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
    let reason = format!(
        "no temporary directory on a filesystem other than that of {} ({})",
        reference.display(),
        refused.join("; ")
    );
    if std::env::var_os(REQUIRE).is_some_and(|value| value == "1") {
        panic!("{reason}, and {REQUIRE}=1 requires one");
    }
    eprintln!(
        "{}: skipped: {reason}",
        std::thread::current().name().unwrap_or("test")
    );
    None
}

/// A fresh `0700` directory on a filesystem other than `reference`'s, or
/// `None` after printing why the test is skipped.
#[allow(dead_code)] // not every test target uses both
pub fn tempdir(reference: &Path) -> Option<tempfile::TempDir> {
    make(reference, false, &candidates())
}

/// [`tempdir`] where every user may search down from `/`, for a fixture a
/// command run as another user opens.
#[allow(dead_code)] // not every test target uses both
pub fn reachable_tempdir(reference: &Path) -> Option<tempfile::TempDir> {
    make(reference, true, &candidates())
}

/// [`tempdir`] over `candidates` instead of the usual ones, for the test of
/// this helper.
#[allow(dead_code)] // only the helper's own test uses it
pub fn tempdir_among(reference: &Path, candidates: &[PathBuf]) -> Option<tempfile::TempDir> {
    make(reference, false, candidates)
}
