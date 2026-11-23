//! A temporary directory that other users can reach.
//!
//! A root-only test that runs a command as an unprivileged user needs its
//! fixture where that user can get to it. `TMPDIR` may be private to the
//! user running the tests (pam_tmpdir's `/tmp/user/0`, a `mktemp -d`
//! directory, both `0700`): nobody else reaches a directory made there,
//! whatever its own mode. [`tempdir`] makes its directory, with mode
//! `0755`, in the first of `TMPDIR`, `/tmp` and `/var/tmp` that every user
//! may search down from `/`.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Why some user cannot reach `directory`, or `None`.
fn unreachable(directory: &Path) -> Option<String> {
    for ancestor in directory.ancestors() {
        match std::fs::metadata(ancestor) {
            Ok(metadata) if metadata.permissions().mode() & 0o001 != 0 => {}
            Ok(metadata) => {
                return Some(format!(
                    "{} has mode {:04o}",
                    ancestor.display(),
                    metadata.permissions().mode() & 0o7777
                ))
            }
            Err(error) => return Some(format!("{}: {error}", ancestor.display())),
        }
    }
    None
}

/// A fresh `0755` directory every user can reach. `Err` lists why no
/// candidate would do; the caller reports that it skips.
pub fn tempdir() -> Result<tempfile::TempDir, String> {
    let mut refused = Vec::new();
    for candidate in [std::env::temp_dir(), "/tmp".into(), "/var/tmp".into()] {
        let made = std::fs::canonicalize(&candidate)
            .map_err(|error| error.to_string())
            .and_then(|base| match unreachable(&base) {
                Some(reason) => Err(reason),
                None => tempfile::tempdir_in(base).map_err(|error| error.to_string()),
            });
        match made {
            Ok(directory) => {
                std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755))
                    .map_err(|error| error.to_string())?;
                return Ok(directory);
            }
            Err(reason) => refused.push(format!("{}: {reason}", candidate.display())),
        }
    }
    Err(format!(
        "no temporary directory that other users can reach ({})",
        refused.join("; ")
    ))
}
