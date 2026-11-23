//! A temporary directory with a short path, for Unix sockets.
//!
//! A Unix socket address holds a path of at most 107 bytes on Linux (103
//! on macOS and the BSDs). `TMPDIR` can be longer than that by itself, as a
//! per-user or per-job directory may be, and a fixture below it then fails
//! with "path must be shorter than SUN_LEN", or its configuration is
//! refused, before the test reaches what it is about. [`tempdir`] makes its
//! directory, mode `0700`, in the shortest of `TMPDIR`, `/tmp` and
//! `/var/tmp` that takes one.

/// A fresh `0700` directory with a short path.
pub fn tempdir() -> std::io::Result<tempfile::TempDir> {
    let mut candidates = vec![std::env::temp_dir()];
    if cfg!(unix) {
        candidates.extend(["/tmp".into(), "/var/tmp".into()]);
    }
    // Stable: `TMPDIR` wins a tie.
    candidates.sort_by_key(|candidate| candidate.as_os_str().len());
    let mut refused = Vec::new();
    for candidate in candidates {
        match tempfile::tempdir_in(&candidate) {
            Ok(directory) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(
                        directory.path(),
                        std::fs::Permissions::from_mode(0o700),
                    )?;
                }
                return Ok(directory);
            }
            Err(error) => refused.push(format!("{}: {error}", candidate.display())),
        }
    }
    Err(std::io::Error::other(format!(
        "no temporary directory for a socket fixture ({})",
        refused.join("; ")
    )))
}
