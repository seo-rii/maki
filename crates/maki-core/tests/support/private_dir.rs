//! A temporary directory with an explicit mode.
//!
//! `tempfile::tempdir()` creates its directory with the process umask:
//! `0775` under `umask 002`, the default for ordinary users with a private
//! group. The remote witness refuses a state directory its group or others
//! can write, so a fixture made that way is refused there, while the same
//! test passes at `umask 022`. [`tempdir`] sets `0700` whatever the umask:
//! `set_permissions` is not subject to it. A test of the mode rule sets the
//! mode it needs itself.

/// `tempfile::tempdir()`, then mode `0700` on Unix.
pub fn tempdir() -> std::io::Result<tempfile::TempDir> {
    let directory = tempfile::tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(directory)
}
