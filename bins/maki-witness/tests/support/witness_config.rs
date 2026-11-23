//! Write a witness configuration fixture with an explicit mode.
//!
//! `maki-witness` refuses a configuration that its group or others can
//! write. `std::fs::write` creates a file with the process umask, so under
//! `umask 002` (the default for ordinary users with a private group) a
//! fixture would be `0664` and refused before the command reads it.
//! [`write`] sets `0644`, the mode `umask 022` gives, whatever the umask:
//! `set_permissions` is not subject to it. A test of the mode rule sets the
//! mode it needs itself.

use std::path::Path;

/// `std::fs::write`, then mode `0644` on Unix.
pub fn write(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    let path = path.as_ref();
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}
