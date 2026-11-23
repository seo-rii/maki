//! Reading a volume configuration file (SPEC §8).
//!
//! A volume configuration decides where plaintext goes: the crypto provider
//! and its endpoints, TLS trust, credential references, the backing root and
//! the rollback witness. Whoever can change the file, or substitute another
//! one under its name, can send the volume's data to an endpoint they
//! control. Every loader (the daemon, the `maki` commands and
//! `maki-benchmark`) therefore reads it through [`read_volume_config`],
//! which on Unix accepts only a regular file with one link, opened without
//! following a final symlink, owned by root or by this process's user and
//! not writable by its group or others. Group and other read stay allowed:
//! a configuration holds credential references, never secrets (SPEC §9),
//! and the recommended `root:maki 0640` is read by the daemon through its
//! group. The owner and mode rule is the witness configuration's (secret
//! files share the owner rule and refuse any group or other access); the
//! single link is the attach configuration's.
//! Every check describes the opened descriptor, which is then read, so a
//! swap between check and read cannot change what is loaded.

use std::io::Read;
use std::path::Path;

/// The largest volume configuration read into memory.
pub const MAX_VOLUME_CONFIG_BYTES: u64 = 1 << 20;

/// Why a volume configuration file was not read.
#[derive(Debug, thiserror::Error)]
pub enum ConfigFileError {
    /// Opening or reading failed: the file is missing, this user may not
    /// read it, or an I/O error occurred.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The file exists but is not one a loader may trust.
    #[error("{0}")]
    Refused(String),
}

impl ConfigFileError {
    /// The operating system denied this user read access to the file. A
    /// file the checks refused is not this case.
    pub fn is_access_denied(&self) -> bool {
        matches!(self, Self::Io(error) if error.kind() == std::io::ErrorKind::PermissionDenied)
    }
}

fn refused(reason: impl Into<String>) -> ConfigFileError {
    ConfigFileError::Refused(reason.into())
}

/// Read the volume configuration at `path` after checking that it may be
/// trusted (see the module documentation). The error does not repeat the
/// path; callers name it.
pub fn read_volume_config(path: &Path) -> Result<String, ConfigFileError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Neither follow a final symlink nor block on a FIFO without a writer.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        #[cfg(unix)]
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            return Err(refused(
                "is a symbolic link: a volume configuration is opened without following one, \
                 so name the file itself (SPEC 8)",
            ))
        }
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(refused("is not a regular file (SPEC 8)"));
    }
    #[cfg(unix)]
    check_trusted(&metadata)?;
    if metadata.len() > MAX_VOLUME_CONFIG_BYTES {
        return Err(refused(
            "is larger than 1 MiB, the bound for a volume configuration",
        ));
    }
    let mut text = String::new();
    file.take(MAX_VOLUME_CONFIG_BYTES + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_VOLUME_CONFIG_BYTES {
        return Err(refused(
            "grew beyond 1 MiB, the bound for a volume configuration, while being read",
        ));
    }
    Ok(text)
}

/// The owner, mode and link rules of SPEC §8, on the opened file.
#[cfg(unix)]
fn check_trusted(metadata: &std::fs::Metadata) -> Result<(), ConfigFileError> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    let owner = metadata.uid();
    if owner != 0 && owner != euid {
        return Err(refused(format!(
            "is owned by uid {owner}, not by root or this process's user (uid {euid}): its owner \
             can rewrite it whatever its mode; make it root-owned (root:maki 0640) or run as \
             its owner (SPEC 8)"
        )));
    }
    // A POSIX ACL that grants another user or group write access shows in
    // the group bits, which then hold the ACL mask.
    let mode = metadata.mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(refused(format!(
            "has mode {mode:04o}: it is writable by the group or by others; only its owner may \
             write a volume configuration, as with root:maki 0640 (SPEC 8)"
        )));
    }
    let links = metadata.nlink();
    if links != 1 {
        return Err(refused(format!(
            "has {links} hard links; a volume configuration must have exactly one, so that it \
             cannot be a file linked in from, or kept under, another name (SPEC 8)"
        )));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn an_oversized_configuration_is_refused_before_it_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volume.toml");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_VOLUME_CONFIG_BYTES + 1).unwrap();
        let error = read_volume_config(&path).unwrap_err();
        assert!(error.to_string().contains("larger than 1 MiB"), "{error}");
        file.set_len(MAX_VOLUME_CONFIG_BYTES).unwrap();
        assert_eq!(
            read_volume_config(&path).unwrap().len() as u64,
            MAX_VOLUME_CONFIG_BYTES
        );
    }

    #[test]
    fn a_fifo_is_refused_without_waiting_for_a_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volume.toml");
        let name = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        // SAFETY: `name` is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let error = read_volume_config(&path).unwrap_err();
        assert!(error.to_string().contains("not a regular file"), "{error}");
    }

    #[test]
    fn only_an_operating_system_denial_is_access_denied() {
        let denied = ConfigFileError::Io(std::io::Error::from_raw_os_error(libc::EACCES));
        assert!(denied.is_access_denied());
        assert!(!refused("has mode 0664").is_access_denied());
        let missing = ConfigFileError::Io(std::io::ErrorKind::NotFound.into());
        assert!(!missing.is_access_denied());
    }
}
