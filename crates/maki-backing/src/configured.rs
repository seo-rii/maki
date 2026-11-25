//! The directories a volume configuration names. A command that must open
//! one and cannot refuses it with the directory, its path, the setting that
//! names it and what to check, instead of the bare system error: a missing
//! directory is often a typo, or a filesystem that is not mounted.

use std::io;
use std::path::Path;

use crate::FileBacking;

/// A directory a configuration names, as its refusals describe it.
pub struct ConfiguredDirectory {
    what: &'static str,
    key: &'static str,
    /// Whether a path that, followed, is something other than a directory
    /// is refused as invalid input: the rollback witness has always refused
    /// one so (its own check follows the path). Every other path that is
    /// not a directory keeps the system's NotADirectory.
    other_than_a_directory_is_input: bool,
}

/// `backing.root`.
pub const BACKING_ROOT: ConfiguredDirectory = ConfiguredDirectory {
    what: "backing root",
    key: "backing.root",
    other_than_a_directory_is_input: false,
};

/// `backing.rollback_protection.witness_root`.
pub const WITNESS_ROOT: ConfiguredDirectory = ConfiguredDirectory {
    what: "rollback witness directory",
    key: "backing.rollback_protection.witness_root",
    other_than_a_directory_is_input: true,
};

impl ConfiguredDirectory {
    /// Whether this process can open the directory at `path`, or its
    /// worded refusal ([`Self::refusal`]). It opens the directory read-only
    /// with the checks a backing applies (no symbolic link is followed)
    /// and changes nothing: it never creates a directory.
    pub fn reachable(&self, path: &Path) -> io::Result<()> {
        match FileBacking::read_only(path) {
            Ok(_) => Ok(()),
            Err(error) => Err(self.refusal(path, error)),
        }
    }

    /// Whether this process may create entries in the directory at `path`
    /// ([`FileBacking::may_write_root`]), or the worded refusal of a
    /// directory it cannot open or look at. It changes nothing.
    pub fn may_write(&self, path: &Path) -> io::Result<bool> {
        FileBacking::may_write_root(path).map_err(|error| self.refusal(path, error))
    }

    /// The directory at `path` as the refusals name it: "the backing root
    /// <path> (`backing.root`)".
    pub fn named(&self, path: &Path) -> String {
        format!("the {} {} (`{}`)", self.what, path.display(), self.key)
    }

    /// `error`, met while reaching or reading the directory at `path`,
    /// with the directory, its path, its setting and what to check. The
    /// kind is the one `error` has, but for what
    /// `other_than_a_directory_is_input` says.
    pub fn refusal(&self, path: &Path, error: io::Error) -> io::Error {
        let Self { what, key, .. } = self;
        let shown = path.display();
        let (kind, message) = match error.kind() {
            io::ErrorKind::NotFound => (
                error.kind(),
                format!(
                    "the {what} {shown} (`{key}`) does not exist: check the configured path for \
                     a typo and that the filesystem that holds it is mounted"
                ),
            ),
            io::ErrorKind::PermissionDenied => (
                error.kind(),
                format!(
                    "this process may not open the {what} {shown} (`{key}`): {error}; check the \
                     owner and mode of the directory and of the directories above it"
                ),
            ),
            io::ErrorKind::NotADirectory => {
                // The path is opened without following a symbolic link in
                // any component. Say which is wrong: the path itself, or
                // the way to it.
                let wrong = match std::fs::symlink_metadata(path) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        "is a symbolic link, which is not followed: configure the directory \
                         itself"
                    }
                    Ok(metadata) if !metadata.is_dir() => "is not a directory",
                    Ok(_) => {
                        "is reached through a symbolic link, which is not followed: configure \
                         the path without it"
                    }
                    Err(_) => "cannot be reached: a component of its path is not a directory",
                };
                let input = self.other_than_a_directory_is_input
                    && std::fs::metadata(path).is_ok_and(|metadata| !metadata.is_dir());
                (
                    if input {
                        io::ErrorKind::InvalidInput
                    } else {
                        error.kind()
                    },
                    format!("the {what} {shown} (`{key}`) {wrong}"),
                )
            }
            _ => (
                error.kind(),
                format!("cannot open the {what} {shown} (`{key}`): {error}"),
            ),
        };
        io::Error::new(kind, message)
    }
}
