//! `maki-backing` — the volume backing-store abstraction (SPEC §21).
//!
//! A `Backing` is a confined, filesystem-like namespace rooted at the volume
//! directory (`/var/lib/maki/<volume>`). All paths are relative,
//! forward-slash separated, and may never escape the root.
//!
//! Durability model mirrors POSIX:
//! - `write_at` data is volatile until `sync_data` on that file succeeds,
//! - namespace operations (create/remove/rename) are volatile until
//!   `sync_dir` on the parent directory succeeds.
//!
//! `FileBacking` talks to a real filesystem; `MemBacking` is an in-memory
//! stand-in; `maki-test-support::CrashableBacking` simulates crashes.

pub mod file;
pub mod mem;
pub mod path;

pub use file::FileBacking;
pub use mem::MemBacking;

use std::io;
use std::sync::Arc;

/// An open file within a backing namespace. Positional I/O only.
pub trait BackingFile: Send + Sync {
    /// Read exactly `buf.len()` bytes at `offset`, or fail with
    /// `UnexpectedEof` if the file is too short.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()>;

    /// Write all of `data` at `offset`, extending the file if needed.
    /// The write is volatile until `sync_data` succeeds.
    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()>;

    fn set_len(&self, len: u64) -> io::Result<()>;

    fn len(&self) -> io::Result<u64>;

    fn is_empty(&self) -> io::Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Make all previously written data durable (fdatasync).
    fn sync_data(&self) -> io::Result<()>;
}

/// Held while a volume is attached; dropping releases the lock.
pub trait VolumeLock: Send + Sync {}

/// A confined storage namespace for one volume.
pub trait Backing: Send + Sync + 'static {
    /// Open a file. With `create = true`, creates it (volatile until the
    /// parent directory is synced).
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>>;

    fn exists(&self, path: &str) -> io::Result<bool>;

    fn remove(&self, path: &str) -> io::Result<()>;

    fn rename(&self, from: &str, to: &str) -> io::Result<()>;

    fn create_dir_all(&self, path: &str) -> io::Result<()>;

    /// Sorted file/dir names directly inside `dir` ("" = root).
    fn list(&self, dir: &str) -> io::Result<Vec<String>>;

    /// Make namespace operations under `dir` durable (fsync of directory).
    fn sync_dir(&self, dir: &str) -> io::Result<()>;

    /// Acquire the exclusive volume lock file. Fails with `WouldBlock` if
    /// another process/daemon holds it (`VOLUME_ALREADY_ATTACHED`).
    fn try_lock(&self, path: &str) -> io::Result<Box<dyn VolumeLock>>;
}
