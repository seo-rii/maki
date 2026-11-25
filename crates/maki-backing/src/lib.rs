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

// Diagnostics go through `tracing`: the `print!` family panics when the
// write fails (a closed pipe, a full disk). Tests may print.
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]

pub mod file;
pub mod mem;
pub mod path;
pub mod remote_witness;
mod rollback;
pub mod witness;
pub use rollback::gc as remote_gc;
pub use rollback::RollbackBacking;

pub use file::FileBacking;
pub use mem::MemBacking;

/// Ceiling for [`raise_open_file_limit`]: Linux's default `fs.nr_open`.
#[cfg(unix)]
const OPEN_FILE_LIMIT_CAP: u64 = 1 << 20;

/// Raise the soft `RLIMIT_NOFILE` to the hard limit (at most 2^20) and return
/// the soft limit now in effect; never lowers it.
///
/// Every cataloged shard keeps its data file open, and systemd starts
/// services with a soft limit of 1024 under a much higher hard limit, so a
/// volume with about a thousand shards would fail with EMFILE (BUG-124).
/// Nothing here uses `select(2)`, the reason that soft limit stays low.
#[cfg(unix)]
#[allow(clippy::unnecessary_cast)] // `rlim_t` is `u64` on Linux, not on every Unix
pub fn raise_open_file_limit() -> io::Result<u64> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes into a valid, owned struct.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let target = (limit.rlim_max as u64).min(OPEN_FILE_LIMIT_CAP) as libc::rlim_t;
    if limit.rlim_cur >= target {
        return Ok(limit.rlim_cur as u64);
    }
    limit.rlim_cur = target;
    // SAFETY: setrlimit reads a valid struct; the soft limit stays within
    // the unchanged hard limit.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(target as u64)
}

/// No descriptor limit to raise on this platform.
#[cfg(not(unix))]
pub fn raise_open_file_limit() -> io::Result<u64> {
    Ok(u64::MAX)
}

// Share the executable crash model with this crate's unit tests without a
// dependency cycle through maki-test-support.
#[cfg(test)]
extern crate self as maki_backing;

// Rollback fixtures put the witness on another filesystem than the backing.
#[cfg(all(test, target_os = "linux"))]
#[path = "../tests/support/other_filesystem.rs"]
mod other_filesystem;

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

    /// Reserve physical storage for a byte range before the caller publishes
    /// work that will later depend on writing it. Real Linux files override
    /// this with `posix_fallocate`. A successful return allocates every hole
    /// in the range, which keeps later writes there from failing for lack
    /// of filesystem space only where the filesystem overwrites allocated
    /// extents in place. It does not unshare extents the file shares with
    /// another file, so it does not cover them: on XFS with reflink (the
    /// `mkfs.xfs` default since xfsprogs 5.1), a `cp --reflink` copy (GNU
    /// coreutils 9 `cp` defaults to `--reflink=auto`) shares every extent,
    /// `posix_fallocate` still returns success, and an in-place overwrite is
    /// copy-on-write and can fail with ENOSPC. Backing files must not share
    /// extents with copies. Nor does it cover a copy-on-write filesystem,
    /// where every overwrite of data already written needs new space even
    /// without sharing: btrfs by default, and ZFS. A btrfs NOCOW file
    /// (`chattr +C` while it is still empty, or inherited from its directory
    /// at creation) is overwritten in place unless btrfs falls back to
    /// copy-on-write, as it does for an extent a snapshot or reflink shares.
    /// Allocation metadata may remain volatile after this call even when
    /// the file length is already durable. Call `sync_all` before publishing
    /// a journal record that depends on crash-surviving completion space.
    /// In-memory backings may model allocation by extending the file;
    /// extent-aware tests must track unwritten reservations separately.
    /// A zero-length range reserves nothing: every backing returns success
    /// without changing the file (Linux `fallocate(2)` itself would refuse
    /// it with EINVAL).
    fn allocate_range(&self, offset: u64, len: u64) -> io::Result<()> {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "allocation overflow"))?;
        if len == 0 {
            return Ok(());
        }
        if self.len()? < end {
            self.set_len(end)?;
        }
        Ok(())
    }

    /// Replace an existing byte range with zeroes while allowing the backing
    /// store to release its physical storage. The file length is unchanged,
    /// and the change is volatile until `sync_data` succeeds.
    fn punch_hole(&self, _offset: u64, _len: u64) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "hole punching is not supported by this backing",
        ))
    }

    fn len(&self) -> io::Result<u64>;

    fn is_empty(&self) -> io::Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Make all previously written data durable (fdatasync).
    fn sync_data(&self) -> io::Result<()>;

    /// Make data and allocation metadata durable. In-memory/transactional
    /// backings commit both together; filesystem backings must use fsync.
    fn sync_all(&self) -> io::Result<()> {
        self.sync_data()
    }

    /// The file's owner where the backing has Unix ownership; `None` where
    /// it has none (in-memory and non-Unix backings).
    fn owner(&self) -> io::Result<Option<FileOwner>> {
        Ok(None)
    }

    /// Give the open file to `owner` (`fchown` on the descriptor, no
    /// pathname lookup). Only a privileged process can give a file to
    /// another user, so callers decide when to ask. Like other inode
    /// metadata, the change is volatile until `sync_all` succeeds.
    fn set_owner(&self, owner: FileOwner) -> io::Result<()> {
        let _ = owner;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "file ownership is not supported by this backing",
        ))
    }
}

/// A Unix file owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileOwner {
    pub uid: u32,
    pub gid: u32,
}

/// Held while a volume is attached; dropping releases the lock at once, even
/// while a child process forked meanwhile still holds a copy of the lock
/// file's descriptor.
pub trait VolumeLock: Send + Sync {}

/// A confined storage namespace for one volume.
pub trait Backing: Send + Sync + 'static {
    /// Validate the independent freshness authority, if this backing has one.
    /// Callers serving cached data must also check this session guard.
    fn check_freshness(&self) -> io::Result<()> {
        Ok(())
    }

    /// Why this backing's session stopped for good, if it has: a backing
    /// with a freshness authority that observed a change it did not make,
    /// or could not tell the outcome of its own commit, refuses every later
    /// operation until the volume is opened again. Answers at once, without
    /// storage or witness I/O, so a status query never waits for either.
    fn session_stopped(&self) -> Option<String> {
        None
    }

    /// Open a file. With `create = true`, creates it (volatile until the
    /// parent directory is synced).
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>>;

    fn exists(&self, path: &str) -> io::Result<bool>;

    fn remove(&self, path: &str) -> io::Result<()>;

    /// Atomically rename a file. Directory moves are backend-specific;
    /// portable callers must use file paths.
    fn rename(&self, from: &str, to: &str) -> io::Result<()>;

    fn create_dir_all(&self, path: &str) -> io::Result<()>;

    /// Sorted file/dir names directly inside `dir` ("" = root). A name that
    /// is not UTF-8 fails the listing with `InvalidData`, so a caller that
    /// must account for every entry (one proving a directory empty) never
    /// misses one, and no name is converted lossily into one that opens a
    /// different entry.
    fn list(&self, dir: &str) -> io::Result<Vec<String>>;

    /// [`list`](Backing::list) without the names that are not UTF-8, for
    /// scans that look only for names the volume writes (all ASCII) and
    /// ignore every other entry: such a name is none of those, so it is
    /// skipped like any other unknown name instead of failing the scan.
    /// Each name returned is exact. A backing whose names are all UTF-8
    /// keeps this default; one that forwards `list` to a backing that can
    /// hold other names forwards this too, or it refuses them.
    fn list_skipping_non_utf8(&self, dir: &str) -> io::Result<Vec<String>> {
        self.list(dir)
    }

    /// Make namespace operations under `dir` durable (fsync of directory).
    fn sync_dir(&self, dir: &str) -> io::Result<()>;

    /// Acquire the exclusive volume lock file. Fails with `WouldBlock` if
    /// another process/daemon holds it (`VOLUME_ALREADY_ATTACHED`).
    fn try_lock(&self, path: &str) -> io::Result<Box<dyn VolumeLock>>;

    /// Free space available to this namespace, if the backing can tell
    /// (`None` = unknown). Feeds the journal emergency reserve and the
    /// `maki_backing_free_bytes` metric.
    fn free_bytes(&self) -> io::Result<Option<u64>> {
        Ok(None)
    }

    /// The owner of directory `dir` ("" = root) where the backing has Unix
    /// ownership; `None` where it has none (in-memory and non-Unix
    /// backings, and views that do not forward it).
    fn directory_owner(&self, dir: &str) -> io::Result<Option<FileOwner>> {
        let _ = dir;
        Ok(None)
    }
}
