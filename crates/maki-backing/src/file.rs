//! Real-filesystem backing rooted at a volume directory.

use std::ffi::{OsStr, OsString};
#[cfg(any(not(target_os = "linux"), test))]
use std::fs;
use std::fs::File;
#[cfg(not(target_os = "linux"))]
use std::fs::OpenOptions;
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(any(not(target_os = "linux"), test))]
use std::path::Path;
use std::path::PathBuf;
#[cfg(not(target_os = "linux"))]
use std::sync::Arc;

#[cfg(not(target_os = "linux"))]
use crate::path::validate;
use crate::{Backing, BackingFile, VolumeLock};

#[cfg(target_os = "linux")]
#[path = "file_linux.rs"]
mod linux;

/// `Backing` over a real directory tree. Linux pins the root and resolves
/// every component through directory descriptors without following symlinks.
/// Other development platforms perform pathname validation only.
///
/// Entries are created owner-only (`0600` files, `0700` directories) for
/// the user that runs the process, except that on Linux a process running
/// as root creates a file or directory inside the root, in a directory
/// another user owns, for that user (the directory's uid and gid): an
/// offline check or inspect run as root may recreate a lock file or
/// manifest slot in the daemon user's volume, and must not lock that user
/// out. A file is given away before it holds a byte (and, where the
/// filesystem has unnamed files, before it is linked under its name), an
/// existing entry is never given away, and a refused change creates
/// nothing. The root and missing ancestors of it, which [`FileBacking::new`]
/// creates, belong to the user that runs the process.
pub struct FileBacking {
    #[cfg(target_os = "linux")]
    directory: linux::Directory,
    #[cfg(not(target_os = "linux"))]
    root: PathBuf,
    /// Set by [`FileBacking::read_only`].
    read_only: bool,
}

impl FileBacking {
    pub fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                directory: linux::Directory::new(&root)?,
                read_only: false,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            create_private_dir_all(&root)?;
            Ok(Self {
                root,
                read_only: false,
            })
        }
    }

    /// A view of an existing root that only reads, for a source kept where
    /// nothing can change it (a read-only mount, immutable files, a
    /// read-only export, files this user may not write). It creates, probes
    /// and syncs nothing while opening the root, and opens files read-only
    /// with the same no-follow, regular-file and single-link checks. Creating
    /// or removing entries, renames, directory syncs and `try_lock` fail with
    /// `ReadOnlyFilesystem`, and an opened file's descriptor is read-only.
    /// [`Backing::try_lock_shared_existing`] excludes writers instead and
    /// never creates the lock file; `try_lock_shared`, which a restore
    /// uses, creates one that is missing, as `try_lock` does.
    pub fn read_only(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                directory: linux::Directory::existing(&root)?,
                read_only: true,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            if !fs::metadata(&root)?.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    "backing root is not a directory",
                ));
            }
            Ok(Self {
                root,
                read_only: true,
            })
        }
    }

    /// Take the lock file `path` shared: other shared holders are admitted,
    /// and an exclusive [`Backing::try_lock`] holder excludes them and is
    /// excluded (`WouldBlock`). An existing lock file is opened read-only, so
    /// this works on read-only media. A missing one is created first, as
    /// `try_lock` does, which needs write access.
    pub(crate) fn try_lock_shared(&self, path: &str) -> io::Result<Box<dyn VolumeLock>> {
        #[cfg(target_os = "linux")]
        let file = self.directory.lock_file(path)?;
        #[cfg(not(target_os = "linux"))]
        let file = {
            let p = self.resolve(path, false)?;
            match open_options().read(true).open(&p) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => open_options()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(&p)?,
                file => file?,
            }
        };
        lock_shared(file)
    }

    /// Whether this process may create entries in this backing's root. On
    /// Linux it asks about the pinned root descriptor that every operation
    /// of this backing resolves through, so the answer concerns the
    /// directory this backing reads, even if the path has been renamed or
    /// replaced since it was opened, and nothing is created, written or
    /// synced. The answer is the kernel's for this process's effective
    /// credentials, ACLs and capabilities (`faccessat` with `AT_EACCESS`):
    /// `false` on a read-only mount, a read-only bind mount included
    /// (EROFS), for a directory without write permission for this process
    /// (EACCES), and for an immutable directory (EPERM). It says nothing
    /// about the files below the root. Only Linux asks; on other platforms,
    /// which serve development only, the answer is `true`.
    pub fn may_write(&self) -> io::Result<bool> {
        #[cfg(target_os = "linux")]
        {
            self.directory.may_write()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(true)
        }
    }

    /// [`Self::may_write`] of the existing directory `root`, opened as
    /// [`FileBacking::read_only`] opens it and closed again. A caller that
    /// reads the root after asking asks the view it reads through instead.
    pub fn may_write_root(root: impl Into<PathBuf>) -> io::Result<bool> {
        Self::read_only(root)?.may_write()
    }

    /// Refuse a change through a [`FileBacking::read_only`] view.
    fn writable(&self) -> io::Result<()> {
        if self.read_only {
            return Err(io::Error::new(
                io::ErrorKind::ReadOnlyFilesystem,
                "read-only backing view",
            ));
        }
        Ok(())
    }

    /// Describe the root directory. On Linux this is the pinned descriptor
    /// every operation resolves through, so a check concerns the directory
    /// actually used; other development platforms describe the pathname.
    /// `FileBacking` applies no owner or mode rule of its own: volume roots
    /// and the remote witness state directory have different rules, which
    /// their callers enforce.
    #[cfg(unix)]
    pub(crate) fn root_metadata(&self) -> io::Result<std::fs::Metadata> {
        #[cfg(target_os = "linux")]
        {
            self.directory.root_metadata()
        }
        #[cfg(not(target_os = "linux"))]
        {
            fs::symlink_metadata(&self.root)
        }
    }

    /// Describe an existing entry without following a final symlink, or
    /// `None` when it is absent.
    #[cfg(unix)]
    pub(crate) fn entry_metadata(&self, path: &str) -> io::Result<Option<std::fs::Metadata>> {
        #[cfg(target_os = "linux")]
        let metadata = self.directory.entry_metadata(path);
        #[cfg(not(target_os = "linux"))]
        let metadata = fs::symlink_metadata(self.resolve(path, false)?);
        match metadata {
            Ok(metadata) => Ok(Some(metadata)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// GC uses bounded, sorted pages after an exclusive name cursor and a
    /// pinned-directory retirement operation;
    /// neither operation is available on pathname-only development backends.
    /// Pages hold exact entry names in byte order; anyone who can write the
    /// root can add a name that is not UTF-8.
    pub(crate) fn gc_entries(&self, after: Option<&OsStr>) -> io::Result<Vec<OsString>> {
        #[cfg(target_os = "linux")]
        {
            self.directory.gc_entries(after)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = after;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "remote GC requires Linux",
            ))
        }
    }

    pub(crate) fn gc_retire(&self, original: &str, retired: bool) -> io::Result<GcRemoval> {
        #[cfg(target_os = "linux")]
        {
            self.directory.gc_retire(original, retired)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (original, retired);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "remote GC requires Linux",
            ))
        }
    }

    pub(crate) fn gc_scope(&self, namespace: &str) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                directory: self.directory.gc_scope(namespace)?,
                read_only: self.read_only,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = namespace;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "remote GC requires Linux",
            ))
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn resolve(&self, rel: &str, allow_empty: bool) -> io::Result<PathBuf> {
        validate(rel, allow_empty)?;
        let mut p = self.root.clone();
        for comp in rel.split('/').filter(|c| !c.is_empty()) {
            p.push(comp);
            // The namespace is escape-proof only if it cannot be
            // redirected: no component under the root may be a symlink
            // (third review, backing path hardening). Unix opens also pass
            // O_NOFOLLOW for the final component.
            if let Ok(meta) = fs::symlink_metadata(&p) {
                if meta.file_type().is_symlink() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid backing path {rel:?}: {} is a symlink", p.display()),
                    ));
                }
            }
        }
        Ok(p)
    }

    /// A directory's sorted entry names for `Backing::list`, each exactly
    /// as stored. A name that is not UTF-8 fails the listing, unless
    /// `skip_non_utf8` leaves it out; it is never converted lossily, which
    /// could return a name that opens a different entry.
    #[cfg(not(target_os = "linux"))]
    fn utf8_names(&self, dir: &str, skip_non_utf8: bool) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in fs::read_dir(self.resolve(dir, true)?)? {
            match entry?.file_name().into_string() {
                Ok(name) => names.push(name),
                Err(_) if skip_non_utf8 => {}
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "directory entry name is not UTF-8",
                    ))
                }
            }
        }
        names.sort();
        Ok(names)
    }
}

// The shared GC dispatcher uses this result type, but only Linux constructs
// successful outcomes; other platforms return Unsupported before doing GC.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum GcRemoval {
    Removed,
    Live,
    Unrecognized,
    /// The candidate could not be opened or examined, for the reason held.
    /// Nothing about it was changed.
    Unreadable(io::Error),
    /// The candidate passed examination, and a step that changes it alone
    /// (its rename when its own directory is immutable or append-only, an
    /// unlink in it, the sync of its directory, its removal) failed, for
    /// the reason held. `tombstone` says whether it is
    /// now under its tombstone name.
    Unfinished {
        tombstone: bool,
        error: io::Error,
    },
}

/// `OpenOptions` that never follow a symlink at the final component and
/// create files owner-only (SPEC §8: data, journal and metadata files are
/// `maki:maki 0600`).
#[cfg(not(target_os = "linux"))]
fn open_options() -> OpenOptions {
    #[allow(unused_mut)] // only Unix adds flags
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
        options.mode(0o600);
    }
    options
}

/// `create_dir_all` with owner-only directories (SPEC §8: the volume
/// directory and everything under it are `maki:maki 0700`). Existing
/// directories keep their mode.
#[cfg(not(target_os = "linux"))]
fn create_private_dir_all(path: &Path) -> io::Result<()> {
    #[allow(unused_mut)] // only Unix sets a mode
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

pub struct RealFile {
    file: File,
}

#[cfg(target_os = "linux")]
fn retry_interrupted_allocation(mut allocate: impl FnMut() -> libc::c_int) -> io::Result<()> {
    loop {
        match allocate() {
            0 => return Ok(()),
            libc::EINTR => continue,
            errno => return Err(io::Error::from_raw_os_error(errno)),
        }
    }
}

impl BackingFile for RealFile {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        read_exact_at(&self.file, offset, buf)
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        write_all_at(&self.file, offset, data)
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.file.set_len(len)
    }

    fn allocate_range(&self, offset: u64, len: u64) -> io::Result<()> {
        let _end = offset
            .checked_add(len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "allocation overflow"))?;
        if len == 0 {
            // Nothing to reserve; posix_fallocate would fail with EINVAL.
            return Ok(());
        }
        #[cfg(target_os = "linux")]
        {
            let offset = i64::try_from(offset).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "allocation offset exceeds off_t",
                )
            })?;
            let len = i64::try_from(len).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "allocation length exceeds off_t",
                )
            })?;
            retry_interrupted_allocation(|| {
                // SAFETY: the descriptor stays open and the range fits off_t.
                unsafe { libc::posix_fallocate(self.file.as_raw_fd(), offset, len) }
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            if self.len()? < _end {
                self.set_len(_end)?;
            }
            Ok(())
        }
    }

    fn punch_hole(&self, offset: u64, len: u64) -> io::Result<()> {
        if len == 0 {
            return Ok(());
        }
        let end = offset
            .checked_add(len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "hole-punch overflow"))?;
        #[cfg(target_os = "linux")]
        {
            let offset = i64::try_from(offset).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "hole-punch offset exceeds off_t",
                )
            })?;
            let len = i64::try_from(len).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "hole-punch length exceeds off_t",
                )
            })?;
            i64::try_from(end).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "hole-punch end exceeds off_t")
            })?;
            loop {
                // SAFETY: the descriptor stays open for the call and the
                // validated range is non-negative and representable by off_t.
                let result = unsafe {
                    libc::fallocate(
                        self.file.as_raw_fd(),
                        libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                        offset,
                        len,
                    )
                };
                if result == 0 {
                    return Ok(());
                }
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = end;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "hole punching is not supported on this platform",
            ))
        }
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    fn sync_data(&self) -> io::Result<()> {
        self.file.sync_data()
    }

    fn sync_all(&self) -> io::Result<()> {
        self.file.sync_all()
    }

    #[cfg(unix)]
    fn owner(&self) -> io::Result<Option<crate::FileOwner>> {
        use std::os::unix::fs::MetadataExt;
        let metadata = self.file.metadata()?;
        Ok(Some(crate::FileOwner {
            uid: metadata.uid(),
            gid: metadata.gid(),
        }))
    }

    #[cfg(unix)]
    fn set_owner(&self, owner: crate::FileOwner) -> io::Result<()> {
        std::os::unix::fs::fchown(&self.file, Some(owner.uid), Some(owner.gid))
    }
}

#[cfg(unix)]
fn read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

#[cfg(unix)]
fn write_all_at(file: &File, offset: u64, data: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.write_all_at(data, offset)
}

#[cfg(windows)]
fn read_exact_at(file: &File, mut offset: u64, mut buf: &mut [u8]) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match file.seek_read(buf, offset) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "read past EOF",
                ))
            }
            Ok(n) => {
                buf = &mut buf[n..];
                offset += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(windows)]
fn write_all_at(file: &File, mut offset: u64, mut data: &[u8]) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !data.is_empty() {
        match file.seek_write(data, offset) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "seek_write returned 0",
                ))
            }
            Ok(n) => {
                data = &data[n..];
                offset += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// An acquired `flock` lock. It belongs to the open file description, which
/// a child forked by any thread shares until its `exec` closes its copy, so
/// closing this descriptor alone would leave the lock held for that child.
/// Dropping unlocks first: the lock ends with its holder.
struct FileLock {
    file: File,
}

impl VolumeLock for FileLock {}

/// Lock the opened lock `file` shared without waiting.
fn lock_shared(file: File) -> io::Result<Box<dyn VolumeLock>> {
    match file.try_lock_shared() {
        Ok(()) => Ok(Box::new(FileLock { file })),
        Err(std::fs::TryLockError::WouldBlock) => Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "lock held exclusively by another operation",
        )),
        Err(std::fs::TryLockError::Error(error)) => Err(error),
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // Releasing a held lock does not fail on a valid descriptor; the
        // close that follows still releases it where no child shares it.
        let _ = self.file.unlock();
    }
}

#[cfg(not(target_os = "linux"))]
impl Backing for FileBacking {
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        if create {
            self.writable()?;
        }
        let p = self.resolve(path, false)?;
        let file = open_options()
            .read(true)
            .write(!self.read_only)
            .create(create)
            .open(&p)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "backing entry is not a regular file",
            ));
        }
        Ok(Arc::new(RealFile { file }))
    }

    fn exists(&self, path: &str) -> io::Result<bool> {
        Ok(self.resolve(path, false)?.exists())
    }

    fn remove(&self, path: &str) -> io::Result<()> {
        self.writable()?;
        fs::remove_file(self.resolve(path, false)?)
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        self.writable()?;
        fs::rename(self.resolve(from, false)?, self.resolve(to, false)?)
    }

    fn create_dir_all(&self, path: &str) -> io::Result<()> {
        self.writable()?;
        create_private_dir_all(&self.resolve(path, false)?)
    }

    fn list(&self, dir: &str) -> io::Result<Vec<String>> {
        self.utf8_names(dir, false)
    }

    fn list_skipping_non_utf8(&self, dir: &str) -> io::Result<Vec<String>> {
        self.utf8_names(dir, true)
    }

    fn sync_dir(&self, dir: &str) -> io::Result<()> {
        self.writable()?;
        let p = self.resolve(dir, true)?;
        sync_dir_impl(&p)
    }

    fn try_lock(&self, path: &str) -> io::Result<Box<dyn VolumeLock>> {
        self.writable()?;
        let p = self.resolve(path, false)?;
        let file = open_options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&p)?;
        match file.try_lock() {
            Ok(()) => Ok(Box::new(FileLock { file })),
            Err(std::fs::TryLockError::WouldBlock) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "VOLUME_ALREADY_ATTACHED",
            )),
            Err(std::fs::TryLockError::Error(e)) => Err(e),
        }
    }

    fn is_read_only(&self) -> bool {
        self.read_only
    }

    fn try_lock_shared_existing(&self, path: &str) -> io::Result<Box<dyn VolumeLock>> {
        let file = open_options().read(true).open(self.resolve(path, false)?)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "backing entry is not a regular file",
            ));
        }
        lock_shared(file)
    }

    #[cfg(unix)]
    fn free_bytes(&self) -> io::Result<Option<u64>> {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(self.root.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "root path contains NUL"))?;
        // SAFETY: statvfs writes into the zeroed struct we pass; the path is a
        // valid NUL-terminated C string for the duration of the call.
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(path.as_ptr(), &mut st) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(
            (st.f_bavail as u64).saturating_mul(st.f_frsize as u64),
        ))
    }

    /// Free-space queries are not wired on non-Unix development hosts.
    #[cfg(not(unix))]
    fn free_bytes(&self) -> io::Result<Option<u64>> {
        Ok(None)
    }

    #[cfg(unix)]
    fn directory_owner(&self, dir: &str) -> io::Result<Option<crate::FileOwner>> {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(self.resolve(dir, true)?)?;
        Ok(Some(crate::FileOwner {
            uid: metadata.uid(),
            gid: metadata.gid(),
        }))
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn sync_dir_impl(p: &Path) -> io::Result<()> {
    File::open(p)?.sync_all()
}

/// Windows has no directory fsync; metadata durability is handled by NTFS
/// journaling. Development-only path — production runs on Linux.
#[cfg(windows)]
fn sync_dir_impl(p: &Path) -> io::Result<()> {
    let _ = p;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn interrupted_allocation_retries_and_preserves_the_terminal_result() {
        for terminal in [0, libc::ENOSPC] {
            let mut results = [libc::EINTR, libc::EINTR, terminal].into_iter();
            let result = retry_interrupted_allocation(|| results.next().unwrap());
            assert_eq!(
                result.err().and_then(|e| e.raw_os_error()),
                (terminal != 0).then_some(terminal)
            );
            assert_eq!(results.next(), None);
        }
    }

    #[test]
    fn read_write_roundtrip_and_eof() {
        let dir = tempfile::tempdir().unwrap();
        let backing = FileBacking::new(dir.path()).unwrap();
        backing.create_dir_all("journal").unwrap();
        let f = backing.open("journal/seg-1", true).unwrap();
        f.write_at(10, b"hello").unwrap();
        let mut buf = [0u8; 5];
        f.read_at(10, &mut buf).unwrap();
        assert_eq!(&buf, b"hello");
        assert_eq!(f.len().unwrap(), 15);
        let mut big = [0u8; 32];
        let err = f.read_at(0, &mut big).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn lock_is_exclusive() {
        let dir = tempfile::tempdir().unwrap();
        let backing = FileBacking::new(dir.path()).unwrap();
        let l1 = backing.try_lock("volume.lock").unwrap();
        let err = match backing.try_lock("volume.lock") {
            Ok(_) => panic!("second lock must fail"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        drop(l1);
        backing.try_lock("volume.lock").unwrap();
    }

    #[test]
    fn read_only_view_reads_and_refuses_changes() {
        let dir = tempfile::tempdir().unwrap();
        let backing = FileBacking::new(dir.path()).unwrap();
        backing.create_dir_all("sub").unwrap();
        backing
            .open("sub/file", true)
            .unwrap()
            .write_at(0, b"bytes")
            .unwrap();
        assert!(FileBacking::read_only(dir.path().join("missing")).is_err());
        assert!(!dir.path().join("missing").exists());
        let view = FileBacking::read_only(dir.path()).unwrap();
        let file = view.open("sub/file", false).unwrap();
        let mut bytes = [0; 5];
        file.read_at(0, &mut bytes).unwrap();
        assert_eq!(&bytes, b"bytes");
        assert!(file.write_at(0, b"x").is_err());
        assert_eq!(view.list("sub").unwrap(), ["file"]);
        let refused = |result: io::Result<()>| {
            assert_eq!(
                result.unwrap_err().kind(),
                io::ErrorKind::ReadOnlyFilesystem
            )
        };
        refused(view.open("sub/new", true).map(drop));
        refused(view.remove("sub/file"));
        refused(view.rename("sub/file", "moved"));
        refused(view.create_dir_all("new"));
        refused(view.sync_dir(""));
        refused(view.try_lock("volume.lock").map(drop));
        assert_eq!(fs::read(dir.path().join("sub/file")).unwrap(), b"bytes");
        // Shared holders admit each other and exclude an exclusive holder.
        let shared = view.try_lock_shared("volume.lock").unwrap();
        let second = view.try_lock_shared("volume.lock").unwrap();
        let exclusive = backing.try_lock("volume.lock").err().unwrap();
        assert_eq!(exclusive.kind(), io::ErrorKind::WouldBlock);
        drop((shared, second));
        let exclusive = backing.try_lock("volume.lock").unwrap();
        let shared = view.try_lock_shared("volume.lock").err().unwrap();
        assert_eq!(shared.kind(), io::ErrorKind::WouldBlock);
        drop(exclusive);
    }

    #[test]
    fn a_shared_lock_of_an_existing_file_creates_nothing_and_excludes_a_writer() {
        let dir = tempfile::tempdir().unwrap();
        let backing = FileBacking::new(dir.path()).unwrap();
        let view = FileBacking::read_only(dir.path()).unwrap();
        assert!(view.is_read_only());
        assert!(!backing.is_read_only());
        for missing in [
            view.try_lock_shared_existing("volume.lock"),
            backing.try_lock_shared_existing("volume.lock"),
        ] {
            assert_eq!(missing.err().unwrap().kind(), io::ErrorKind::NotFound);
        }
        assert!(!dir.path().join("volume.lock").exists());
        backing.create_dir_all("sub").unwrap();
        assert!(view.try_lock_shared_existing("sub").is_err());

        drop(backing.try_lock("volume.lock").unwrap());
        let shared = view.try_lock_shared_existing("volume.lock").unwrap();
        let second = backing.try_lock_shared_existing("volume.lock").unwrap();
        let exclusive = backing.try_lock("volume.lock").err().unwrap();
        assert_eq!(exclusive.kind(), io::ErrorKind::WouldBlock);
        drop((shared, second));
        let exclusive = backing.try_lock("volume.lock").unwrap();
        let shared = view.try_lock_shared_existing("volume.lock").err().unwrap();
        assert_eq!(shared.kind(), io::ErrorKind::WouldBlock);
        drop(exclusive);
    }

    /// Whether a root may be written is asked without creating anything.
    /// The answers for a read-only mount and for a directory this process
    /// may not write are tested by the binaries that use it (`maki`,
    /// `maki-check`), where a root run can drop the capability that
    /// ignores modes.
    #[test]
    fn a_writable_root_may_be_written_and_a_missing_one_is_not_created() {
        let dir = tempfile::tempdir().unwrap();
        assert!(FileBacking::may_write_root(dir.path()).unwrap());
        assert!(FileBacking::read_only(dir.path())
            .unwrap()
            .may_write()
            .unwrap());
        let missing = dir.path().join("missing");
        assert_eq!(
            FileBacking::may_write_root(&missing).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert!(!missing.exists());
        fs::write(&missing, b"").unwrap();
        assert!(FileBacking::may_write_root(&missing).is_err());
    }

    /// `may_write` answers for the directory the backing holds, not for
    /// whatever its path names by now, so a caller that reads through the
    /// view it asked reads the directory the answer is about.
    #[test]
    fn may_write_answers_for_the_root_the_view_holds_not_for_its_path() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        fs::create_dir(&root).unwrap();
        let view = FileBacking::read_only(&root).unwrap();
        fs::rename(&root, dir.path().join("moved")).unwrap();
        fs::write(&root, b"").unwrap();
        assert!(view.may_write().unwrap());
        assert!(FileBacking::may_write_root(&root).is_err());
    }

    #[test]
    fn escape_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let backing = FileBacking::new(dir.path()).unwrap();
        assert!(backing.open("../evil", true).is_err());
        assert!(backing.open("/abs", true).is_err());
    }

    /// SPEC §8: the volume directory tree is `0700` and its files `0600`,
    /// whatever the process umask says. Ciphertext, metadata, the journal
    /// and the key canary must not be readable by other users.
    #[cfg(unix)]
    #[test]
    fn created_directories_and_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("vol");
        let backing = FileBacking::new(&root).unwrap();
        assert_eq!(mode(&root), 0o700);
        backing.create_dir_all("data/sub").unwrap();
        assert_eq!(mode(&root.join("data")), 0o700);
        assert_eq!(mode(&root.join("data/sub")), 0o700);
        backing.open("data/sub/shard", true).unwrap();
        assert_eq!(mode(&root.join("data/sub/shard")), 0o600);
        backing.try_lock("volume.lock").unwrap();
        assert_eq!(mode(&root.join("volume.lock")), 0o600);
    }

    /// Lexical validation stops `..` and absolute paths; a symlink planted
    /// under the root would still redirect an open outside it (third
    /// review). Neither a directory nor a file symlink is ever followed.
    #[cfg(unix)]
    #[test]
    fn symlinks_inside_the_root_are_never_followed() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("victim"), b"data").unwrap();
        let root = dir.path().join("root");
        let backing = FileBacking::new(&root).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("journal")).unwrap();
        std::os::unix::fs::symlink(outside.join("victim"), root.join("seg")).unwrap();

        assert!(backing.open("journal/victim", false).is_err());
        assert!(backing.open("journal/new", true).is_err());
        assert!(backing.open("seg", false).is_err());
        assert!(backing.open("seg", true).is_err());
        assert!(backing.try_lock("seg").is_err());
        assert!(backing.list("journal").is_err());
        assert!(backing.create_dir_all("journal/sub").is_err());
        assert_eq!(fs::read(outside.join("victim")).unwrap(), b"data");
        assert!(!outside.join("new").exists());
        // Real entries next to the symlinks keep working.
        backing.open("real", true).unwrap();
        assert!(backing.exists("real").unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn free_bytes_reports_space_on_a_real_filesystem() {
        let dir = tempfile::tempdir().unwrap();
        let backing = FileBacking::new(dir.path()).unwrap();
        let free = backing.free_bytes().unwrap().expect("statvfs available");
        assert!(free > 0);
    }
}
