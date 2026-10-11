//! Linux namespace operations are relative to open directories, never a
//! previously checked absolute pathname. A renamed root stays the same volume.

use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};
use std::sync::Arc;

use super::{Backing, BackingFile, FileBacking, FileLock, GcRemoval, RealFile, VolumeLock};
use crate::path::validate;

pub(super) struct Directory(File);

fn name(value: &OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "backing path contains NUL"))
}

fn open_at(parent: &File, child: &CStr, flags: i32) -> io::Result<File> {
    // SAFETY: parent remains open, child is NUL terminated, and a successful
    // descriptor is newly owned by the File returned here. O_CREAT uses 0600.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            child.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn child_dir(parent: &File, child: &CStr, create: bool) -> io::Result<File> {
    // Searching a known pathname needs execute permission, not permission to
    // list each ancestor. Inspect an existing directory before trying mkdir.
    match open_at(parent, child, libc::O_PATH | libc::O_DIRECTORY) {
        Ok(directory) => return Ok(directory),
        Err(error) if create && error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    if create {
        // SAFETY: both arguments remain valid through mkdirat; no symlink is
        // followed. EEXIST is checked by the subsequent O_DIRECTORY open.
        if unsafe { libc::mkdirat(parent.as_raw_fd(), child.as_ptr(), 0o700) } != 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        }
    }
    open_at(parent, child, libc::O_PATH | libc::O_DIRECTORY)
}

impl Directory {
    pub(super) fn new(root: &Path) -> io::Result<Self> {
        let mut directory = File::open(if root.is_absolute() { "/" } else { "." })?;
        for component in root.components() {
            match component {
                Component::RootDir | Component::CurDir => continue,
                // The configured root may be relative on development callers;
                // parent traversal is allowed only while selecting that root.
                Component::Normal(_) | Component::ParentDir => {
                    directory = child_dir(&directory, &name(component.as_os_str())?, true)?;
                }
                Component::Prefix(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid Linux root",
                    ))
                }
            }
        }
        Ok(Self(open_at(
            &directory,
            c".",
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?))
    }

    fn directory(&self, path: &str, create: bool) -> io::Result<File> {
        validate(path, true)?;
        // Opening '.' creates an independent directory stream offset. dup()
        // would share it and repeated/concurrent list calls could miss entries.
        let mut directory = child_dir(&self.0, c".", false)?;
        for component in path.split('/').filter(|part| !part.is_empty()) {
            directory = child_dir(&directory, &name(OsStr::new(component))?, create)?;
        }
        Ok(directory)
    }

    fn parent(&self, path: &str) -> io::Result<(File, CString)> {
        validate(path, false)?;
        let (parent, child) = path.rsplit_once('/').unwrap_or(("", path));
        Ok((self.directory(parent, false)?, name(OsStr::new(child))?))
    }

    fn open_file(&self, path: &str, create: bool) -> io::Result<File> {
        let (parent, child) = self.parent(path)?;
        let file = open_at(
            &parent,
            &child,
            libc::O_RDWR | libc::O_NONBLOCK | if create { libc::O_CREAT } else { 0 },
        )?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "backing entry is not a regular file",
            ));
        }
        Ok(file)
    }
}

fn entry_exists(parent: &File, child: &CStr) -> io::Result<bool> {
    // SAFETY: stat storage is initialized, parent is open and child is a valid
    // C string. AT_SYMLINK_NOFOLLOW prevents dereferencing a final symlink.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            child.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(error)
        };
    }
    if stat.st_mode & libc::S_IFMT == libc::S_IFLNK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "backing entry is a symlink",
        ));
    }
    Ok(true)
}

struct DirectoryStream(*mut libc::DIR);

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns the successful fdopendir stream exactly once.
        unsafe { libc::closedir(self.0) };
    }
}

fn names(directory: &File, maximum: usize) -> io::Result<Vec<String>> {
    let fd = open_at(directory, c".", libc::O_RDONLY | libc::O_DIRECTORY)?.into_raw_fd();
    // SAFETY: fdopendir takes ownership on success; on failure we close fd.
    let raw = unsafe { libc::fdopendir(fd) };
    if raw.is_null() {
        let error = io::Error::last_os_error();
        drop(unsafe { File::from_raw_fd(fd) });
        return Err(error);
    }
    let stream = DirectoryStream(raw);
    let mut names = Vec::new();
    loop {
        // SAFETY: stream is private, and each name is copied before readdir.
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(0) {
                return Err(error);
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name == c"." || name == c".." {
            continue;
        }
        if names.len() == maximum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "GC directory entry bound exceeded",
            ));
        }
        let name = name.to_str().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "non-UTF8 GC directory entry")
        })?;
        names.push(name.to_owned());
    }
    names.sort();
    Ok(names)
}

fn same_entry(parent: &File, name: &CStr, file: &File) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: valid pinned directory, C string and stat storage. No link follow.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(error)
        };
    }
    let metadata = file.metadata()?;
    Ok(stat.st_dev as u64 == metadata.dev() && stat.st_ino as u64 == metadata.ino())
}

fn mount_id(file: &File) -> io::Result<u64> {
    let mut stat: libc::statx = unsafe { std::mem::zeroed() };
    // SAFETY: AT_EMPTY_PATH inspects this open descriptor; initialized storage.
    if unsafe {
        libc::statx(
            file.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            libc::STATX_MNT_ID,
            &mut stat,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if stat.stx_mask & libc::STATX_MNT_ID == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "GC needs mount identity support",
        ));
    }
    Ok(stat.stx_mnt_id)
}

fn unexpected(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound
        || matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR))
        || error.kind() == io::ErrorKind::InvalidData
}

impl Directory {
    pub(super) fn gc_entries(&self) -> io::Result<Vec<String>> {
        names(&self.0, 4096)
    }

    pub(super) fn gc_scope(&self, namespace: &str) -> io::Result<Self> {
        validate(namespace, false)?;
        if namespace.contains('/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "GC namespace is not a root child",
            ));
        }
        let name = name(OsStr::new(namespace))?;
        let directory = open_at(&self.0, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
        if mount_id(&directory)? != mount_id(&self.0)? || !same_entry(&self.0, &name, &directory)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "GC authority namespace crosses a mount or changed",
            ));
        }
        Ok(Self(directory))
    }

    /// Called only while the root operation lock excludes all physical forks.
    /// Retirement is made durable before any ciphertext is unlinked.
    pub(super) fn gc_retire(&self, original: &str, retired: bool) -> io::Result<GcRemoval> {
        use std::os::unix::fs::MetadataExt;
        validate(original, false)?;
        if original.contains('/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "GC namespace is not a root child",
            ));
        }
        let original_name = name(OsStr::new(original))?;
        let retired_name = name(OsStr::new(&format!(".remote-gc-{original}")))?;
        let current_name = if retired {
            &retired_name
        } else {
            &original_name
        };
        // Collision refusal ensures no retired path can stand in for an
        // existing original session or overwrite another directory.
        match entry_exists(
            &self.0,
            if retired {
                &original_name
            } else {
                &retired_name
            },
        ) {
            Ok(false) => {}
            Ok(true) => return Ok(GcRemoval::Unrecognized),
            Err(error) if unexpected(&error) || error.kind() == io::ErrorKind::InvalidInput => {
                return Ok(GcRemoval::Unrecognized)
            }
            Err(error) => return Err(error),
        }
        let directory = match open_at(&self.0, current_name, libc::O_RDONLY | libc::O_DIRECTORY) {
            Ok(directory) => directory,
            Err(error) if unexpected(&error) => return Ok(GcRemoval::Unrecognized),
            Err(error) => return Err(error),
        };
        if mount_id(&directory)? != mount_id(&self.0)?
            || !same_entry(&self.0, current_name, &directory)?
        {
            return Ok(GcRemoval::Unrecognized);
        }
        let entries = match names(&directory, 4) {
            Ok(entries) => entries,
            Err(error) if unexpected(&error) => return Ok(GcRemoval::Unrecognized),
            Err(error) => return Err(error),
        };
        let mut files = Vec::new();
        let mut lock = None;
        for entry in &entries {
            if ![
                "rollback.arena",
                "rollback.manifest.0",
                "rollback.manifest.1",
                "rollback.lock",
            ]
            .contains(&entry.as_str())
            {
                return Ok(GcRemoval::Unrecognized);
            }
            let entry_name = name(OsStr::new(entry))?;
            let file = match open_at(&directory, &entry_name, libc::O_RDWR | libc::O_NONBLOCK) {
                Ok(file) => file,
                Err(error) if unexpected(&error) => return Ok(GcRemoval::Unrecognized),
                Err(error) => return Err(error),
            };
            let metadata = file.metadata()?;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || mount_id(&file)? != mount_id(&directory)?
                || !same_entry(&directory, &entry_name, &file)?
            {
                return Ok(GcRemoval::Unrecognized);
            }
            if entry == "rollback.lock" {
                match file.try_lock() {
                    Ok(()) => lock = Some(file),
                    Err(std::fs::TryLockError::WouldBlock) => return Ok(GcRemoval::Live),
                    Err(std::fs::TryLockError::Error(error)) => return Err(error),
                }
            } else {
                files.push((entry_name, file));
            }
        }
        // An original namespace without its durable lifetime lock has no
        // proof that an old State handle is gone. A durable tombstone does.
        if lock.is_none() && !retired {
            return Ok(GcRemoval::Unrecognized);
        }
        if !same_entry(&self.0, current_name, &directory)? {
            return Ok(GcRemoval::Unrecognized);
        }
        if !retired {
            // SAFETY: names are pinned-root children; NOREPLACE prevents an
            // existing retirement namespace from ever being overwritten.
            if unsafe {
                libc::renameat2(
                    self.0.as_raw_fd(),
                    original_name.as_ptr(),
                    self.0.as_raw_fd(),
                    retired_name.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } != 0
            {
                let error = io::Error::last_os_error();
                return if error.kind() == io::ErrorKind::AlreadyExists {
                    Ok(GcRemoval::Unrecognized)
                } else {
                    Err(error)
                };
            }
        }
        if !same_entry(&self.0, &retired_name, &directory)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "GC retirement directory changed",
            ));
        }
        // Re-publish surviving tombstones after a restart too: page-cache
        // visibility alone is not enough to authorize deleting their files.
        self.0.sync_all()?;
        for (entry_name, file) in &files {
            if file.metadata()?.nlink() != 1 || !same_entry(&directory, entry_name, file)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "GC retired file changed",
                ));
            }
            // SAFETY: pinned namespace and exact regular-file inode checked.
            if unsafe { libc::unlinkat(directory.as_raw_fd(), entry_name.as_ptr(), 0) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        directory.sync_all()?;
        if let Some(file) = &lock {
            if file.metadata()?.nlink() != 1 || !same_entry(&directory, c"rollback.lock", file)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "GC retired lock changed",
                ));
            }
            // Keep the acquired lock descriptor alive through rmdir + fsync.
            if unsafe { libc::unlinkat(directory.as_raw_fd(), c"rollback.lock".as_ptr(), 0) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        if !same_entry(&self.0, &retired_name, &directory)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "GC retired directory changed",
            ));
        }
        // SAFETY: removes only this verified empty directory, never recursive.
        if unsafe {
            libc::unlinkat(
                self.0.as_raw_fd(),
                retired_name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        self.0.sync_all()?;
        Ok(GcRemoval::Removed)
    }
}

impl Backing for FileBacking {
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        Ok(Arc::new(RealFile {
            file: self.directory.open_file(path, create)?,
        }))
    }

    fn exists(&self, path: &str) -> io::Result<bool> {
        match self.directory.parent(path) {
            Ok((parent, child)) => entry_exists(&parent, &child),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn remove(&self, path: &str) -> io::Result<()> {
        let (parent, child) = self.directory.parent(path)?;
        entry_exists(&parent, &child)?;
        // SAFETY: unlinkat removes the named entry, never follows a final link.
        if unsafe { libc::unlinkat(parent.as_raw_fd(), child.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        let (source, from) = self.directory.parent(from)?;
        let (target, to) = self.directory.parent(to)?;
        entry_exists(&source, &from)?;
        entry_exists(&target, &to)?;
        // SAFETY: pinned parents and valid names. renameat never follows a final
        // symlink; a concurrent link replacement can move only the link itself.
        if unsafe {
            libc::renameat(
                source.as_raw_fd(),
                from.as_ptr(),
                target.as_raw_fd(),
                to.as_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn create_dir_all(&self, path: &str) -> io::Result<()> {
        validate(path, false)?;
        self.directory.directory(path, true).map(|_| ())
    }

    fn list(&self, path: &str) -> io::Result<Vec<String>> {
        let directory = self.directory.directory(path, false)?;
        let fd = open_at(&directory, c".", libc::O_RDONLY | libc::O_DIRECTORY)?.into_raw_fd();
        // SAFETY: fdopendir takes ownership on success; on failure we close fd.
        let raw = unsafe { libc::fdopendir(fd) };
        if raw.is_null() {
            let error = io::Error::last_os_error();
            drop(unsafe { File::from_raw_fd(fd) });
            return Err(error);
        }
        let stream = DirectoryStream(raw);
        let mut names = Vec::new();
        loop {
            // SAFETY: stream is private to this call. Clear this thread's errno
            // to distinguish end-of-directory from an error; copy d_name before
            // the next readdir, which may invalidate its storage.
            unsafe { *libc::__errno_location() = 0 };
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(0) {
                    return Err(error);
                }
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if name != c"." && name != c".." {
                names.push(name.to_string_lossy().into_owned());
            }
        }
        names.sort();
        Ok(names)
    }

    fn sync_dir(&self, path: &str) -> io::Result<()> {
        let directory = self.directory.directory(path, false)?;
        open_at(&directory, c".", libc::O_RDONLY | libc::O_DIRECTORY)?.sync_all()
    }

    fn try_lock(&self, path: &str) -> io::Result<Box<dyn VolumeLock>> {
        let file = self.directory.open_file(path, true)?;
        match file.try_lock() {
            Ok(()) => Ok(Box::new(FileLock { _file: file })),
            Err(std::fs::TryLockError::WouldBlock) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "VOLUME_ALREADY_ATTACHED",
            )),
            Err(std::fs::TryLockError::Error(error)) => Err(error),
        }
    }

    fn free_bytes(&self) -> io::Result<Option<u64>> {
        // SAFETY: fstatvfs writes into initialized storage using the pinned root.
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatvfs(self.directory.0.as_raw_fd(), &mut stat) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(
            (stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64),
        ))
    }
}
