//! Linux namespace operations are relative to open directories, never a
//! previously checked absolute pathname. A renamed root stays the same volume.

use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};
use std::sync::Arc;

use super::{Backing, BackingFile, FileBacking, FileLock, RealFile, VolumeLock};
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
