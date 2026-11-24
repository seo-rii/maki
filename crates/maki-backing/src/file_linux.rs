//! Linux namespace operations are relative to open directories, never a
//! previously checked absolute pathname. A renamed root stays the same volume.

use std::collections::BinaryHeap;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
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

/// Open `child`, creating it owner-only (`0600`) when it is missing. A new
/// file belongs to this process's user, except that a root process creates
/// it for the owner of `parent` when another user owns that directory
/// ([`new_entry_owner`]): a lock file or manifest slot that a root-run
/// offline check recreates must not lock the daemon user out of its own
/// volume. An existing entry is opened as it is; root gives away only a
/// file it has just created.
fn create_or_open(parent: &File, child: &CStr, access: i32) -> io::Result<File> {
    match creation_owner(parent)? {
        None => open_at(parent, child, access | libc::O_CREAT),
        Some(owner) => create_or_open_for(parent, child, access, owner, true),
    }
}

/// The owner [`new_entry_owner`] picks for an entry this process creates
/// in `parent`, if not this process's user.
fn creation_owner(parent: &File) -> io::Result<Option<crate::FileOwner>> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        return Ok(None);
    }
    let metadata = parent.metadata()?;
    Ok(new_entry_owner(
        euid,
        crate::FileOwner {
            uid: metadata.uid(),
            gid: metadata.gid(),
        },
    ))
}

/// The owner an entry that a process with effective uid `euid` creates in
/// a directory owned by `directory` must be given, if not its creator. Only
/// root can give an entry away, and only a directory another user owns
/// needs it. That user can already create and replace every entry there,
/// so a new one root creates for them gives them nothing they lack, and
/// root never gives an entry to anyone else. A root-owned directory gets
/// root's entries, as the daemon could not create any there either.
fn new_entry_owner(euid: u32, directory: crate::FileOwner) -> Option<crate::FileOwner> {
    (euid == 0 && directory.uid != 0).then_some(directory)
}

/// [`child_dir`] creating a missing directory inside the backing root. Like
/// a file ([`create_or_open`]), it is created for the owner of `parent`
/// when a root process creates it in a directory another user owns. The
/// root itself and missing ancestors of it (`Directory::new`) belong to the
/// user that runs the process.
fn create_or_open_dir(parent: &File, child: &CStr) -> io::Result<File> {
    let Some(owner) = creation_owner(parent)? else {
        return child_dir(parent, child, true);
    };
    match open_at(parent, child, libc::O_PATH | libc::O_DIRECTORY) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        existing => return existing,
    }
    // SAFETY: both arguments remain valid through mkdirat; no symlink is
    // followed.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), child.as_ptr(), 0o700) } == 0 {
        give_new_directory(parent, child, owner)?;
    } else {
        let error = io::Error::last_os_error();
        // Another process created it meanwhile: open theirs as it is.
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(error);
        }
    }
    open_at(parent, child, libc::O_PATH | libc::O_DIRECTORY)
}

/// Give the directory this process has just created as `child` to `owner`,
/// durably. A directory cannot be created unnamed, so the parent's owner
/// could swap another one in under that name: whatever directory the name
/// holds is given away only while it is empty and this process's user's
/// (root's), which only a root process can have made, so nothing that holds
/// an entry or belongs to anyone else changes owner. A refused change
/// removes it again. A crash before the change leaves an empty root-owned
/// directory, which a later run opens as it is.
fn give_new_directory(parent: &File, child: &CStr, owner: crate::FileOwner) -> io::Result<()> {
    let directory = open_at(parent, child, libc::O_RDONLY | libc::O_DIRECTORY)?;
    let mut empty = true;
    visit_names(&directory, |_| {
        empty = false;
        Ok(())
    })?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    if directory.metadata()?.uid() != unsafe { libc::geteuid() } || !empty {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a backing directory changed while it was being created",
        ));
    }
    if let Err(error) = give(&directory, owner) {
        // SAFETY: pinned parent and NUL-terminated name; AT_REMOVEDIR
        // removes only an empty directory.
        unsafe { libc::unlinkat(parent.as_raw_fd(), child.as_ptr(), libc::AT_REMOVEDIR) };
        return Err(error);
    }
    Ok(())
}

/// [`create_or_open`] for a file that must be created for `owner`.
/// `unnamed` tries an `O_TMPFILE` creation first; tests clear it to cover
/// filesystems without one.
fn create_or_open_for(
    parent: &File,
    child: &CStr,
    access: i32,
    owner: crate::FileOwner,
    unnamed: bool,
) -> io::Result<File> {
    match open_at(parent, child, access) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        existing => return existing,
    }
    match create_for(parent, child, access, owner, unnamed)? {
        Some(file) => Ok(file),
        // Another process created the entry meanwhile: open theirs as it is.
        None => open_at(parent, child, access),
    }
}

/// Create `child` for `owner`, or `None` when an entry of that name exists.
/// The file is created unnamed (`O_TMPFILE`), given away and synced with
/// fsync (fdatasync need not persist an owner change) before it is linked
/// under its name, so the name never shows a root-owned file, even after a
/// crash, and a refused owner change leaves nothing behind. Where the
/// filesystem has no unnamed files, the file is created under its name and
/// given away at once; when that fails it is removed again.
fn create_for(
    parent: &File,
    child: &CStr,
    access: i32,
    owner: crate::FileOwner,
    unnamed: bool,
) -> io::Result<Option<File>> {
    if unnamed {
        // An unnamed file needs write access. A caller that asked for a
        // read-only descriptor takes a lock with it and never writes.
        match open_at(
            parent,
            c".",
            libc::O_TMPFILE | libc::O_RDWR | (access & libc::O_NONBLOCK),
        ) {
            Ok(file) => {
                give(&file, owner)?;
                match link_unnamed(&file, parent, child) {
                    Ok(()) => return Ok(Some(file)),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(None),
                    // Linking failed otherwise (no CAP_DAC_READ_SEARCH and
                    // no /proc, for one): the named form below either
                    // works or reports what stops it.
                    Err(_) => {}
                }
            }
            Err(error) if matches!(error.raw_os_error(), Some(libc::EOPNOTSUPP | libc::EISDIR)) => {
            }
            Err(error) => return Err(error),
        }
    }
    let file = match open_at(parent, child, access | libc::O_CREAT | libc::O_EXCL) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(None),
        Err(error) => return Err(error),
    };
    if let Err(error) = give(&file, owner) {
        // Leave no file its directory's owner cannot open. SAFETY: pinned
        // parent and NUL-terminated name; unlinkat never follows a link.
        unsafe { libc::unlinkat(parent.as_raw_fd(), child.as_ptr(), 0) };
        return Err(error);
    }
    Ok(Some(file))
}

/// Give an entry this process has just created, and nothing has written,
/// to `owner`, and make the change durable.
fn give(entry: &File, owner: crate::FileOwner) -> io::Result<()> {
    std::os::unix::fs::fchown(entry, Some(owner.uid), Some(owner.gid)).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "cannot create the backing entry for the owner of its directory (uid {}, gid \
                 {}): {error}",
                owner.uid, owner.gid
            ),
        )
    })?;
    entry.sync_all()
}

/// Link an unnamed (`O_TMPFILE`) file as `child`; `AlreadyExists` when the
/// name is taken.
fn link_unnamed(file: &File, parent: &File, child: &CStr) -> io::Result<()> {
    match link_descriptor(file, parent, child) {
        // AT_EMPTY_PATH needs CAP_DAC_READ_SEARCH before Linux 6.10, and a
        // unit's bounding set can drop it; linking the descriptor's /proc
        // entry does not.
        Err(error) if error.kind() != io::ErrorKind::AlreadyExists => {
            link_through_proc(file, parent, child)
        }
        linked => linked,
    }
}

fn link_descriptor(file: &File, parent: &File, child: &CStr) -> io::Result<()> {
    // SAFETY: open descriptors and NUL-terminated names; AT_EMPTY_PATH
    // names the file descriptor itself.
    if unsafe {
        libc::linkat(
            file.as_raw_fd(),
            c"".as_ptr(),
            parent.as_raw_fd(),
            child.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn link_through_proc(file: &File, parent: &File, child: &CStr) -> io::Result<()> {
    let path = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "descriptor path"))?;
    // SAFETY: open descriptor and NUL-terminated names; AT_SYMLINK_FOLLOW
    // resolves the descriptor's link to the file itself.
    if unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            path.as_ptr(),
            parent.as_raw_fd(),
            child.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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

fn writable_directory(directory: &File) -> io::Result<bool> {
    // Use the held directory and effective credentials, including ACLs and
    // read-only mounts. This call cannot create a child in search-only
    // ancestors, so it does not require a publication barrier for them.
    if unsafe {
        libc::faccessat(
            directory.as_raw_fd(),
            c".".as_ptr(),
            libc::W_OK,
            libc::AT_EACCESS,
        )
    } == 0
    {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::EACCES | libc::EROFS) => Ok(false),
        _ => Err(error),
    }
}

impl Directory {
    pub(super) fn new(root: &Path) -> io::Result<Self> {
        Self::new_with_sync(root, File::sync_all)
    }

    fn new_with_sync(
        root: &Path,
        mut sync: impl FnMut(&File) -> io::Result<()>,
    ) -> io::Result<Self> {
        let mut directory = File::open(if root.is_absolute() { "/" } else { "." })?;
        let mut parents = Vec::new();
        for component in root.components() {
            match component {
                Component::RootDir | Component::CurDir => continue,
                // The configured root may be relative on development callers;
                // parent traversal is allowed only while selecting that root.
                Component::Normal(_) | Component::ParentDir => {
                    let child = name(component.as_os_str())?;
                    let mut sync_parent = None;
                    let next = match open_at(&directory, &child, libc::O_PATH | libc::O_DIRECTORY) {
                        Ok(next) => next,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {
                            // O_PATH cannot be fsynced. Establish the ability
                            // to sync before mkdir, so an unreadable parent
                            // cannot leave an entry that retries would skip.
                            sync_parent = Some(open_at(
                                &directory,
                                c".",
                                libc::O_RDONLY | libc::O_DIRECTORY,
                            )?);
                            child_dir(&directory, &child, true)?
                        }
                        Err(error) => return Err(error),
                    };
                    if directory.metadata()?.dev() != next.metadata()?.dev() {
                        // Ancestors on another filesystem cannot contain
                        // entries created while opening this backing root.
                        // Do not flush unrelated mounts or retain their FDs.
                        parents.clear();
                    } else {
                        if sync_parent.is_none() && writable_directory(&directory)? {
                            sync_parent =
                                match open_at(&directory, c".", libc::O_RDONLY | libc::O_DIRECTORY)
                                {
                                    Ok(parent) => Some(parent),
                                    // Existing known paths need only search
                                    // permission; this call did not create them.
                                    Err(error)
                                        if error.kind() == io::ErrorKind::PermissionDenied =>
                                    {
                                        None
                                    }
                                    Err(error) => return Err(error),
                                };
                        }
                        if let Some(parent) = sync_parent {
                            parents.push(parent);
                        }
                    }
                    directory = next;
                }
                Component::Prefix(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid Linux root",
                    ))
                }
            }
        }
        let root = open_at(&directory, c".", libc::O_RDONLY | libc::O_DIRECTORY)?;
        if writable_directory(&root)? {
            sync(&root)?;
        }
        // Re-sync existing writable parents too: after a failed directory
        // sync, the next opener sees EEXIST but still owes the same barrier.
        // Bottom-up order persists each new directory before its own name.
        for parent in parents.iter().rev() {
            sync(parent)?;
        }
        Ok(Self(root))
    }

    /// Pin an existing root for reading only: each component is opened
    /// without following a symlink, and nothing is created, probed for write
    /// access or synced (an immutable directory answers that probe EPERM).
    pub(super) fn existing(root: &Path) -> io::Result<Self> {
        let mut directory = File::open(if root.is_absolute() { "/" } else { "." })?;
        for component in root.components() {
            match component {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(_) | Component::ParentDir => {
                    let child = name(component.as_os_str())?;
                    directory = open_at(&directory, &child, libc::O_PATH | libc::O_DIRECTORY)?;
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

    pub(super) fn root_metadata(&self) -> io::Result<std::fs::Metadata> {
        self.0.metadata()
    }

    pub(super) fn entry_metadata(&self, path: &str) -> io::Result<std::fs::Metadata> {
        let (parent, child) = self.parent(path)?;
        // O_PATH with O_NOFOLLOW describes a final symlink itself and does
        // not block on a FIFO.
        open_at(&parent, &child, libc::O_PATH)?.metadata()
    }

    fn directory(&self, path: &str, create: bool) -> io::Result<File> {
        validate(path, true)?;
        // Opening '.' creates an independent directory stream offset. dup()
        // would share it and repeated/concurrent list calls could miss entries.
        let mut directory = child_dir(&self.0, c".", false)?;
        for component in path.split('/').filter(|part| !part.is_empty()) {
            let component = name(OsStr::new(component))?;
            directory = if create {
                create_or_open_dir(&directory, &component)?
            } else {
                child_dir(&directory, &component, false)?
            };
        }
        Ok(directory)
    }

    fn parent(&self, path: &str) -> io::Result<(File, CString)> {
        validate(path, false)?;
        let (parent, child) = path.rsplit_once('/').unwrap_or(("", path));
        Ok((self.directory(parent, false)?, name(OsStr::new(child))?))
    }

    fn open_file(&self, path: &str, create: bool, read_only: bool) -> io::Result<File> {
        let (parent, child) = self.parent(path)?;
        let access = if read_only {
            libc::O_RDONLY
        } else {
            libc::O_RDWR
        } | libc::O_NONBLOCK;
        let file = if create {
            create_or_open(&parent, &child, access)?
        } else {
            open_at(&parent, &child, access)?
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "backing entry is not a regular file",
            ));
        }
        // O_NOFOLLOW does not reject hardlinks. Inspect the opened inode,
        // including existing files opened with O_CREAT and volume locks.
        // This cannot prevent another link from being added after the check.
        if metadata.nlink() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "backing entry must have exactly one hard link",
            ));
        }
        Ok(file)
    }

    /// A lock file opened read-only, created first only if it is missing.
    pub(super) fn lock_file(&self, path: &str) -> io::Result<File> {
        match self.open_file(path, false, true) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.open_file(path, true, true)
            }
            file => file,
        }
    }
}

#[cfg(test)]
#[path = "root_directory_tests.rs"]
mod root_directory_tests;

#[cfg(test)]
#[path = "creation_owner_tests.rs"]
mod creation_owner_tests;

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

/// Visit each entry's exact name bytes; a name need not be UTF-8.
fn visit_names(
    directory: &File,
    mut visit: impl FnMut(&OsStr) -> io::Result<()>,
) -> io::Result<()> {
    // A fresh open file description gives each scan its own directory offset.
    let fd = open_at(directory, c".", libc::O_RDONLY | libc::O_DIRECTORY)?.into_raw_fd();
    // SAFETY: fdopendir takes ownership on success; on failure we close fd.
    let raw = unsafe { libc::fdopendir(fd) };
    if raw.is_null() {
        let error = io::Error::last_os_error();
        drop(unsafe { File::from_raw_fd(fd) });
        return Err(error);
    }
    let stream = DirectoryStream(raw);
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
        visit(OsStr::from_bytes(name.to_bytes()))?;
    }
    Ok(())
}

/// A directory's sorted entry names for `Backing::list`, each exactly as
/// stored. A name that is not UTF-8 fails the listing, unless
/// `skip_non_utf8` leaves it out; it is never converted lossily, which
/// could return a name that opens a different entry.
fn utf8_names(directory: &File, skip_non_utf8: bool) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    visit_names(directory, |name| {
        match name.to_str() {
            Some(name) => names.push(name.to_owned()),
            None if skip_non_utf8 => {}
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "directory entry name is not UTF-8",
                ))
            }
        }
        Ok(())
    })?;
    names.sort();
    Ok(names)
}

/// A namespace's entries for retirement, which must account for each one:
/// a name that is not UTF-8 fails the scan, so the namespace is kept.
fn names(directory: &File, maximum: usize) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    visit_names(directory, |name| {
        let name = name.to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "non-UTF8 GC directory entry")
        })?;
        if names.len() == maximum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "GC directory entry bound exceeded",
            ));
        }
        names.push(name.to_owned());
        Ok(())
    })?;
    names.sort();
    Ok(names)
}

/// The smallest `maximum` names above `after`, ordered by their bytes, so a
/// name that is not UTF-8 is listed exactly once like any other.
fn names_after(
    directory: &File,
    after: Option<&OsStr>,
    maximum: usize,
) -> io::Result<Vec<OsString>> {
    assert!(maximum > 0);
    let mut page = BinaryHeap::<OsString>::new();
    visit_names(directory, |name| {
        if after.is_some_and(|after| name <= after) {
            return Ok(());
        }
        if page.len() < maximum {
            page.push(name.to_owned());
        } else if let Some(mut largest) = page.peek_mut() {
            if name < largest.as_os_str() {
                *largest = name.to_owned();
            }
        }
        Ok(())
    })?;
    Ok(page.into_sorted_vec())
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
    // libc identity fields can be narrower than MetadataExt's u64 on Linux ABIs.
    #[allow(clippy::unnecessary_cast)]
    let matches = stat.st_dev as u64 == metadata.dev() && stat.st_ino as u64 == metadata.ino();
    Ok(matches)
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

/// Name the step of a candidate's examination or retirement that `error`
/// stopped.
fn examining(step: impl std::fmt::Display, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{step}: {error}"))
}

/// Whether `directory` carries the immutable or the append-only flag. A
/// filesystem without the flags has neither.
fn immutable_or_append_only(directory: &File) -> bool {
    const FS_IMMUTABLE_FL: libc::c_int = 0x10;
    const FS_APPEND_FL: libc::c_int = 0x20;
    let mut flags: libc::c_int = 0;
    // SAFETY: valid descriptor; FS_IOC_GETFLAGS writes one int.
    let read = unsafe { libc::ioctl(directory.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut flags) };
    read == 0 && (flags & (FS_IMMUTABLE_FL | FS_APPEND_FL)) != 0
}

/// A retirement that stopped at a step changing the candidate alone.
fn unfinished(tombstone: bool, step: impl std::fmt::Display, error: io::Error) -> GcRemoval {
    GcRemoval::Unfinished {
        tombstone,
        error: examining(step, error),
    }
}

/// A stale namespace that passed examination: it holds only known,
/// single-link regular files on the root's mount, and this pass holds its
/// lifetime lock if the lock file is still there.
struct GcCandidate {
    directory: File,
    files: Vec<(CString, File)>,
    lock: Option<FileLock>,
}

enum GcExamined {
    Quiescent(GcCandidate),
    /// Live or unrecognized: kept, and nothing failed.
    Kept(GcRemoval),
}

impl Directory {
    pub(super) fn gc_entries(&self, after: Option<&OsStr>) -> io::Result<Vec<OsString>> {
        names_after(&self.0, after, 4096)
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

    /// Open and check one retirement candidate, changing nothing. Every
    /// error returned here is a failure to open or examine that candidate
    /// (its directory, its listing, one of its files or its lifetime lock),
    /// named with the step it stopped. It says nothing about the root or
    /// about any other candidate.
    fn gc_examine(
        &self,
        current_name: &CStr,
        counterpart: &CStr,
        retired: bool,
        root_mount: u64,
    ) -> io::Result<GcExamined> {
        let unrecognized = || Ok(GcExamined::Kept(GcRemoval::Unrecognized));
        // Collision refusal ensures no retired path can stand in for an
        // existing original session or overwrite another directory.
        match entry_exists(&self.0, counterpart) {
            Ok(false) => {}
            Ok(true) => return unrecognized(),
            Err(error) if unexpected(&error) || error.kind() == io::ErrorKind::InvalidInput => {
                return unrecognized()
            }
            Err(error) => return Err(examining("checking for a retirement collision", error)),
        }
        let directory = match open_at(&self.0, current_name, libc::O_RDONLY | libc::O_DIRECTORY) {
            Ok(directory) => directory,
            Err(error) if unexpected(&error) => return unrecognized(),
            Err(error) => return Err(examining("opening the namespace directory", error)),
        };
        let inspecting = |error| examining("examining the namespace directory", error);
        let mount = mount_id(&directory).map_err(inspecting)?;
        if mount != root_mount
            || !same_entry(&self.0, current_name, &directory).map_err(inspecting)?
        {
            return unrecognized();
        }
        let entries = match names(&directory, 4) {
            Ok(entries) => entries,
            Err(error) if unexpected(&error) => return unrecognized(),
            Err(error) => return Err(examining("listing the namespace", error)),
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
                return unrecognized();
            }
            let entry_name = name(OsStr::new(entry))?;
            let file = match open_at(&directory, &entry_name, libc::O_RDWR | libc::O_NONBLOCK) {
                Ok(file) => file,
                Err(error) if unexpected(&error) => return unrecognized(),
                Err(error) => return Err(examining(format_args!("opening {entry}"), error)),
            };
            let inspecting = |error| examining(format_args!("examining {entry}"), error);
            let metadata = file.metadata().map_err(inspecting)?;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || mount_id(&file).map_err(inspecting)? != mount
                || !same_entry(&directory, &entry_name, &file).map_err(inspecting)?
            {
                return unrecognized();
            }
            if entry == "rollback.lock" {
                match file.try_lock() {
                    // `FileLock` unlocks on every return, here and in the
                    // caller.
                    Ok(()) => lock = Some(FileLock { file }),
                    Err(std::fs::TryLockError::WouldBlock) => {
                        return Ok(GcExamined::Kept(GcRemoval::Live))
                    }
                    // A lock that could not be tried is not a free lock.
                    Err(std::fs::TryLockError::Error(error)) => {
                        return Err(examining("locking rollback.lock", error))
                    }
                }
            } else {
                files.push((entry_name, file));
            }
        }
        // An original namespace without its durable lifetime lock has no
        // proof that an old State handle is gone. A durable tombstone does.
        if lock.is_none() && !retired {
            return unrecognized();
        }
        if !same_entry(&self.0, current_name, &directory).map_err(inspecting)? {
            return unrecognized();
        }
        Ok(GcExamined::Quiescent(GcCandidate {
            directory,
            files,
            lock,
        }))
    }

    /// Called only while the root operation lock excludes all physical forks.
    /// Retirement is made durable before any ciphertext is unlinked.
    ///
    /// A candidate that cannot be opened or examined is returned as
    /// [`GcRemoval::Unreadable`]: nothing about it has been changed, and
    /// the failure says nothing about any other candidate, so the caller
    /// keeps it and goes on. A step of its retirement that changes the
    /// candidate alone (its rename when its own directory is immutable or
    /// append-only, which changes nothing, an unlink in it, the sync of its
    /// directory, its removal) that fails is
    /// returned as [`GcRemoval::Unfinished`]: the tombstone, once renamed,
    /// is already durable, and every other candidate's deletion rests on its
    /// own examination, lock and durable tombstone, so the caller keeps it
    /// as the step left it and goes on; a later pass resumes it. An error is
    /// returned only for the root itself (its mount identity, its syncs, a
    /// rename it or its filesystem refuses) and for an entry that changed
    /// identity while it was being retired, which only something other than
    /// this pass can have done.
    pub(super) fn gc_retire(&self, original: &str, retired: bool) -> io::Result<GcRemoval> {
        validate(original, false)?;
        if original.contains('/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "GC namespace is not a root child",
            ));
        }
        let original_name = name(OsStr::new(original))?;
        let retired_name = name(OsStr::new(&format!(".remote-gc-{original}")))?;
        let (current_name, counterpart) = if retired {
            (&retired_name, &original_name)
        } else {
            (&original_name, &retired_name)
        };
        let root_mount = mount_id(&self.0)?;
        let GcCandidate {
            directory,
            files,
            lock,
        } = match self.gc_examine(current_name, counterpart, retired, root_mount) {
            Ok(GcExamined::Quiescent(candidate)) => candidate,
            Ok(GcExamined::Kept(kept)) => return Ok(kept),
            Err(error) => return Ok(GcRemoval::Unreadable(error)),
        };
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
                // Renaming a directory inside its parent needs no
                // permission on the directory itself, so a failure is the
                // root's or its filesystem's (no write permission on the
                // root, a read-only or full filesystem, an append-only root,
                // an I/O error) and ends the pass, except the namespace's own
                // immutable or append-only flag, which concerns it alone when
                // the root carries neither.
                // Nothing has been renamed either way.
                return if error.kind() == io::ErrorKind::AlreadyExists {
                    Ok(GcRemoval::Unrecognized)
                } else if error.raw_os_error() == Some(libc::EPERM)
                    && immutable_or_append_only(&directory)
                    && !immutable_or_append_only(&self.0)
                {
                    Ok(unfinished(
                        false,
                        "renaming the immutable or append-only namespace directory to its \
                         tombstone",
                        error,
                    ))
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
                return Ok(unfinished(
                    true,
                    format_args!("unlinking {}", entry_name.to_string_lossy()),
                    io::Error::last_os_error(),
                ));
            }
        }
        // A failed sync is not retried here: the next pass lists what this
        // directory holds again and repeats every step from there.
        if let Err(error) = directory.sync_all() {
            return Ok(unfinished(true, "syncing the tombstone directory", error));
        }
        if let Some(FileLock { file }) = &lock {
            if file.metadata()?.nlink() != 1 || !same_entry(&directory, c"rollback.lock", file)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "GC retired lock changed",
                ));
            }
            // Keep the acquired lock descriptor alive through rmdir + fsync.
            if unsafe { libc::unlinkat(directory.as_raw_fd(), c"rollback.lock".as_ptr(), 0) } != 0 {
                return Ok(unfinished(
                    true,
                    "unlinking rollback.lock",
                    io::Error::last_os_error(),
                ));
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
            return Ok(unfinished(
                true,
                "removing the tombstone directory",
                io::Error::last_os_error(),
            ));
        }
        self.0.sync_all()?;
        Ok(GcRemoval::Removed)
    }
}

impl Backing for FileBacking {
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        if create {
            self.writable()?;
        }
        Ok(Arc::new(RealFile {
            file: self.directory.open_file(path, create, self.read_only)?,
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
        self.writable()?;
        let (parent, child) = self.directory.parent(path)?;
        entry_exists(&parent, &child)?;
        // SAFETY: unlinkat removes the named entry, never follows a final link.
        if unsafe { libc::unlinkat(parent.as_raw_fd(), child.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        self.writable()?;
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
        self.writable()?;
        validate(path, false)?;
        self.directory.directory(path, true).map(|_| ())
    }

    fn list(&self, path: &str) -> io::Result<Vec<String>> {
        utf8_names(&self.directory.directory(path, false)?, false)
    }

    fn list_skipping_non_utf8(&self, path: &str) -> io::Result<Vec<String>> {
        utf8_names(&self.directory.directory(path, false)?, true)
    }

    fn sync_dir(&self, path: &str) -> io::Result<()> {
        self.writable()?;
        let directory = self.directory.directory(path, false)?;
        open_at(&directory, c".", libc::O_RDONLY | libc::O_DIRECTORY)?.sync_all()
    }

    fn try_lock(&self, path: &str) -> io::Result<Box<dyn VolumeLock>> {
        self.writable()?;
        let file = self.directory.open_file(path, true, false)?;
        match file.try_lock() {
            Ok(()) => Ok(Box::new(FileLock { file })),
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
        // libc counter widths vary by ABI; widen before the saturating product.
        #[allow(clippy::unnecessary_cast)]
        let available = (stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64);
        Ok(Some(available))
    }

    fn directory_owner(&self, dir: &str) -> io::Result<Option<crate::FileOwner>> {
        let metadata = self.directory.directory(dir, false)?.metadata()?;
        Ok(Some(crate::FileOwner {
            uid: metadata.uid(),
            gid: metadata.gid(),
        }))
    }
}
