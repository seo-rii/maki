//! Real-filesystem backing rooted at a volume directory.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::path::validate;
use crate::{Backing, BackingFile, VolumeLock};

/// `Backing` over a real directory tree. Paths are validated so no operation
/// can escape `root`.
pub struct FileBacking {
    root: PathBuf,
}

impl FileBacking {
    pub fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        create_private_dir_all(&root)?;
        Ok(Self { root })
    }

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
}

/// `OpenOptions` that never follow a symlink at the final component and
/// create files owner-only (SPEC §8: data, journal and metadata files are
/// `maki:maki 0600`).
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

    fn len(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    fn sync_data(&self) -> io::Result<()> {
        self.file.sync_data()
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

struct FileLock {
    _file: File,
}

impl VolumeLock for FileLock {}

impl Backing for FileBacking {
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        let p = self.resolve(path, false)?;
        let file = open_options()
            .read(true)
            .write(true)
            .create(create)
            .open(&p)?;
        Ok(Arc::new(RealFile { file }))
    }

    fn exists(&self, path: &str) -> io::Result<bool> {
        Ok(self.resolve(path, false)?.exists())
    }

    fn remove(&self, path: &str) -> io::Result<()> {
        fs::remove_file(self.resolve(path, false)?)
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        fs::rename(self.resolve(from, false)?, self.resolve(to, false)?)
    }

    fn create_dir_all(&self, path: &str) -> io::Result<()> {
        create_private_dir_all(&self.resolve(path, false)?)
    }

    fn list(&self, dir: &str) -> io::Result<Vec<String>> {
        let p = self.resolve(dir, true)?;
        let mut names = Vec::new();
        for entry in fs::read_dir(p)? {
            names.push(entry?.file_name().to_string_lossy().into_owned());
        }
        names.sort();
        Ok(names)
    }

    fn sync_dir(&self, dir: &str) -> io::Result<()> {
        let p = self.resolve(dir, true)?;
        sync_dir_impl(&p)
    }

    fn try_lock(&self, path: &str) -> io::Result<Box<dyn VolumeLock>> {
        let p = self.resolve(path, false)?;
        let file = open_options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&p)?;
        match file.try_lock() {
            Ok(()) => Ok(Box::new(FileLock { _file: file })),
            Err(std::fs::TryLockError::WouldBlock) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "VOLUME_ALREADY_ATTACHED",
            )),
            Err(std::fs::TryLockError::Error(e)) => Err(e),
        }
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
}

#[cfg(unix)]
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
