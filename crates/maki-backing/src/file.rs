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
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn resolve(&self, rel: &str, allow_empty: bool) -> io::Result<PathBuf> {
        validate(rel, allow_empty)?;
        let mut p = self.root.clone();
        for comp in rel.split('/').filter(|c| !c.is_empty()) {
            p.push(comp);
        }
        Ok(p)
    }
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
        let file = OpenOptions::new()
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
        fs::create_dir_all(self.resolve(path, false)?)
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
        let file = OpenOptions::new()
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
}
