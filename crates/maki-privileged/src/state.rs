//! Root-controlled attach state. Every directory is opened relative to an
//! already verified descriptor; symlinks and non-root writable ancestors
//! are refused before any lock or record is opened.

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

use crate::config::{check_abs_path, check_lvm_name, check_uuid, check_volume_name};
use crate::plan::{AttachmentIdentity, BOUND_DEVICE_RECORD_DIR};
use crate::probe::nbd_index;

const RECORD_MAX_BYTES: u64 = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BoundDeviceRecord {
    pub version: u32,
    pub volume: String,
    pub attachment: AttachmentIdentity,
    pub device: String,
    /// Passed to nbd-client's netlink identifier and checked against the
    /// live kernel backend attribute, including before rollback.
    pub connection_id: String,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

impl BoundDeviceRecord {
    fn validate(&self) -> io::Result<()> {
        check_volume_name(&self.volume).map_err(|e| invalid(e.to_string()))?;
        check_uuid("volume_uuid", &self.attachment.volume_uuid)
            .map_err(|e| invalid(e.to_string()))?;
        check_abs_path("nbd_socket", &self.attachment.nbd_socket)
            .map_err(|e| invalid(e.to_string()))?;
        check_abs_path("mountpoint", &self.attachment.mountpoint)
            .map_err(|e| invalid(e.to_string()))?;
        check_lvm_name("vg_name", &self.attachment.vg_name).map_err(|e| invalid(e.to_string()))?;
        check_lvm_name("lv_name", &self.attachment.lv_name).map_err(|e| invalid(e.to_string()))?;
        let nonce = self
            .connection_id
            .strip_prefix("maki-")
            .ok_or_else(|| invalid("invalid attachment identifier"))?;
        check_uuid("connection_id", nonce).map_err(|e| invalid(e.to_string()))?;
        if self.version != 1 || nbd_index(&self.device).is_none() {
            return Err(invalid("unsupported or invalid attach record"));
        }
        Ok(())
    }
}

pub(crate) struct TrustedState {
    directory: File,
    owner: u32,
}

fn trusted_directory(file: &File, owner: u32) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "attach state ancestor must be a root-owned directory without group/other write access",
        ));
    }
    Ok(())
}

fn private_regular_file(file: &File, owner: u32) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "attach state must be a private root-owned regular file with one link",
        ));
    }
    Ok(())
}

fn openat(directory: &File, name: &CString, flags: i32, mode: u32) -> io::Result<File> {
    // SAFETY: the directory descriptor and NUL-terminated name are valid;
    // a successful open returns a new descriptor owned by the File.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            mode,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

impl TrustedState {
    pub fn open() -> io::Result<Self> {
        Self::open_beneath(
            File::open("/")?,
            Path::new(BOUND_DEVICE_RECORD_DIR)
                .strip_prefix("/")
                .unwrap(),
            0,
        )
    }

    pub(crate) fn open_beneath(
        mut directory: File,
        relative: &Path,
        owner: u32,
    ) -> io::Result<Self> {
        trusted_directory(&directory, owner)?;
        let components: Vec<_> = relative.components().collect();
        for (index, component) in components.iter().enumerate() {
            let Component::Normal(name) = component else {
                return Err(invalid(
                    "attach state directory must use normal relative components",
                ));
            };
            let name = CString::new(name.as_bytes()).map_err(|_| invalid("invalid directory"))?;
            let flags = libc::O_RDONLY | libc::O_DIRECTORY;
            let child = match openat(&directory, &name, flags, 0) {
                Ok(child) => child,
                Err(e) if e.kind() == io::ErrorKind::NotFound && index + 1 == components.len() => {
                    // Only the final helper directory may be created. Its
                    // parent has already been verified through a held fd.
                    let rc = unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) };
                    if rc != 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
                    {
                        return Err(io::Error::last_os_error());
                    }
                    openat(&directory, &name, flags, 0)?
                }
                Err(e) => return Err(e),
            };
            trusted_directory(&child, owner)?;
            directory = child;
        }
        Ok(Self { directory, owner })
    }

    pub fn lock(&self) -> io::Result<File> {
        let name = CString::new("attach.lock").unwrap();
        let file = openat(&self.directory, &name, libc::O_RDWR | libc::O_CREAT, 0o600)?;
        private_regular_file(&file, self.owner)?;
        file.lock()?;
        Ok(file)
    }

    fn record_name(volume: &str) -> io::Result<CString> {
        check_volume_name(volume).map_err(|e| invalid(e.to_string()))?;
        CString::new(format!("{volume}.nbd")).map_err(|_| invalid("invalid volume name"))
    }

    pub fn read(&self, volume: &str) -> io::Result<Option<BoundDeviceRecord>> {
        let name = Self::record_name(volume)?;
        let file = match openat(&self.directory, &name, libc::O_RDONLY, 0) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        private_regular_file(&file, self.owner)?;
        let mut bytes = Vec::new();
        file.take(RECORD_MAX_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > RECORD_MAX_BYTES {
            return Err(invalid("attach record exceeds size limit"));
        }
        let record: BoundDeviceRecord = serde_json::from_slice(&bytes).map_err(|_| {
            invalid("invalid attach record; legacy device-only records are not trusted")
        })?;
        record.validate()?;
        if record.volume != volume {
            return Err(invalid("attach record belongs to a different volume"));
        }
        Ok(Some(record))
    }

    pub fn write(&self, record: &BoundDeviceRecord) -> io::Result<()> {
        record.validate()?;
        let destination = Self::record_name(&record.volume)?;
        let temporary = CString::new(format!(
            ".{}.{}.{}.tmp",
            record.volume,
            std::process::id(),
            record.connection_id,
        ))
        .map_err(|_| invalid("invalid temporary record name"))?;
        let mut file = openat(
            &self.directory,
            &temporary,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        let result = (|| {
            private_regular_file(&file, self.owner)?;
            let bytes = serde_json::to_vec(record).map_err(|e| invalid(e.to_string()))?;
            if bytes.len() as u64 > RECORD_MAX_BYTES {
                return Err(invalid("attach record exceeds size limit"));
            }
            file.write_all(&bytes)?;
            file.sync_all()?;
            let rc = unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    temporary.as_ptr(),
                    self.directory.as_raw_fd(),
                    destination.as_ptr(),
                )
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            self.directory.sync_all()
        })();
        // Only remove the temporary name created exclusively by this call.
        let _ = unsafe { libc::unlinkat(self.directory.as_raw_fd(), temporary.as_ptr(), 0) };
        result
    }

    pub fn remove(&self, volume: &str) -> io::Result<()> {
        let name = Self::record_name(volume)?;
        let rc = unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) };
        if rc != 0 && io::Error::last_os_error().kind() != io::ErrorKind::NotFound {
            return Err(io::Error::last_os_error());
        }
        self.directory.sync_all()
    }
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod tests;
