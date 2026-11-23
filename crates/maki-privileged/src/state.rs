//! Root-controlled attach state. Every directory is opened relative to an
//! already verified descriptor; symlinks and non-root writable ancestors
//! are refused before any lock or record is opened.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::config::{check_abs_path, check_instance_name, check_lvm_name, check_uuid};
use crate::plan::{AttachmentIdentity, BOUND_DEVICE_RECORD_DIR};
use crate::probe::nbd_index;

const CONFIG_MAX_BYTES: u64 = 64 * 1024;
// A record can include both the 64 KiB configuration's identity and a
// verified 64 KiB LVM report/topology. Allow JSON escaping and envelope
// overhead while keeping reads and serialization strictly bounded.
const RECORD_MAX_BYTES: u64 = 4 * CONFIG_MAX_BYTES;
// No host has more attachments than NBD devices; allocation reads at most
// this many block devices too.
const STATE_MAX_ENTRIES: usize = 65_536;

#[derive(Default)]
struct RecordBuffer(Vec<u8>);

impl Write for RecordBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > RECORD_MAX_BYTES as usize - self.0.len() {
            return Err(invalid("attach record exceeds size limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

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
    /// Kernel identity captured with this backend still connected, before mount.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<crate::exec::recover::RecoveryProof>,
    /// Verified LVM identity published before activation. It authorizes only
    /// scoped recovery of that exact mapping if activation outlives the helper.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_intent: Option<crate::exec::recover::RecoveryIntent>,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

impl BoundDeviceRecord {
    fn validate(&self) -> io::Result<()> {
        check_instance_name(&self.volume).map_err(|e| invalid(e.to_string()))?;
        check_uuid("volume_uuid", &self.attachment.volume_uuid)
            .map_err(|e| invalid(e.to_string()))?;
        check_abs_path("nbd_socket", &self.attachment.nbd_socket)
            .map_err(|e| invalid(e.to_string()))?;
        check_abs_path("mountpoint", &self.attachment.mountpoint)
            .map_err(|e| invalid(e.to_string()))?;
        check_lvm_name("vg_name", &self.attachment.vg_name).map_err(|e| invalid(e.to_string()))?;
        check_lvm_name("lv_name", &self.attachment.lv_name).map_err(|e| invalid(e.to_string()))?;
        if let Some(pins) = &self.attachment.lvm_identity {
            crate::config::check_lvm_identity(pins).map_err(|e| invalid(e.to_string()))?;
        }
        let nonce = self
            .connection_id
            .strip_prefix("maki-")
            .ok_or_else(|| invalid("invalid attachment identifier"))?;
        check_uuid("connection_id", nonce).map_err(|e| invalid(e.to_string()))?;
        if self.version != 1 || nbd_index(&self.device).is_none() {
            return Err(invalid("unsupported or invalid attach record"));
        }
        if self.recovery.is_some() && self.recovery_intent.is_some() {
            return Err(invalid("attach record has conflicting recovery states"));
        }
        if let Some(intent) = &self.recovery_intent {
            intent.validate(self)?;
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

/// The held exclusive `attach.lock`. A `flock` lock belongs to the open file
/// description, which every command the helper forks shares until its `exec`
/// closes its copy, so closing the descriptor alone would leave the lock held
/// for such a child. Dropping unlocks first.
pub struct StateLock(File);

impl Drop for StateLock {
    fn drop(&mut self) {
        // Releasing a held lock does not fail on a valid descriptor; the
        // close that follows still releases it where no child shares it.
        let _ = self.0.unlock();
    }
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

    pub fn open_existing() -> io::Result<Self> {
        Self::open_existing_beneath(
            File::open("/")?,
            Path::new(BOUND_DEVICE_RECORD_DIR)
                .strip_prefix("/")
                .unwrap(),
            0,
        )
    }

    pub(crate) fn open_beneath(directory: File, relative: &Path, owner: u32) -> io::Result<Self> {
        Self::open_directory(directory, relative, owner, true)
    }

    pub(crate) fn open_existing_beneath(
        directory: File,
        relative: &Path,
        owner: u32,
    ) -> io::Result<Self> {
        Self::open_directory(directory, relative, owner, false)
    }

    fn open_directory(
        mut directory: File,
        relative: &Path,
        owner: u32,
        create: bool,
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
                Err(e)
                    if create
                        && e.kind() == io::ErrorKind::NotFound
                        && index + 1 == components.len() =>
                {
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

    fn lock_file(&self) -> io::Result<File> {
        let name = CString::new("attach.lock").unwrap();
        let file = openat(&self.directory, &name, libc::O_RDWR | libc::O_CREAT, 0o600)?;
        private_regular_file(&file, self.owner)?;
        Ok(file)
    }

    pub fn lock(&self) -> io::Result<StateLock> {
        let file = self.lock_file()?;
        file.lock()?;
        Ok(StateLock(file))
    }

    /// Take the lock, but give up at `deadline` rather than queue behind
    /// another helper for as long as that one runs.
    pub fn lock_until(&self, deadline: Instant) -> io::Result<StateLock> {
        let file = self.lock_file()?;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(StateLock(file)),
                Err(std::fs::TryLockError::Error(error)) => return Err(error),
                Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "the attach lock is held by another helper",
                    ));
                }
            }
        }
    }

    /// Verification joins the same exclusive lock without creating a file.
    pub fn lock_existing(&self) -> io::Result<StateLock> {
        let name = CString::new("attach.lock").unwrap();
        let file = openat(&self.directory, &name, libc::O_RDONLY | libc::O_NOATIME, 0)?;
        private_regular_file(&file, self.owner)?;
        file.lock()?;
        Ok(StateLock(file))
    }

    fn record_name(volume: &str) -> io::Result<CString> {
        check_instance_name(volume).map_err(|e| invalid(e.to_string()))?;
        CString::new(format!("{volume}.nbd")).map_err(|_| invalid("invalid volume name"))
    }

    pub fn read(&self, volume: &str) -> io::Result<Option<BoundDeviceRecord>> {
        self.read_record(volume, false)
    }

    pub fn read_for_verify(&self, volume: &str) -> io::Result<Option<BoundDeviceRecord>> {
        self.read_record(volume, true)
    }

    fn read_record(&self, volume: &str, no_atime: bool) -> io::Result<Option<BoundDeviceRecord>> {
        let name = Self::record_name(volume)?;
        let flags = libc::O_RDONLY | if no_atime { libc::O_NOATIME } else { 0 };
        let file = match openat(&self.directory, &name, flags, 0) {
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

    /// The NBD device each other volume's trusted record names, by device.
    ///
    /// A record can outlive its connection: a helper killed after publishing
    /// it and before connecting, or after disconnecting and before retiring
    /// it, leaves one whose device shows no backend, holder or mount. Such a
    /// device is still that volume's, so sysfs alone cannot show a device to
    /// be unclaimed. Call with the attach lock held, which every writer of
    /// these records holds.
    ///
    /// Every `<volume>.nbd` entry must be a readable trusted record. One that
    /// is not may name any device, so the listing fails and names the entry
    /// instead of leaving it out. Other names (the lock, a temporary record
    /// of a killed write) are not records.
    pub fn devices_of_other_volumes(&self, volume: &str) -> io::Result<BTreeMap<String, String>> {
        // List the directory this descriptor holds, wherever its path now
        // leads; each record is then opened relative to the descriptor.
        let listing = format!("/proc/self/fd/{}", self.directory.as_raw_fd());
        let mut names = Vec::new();
        for (count, entry) in std::fs::read_dir(listing)?.enumerate() {
            if count >= STATE_MAX_ENTRIES {
                return Err(invalid("attach state directory exceeds the listing limit"));
            }
            let name = entry?.file_name();
            if name.as_bytes().ends_with(b".nbd") {
                names.push(name);
            }
        }
        names.sort();
        let mut devices = BTreeMap::new();
        for name in names {
            let unreadable = |error: io::Error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "attach record {:?} cannot be read: {error}. It may name any NBD device, \
                         so no device is chosen while it exists; resolve that volume's \
                         attachment, or remove the record once nothing of it remains",
                        Path::new(BOUND_DEVICE_RECORD_DIR).join(&name),
                    ),
                )
            };
            let other = name
                .to_str()
                .and_then(|name| name.strip_suffix(".nbd"))
                .filter(|other| check_instance_name(other).is_ok())
                .ok_or_else(|| unreadable(invalid("not a volume's record name")))?;
            if other == volume {
                continue;
            }
            // An entry removed since the listing reserves nothing.
            if let Some(record) = self.read(other).map_err(unreadable)? {
                devices.entry(record.device).or_insert(record.volume);
            }
        }
        Ok(devices)
    }

    pub fn write(&self, record: &BoundDeviceRecord) -> io::Result<()> {
        record.validate()?;
        // Validate the actual encoded size before creating a temporary file.
        // Oversized state never replaces an earlier cleanup authority.
        let mut bytes = RecordBuffer::default();
        serde_json::to_writer(&mut bytes, record).map_err(|e| invalid(e.to_string()))?;
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
            file.write_all(&bytes.0)?;
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

/// Every executing verb accepts only an existing root-controlled config: it
/// runs as root on what the file says (R5-030). Plans read any file.
pub(crate) fn read_verify_config(path: &Path) -> io::Result<String> {
    let relative = path
        .strip_prefix("/")
        .map_err(|_| invalid("config path must be absolute"))?;
    read_config_beneath(File::open("/")?, relative, 0)
}

fn read_config_beneath(directory: File, relative: &Path, owner: u32) -> io::Result<String> {
    let parent = relative
        .parent()
        .ok_or_else(|| invalid("config path has no parent"))?;
    let name = relative
        .file_name()
        .ok_or_else(|| invalid("config path has no filename"))?;
    let state = TrustedState::open_existing_beneath(directory, parent, owner)?;
    let name = CString::new(name.as_bytes()).map_err(|_| invalid("invalid config filename"))?;
    let file = openat(&state.directory, &name, libc::O_RDONLY | libc::O_NOATIME, 0)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied,
            "attach config must be a root-owned regular file without group/other write access and with one link"));
    }
    let mut content = String::new();
    file.take(CONFIG_MAX_BYTES + 1)
        .read_to_string(&mut content)?;
    if content.len() as u64 > CONFIG_MAX_BYTES {
        return Err(invalid("attach config exceeds size limit"));
    }
    Ok(content)
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod tests;
