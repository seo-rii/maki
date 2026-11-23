//! Read-only workload-start gate. The interface exposes observations only;
//! it cannot allocate a device, run a mutation step, or repair attach state.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

use super::{
    command, identity_error, recover, verify_filesystem_probe, ExecError, LinuxSystem, System,
};
use crate::config::{self, AttachOverrides};
use crate::plan::{AttachRequest, AttachmentIdentity, AUTO_NBD_DEVICE, SENTINEL_FILE};
use crate::state::{read_verify_config, BoundDeviceRecord, TrustedState};

pub(super) trait WorkloadSystem {
    fn backend(&self, device: &str) -> io::Result<Option<String>>;
    fn mounted(&self, record: &BoundDeviceRecord) -> io::Result<recover::VerifiedMount>;
    fn filesystem(
        &self,
        record: &BoundDeviceRecord,
        mount: &recover::VerifiedMount,
        uuid: &str,
    ) -> Result<(), ExecError>;
    fn sentinel(
        &self,
        record: &BoundDeviceRecord,
        mount: &recover::VerifiedMount,
    ) -> io::Result<String>;
}

fn device_number(value: u64) -> (u32, u32) {
    (libc::major(value), libc::minor(value))
}

/// Open with `O_NOATIME`, or without that one flag when the kernel refuses
/// it. `O_NOATIME` needs ownership of the inode or CAP_FOWNER; the volume
/// root and sentinel can belong to the workload user, and `ExecStartPre=!`
/// keeps the unit's `CapabilityBoundingSet=`, so the gate may lack it. The
/// flag only spares an access-time update (the volume is mounted `noatime`
/// in any case); every other flag stays, and the caller's device checks on
/// the opened descriptor bind what is read either way.
pub(super) fn open_noatime(
    flags: libc::c_int,
    open: impl Fn(libc::c_int) -> io::Result<File>,
) -> io::Result<File> {
    match open(flags | libc::O_NOATIME) {
        Err(error) if error.raw_os_error() == Some(libc::EPERM) => open(flags),
        result => result,
    }
}

/// Bind the sentinel read to the observed mounted device. No write probe or
/// sentinel initialization is used.
pub(super) fn read_mounted_sentinel(mountpoint: &str, device: (u32, u32)) -> io::Result<String> {
    let root = open_noatime(libc::O_DIRECTORY | libc::O_NOFOLLOW, |flags| {
        OpenOptions::new()
            .read(true)
            .custom_flags(flags)
            .open(mountpoint)
    })?;
    if device_number(root.metadata()?.dev()) != device {
        return Err(io::Error::other(
            "opened mount root is not the verified device",
        ));
    }
    let name = CString::new(SENTINEL_FILE).unwrap();
    let file = open_noatime(
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        |flags| {
            // SAFETY: root remains open and name is NUL-terminated. The
            // returned descriptor is exclusively owned by the File below.
            let fd = unsafe { libc::openat(root.as_raw_fd(), name.as_ptr(), flags) };
            if fd < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(unsafe { File::from_raw_fd(fd) })
            }
        },
    )?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.len() > super::SENTINEL_MAX_BYTES
        || device_number(metadata.dev()) != device
    {
        return Err(io::Error::other(
            "sentinel is not a bounded regular file on the verified mount",
        ));
    }
    let mut content = String::new();
    file.take(super::SENTINEL_MAX_BYTES + 1)
        .read_to_string(&mut content)?;
    if content.len() as u64 > super::SENTINEL_MAX_BYTES || content.trim().is_empty() {
        return Err(io::Error::other("sentinel is empty or exceeds its bound"));
    }
    Ok(content.trim().into())
}

impl WorkloadSystem for LinuxSystem {
    fn backend(&self, device: &str) -> io::Result<Option<String>> {
        System::backend(self, device)
    }

    fn mounted(&self, record: &BoundDeviceRecord) -> io::Result<recover::VerifiedMount> {
        recover::observe_complete(
            record,
            &super::read_mountinfo()?,
            Path::new("/sys/class/block"),
        )
    }

    fn filesystem(
        &self,
        record: &BoundDeviceRecord,
        mount: &recover::VerifiedMount,
        uuid: &str,
    ) -> Result<(), ExecError> {
        let device = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(format!(
                "/dev/{}/{}",
                record.attachment.vg_name, record.attachment.lv_name
            ))?;
        let metadata = device.metadata()?;
        if !metadata.file_type().is_block_device() || device_number(metadata.rdev()) != mount.device
        {
            return Err(identity_error(
                "filesystem probe device does not match the verified mount",
            ));
        }
        // The child opens our still-held descriptor through proc, so replacing
        // /dev/VG/LV cannot redirect the probe after the device-number check.
        let pinned = format!("/proc/{}/fd/{}", std::process::id(), device.as_raw_fd());
        let output = command::capture(
            crate::exec::command::controlled("blkid").args([
                "--probe",
                "--output",
                "export",
                "--match-tag",
                "TYPE",
                "--match-tag",
                "UUID",
                &pinned,
            ]),
            command::Policy::PROBE,
        )?;
        verify_filesystem_probe(Some(uuid), &output)
    }

    fn sentinel(
        &self,
        record: &BoundDeviceRecord,
        mount: &recover::VerifiedMount,
    ) -> io::Result<String> {
        read_mounted_sentinel(&record.attachment.mountpoint, mount.device)
    }
}

fn live_mount(
    record: &BoundDeviceRecord,
    system: &impl WorkloadSystem,
) -> Result<recover::VerifiedMount, ExecError> {
    if system.backend(&record.device)?.as_deref() != Some(&record.connection_id) {
        return Err(identity_error(
            "workload backend identifier is absent, foreign, or changed",
        ));
    }
    let mount = system.mounted(record)?;
    if system.backend(&record.device)?.as_deref() != Some(&record.connection_id) {
        return Err(identity_error(
            "workload backend identifier changed during observation",
        ));
    }
    Ok(mount)
}

pub(super) fn verify_request(
    request: &AttachRequest,
    state: &TrustedState,
    system: &impl WorkloadSystem,
) -> Result<(), ExecError> {
    let uuid = request
        .fs_uuid
        .as_deref()
        .ok_or_else(|| identity_error("verify requires configured fs_uuid"))?;
    config::check_uuid("volume_uuid", &request.volume_uuid)
        .map_err(|e| identity_error(e.to_string()))?;
    config::check_uuid("fs_uuid", uuid).map_err(|e| identity_error(e.to_string()))?;
    let record = state
        .read_for_verify(&request.volume)?
        .ok_or_else(|| identity_error("no trusted attachment to verify"))?;
    if record.attachment != AttachmentIdentity::from(request)
        || (request.nbd_device != AUTO_NBD_DEVICE && request.nbd_device != record.device)
    {
        return Err(identity_error(
            "verify configuration does not match the trusted attach record",
        ));
    }
    if record.recovery.is_none() {
        return Err(identity_error("attachment has no persisted mapping proof"));
    }
    let before = live_mount(&record, system)?;
    system.filesystem(&record, &before, uuid)?;
    let after_probe = live_mount(&record, system)?;
    if before != after_probe {
        return Err(identity_error(
            "workload mount changed during filesystem probe",
        ));
    }
    if !system
        .sentinel(&record, &after_probe)?
        .eq_ignore_ascii_case(&request.volume_uuid)
    {
        return Err(identity_error("workload volume sentinel does not match"));
    }
    if live_mount(&record, system)? != before {
        return Err(identity_error(
            "workload mount changed during sentinel read",
        ));
    }
    Ok(())
}

pub(super) fn execute(volume: &str, config_path: &Path) -> Result<(), ExecError> {
    config::check_volume_name(volume).map_err(|e| identity_error(e.to_string()))?;
    config::check_abs_path("config", &config_path.to_string_lossy())
        .map_err(|e| identity_error(e.to_string()))?;
    let state = TrustedState::open_existing()?;
    let _lock = state.lock_existing()?;
    let config = read_verify_config(config_path)?;
    let request = config::parse(&config)
        .and_then(|config| config.into_request(volume, AttachOverrides::default(), true))
        .map_err(|e| identity_error(e.to_string()))?;
    verify_request(&request, &state, &LinuxSystem)
}
