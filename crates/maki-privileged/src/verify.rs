//! Secure mount validation (SPEC §39). If any check fails, the dependent
//! container/service MUST NOT start.
//!
//! Two layers (third review, F02): [`verify_mount_device`] proves the
//! mounted filesystem's bytes live on the NBD device this attach connected
//! and nowhere else, and runs *before* anything is written to the
//! filesystem (sentinel, probe); [`verify_mount_identity`] then checks the
//! filesystem type and UUID, the sentinel, the NBD connection and the
//! read/write probe. A sentinel is never a substitute for the topology
//! check: on a fresh filesystem it is created by this very helper, so it
//! can only ever confirm which device the helper *thinks* it mounted.

#[derive(Debug, Clone)]
pub struct MountExpectation {
    /// Expected XFS filesystem UUID (None = skip, e.g. first boot).
    pub fs_uuid: Option<String>,
    /// The Maki volume UUID recorded in the sentinel file.
    pub volume_uuid: String,
    /// The NBD device (`/dev/nbdN`) every byte of the mounted filesystem
    /// must be stored on.
    pub nbd_device: String,
}

/// Facts gathered by the executor (or the mount-guard script).
#[derive(Debug, Clone)]
pub struct MountObservation {
    pub mountpoint_exists: bool,
    pub fstype: Option<String>,
    pub fs_uuid: Option<String>,
    /// Volume UUID read from `<mountpoint>/.maki-sentinel`.
    pub sentinel_volume_uuid: Option<String>,
    pub nbd_connected: bool,
    pub rw_probe_ok: bool,
    /// The block devices the mounted filesystem ultimately lives on: the
    /// leaves of the sysfs `slaves` walk from the mount source, as
    /// `/dev/...` names (partitions folded into their NBD device). Empty
    /// when the walk could not be done.
    pub backing_devices: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("secure mount validation failed: {0}")]
pub struct MountVerifyError(pub String);

/// The mounted filesystem is on `nbd_device` and only on it. A filesystem
/// with no resolvable backing, or with any other device underneath (a
/// local disk mounted by mistake, a volume group spanning the NBD device
/// and something else), is refused before it is touched.
pub fn verify_mount_device(
    nbd_device: &str,
    observed: &MountObservation,
) -> Result<(), MountVerifyError> {
    if !observed.mountpoint_exists {
        return Err(MountVerifyError("mountpoint does not exist".to_string()));
    }
    if observed.fstype.is_none() {
        return Err(MountVerifyError(
            "nothing is mounted at the mountpoint".to_string(),
        ));
    }
    if observed.backing_devices.is_empty() {
        return Err(MountVerifyError(
            "could not resolve the block devices under the mounted filesystem".to_string(),
        ));
    }
    if observed.backing_devices.iter().any(|d| d != nbd_device) {
        return Err(MountVerifyError(format!(
            "the mounted filesystem is not stored only on {nbd_device}: its backing devices \
             are {:?}",
            observed.backing_devices
        )));
    }
    Ok(())
}

pub fn verify_mount_identity(
    expected: &MountExpectation,
    observed: &MountObservation,
) -> Result<(), MountVerifyError> {
    verify_mount_device(&expected.nbd_device, observed)?;
    match observed.fstype.as_deref() {
        Some("xfs") => {}
        other => {
            return Err(MountVerifyError(format!(
                "filesystem type {other:?} is not XFS"
            )))
        }
    }
    if let Some(expected_fs_uuid) = &expected.fs_uuid {
        if observed.fs_uuid.as_ref() != Some(expected_fs_uuid) {
            return Err(MountVerifyError(format!(
                "filesystem UUID mismatch: {:?} != expected {:?}",
                observed.fs_uuid, expected_fs_uuid
            )));
        }
    }
    match &observed.sentinel_volume_uuid {
        Some(uuid) if *uuid == expected.volume_uuid => {}
        other => {
            return Err(MountVerifyError(format!(
                "Maki volume sentinel mismatch: {other:?} != {:?}",
                expected.volume_uuid
            )))
        }
    }
    if !observed.nbd_connected {
        return Err(MountVerifyError("NBD connection is not active".to_string()));
    }
    if !observed.rw_probe_ok {
        return Err(MountVerifyError("read/write probe failed".to_string()));
    }
    Ok(())
}
