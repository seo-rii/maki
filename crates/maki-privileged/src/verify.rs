//! Secure mount validation (SPEC §39). If any check fails, the dependent
//! container/service MUST NOT start.

#[derive(Debug, Clone)]
pub struct MountExpectation {
    /// Expected XFS filesystem UUID (None = skip, e.g. first boot).
    pub fs_uuid: Option<String>,
    /// The Maki volume UUID recorded in the sentinel file.
    pub volume_uuid: String,
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
}

#[derive(Debug, thiserror::Error)]
#[error("secure mount validation failed: {0}")]
pub struct MountVerifyError(pub String);

pub fn verify_mount_identity(
    expected: &MountExpectation,
    observed: &MountObservation,
) -> Result<(), MountVerifyError> {
    if !observed.mountpoint_exists {
        return Err(MountVerifyError("mountpoint does not exist".to_string()));
    }
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
