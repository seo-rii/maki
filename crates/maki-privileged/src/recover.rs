//! Recovery authorization lives in root-controlled state, independent of reads
//! from a filesystem whose NBD server has died. All observations below are
//! kernel metadata; none opens a file on the mounted volume.

use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{identity_error, lvm_preflight, ExecError, System};
use crate::detach::{device_number, is_nbd_partition, mapped_volume_group, DetachObservation};
use crate::plan::{Plan, PlannedStep, AUTO_NBD_DEVICE};
use crate::state::{BoundDeviceRecord, TrustedState};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryProof {
    nodes: Vec<BlockIdentity>,
    /// Attach verified that the target was empty before publishing this proof.
    mount_permitted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryIntent {
    verified: lvm_preflight::VerifiedLvm,
}

impl RecoveryIntent {
    pub(super) fn new(verified: &lvm_preflight::VerifiedLvm) -> Self {
        Self {
            verified: verified.clone(),
        }
    }

    pub(super) fn verified(&self) -> &lvm_preflight::VerifiedLvm {
        &self.verified
    }

    pub(crate) fn validate(&self, record: &BoundDeviceRecord) -> io::Result<()> {
        lvm_preflight::validate_recovery_identity(record, &self.verified)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockIdentity {
    name: String,
    device: (u32, u32),
    dm_name: Option<String>,
    dm_uuid: Option<String>,
    slaves: Vec<String>,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn names(directory: &Path) -> io::Result<Vec<String>> {
    let mut result = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| invalid("invalid kernel block name"))?;
        if result.len() >= 64 {
            return Err(invalid("recovery topology exceeds the supported bound"));
        }
        result.push(name);
    }
    result.sort();
    Ok(result)
}

fn inventory(record: &BoundDeviceRecord, sysfs: &Path) -> io::Result<Vec<BlockIdentity>> {
    let nbd = record
        .device
        .strip_prefix("/dev/")
        .ok_or_else(|| invalid("invalid NBD path"))?;
    let mut nodes = Vec::new();
    for entry in std::fs::read_dir(sysfs)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid("invalid kernel block name"))?;
        let path = entry.path();
        let (dm_name, dm_uuid, slaves) = if name == nbd || is_nbd_partition(sysfs, &name, nbd)? {
            (None, None, Vec::new())
        } else if name.starts_with("dm-") {
            let dm_name = std::fs::read_to_string(path.join("dm/name"))?
                .trim()
                .to_string();
            if mapped_volume_group(&dm_name).as_deref() != Some(&record.attachment.vg_name) {
                continue;
            }
            let uuid = std::fs::read_to_string(path.join("dm/uuid"))?
                .trim()
                .to_string();
            if !uuid.starts_with("LVM-") {
                return Err(invalid("recovery mapping is not an LVM device"));
            }
            (Some(dm_name), Some(uuid), names(&path.join("slaves"))?)
        } else {
            continue;
        };
        if nodes.len() >= 64 {
            return Err(invalid("recovery topology exceeds the supported bound"));
        }
        nodes.push(BlockIdentity {
            name,
            device: device_number(&std::fs::read_to_string(path.join("dev"))?)?,
            dm_name,
            dm_uuid,
            slaves,
        });
    }
    if !nodes.iter().any(|node| node.name == nbd) {
        return Err(invalid("recorded NBD kernel device is missing"));
    }
    // Every holder must be one of these exact mappings. A foreign mapper,
    // partition holder, or topology that changed during probing fails closed.
    for node in &nodes {
        for holder in names(&sysfs.join(&node.name).join("holders"))? {
            if !nodes
                .iter()
                .any(|candidate| candidate.name == holder && candidate.slaves.contains(&node.name))
            {
                return Err(invalid(
                    "unrecorded holder or inconsistent recovery topology",
                ));
            }
        }
        for slave in &node.slaves {
            if !nodes.iter().any(|candidate| &candidate.name == slave) {
                return Err(invalid("recovery mapping has an unrecorded backing device"));
            }
            if !names(&sysfs.join(slave).join("holders"))?.contains(&node.name) {
                return Err(invalid("inconsistent recovery dependency observation"));
            }
        }
    }
    nodes.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(nodes)
}

fn check_mounts(
    record: &BoundDeviceRecord,
    mounts: &str,
    nodes: &[BlockIdentity],
) -> io::Result<()> {
    for line in mounts.lines().filter(|line| !line.trim().is_empty()) {
        let (left, _) = line
            .split_once(" - ")
            .ok_or_else(|| invalid("incomplete mountinfo"))?;
        let fields: Vec<_> = left.split_whitespace().collect();
        if fields.len() < 6 {
            return Err(invalid("incomplete mountinfo"));
        }
        let device = device_number(fields[2])?;
        if nodes.iter().any(|node| node.device == device)
            && crate::probe::unescape(fields[4]) != record.attachment.mountpoint
        {
            return Err(invalid(
                "recorded block device has another mount; stop all workload mounts before recovery",
            ));
        }
    }
    Ok(())
}

/// Called after activation, while the backend nonce still matches. The caller
/// brackets this observation and its atomic publication with nonce checks.
pub(super) fn capture(
    record: &BoundDeviceRecord,
    mounts: &str,
    sysfs: &Path,
) -> io::Result<RecoveryProof> {
    let observed = crate::detach::observe_kernel(record, mounts, sysfs, false, false)?;
    if observed.mounted || !observed.vg_active {
        return Err(invalid(
            "cannot record recovery identity without an active VG and an empty mount target",
        ));
    }
    let nodes = inventory(record, sysfs)?;
    let lv = format!(
        "{}-{}",
        record.attachment.vg_name.replace('-', "--"),
        record.attachment.lv_name.replace('-', "--")
    );
    if !nodes
        .iter()
        .any(|node| node.dm_name.as_deref() == Some(&lv))
    {
        return Err(invalid("expected logical volume is absent before mount"));
    }
    check_mounts(record, mounts, &nodes)?;
    Ok(RecoveryProof {
        nodes,
        mount_permitted: true,
    })
}

/// Missing recorded nodes mean a previous cleanup step completed. Present
/// nodes must match exactly, and new mappings or holders are never adopted.
pub(super) fn observe(
    record: &BoundDeviceRecord,
    mounts: &str,
    sysfs: &Path,
) -> io::Result<DetachObservation> {
    let observed = crate::detach::observe_kernel(record, mounts, sysfs, false, false)?;
    let Some(proof) = &record.recovery else {
        if let Some(intent) = &record.recovery_intent {
            if observed.mounted {
                return Err(invalid(
                    "pre-activation recovery identity never authorized an upper layer",
                ));
            }
            lvm_preflight::verify_recovery_device_identity(record, intent.verified(), sysfs)?;
            if observed.vg_active {
                lvm_preflight::verify_recovery_mapping(record, intent.verified(), sysfs)?;
            } else if observed.nbd_in_use {
                return Err(invalid(
                    "pre-activation recovery identity has an unexpected holder",
                ));
            }
            let nodes = inventory(record, sysfs)?;
            check_mounts(record, mounts, &nodes)?;
            return Ok(observed);
        }
        if observed.mounted || observed.vg_active || observed.nbd_in_use {
            return Err(invalid(
                "legacy attachment has no independent recovery proof; refusing live cleanup",
            ));
        }
        return Ok(observed);
    };
    let nodes = inventory(record, sysfs)?;
    if nodes.iter().any(|node| !proof.nodes.contains(node)) {
        return Err(invalid(
            "kernel mapping identity changed since attach; refusing recovery",
        ));
    }
    if observed.mounted && !proof.mount_permitted {
        return Err(invalid("attachment never authorized a mount"));
    }
    check_mounts(record, mounts, &nodes)?;
    Ok(observed)
}

/// Exact mount snapshot for a repeatable workload-start gate. Cleanup may
/// tolerate absent proof nodes; this observer requires every node to remain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerifiedMount {
    pub device: (u32, u32),
    mountinfo: String,
}

pub(super) fn observe_complete(
    record: &BoundDeviceRecord,
    mounts: &str,
    sysfs: &Path,
) -> io::Result<VerifiedMount> {
    let proof = record
        .recovery
        .as_ref()
        .ok_or_else(|| invalid("attachment has no persisted mapping proof"))?;
    let observed = observe(record, mounts, sysfs)?;
    if !observed.mounted || !observed.vg_active || !proof.mount_permitted {
        return Err(invalid("attachment is not a complete mounted XFS volume"));
    }
    if inventory(record, sysfs)? != proof.nodes {
        return Err(invalid("persisted mapping proof is incomplete or changed"));
    }
    let mut verified_mount = None;
    for line in mounts.lines() {
        let (left, right) = line
            .split_once(" - ")
            .ok_or_else(|| invalid("incomplete mountinfo"))?;
        let fields: Vec<_> = left.split_whitespace().collect();
        let filesystem: Vec<_> = right.split_whitespace().collect();
        if fields.len() < 6 || filesystem.len() < 3 {
            return Err(invalid("incomplete mountinfo"));
        }
        let mounted_path = crate::probe::unescape(fields[4]);
        if mounted_path != record.attachment.mountpoint {
            // A foreign filesystem below the dedicated volume can hide data
            // paths even while its root and sentinel are correct. Compare
            // decoded path components, including when the configured root is
            // '/', rather than rejecting unrelated names with the same prefix.
            if Path::new(&mounted_path).starts_with(&record.attachment.mountpoint) {
                return Err(invalid("workload volume contains a nested mount"));
            }
            continue;
        }
        // Kernel-only evidence of rw mounting, not a claim that writes or
        // database recovery would succeed; the gate performs no write probe.
        if !fields[5].split(',').any(|option| option == "rw")
            || !filesystem[2].split(',').any(|option| option == "rw")
        {
            return Err(invalid("workload mount is read-only"));
        }
        verified_mount = Some(VerifiedMount {
            device: device_number(fields[2])?,
            mountinfo: line.into(),
        });
    }
    verified_mount.ok_or_else(|| invalid("workload mount is missing"))
}

fn absent_backend(record: &BoundDeviceRecord, system: &impl System) -> Result<(), ExecError> {
    match system.backend(&record.device)? {
        None => Ok(()),
        Some(identifier) if identifier == record.connection_id => Err(identity_error(
            "backend is still connected; use detach for a live attachment",
        )),
        Some(_) => Err(identity_error(
            "recorded NBD device now has a foreign backend; refusing recovery",
        )),
    }
}

pub(super) fn execute(
    plan: &Plan,
    state: &TrustedState,
    system: &mut impl System,
) -> Result<(), ExecError> {
    let record = state
        .read(&plan.volume)?
        .ok_or_else(|| identity_error("no trusted attachment to recover"))?;
    if plan.attachment.as_ref() != Some(&record.attachment)
        || plan.steps.len() != 3
        || !matches!(&plan.steps[0], PlannedStep::Umount { mountpoint } if mountpoint == &record.attachment.mountpoint)
        || !matches!(&plan.steps[1], PlannedStep::LvmDeactivate { vg_name } if vg_name == &record.attachment.vg_name)
        || !matches!(&plan.steps[2], PlannedStep::NbdDisconnect { device } if device == AUTO_NBD_DEVICE || device == &record.device)
    {
        return Err(identity_error(
            "recovery configuration does not match the trusted attachment",
        ));
    }
    for _ in 0..4 {
        absent_backend(&record, system)?;
        let observed = system.recovery_observation(&record)?;
        absent_backend(&record, system)?;
        let step = if observed.mounted {
            PlannedStep::Umount {
                mountpoint: record.attachment.mountpoint.clone(),
            }
        } else if observed.vg_active {
            PlannedStep::LvmDeactivate {
                vg_name: record.attachment.vg_name.clone(),
            }
        } else if observed.nbd_in_use {
            return Err(identity_error(
                "NBD still has users; keeping recovery state",
            ));
        } else {
            state.remove(&plan.volume)?;
            return Ok(());
        };
        // A failed command may already have applied its effect. Keep the
        // original record; a retry observes which upper layers remain.
        if matches!(step, PlannedStep::LvmDeactivate { .. }) && record.recovery.is_none() {
            if let Some(intent) = &record.recovery_intent {
                system.recover_deactivate_lvm(&record, intent.verified())?;
            } else {
                system.run_step(&step, None)?;
            }
        } else {
            system.run_step(&step, None)?;
        }
    }
    Err(identity_error(
        "recovery did not converge; keeping attachment record",
    ))
}
