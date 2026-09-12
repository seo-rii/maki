//! Recovery authorization lives in root-controlled state, independent of reads
//! from a filesystem whose NBD server has died. All observations below are
//! kernel metadata; none opens a file on the mounted volume.

use std::io;
use std::path::Path;
use std::process::{Command, Output};

use serde::{Deserialize, Serialize};

use super::{
    command, identity_error, lvm_preflight, verify_connection, ExecError, LinuxSystem, System,
};
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

fn single_deactivation_mapping<'a>(
    nodes: &'a [BlockIdentity],
    expected_name: &str,
) -> io::Result<&'a BlockIdentity> {
    let mut mappings = nodes.iter().filter(|node| node.dm_name.is_some());
    let mapping = mappings
        .next()
        .ok_or_else(|| invalid("recovery proof has no device-mapper target"))?;
    if mappings.next().is_some()
        || mapping.dm_name.as_deref() != Some(expected_name)
        || mapping.dm_uuid.is_none()
        || mapping.slaves.is_empty()
        || nodes.iter().any(|node| node.slaves.contains(&mapping.name))
    {
        return Err(invalid(
            "direct deactivation requires one exact top-level target mapping",
        ));
    }
    Ok(mapping)
}

fn force_deactivation_target_at(
    record: &BoundDeviceRecord,
    mounts: &str,
    sysfs: &Path,
) -> io::Result<Option<BlockIdentity>> {
    let proof = record
        .recovery
        .as_ref()
        .ok_or_else(|| invalid("attachment has no completed recovery proof"))?;
    let expected_name = format!(
        "{}-{}",
        record.attachment.vg_name.replace('-', "--"),
        record.attachment.lv_name.replace('-', "--")
    );
    // Restrict the fallback to the qualified single linear-style target. A
    // multi-LV/internal topology needs LVM metadata handling and stays closed.
    single_deactivation_mapping(&proof.nodes, &expected_name)?;

    let observed = observe(record, mounts, sysfs)?;
    if observed.mounted {
        return Err(invalid(
            "cannot directly deactivate a mounted recovery mapping",
        ));
    }
    let nodes = inventory(record, sysfs)?;
    if nodes.iter().any(|node| !proof.nodes.contains(node)) {
        return Err(invalid(
            "kernel mapping identity changed since attach; refusing direct deactivation",
        ));
    }
    check_mounts(record, mounts, &nodes)?;
    if !observed.vg_active {
        if observed.nbd_in_use {
            return Err(invalid(
                "NBD still has an unverified user after mapping deactivation",
            ));
        }
        return Ok(None);
    }
    single_deactivation_mapping(&nodes, &expected_name)
        .cloned()
        .map(Some)
}

fn controlled_dmsetup() -> Command {
    let mut command = Command::new("dmsetup");
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C");
    command
}

fn dmsetup_info_command(name: &str) -> Command {
    let mut command = controlled_dmsetup();
    command.args([
        "info",
        "--noheadings",
        "--columns",
        "--separator",
        "\t",
        "-o",
        "name,uuid,major,minor,open",
        name,
    ]);
    command
}

fn dmsetup_remove_command(name: &str) -> Command {
    let mut command = controlled_dmsetup();
    command.args(["remove", name]);
    command
}

fn verify_removal_info(expected: &BlockIdentity, output: &Output) -> io::Result<()> {
    if !output.status.success()
        || !output.stderr.is_empty()
        || output.stdout.len() > command::Policy::PROBE.max_output_bytes
    {
        return Err(invalid("device-mapper identity probe failed"));
    }
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| invalid("invalid device-mapper identity report"))?;
    let lines: Vec<_> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    if lines.len() != 1 {
        return Err(invalid("ambiguous device-mapper identity report"));
    }
    let fields: Vec<_> = lines[0].split('\t').map(str::trim).collect();
    if fields.len() != 5
        || Some(fields[0]) != expected.dm_name.as_deref()
        || Some(fields[1]) != expected.dm_uuid.as_deref()
        || fields[2].parse::<u32>().ok() != Some(expected.device.0)
        || fields[3].parse::<u32>().ok() != Some(expected.device.1)
        || fields[4] != "0"
    {
        return Err(invalid(
            "device-mapper target is open or its identity changed",
        ));
    }
    Ok(())
}

pub(super) fn deactivate_connected_from_proof(record: &BoundDeviceRecord) -> Result<(), ExecError> {
    verify_connection(record, &LinuxSystem)?;
    let mounts = std::fs::read_to_string("/proc/self/mountinfo")?;
    let Some(mapping) =
        force_deactivation_target_at(record, &mounts, Path::new("/sys/class/block"))?
    else {
        return Ok(());
    };
    let name = mapping
        .dm_name
        .as_deref()
        .ok_or_else(|| identity_error("verified mapping has no device-mapper name"))?;
    let output = command::capture(&mut dmsetup_info_command(name), command::Policy::PROBE)?;
    verify_removal_info(&mapping, &output)?;

    // Recheck both independent authorities immediately before mutation: the
    // netlink connection nonce and the exact root-owned recovery proof.
    verify_connection(record, &LinuxSystem)?;
    let mounts = std::fs::read_to_string("/proc/self/mountinfo")?;
    if force_deactivation_target_at(record, &mounts, Path::new("/sys/class/block"))?
        != Some(mapping.clone())
    {
        return Err(identity_error(
            "device-mapper identity changed before direct deactivation",
        ));
    }
    let output = command::capture(&mut dmsetup_remove_command(name), command::Policy::STEP)?;
    if !output.status.success() {
        return Err(ExecError::StepFailed {
            step: format!("dmsetup remove {name}"),
            status: output.status.code(),
            stderr: "external command output omitted".into(),
        });
    }

    verify_connection(record, &LinuxSystem)?;
    let mounts = std::fs::read_to_string("/proc/self/mountinfo")?;
    if force_deactivation_target_at(record, &mounts, Path::new("/sys/class/block"))?.is_some() {
        return Err(identity_error(
            "device-mapper target remained after direct deactivation",
        ));
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
                lvm_preflight::verify_recovery_rollback_mapping(record, intent.verified(), sysfs)?;
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

#[cfg(test)]
mod force_deactivation_tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    fn node(name: &str, dm_name: Option<&str>, slaves: &[&str]) -> BlockIdentity {
        BlockIdentity {
            name: name.into(),
            device: (253, 0),
            dm_name: dm_name.map(str::to_owned),
            dm_uuid: dm_name.map(|name| format!("LVM-{name}")),
            slaves: slaves.iter().map(|name| (*name).into()).collect(),
        }
    }

    #[test]
    fn forced_deactivation_accepts_only_one_target_mapping() {
        let nbd = node("nbd3", None, &[]);
        let pool = node("dm-0", Some("vg-pool"), &["nbd3"]);
        let data = node("dm-1", Some("vg-data"), &["dm-0"]);

        assert_eq!(
            single_deactivation_mapping(&[nbd.clone(), data.clone()], "vg-data")
                .unwrap()
                .dm_name
                .as_deref(),
            Some("vg-data")
        );
        assert!(single_deactivation_mapping(&[nbd.clone(), pool, data], "vg-data").is_err());
        assert!(single_deactivation_mapping(std::slice::from_ref(&nbd), "vg-data").is_err());
        assert!(single_deactivation_mapping(
            &[nbd, node("dm-1", Some("vg-other"), &["nbd3"])],
            "vg-data"
        )
        .is_err());
    }

    #[test]
    fn forced_deactivation_requires_exact_closed_dm_identity() {
        let expected = node("dm-7", Some("vg-data"), &["nbd3"]);
        let output = |line: &str| std::process::Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: line.as_bytes().to_vec(),
            stderr: Vec::new(),
        };
        assert!(
            verify_removal_info(&expected, &output("vg-data\tLVM-vg-data\t253\t0\t0\n")).is_ok()
        );
        for changed in [
            "other\tLVM-vg-data\t253\t0\t0\n",
            "vg-data\tLVM-other\t253\t0\t0\n",
            "vg-data\tLVM-vg-data\t253\t9\t0\n",
            "vg-data\tLVM-vg-data\t253\t0\t1\n",
            "vg-data\tLVM-vg-data\t253\t0\t0\nextra\n",
        ] {
            assert!(
                verify_removal_info(&expected, &output(changed)).is_err(),
                "accepted changed dmsetup identity: {changed:?}"
            );
        }
    }

    #[test]
    fn forced_deactivation_commands_do_not_force_defer_or_retry() {
        let info = dmsetup_info_command("vg-data");
        assert_eq!(
            info.get_args()
                .map(|arg| arg.to_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "info",
                "--noheadings",
                "--columns",
                "--separator",
                "\t",
                "-o",
                "name,uuid,major,minor,open",
                "vg-data"
            ]
        );
        let remove = dmsetup_remove_command("vg-data");
        assert_eq!(
            remove
                .get_args()
                .map(|arg| arg.to_str().unwrap())
                .collect::<Vec<_>>(),
            ["remove", "vg-data"]
        );
    }
}
