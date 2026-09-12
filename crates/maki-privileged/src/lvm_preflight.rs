//! Pre-activation containment, not authentication against a configured LVM
//! UUID. Read-only reports are lockless; external privileged LVM/udev actions
//! are outside the helper lock. The verified identity is also persisted before
//! activation so recovery can scope cleanup across the proof-publication gap.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::{Command, Output};

use serde::{Deserialize, Serialize};

use super::{command, identity_error, verify_connection, ExecError, LinuxSystem};
use crate::detach::device_number;
use crate::state::BoundDeviceRecord;

const MAX_DEVICES: usize = 64;
const MAX_REPORT: usize = 64 * 1024;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Device {
    pub(super) path: String,
    pub(super) number: (u32, u32),
    pub(super) start: u64,
    pub(super) sectors: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VerifiedLvm {
    devices: Vec<Device>,
    labels: BTreeMap<String, String>,
    vg_uuid: String,
    vg_seqno: u64,
    lv_uuid: String,
    lvs: BTreeMap<String, String>,
    layouts: BTreeMap<String, BTreeSet<String>>,
}

pub(super) fn validate_recovery_identity(
    record: &BoundDeviceRecord,
    verified: &VerifiedLvm,
) -> io::Result<()> {
    if verified.devices.is_empty() || verified.devices.len() > MAX_DEVICES {
        return Err(invalid("invalid persisted LVM device count"));
    }
    let nbd = record
        .device
        .strip_prefix("/dev/")
        .ok_or_else(|| invalid("invalid NBD path"))?;
    let mut paths = BTreeSet::new();
    let mut numbers = BTreeSet::new();
    let mut root_sectors = None;
    for device in &verified.devices {
        let name = device
            .path
            .strip_prefix("/dev/")
            .ok_or_else(|| invalid("invalid persisted LVM device path"))?;
        let partition = name.strip_prefix(&format!("{nbd}p"));
        if name != nbd
            && partition.is_none_or(|suffix| {
                suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit())
            })
        {
            return Err(invalid("invalid persisted LVM device path"));
        }
        if device.sectors == 0
            || device.start.checked_add(device.sectors).is_none()
            || !paths.insert(device.path.clone())
            || !numbers.insert(device.number)
        {
            return Err(invalid("invalid persisted LVM device identity"));
        }
        if name == nbd && (device.start != 0 || root_sectors.replace(device.sectors).is_some()) {
            return Err(invalid("invalid persisted root NBD identity"));
        }
    }
    let root_sectors = root_sectors.ok_or_else(|| invalid("persisted NBD root is missing"))?;
    if verified
        .devices
        .iter()
        .any(|device| device.start + device.sectors > root_sectors)
    {
        return Err(invalid("persisted NBD partition is outside the device"));
    }
    let mut labels = BTreeSet::new();
    if verified.labels.is_empty()
        || verified.labels.iter().any(|(path, id)| {
            !paths.contains(path) || uuid(id).is_err() || !labels.insert(id.clone())
        })
        || uuid(&verified.vg_uuid).is_err()
        || uuid(&verified.lv_uuid).is_err()
        || verified.lvs.is_empty()
        || verified.lvs.len() > MAX_DEVICES
    {
        return Err(invalid("invalid persisted LVM metadata identity"));
    }
    let mut lv_ids = BTreeSet::new();
    for (name, id) in &verified.lvs {
        crate::config::check_lvm_name("persisted_lv_name", name)
            .map_err(|_| invalid("invalid persisted LV name"))?;
        if uuid(id).is_err() || !lv_ids.insert(id.clone()) {
            return Err(invalid("invalid persisted LV identity"));
        }
    }
    if verified.lvs.get(&record.attachment.lv_name) != Some(&verified.lv_uuid)
        || verified.layouts.keys().collect::<BTreeSet<_>>()
            != verified.lvs.values().collect::<BTreeSet<_>>()
        || verified.layouts.values().any(|layout| {
            layout.is_empty()
                || layout.iter().any(|token| {
                    token.is_empty()
                        || !token.bytes().all(|byte| {
                            byte.is_ascii_lowercase()
                                || byte.is_ascii_digit()
                                || byte == b'_'
                                || byte == b'-'
                        })
                })
                || (layout.contains("cache") && layout.contains("cachevol"))
        })
    {
        return Err(invalid("inconsistent persisted LVM identity"));
    }
    Ok(())
}

fn uuid(value: &str) -> io::Result<String> {
    // LVM IDs are alphanumeric, not RFC 4122 UUIDs.
    let widths = [6, 4, 4, 4, 4, 4, 6];
    let parts: Vec<_> = value.split('-').collect();
    if parts.len() != widths.len()
        || parts.iter().zip(widths).any(|(part, width)| {
            part.len() != width || !part.bytes().all(|b| b.is_ascii_alphanumeric())
        })
    {
        return Err(invalid("invalid LVM UUID"));
    }
    Ok(value.to_owned())
}

fn kernel_u64(path: &Path) -> io::Result<u64> {
    std::fs::read_to_string(path)?
        .trim()
        .parse()
        .map_err(|_| invalid("invalid kernel block geometry"))
}

fn number(path: &Path) -> io::Result<(u32, u32)> {
    let metadata = std::fs::metadata(path)?;
    if !metadata.file_type().is_block_device() {
        return Err(invalid("LVM candidate is not a block device"));
    }
    Ok((libc::major(metadata.rdev()), libc::minor(metadata.rdev())))
}

fn discover_at(
    sysfs: &Path,
    device: &str,
    mut dev_number: impl FnMut(&Path) -> io::Result<(u32, u32)>,
) -> io::Result<Vec<Device>> {
    if crate::probe::nbd_index(device).is_none() {
        return Err(invalid("invalid NBD device for LVM preflight"));
    }
    let nbd = device
        .strip_prefix("/dev/")
        .ok_or_else(|| invalid("invalid NBD path"))?;
    let root = sysfs.join(nbd).canonicalize()?;
    let total = kernel_u64(&root.join("size"))?;
    if total == 0 {
        return Err(invalid("NBD geometry is empty"));
    }
    let mut names = vec![nbd.to_owned()];
    for entry in std::fs::read_dir(sysfs)? {
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| invalid("invalid block name"))?;
        if name.starts_with(&format!("{nbd}p")) {
            if names.len() >= MAX_DEVICES {
                return Err(invalid("too many NBD partitions for LVM preflight"));
            }
            names.push(name);
        }
    }
    names.sort();
    let mut devices = Vec::new();
    let mut numbers = BTreeSet::new();
    for name in names {
        let path = sysfs.join(&name).canonicalize()?;
        let (start, sectors) = if name == nbd {
            (0, total)
        } else {
            if !crate::detach::is_nbd_partition(sysfs, &name, nbd)?
                || path.parent() != Some(root.as_path())
            {
                return Err(invalid(
                    "NBD partition is not a child of the recorded kernel device",
                ));
            }
            let start = kernel_u64(&path.join("start"))?;
            let sectors = kernel_u64(&path.join("size"))?;
            if sectors == 0 || start.checked_add(sectors).is_none_or(|end| end > total) {
                return Err(invalid("NBD partition lies outside the recorded device"));
            }
            (start, sectors)
        };
        if std::fs::read_dir(path.join("holders"))?
            .next()
            .transpose()?
            .is_some()
        {
            return Err(invalid("LVM candidate already has a kernel holder"));
        }
        let number = device_number(&std::fs::read_to_string(path.join("dev"))?)?;
        let path = format!("/dev/{name}");
        if !numbers.insert(number) || dev_number(Path::new(&path))? != number {
            return Err(invalid(
                "LVM candidate device node does not match kernel identity",
            ));
        }
        devices.push(Device {
            path,
            number,
            start,
            sectors,
        });
    }
    Ok(devices)
}

fn discover(record: &BoundDeviceRecord) -> io::Result<Vec<Device>> {
    discover_at(Path::new("/sys/class/block"), &record.device, number)
}

fn controlled_command(program: &str) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C");
    command
}

fn probe_label(output: &Output) -> io::Result<Option<String>> {
    // blkid status 2 conflates no signature with failures to gather data.
    // In particular, never treat that status as proof of an absent PV label.
    if !output.status.success() || !output.stderr.is_empty() || output.stdout.len() > MAX_REPORT {
        return Err(invalid("LVM candidate label probe failed or was ambiguous"));
    }
    let text =
        std::str::from_utf8(&output.stdout).map_err(|_| invalid("invalid block label report"))?;
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| invalid("invalid block label field"))?;
        if fields.insert(key, value).is_some() {
            return Err(invalid("duplicate block label field"));
        }
    }
    match fields.get("TYPE").copied() {
        Some("LVM2_member") if !fields.contains_key("PTTYPE") => uuid(
            fields
                .get("UUID")
                .ok_or_else(|| invalid("PV label has no UUID"))?,
        )
        .map(Some),
        Some("LVM2_member") => Err(invalid("PV label overlaps a partition table")),
        Some(value) if !value.is_empty() => Ok(None),
        None if fields.get("PTTYPE").is_some_and(|value| !value.is_empty()) => Ok(None),
        _ => Err(invalid("LVM candidate has no unambiguous recognized label")),
    }
}

fn read_labels(devices: &[Device]) -> io::Result<BTreeMap<String, String>> {
    let mut labels = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for device in devices {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&device.path)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_block_device()
            || (libc::major(metadata.rdev()), libc::minor(metadata.rdev())) != device.number
        {
            return Err(invalid("PV label probe device was replaced"));
        }
        // Hold the parent's descriptor: LVM itself closes inherited FDs, and
        // the same stable proc path pattern is used by the filesystem probe.
        let pinned = format!("/proc/{}/fd/{}", std::process::id(), file.as_raw_fd());
        let output = command::capture(
            controlled_command("blkid").args([
                "--probe",
                "--output",
                "export",
                "--match-tag",
                "TYPE",
                "--match-tag",
                "UUID",
                "--match-tag",
                "PTTYPE",
                &pinned,
            ]),
            command::Policy::PROBE,
        )?;
        if let Some(id) = probe_label(&output)? {
            if !seen.insert(id.clone()) {
                return Err(invalid("duplicate PV labels on NBD candidates"));
            }
            labels.insert(device.path.clone(), id);
        }
    }
    Ok(labels)
}

fn device_list(devices: &[Device]) -> String {
    devices
        .iter()
        .map(|device| device.path.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

fn report_command(devices: &[Device]) -> Command {
    let mut command = controlled_command("lvm");
    command.args(["fullreport", "--readonly", "--all", "--foreign", "--shared", "--reportformat", "json", "--binary",
        "--devices", &device_list(devices), "--config", r#"report { list_item_separator="," }"#,
        "--configreport", "vg", "--options", "vg_name,vg_uuid,vg_seqno,pv_count,vg_missing_pv_count,vg_partial,vg_exported,vg_systemid,vg_lock_type",
        "--configreport", "pv", "--options", "pv_name,pv_uuid,vg_uuid,pv_missing,pv_duplicate",
        "--configreport", "lv", "--options", "lv_name,lv_uuid,vg_uuid,lv_layout",
        "--configreport", "pvseg", "--options", "pv_uuid",
        "--configreport", "seg", "--options", "lv_uuid"]);
    command
}

#[derive(Deserialize)]
struct Report {
    report: Vec<Group>,
}
#[derive(Deserialize)]
struct Group {
    vg: Vec<Vg>,
    pv: Vec<Pv>,
    lv: Vec<Lv>,
}
#[derive(Deserialize)]
struct Vg {
    vg_name: String,
    vg_uuid: String,
    vg_seqno: String,
    pv_count: String,
    vg_missing_pv_count: String,
    vg_partial: String,
    vg_exported: String,
    vg_systemid: String,
    vg_lock_type: String,
}
#[derive(Deserialize)]
struct Pv {
    pv_name: String,
    pv_uuid: String,
    vg_uuid: String,
    pv_missing: String,
    pv_duplicate: String,
}
#[derive(Deserialize)]
struct Lv {
    lv_name: String,
    lv_uuid: String,
    vg_uuid: String,
    lv_layout: String,
}

pub(super) fn validate(
    bytes: &[u8],
    devices: Vec<Device>,
    labels: BTreeMap<String, String>,
    vg_name: &str,
    lv_name: &str,
    mut resolve_device: impl FnMut(&str) -> io::Result<(u32, u32)>,
) -> io::Result<VerifiedLvm> {
    if bytes.len() > MAX_REPORT || devices.is_empty() || devices.len() > MAX_DEVICES {
        return Err(invalid(
            "LVM preflight report or device count exceeds its bound",
        ));
    }
    let labelled: Vec<_> = devices
        .iter()
        .filter(|device| labels.contains_key(&device.path))
        .collect();
    for (index, first) in labelled.iter().enumerate() {
        let end = first
            .start
            .checked_add(first.sectors)
            .ok_or_else(|| invalid("PV range overflow"))?;
        if first.sectors == 0 {
            return Err(invalid("PV range is empty"));
        }
        for second in &labelled[index + 1..] {
            let other_end = second
                .start
                .checked_add(second.sectors)
                .ok_or_else(|| invalid("PV range overflow"))?;
            if first.start < other_end && second.start < end {
                return Err(invalid(
                    "independent PV labels overlap underlying NBD sectors",
                ));
            }
        }
    }
    let report: Report = serde_json::from_slice(bytes)
        .map_err(|_| invalid("invalid or unsupported LVM fullreport"))?;
    let mut selected = None;
    let mut pv_labels = BTreeMap::new();
    let mut all_pv_ids = BTreeSet::new();
    for group in report.report {
        if group.vg.len() != 1 {
            return Err(invalid("LVM fullreport has ambiguous VG membership"));
        }
        let vg = group.vg.into_iter().next().unwrap();
        let vg_id = uuid(&vg.vg_uuid)?;
        // A different VG in the candidate set is not owned by this attach.
        // It must not disappear through report filtering or activation flags.
        if vg.vg_name != vg_name || selected.is_some() {
            return Err(invalid(
                "NBD PV metadata contains a foreign or ambiguous VG",
            ));
        }
        if vg.vg_missing_pv_count != "0"
            || vg.vg_partial != "0"
            || vg.vg_exported != "0"
            || !vg.vg_systemid.is_empty()
            || !matches!(vg.vg_lock_type.as_str(), "" | "none")
        {
            return Err(invalid(
                "LVM VG is missing, partial, exported, or requires external ownership coordination",
            ));
        }
        let count: usize = vg
            .pv_count
            .parse()
            .map_err(|_| invalid("invalid VG PV count"))?;
        if count == 0 || count != group.pv.len() || count > devices.len() {
            return Err(invalid("LVM VG has incomplete PV membership"));
        }
        for pv in group.pv {
            let id = uuid(&pv.pv_uuid)?;
            if !pv.pv_name.starts_with("/dev/") {
                return Err(invalid("invalid LVM PV device path"));
            }
            let dev_number = resolve_device(&pv.pv_name)?;
            let device = devices
                .iter()
                .find(|device| device.number == dev_number)
                .ok_or_else(|| invalid("LVM PV is outside the verified NBD candidates"))?;
            if pv.vg_uuid != vg_id
                || pv.pv_missing != "0"
                || pv.pv_duplicate != "0"
                || labels.get(&device.path) != Some(&id)
                || !all_pv_ids.insert(id.clone())
                || pv_labels.insert(device.path.clone(), id).is_some()
            {
                return Err(invalid(
                    "LVM PV membership does not match unique verified NBD labels",
                ));
            }
        }
        let mut lvs = BTreeMap::new();
        let mut layouts = BTreeMap::new();
        let mut lv_ids = BTreeSet::new();
        for lv in group.lv {
            let id = uuid(&lv.lv_uuid)?;
            let mut layout = BTreeSet::new();
            for token in lv.lv_layout.split(',').map(str::trim) {
                if token.is_empty()
                    || !token.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-'
                    })
                    || !layout.insert(token.to_owned())
                {
                    return Err(invalid("invalid or unsupported LVM layout report"));
                }
            }
            // LVM cachevol format 2 can synthesize cdata/cmeta IDs that are
            // not LV UUIDs in fullreport. Refuse before creating mappings that
            // this unit could not verify or safely roll back afterwards.
            if layout.contains("cache") && layout.contains("cachevol") {
                return Err(invalid(
                    "cachevol synthetic mapping UUIDs are not supported by preflight",
                ));
            }
            layouts.insert(id.clone(), layout);
            if lv.vg_uuid != vg_id
                || lv.lv_name.is_empty()
                || !lv_ids.insert(id.clone())
                || lvs.insert(lv.lv_name, id).is_some()
            {
                return Err(invalid("LVM LV identity is foreign or ambiguous"));
            }
        }
        let lv_id = lvs
            .get(lv_name)
            .ok_or_else(|| invalid("configured LV is missing from verified VG"))?
            .clone();
        let seq = vg
            .vg_seqno
            .parse()
            .map_err(|_| invalid("invalid LVM metadata sequence"))?;
        selected = Some((vg_id, seq, lv_id, lvs, layouts));
    }
    if labels.is_empty() || labels != pv_labels {
        return Err(invalid(
            "LVM fullreport omitted independently observed PV labels",
        ));
    }
    let (vg_uuid, vg_seqno, lv_uuid, lvs, layouts) =
        selected.ok_or_else(|| invalid("configured VG is absent"))?;
    Ok(VerifiedLvm {
        devices,
        labels,
        vg_uuid,
        vg_seqno,
        lv_uuid,
        lvs,
        layouts,
    })
}

pub(super) fn prepare(record: &BoundDeviceRecord) -> Result<VerifiedLvm, ExecError> {
    let devices = discover(record)?;
    ensure_inactive(record)?;
    let labels = read_labels(&devices)?;
    let output = command::capture(&mut report_command(&devices), command::Policy::PROBE)?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(identity_error(
            "LVM read-only report failed or reported warnings",
        ));
    }
    Ok(validate(
        &output.stdout,
        devices,
        labels,
        &record.attachment.vg_name,
        &record.attachment.lv_name,
        |path| number(Path::new(path)),
    )?)
}

fn ensure_inactive(record: &BoundDeviceRecord) -> io::Result<()> {
    let observed = crate::detach::observe_kernel(
        record,
        &std::fs::read_to_string("/proc/self/mountinfo")?,
        Path::new("/sys/class/block"),
        false,
        false,
    )?;
    if observed.mounted || observed.vg_active || observed.nbd_in_use {
        return Err(invalid(
            "LVM preflight found an existing mount, mapping, or holder",
        ));
    }
    Ok(())
}

fn activation_command(verified: &VerifiedLvm) -> Command {
    let mut command = controlled_command("vgchange");
    command.args([
        "--activate",
        "y",
        "--activationmode",
        "complete",
        "--devices",
        &device_list(&verified.devices),
        "--select",
        &format!("vg_uuid={}", verified.vg_uuid),
        "--config",
        "devices { allow_changes_with_duplicate_pvs=0 }",
    ]);
    command
}

pub(super) fn activate(
    record: &BoundDeviceRecord,
    verified: &VerifiedLvm,
    attempted: &mut bool,
) -> Result<(), ExecError> {
    if &prepare(record)? != verified {
        return Err(identity_error(
            "LVM metadata or candidate identity changed before activation",
        ));
    }
    // Repeat both checks after the possibly blocking label/report reads.
    if discover(record)? != verified.devices {
        return Err(identity_error(
            "LVM candidate kernel identity changed before activation",
        ));
    }
    ensure_inactive(record)?;
    verify_connection(record, &LinuxSystem)?;
    *attempted = true;
    let output = command::capture(&mut activation_command(verified), command::Policy::STEP)?;
    if !output.status.success() {
        return Err(identity_error("scoped LVM activation failed"));
    }
    Ok(())
}

pub(super) fn verify_mapping(
    record: &BoundDeviceRecord,
    verified: &VerifiedLvm,
    sysfs: &Path,
) -> io::Result<()> {
    verify_mappings(record, verified, sysfs, true)
}

pub(super) fn verify_rollback_mapping(
    record: &BoundDeviceRecord,
    verified: &VerifiedLvm,
    sysfs: &Path,
) -> io::Result<()> {
    verify_mappings(record, verified, sysfs, false)
}

fn verify_recovery_devices(
    record: &BoundDeviceRecord,
    verified: &VerifiedLvm,
    sysfs: &Path,
) -> io::Result<()> {
    let nbd = record
        .device
        .strip_prefix("/dev/")
        .ok_or_else(|| invalid("invalid NBD path"))?;
    let mut actual = BTreeSet::new();
    for entry in std::fs::read_dir(sysfs)? {
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| invalid("invalid block name"))?;
        if name == nbd || crate::detach::is_nbd_partition(sysfs, &name, nbd)? {
            actual.insert(name);
        }
    }
    let expected: BTreeSet<_> = verified
        .devices
        .iter()
        .map(|device| {
            device
                .path
                .strip_prefix("/dev/")
                .ok_or_else(|| invalid("invalid persisted LVM device path"))
                .map(str::to_owned)
        })
        .collect::<io::Result<_>>()?;
    if actual != expected {
        return Err(invalid(
            "current NBD devices do not match the pre-activation identity",
        ));
    }
    for device in &verified.devices {
        let name = device.path.strip_prefix("/dev/").unwrap();
        let path = sysfs.join(name);
        if device_number(&std::fs::read_to_string(path.join("dev"))?)? != device.number
            || kernel_u64(&path.join("size"))? != device.sectors
            || (name != nbd
                && (kernel_u64(&path.join("start"))? != device.start
                    || !crate::detach::is_nbd_partition(sysfs, name, nbd)?))
            || (name == nbd && device.start != 0)
        {
            return Err(invalid(
                "current NBD geometry does not match the pre-activation identity",
            ));
        }
    }
    Ok(())
}

pub(super) fn verify_recovery_mapping(
    record: &BoundDeviceRecord,
    verified: &VerifiedLvm,
    sysfs: &Path,
) -> io::Result<()> {
    verify_recovery_devices(record, verified, sysfs)?;
    verify_mappings(record, verified, sysfs, true)
}

pub(super) fn verify_recovery_device_identity(
    record: &BoundDeviceRecord,
    verified: &VerifiedLvm,
    sysfs: &Path,
) -> io::Result<()> {
    verify_recovery_devices(record, verified, sysfs)
}

fn verify_mappings(
    record: &BoundDeviceRecord,
    verified: &VerifiedLvm,
    sysfs: &Path,
    require_target: bool,
) -> io::Result<()> {
    let expected_name = format!(
        "{}-{}",
        record.attachment.vg_name.replace('-', "--"),
        record.attachment.lv_name.replace('-', "--")
    );
    let expected_uuid = format!(
        "LVM-{}{}",
        verified.vg_uuid.replace('-', ""),
        verified.lv_uuid.replace('-', "")
    );
    let mut found = false;
    for entry in std::fs::read_dir(sysfs)? {
        let entry = entry?;
        if !entry.file_name().as_encoded_bytes().starts_with(b"dm-") {
            continue;
        }
        let path = entry.path();
        let name = std::fs::read_to_string(path.join("dm/name"))?;
        if crate::detach::mapped_volume_group(name.trim()).as_deref()
            != Some(&record.attachment.vg_name)
        {
            continue;
        }
        let actual_uuid = std::fs::read_to_string(path.join("dm/uuid"))?;
        let actual_uuid = actual_uuid.trim();
        let owned = verified.lvs.values().any(|id| {
            let base = format!(
                "LVM-{}{}",
                verified.vg_uuid.replace('-', ""),
                id.replace('-', "")
            );
            actual_uuid == base
                || actual_uuid
                    .strip_prefix(&base)
                    .is_some_and(|suffix| suffix.starts_with('-'))
        });
        if !owned {
            return Err(invalid("activated VG contains an unverified LV UUID"));
        }
        if name.trim() == expected_name {
            if found || actual_uuid != expected_uuid {
                return Err(invalid(
                    "activated LV UUID does not match preflight metadata",
                ));
            }
            found = true;
        }
    }
    if require_target && !found {
        return Err(invalid("verified LV was not activated"));
    }
    Ok(())
}

pub(super) fn deactivate(
    record: &BoundDeviceRecord,
    verified: &VerifiedLvm,
) -> Result<(), ExecError> {
    // Existing rollback observers verify the complete live topology and nonce.
    // Never let metadata lookup for that teardown escape the same PV scope.
    for device in &verified.devices {
        if number(Path::new(&device.path))? != device.number {
            return Err(identity_error("LVM candidate was replaced before rollback"));
        }
    }
    verify_connection(record, &LinuxSystem)?;
    let output = command::capture(&mut deactivation_command(verified), command::Policy::STEP)?;
    if !output.status.success() {
        return Err(identity_error("scoped LVM rollback failed"));
    }
    Ok(())
}

fn deactivation_command(verified: &VerifiedLvm) -> Command {
    let mut command = controlled_command("vgchange");
    command.args([
        "--activate",
        "n",
        "--devices",
        &device_list(&verified.devices),
        "--select",
        &format!("vg_uuid={}", verified.vg_uuid),
        "--config",
        "devices { allow_changes_with_duplicate_pvs=0 }",
    ]);
    command
}

pub(super) fn deactivate_recovery(
    record: &BoundDeviceRecord,
    verified: &VerifiedLvm,
) -> Result<(), ExecError> {
    verify_recovery_mapping(record, verified, Path::new("/sys/class/block"))?;
    for device in &verified.devices {
        if number(Path::new(&device.path))? != device.number {
            return Err(identity_error(
                "LVM recovery candidate was replaced before deactivation",
            ));
        }
    }
    if super::nbd_backend_at(Path::new("/sys/block"), &record.device)?.is_some() {
        return Err(identity_error(
            "NBD backend reappeared before recovery deactivation",
        ));
    }
    let output = command::capture(&mut deactivation_command(verified), command::Policy::STEP)?;
    if !output.status.success() {
        return Err(identity_error("scoped LVM recovery deactivation failed"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "lvm_preflight_tests.rs"]
mod tests;
