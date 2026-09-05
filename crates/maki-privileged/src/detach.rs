//! Read-only detach observations. Absence is distinct from a failed probe:
//! retries may skip completed work only after checking the current kernel
//! mount and device-mapper topology against the trusted attachment.

use std::collections::HashSet;
use std::io;
use std::path::Path;

use crate::state::BoundDeviceRecord;

#[derive(Debug, Clone, Copy)]
pub(crate) struct DetachObservation {
    pub mounted: bool,
    pub vg_active: bool,
    pub nbd_in_use: bool,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn device_number(value: &str) -> io::Result<(u32, u32)> {
    let (major, minor) = value
        .trim()
        .split_once(':')
        .ok_or_else(|| invalid("invalid kernel device number"))?;
    Ok((
        major
            .parse()
            .map_err(|_| invalid("invalid kernel device major"))?,
        minor
            .parse()
            .map_err(|_| invalid("invalid kernel device minor"))?,
    ))
}

fn mapped_volume_group(name: &str) -> Option<String> {
    let mut group = String::new();
    let mut chars = name.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '-' {
            if chars.peek() != Some(&'-') {
                return Some(group);
            }
            chars.next();
        }
        group.push(c);
    }
    None
}

fn is_nbd_partition(sysfs: &Path, name: &str, nbd: &str) -> io::Result<bool> {
    let Some(suffix) = name.strip_prefix(&format!("{nbd}p")) else {
        return Ok(false);
    };
    if suffix.is_empty() || !suffix.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(false);
    }
    let expected: u32 = suffix
        .parse()
        .map_err(|_| invalid("invalid NBD partition number"))?;
    let actual: u32 = std::fs::read_to_string(sysfs.join(name).join("partition"))?
        .trim()
        .parse()
        .map_err(|_| invalid("invalid NBD partition number"))?;
    if expected == 0 || actual != expected {
        return Err(invalid(
            "NBD partition name does not match its kernel partition number",
        ));
    }
    Ok(true)
}

fn depends_only_on(
    sysfs: &Path,
    name: &str,
    nbd: &str,
    visiting: &mut HashSet<String>,
) -> io::Result<bool> {
    if name == nbd {
        return Ok(true);
    }
    // A partition of the recorded device is also backed by that device.
    if is_nbd_partition(sysfs, name, nbd)? {
        return Ok(true);
    }
    if visiting.len() >= 64 || !visiting.insert(name.to_string()) {
        return Err(invalid("cyclic or excessive block-device dependency depth"));
    }
    let mut any = false;
    for slave in std::fs::read_dir(sysfs.join(name).join("slaves"))? {
        let name = slave?.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| invalid("invalid block-device name"))?;
        if !depends_only_on(sysfs, name, nbd, visiting)? {
            return Ok(false);
        }
        any = true;
    }
    visiting.remove(name);
    Ok(any)
}

pub(crate) fn observe(
    record: &BoundDeviceRecord,
    mountinfo: &str,
    sysfs: &Path,
) -> io::Result<DetachObservation> {
    let nbd_index = crate::probe::nbd_index(&record.device)
        .ok_or_else(|| invalid("invalid recorded NBD device"))?;
    let nbd = format!("nbd{nbd_index}");
    let vg_prefix = format!("{}-", record.attachment.vg_name.replace('-', "--"));
    let lv_name = format!(
        "{vg_prefix}{}",
        record.attachment.lv_name.replace('-', "--")
    );
    let mut vg_active = false;
    let mut expected_lv_device = None;
    let mut nbd_devices = HashSet::new();
    let mut nbd_in_use = false;
    for entry in std::fs::read_dir(sysfs)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name == nbd || is_nbd_partition(sysfs, name, &nbd)? {
            nbd_devices.insert(device_number(&std::fs::read_to_string(
                entry.path().join("dev"),
            )?)?);
            if std::fs::read_dir(entry.path().join("holders"))?
                .next()
                .transpose()?
                .is_some()
            {
                nbd_in_use = true;
            }
        }
        if !name.starts_with("dm-") {
            continue;
        }
        let dm_name = std::fs::read_to_string(entry.path().join("dm/name"))?;
        if mapped_volume_group(dm_name.trim()).as_deref() != Some(&record.attachment.vg_name) {
            continue;
        }
        let uuid = std::fs::read_to_string(entry.path().join("dm/uuid"))?;
        if !uuid.starts_with("LVM-") || !depends_only_on(sysfs, name, &nbd, &mut HashSet::new())? {
            return Err(invalid(
                "active VG mapping is not backed exclusively by the recorded NBD device",
            ));
        }
        vg_active = true;
        if dm_name.trim() == lv_name {
            expected_lv_device = Some(device_number(&std::fs::read_to_string(
                entry.path().join("dev"),
            )?)?);
        }
    }

    let mut mounted_device = None;
    for line in mountinfo.lines().filter(|line| !line.trim().is_empty()) {
        let (left, right) = line
            .split_once(" - ")
            .ok_or_else(|| invalid("incomplete mountinfo observation"))?;
        let fields: Vec<_> = left.split_whitespace().collect();
        let filesystem: Vec<_> = right.split_whitespace().collect();
        if fields.len() < 6 || filesystem.len() < 3 {
            return Err(invalid("incomplete mountinfo observation"));
        }
        let device = device_number(fields[2])?;
        // Partitions have their own holders directories, and direct
        // filesystem mounts are represented in mountinfo rather than in
        // holders. Neither may be mistaken for an entirely unused NBD.
        nbd_in_use |= nbd_devices.contains(&device);
        if crate::probe::unescape(fields[4]) == record.attachment.mountpoint {
            // Every entry at the target must belong to the same complete
            // filesystem. A stacked or bind-subtree mount is not safe to
            // unmount as part of this recorded attachment.
            if crate::probe::unescape(fields[3]) != "/"
                || filesystem[0] != "xfs"
                || expected_lv_device != Some(device)
                || mounted_device.is_some()
            {
                return Err(invalid(
                    "mountpoint no longer identifies the recorded XFS logical volume",
                ));
            }
            mounted_device = Some(device);
        }
    }
    let mounted = mounted_device.is_some();
    if mounted
        && crate::exec::read_sentinel(&record.attachment.mountpoint).as_deref()
            != Some(&record.attachment.volume_uuid)
    {
        return Err(invalid(
            "mounted volume sentinel no longer matches the attachment",
        ));
    }
    Ok(DetachObservation {
        mounted,
        vg_active,
        nbd_in_use,
    })
}

#[cfg(test)]
#[path = "detach_tests.rs"]
mod tests;
