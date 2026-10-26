//! Read-only automatic NBD admission. A missing connection does not imply
//! an unused device: stale mappings and direct mounts may remain. Selection
//! runs under the attach lock; the executor rechecks its chosen device before
//! publishing an attachment or connecting it.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};
use std::path::Path;

use super::ExecError;

const MAX_BLOCK_DEVICES: usize = 65_536;
const MAX_MOUNTINFO_BYTES: usize = 16 * 1024 * 1024;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(super) fn allocate(sysfs: &Path, mountinfo: &Path) -> Result<String, ExecError> {
    let mut mounts = String::new();
    std::fs::File::open(mountinfo)?
        .take(MAX_MOUNTINFO_BYTES as u64 + 1)
        .read_to_string(&mut mounts)?;
    choose(sysfs, &mounts)
}

fn choose(sysfs: &Path, mountinfo: &str) -> Result<String, ExecError> {
    if mountinfo.len() > MAX_MOUNTINFO_BYTES {
        return Err(invalid("mount inventory exceeds the allocation observation limit").into());
    }
    let mut mounted = BTreeSet::new();
    for line in mountinfo.lines().filter(|line| !line.trim().is_empty()) {
        let (left, right) = line
            .split_once(" - ")
            .ok_or_else(|| invalid("incomplete mount inventory during NBD allocation"))?;
        let mut fields = crate::probe::mountinfo_fields(left);
        let number = fields
            .nth(2)
            .ok_or_else(|| invalid("incomplete mount inventory during NBD allocation"))?;
        if fields.take(3).count() != 3 || crate::probe::mountinfo_fields(right).take(3).count() != 3
        {
            return Err(invalid("incomplete mount inventory during NBD allocation").into());
        }
        mounted.insert(crate::detach::device_number(number)?);
    }

    // Group root devices and their partitions in one bounded sysfs pass.
    // Numeric root ordering keeps nbd2 ahead of nbd10.
    let mut devices: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    for (count, entry) in std::fs::read_dir(sysfs)?.enumerate() {
        if count >= MAX_BLOCK_DEVICES {
            return Err(invalid("block inventory exceeds the allocation observation limit").into());
        }
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid("invalid kernel block name"))?;
        let Some(device) = crate::probe::nbd_device_of(&name) else {
            continue;
        };
        let index =
            crate::probe::nbd_index(&device).ok_or_else(|| invalid("invalid kernel NBD name"))?;
        devices.entry(index).or_default().push(name);
    }
    'candidate: for (index, names) in devices {
        let root = format!("nbd{index}");
        let device = format!("/dev/{root}");
        // A PID alone is sufficient to establish occupancy, including NBDs
        // connected by clients that do not publish a backend identifier.
        if sysfs.join(&root).join("pid").try_exists()?
            || super::nbd_backend_at(sysfs, &device)?.is_some()
        {
            continue;
        }
        if !names.contains(&root) {
            return Err(invalid("NBD root disappeared from the block inventory").into());
        }
        for name in names {
            if name != root && !crate::detach::is_nbd_partition(sysfs, &name, &root)? {
                return Err(invalid("invalid NBD partition in block inventory").into());
            }
            let path = sysfs.join(name);
            let number = crate::detach::device_number(&std::fs::read_to_string(path.join("dev"))?)?;
            // Direct mounts are absent from holders. Partition holders are
            // absent from the root NBD's holders, so both must be checked.
            if mounted.contains(&number)
                || std::fs::read_dir(path.join("holders"))?
                    .next()
                    .transpose()?
                    .is_some()
            {
                continue 'candidate;
            }
        }
        return Ok(device);
    }
    Err(ExecError::NoFreeDevice)
}

#[cfg(test)]
#[path = "allocation_tests.rs"]
mod tests;
