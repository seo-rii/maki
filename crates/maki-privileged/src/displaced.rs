//! A trusted record whose NBD device carries another connection: another
//! volume attached on it by a helper from before records reserved their
//! devices, or an NBD client started outside the helper. The device is no
//! longer the record's, but the record is still the only authority over what
//! its attachment may have left behind: a mount at its mountpoint, or a
//! mapping of its volume group, which on the device's number would now read
//! the other connection's data.
//!
//! These read-only observations decide whether the record may be retired.
//! Only device-mapper names an LVM mapping by the VG it belongs to: its uuid
//! is `LVM-<VG UUID><LV UUID>[-suffix]`, the UUIDs without their dashes, set
//! when LVM creates it. A holder of the device whose uuid names another VG
//! is therefore not the recorded attachment's, whoever set up the present
//! connection.

use std::collections::BTreeSet;
use std::io;
use std::path::Path;

use crate::detach::{device_number, is_nbd_partition, mount_device_number};
use crate::state::BoundDeviceRecord;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// The VG UUID of an LVM mapping's device-mapper uuid,
/// `LVM-<VG UUID><LV UUID>` with an optional `-<suffix>` for internal LVs
/// (`-tdata`, `-real`, ...), both UUIDs without their dashes. `None` for
/// every other uuid, an empty one included.
fn lvm_mapping_vg(uuid: &str) -> Option<&str> {
    let identity = uuid.strip_prefix("LVM-")?;
    let (uuids, suffix) = identity.split_at_checked(64)?;
    let suffix_ok = suffix.is_empty()
        || suffix.strip_prefix('-').is_some_and(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        });
    (uuids.bytes().all(|byte| byte.is_ascii_alphanumeric()) && suffix_ok).then(|| &uuids[..32])
}

/// An LVM UUID as device-mapper writes it: 32 alphanumerics, no dashes.
fn bare(uuid: &str) -> Option<String> {
    let bare = uuid.replace('-', "");
    (bare.len() == 32 && bare.bytes().all(|byte| byte.is_ascii_alphanumeric())).then_some(bare)
}

/// The recorded attachment's VG UUID, as device-mapper writes it, from
/// everything in the record that names it: the completed mapping proof, the
/// pre-activation intent and the administrator pins. They must agree. `Err`
/// says why the record names none; it then cannot show that a mapping is
/// not its volume group's.
pub(super) fn recorded_vg_uuid(record: &BoundDeviceRecord) -> Result<String, &'static str> {
    let mut named = BTreeSet::new();
    let pins = record
        .attachment
        .lvm_identity
        .as_ref()
        .map(|pins| bare(&pins.vg_uuid));
    let intent = record
        .recovery_intent
        .as_ref()
        .map(|intent| bare(intent.verified().vg_uuid()));
    let proof = record.recovery.as_ref().map(|proof| proof.vg_uuid());
    for uuid in [pins, intent, proof].into_iter().flatten() {
        named.insert(uuid.ok_or("the record names its VG UUID in an unexpected form")?);
    }
    let mut named = named.into_iter();
    match (named.next(), named.next()) {
        (Some(uuid), None) => Ok(uuid),
        (None, _) => Err(
            "the record carries no VG UUID (no mapping proof, activation intent or administrator \
             LVM pins), so no mapping can be shown not to be its volume group's",
        ),
        (Some(_), Some(_)) => Err("the record names more than one VG UUID"),
    }
}

/// What the host still shows of `record`'s attachment, whose device carries
/// another connection, or `None` when it shows nothing. `vg_uuid` is
/// [`recorded_vg_uuid`]. Every read must succeed: an observation that
/// cannot be made is an error, never "nothing remains".
///
/// Something remains while a mount sits at the recorded mountpoint, a mount
/// is of a mapping of the recorded VG, any device-mapper device on the host
/// belongs to that VG, or a holder of the device or of one of its partitions
/// is not an LVM mapping of another VG: a crypt, multipath or partition
/// mapping, or one without a uuid, could have been set up on the recorded
/// VG's device as well as on the present connection's.
pub(super) fn remains(
    record: &BoundDeviceRecord,
    vg_uuid: &str,
    mounts: &[u8],
    sysfs: &Path,
) -> io::Result<Option<String>> {
    let index = crate::probe::nbd_index(&record.device)
        .ok_or_else(|| invalid("invalid recorded NBD device"))?;
    let nbd = format!("nbd{index}");
    let owned = format!("LVM-{vg_uuid}");
    // The recorded VG's mappings, by kernel name and device number, and the
    // holders of the device and of its partitions.
    let mut mappings = Vec::new();
    let mut holders = Vec::new();
    for entry in std::fs::read_dir(sysfs)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid("invalid kernel block name"))?;
        if name == nbd || is_nbd_partition(sysfs, &name, &nbd)? {
            for holder in std::fs::read_dir(entry.path().join("holders"))? {
                let holder = holder?
                    .file_name()
                    .into_string()
                    .map_err(|_| invalid("invalid kernel block name"))?;
                holders.push((name.clone(), holder));
            }
        }
        if name.starts_with("dm-") {
            let uuid = std::fs::read_to_string(entry.path().join("dm/uuid"))?;
            if uuid.trim().starts_with(&owned) {
                let number = device_number(&std::fs::read_to_string(entry.path().join("dev"))?)?;
                mappings.push((name, number));
            }
        }
    }

    for line in crate::probe::mountinfo_lines(mounts).filter(|line| !line.trim_ascii().is_empty()) {
        let mount =
            crate::probe::mount_record(line).ok_or_else(|| invalid("incomplete mountinfo"))?;
        let mountpoint = crate::probe::unescape(mount.mountpoint);
        if mountpoint == record.attachment.mountpoint.as_bytes() {
            return Ok(Some(format!(
                "something is mounted at the recorded mountpoint {}",
                record.attachment.mountpoint
            )));
        }
        let device = mount_device_number(mount.device)?;
        if let Some((name, _)) = mappings.iter().find(|(_, number)| *number == device) {
            return Ok(Some(format!(
                "{name}, a mapping of the recorded volume group, is mounted at {:?}",
                String::from_utf8_lossy(&mountpoint)
            )));
        }
    }

    if let Some((name, _)) = mappings.first() {
        return Ok(Some(
            match holders
                .iter()
                .find(|(_, holder)| holder == name)
                .map(|(device, _)| device)
            {
                Some(device) => format!(
                    "{name} is a mapping of the recorded volume group on /dev/{device}; it now \
                     reads the other connection's data"
                ),
                None => format!("{name} is a mapping of the recorded volume group"),
            },
        ));
    }
    for (device, holder) in &holders {
        if !holder.starts_with("dm-") {
            return Ok(Some(format!(
                "{holder} holds /dev/{device} and is not a device-mapper device, so it cannot be \
                 shown not to be the recorded attachment's"
            )));
        }
        // A holder that appeared after the walk above is read here.
        let uuid = std::fs::read_to_string(sysfs.join(holder).join("dm/uuid"))?;
        match lvm_mapping_vg(uuid.trim()) {
            Some(vg) if vg != vg_uuid => {}
            Some(_) => {
                return Ok(Some(format!(
                    "{holder} is a mapping of the recorded volume group on /dev/{device}; it \
                     now reads the other connection's data"
                )))
            }
            None => {
                return Ok(Some(format!(
                    "{holder} holds /dev/{device} and is not an LVM mapping of another volume \
                     group, so it cannot be shown not to be the recorded attachment's"
                )))
            }
        }
    }
    Ok(None)
}
