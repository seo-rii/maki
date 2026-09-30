//! Review R5-002: the XFS volume is mounted by root, but its bytes are
//! whatever the unprivileged daemon (and an untrusted provider) serves. A
//! crafted image with a setuid-root binary or a device node for a host disk
//! must not become a local privilege escalation, so the mount carries
//! `nosuid,nodev` and the post-mount verification refuses a mount without
//! them.

use maki_privileged::plan::PlannedStep;
use maki_privileged::probe::parse_mountinfo;
use maki_privileged::verify::{verify_mount_device, MountObservation};

fn observation(options: &[&str]) -> MountObservation {
    MountObservation {
        mountpoint_exists: true,
        fstype: Some("xfs".into()),
        fs_uuid: None,
        sentinel_volume_uuid: None,
        nbd_connected: true,
        rw_probe_ok: false,
        backing_devices: vec!["/dev/nbd0".into()],
        mount_options: options.iter().map(|o| o.to_string()).collect(),
    }
}

#[test]
fn the_planned_mount_is_nosuid_and_nodev() {
    let step = PlannedStep::MountXfs {
        device: "/dev/vg_maki_pg/data".into(),
        mountpoint: "/srv/pg".into(),
    };
    let rendered = step.to_string();
    let options = rendered
        .split_whitespace()
        .skip_while(|word| *word != "-o")
        .nth(1)
        .unwrap();
    let options: Vec<&str> = options.split(',').collect();
    for required in ["nosuid", "nodev", "noatime"] {
        assert!(options.contains(&required), "{rendered}");
    }
}

#[test]
fn mountinfo_reports_the_per_mount_options() {
    let entry = parse_mountinfo(
        "40 25 253:2 / /srv/pg rw,nosuid,nodev,noatime shared:1 - xfs /dev/mapper/vg-data rw\n",
        "/srv/pg",
    )
    .unwrap();
    assert_eq!(entry.mount_options, ["rw", "nosuid", "nodev", "noatime"]);
}

#[test]
fn a_mount_without_nosuid_or_nodev_is_refused() {
    verify_mount_device("/dev/nbd0", &observation(&["rw", "nosuid", "nodev"])).unwrap();
    for options in [
        &["rw", "noatime"][..],
        &["rw", "nosuid"][..],
        &["rw", "nodev"][..],
        &[][..],
    ] {
        let error = verify_mount_device("/dev/nbd0", &observation(options)).unwrap_err();
        assert!(error.to_string().contains("nosuid"), "{error}");
    }
}
