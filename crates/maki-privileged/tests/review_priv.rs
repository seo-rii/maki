//! Review M-006 / M-016 (pure parts, every platform): rollback derivation,
//! NBD device binding, attach configuration and argument hygiene, and the
//! parsers the Linux executor feeds with mountinfo, sysfs and /proc/swaps.

use maki_privileged::config::{
    check_abs_path, check_argument, check_uuid, parse, AttachConfig, AttachOverrides,
};
use maki_privileged::plan::{
    plan_attach, plan_detach, rollback_steps, PlannedStep, AUTO_NBD_DEVICE,
};
use maki_privileged::probe::{choose_free_nbd, nbd_index, parse_mountinfo};
use maki_privileged::verify::{verify_mount_identity, MountExpectation, MountObservation};

const UUID: &str = "0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c";

fn config_text() -> String {
    format!(
        r#"
volume_uuid = "{UUID}"
mountpoint = "/srv/pg"
vg_name = "vg_maki_pg"
device_block_size = 4096
"#
    )
}

// ---------- configuration ----------

#[test]
fn config_resolves_defaults_and_auto_device() {
    let cfg = parse(&config_text()).unwrap();
    let request = cfg
        .into_request("pg", AttachOverrides::default(), true)
        .unwrap();
    assert_eq!(request.nbd_device, AUTO_NBD_DEVICE);
    assert_eq!(request.nbd_socket, "/run/maki/pg/nbd.sock");
    assert_eq!(request.lv_name, "data");
    assert_eq!(request.mountpoint, "/srv/pg");
    assert_eq!(request.volume_uuid, UUID);
    assert!(!request.init_sentinel);
}

#[test]
fn execution_requires_a_volume_uuid_but_plan_rendering_does_not() {
    let cfg = AttachConfig::default();
    let err = cfg
        .clone()
        .into_request("pg", AttachOverrides::default(), true)
        .unwrap_err();
    assert!(err.to_string().contains("volume_uuid"), "{err}");
    let request = cfg
        .into_request("pg", AttachOverrides::default(), false)
        .unwrap();
    assert_eq!(request.volume_uuid, "<unset>");
}

#[test]
fn overrides_win_and_are_validated() {
    let cfg = parse(&config_text()).unwrap();
    let request = cfg
        .clone()
        .into_request(
            "pg",
            AttachOverrides {
                nbd_device: Some("/dev/nbd7".into()),
                mountpoint: Some("/mnt/pg".into()),
                ..Default::default()
            },
            true,
        )
        .unwrap();
    assert_eq!(request.nbd_device, "/dev/nbd7");
    assert_eq!(request.mountpoint, "/mnt/pg");

    for (field, value) in [
        ("nbd_device", "-d"),
        ("nbd_device", "/dev/sda"),
        ("mountpoint", "srv/pg"),
        ("mountpoint", "/srv/../etc"),
        ("mountpoint", "/srv/pg/"),
        ("vg_name", "vg/evil"),
        ("vg_name", "--force"),
        ("volume_uuid", "not-a-uuid"),
        ("fs_uuid", "zz7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c"),
    ] {
        let mut overrides = AttachOverrides::default();
        match field {
            "nbd_device" => overrides.nbd_device = Some(value.into()),
            "mountpoint" => overrides.mountpoint = Some(value.into()),
            "vg_name" => overrides.vg_name = Some(value.into()),
            "volume_uuid" => overrides.volume_uuid = Some(value.into()),
            "fs_uuid" => overrides.fs_uuid = Some(value.into()),
            _ => unreachable!(),
        }
        let err = cfg
            .clone()
            .into_request("pg", overrides, true)
            .expect_err(&format!("{field}={value} must be rejected"));
        assert!(err.to_string().contains(field), "{field}: {err}");
    }
    assert!(parse(&config_text())
        .unwrap()
        .into_request("bad name", AttachOverrides::default(), true)
        .is_err());
    assert!(
        parse("unknown_key = 1\n").is_err(),
        "unknown fields rejected"
    );
}

#[test]
fn argument_hygiene() {
    assert!(check_argument("x", "value").is_ok());
    assert!(check_argument("x", "").is_err());
    assert!(check_argument("x", "-rf").is_err());
    assert!(check_argument("x", "a\nb").is_err());
    assert!(check_abs_path("p", "/a/b").is_ok());
    assert!(check_abs_path("p", "/").is_ok());
    assert!(check_abs_path("p", "a/b").is_err());
    assert!(check_abs_path("p", "/a//b").is_err());
    assert!(check_abs_path("p", "/a/./b").is_err());
    assert!(check_uuid("u", UUID).is_ok());
    assert!(check_uuid("u", &UUID.to_uppercase()).is_ok());
    assert!(check_uuid("u", "0f7c2b1a3d4e4f5a8b6c7d8e9f0a1b2c").is_err());
}

// ---------- plans ----------

fn request() -> maki_privileged::plan::AttachRequest {
    parse(&config_text())
        .unwrap()
        .into_request("pg", AttachOverrides::default(), true)
        .unwrap()
}

#[test]
fn attach_plan_binds_the_allocated_device_everywhere() {
    let mut plan = plan_attach(&request());
    assert!(plan.needs_device_allocation());
    assert!(plan.to_string().contains(AUTO_NBD_DEVICE));
    plan.bind_device("/dev/nbd3");
    assert!(!plan.needs_device_allocation());
    let rendered = plan.to_string();
    assert!(!rendered.contains("<auto>"), "{rendered}");
    assert!(rendered.contains("nbd-client -unix /run/maki/pg/nbd.sock /dev/nbd3 -b 4096"));
    assert!(rendered.contains("blockdev --setbsz 4096 /dev/nbd3"));
    assert!(rendered.contains("nbd /dev/nbd3)"), "{rendered}");
    let mut detach = plan_detach(&request());
    detach.bind_device("/dev/nbd3");
    assert!(detach.to_string().contains("nbd-client -d /dev/nbd3"));
}

#[test]
fn nbd_connect_uses_the_configured_block_size() {
    let mut cfg = parse(&config_text()).unwrap();
    cfg.device_block_size = Some(512);
    let plan = plan_attach(
        &cfg.into_request("pg", AttachOverrides::default(), true)
            .unwrap(),
    );
    assert!(plan.to_string().contains("-b 512"), "{plan}");
    assert!(plan.to_string().contains("--setbsz 512"), "{plan}");
}

#[test]
fn init_sentinel_adds_a_write_step_before_verification() {
    let cfg = parse(&format!("{}\ninit_sentinel = true\n", config_text())).unwrap();
    let plan = plan_attach(
        &cfg.into_request("pg", AttachOverrides::default(), true)
            .unwrap(),
    );
    let kinds: Vec<&str> = plan.steps.iter().map(|s| s.kind()).collect();
    assert_eq!(
        kinds,
        [
            "modprobe-nbd",
            "nbd-connect",
            "set-block-size",
            "lvm-activate",
            "mount-xfs",
            "write-sentinel",
            "verify-mount-identity"
        ]
    );
}

#[test]
fn rollback_reverses_the_executed_prefix() {
    let plan = plan_attach(&request());
    // Failure at verify: everything before it ran.
    let executed: Vec<PlannedStep> = plan.steps[..5].to_vec();
    let rollback = rollback_steps(&executed);
    let kinds: Vec<&str> = rollback.iter().map(|s| s.kind()).collect();
    assert_eq!(kinds, ["umount", "lvm-deactivate", "nbd-disconnect"]);
    // Failure right after nbd-connect: only the disconnect.
    let kinds: Vec<&str> = rollback_steps(&plan.steps[..2])
        .iter()
        .map(|s| s.kind())
        .collect();
    assert_eq!(kinds, ["nbd-disconnect"]);
    assert!(rollback_steps(&[]).is_empty());
    assert!(
        rollback_steps(&plan.steps[..1]).is_empty(),
        "modprobe needs no undo"
    );
}

// ---------- probes ----------

const MOUNTINFO: &str = "\
25 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw
40 25 253:2 / /srv/pg rw,noatime - xfs /dev/mapper/vg_maki_pg-data rw
41 25 0:44 / /srv/my\\040vol rw - xfs /dev/mapper/vg-x rw
42 25 253:3 / /srv/pg rw - ext4 /dev/mapper/other rw
";

#[test]
fn mountinfo_parsing_finds_the_visible_mount_and_decodes_escapes() {
    let entry = parse_mountinfo(MOUNTINFO, "/srv/pg").unwrap();
    assert_eq!(entry.fstype, "ext4", "the last (topmost) mount wins");
    assert_eq!(entry.source, "/dev/mapper/other");
    let first_two: String = MOUNTINFO.lines().take(2).collect::<Vec<_>>().join("\n");
    let entry = parse_mountinfo(&first_two, "/srv/pg").unwrap();
    assert_eq!(entry.fstype, "xfs");
    assert_eq!(entry.source, "/dev/mapper/vg_maki_pg-data");
    let spaced = parse_mountinfo(MOUNTINFO, "/srv/my vol").unwrap();
    assert_eq!(spaced.source, "/dev/mapper/vg-x");
    assert!(parse_mountinfo(MOUNTINFO, "/srv/nothing").is_none());
    assert!(parse_mountinfo("garbage line\n", "/").is_none());
}

#[test]
fn free_nbd_allocation_picks_the_lowest_unconnected_device() {
    let devices = vec![
        ("nbd0".to_string(), true),
        ("nbd10".to_string(), false),
        ("nbd2".to_string(), false),
        ("nbd1".to_string(), true),
        ("sda".to_string(), false),
    ];
    assert_eq!(choose_free_nbd(&devices).as_deref(), Some("/dev/nbd2"));
    assert!(choose_free_nbd(&[("nbd0".to_string(), true)]).is_none());
    assert!(choose_free_nbd(&[]).is_none());
    assert_eq!(nbd_index("/dev/nbd12"), Some(12));
    assert_eq!(nbd_index("/dev/sda"), None);
}

// ---------- verifier stays strict ----------

#[test]
fn verifier_rejects_wrong_device_and_missing_sentinel() {
    let expected = MountExpectation {
        fs_uuid: Some("f".repeat(8)),
        volume_uuid: UUID.to_string(),
    };
    let mut observed = MountObservation {
        mountpoint_exists: true,
        fstype: Some("xfs".into()),
        fs_uuid: Some("f".repeat(8)),
        sentinel_volume_uuid: Some(UUID.into()),
        nbd_connected: true,
        rw_probe_ok: true,
    };
    verify_mount_identity(&expected, &observed).unwrap();
    observed.sentinel_volume_uuid = None;
    assert!(verify_mount_identity(&expected, &observed).is_err());
    observed.sentinel_volume_uuid = Some(UUID.into());
    observed.fs_uuid = Some("other".into());
    assert!(verify_mount_identity(&expected, &observed).is_err());
}
