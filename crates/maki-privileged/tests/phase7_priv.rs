//! Phase 7 — privilege model (SPEC §4–§6, §49).
//!
//! PRIV-001/002/012/015/016 are enforced by systemd; here we pin the unit
//! files so a packaging regression fails CI. PRIV-010 is enforced by
//! construction (the helper has no credential machinery) and pinned by plan
//! inspection. OS-level enforcement is exercised by the Linux checklist in
//! docs/operations.md.

use maki_privileged::plan::{plan_attach, plan_detach, plan_grow, AttachRequest, GrowRequest};
use maki_privileged::verify::{verify_mount_identity, MountExpectation, MountObservation};

fn packaging(path: &str) -> String {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../packaging/");
    std::fs::read_to_string(format!("{root}{path}"))
        .unwrap_or_else(|e| panic!("missing packaging file {path}: {e}"))
}

// ---------- packaging pins (PRIV-001/002/012/015 + sandbox) ----------

#[test]
fn data_plane_unit_is_unprivileged_and_sandboxed() {
    let unit = packaging("systemd/maki@.service");
    for required in [
        "User=maki", // PRIV-001: UID != 0
        "Group=maki",
        "CapabilityBoundingSet=", // PRIV-002: empty capability set
        "AmbientCapabilities=",
        "NoNewPrivileges=yes",
        "LimitCORE=0",          // PRIV-015: no core dumps
        "Restart=on-failure",   // PRIV-012: restart after failure
        "ProtectSystem=strict", // PRIV-004: /etc immutable
        "ProtectHome=yes",
        "PrivateTmp=yes",
        "ReadWritePaths=/var/lib/maki/%i",
        "ReadWritePaths=/run/maki/%i",
        "LoadCredential=",
    ] {
        assert!(
            unit.contains(required),
            "maki@.service must contain {required:?}"
        );
    }
    assert!(
        !unit.contains("User=root"),
        "data plane must never run as root"
    );
}

#[test]
fn users_groups_and_directories_are_declared() {
    let sysusers = packaging("sysusers.d/maki.conf");
    assert!(sysusers.contains("u maki "), "maki system user");
    assert!(sysusers.contains("g maki-admin"), "maki-admin group");

    let tmpfiles = packaging("tmpfiles.d/maki.conf");
    assert!(tmpfiles.contains("/run/maki"));
    assert!(tmpfiles.contains("/var/lib/maki"));
    // PRIV-006/007 groundwork: runtime dirs are not world-accessible.
    for line in tmpfiles.lines().filter(|l| l.starts_with('d')) {
        let mode = line.split_whitespace().nth(2).unwrap_or("");
        assert!(
            mode.ends_with('0'),
            "runtime dirs must exclude 'other': {line}"
        );
    }
}

#[test]
fn helper_unit_is_oneshot_and_separate() {
    let unit = packaging("systemd/maki-attach@.service");
    assert!(unit.contains("Type=oneshot"));
    assert!(unit.contains("maki-attach"));
    // The helper never receives crypto credentials (PRIV-010).
    assert!(
        !unit.contains("LoadCredential"),
        "privileged helper must not load crypto credentials"
    );
}

// ---------- attach/detach/grow plans ----------

fn request() -> AttachRequest {
    AttachRequest {
        volume: "postgres".to_string(),
        nbd_socket: "/run/maki/postgres/nbd.sock".to_string(),
        nbd_device: "/dev/nbd0".to_string(),
        device_block_size: 4096,
        vg_name: "vg_maki_postgres".to_string(),
        lv_name: "data".to_string(),
        mountpoint: "/srv/postgres".to_string(),
        volume_uuid: "0123-4567".to_string(),
        fs_uuid: None,
        init_sentinel: false,
    }
}

#[test]
fn attach_plan_has_expected_step_order() {
    let plan = plan_attach(&request());
    let kinds: Vec<&'static str> = plan.steps.iter().map(|s| s.kind()).collect();
    assert_eq!(
        kinds,
        [
            "modprobe-nbd",
            "nbd-connect",
            "set-block-size",
            "lvm-activate",
            "mount-xfs",
            "verify-mount-identity",
        ]
    );
}

/// PRIV-010: the privileged helper's plan never references key material,
/// tokens, or plaintext—it is purely a storage control-plane actor.
#[test]
fn plans_contain_no_credential_material() {
    let rendered = format!(
        "{}\n{}\n{}",
        plan_attach(&request()),
        plan_detach(&request()),
        plan_grow(&GrowRequest {
            volume: "postgres".into(),
            vg_name: "vg_maki_postgres".into(),
            lv_name: "data".into(),
            add_bytes: 10 << 30,
            mountpoint: "/srv/postgres".into(),
        })
    );
    let lower = rendered.to_lowercase();
    for forbidden in [
        "credential",
        "token",
        "secret",
        "key=",
        "tls",
        "authorization",
    ] {
        assert!(
            !lower.contains(forbidden),
            "plan leaked credential-adjacent term {forbidden:?}:\n{rendered}"
        );
    }
}

#[test]
fn detach_plan_reverses_attach() {
    let plan = plan_detach(&request());
    let kinds: Vec<&'static str> = plan.steps.iter().map(|s| s.kind()).collect();
    assert_eq!(
        kinds,
        ["umount", "lvm-deactivate", "nbd-disconnect"],
        "detach must unmount before disconnecting NBD"
    );
}

#[test]
fn grow_plan_is_lvextend_then_xfs_growfs() {
    let plan = plan_grow(&GrowRequest {
        volume: "postgres".into(),
        vg_name: "vg".into(),
        lv_name: "data".into(),
        add_bytes: 1 << 30,
        mountpoint: "/srv/postgres".into(),
    });
    let kinds: Vec<&'static str> = plan.steps.iter().map(|s| s.kind()).collect();
    assert_eq!(kinds, ["lvextend", "xfs-growfs"]);
}

// ---------- secure mount validation (SPEC §39, PRIV-013 groundwork) ----------

fn good_observation() -> MountObservation {
    MountObservation {
        mountpoint_exists: true,
        fstype: Some("xfs".to_string()),
        fs_uuid: Some("AAAA-BBBB".to_string()),
        sentinel_volume_uuid: Some("0123-4567".to_string()),
        nbd_connected: true,
        rw_probe_ok: true,
    }
}

fn expectation() -> MountExpectation {
    MountExpectation {
        fs_uuid: Some("AAAA-BBBB".to_string()),
        volume_uuid: "0123-4567".to_string(),
    }
}

#[test]
fn mount_identity_accepts_matching_mount() {
    verify_mount_identity(&expectation(), &good_observation()).unwrap();
}

#[test]
fn mount_identity_rejects_every_mismatch() {
    type Mutation = Box<dyn Fn(&mut MountObservation)>;
    let cases: Vec<(&str, Mutation)> = vec![
        (
            "missing mountpoint",
            Box::new(|o| o.mountpoint_exists = false),
        ),
        ("wrong fstype", Box::new(|o| o.fstype = Some("ext4".into()))),
        (
            "wrong fs uuid",
            Box::new(|o| o.fs_uuid = Some("XXXX".into())),
        ),
        (
            "wrong volume uuid",
            Box::new(|o| o.sentinel_volume_uuid = Some("9999".into())),
        ),
        (
            "missing sentinel",
            Box::new(|o| o.sentinel_volume_uuid = None),
        ),
        ("nbd down", Box::new(|o| o.nbd_connected = false)),
        ("probe failed", Box::new(|o| o.rw_probe_ok = false)),
    ];
    for (name, mutate) in cases {
        let mut obs = good_observation();
        mutate(&mut obs);
        assert!(
            verify_mount_identity(&expectation(), &obs).is_err(),
            "case {name:?} must fail — the container must not start"
        );
    }
}
