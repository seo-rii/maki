//! Grow, detach, cleanup and recovery run LVM commands on the recorded
//! attachment's volume group. A volume group of the same name on another
//! disk (a second disk, a cloned image) is never what they act on: not when
//! LVM's own scan sees both, not when the host's LVM configuration leaves
//! the NBD devices out of that scan (attach reaches them with `--devices`),
//! and not when the daemon behind the connection serves no reads.

use super::*;
use crate::plan::{plan_grow, GrowRequest};

/// The UUID of a VG named like pg's on another disk.
const NAMESAKE: &str = "ffffff-bbbb-cccc-dddd-eeee-ffff-gggggg";

/// What LVM's own scan covers on the host.
#[derive(Clone, Copy, Debug)]
enum Scan {
    /// Every block device, LVM's default.
    Everything,
    /// Every device but `/dev/nbd*`: a devices file that does not list
    /// them, or a filter that rejects them.
    WithoutNbd,
}

const CASES: [(Scan, bool); 4] = [
    (Scan::Everything, false),
    (Scan::Everything, true),
    (Scan::WithoutNbd, false),
    (Scan::WithoutNbd, true),
];

/// Volume pg attached on `/dev/nbd3`, and with `namesake` a disk whose
/// inactive VG is named `vg_maki_pg` too.
fn attached(scan: Scan, namesake: bool) -> (Host, TrustedState, AttachRequest) {
    let mut host = Host::new();
    let state = host.state();
    {
        let mut lvm = host.lvm.borrow_mut();
        lvm.scan_leaves_out_nbd = matches!(scan, Scan::WithoutNbd);
        if namesake {
            lvm.disks.push(Disk {
                device: "/dev/sdb",
                vg_name: "vg_maki_pg",
                vg_uuid: NAMESAKE,
                lv_name: "data",
                lv_bytes: 1 << 30,
            });
        }
    }
    let pg = request(&PG);
    execute_with(&plan_attach(&pg), Some(&state), &mut host).unwrap();
    assert_attached(&host, &state.read("pg").unwrap().unwrap());
    host.commands.clear();
    (host, state, pg)
}

fn assert_namesake_untouched(host: &Host, case: &str) {
    let lvm = host.lvm.borrow();
    assert!(
        lvm.acted_on.iter().all(|(_, uuid)| *uuid != NAMESAKE),
        "{case}: {:?}",
        lvm.acted_on
    );
    if let Some(disk) = lvm.disks.first() {
        assert_eq!(disk.lv_bytes, 1 << 30, "{case}");
    }
}

fn grow(request: &AttachRequest, target_bytes: u64) -> Plan {
    plan_grow(&GrowRequest {
        volume: request.volume.clone(),
        nbd_device: AUTO_NBD_DEVICE.into(),
        volume_uuid: request.volume_uuid.clone(),
        nbd_socket: request.nbd_socket.clone(),
        vg_name: request.vg_name.clone(),
        lv_name: request.lv_name.clone(),
        lvm_identity: request.lvm_identity.clone(),
        target_bytes,
        fs_uuid: None,
        mountpoint: request.mountpoint.clone(),
    })
}

/// `lvextend` finds the recorded LV on the recorded device, whatever LVM's
/// own scan covers and whatever else carries the VG's name.
#[test]
fn grow_extends_the_recorded_lv_and_never_a_namesake() {
    for (scan, namesake) in CASES {
        let case = format!("{scan:?}, namesake {namesake}");
        let (mut host, state, pg) = attached(scan, namesake);

        execute_with(&grow(&pg, 2 << 30), Some(&state), &mut host)
            .unwrap_or_else(|error| panic!("{case}: {error}"));

        assert_eq!(
            host.lv_size("vg_maki_pg", "data").unwrap(),
            2 << 30,
            "{case}"
        );
        assert_eq!(
            host.lvm.borrow().acted_on,
            [("lvextend", PG.vg_uuid)],
            "{case}"
        );
        assert_eq!(host.commands, ["lvextend", "xfs-growfs"], "{case}");
        assert_namesake_untouched(&host, &case);
    }
}

/// Detach, and cleanup while the daemon serves, deactivate the recorded VG
/// and nothing else.
#[test]
fn detach_deactivates_the_recorded_volume_group_and_never_a_namesake() {
    for verb in ["detach", "cleanup"] {
        for (scan, namesake) in CASES {
            let case = format!("{verb}, {scan:?}, namesake {namesake}");
            let (mut host, state, pg) = attached(scan, namesake);

            run_verb(verb, &pg, &state, &mut host)
                .unwrap_or_else(|error| panic!("{case}: {error}"));

            assert_eq!(
                host.commands,
                ["umount", "lvm-deactivate", "nbd-disconnect"],
                "{case}"
            );
            assert!(host.mapping("vg_maki_pg").is_none(), "{case}");
            assert!(state.read("pg").unwrap().is_none(), "{case}");
            assert_eq!(
                host.lvm.borrow().acted_on,
                [("vgchange", PG.vg_uuid)],
                "{case}"
            );
            assert_namesake_untouched(&host, &case);
        }
    }
}

/// After the daemon died, LVM cannot read the recorded VG: its deactivation
/// has to fail for cleanup to remove the proven mapping directly. Finding a
/// namesake to deactivate instead ends with that command's success and no
/// way down.
#[test]
fn cleanup_after_the_daemon_died_reaches_its_fallback_beside_a_namesake() {
    for (scan, namesake) in CASES {
        let case = format!("{scan:?}, namesake {namesake}");
        let (mut host, state, pg) = attached(scan, namesake);
        host.lvm.borrow_mut().nbd_unreadable = true;

        cleanup_with(&plan_detach(&pg), &state, &mut host)
            .unwrap_or_else(|error| panic!("{case}: {error}"));

        assert_eq!(
            host.commands,
            [
                "umount",
                "lvm-deactivate",
                "dmsetup-remove",
                "nbd-disconnect"
            ],
            "{case}"
        );
        assert!(host.mapping("vg_maki_pg").is_none(), "{case}");
        assert!(state.read("pg").unwrap().is_none(), "{case}");
        assert!(host.lvm.borrow().acted_on.is_empty(), "{case}");
        assert_namesake_untouched(&host, &case);
    }
}

/// Recovery of a device without a backend whose mapping stayed: LVM cannot
/// read the recorded VG, and must not deactivate the only VG of that name
/// it can read.
#[test]
fn recovery_never_deactivates_a_namesake() {
    for (scan, namesake) in CASES {
        let case = format!("{scan:?}, namesake {namesake}");
        let (mut host, state, pg) = attached(scan, namesake);
        let record = state.read("pg").unwrap().unwrap();
        let nbd = host.nbd("/dev/nbd3");
        std::fs::remove_file(nbd.join("pid")).unwrap();
        std::fs::remove_file(nbd.join("backend")).unwrap();

        let error = recover_with(&plan_detach(&pg), &state, &mut host)
            .expect_err(&format!("{case}: recovered without deactivating"))
            .to_string();

        assert!(error.contains("vgchange -an vg_maki_pg"), "{case}: {error}");
        assert_eq!(host.commands, ["umount", "lvm-deactivate"], "{case}");
        assert!(host.mapping("vg_maki_pg").is_some(), "{case}");
        assert_eq!(state.read("pg").unwrap(), Some(record), "{case}");
        assert!(host.lvm.borrow().acted_on.is_empty(), "{case}");
        assert_namesake_untouched(&host, &case);
    }
}

fn argv(command: &std::process::Command) -> Vec<String> {
    std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|arg| arg.to_str().unwrap().to_owned())
        .collect()
}

const NO_DUPLICATE_PV_CHANGES: &str = "devices { allow_changes_with_duplicate_pvs=0 }";

/// The commands name the recorded VG and LV within the devices and VG UUID
/// that attach verified: from the mapping proof, the activation intent or
/// the administrator pins. A record from before either exists is held to
/// its NBD device.
#[test]
fn every_kind_of_record_scopes_its_commands_to_what_attach_verified() {
    let (_host, state, _) = attached(Scan::Everything, false);
    let proven = state.read("pg").unwrap().unwrap();

    let mut host = Host::new();
    let intent_state = host.state();
    host.killed_after = Some("lvm-activate");
    assert!(killed(|| {
        let _ = execute_with(&plan_attach(&request(&PG)), Some(&intent_state), &mut host);
    }));
    let intended = intent_state.read("pg").unwrap().unwrap();
    assert!(intended.recovery_intent.is_some());

    let legacy = BoundDeviceRecord {
        recovery: None,
        recovery_intent: None,
        ..proven.clone()
    };
    let pinned = BoundDeviceRecord {
        attachment: (&super::pinned(&PG)).into(),
        ..legacy.clone()
    };

    let uuid = format!("vg_uuid={}", PG.vg_uuid);
    for (record, select) in [
        (&proven, Some(&uuid)),
        (&intended, Some(&uuid)),
        (&pinned, Some(&uuid)),
        (&legacy, None),
    ] {
        let scope = lvm_preflight::recorded_scope(record).unwrap();
        let mut expected = vec!["vgchange", "--devices", "/dev/nbd3", "--activate", "n"];
        if let Some(select) = select {
            expected.extend(["--select", select]);
        }
        expected.extend(["--config", NO_DUPLICATE_PV_CHANGES, "vg_maki_pg"]);
        assert_eq!(
            argv(&lvm_preflight::recorded_deactivation_command(
                &scope,
                "vg_maki_pg"
            )),
            expected
        );
        assert_eq!(
            argv(&lvm_preflight::recorded_extend_command(
                &scope,
                "vg_maki_pg",
                "data",
                2 << 30
            )),
            [
                "lvextend",
                "--devices",
                "/dev/nbd3",
                "--config",
                NO_DUPLICATE_PV_CHANGES,
                "-L",
                "2147483648b",
                "vg_maki_pg/data"
            ]
        );
    }

    // Pins that name another VG than the proof are not resolved either way.
    let mut conflicting = proven.clone();
    conflicting.attachment = (&super::pinned(&DB)).into();
    conflicting.attachment.vg_name = proven.attachment.vg_name.clone();
    assert!(lvm_preflight::recorded_scope(&conflicting).is_err());
}

/// The plan is rendered before any record is read, and the same text names
/// a failed step. It states the scope every record gets: the recorded PVs,
/// and a selection by VG UUID only where the record names one; `lvextend`
/// is never selected by UUID.
#[test]
fn the_plan_states_the_scope_each_kind_of_record_gets() {
    let pg = request(&PG);
    let detach = plan_detach(&pg).to_string();
    assert!(
        detach.contains(
            "vgchange -an vg_maki_pg, on the recorded PVs only and by the recorded VG UUID \
             where the record names one"
        ),
        "{detach}"
    );
    let grow = grow(&pg, 2 << 30).to_string();
    assert!(
        grow.contains("lvextend -L 2147483648b vg_maki_pg/data, on the recorded PVs only"),
        "{grow}"
    );
    assert!(!grow.contains("UUID"), "{grow}");
}
