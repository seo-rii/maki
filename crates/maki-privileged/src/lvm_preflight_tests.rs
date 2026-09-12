use super::*;
use std::os::unix::process::ExitStatusExt;

const VG: &str = "aaaaaa-bbbb-cccc-dddd-eeee-ffff-gggggg";
const LV: &str = "hhhhhh-iiii-jjjj-kkkk-llll-mmmm-nnnnnn";
const PV1: &str = "111111-2222-3333-4444-5555-6666-777777";
const PV2: &str = "888888-9999-aaaa-bbbb-cccc-dddd-eeeeee";

fn devices() -> Vec<Device> {
    vec![
        Device {
            path: "/dev/nbd3".into(),
            number: (43, 3),
            start: 0,
            sectors: 4096,
        },
        Device {
            path: "/dev/nbd3p1".into(),
            number: (43, 4),
            start: 128,
            sectors: 512,
        },
        Device {
            path: "/dev/nbd3p2".into(),
            number: (43, 5),
            start: 1024,
            sectors: 512,
        },
    ]
}

fn labels() -> BTreeMap<String, String> {
    [
        ("/dev/nbd3p1".into(), PV1.into()),
        ("/dev/nbd3p2".into(), PV2.into()),
    ]
    .into()
}

fn fixture() -> serde_json::Value {
    serde_json::json!({"report": [{
        "vg": [{"vg_name":"vg_maki_pg","vg_uuid":VG,"vg_seqno":"17","pv_count":"2",
            "vg_missing_pv_count":"0","vg_partial":"0","vg_exported":"0","vg_systemid":"","vg_lock_type":""}],
        "pv": [
            {"pv_name":"/dev/nbd3p1","pv_uuid":PV1,"vg_uuid":VG,"pv_missing":"0","pv_duplicate":"0"},
            {"pv_name":"/dev/nbd3p2","pv_uuid":PV2,"vg_uuid":VG,"pv_missing":"0","pv_duplicate":"0"}],
        "lv": [
            {"lv_name":"data","lv_uuid":LV,"vg_uuid":VG,"lv_layout":"thin,sparse"},
            {"lv_name":"[pool_tdata]","lv_uuid":"111111-aaaa-bbbb-cccc-dddd-eeee-ffffff","vg_uuid":VG,"lv_layout":"striped"},
            {"lv_name":"[pool_tmeta]","lv_uuid":"222222-aaaa-bbbb-cccc-dddd-eeee-ffffff","vg_uuid":VG,"lv_layout":"raid,raid1"}],
        "pvseg": [], "seg": []
    }]})
}

fn check(value: &serde_json::Value) -> io::Result<VerifiedLvm> {
    validate(
        &serde_json::to_vec(value).unwrap(),
        devices(),
        labels(),
        "vg_maki_pg",
        "data",
        resolve_name,
    )
}

fn resolve_name(path: &str) -> io::Result<(u32, u32)> {
    if path == "/dev/disk/by-id/fixture-pv1" {
        return Ok((43, 4));
    }
    devices()
        .iter()
        .find(|device| device.path == path)
        .map(|device| device.number)
        .ok_or_else(|| invalid("fixture device is outside allowlist"))
}

#[test]
fn multiple_pvs_and_hidden_metadata_lvs_are_supported_without_layout_restriction() {
    let verified = check(&fixture()).unwrap();
    assert_eq!(verified.lvs.len(), 3);
    assert_eq!(verified.vg_uuid, VG);
    assert_eq!(verified.lv_uuid, LV);
    let mut reordered = fixture();
    reordered["report"][0]["pv"]
        .as_array_mut()
        .unwrap()
        .reverse();
    reordered["report"][0]["lv"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert_eq!(check(&reordered).unwrap(), verified);
}

#[test]
fn metadata_rejection_covers_missing_foreign_duplicate_and_ambiguous_identity() {
    for (field, value) in [
        ("vg_partial", "1"),
        ("vg_partial", "unknown"),
        ("vg_exported", "1"),
        ("vg_missing_pv_count", "1"),
        ("pv_count", "3"),
        ("vg_systemid", "another-host"),
        ("vg_lock_type", "sanlock"),
        ("vg_uuid", "x || vg_name=foreign"),
        ("vg_seqno", "-1"),
    ] {
        let mut report = fixture();
        report["report"][0]["vg"][0][field] = value.into();
        assert!(check(&report).is_err(), "accepted invalid {field}");
    }
    for (field, value) in [
        ("pv_name", "/dev/sda"),
        ("pv_uuid", PV1),
        ("pv_missing", "1"),
        ("pv_duplicate", "1"),
        ("pv_duplicate", "unknown"),
        ("vg_uuid", PV1),
    ] {
        let mut report = fixture();
        report["report"][0]["pv"][1][field] = value.into();
        assert!(check(&report).is_err(), "accepted invalid PV {field}");
    }
    for (field, value) in [("lv_name", "other"), ("vg_uuid", PV1), ("lv_uuid", "bad")] {
        let mut report = fixture();
        report["report"][0]["lv"][0][field] = value.into();
        assert!(check(&report).is_err(), "accepted invalid LV {field}");
    }
    let mut duplicate = fixture();
    let group = duplicate["report"][0].clone();
    duplicate["report"].as_array_mut().unwrap().push(group);
    assert!(check(&duplicate).is_err());
}

#[test]
fn omitted_independent_label_cannot_be_hidden_by_a_clean_fullreport() {
    let mut report = fixture();
    report["report"][0]["pv"].as_array_mut().unwrap().pop();
    report["report"][0]["vg"][0]["pv_count"] = "1".into();
    assert!(check(&report).is_err());
    let mut independent = labels();
    independent.insert("/dev/nbd3p2".into(), PV1.into());
    assert!(validate(
        &serde_json::to_vec(&fixture()).unwrap(),
        devices(),
        independent,
        "vg_maki_pg",
        "data",
        resolve_name
    )
    .is_err());
}

fn output(code: i32, bytes: &[u8]) -> Output {
    Output {
        status: std::process::ExitStatus::from_raw(code << 8),
        stdout: bytes.to_vec(),
        stderr: vec![],
    }
}

#[test]
fn blkid_requires_positive_unambiguous_identity_and_never_assumes_exit_two_is_empty() {
    let pv = format!("UUID={PV1}\nTYPE=LVM2_member\n");
    assert_eq!(
        probe_label(&output(0, pv.as_bytes())).unwrap().as_deref(),
        Some(PV1)
    );
    assert_eq!(probe_label(&output(0, b"PTTYPE=gpt\n")).unwrap(), None);
    assert_eq!(
        probe_label(&output(0, b"TYPE=ext4\nUUID=other\n")).unwrap(),
        None
    );
    for code in [2, 4, 8] {
        assert!(probe_label(&output(code, pv.as_bytes())).is_err());
    }
    for bad in [
        "",
        "TYPE=LVM2_member\n",
        "TYPE=LVM2_member\nUUID=bad\n",
        "TYPE=ext4\nTYPE=LVM2_member\n",
        "PART_ENTRY_SCHEME=gpt\n",
    ] {
        assert!(probe_label(&output(0, bad.as_bytes())).is_err());
    }
    assert!(probe_label(&output(0, format!("{pv}PTTYPE=gpt\n").as_bytes())).is_err());
}

#[test]
fn report_parse_is_bounded_and_required_fields_cannot_disappear() {
    let bytes = vec![b' '; MAX_REPORT + 1];
    assert!(validate(
        &bytes,
        devices(),
        labels(),
        "vg_maki_pg",
        "data",
        resolve_name
    )
    .is_err());
    let mut report = fixture();
    report["report"][0]["vg"][0]
        .as_object_mut()
        .unwrap()
        .remove("vg_partial");
    assert!(check(&report).is_err());
    assert!(validate(
        b"{",
        devices(),
        labels(),
        "vg_maki_pg",
        "data",
        resolve_name
    )
    .is_err());
}

#[test]
fn activation_always_uses_exact_validated_devices_uuid_and_complete_mode() {
    let verified = check(&fixture()).unwrap();
    let command = activation_command(&verified);
    let args: Vec<_> = command
        .get_args()
        .map(|arg| arg.to_str().unwrap())
        .collect();
    assert_eq!(
        args,
        [
            "--activate",
            "y",
            "--activationmode",
            "complete",
            "--devices",
            "/dev/nbd3,/dev/nbd3p1,/dev/nbd3p2",
            "--select",
            &format!("vg_uuid={VG}"),
            "--config",
            "devices { allow_changes_with_duplicate_pvs=0 }"
        ]
    );
    let report = report_command(&devices());
    let args: Vec<_> = report.get_args().map(|arg| arg.to_str().unwrap()).collect();
    assert!(args.contains(&"--readonly") && args.contains(&"--all") && args.contains(&"--devices"));
    assert!(!args.contains(&"--uuid"));

    let command = deactivation_command(&verified);
    let args: Vec<_> = command
        .get_args()
        .map(|arg| arg.to_str().unwrap())
        .collect();
    assert_eq!(
        args,
        [
            "--activate",
            "n",
            "--devices",
            "/dev/nbd3,/dev/nbd3p1,/dev/nbd3p2",
            "--select",
            &format!("vg_uuid={VG}"),
            "--config",
            "devices { allow_changes_with_duplicate_pvs=0 }"
        ]
    );
}

#[test]
fn independently_labelled_pvs_must_not_overlap_underlying_nbd_sectors() {
    let mut overlap = devices();
    overlap[2].start = 256;
    assert!(validate(
        &serde_json::to_vec(&fixture()).unwrap(),
        overlap,
        labels(),
        "vg_maki_pg",
        "data",
        resolve_name
    )
    .is_err());
}

#[test]
fn plan_describes_conditional_verified_activation_without_claiming_to_have_probed() {
    let step = crate::plan::PlannedStep::LvmActivate {
        vg_name: "vg_maki_pg".into(),
    };
    let description = step.to_string();
    assert!(
        description.contains("preflight")
            && description.contains("UUID")
            && description.contains("devices")
    );
}

struct Tree(std::path::PathBuf);
impl Tree {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "maki-lvm-preflight-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn mapping(&self, node: &str, name: &str, id: &str) {
        let path = self.0.join(node).join("dm");
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("name"), name).unwrap();
        std::fs::write(path.join("uuid"), id).unwrap();
    }
}
impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn record() -> BoundDeviceRecord {
    BoundDeviceRecord {
        version: 1,
        volume: "pg".into(),
        device: "/dev/nbd3".into(),
        connection_id: "fixture".into(),
        attachment: crate::plan::AttachmentIdentity {
            volume_uuid: "fixture".into(),
            nbd_socket: "fixture".into(),
            mountpoint: "/mount".into(),
            vg_name: "vg_maki_pg".into(),
            lv_name: "data".into(),
        },
        recovery: None,
        recovery_intent: None,
    }
}

#[test]
fn a_valid_target_uuid_does_not_authorize_an_unreported_same_vg_mapping() {
    let tree = Tree::new();
    tree.mapping(
        "dm-0",
        "vg_maki_pg-data",
        &format!("LVM-{}{}", VG.replace('-', ""), LV.replace('-', "")),
    );
    tree.mapping("dm-1", "vg_maki_pg-other", "LVM-foreign");
    assert!(verify_mapping(&record(), &check(&fixture()).unwrap(), &tree.0).is_err());
}

#[test]
fn pv_report_alias_is_matched_by_device_number() {
    let mut report = fixture();
    report["report"][0]["pv"][0]["pv_name"] = "/dev/disk/by-id/fixture-pv1".into();
    assert!(check(&report).is_ok());
}

#[test]
fn cachevol_synthetic_mapping_ids_are_rejected_before_activation() {
    let mut report = fixture();
    report["report"][0]["lv"][1]["lv_layout"] = "cache,cachevol".into();
    assert!(check(&report).is_err());
}

#[test]
fn kernel_partition_parent_geometry_device_number_and_holders_are_verified() {
    for fault in ["none", "parent", "number", "range", "overflow", "holder"] {
        let tree = Tree::new();
        let class = tree.0.join("class");
        let root = tree.0.join("block/nbd3");
        let partition = root.join("nbd3p1");
        std::fs::create_dir_all(root.join("holders")).unwrap();
        std::fs::create_dir_all(partition.join("holders")).unwrap();
        std::fs::create_dir(&class).unwrap();
        std::fs::write(root.join("dev"), "43:3").unwrap();
        std::fs::write(root.join("size"), "4096").unwrap();
        std::fs::write(partition.join("dev"), "43:4").unwrap();
        std::fs::write(partition.join("partition"), "1").unwrap();
        std::fs::write(partition.join("start"), "128").unwrap();
        std::fs::write(partition.join("size"), "512").unwrap();
        std::os::unix::fs::symlink(&root, class.join("nbd3")).unwrap();
        std::os::unix::fs::symlink(&partition, class.join("nbd3p1")).unwrap();
        match fault {
            "parent" => {
                let foreign = tree.0.join("foreign");
                std::fs::rename(&partition, &foreign).unwrap();
                std::fs::remove_file(class.join("nbd3p1")).unwrap();
                std::os::unix::fs::symlink(foreign, class.join("nbd3p1")).unwrap();
            }
            "range" => std::fs::write(partition.join("start"), "4000").unwrap(),
            "overflow" => std::fs::write(partition.join("start"), u64::MAX.to_string()).unwrap(),
            "holder" => std::fs::write(partition.join("holders/dm-0"), "").unwrap(),
            _ => {}
        }
        let result = discover_at(&class, "/dev/nbd3", |path| {
            if fault == "number" {
                Ok((8, 0))
            } else {
                resolve_name(path.to_str().unwrap())
            }
        });
        assert_eq!(
            result.is_ok(),
            fault == "none",
            "unexpected outcome for {fault}"
        );
    }
}

#[test]
fn known_internal_lvm_layers_are_owned_and_partial_activation_can_be_rolled_back() {
    let tree = Tree::new();
    let verified = check(&fixture()).unwrap();
    let internal = "111111aaaabbbbccccddddeeeeffffff";
    for layer in [
        "real", "tpool", "tdata", "tmeta", "cdata", "cmeta", "cvol", "pool",
    ] {
        tree.mapping(
            "dm-1",
            "vg_maki_pg-pool_tdata",
            &format!("LVM-{}{internal}-{layer}", VG.replace('-', "")),
        );
        assert!(verify_rollback_mapping(&record(), &verified, &tree.0).is_ok());
        assert!(
            verify_mapping(&record(), &verified, &tree.0).is_err(),
            "workload target must exist"
        );
        tree.mapping(
            "dm-0",
            "vg_maki_pg-data",
            &format!("LVM-{}{}", VG.replace('-', ""), LV.replace('-', "")),
        );
        assert!(verify_mapping(&record(), &verified, &tree.0).is_ok());
        std::fs::remove_dir_all(tree.0.join("dm-0")).unwrap();
    }
}

#[test]
fn unknown_internal_mapping_uuid_suffix_is_not_owned() {
    let tree = Tree::new();
    let verified = check(&fixture()).unwrap();
    let internal = "111111aaaabbbbccccddddeeeeffffff";
    tree.mapping(
        "dm-0",
        "vg_maki_pg-pool_tdata",
        &format!("LVM-{}{internal}-foreign", VG.replace('-', "")),
    );
    assert!(verify_rollback_mapping(&record(), &verified, &tree.0).is_err());
}

#[test]
fn layout_changes_participate_in_fresh_metadata_equality_and_separator_is_fixed() {
    let first = check(&fixture()).unwrap();
    let mut changed = fixture();
    changed["report"][0]["lv"][1]["lv_layout"] = "linear".into();
    assert_ne!(check(&changed).unwrap(), first);
    changed["report"][0]["lv"][1]["lv_layout"] = "cache|cachevol".into();
    assert!(check(&changed).is_err());
    changed["report"][0]["lv"][1]
        .as_object_mut()
        .unwrap()
        .remove("lv_layout");
    assert!(check(&changed).is_err());
    let command = report_command(&devices());
    assert!(command
        .get_args()
        .any(|arg| arg == r#"report { list_item_separator="," }"#));
}

#[test]
fn whole_device_pv_overlapping_a_partition_pv_is_rejected() {
    let mut report = fixture();
    report["report"][0]["pv"][0]["pv_name"] = "/dev/nbd3".into();
    let labels = [
        ("/dev/nbd3".into(), PV1.into()),
        ("/dev/nbd3p2".into(), PV2.into()),
    ]
    .into();
    assert!(validate(
        &serde_json::to_vec(&report).unwrap(),
        devices(),
        labels,
        "vg_maki_pg",
        "data",
        resolve_name
    )
    .is_err());
}
