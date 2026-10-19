//! F05: hexadecimal volume UUID spelling must preserve attachment identity.

use maki_privileged::{
    config::{parse, AttachOverrides},
    plan::AttachmentIdentity,
    verify::{verify_mount_identity, MountExpectation, MountObservation},
};

const UUID: &str = "abcdef01-2345-6789-abcd-ef0123456789";

fn identity(uuid: &str) -> AttachmentIdentity {
    let request = parse(&format!("volume_uuid = '{uuid}'"))
        .unwrap()
        .into_request("review", AttachOverrides::default(), true)
        .unwrap();
    (&request).into()
}

#[test]
fn review_f05_serialized_attachment_uuid_is_case_insensitive() {
    let lower = identity(UUID);
    let upper = identity(&UUID.to_ascii_uppercase());
    let stored: AttachmentIdentity =
        serde_json::from_slice(&serde_json::to_vec(&upper).unwrap()).unwrap();
    assert_eq!(stored, lower);
    assert_ne!(stored, identity("00000000-2345-6789-abcd-ef0123456789"));
    for field in ["nbd_socket", "mountpoint", "vg_name", "lv_name"] {
        let mut changed = serde_json::to_value(&upper).unwrap();
        changed[field] = changed[field].as_str().unwrap().to_ascii_uppercase().into();
        if changed == serde_json::to_value(&upper).unwrap() {
            changed[field] = "changed".into();
        }
        assert_ne!(lower, serde_json::from_value(changed).unwrap(), "{field}");
    }
}

#[test]
fn review_f05_lvm_identifiers_remain_case_sensitive() {
    let raw = format!(
        "volume_uuid = '{UUID}'\n[lvm_identity]\npv_uuids = ['aaaaaa-bbbb-cccc-dddd-eeee-ffff-gggggg']\nvg_uuid = 'hhhhhh-iiii-jjjj-kkkk-llll-mmmm-nnnnnn'\nlv_uuid = 'oooooo-pppp-qqqq-rrrr-ssss-tttt-uuuuuu'"
    );
    let request = parse(&raw)
        .unwrap()
        .into_request("review", AttachOverrides::default(), true)
        .unwrap();
    let original = AttachmentIdentity::from(&request);
    for field in ["pv", "vg", "lv"] {
        let mut changed = original.clone();
        let pins = changed.lvm_identity.as_mut().unwrap();
        match field {
            "pv" => pins.pv_uuids[0].make_ascii_uppercase(),
            "vg" => pins.vg_uuid.make_ascii_uppercase(),
            "lv" => pins.lv_uuid.make_ascii_uppercase(),
            _ => unreachable!(),
        }
        assert_ne!(original, changed, "{field}");
    }
}

#[test]
fn review_f05_sentinel_and_expected_uuid_accept_both_spellings() {
    let mut expected = MountExpectation {
        fs_uuid: None,
        volume_uuid: UUID.into(),
        nbd_device: "/dev/nbd0".into(),
    };
    let mut observed = MountObservation {
        mountpoint_exists: true,
        fstype: Some("xfs".into()),
        fs_uuid: None,
        sentinel_volume_uuid: Some(UUID.into()),
        nbd_connected: true,
        rw_probe_ok: true,
        backing_devices: vec!["/dev/nbd0".into()],
        mount_options: vec!["nosuid".into(), "nodev".into()],
    };
    for config in [UUID.to_owned(), UUID.to_ascii_uppercase()] {
        expected.volume_uuid = config;
        for sentinel in [UUID.to_owned(), UUID.to_ascii_uppercase()] {
            observed.sentinel_volume_uuid = Some(sentinel);
            verify_mount_identity(&expected, &observed).unwrap();
        }
    }
    observed.sentinel_volume_uuid = Some("00000000-2345-6789-abcd-ef0123456789".into());
    assert!(verify_mount_identity(&expected, &observed).is_err());
}
