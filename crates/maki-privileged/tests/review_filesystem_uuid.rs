//! BUG-071: configured filesystem UUID spelling must not change its identity.

use maki_privileged::{
    config::{parse, AttachOverrides},
    verify::{
        verify_filesystem_identity, verify_mount_identity, MountExpectation, MountObservation,
    },
};

const UUID: &str = "abcdef12-3456-4789-abcd-0123456789ab";
const DIFFERENT_UUID: &str = "ffffffff-3456-4789-abcd-0123456789ab";

fn configured_uuid(value: &str) -> String {
    let raw = format!("volume_uuid = '{UUID}'\nfs_uuid = '{value}'\n");
    parse(&raw)
        .unwrap()
        .into_request("audit", AttachOverrides::default(), true)
        .unwrap()
        .fs_uuid
        .unwrap()
}

#[test]
fn uppercase_config_matches_lowercase_filesystem_identity() {
    let expected = configured_uuid(&UUID.to_ascii_uppercase());
    verify_filesystem_identity(Some(&expected), Some("xfs"), Some(UUID)).unwrap();
}

#[test]
fn lowercase_config_matches_uppercase_observed_identity() {
    let expected = configured_uuid(UUID);
    let observed = UUID.to_ascii_uppercase();
    verify_filesystem_identity(Some(&expected), Some("xfs"), Some(&observed)).unwrap();
}

#[test]
fn mixed_case_uuid_matches_through_full_mount_verifier() {
    let expected = MountExpectation {
        fs_uuid: Some(configured_uuid("aBcDeF12-3456-4789-AbCd-0123456789aB")),
        volume_uuid: UUID.into(),
        nbd_device: "/dev/nbd0".into(),
    };
    let observed = MountObservation {
        mountpoint_exists: true,
        fstype: Some("xfs".into()),
        fs_uuid: Some(UUID.into()),
        sentinel_volume_uuid: Some(UUID.into()),
        nbd_connected: true,
        rw_probe_ok: true,
        backing_devices: vec!["/dev/nbd0".into()],
        mount_options: vec!["nosuid".into(), "nodev".into()],
    };
    verify_mount_identity(&expected, &observed).unwrap();
}

#[test]
fn matching_uuid_without_spelling_changes_succeeds() {
    verify_filesystem_identity(Some(UUID), Some("xfs"), Some(UUID)).unwrap();
}

#[test]
fn different_or_missing_uuid_and_non_xfs_filesystems_remain_refused() {
    for observed in [Some(DIFFERENT_UUID), None] {
        assert!(verify_filesystem_identity(Some(UUID), Some("xfs"), observed).is_err());
    }
    assert!(verify_filesystem_identity(Some(UUID), Some("ext4"), Some(UUID)).is_err());
}

#[test]
fn malformed_uuid_cannot_match_itself_or_bypass_config_validation() {
    for malformed in [
        "not-a-uuid",
        "abcdef1234564789abcd0123456789ab",
        "abcdef12-3456-4789-abcd-0123456789ag",
    ] {
        let raw = format!("volume_uuid = '{UUID}'\nfs_uuid = '{malformed}'\n");
        assert!(parse(&raw)
            .unwrap()
            .into_request("audit", AttachOverrides::default(), true)
            .is_err());
        assert!(verify_filesystem_identity(Some(malformed), Some("xfs"), Some(malformed)).is_err());
        assert!(verify_filesystem_identity(Some(UUID), Some("xfs"), Some(malformed)).is_err());
    }
}

#[test]
fn first_boot_without_a_pinned_uuid_still_checks_filesystem_type() {
    verify_filesystem_identity(None, Some("xfs"), None).unwrap();
    assert!(verify_filesystem_identity(None, Some("ext4"), None).is_err());
}
