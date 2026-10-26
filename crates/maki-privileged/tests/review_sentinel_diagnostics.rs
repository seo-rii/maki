//! BUG-167: errors must not carry bytes from the workload's sentinel file.
//! Only pure verification and a disposable plain directory are exercised;
//! no mount, LVM, NBD, or privileged subprocess runs.
#![cfg(target_os = "linux")]

use maki_privileged::plan::{Plan, PlannedStep, SENTINEL_FILE};
use maki_privileged::verify::{verify_mount_identity, MountExpectation, MountObservation};
use std::error::Error;

const UUID: &str = "abcdef12-2345-6789-abcd-ef0123456789";
const PRIVATE_CONTENT: &str = "synthetic-private-file-content-bug167";
const OTHER_UUID: &str = "99999999-2222-3333-4444-555555555555";

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "maki-sentinel-diagnostics-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn fixture(sentinel: Option<&str>) -> (MountExpectation, MountObservation) {
    (
        MountExpectation {
            fs_uuid: None,
            volume_uuid: UUID.into(),
            nbd_device: "/dev/nbd0".into(),
        },
        MountObservation {
            mountpoint_exists: true,
            fstype: Some("xfs".into()),
            fs_uuid: None,
            sentinel_volume_uuid: sentinel.map(str::to_owned),
            nbd_connected: true,
            rw_probe_ok: true,
            backing_devices: vec!["/dev/nbd0".into()],
            mount_options: vec!["rw".into(), "nosuid".into(), "nodev".into()],
        },
    )
}

fn sentinel_plan(root: &Scratch) -> Plan {
    Plan {
        description: "isolated plain-file sentinel diagnostic regression".into(),
        volume: "review".into(),
        attachment: None,
        steps: vec![PlannedStep::WriteSentinel {
            mountpoint: root.0.to_str().unwrap().into(),
            volume_uuid: UUID.into(),
        }],
    }
}

fn assert_redacted(mut error: &(dyn Error + 'static), payload: &str) {
    loop {
        let display_leaks = error.to_string().contains(payload);
        let debug_leaks = format!("{error:?}").contains(payload);
        assert!(
            !display_leaks && !debug_leaks,
            "sentinel exposed by Display: {display_leaks}, Debug: {debug_leaks}"
        );
        match error.source() {
            Some(source) => error = source,
            None => break,
        }
    }
}

#[test]
fn mount_error_chain_does_not_expose_sentinel_payload() {
    for payload in [PRIVATE_CONTENT, OTHER_UUID] {
        let (expected, observed) = fixture(Some(payload));
        let error = verify_mount_identity(&expected, &observed).unwrap_err();
        assert!(error.to_string().contains("sentinel"));
        assert_redacted(&error, payload);
        let wrapped = maki_privileged::exec::ExecError::Verify(error);
        assert_redacted(&wrapped, payload);
    }
}

#[test]
fn initialization_error_chain_does_not_expose_existing_payload() {
    for payload in [PRIVATE_CONTENT, OTHER_UUID] {
        let root = Scratch::new();
        let path = root.0.join(SENTINEL_FILE);
        std::fs::write(&path, payload).unwrap();
        let error = maki_privileged::exec::execute(&sentinel_plan(&root)).unwrap_err();
        assert_eq!(std::fs::read_to_string(path).unwrap(), payload);
        assert!(error.to_string().contains("sentinel"));
        assert!(error.to_string().contains("refusing to overwrite"));
        assert_redacted(&error, payload);
    }
}

#[test]
fn missing_sentinel_remains_identifiable() {
    let (expected, observed) = fixture(None);
    let error = verify_mount_identity(&expected, &observed).unwrap_err();
    assert!(error.to_string().contains("sentinel"));
    assert!(error.to_string().contains("missing"));
}

#[test]
fn matching_sentinel_creation_and_retry_still_work() {
    for spelling in [UUID.to_owned(), UUID.to_ascii_uppercase()] {
        let (expected, observed) = fixture(Some(&spelling));
        verify_mount_identity(&expected, &observed).unwrap();
        let root = Scratch::new();
        let plan = sentinel_plan(&root);
        maki_privileged::exec::execute(&plan).unwrap();
        let path = root.0.join(SENTINEL_FILE);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), format!("{UUID}\n"));
        std::fs::write(&path, format!(" {spelling}\n")).unwrap();
        maki_privileged::exec::execute(&plan).unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), format!("{UUID}\n"));
    }
}
